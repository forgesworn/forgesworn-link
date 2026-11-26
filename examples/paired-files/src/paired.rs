//! Invite-authenticated pairing and hash-verified file transfer.

use std::io::{BufRead, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::{Args, Subcommand};
use link_core::card::{Card, MAX_CARD_BYTES, VerifyContext};
use link_core::id::TransportKey;
use link_core::rendezvous::PAIRING_SECRET_BYTES;
use link_endpoint::{AcceptedSession, Endpoint, EndpointConfig, RelaySpec, Session};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tempfile::NamedTempFile;
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;
use zeroize::Zeroizing;

#[path = "state.rs"]
mod state;

use state::{SavedCard, SavedPair, StagedPair, read_admission_key};

const INVITE_PREFIX: &str = "fsl-file-1.";
const INVITE_LIFETIME: Duration = Duration::from_secs(300);
const MAX_INVITE_TEXT: u64 = 6000;
const ACCEPTED: u8 = 1;
const CHUNK: usize = 64 * 1024;

#[derive(Debug, Subcommand)]
pub(super) enum Command {
    /// Create a one-use invite and receive a file.
    PairReceive(TransferArgs),
    /// Read an invite from stdin and send a file.
    PairSend(TransferArgs),
    /// Receive another file using the saved pairing.
    SavedReceive(SavedArgs),
    /// Send another file using the saved pairing.
    SavedSend(SavedArgs),
}

impl Command {
    pub(super) async fn run(self) -> Result<()> {
        match self {
            Self::PairReceive(args) => receive(args).await,
            Self::PairSend(args) => send(args).await,
            Self::SavedReceive(args) => saved_receive(args).await,
            Self::SavedSend(args) => saved_send(args).await,
        }
    }
}

#[derive(Args, Debug, Deserialize, Serialize)]
struct RelayArgs {
    /// The owner-approved relay URL, including the /link path.
    #[arg(long)]
    relay: String,
    /// SHA-256 of the relay certificate for a self-signed relay.
    #[arg(long)]
    relay_cert_sha256: Option<String>,
    /// Operator-issued key file when the approved relay requires admission.
    #[arg(long, value_name = "FILE")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    relay_admission_key_file: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub(super) struct TransferArgs {
    #[command(flatten)]
    relay: RelayArgs,
    /// Create a new pairing record at this path to use on later runs.
    #[arg(long, value_name = "PAIR_FILE")]
    state: Option<PathBuf>,
    /// The input or output file, chosen locally.
    #[arg(value_name = "FILE")]
    file: PathBuf,
}

#[derive(Args, Debug)]
pub(super) struct SavedArgs {
    /// The pairing record created by this peer.
    #[arg(long, value_name = "PAIR_FILE")]
    state: PathBuf,
    /// Use a different operator key file for this transfer.
    #[arg(long, value_name = "FILE")]
    relay_admission_key_file: Option<PathBuf>,
    /// The input or output file, chosen locally.
    #[arg(value_name = "FILE")]
    file: PathBuf,
}

impl RelayArgs {
    fn config(&self, key: TransportKey, key_file: Option<&Path>) -> Result<EndpointConfig> {
        ensure!(
            self.relay.starts_with("wss://"),
            "the relay must use wss://"
        );
        let mut relay = match &self.relay_cert_sha256 {
            Some(pin) => RelaySpec::pinned(&self.relay, pin),
            None => RelaySpec::plain(&self.relay),
        };
        if let Some(path) = key_file.or(self.relay_admission_key_file.as_deref()) {
            relay = relay.with_admission_key(read_admission_key(path)?);
        }
        let mut config = EndpointConfig::new(key);
        config.relays = vec![relay];
        Ok(config)
    }

    async fn open_for_pairing(&mut self, key: TransportKey) -> Result<Endpoint> {
        if let Some(path) = &mut self.relay_admission_key_file {
            *path = std::path::absolute(&*path)?;
        }
        Endpoint::open(self.config(key, None)?).await
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn invite_text(card: &Card, secret: &[u8; PAIRING_SECRET_BYTES]) -> Zeroizing<String> {
    let mut bytes = Zeroizing::new(Vec::from(secret.as_slice()));
    bytes.extend(card.as_bytes());
    let mut text = Zeroizing::new(String::from(INVITE_PREFIX));
    URL_SAFE_NO_PAD.encode_string(bytes.as_slice(), &mut text);
    text
}

fn read_invite() -> Result<(Card, u64, Zeroizing<[u8; PAIRING_SECRET_BYTES]>)> {
    eprintln!("Paste the receiver's invite and press Enter.");
    let mut line = Zeroizing::new(String::new());
    std::io::stdin()
        .lock()
        .take(MAX_INVITE_TEXT)
        .read_line(&mut line)?;
    let code = line
        .trim()
        .strip_prefix(INVITE_PREFIX)
        .context("expected a Link file invite")?;
    let bytes = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(code)
            .context("invalid Link file invite")?,
    );
    let (secret, card) = bytes
        .split_first_chunk::<PAIRING_SECRET_BYTES>()
        .context("invalid Link file invite")?;
    ensure!(card.len() <= MAX_CARD_BYTES, "invite card is too large");
    let verified_at = unix_now();
    let card = Card::verify(card, &VerifyContext::new(verified_at))?;
    Ok((card, verified_at, Zeroizing::new(*secret)))
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn stage_output(path: &Path) -> Result<NamedTempFile> {
    ensure!(!path.try_exists()?, "the output file already exists");
    NamedTempFile::new_in(parent_directory(path)).context("staging the output file")
}

async fn wait_for_relay(endpoint: &Endpoint) -> Result<()> {
    timeout(
        Duration::from_secs(15),
        endpoint.paths().relay().home().wait_up(),
    )
    .await
    .context("waiting for the approved relay")?
    .context("approved relay unavailable")?;
    Ok(())
}

async fn receive(mut args: TransferArgs) -> Result<()> {
    let staged = stage_output(&args.file)?;
    let state = args.state.map(StagedPair::new).transpose()?;
    let key = TransportKey::generate();
    let endpoint = args.relay.open_for_pairing(key.clone()).await?;
    let mut secret = Zeroizing::new([0; PAIRING_SECRET_BYTES]);
    OsRng.fill_bytes(secret.as_mut());
    let registration = endpoint.register_pairing_secret(*secret, INVITE_LIFETIME)?;
    wait_for_relay(&endpoint).await?;
    let card = endpoint.card(INVITE_LIFETIME, Vec::new());
    println!("invite {}", invite_text(&card, &secret).as_str());

    let first = timeout(INVITE_LIFETIME, endpoint.accept_any())
        .await
        .context("invite expired")??;
    let AcceptedSession::Pairing(pair) = first else {
        anyhow::bail!("expected an invite-authenticated pairing session");
    };
    let peer = pair.peer();
    let mut stream = pair.accept_stream().await?;
    let mut proof = Zeroizing::new([0; PAIRING_SECRET_BYTES]);
    stream.read_exact(proof.as_mut()).await?;
    ensure!(
        bool::from(proof.as_ref().ct_eq(secret.as_ref())),
        "pairing proof did not match the invite"
    );
    ensure!(
        stream.recv.read(&mut [0]).await?.is_none(),
        "extra pairing bytes"
    );
    let route_secret = pair.paired_route_secret()?;
    if let Some(state) = state {
        state.save(SavedPair::new(args.relay, &key, peer, &route_secret, None))?;
    }
    endpoint
        .rendezvous_book()
        .context("paired endpoint needs a tag book")?
        .upsert_paired(peer, *route_secret);
    drop(secret);
    stream.write_u8(ACCEPTED).await?;
    stream.finish().await?;
    drop(registration);

    let session = timeout(Duration::from_secs(30), endpoint.accept())
        .await
        .context("waiting for the paired transfer")??;
    ensure!(
        session.peer() == peer,
        "transfer peer differs from paired peer"
    );
    receive_file(&session, staged, &args.file).await?;
    endpoint.close().await;
    Ok(())
}

async fn receive_file(session: &Session, staged: NamedTempFile, output: &Path) -> Result<()> {
    let mut stream = session.accept_stream().await?;
    let size = stream.read_u64().await?;
    let mut file = File::from_std(staged.reopen()?);
    let digest = copy_and_hash(&mut stream, &mut file, size).await?;
    let mut offered = [0; 32];
    stream.read_exact(&mut offered).await?;
    ensure!(digest == offered, "file digest did not match");
    ensure!(
        stream.recv.read(&mut [0]).await?.is_none(),
        "extra transfer bytes"
    );
    file.flush().await?;
    drop(file);
    staged
        .persist_noclobber(output)
        .context("saving the verified file")?;
    stream.write_all(&digest).await?;
    stream.finish().await?;
    let _ = timeout(Duration::from_secs(5), stream.send.stopped()).await;
    println!(
        "received {size} bytes sha256={} path={}",
        hex::encode(digest),
        session.path().status
    );
    Ok(())
}

async fn open_input(path: &Path) -> Result<(File, u64)> {
    let file = File::open(path).await?;
    let meta = file.metadata().await?;
    ensure!(meta.is_file(), "the input must be a regular file");
    Ok((file, meta.len()))
}

async fn send(mut args: TransferArgs) -> Result<()> {
    let (file, size) = open_input(&args.file).await?;
    let state = args.state.map(StagedPair::new).transpose()?;
    let (card, verified_at, secret) = read_invite()?;
    let remaining = card.expires_at.saturating_sub(unix_now());
    ensure!(remaining != 0, "invite expired");
    let key = TransportKey::generate();
    let endpoint = args.relay.open_for_pairing(key.clone()).await?;
    let registration = endpoint
        .register_pairing_secret(*secret, INVITE_LIFETIME.min(Duration::from_secs(remaining)))?;
    let pair = endpoint.connect_pairing(&card, &registration).await?;
    let mut stream = pair.open_stream().await?;
    stream.write_all(secret.as_ref()).await?;
    drop(secret);
    stream.finish().await?;
    ensure!(
        stream.read_u8().await? == ACCEPTED,
        "receiver declined pairing"
    );
    let route_secret = pair.paired_route_secret()?;
    if let Some(state) = state {
        state.save(SavedPair::new(
            args.relay,
            &key,
            card.node_id,
            &route_secret,
            Some(SavedCard::new(&card, verified_at)),
        ))?;
    }
    endpoint
        .rendezvous_book()
        .context("paired endpoint needs a tag book")?
        .upsert_paired(card.node_id, *route_secret);
    pair.close().await;
    drop(registration);

    let session = endpoint.connect(&card).await?;
    send_file(&session, file, size).await?;
    endpoint.close().await;
    Ok(())
}

async fn send_file(session: &Session, mut file: File, size: u64) -> Result<()> {
    let mut stream = session.open_stream().await?;
    stream.write_u64(size).await?;
    let digest = copy_and_hash(&mut file, &mut stream, size).await?;
    ensure!(
        file.read(&mut [0]).await? == 0,
        "input grew during transfer"
    );
    stream.write_all(&digest).await?;
    stream.finish().await?;
    let mut received = [0; 32];
    stream.read_exact(&mut received).await?;
    ensure!(
        received == digest,
        "receiver returned a different file digest"
    );
    println!(
        "sent {size} bytes sha256={} path={}",
        hex::encode(digest),
        session.path().status
    );
    Ok(())
}

async fn saved_receive(args: SavedArgs) -> Result<()> {
    let pair = SavedPair::load(&args.state)?;
    let peer = pair.receive_peer()?;
    let staged = stage_output(&args.file)?;
    let endpoint = pair.open(args.relay_admission_key_file.as_deref()).await?;
    wait_for_relay(&endpoint).await?;
    println!("ready for paired transfer");
    let session = endpoint.accept().await?;
    ensure!(
        session.peer() == peer,
        "transfer peer differs from saved peer"
    );
    receive_file(&session, staged, &args.file).await?;
    endpoint.close().await;
    Ok(())
}

async fn saved_send(args: SavedArgs) -> Result<()> {
    let pair = SavedPair::load(&args.state)?;
    let card = pair.send_card()?;
    let (file, size) = open_input(&args.file).await?;
    let endpoint = pair.open(args.relay_admission_key_file.as_deref()).await?;
    let session = endpoint.connect(&card).await?;
    send_file(&session, file, size).await?;
    endpoint.close().await;
    Ok(())
}

async fn copy_and_hash(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    mut remaining: u64,
) -> Result<[u8; 32]> {
    let mut buffer = vec![0; CHUNK];
    let mut hasher = Sha256::new();
    while remaining > 0 {
        let length = remaining.min(buffer.len() as u64) as usize;
        let chunk = &mut buffer[..length];
        reader.read_exact(chunk).await?;
        writer.write_all(chunk).await?;
        hasher.update(chunk);
        remaining -= length as u64;
    }
    Ok(hasher.finalize().into())
}
