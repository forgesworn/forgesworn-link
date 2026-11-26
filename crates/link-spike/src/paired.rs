//! One file transfer after an invite-authenticated Link pairing.

use std::io::{BufRead, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Args;
use link_core::card::{Card, MAX_CARD_BYTES, VerifyContext};
use link_core::id::TransportKey;
use link_core::rendezvous::PAIRING_SECRET_BYTES;
use link_endpoint::{AcceptedSession, Endpoint, EndpointConfig, RelaySpec};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;
use zeroize::Zeroizing;

use super::{CHUNK, unix_now};

const INVITE_PREFIX: &str = "fsl-file-1.";
const INVITE_LIFETIME: Duration = Duration::from_secs(300);
const MAX_INVITE_TEXT: u64 = 6000;
const ACCEPTED: u8 = 1;

#[derive(Args, Debug)]
pub(super) struct TransferArgs {
    /// The owner-approved relay URL, including the /link path.
    #[arg(long)]
    relay: String,
    /// SHA-256 of the relay certificate for a self-signed relay.
    #[arg(long)]
    relay_cert_sha256: Option<String>,
    /// The input or output file, chosen locally.
    #[arg(value_name = "FILE")]
    file: PathBuf,
}

impl TransferArgs {
    async fn open_endpoint(&self) -> Result<Endpoint> {
        ensure!(
            self.relay.starts_with("wss://"),
            "the relay must use wss://"
        );
        let relay = match &self.relay_cert_sha256 {
            Some(pin) => RelaySpec::pinned(&self.relay, pin),
            None => RelaySpec::plain(&self.relay),
        };
        let mut config = EndpointConfig::new(TransportKey::generate());
        config.relays = vec![relay];
        Endpoint::open(config).await
    }
}

fn invite_text(card: &Card, secret: &[u8; PAIRING_SECRET_BYTES]) -> Zeroizing<String> {
    let mut bytes = Zeroizing::new(Vec::from(secret.as_slice()));
    bytes.extend(card.as_bytes());
    let mut text = Zeroizing::new(String::from(INVITE_PREFIX));
    URL_SAFE_NO_PAD.encode_string(bytes.as_slice(), &mut text);
    text
}

fn read_invite() -> Result<(Card, Zeroizing<[u8; PAIRING_SECRET_BYTES]>)> {
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
    let card = Card::verify(card, &VerifyContext::new(unix_now()))?;
    Ok((card, Zeroizing::new(*secret)))
}

pub(super) async fn receive(args: TransferArgs) -> Result<()> {
    ensure!(!args.file.exists(), "the output file already exists");
    let parent = args
        .file
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let staged = tempfile::NamedTempFile::new_in(parent)?;
    let endpoint = args.open_endpoint().await?;
    let mut secret = Zeroizing::new([0; PAIRING_SECRET_BYTES]);
    OsRng.fill_bytes(secret.as_mut());
    let registration = endpoint.register_pairing_secret(*secret, INVITE_LIFETIME)?;
    timeout(
        Duration::from_secs(15),
        endpoint.paths().relay().home().wait_up(),
    )
    .await
    .context("waiting for the approved relay")?
    .context("approved relay unavailable")?;
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
    endpoint
        .rendezvous_book()
        .context("paired endpoint needs a tag book")?
        .upsert_paired(peer, *pair.paired_route_secret()?);
    drop(registration);
    drop(secret);
    stream.write_u8(ACCEPTED).await?;
    stream.finish().await?;

    let session = timeout(Duration::from_secs(30), endpoint.accept())
        .await
        .context("waiting for the paired transfer")??;
    ensure!(
        session.peer() == peer,
        "transfer peer differs from paired peer"
    );
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
        .persist_noclobber(&args.file)
        .context("saving the verified file")?;
    stream.write_all(&digest).await?;
    stream.finish().await?;
    let _ = timeout(Duration::from_secs(5), stream.send.stopped()).await;
    println!(
        "received {size} bytes sha256={} path={}",
        hex::encode(digest),
        session.path().status
    );
    endpoint.close().await;
    Ok(())
}

pub(super) async fn send(args: TransferArgs) -> Result<()> {
    let mut file = File::open(&args.file).await?;
    let meta = file.metadata().await?;
    ensure!(meta.is_file(), "the input must be a regular file");
    let size = meta.len();
    let (card, secret) = read_invite()?;
    let remaining = card.expires_at.saturating_sub(unix_now());
    ensure!(remaining != 0, "invite expired");
    let endpoint = args.open_endpoint().await?;
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
    endpoint
        .rendezvous_book()
        .context("paired endpoint needs a tag book")?
        .upsert_paired(card.node_id, *pair.paired_route_secret()?);
    pair.close().await;
    drop(registration);

    let session = endpoint.connect(&card).await?;
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
