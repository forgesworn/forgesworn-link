//! `link-spike`: the command line surface for the Phase 0 spike.
//!
//! Nothing here is a product.  It exists so a person can run the contract by
//! hand on two machines and record what actually happened.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use clap::{Args, Parser, Subcommand};
use link_core::card::{Card, Hint, VerifyContext};
use link_core::id::TransportKey;
use link_core::path::PathStatus;
use link_endpoint::{Endpoint, EndpointConfig, RelaySpec, Session};
use sha2::{Digest, Sha256};

const CHUNK: usize = 64 * 1024;

#[derive(Parser, Debug)]
#[command(name = "link-spike", about = "ForgeSworn Link Phase 0 spike")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Mint a transport key and print its node ID.
    Keygen(Keygen),
    /// Print a signed FSL-CARD-1 for a key.
    Card(CardArgs),
    /// Accept sessions and sink streams, printing a PathReport on every change.
    Serve(ServeArgs),
    /// Connect to a peer card and stream deterministic bytes over one stream.
    Send(SendArgs),
}

#[derive(Args, Debug)]
struct Keygen {
    /// Where to write the 64 character seed.  Created with owner-only permissions.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
struct KeyArgs {
    /// File holding a 64 character hex seed.
    #[arg(long, env = "LINK_KEY_FILE")]
    key_file: Option<PathBuf>,
    /// Hex seed on the command line.  Convenient, and it leaks to the process list.
    #[arg(long, env = "LINK_KEY_HEX")]
    key_hex: Option<String>,
}

impl KeyArgs {
    fn load(&self) -> anyhow::Result<TransportKey> {
        let text = match (&self.key_file, &self.key_hex) {
            (Some(path), _) => std::fs::read_to_string(path)?,
            (None, Some(hex_text)) => hex_text.clone(),
            (None, None) => anyhow::bail!("pass --key-file or --key-hex"),
        };
        let raw = hex::decode(text.trim())?;
        let seed: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("a seed is 32 bytes of hex"))?;
        Ok(TransportKey::from_seed(seed))
    }
}

#[derive(Args, Debug, Clone)]
struct RelayArgs {
    /// Relay URL.  Repeatable; the order is the failover order.
    #[arg(long = "relay")]
    relays: Vec<String>,
    /// SHA-256 of a wss:// relay's DER leaf, positionally matched to --relay.
    #[arg(long = "relay-cert-sha256")]
    relay_certs: Vec<String>,
    /// Accept any wss:// relay certificate.  Development only.
    #[arg(long)]
    relay_insecure_tls: bool,
}

impl RelayArgs {
    fn specs(&self) -> Vec<RelaySpec> {
        self.relays
            .iter()
            .enumerate()
            .map(|(index, url)| RelaySpec {
                url: url.clone(),
                cert_sha256: self.relay_certs.get(index).cloned(),
                insecure_tls: self.relay_insecure_tls,
            })
            .collect()
    }
}

#[derive(Args, Debug)]
struct CardArgs {
    #[command(flatten)]
    key: KeyArgs,
    #[command(flatten)]
    relay: RelayArgs,
    /// Card lifetime in seconds, at most 604800.
    #[arg(long, default_value_t = 3600)]
    ttl: u64,
    /// UDP candidate hint.  Only include one with the owner's consent.
    #[arg(long = "udp")]
    udp: Vec<SocketAddr>,
    /// Onion hint as `<56 character host>:<port>`, without `.onion`.
    #[arg(long = "onion")]
    onion: Vec<String>,
    /// Serial.  Must be strictly above every serial this key has ever signed.
    #[arg(long)]
    serial: Option<u64>,
}

#[derive(Args, Debug)]
struct ServeArgs {
    #[command(flatten)]
    key: KeyArgs,
    #[command(flatten)]
    relay: RelayArgs,
    /// Owner declines direct paths: stay on the relay whatever the peer offers.
    #[arg(long)]
    no_direct: bool,
    /// UDP reflector, usually the relay host with the reflector port.
    #[arg(long)]
    reflector: Option<SocketAddr>,
    /// Local UDP bind for direct paths and probes.
    #[arg(long, default_value = "0.0.0.0:0")]
    bind: SocketAddr,
    /// Echo the payload back instead of only returning its digest.
    #[arg(long)]
    echo: bool,
    /// Stop after this many sessions.  Zero means run until interrupted.
    #[arg(long, default_value_t = 0)]
    sessions: usize,
}

#[derive(Args, Debug)]
struct SendArgs {
    #[command(flatten)]
    key: KeyArgs,
    #[command(flatten)]
    relay: RelayArgs,
    /// The peer's card, base64 or hex.
    #[arg(long)]
    card: String,
    /// Mebibytes to stream over one QUIC stream.
    #[arg(long, default_value_t = 8)]
    mib: usize,
    #[arg(long)]
    no_direct: bool,
    #[arg(long)]
    reflector: Option<SocketAddr>,
    #[arg(long, default_value = "0.0.0.0:0")]
    bind: SocketAddr,
    /// Settle on the relay for this many seconds before probing for a direct path.
    #[arg(long, default_value_t = 0)]
    settle: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();

    match Cli::parse().command {
        Command::Keygen(args) => keygen(args),
        Command::Card(args) => card(args),
        Command::Serve(args) => serve(args).await,
        Command::Send(args) => send(args).await,
    }
}

fn keygen(args: Keygen) -> anyhow::Result<()> {
    let key = TransportKey::generate();
    let seed = hex::encode(key.seed());
    if let Some(path) = &args.out {
        std::fs::write(path, format!("{seed}\n"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        eprintln!("wrote the seed to {}", path.display());
    } else {
        println!("seed_hex {seed}");
    }
    println!("node_id_hex {}", key.node_id().to_hex());
    println!("node_id_base32 {}", key.node_id().to_base32());
    println!("synthetic {}", key.node_id().synthetic_addr());
    Ok(())
}

fn card(args: CardArgs) -> anyhow::Result<()> {
    let key = args.key.load()?;
    let now = unix_now();
    let mut hints: Vec<Hint> = args
        .relay
        .relays
        .iter()
        .map(|url| Hint::relay(url))
        .collect();
    hints.extend(args.udp.iter().copied().map(Hint::udp));
    for entry in &args.onion {
        let (host, port) = entry
            .rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("onion hints look like <host>:<port>"))?;
        anyhow::ensure!(host.len() == 56, "a v3 onion host is 56 characters");
        hints.push(Hint::onion(host, port.parse()?));
    }
    anyhow::ensure!(
        hints.len() <= link_core::card::MAX_HINTS,
        "at most 16 hints"
    );

    let ttl = args.ttl.clamp(1, link_core::card::MAX_LIFETIME_SECONDS);
    let card = Card::sign(&key, now, now + ttl, args.serial.unwrap_or(now), hints);

    // Verify what was just signed, so a bad card never leaves this process.
    Card::verify(
        card.as_bytes(),
        &VerifyContext::new(now).expecting(key.node_id()),
    )
    .map_err(|e| anyhow::anyhow!("the freshly signed card does not verify: {e}"))?;

    println!("node_id_base32 {}", card.node_id.to_base32());
    println!("expires_at {}", card.expires_at);
    println!("serial {}", card.serial);
    println!("card_hex {}", hex::encode(card.as_bytes()));
    println!("card_b64 {}", BASE64.encode(card.as_bytes()));
    Ok(())
}

fn parse_card(text: &str) -> anyhow::Result<Card> {
    let text = text.trim();
    let bytes = match hex::decode(text) {
        Ok(bytes) => bytes,
        Err(_) => BASE64.decode(text)?,
    };
    let ctx = VerifyContext::new(unix_now());
    Card::verify(&bytes, &ctx).map_err(|e| anyhow::anyhow!("{e}"))
}

async fn serve(args: ServeArgs) -> anyhow::Result<()> {
    let key = args.key.load()?;
    let mut config = EndpointConfig::new(key);
    config.relays = args.relay.specs();
    config.allow_direct = !args.no_direct;
    config.reflector = args.reflector;
    config.bind = args.bind;
    let endpoint = Arc::new(Endpoint::open(config).await?);

    println!("node_id_base32 {}", endpoint.node_id().to_base32());
    println!("udp_bind {}", endpoint.paths().udp_local());
    let card = endpoint.card(Duration::from_secs(3600), Vec::new());
    println!("card_b64 {}", BASE64.encode(card.as_bytes()));

    let mut served = 0usize;
    loop {
        let session = match endpoint.accept().await {
            Ok(session) => Arc::new(session),
            Err(reason) => {
                println!(
                    "{}",
                    serde_json::json!({ "event": "accept_failed", "reason": reason.to_string() })
                );
                return Err(anyhow::anyhow!("accept failed: {reason}"));
            }
        };
        eprintln!("session from {}", session.peer());
        tokio::spawn(watch_path(session.clone()));
        let echo = args.echo;
        let handle = tokio::spawn(async move {
            loop {
                match serve_stream(&session, echo).await {
                    Ok(bytes) => eprintln!("stream done, {bytes} bytes"),
                    Err(e) => {
                        eprintln!("stream ended: {e}");
                        break;
                    }
                }
            }
            println!("{}", report_json(&session, "final"));
        });
        served += 1;
        if args.sessions != 0 && served >= args.sessions {
            let _ = handle.await;
            return Ok(());
        }
    }
}

async fn serve_stream(session: &Session, echo: bool) -> anyhow::Result<usize> {
    let mut stream = session.accept_stream().await?;
    let mut header = [0u8; 8];
    stream.recv.read_exact(&mut header).await?;
    let total = u64::from_be_bytes(header) as usize;

    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut read = 0usize;
    while read < total {
        let len = buf.len().min(total - read);
        stream.recv.read_exact(&mut buf[..len]).await?;
        hasher.update(&buf[..len]);
        if echo {
            stream.send.write_all(&buf[..len]).await?;
        }
        read += len;
    }
    let digest = hasher.finalize();
    stream.send.write_all(&digest).await?;
    stream.send.finish()?;
    println!(
        "{}",
        serde_json::json!({
            "event": "received",
            "bytes": read,
            "sha256": hex::encode(digest),
            "path": serde_json::to_value(session.path())?,
        })
    );
    Ok(read)
}

async fn send(args: SendArgs) -> anyhow::Result<()> {
    let key = args.key.load()?;
    let card = parse_card(&args.card)?;
    let mut config = EndpointConfig::new(key);
    config.relays = args.relay.specs();
    config.allow_direct = !args.no_direct;
    config.reflector = args.reflector;
    config.bind = args.bind;
    config.probe_delay = Duration::from_secs(args.settle);
    let endpoint = Endpoint::open(config).await?;

    let session = Arc::new(
        endpoint
            .connect(&card)
            .await
            .map_err(|reason| anyhow::anyhow!("connect failed: {reason}"))?,
    );
    println!("{}", report_json(&session, "connected"));
    tokio::spawn(watch_path(session.clone()));

    let total = args.mib * 1024 * 1024;
    let mut stream = session.open_stream().await?;
    stream.send.write_all(&(total as u64).to_be_bytes()).await?;

    let mut hasher = Sha256::new();
    let mut state = 0x5eed_0000_0000_0001u64;
    let mut buf = vec![0u8; CHUNK];
    let mut written = 0usize;
    while written < total {
        let len = buf.len().min(total - written);
        fill(&mut state, &mut buf[..len]);
        hasher.update(&buf[..len]);
        stream.send.write_all(&buf[..len]).await?;
        written += len;
    }
    stream.send.finish()?;
    let sent = hasher.finalize();
    println!("sent_sha256 {}", hex::encode(sent));

    let mut echoed = [0u8; 32];
    stream.recv.read_exact(&mut echoed).await?;
    println!("peer_sha256 {}", hex::encode(echoed));
    let matched = echoed == sent.as_slice();
    println!(
        "{}",
        serde_json::json!({
            "event": "final",
            "bytes": total,
            "digest_match": matched,
            "path": serde_json::to_value(session.path())?,
        })
    );
    session.close(0).await;
    anyhow::ensure!(matched, "the peer digest does not match what was sent");
    Ok(())
}

/// Print a PathReport whenever the status changes, spec 4.3.
async fn watch_path(session: Arc<Session>) {
    let mut last: Option<PathStatus> = None;
    loop {
        let report = session.path();
        if last != Some(report.status) {
            last = Some(report.status);
            match serde_json::to_string(&report) {
                Ok(json) => println!("{json}"),
                Err(e) => eprintln!("cannot serialise the path report: {e}"),
            }
            if matches!(report.status, PathStatus::Failed(_)) {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn report_json(session: &Session, event: &str) -> String {
    serde_json::json!({
        "event": event,
        "peer": session.peer().to_base32(),
        "path": serde_json::to_value(session.path()).unwrap_or(serde_json::Value::Null),
    })
    .to_string()
}

/// Deterministic payload, so both ends can check the same bytes without a fixture.
fn fill(state: &mut u64, buf: &mut [u8]) {
    for chunk in buf.chunks_mut(8) {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        let bytes = x.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
