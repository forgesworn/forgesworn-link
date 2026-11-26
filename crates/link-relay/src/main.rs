//! The `link-relay` binary: WebSocket datagram relay plus UDP reflector.

use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use clap::Parser;
use link_core::RelayAdmissionKey;
use link_core::admission::RELAY_ADMISSION_KEY_BYTES;
use link_relay::{MAX_ADMISSION_KEYS, RelayAdmission, RelayConfig, TlsMaterial};
use tokio::io::AsyncReadExt;
use tracing_subscriber::{filter::filter_fn, prelude::*};
use zeroize::Zeroizing;

#[derive(Parser, Debug)]
#[command(
    name = "link-relay",
    about = "ForgeSworn Link Phase 0 relay and reflector"
)]
struct Args {
    /// Address for the WebSocket listener.
    #[arg(long, default_value = "127.0.0.1:0")]
    ws_bind: SocketAddr,
    /// Address for the UDP reflector.
    #[arg(long, default_value = "127.0.0.1:0")]
    udp_bind: SocketAddr,
    /// Host a node may have signed against.  Repeatable, lowercase, no port.
    #[arg(long = "host", default_values_t = [String::from("127.0.0.1")])]
    hosts: Vec<String>,
    /// Serve plain ws:// instead of wss://.  Only acceptable on loopback.
    #[arg(long)]
    insecure_ws: bool,
    /// Require an operator key. Reload this private allowlist while running.
    #[arg(long, value_name = "FILE")]
    admission_keys_file: Option<PathBuf>,
    /// Per-session outbound byte budget.  Zero means no budget.
    #[arg(long, default_value_t = 0)]
    bytes_per_second: u64,
    /// Cap on concurrent sessions, including handshakes.
    #[arg(long, default_value_t = 1024)]
    max_sessions: usize,
    /// Cap on concurrent sessions from one source address.  Zero means none.
    #[arg(long, default_value_t = 16)]
    sessions_per_source: usize,
    /// Reflector replies per source address per second.
    #[arg(long, default_value_t = 20.0)]
    reflector_per_second: f64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        // WebSocket trace events can contain frame contents. Keep dependency
        // diagnostics out of the journal even if the operator selects TRACE.
        .with(
            tracing_subscriber::fmt::layer().with_filter(filter_fn(|metadata| {
                metadata.target() == link_relay::LOG_TARGET
            })),
        )
        .init();

    let args = Args::parse();
    let tls = if args.insecure_ws {
        None
    } else {
        Some(TlsMaterial::self_signed(&args.hosts)?)
    };
    let config = RelayConfig {
        ws_bind: args.ws_bind,
        udp_bind: args.udp_bind,
        hosts: args.hosts.clone(),
        tls,
        bytes_per_second: args.bytes_per_second,
        max_sessions: args.max_sessions,
        max_sessions_per_source: args.sessions_per_source,
        reflector_per_second: args.reflector_per_second,
    };

    let admission = match args.admission_keys_file {
        Some(path) => {
            let policy = RelayAdmission::default();
            reload_keys(&path, &policy).await?;
            Some((path, policy))
        }
        None => None,
    };
    let handle = match &admission {
        Some((_, policy)) => link_relay::start_with_admission(config, policy.clone()).await?,
        None => link_relay::start(config).await?,
    };
    let host = args
        .hosts
        .first()
        .cloned()
        .unwrap_or_else(|| "127.0.0.1".into());
    println!("relay_url {}", handle.url(&host));
    println!("reflector {}", handle.udp_addr);
    match &handle.tls_fingerprint {
        Some(fingerprint) => println!("tls_sha256 {fingerprint}"),
        None => println!("tls none (plain ws, loopback only)"),
    }

    let stopped = match admission {
        Some((path, policy)) => watch_admission_file(&path, &policy).await,
        None => link_relay::wait_for_ctrl_c().await,
    };
    handle.shutdown();
    stopped?;
    Ok(())
}

async fn reload_keys(path: &Path, policy: &RelayAdmission) -> Result<()> {
    const MAX_BYTES: u64 = (MAX_ADMISSION_KEYS * (2 * RELAY_ADMISSION_KEY_BYTES + 2)) as u64;
    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .context("opening the admission allowlist")?;
    ensure!(
        metadata.is_file(),
        "the admission allowlist must be a regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "the admission allowlist must be owner-only"
        );
    }
    let mut bytes = Zeroizing::new(Vec::new());
    tokio::fs::File::open(path)
        .await?
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .await?;
    ensure!(
        bytes.len() as u64 <= MAX_BYTES,
        "the admission allowlist is too large"
    );
    let keys = std::str::from_utf8(&bytes)?
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            RelayAdmissionKey::from_hex(line).context("invalid hex key in admission allowlist")
        })
        .collect::<Result<Vec<_>>>()?;
    policy.replace_keys(keys)
}

async fn watch_admission_file(path: &Path, policy: &RelayAdmission) -> io::Result<()> {
    let shutdown = link_relay::wait_for_ctrl_c();
    tokio::pin!(shutdown);
    let mut ticks = tokio::time::interval(Duration::from_secs(1));
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut closed = false;
    loop {
        tokio::select! {
            result = &mut shutdown => return result,
            _ = ticks.tick() => {}
        }
        if reload_keys(path, policy).await.is_err() {
            if !closed {
                policy
                    .replace_keys(Vec::new())
                    .expect("empty admission allowlist");
                tracing::warn!(target: link_relay::LOG_TARGET, "admission allowlist unavailable; relay access closed");
                closed = true;
            }
        } else if closed {
            tracing::info!(target: link_relay::LOG_TARGET, "admission allowlist restored");
            closed = false;
        }
    }
}
