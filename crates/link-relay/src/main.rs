//! The `link-relay` binary: WebSocket datagram relay plus UDP reflector.

use std::net::SocketAddr;

use clap::Parser;
use link_relay::{RelayConfig, TlsMaterial};

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
    /// Per-session outbound byte budget.  Zero means no budget.
    #[arg(long, default_value_t = 0)]
    bytes_per_second: u64,
    /// Cap on concurrent authenticated sessions.
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
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
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

    let handle = link_relay::start(config).await?;
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

    link_relay::wait_for_ctrl_c().await?;
    handle.shutdown();
    Ok(())
}
