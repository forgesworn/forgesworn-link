//! Run the native Link probe's silent UDP loss case with Iroh.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use iroh::endpoint::{Connection, Endpoint, RelayMode, presets};
use iroh::{EndpointAddr, RelayMap, RelayUrl, TransportAddr};
use iroh_relay::server::{CertConfig, RelayConfig, Server, ServerConfig, TlsConfig};
use iroh_relay::tls::CaTlsConfig;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};

#[path = "../../../crates/link-endpoint/examples/support/gateway.rs"]
mod gateway;
use gateway::{Gateway, IPV4, IPV6};

const ALPN: &[u8] = b"link-iroh-recovery/0";
const PAYLOAD: [u8; 1024] = [0xa5; 1024];

async fn start_relay() -> Result<(Server, RelayUrl, CaTlsConfig)> {
    let bind: SocketAddr = IPV4.parse()?;
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec![bind.ip().to_string()])?;
    let cert = cert.der().clone();
    let ca_tls = CaTlsConfig::custom_roots([cert.clone()]);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    let mut relay_config = RelayConfig::new(bind);
    relay_config.tls = Some(TlsConfig::new(bind, CertConfig::Manual { server_config }));
    let mut config = ServerConfig::default();
    config.relay = Some(relay_config);
    let relay = Server::spawn(config).await?;
    let addr = relay.https_addr().context("missing Iroh relay address")?;
    Ok((relay, format!("https://{addr}").parse()?, ca_tls))
}

fn selected(conn: &Connection, addr: &TransportAddr) -> bool {
    conn.paths()
        .iter()
        .any(|path| path.is_selected() && path.remote_addr() == addr)
}

async fn wait_path(
    (a, b): (&Connection, &Connection),
    (addr_a, addr_b): (TransportAddr, TransportAddr),
) -> Result<()> {
    timeout(Duration::from_secs(18), async {
        while !(selected(a, &addr_a) && selected(b, &addr_b)) {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .with_context(|| format!("Iroh did not select {addr_a} and {addr_b}"))
}

async fn serve(conn: &Connection) -> Result<()> {
    for _ in 0..2 {
        let (mut send, mut recv) = conn.accept_bi().await?;
        let mut size = [0; 8];
        recv.read_exact(&mut size).await?;
        ensure!(
            u64::from_be_bytes(size) == PAYLOAD.len() as u64,
            "wrong request"
        );
        send.write_all(&PAYLOAD).await?;
        send.finish()?;
    }
    Ok(())
}

async fn transfer(conn: &Connection) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(&(PAYLOAD.len() as u64).to_be_bytes())
        .await?;
    send.finish()?;
    let mut bytes = [0; PAYLOAD.len()];
    recv.read_exact(&mut bytes).await?;
    ensure!(
        recv.read(&mut [0]).await?.is_none(),
        "response exceeds requested size"
    );
    ensure!(
        Sha256::digest(bytes) == Sha256::digest(PAYLOAD),
        "wrong payload"
    );
    Ok(())
}

async fn recover() -> Result<(Duration, Duration)> {
    let (_relay, url, ca_tls) = start_relay().await?;
    let relay_mode = RelayMode::Custom(RelayMap::from_iter([url.clone()]));
    let builder = |bind| {
        Endpoint::builder(presets::Minimal)
            .relay_mode(relay_mode.clone())
            .clear_address_lookup()
            .clear_ip_transports()
            .ca_tls_config(ca_tls.clone())
            .alpns(vec![ALPN.to_vec()])
            .bind_addr(bind)
    };
    let (a, b) = tokio::try_join!(builder(IPV4)?.bind(), builder(IPV6)?.bind())?;
    timeout(Duration::from_secs(5), async {
        tokio::join!(a.online(), b.online());
    })
    .await?;
    let relay_addr = || TransportAddr::Relay(url.clone());
    let (sending, receiving) = timeout(Duration::from_secs(15), async {
        tokio::join!(
            a.connect(EndpointAddr::new(b.id()).with_relay_url(url.clone()), ALPN),
            async { Ok::<_, anyhow::Error>(b.accept().await.context("Iroh accept")?.await?) }
        )
    })
    .await?;
    let sending = sending?;
    let receiving = receiving?;
    let connections = (&sending, &receiving);
    wait_path(connections, (relay_addr(), relay_addr())).await?;

    let [bind_a] = a.bound_sockets()[..] else {
        anyhow::bail!("unexpected Iroh dialler sockets");
    };
    let [bind_b] = b.bound_sockets()[..] else {
        anyhow::bail!("unexpected Iroh listener sockets");
    };
    let gateway = Gateway::start(bind_a, bind_b).await?;
    tokio::join!(
        a.add_external_addr(gateway.addrs.1),
        b.add_external_addr(gateway.addrs.0)
    );
    wait_path(
        connections,
        (
            TransportAddr::Ip(gateway.addrs.0),
            TransportAddr::Ip(gateway.addrs.1),
        ),
    )
    .await?;
    ensure!(
        [&sending, &receiving]
            .iter()
            .all(|c| c.paths().iter().any(|p| p.is_relay())),
        "Iroh relay path must be available before the outage"
    );

    let exercise = async {
        timeout(Duration::from_secs(5), transfer(&sending)).await??;
        let start = Instant::now();
        gateway.blackhole();
        tokio::try_join!(
            async {
                timeout(Duration::from_secs(45), transfer(&sending)).await??;
                Ok::<_, anyhow::Error>(start.elapsed())
            },
            async {
                wait_path(connections, (relay_addr(), relay_addr())).await?;
                Ok::<_, anyhow::Error>(start.elapsed())
            }
        )
    };
    let ((), elapsed) = tokio::try_join!(serve(&receiving), exercise)?;
    gateway.check()?;
    tokio::join!(a.close(), b.close());
    Ok(elapsed)
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("TLS crypto provider");
    let mut args = std::env::args().skip(1);
    let samples = args
        .next()
        .map(|arg| arg.parse())
        .transpose()?
        .unwrap_or(10);
    ensure!(
        samples > 0 && args.next().is_none(),
        "provide a positive sample count"
    );
    for offset in (0..samples).step_by(4) {
        let mut batch = JoinSet::new();
        for _ in offset..samples.min(offset + 4) {
            batch.spawn(recover());
        }
        while let Some(sample) = batch.join_next().await {
            let (response, selected_path) = sample??;
            println!(
                "recovery,blackhole,{:.4},{:.4},{:.4}",
                response.max(selected_path).as_secs_f64() * 1000.0,
                response.as_secs_f64() * 1000.0,
                selected_path.as_secs_f64() * 1000.0
            );
        }
    }
    Ok(())
}
