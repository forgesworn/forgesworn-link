//! Compare verified native Link and Iroh transfers on loopback.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use iroh::endpoint::{Connection, RecvStream, RelayMode, SendStream, presets};
use iroh::{EndpointAddr, RelayMap, SecretKey, TransportAddr};
use link_endpoint::{
    Endpoint, EndpointConfig, PathStatus, RelaySpec, Session, Stream, TransportKey,
};
use link_relay::{RelayConfig, TlsMaterial};
use sha2::{Digest, Sha256};
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{sleep, timeout};
use zeroize::Zeroizing;

#[path = "../relay.rs"]
mod relay;

const BIND: &str = "127.0.0.1:0";
const ALPN: &[u8] = b"link-iroh-native/0";
const SETUP_TIMEOUT: Duration = Duration::from_secs(15);
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(30);
const BULK_BYTES: usize = 64 * 1024 * 1024;
const COLD_BYTES: usize = 1024;
const WARMUP_TRANSFERS: usize = 2;
static CHUNK: [u8; 64 * 1024] = [0xa5; 64 * 1024];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Case {
    ColdRelay,
    Direct,
    Relay,
}

impl Case {
    fn counts(self, samples: usize) -> (usize, usize, usize) {
        // Fresh pairs, warm-up transfers per pair, measured transfers per pair.
        match self {
            Self::ColdRelay => (samples, 0, 1),
            Self::Direct | Self::Relay => (1, WARMUP_TRANSFERS, samples),
        }
    }

    fn payload_bytes(self) -> usize {
        match self {
            Self::ColdRelay => COLD_BYTES,
            Self::Direct | Self::Relay => BULK_BYTES,
        }
    }
}

trait Streams {
    type Stream: AsyncRead + AsyncWrite + Unpin;
    async fn open(&self) -> Result<Self::Stream>;
    async fn accept(&self) -> Result<Self::Stream>;
}

impl Streams for Session {
    type Stream = Stream;

    async fn open(&self) -> Result<Self::Stream> {
        self.open_stream().await
    }

    async fn accept(&self) -> Result<Self::Stream> {
        self.accept_stream().await
    }
}

impl Streams for Connection {
    type Stream = io::Join<RecvStream, SendStream>;

    async fn open(&self) -> Result<Self::Stream> {
        let (send, recv) = self.open_bi().await?;
        Ok(io::join(recv, send))
    }

    async fn accept(&self) -> Result<Self::Stream> {
        let (send, recv) = self.accept_bi().await?;
        Ok(io::join(recv, send))
    }
}

struct Payload {
    bytes: usize,
    digest: [u8; 32],
}

impl Payload {
    fn new(bytes: usize) -> Self {
        let mut hasher = Sha256::new();
        for offset in (0..bytes).step_by(CHUNK.len()) {
            hasher.update(&CHUNK[..CHUNK.len().min(bytes - offset)]);
        }
        Self {
            bytes,
            digest: hasher.finalize().into(),
        }
    }

    async fn respond(&self, conn: &impl Streams) -> Result<()> {
        let mut stream = conn.accept().await?;
        ensure!(
            stream.read_u64().await? == self.bytes as u64,
            "wrong request size"
        );
        for offset in (0..self.bytes).step_by(CHUNK.len()) {
            stream
                .write_all(&CHUNK[..CHUNK.len().min(self.bytes - offset)])
                .await?;
        }
        stream.shutdown().await?;
        Ok(())
    }

    async fn read_verified(&self, conn: &impl Streams) -> Result<()> {
        let mut stream = conn.open().await?;
        stream.write_u64(self.bytes as u64).await?;
        stream.shutdown().await?;
        let mut buf = vec![0; CHUNK.len()];
        let mut hasher = Sha256::new();
        let mut received = 0;
        loop {
            let bytes = stream.read(&mut buf).await?;
            if bytes == 0 {
                break;
            }
            received += bytes;
            ensure!(received <= self.bytes, "response exceeds requested size");
            hasher.update(&buf[..bytes]);
        }
        let digest: [u8; 32] = hasher.finalize().into();
        ensure!(
            received == self.bytes && digest == self.digest,
            "wrong response payload"
        );
        Ok(())
    }
}

async fn measure<S: Streams>(
    (client, server): (&S, &S),
    (warmup, samples): (usize, usize),
    payload: &Payload,
    cold_dial: Option<(Instant, Duration)>,
    mut verify_path: impl FnMut() -> Result<()>,
) -> Result<()> {
    for round in 0..warmup + samples {
        let (started, startup) = cold_dial.unwrap_or_else(|| (Instant::now(), Duration::ZERO));
        let elapsed = timeout(TRANSFER_TIMEOUT, async {
            let (_, elapsed) = tokio::try_join!(payload.respond(server), async {
                payload.read_verified(client).await?;
                Ok(started.elapsed())
            })?;
            Ok::<_, anyhow::Error>(elapsed)
        })
        .await
        .context("verified transfer timed out")??;
        verify_path()?;
        let phase = if round < warmup { "warmup" } else { "sample" };
        println!(
            "{phase},{},{:.9},{:.9}",
            payload.bytes,
            elapsed.as_secs_f64(),
            startup.as_secs_f64()
        );
    }
    Ok(())
}

async fn wait_path(selected: impl Fn() -> bool) -> Result<()> {
    timeout(SETUP_TIMEOUT, async {
        while !selected() {
            sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .context("expected paths were not selected")
}

async fn link(case: Case, samples: usize, bind: SocketAddr, payload: &Payload) -> Result<()> {
    let tls = TlsMaterial::self_signed(&[bind.ip().to_string()])?;
    let fingerprint = tls.fingerprint();
    let relay = link_relay::start(RelayConfig {
        ws_bind: bind,
        udp_bind: bind,
        tls: Some(tls),
        ..RelayConfig::default()
    })
    .await?;
    let spec = RelaySpec::pinned(relay.url(&bind.ip().to_string()), fingerprint);
    let (pairs, warmup, samples) = case.counts(samples);
    let result = async {
        for _ in 0..pairs {
            let a_key = TransportKey::generate();
            let b_key = TransportKey::generate();
            let a_id = a_key.node_id();
            let b_id = b_key.node_id();
            let shared = Zeroizing::new(TransportKey::generate().seed());
            let config = |key, peer| {
                let mut config = EndpointConfig::new(key);
                config.relays = vec![spec.clone()];
                config.bind = bind;
                config.allow_direct = case == Case::Direct;
                config.net_poll = Duration::ZERO;
                config.paired_routes = Some(HashMap::from([(peer, shared.clone())]));
                config
            };
            let (a_config, b_config) = (config(a_key, b_id), config(b_key, a_id));
            let started = Instant::now();
            let (a, b) = tokio::try_join!(Endpoint::open(a_config), Endpoint::open(b_config))?;
            let (client, server, dialled) = timeout(SETUP_TIMEOUT, async {
                let (a_relay, b_relay) = (a.paths().relay().home(), b.paths().relay().home());
                let (a_ready, b_ready) = tokio::join!(a_relay.wait_up(), b_relay.wait_up());
                ensure!(a_ready.is_some() && b_ready.is_some(), "Link relay refused");
                let card = b.card(Duration::from_secs(300), Vec::new());
                let dialled = Instant::now();
                let (client, server) = tokio::try_join!(a.connect(&card), b.accept())?;
                Ok((client, server, dialled))
            })
            .await
            .context("Link relay registration or QUIC setup timed out")??;
            let expected = if case == Case::Direct {
                PathStatus::Direct
            } else {
                PathStatus::Relayed
            };
            let selected = || {
                let (c, s) = (client.path(), server.path());
                c.status == expected
                    && s.status == expected
                    && (expected != PathStatus::Direct
                        || (c.direct == Some(b.paths().udp_local())
                            && s.direct == Some(a.paths().udp_local())))
            };
            wait_path(selected).await?;
            let transitions = || (client.history().len(), server.history().len());
            let initial = transitions();
            measure(
                (&client, &server),
                (warmup, samples),
                payload,
                (case == Case::ColdRelay).then_some((dialled, dialled.duration_since(started))),
                || {
                    ensure!(selected() && transitions() == initial, "Link path changed");
                    Ok(())
                },
            )
            .await?;
            tokio::join!(a.close(), b.close());
        }
        Ok(())
    }
    .await;
    relay.shutdown();
    result
}

fn selected_bytes(conn: &Connection, addr: &TransportAddr) -> Option<u64> {
    conn.paths()
        .iter()
        .find(|path| path.is_selected() && path.remote_addr() == addr)
        .map(|path| path.stats().udp_rx.bytes)
}

async fn iroh(case: Case, samples: usize, bind: SocketAddr, payload: &Payload) -> Result<()> {
    let (relay, url, tls) = relay::start_relay(bind).await?;
    let (pairs, warmup, samples) = case.counts(samples);
    let bind_udp = case == Case::Direct;
    let result = async {
        for _ in 0..pairs {
            let builder = || {
                let builder = iroh::Endpoint::builder(presets::Minimal)
                    .secret_key(SecretKey::generate())
                    .relay_mode(RelayMode::Custom(RelayMap::from_iter([url.clone()])))
                    .clear_address_lookup()
                    .clear_ip_transports()
                    .ca_tls_config(tls.clone())
                    .alpns(vec![ALPN.to_vec()]);
                Ok::<_, anyhow::Error>(if bind_udp {
                    builder.bind_addr(bind)?
                } else {
                    builder
                })
            };
            let (a_builder, b_builder) = (builder()?, builder()?);
            let started = Instant::now();
            let (a, b) = tokio::try_join!(a_builder.bind(), b_builder.bind())?;
            let mut address = EndpointAddr::new(b.id()).with_relay_url(url.clone());
            let (client_path, server_path) = if bind_udp {
                let [a_udp] = a.bound_sockets()[..] else {
                    bail!("expected one Iroh client UDP socket");
                };
                let [b_udp] = b.bound_sockets()[..] else {
                    bail!("expected one Iroh server UDP socket");
                };
                address = address.with_ip_addr(b_udp);
                (TransportAddr::Ip(b_udp), TransportAddr::Ip(a_udp))
            } else {
                ensure!(
                    a.bound_sockets().is_empty() && b.bound_sockets().is_empty(),
                    "unexpected Iroh UDP socket in relay-only mode"
                );
                (
                    TransportAddr::Relay(url.clone()),
                    TransportAddr::Relay(url.clone()),
                )
            };
            let (client, server, dialled) = timeout(SETUP_TIMEOUT, async {
                tokio::join!(a.online(), b.online());
                let dialled = Instant::now();
                let (client, server) = tokio::try_join!(
                    async { Ok::<_, anyhow::Error>(a.connect(address, ALPN).await?) },
                    async { Ok(b.accept().await.context("Iroh accept")?.await?) }
                )?;
                Ok::<_, anyhow::Error>((client, server, dialled))
            })
            .await
            .context("Iroh relay registration or QUIC setup timed out")??;
            let received = || selected_bytes(&client, &client_path);
            let selected =
                || received().is_some() && selected_bytes(&server, &server_path).is_some();
            wait_path(selected).await?;
            let mut previous_bytes = received().context("missing selected Iroh client path")?;
            measure(
                (&client, &server),
                (warmup, samples),
                payload,
                (case == Case::ColdRelay).then_some((dialled, dialled.duration_since(started))),
                || {
                    let bytes = received().context("Iroh client path changed")?;
                    ensure!(
                        selected() && bytes.saturating_sub(previous_bytes) >= payload.bytes as u64,
                        "expected Iroh path did not carry the response"
                    );
                    previous_bytes = bytes;
                    Ok(())
                },
            )
            .await?;
            tokio::join!(a.close(), b.close());
        }
        Ok(())
    }
    .await;
    let stopped = relay.shutdown().await;
    result?;
    stopped?;
    Ok(())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let implementation = args.next().context("use link or iroh")?;
    let case = match args.next().as_deref() {
        Some("cold-relay") => Case::ColdRelay,
        Some("direct") => Case::Direct,
        Some("relay") => Case::Relay,
        _ => bail!("use cold-relay, direct or relay"),
    };
    let samples = args.next().context("give a sample count")?.parse()?;
    ensure!(
        samples > 0 && args.next().is_none(),
        "give one positive sample count"
    );
    let bind = BIND.parse()?;
    let payload = Payload::new(case.payload_bytes());
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("TLS crypto provider");
    match implementation.as_str() {
        "link" => link(case, samples, bind, &payload).await,
        "iroh" => iroh(case, samples, bind, &payload).await,
        _ => bail!("use link or iroh"),
    }
}
