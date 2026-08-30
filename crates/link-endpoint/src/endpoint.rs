//! `Endpoint` of spec section 5: the transport key, the path socket and the relays.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use link_core::card::{Card, Hint};
use link_core::id::{NodeId, TransportKey, node_id_from_cert_der};
use link_core::path::FailReason;
use link_core::tls::{
    PinnedClientVerifier, PinnedServerVerifier, RefusingClientVerifier, node_certificate,
};
use quinn::VarInt;
use tracing::{info, warn};

use crate::path_socket::{Paths, build};
use crate::relay_client::{RelaySpec, RelayStatus};
use crate::rendezvous_book::{RendezvousPeer, TagBook};
use crate::session::Session;

/// Cap the MTU so a QUIC packet always fits the relay's 1..=1350 frame bound.
pub const MAX_MTU: u16 = 1350;
const ALPN: &[u8] = b"fsl/0";
/// Bounded per-stream and per-connection flow control, so memory does not grow
/// with transfer size.
const STREAM_RECEIVE_WINDOW: u64 = 1 << 20;
const CONNECTION_RECEIVE_WINDOW: u64 = 4 << 20;

#[derive(Clone, Debug)]
pub struct EndpointConfig {
    pub key: TransportKey,
    pub relays: Vec<RelaySpec>,
    /// Owner consent for direct paths.  Relay-only is a first-class configuration.
    pub allow_direct: bool,
    /// Real UDP bind for direct paths and probes.
    pub bind: SocketAddr,
    /// Optional reflector for the reflexive candidate, spec 3.2.
    pub reflector: Option<SocketAddr>,
    /// Settle on the relay for this long before the first probing round.  Not in
    /// the spec: it exists so a test can prove the relay carried a transfer
    /// before the upgrade, and so a product can defer probing.
    pub probe_delay: Duration,
    /// Tag-mode rendezvous material per peer, spec 9.  `Some` switches every
    /// relay session to tag registration, so no node ID, Nostr key or
    /// signature ever reaches a relay; `None` keeps the deployed identity
    /// mode.  The shell computes the material from the pair's cards and Nostr
    /// keys; the transport never touches Nostr.
    pub rendezvous: Option<HashMap<NodeId, RendezvousPeer>>,
}

impl EndpointConfig {
    pub fn new(key: TransportKey) -> Self {
        EndpointConfig {
            key,
            relays: Vec::new(),
            allow_direct: true,
            bind: "0.0.0.0:0".parse().expect("literal"),
            reflector: None,
            probe_delay: Duration::ZERO,
            rendezvous: None,
        }
    }
}

pub struct Endpoint {
    key: TransportKey,
    paths: Arc<Paths>,
    quic: quinn::Endpoint,
    config: EndpointConfig,
    serial: AtomicU64,
}

impl Endpoint {
    /// Bind the sockets and start the relay driver.  Does not wait for a relay.
    pub async fn open(config: EndpointConfig) -> anyhow::Result<Endpoint> {
        let book = config
            .rendezvous
            .clone()
            .map(|peers| Arc::new(TagBook::new(peers)));
        let (socket, paths) =
            build(config.key.clone(), config.bind, config.relays.clone(), book).await?;

        let mut endpoint_config = quinn::EndpointConfig::default();
        endpoint_config.max_udp_payload_size(MAX_MTU)?;

        let leaf = node_certificate(&config.key)?;
        let mut server_crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        // The default server config can never authenticate anyone: every real
        // inbound handshake goes through accept_with and a per-connection pin.
        .with_client_cert_verifier(RefusingClientVerifier::new())
        .with_single_cert(vec![leaf.cert_der.clone()], leaf.key_der.clone_key())?;
        server_crypto.alpn_protocols = vec![ALPN.to_vec()];
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
        ));
        server_config.transport_config(Arc::new(transport_config()));

        let quic = quinn::Endpoint::new_with_abstract_socket(
            endpoint_config,
            Some(server_config),
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;

        let serial_seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let endpoint = Endpoint {
            key: config.key.clone(),
            paths,
            quic,
            config,
            serial: AtomicU64::new(serial_seed),
        };

        if let Some(reflector) = endpoint.config.reflector {
            endpoint.paths.query_reflector(reflector);
            // Give the reflector a moment before the first card or candidate list.
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        info!(
            node = %endpoint.node_id(),
            synthetic = %endpoint.node_id().synthetic_addr(),
            udp = %endpoint.paths.udp_local(),
            allow_direct = endpoint.config.allow_direct,
            "endpoint open"
        );
        Ok(endpoint)
    }

    pub fn node_id(&self) -> NodeId {
        self.key.node_id()
    }

    pub fn paths(&self) -> &Arc<Paths> {
        &self.paths
    }

    pub fn allow_direct(&self) -> bool {
        self.config.allow_direct
    }

    /// Sign a fresh `FSL-CARD-1`.  UDP hints appear only with owner consent.
    pub fn card(&self, ttl: Duration, extra: Vec<Hint>) -> Card {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let ttl = ttl
            .as_secs()
            .clamp(1, link_core::card::MAX_LIFETIME_SECONDS);
        let mut hints: Vec<Hint> = self
            .config
            .relays
            .iter()
            .map(|relay| Hint::relay(&relay.url))
            .collect();
        if self.config.allow_direct {
            for addr in self.paths.local_candidates() {
                hints.push(Hint::udp(addr));
            }
        }
        hints.extend(extra);
        hints.truncate(link_core::card::MAX_HINTS);
        // Strictly increasing per node ID across every card it ever signs.
        let serial = self.serial.fetch_add(1, Ordering::SeqCst).max(now);
        Card::sign(&self.key, now, now + ttl, serial, hints)
    }

    /// Wait for a relay welcome, spec 4.3 Rendezvous.
    async fn rendezvous(&self) -> Result<String, FailReason> {
        match self.paths.relay().status() {
            RelayStatus::Up(url) => return Ok(url),
            RelayStatus::Failed => return Err(FailReason::Relay),
            _ => {}
        }
        self.paths.relay().wait_up().await.ok_or(FailReason::Relay)
    }

    /// Verify nothing here: `Card` can only exist verified or freshly signed.
    pub async fn connect(&self, card: &Card) -> Result<Session, FailReason> {
        let peer = card.node_id;
        if peer == self.node_id() {
            return Err(FailReason::Identity);
        }
        self.paths.register_peer(peer);
        let relay = self.rendezvous().await?;
        info!(%peer, %relay, "rendezvous ready, starting QUIC over the relay");

        let mut client_crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| FailReason::Identity)?
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(peer))
        .with_client_auth_cert(
            vec![
                node_certificate(&self.key)
                    .map_err(|_| FailReason::Identity)?
                    .cert_der,
            ],
            node_certificate(&self.key)
                .map_err(|_| FailReason::Identity)?
                .key_der,
        )
        .map_err(|_| FailReason::Identity)?;
        client_crypto.alpn_protocols = vec![ALPN.to_vec()];

        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
                .map_err(|_| FailReason::Identity)?,
        ));
        client_config.transport_config(Arc::new(transport_config()));

        let connecting = self
            .quic
            .connect_with(client_config, peer.synthetic_addr(), "link")
            .map_err(|e| {
                warn!(%peer, error = %e, "connect refused before the handshake");
                FailReason::Relay
            })?;
        let conn = connecting.await.map_err(|e| {
            let reason = classify(&e);
            warn!(%peer, error = %e, %reason, "QUIC handshake failed");
            reason
        })?;

        Ok(Session::start(
            peer,
            conn,
            self.paths.clone(),
            self.config.allow_direct,
            self.config.probe_delay,
        )
        .await)
    }

    /// Accept an inbound session.  The identity rule is enforced in the
    /// handshake: the client verifier is pinned to the node ID the synthetic
    /// source address belongs to.
    pub async fn accept(&self) -> Result<Session, FailReason> {
        loop {
            let incoming = self.quic.accept().await.ok_or(FailReason::Relay)?;
            let remote = incoming.remote_address();
            let Some(peer) = self.paths.peer_for_synthetic(remote) else {
                warn!(%remote, "refusing an inbound connection from an unknown synthetic address");
                incoming.refuse();
                continue;
            };

            let leaf = match node_certificate(&self.key) {
                Ok(leaf) => leaf,
                Err(_) => return Err(FailReason::Identity),
            };
            let mut server_crypto = match rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            {
                Ok(builder) => builder,
                Err(_) => return Err(FailReason::Identity),
            }
            .with_client_cert_verifier(PinnedClientVerifier::new(peer))
            .with_single_cert(vec![leaf.cert_der], leaf.key_der)
            .map_err(|_| FailReason::Identity)?;
            server_crypto.alpn_protocols = vec![ALPN.to_vec()];

            let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
                .map_err(|_| FailReason::Identity)?;
            let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server));
            server_config.transport_config(Arc::new(transport_config()));

            let connecting = match incoming.accept_with(Arc::new(server_config)) {
                Ok(connecting) => connecting,
                Err(e) => {
                    warn!(%peer, error = %e, "inbound refused");
                    continue;
                }
            };
            let conn = match connecting.await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!(%peer, error = %e, "inbound handshake failed");
                    continue;
                }
            };

            // Belt and braces: the presented leaf must be the node ID the
            // synthetic address was derived from.
            if presented_node_id(&conn) != Some(peer) {
                warn!(%peer, "presented certificate does not match the source node ID");
                conn.close(VarInt::from_u32(1), b"identity");
                return Err(FailReason::Identity);
            }

            return Ok(Session::start(
                peer,
                conn,
                self.paths.clone(),
                self.config.allow_direct,
                self.config.probe_delay,
            )
            .await);
        }
    }

    pub async fn close(&self) {
        self.quic.close(VarInt::from_u32(0), b"closing");
        self.quic.wait_idle().await;
    }
}

fn presented_node_id(conn: &quinn::Connection) -> Option<NodeId> {
    let identity = conn.peer_identity()?;
    let chain = identity
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .ok()?;
    node_id_from_cert_der(chain.first()?.as_ref())
}

fn classify(error: &quinn::ConnectionError) -> FailReason {
    match error {
        quinn::ConnectionError::TimedOut => FailReason::Timeout,
        quinn::ConnectionError::TransportError(e) => {
            // TLS alerts arrive as CRYPTO_ERROR, 0x100 to 0x1ff.
            let code = u64::from(e.code);
            if (0x100..=0x1ff).contains(&code) {
                FailReason::Identity
            } else {
                FailReason::Relay
            }
        }
        _ => FailReason::Relay,
    }
}

fn transport_config() -> quinn::TransportConfig {
    let mut config = quinn::TransportConfig::default();
    // No path MTU discovery: every packet must fit the relay frame bound.
    config
        .initial_mtu(MAX_MTU)
        .min_mtu(MAX_MTU)
        .mtu_discovery_config(None)
        .max_concurrent_bidi_streams(VarInt::from_u32(16))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .stream_receive_window(VarInt::from_u64(STREAM_RECEIVE_WINDOW).expect("window"))
        .receive_window(VarInt::from_u64(CONNECTION_RECEIVE_WINDOW).expect("window"))
        .send_window(CONNECTION_RECEIVE_WINDOW)
        .keep_alive_interval(Some(Duration::from_secs(3)))
        .max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(Duration::from_secs(30)).expect("idle"),
        ));
    config
}
