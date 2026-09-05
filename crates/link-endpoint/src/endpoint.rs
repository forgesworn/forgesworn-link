//! `Endpoint` of spec section 5: the transport key, the path socket and the relays.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use link_core::card::{Card, Hint};
use link_core::id::{NodeId, TransportKey, node_id_from_spki};
use link_core::path::FailReason;
use link_core::rendezvous::PAIRING_SECRET_BYTES;
use link_core::tls::{
    PinnedClientVerifier, PinnedServerVerifier, ProvisionalClientVerifier, RefusingClientVerifier,
    node_identity,
};
use quinn::VarInt;
use rustls::client::AlwaysResolvesClientRawPublicKeys;
use rustls::server::AlwaysResolvesServerRawPublicKeys;
use rustls::sign::CertifiedKey;
use tracing::{info, warn};

use crate::netmon::{NetMonitor, interface_snapshot};
use crate::path_socket::{Paths, build};
use crate::relay_client::{RelayDriver, RelaySpec, RelayStatus};
use crate::rendezvous_book::{PairingRegistration, RendezvousPeer, TagBook};
use crate::session::{Session, Stream};

/// Cap the MTU so a QUIC packet always fits the relay's 1..=1350 frame bound.
pub const MAX_MTU: u16 = 1350;
const ALPN: &[u8] = b"fsl/0";
/// Separate protocol identity for a bounded, unpinned first-contact session.
const PAIRING_ALPN: &[u8] = b"fsl-pair/0";
/// A completed provisional handshake switches from its admitting QR secret to
/// this connection-local TLS exporter.  The relay still sees only an opaque
/// case-0x03 tag, while dropping the QR registration can no longer strand the
/// connection's final packets.
const PAIRING_ROUTE_EXPORT_LABEL: &[u8] = b"EXPORTER-FSL-pair-route-v1";
static NEXT_PAIRING_ROUTE_GENERATION: AtomicU64 = AtomicU64::new(1);
/// Pairing secrets are product-level ten-minute capabilities, never a general
/// anonymous-listener mode.
pub const MAX_PAIRING_LIFETIME: Duration = Duration::from_secs(10 * 60);
/// Even an active peer cannot hold a provisional connection indefinitely.
pub const MAX_PAIRING_SESSION_LIFETIME: Duration = Duration::from_secs(60);
/// Bounded per-stream and per-connection flow control, so memory does not grow
/// with transfer size.
const STREAM_RECEIVE_WINDOW: u64 = 1 << 20;
const CONNECTION_RECEIVE_WINDOW: u64 = 4 << 20;

#[derive(Debug, thiserror::Error)]
pub enum PairingError {
    #[error("pairing rendezvous requires tag mode")]
    TagModeRequired,
    #[error("pairing registration lifetime must be between 1s and 600s")]
    Lifetime,
}

/// What one unified accept loop received.  A provisional session has a
/// deliberately smaller surface and must never be handed to an ordinary
/// application server.
pub enum AcceptedSession {
    Pinned(Session),
    Pairing(PairingSession),
}

/// A relay-only, short-lived first-contact connection.  TLS proves that its
/// peer consistently controls one Ed25519 key, not that the key is a keeper.
/// Exactly one application stream is exposed; product authority comes only
/// from proving the raw pairing secret inside the box-pinned request.
pub struct PairingSession {
    session: Session,
    application_stream_used: AtomicBool,
}

impl PairingSession {
    fn new(session: Session, book: Arc<TagBook>, route: NodeId, generation: u64) -> Self {
        let connection = session.connection();
        let lifetime_connection = connection.clone();
        tokio::spawn(async move {
            tokio::time::sleep(MAX_PAIRING_SESSION_LIFETIME).await;
            lifetime_connection.close(VarInt::from_u32(3), b"pairing lifetime");
        });
        tokio::spawn(async move {
            let reason = connection.closed().await;
            if matches!(reason, quinn::ConnectionError::LocallyClosed) {
                // Quinn reports a local close before its CONNECTION_CLOSE has
                // drained. Keep only the TLS-exported route (never the QR
                // admission secret) for one full provisional-session bound so
                // retransmission cannot be cut off by product handle teardown.
                tokio::time::sleep(MAX_PAIRING_SESSION_LIFETIME).await;
            }
            book.remove_live_pairing(route, generation);
        });
        PairingSession {
            session,
            application_stream_used: AtomicBool::new(false),
        }
    }

    pub fn path(&self) -> link_core::path::PathReport {
        self.session.path()
    }

    pub fn history(&self) -> Vec<link_core::path::PathReport> {
        self.session.history()
    }

    /// The Ed25519 transport key presented by the peer in this provisional
    /// session's TLS handshake.
    ///
    /// This is connection-local consistency only. It is **not** a keeper
    /// identity, is not backed by a card/claim chain on the accepting side,
    /// and grants no product authority. A pairing product may use it to bind
    /// a card carried inside the separately secret-authenticated request to
    /// the key that actually completed this handshake.
    pub fn peer(&self) -> NodeId {
        self.session.peer()
    }

    fn take_application_stream(&self) -> anyhow::Result<()> {
        if self.application_stream_used.swap(true, Ordering::SeqCst) {
            anyhow::bail!("a pairing session exposes exactly one application stream");
        }
        Ok(())
    }

    pub async fn open_stream(&self) -> anyhow::Result<Stream> {
        self.take_application_stream()?;
        self.session.open_stream().await
    }

    pub async fn accept_stream(&self) -> anyhow::Result<Stream> {
        self.take_application_stream()?;
        self.session.accept_stream().await
    }

    /// Close this provisional connection locally.
    ///
    /// Once the TLS handshake completed, its datagrams switched from the QR
    /// admission tag to connection-local exporter material. The caller may
    /// therefore drop its `PairingRegistration` immediately after this
    /// returns: Link retains only that authority-free live route while Quinn
    /// drains the close.
    pub async fn close(&self) {
        self.session.close(3).await;
    }

    /// Wait until this provisional QUIC connection is actually closed.
    ///
    /// A product uses this after finishing its one response when the peer is
    /// responsible for closing the provisional connection. The pairing
    /// session's 60-second hard lifetime still bounds this wait if the peer
    /// disappears without closing cleanly.
    pub async fn closed(&self) -> quinn::ConnectionError {
        self.session.connection().closed().await
    }
}

#[derive(Clone, Debug)]
pub struct EndpointConfig {
    pub key: TransportKey,
    /// Highest card serial this transport key has already signed.  The shell
    /// persists it for the lifetime of the key and updates it after every
    /// card.  `None` is suitable only for a newly minted key.
    pub serial_seed: Option<u64>,
    pub relays: Vec<RelaySpec>,
    /// Owner consent for direct paths.  Relay-only is a first-class configuration.
    pub allow_direct: bool,
    /// Real UDP bind for direct paths and probes.
    pub bind: SocketAddr,
    /// Optional reflector for the reflexive candidate, spec 3.2.  Asked at
    /// open and again after every interface change.
    pub reflector: Option<SocketAddr>,
    /// How often the interface set is polled for a change, spec 4.2.  On a
    /// change every session re-queries the reflector, re-announces its
    /// candidates and starts a probing round.  Zero disables the poll; an
    /// application with a platform connectivity callback then calls
    /// `Session::reannounce` itself.
    pub net_poll: Duration,
    /// Settle on the relay for this long before the first probing round.  Not in
    /// the spec: it exists so a test can prove the relay carried a transfer
    /// before the upgrade, and so a product can defer probing.
    pub probe_delay: Duration,
    /// Maximum time `connect` waits for a relay welcome.  This bounds DNS,
    /// TCP, TLS, WebSocket and registration stalls before QUIC starts.
    pub rendezvous_timeout: Duration,
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
            serial_seed: None,
            relays: Vec::new(),
            allow_direct: true,
            bind: "0.0.0.0:0".parse().expect("literal"),
            reflector: None,
            net_poll: Duration::from_secs(5),
            probe_delay: Duration::ZERO,
            rendezvous_timeout: Duration::from_secs(30),
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
    book: Option<Arc<TagBook>>,
    /// The RFC 7250 identity every handshake presents, built once.
    identity: Arc<CertifiedKey>,
}

impl Endpoint {
    /// Bind the sockets and start the relay driver.  Does not wait for a relay.
    pub async fn open(config: EndpointConfig) -> anyhow::Result<Endpoint> {
        anyhow::ensure!(
            config.serial_seed != Some(u64::MAX),
            "card serial seed is exhausted"
        );
        let book = config
            .rendezvous
            .clone()
            .map(|peers| Arc::new(TagBook::new(peers)));
        let net = NetMonitor::spawn(config.net_poll, interface_snapshot);
        let (socket, paths) = build(
            config.key.clone(),
            config.bind,
            config.relays.clone(),
            book.clone(),
            config.reflector,
            net,
        )
        .await?;

        let mut endpoint_config = quinn::EndpointConfig::default();
        endpoint_config.max_udp_payload_size(MAX_MTU)?;

        let identity = node_identity(&config.key)?;
        let mut server_crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        // The default server config can never authenticate anyone: every real
        // inbound handshake goes through accept_with and a per-connection pin.
        .with_client_cert_verifier(RefusingClientVerifier::new())
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(
            identity.clone(),
        )));
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

        let wall_clock = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let serial_seed = config.serial_seed.unwrap_or(0).max(wall_clock);

        let endpoint = Endpoint {
            key: config.key.clone(),
            paths,
            quic,
            config,
            serial: AtomicU64::new(serial_seed),
            book,
            identity,
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

    /// The live rendezvous book when this endpoint runs tag mode.  An upsert
    /// after a peer's card rotation, or a removal, takes effect at the relay
    /// within a minute (the pump re-registers on change), and the three-epoch
    /// window covers the seam -- no endpoint restart.
    pub fn rendezvous_book(&self) -> Option<&Arc<TagBook>> {
        self.book.as_ref()
    }

    /// Register a short-lived first-contact tag derived from 16 raw secret
    /// bytes.  The returned handle owns the admission lifetime; dropping it
    /// removes Link's zeroising copy immediately. Expiry does the same even if
    /// the product accidentally retains the handle. A completed provisional
    /// connection has already switched to separate TLS-exported routing
    /// material, which grants no admission authority and is cleaned up with
    /// the bounded session.
    pub fn register_pairing_secret(
        &self,
        secret: [u8; PAIRING_SECRET_BYTES],
        lifetime: Duration,
    ) -> Result<PairingRegistration, PairingError> {
        if lifetime < Duration::from_secs(1) || lifetime > MAX_PAIRING_LIFETIME {
            return Err(PairingError::Lifetime);
        }
        let book = self.book.as_ref().ok_or(PairingError::TagModeRequired)?;
        let expires_at = now_unix().saturating_add(lifetime.as_secs());
        let registration = book.register_pairing(secret, expires_at);
        let route = registration.route();
        let weak = Arc::downgrade(book);
        tokio::spawn(async move {
            tokio::time::sleep(lifetime).await;
            if let Some(book) = weak.upgrade() {
                book.remove_pairing(route);
            }
        });
        Ok(registration)
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
        // The caller's extra hints are never dropped: the endpoint truncates
        // its OWN relay and UDP hints into the space that remains, so an
        // ephemeral rendezvous hint (0x04) survives any hint pressure instead
        // of silently costing the pair its forward secrecy.
        let mut extra = extra;
        extra.truncate(link_core::card::MAX_HINTS);
        hints.truncate(link_core::card::MAX_HINTS - extra.len());
        hints.extend(extra);
        // Strictly increasing across both clock movement and process restarts:
        // the counter starts at max(the shell's persisted high-water mark,
        // wall clock) and ratchets to max(last + 1, now).  The shell persists
        // the returned serial before it distributes the card.
        let last = self
            .serial
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |last| {
                Some(last.saturating_add(1).max(now))
            })
            .expect("the ratchet closure always returns Some");
        let serial = last.saturating_add(1).max(now);
        Card::sign(&self.key, now, now + ttl, serial, hints)
    }

    /// Wait for a relay welcome on `driver`, spec 4.3 Rendezvous.
    async fn rendezvous(driver: &RelayDriver, deadline: Duration) -> Result<String, FailReason> {
        match driver.status() {
            RelayStatus::Up(url) => return Ok(url),
            RelayStatus::Superseded => return Err(FailReason::Superseded),
            RelayStatus::Failed => return Err(FailReason::Relay),
            _ => {}
        }
        let terminal = tokio::time::timeout(deadline, driver.wait_up())
            .await
            .map_err(|_| FailReason::Timeout)?;
        terminal.ok_or_else(|| match driver.status() {
            RelayStatus::Superseded => FailReason::Superseded,
            _ => FailReason::Relay,
        })
    }

    fn client_config(
        &self,
        expected_server: NodeId,
        alpn: &[u8],
        pairing: bool,
    ) -> Result<quinn::ClientConfig, FailReason> {
        let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| FailReason::Identity)?
        .dangerous()
        .with_custom_certificate_verifier(PinnedServerVerifier::new(expected_server))
        .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(
            self.identity.clone(),
        )));
        crypto.alpn_protocols = vec![alpn.to_vec()];

        let mut config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|_| FailReason::Identity)?,
        ));
        config.transport_config(Arc::new(if pairing {
            pairing_transport_config()
        } else {
            transport_config()
        }));
        Ok(config)
    }

    fn server_config(
        &self,
        expected_client: Option<NodeId>,
    ) -> Result<quinn::ServerConfig, FailReason> {
        let verifier: Arc<dyn rustls::server::danger::ClientCertVerifier> = match expected_client {
            Some(peer) => PinnedClientVerifier::new(peer),
            None => ProvisionalClientVerifier::new(),
        };
        let mut crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| FailReason::Identity)?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(
            self.identity.clone(),
        )));
        let pairing = expected_client.is_none();
        crypto.alpn_protocols = vec![if pairing { PAIRING_ALPN } else { ALPN }.to_vec()];
        let quic = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
            .map_err(|_| FailReason::Identity)?;
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(quic));
        config.transport_config(Arc::new(if pairing {
            pairing_transport_config()
        } else {
            transport_config()
        }));
        Ok(config)
    }

    /// Verify nothing here: `Card` can only exist verified or freshly signed.
    pub async fn connect(&self, card: &Card) -> Result<Session, FailReason> {
        let peer = card.node_id;
        if peer == self.node_id() {
            return Err(FailReason::Identity);
        }
        if self.book.as_ref().is_some_and(|book| !book.contains(peer)) {
            warn!(%peer, "connect refused: no rendezvous material for peer");
            return Err(FailReason::Rendezvous);
        }
        self.paths.register_peer(peer);
        // Spec 4.3: one QUIC connection per peer, newest wins.  Take the slot
        // before the handshake: an earlier session with this peer is
        // superseded and its proof cleared, so the handshake goes over the
        // relay rather than to a socket the old session pointed at.
        let (session_id, superseded) = self.paths.begin_session(peer);
        // Spec 3.1: dial the peer on the relays its card names, so two nodes
        // need no shared configuration to meet.  A card with no relay hint
        // means this endpoint's own relay.
        let hints: Vec<RelaySpec> = card
            .relay_urls()
            .into_iter()
            .map(RelaySpec::plain)
            .collect();
        let driver = self.paths.set_peer_relays(peer, &hints);
        let relay = match Self::rendezvous(&driver, self.config.rendezvous_timeout).await {
            Ok(relay) => relay,
            Err(reason) => {
                warn!(%peer, %reason, "rendezvous failed before QUIC");
                self.paths.end_session(peer, session_id);
                return Err(reason);
            }
        };
        info!(%peer, %relay, "rendezvous ready, starting QUIC over the relay");

        let client_config = self.client_config(peer, ALPN, false)?;

        let connecting = self
            .quic
            .connect_with(client_config, peer.synthetic_addr(), "link")
            .map_err(|e| {
                warn!(%peer, error = %e, "connect refused before the handshake");
                self.paths.end_session(peer, session_id);
                FailReason::Relay
            })?;
        let conn = connecting.await.map_err(|e| {
            let reason = classify(&e);
            warn!(%peer, error = %e, %reason, "QUIC handshake failed");
            self.paths.end_session(peer, session_id);
            reason
        })?;

        Ok(Session::start(
            peer,
            true,
            conn,
            self.paths.clone(),
            self.config.allow_direct,
            self.config.probe_delay,
            (session_id, superseded),
        )
        .await)
    }

    /// Dial a first-contact route.  The server is still pinned to `card`; only
    /// the listener treats this side's Ed25519 key as provisional.  The route
    /// handle must belong to this endpoint and still be inside its lifetime.
    pub async fn connect_pairing(
        &self,
        card: &Card,
        registration: &PairingRegistration,
    ) -> Result<PairingSession, FailReason> {
        let peer = card.node_id;
        if peer == self.node_id() {
            return Err(FailReason::Identity);
        }
        let Some(book) = self.book.as_ref() else {
            return Err(FailReason::Rendezvous);
        };
        if !registration.belongs_to(book) || !registration.is_active(now_unix()) {
            return Err(FailReason::Rendezvous);
        }
        let route = registration.route();
        if route == self.node_id() || !book.pairing_active(route, now_unix()) {
            return Err(FailReason::Rendezvous);
        }

        self.paths.register_peer(route);
        self.paths.register_peer(peer);
        let (session_id, superseded) = self.paths.begin_session(peer);
        let hints: Vec<RelaySpec> = card
            .relay_urls()
            .into_iter()
            .map(RelaySpec::plain)
            .collect();
        let driver = self.paths.set_peer_relays(route, &hints);
        self.paths.copy_relay_route(route, peer);
        let relay = match Self::rendezvous(&driver, self.config.rendezvous_timeout).await {
            Ok(relay) => relay,
            Err(reason) => {
                self.paths.end_session(peer, session_id);
                return Err(reason);
            }
        };
        info!(%peer, %relay, "pairing rendezvous ready, starting bounded QUIC");

        let client_config = self.client_config(peer, PAIRING_ALPN, true)?;
        let connecting = self
            .quic
            .connect_with(client_config, route.synthetic_addr(), "link-pairing")
            .map_err(|error| {
                warn!(%peer, %error, "pairing connect refused before the handshake");
                self.paths.end_session(peer, session_id);
                FailReason::Relay
            })?;
        let connection = connecting.await.map_err(|error| {
            let reason = classify(&error);
            warn!(%peer, %error, %reason, "pairing QUIC handshake failed");
            self.paths.end_session(peer, session_id);
            reason
        })?;

        let generation = match promote_pairing_route(book, route, &connection) {
            Ok(generation) => generation,
            Err(reason) => {
                connection.close(VarInt::from_u32(3), b"pairing route");
                self.paths.end_session(peer, session_id);
                return Err(reason);
            }
        };

        let session = Session::start(
            peer,
            true,
            connection,
            self.paths.clone(),
            false,
            Duration::ZERO,
            (session_id, superseded),
        )
        .await;
        Ok(PairingSession::new(
            session,
            book.clone(),
            route,
            generation,
        ))
    }

    /// Accept an ordinary pinned session.  A pairing arrival is closed rather
    /// than widened into this API; products that implement first contact use
    /// one unified [`Endpoint::accept_any`] loop and handle the enum explicitly.
    pub async fn accept(&self) -> Result<Session, FailReason> {
        loop {
            match self.accept_any().await? {
                AcceptedSession::Pinned(session) => return Ok(session),
                AcceptedSession::Pairing(session) => {
                    warn!("pairing arrival refused by ordinary accept API");
                    session.close().await;
                }
            }
        }
    }

    /// Accept either an ordinary pinned session or a bounded pairing session.
    /// This is the only accept loop a pairing-capable product runs, so two
    /// tasks never race for quinn's inbound queue.
    pub async fn accept_any(&self) -> Result<AcceptedSession, FailReason> {
        loop {
            let incoming = self.quic.accept().await.ok_or(FailReason::Relay)?;
            let remote = incoming.remote_address();
            let Some(route) = self.paths.peer_for_synthetic(remote) else {
                warn!(%remote, "refusing an inbound connection from an unknown synthetic address");
                incoming.refuse();
                continue;
            };
            let pairing = self
                .book
                .as_ref()
                .is_some_and(|book| book.pairing_active(route, now_unix()));
            let ordinary_slot = (!pairing).then(|| self.paths.begin_session(route));
            let server_config = self.server_config((!pairing).then_some(route))?;

            let connecting = match incoming.accept_with(Arc::new(server_config)) {
                Ok(connecting) => connecting,
                Err(e) => {
                    warn!(%route, error = %e, pairing, "inbound refused");
                    if let Some((session_id, _)) = ordinary_slot {
                        self.paths.end_session(route, session_id);
                    }
                    continue;
                }
            };
            let conn = match connecting.await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!(%route, error = %e, pairing, "inbound handshake failed");
                    if let Some((session_id, _)) = ordinary_slot {
                        self.paths.end_session(route, session_id);
                    }
                    continue;
                }
            };

            let Some(presented) = presented_node_id(&conn) else {
                conn.close(VarInt::from_u32(1), b"identity");
                if let Some((session_id, _)) = ordinary_slot {
                    self.paths.end_session(route, session_id);
                }
                continue;
            };

            if pairing {
                if presented == self.node_id() {
                    conn.close(VarInt::from_u32(1), b"identity");
                    continue;
                }
                let Some(book) = self.book.as_ref() else {
                    conn.close(VarInt::from_u32(3), b"pairing route");
                    continue;
                };
                let generation = match promote_pairing_route(book, route, &conn) {
                    Ok(generation) => generation,
                    Err(reason) => {
                        warn!(%route, %reason, "pairing route promotion failed");
                        conn.close(VarInt::from_u32(3), b"pairing route");
                        continue;
                    }
                };
                self.paths.register_peer(presented);
                self.paths.copy_relay_route(route, presented);
                let (session_id, superseded) = self.paths.begin_session(presented);
                let session = Session::start(
                    presented,
                    false,
                    conn,
                    self.paths.clone(),
                    false,
                    Duration::ZERO,
                    (session_id, superseded),
                )
                .await;
                return Ok(AcceptedSession::Pairing(PairingSession::new(
                    session,
                    book.clone(),
                    route,
                    generation,
                )));
            }

            let (session_id, superseded) = ordinary_slot.expect("ordinary route has a slot");
            if presented != route {
                warn!(peer = %route, %presented, "presented certificate does not match the source node ID");
                conn.close(VarInt::from_u32(1), b"identity");
                self.paths.end_session(route, session_id);
                return Err(FailReason::Identity);
            }
            let session = Session::start(
                route,
                true,
                conn,
                self.paths.clone(),
                self.config.allow_direct,
                self.config.probe_delay,
                (session_id, superseded),
            )
            .await;
            return Ok(AcceptedSession::Pinned(session));
        }
    }

    pub async fn close(&self) {
        self.quic.close(VarInt::from_u32(0), b"closing");
        self.paths.relay().close();
        self.quic.wait_idle().await;
    }
}

fn presented_node_id(conn: &quinn::Connection) -> Option<NodeId> {
    let identity = conn.peer_identity()?;
    let chain = identity
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .ok()?;
    // RFC 7250: the one entry of the peer's "certificate" list is its SPKI.
    node_id_from_spki(chain.first()?.as_ref())
}

fn promote_pairing_route(
    book: &Arc<TagBook>,
    route: NodeId,
    connection: &quinn::Connection,
) -> Result<u64, FailReason> {
    let mut secret = [0u8; link_core::rendezvous::PAIRING_SECRET_BYTES];
    connection
        .export_keying_material(&mut secret, PAIRING_ROUTE_EXPORT_LABEL, b"")
        .map_err(|_| FailReason::Relay)?;
    let generation = NEXT_PAIRING_ROUTE_GENERATION.fetch_add(1, Ordering::Relaxed);
    if !book.promote_pairing(route, secret, generation, now_unix()) {
        return Err(FailReason::Rendezvous);
    }
    Ok(generation)
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
    transport_config_with(16, Duration::from_secs(30))
}

fn pairing_transport_config() -> quinn::TransportConfig {
    // One control stream plus one application stream in each direction.
    transport_config_with(2, Duration::from_secs(30))
}

fn transport_config_with(max_bidi_streams: u32, idle_timeout: Duration) -> quinn::TransportConfig {
    let mut config = quinn::TransportConfig::default();
    // No path MTU discovery: every packet must fit the relay frame bound.
    config
        .initial_mtu(MAX_MTU)
        .min_mtu(MAX_MTU)
        .mtu_discovery_config(None)
        .max_concurrent_bidi_streams(VarInt::from_u32(max_bidi_streams))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .stream_receive_window(VarInt::from_u64(STREAM_RECEIVE_WINDOW).expect("window"))
        .receive_window(VarInt::from_u64(CONNECTION_RECEIVE_WINDOW).expect("window"))
        .send_window(CONNECTION_RECEIVE_WINDOW)
        .keep_alive_interval(Some(Duration::from_secs(3)))
        .max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(idle_timeout).expect("idle"),
        ));
    config
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
