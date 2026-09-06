//! Opt-in native LAN candidate. This is a separate API and protocol identity,
//! not an amendment to the frozen relay-first Link state machine.
mod address;
mod admission;
mod session;
mod socket;
#[cfg(test)]
mod tests;
mod tls;

pub use address::LanBinding;
pub use admission::{CardCheckpoint, LanAdmission, MAX_ADMITTED_PEERS};
pub use session::{
    LanPairingSession, LanSession, LanStream, MAX_PAIRING_SESSION, MAX_PAIRING_STREAM_BYTES,
};

use address::AddressPolicy;
use admission::{Book, Lease};
use link_core::{
    card::{Card, Hint, MAX_LIFETIME_SECONDS, unmap_ipv6},
    id::{NodeId, TransportKey, node_id_from_spki},
    tls::node_identity,
};
use quinn::Runtime;
use rustls::sign::CertifiedKey;
use session::SessionGuard;
use socket::{Counters, LocalSocket};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc};

pub const MAX_CONNECTIONS: usize = 8;
pub const MAX_HANDSHAKES: usize = 4;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_PAIRING_WINDOW: Duration = Duration::from_secs(600);
const READY: &[u8] = b"FSL-LAN-READY\x01";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LanError {
    #[error("address is outside the explicitly selected local interface or development loopback")]
    Address,
    #[error("invalid, expired, changed or replayed peer card")]
    Card,
    #[error("peer identity did not authenticate")]
    Identity,
    #[error("peer or network admission is absent, expired or superseded")]
    Admission,
    #[error("local connection or admission capacity is exhausted")]
    Capacity,
    #[error("LAN connection did not complete within its deadline")]
    Timeout,
    #[error("LAN endpoint or connection closed")]
    Closed,
    #[error("LAN connection failed")]
    Connection,
    #[error("pairing permits exactly one dialler-initiated stream")]
    StreamLimit,
    #[error("invalid local card or pairing lifetime")]
    Lifetime,
}

/// Validate locally and persist the resulting checkpoint with the product's
/// trusted peer identity before calling `admit_peer` or `connect_pairing`.
pub fn verify_peer_card(
    expected: NodeId,
    raw: &[u8],
    saved: Option<&CardCheckpoint>,
) -> Result<CardCheckpoint, LanError> {
    admission::verify_card(expected, raw, saved).map(|(_, checkpoint)| checkpoint)
}

#[derive(Debug, Clone, Copy)]
pub struct LanTraffic {
    pub sent_datagrams: u64,
    pub refused_datagrams: u64,
}

struct Inbound {
    peer: NodeId,
    guard: Arc<SessionGuard>,
}

struct Core {
    key: TransportKey,
    identity: Arc<CertifiedKey>,
    quic: quinn::Endpoint,
    policy: AddressPolicy,
    active: Arc<AtomicBool>,
    book: Arc<Book>,
    slots: Arc<Semaphore>,
    incoming: Mutex<mpsc::Receiver<Inbound>>,
    pairing: Option<Arc<Lease>>,
    counters: Arc<Counters>,
}

impl Core {
    fn open(
        key: TransportKey,
        binding: LanBinding,
        pairing: Option<Duration>,
    ) -> Result<Arc<Self>, LanError> {
        if pairing.is_some_and(|lifetime| {
            lifetime < Duration::from_secs(1) || lifetime > MAX_PAIRING_WINDOW
        }) {
            return Err(LanError::Lifetime);
        }
        let policy = AddressPolicy::new(binding)?;
        let active = Arc::new(AtomicBool::new(true));
        let book = Book::new();
        let identity = node_identity(&key).map_err(|_| LanError::Identity)?;
        let udp = std::net::UdpSocket::bind(policy.bind).map_err(|_| LanError::Address)?;
        udp.set_nonblocking(true).map_err(|_| LanError::Address)?;
        let runtime = Arc::new(quinn::TokioRuntime);
        let counters = Arc::new(Counters::default());
        let socket = Arc::new(LocalSocket {
            inner: runtime
                .wrap_udp_socket(udp)
                .map_err(|_| LanError::Address)?,
            policy: policy.clone(),
            active: active.clone(),
            counters: counters.clone(),
        });
        let mut config = quinn::EndpointConfig::default();
        config
            .max_udp_payload_size(1350)
            .map_err(|_| LanError::Address)?;
        let quic = quinn::Endpoint::new_with_abstract_socket(
            config,
            Some(tls::server(
                identity.clone(),
                book.clone(),
                pairing.is_some(),
            )?),
            socket,
            runtime,
        )
        .map_err(|_| LanError::Address)?;
        let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let window =
            pairing.map(|lifetime| Lease::new(now().saturating_add(lifetime.as_secs()), lifetime));
        let (tx, rx) = mpsc::channel(MAX_CONNECTIONS);
        let core = Arc::new(Self {
            key,
            identity,
            quic: quic.clone(),
            policy: policy.clone(),
            active: active.clone(),
            book: book.clone(),
            slots: slots.clone(),
            incoming: Mutex::new(rx),
            pairing: window.clone(),
            counters,
        });
        tokio::spawn(accept_loop(
            AcceptState {
                node_id: core.key.node_id(),
                quic: quic.clone(),
                policy: policy.clone(),
                active: active.clone(),
                book: book.clone(),
                slots,
                pairing: window.clone(),
            },
            tx,
        ));
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(250)).await;
                book.expire();
                if !active.load(Ordering::Acquire)
                    || !policy.still_present()
                    || window.as_ref().is_some_and(|window| !window.valid())
                {
                    active.store(false, Ordering::Release);
                    book.revoke_all();
                    if let Some(window) = &window {
                        window.revoke();
                    }
                    quic.close(1_u32.into(), b"local admission ended");
                    break;
                }
            }
        });
        Ok(core)
    }
    fn check(&self) -> Result<(), LanError> {
        if !self.active.load(Ordering::Acquire) || !self.policy.still_present() {
            self.close();
            return Err(LanError::Admission);
        }
        if self.pairing.as_ref().is_some_and(|window| !window.valid()) {
            self.close();
            return Err(LanError::Admission);
        }
        Ok(())
    }
    fn close(&self) {
        self.active.store(false, Ordering::Release);
        self.book.revoke_all();
        if let Some(window) = &self.pairing {
            window.revoke();
        }
        self.quic.close(0_u32.into(), b"local endpoint closed");
    }
    fn local_addr(&self) -> Result<SocketAddr, LanError> {
        self.quic.local_addr().map_err(|_| LanError::Closed)
    }
    fn card(&self, lifetime: Duration, serial: u64) -> Result<Card, LanError> {
        self.check()?;
        if lifetime < Duration::from_secs(1)
            || lifetime.as_secs() > MAX_LIFETIME_SECONDS
            || serial == 0
        {
            return Err(LanError::Lifetime);
        }
        let issued = now();
        let expiry = self
            .pairing
            .as_ref()
            .map_or(issued + lifetime.as_secs(), |window| {
                window.expires_at.min(issued + lifetime.as_secs())
            });
        if expiry <= issued {
            return Err(LanError::Admission);
        }
        Ok(Card::sign(
            &self.key,
            issued,
            expiry,
            serial,
            vec![Hint::udp(self.local_addr()?)],
        ))
    }
    fn target(&self, card: &Card, target: SocketAddr) -> Result<(), LanError> {
        self.check()?;
        if card.node_id == self.key.node_id() || !self.policy.permits(target) {
            return Err(LanError::Address);
        }
        if !card
            .udp_candidates()
            .into_iter()
            .map(unmap_ipv6)
            .any(|hint| hint.ip() == target.ip() && hint.port() == target.port())
        {
            return Err(LanError::Address);
        }
        Ok(())
    }
    async fn dial(
        &self,
        peer: NodeId,
        target: SocketAddr,
        lease: Arc<Lease>,
        pairing: bool,
    ) -> Result<Arc<SessionGuard>, LanError> {
        self.check()?;
        if !lease.valid() {
            return Err(LanError::Admission);
        }
        let slot = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| LanError::Capacity)?;
        let config = tls::client(self.identity.clone(), peer, pairing)?;
        let connecting = self
            .quic
            .connect_with(config, target, "lan.invalid")
            .map_err(|_| LanError::Address)?;
        let connection = tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting)
            .await
            .map_err(|_| LanError::Timeout)?
            .map_err(classify)?;
        if self.check().is_err() || !lease.valid() {
            connection.close(1_u32.into(), b"admission changed");
            return Err(LanError::Admission);
        }
        if presented(&connection) != Some(peer) {
            connection.close(1_u32.into(), b"identity");
            return Err(LanError::Identity);
        }
        let ready = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            let mut stream = connection
                .accept_uni()
                .await
                .map_err(|_| LanError::Identity)?;
            let bytes = stream
                .read_to_end(READY.len())
                .await
                .map_err(|_| LanError::Identity)?;
            if bytes != READY {
                return Err(LanError::Identity);
            }
            Ok(())
        })
        .await;
        if !matches!(ready, Ok(Ok(()))) {
            connection.close(1_u32.into(), b"peer did not admit session");
            return Err(LanError::Identity);
        }
        self.check()?;
        lease.attach(&connection, !pairing)?;
        Ok(make_session(
            connection,
            self.active.clone(),
            lease,
            pairing,
            slot,
        ))
    }
    async fn accept(&self) -> Result<Inbound, LanError> {
        loop {
            self.check()?;
            let incoming = self
                .incoming
                .lock()
                .await
                .recv()
                .await
                .ok_or(LanError::Closed)?;
            if incoming.guard.check().is_ok() {
                self.check()?;
                return Ok(incoming);
            }
        }
    }
    fn traffic(&self) -> LanTraffic {
        LanTraffic {
            sent_datagrams: self.counters.sent.load(Ordering::Relaxed),
            refused_datagrams: self.counters.refused.load(Ordering::Relaxed),
        }
    }
}
impl Drop for Core {
    fn drop(&mut self) {
        self.close();
    }
}

/// Ordinary paired native LAN endpoint. Explicitly admitted peer keys only.
pub struct LanEndpoint {
    core: Arc<Core>,
}
impl LanEndpoint {
    pub fn open(key: TransportKey, binding: LanBinding) -> Result<Self, LanError> {
        Ok(Self {
            core: Core::open(key, binding, None)?,
        })
    }
    pub fn node_id(&self) -> NodeId {
        self.core.key.node_id()
    }
    pub fn local_addr(&self) -> Result<SocketAddr, LanError> {
        self.core.local_addr()
    }
    pub fn card(&self, lifetime: Duration, serial: u64) -> Result<Card, LanError> {
        self.core.card(lifetime, serial)
    }
    pub fn traffic(&self) -> LanTraffic {
        self.core.traffic()
    }
    pub fn admit_peer(
        &self,
        expected: NodeId,
        raw: &[u8],
        checkpoint: Option<&CardCheckpoint>,
    ) -> Result<LanAdmission, LanError> {
        self.core.check()?;
        if expected == self.node_id() {
            return Err(LanError::Identity);
        }
        self.core.book.admit(expected, raw, checkpoint)
    }
    pub async fn connect(
        &self,
        admission: &LanAdmission,
        target: SocketAddr,
    ) -> Result<LanSession, LanError> {
        if !Arc::ptr_eq(&admission.book, &self.core.book) || !admission.lease.valid() {
            return Err(LanError::Admission);
        }
        admission::verify_card(
            admission.peer,
            admission.card.as_bytes(),
            Some(&admission.checkpoint),
        )?;
        self.core.target(&admission.card, target)?;
        let guard = self
            .core
            .dial(admission.peer, target, admission.lease.clone(), false)
            .await?;
        Ok(LanSession {
            peer: admission.peer,
            guard,
        })
    }
    pub async fn accept(&self) -> Result<LanSession, LanError> {
        let incoming = self.core.accept().await?;
        Ok(LanSession {
            peer: incoming.peer,
            guard: incoming.guard,
        })
    }
    /// No peer admission is installed by first contact. The expected box key
    /// must come from locally trusted pairing material, not an arbitrary relay.
    pub async fn connect_pairing(
        &self,
        expected_box: NodeId,
        raw: &[u8],
        checkpoint: &CardCheckpoint,
        target: SocketAddr,
    ) -> Result<LanPairingSession, LanError> {
        let (card, _) = admission::verify_card(expected_box, raw, Some(checkpoint))?;
        self.core.target(&card, target)?;
        let lease = Lease::new(card.expires_at, MAX_PAIRING_SESSION);
        let guard = self.core.dial(expected_box, target, lease, true).await?;
        Ok(LanPairingSession {
            peer: expected_box,
            guard,
            dialler: true,
            stream_used: AtomicBool::new(false),
        })
    }
    pub fn close(&self) {
        self.core.close();
    }
}

/// Separate listener and ALPN for one explicit first-contact window. Drop it
/// to stop admission and all provisional work. It cannot return paired sessions.
pub struct LanPairingListener {
    core: Arc<Core>,
}
impl LanPairingListener {
    pub fn open(
        key: TransportKey,
        binding: LanBinding,
        lifetime: Duration,
    ) -> Result<Self, LanError> {
        Ok(Self {
            core: Core::open(key, binding, Some(lifetime))?,
        })
    }
    pub fn node_id(&self) -> NodeId {
        self.core.key.node_id()
    }
    pub fn local_addr(&self) -> Result<SocketAddr, LanError> {
        self.core.local_addr()
    }
    pub fn card(&self, lifetime: Duration, serial: u64) -> Result<Card, LanError> {
        self.core.card(lifetime, serial)
    }
    pub fn traffic(&self) -> LanTraffic {
        self.core.traffic()
    }
    pub async fn accept(&self) -> Result<LanPairingSession, LanError> {
        let incoming = self.core.accept().await?;
        Ok(LanPairingSession {
            peer: incoming.peer,
            guard: incoming.guard,
            dialler: false,
            stream_used: AtomicBool::new(false),
        })
    }
    pub fn close(&self) {
        self.core.close();
    }
}

struct AcceptState {
    node_id: NodeId,
    quic: quinn::Endpoint,
    policy: AddressPolicy,
    active: Arc<AtomicBool>,
    book: Arc<Book>,
    slots: Arc<Semaphore>,
    pairing: Option<Arc<Lease>>,
}
async fn accept_loop(state: AcceptState, sender: mpsc::Sender<Inbound>) {
    let state = Arc::new(state);
    let handshakes = Arc::new(Semaphore::new(MAX_HANDSHAKES));
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        while tasks.try_join_next().is_some() {}
        tokio::select! {
            incoming = state.quic.accept() => {
                let Some(incoming) = incoming else { break; };
                if !state.active.load(Ordering::Acquire)
                    || !state.policy.permits(incoming.remote_address())
                    || state.pairing.as_ref().is_some_and(|window| !window.valid())
                {
                    incoming.ignore();
                    continue;
                }
                if !incoming.remote_address_validated() {
                    let _ = incoming.retry();
                    continue;
                }
                let Ok(slot) = state.slots.clone().try_acquire_owned() else {
                    incoming.refuse();
                    continue;
                };
                let Ok(handshake) = handshakes.clone().try_acquire_owned() else {
                    incoming.refuse();
                    continue;
                };
                let generation = state.book.generation.load(Ordering::Acquire);
                tasks.spawn(accept_handshake(
                    state.clone(), sender.clone(), incoming, generation, slot, handshake,
                ));
            }
            _ = tasks.join_next(), if !tasks.is_empty() => {},
        }
    }
}

async fn accept_handshake(
    state: Arc<AcceptState>,
    sender: mpsc::Sender<Inbound>,
    incoming: quinn::Incoming,
    generation: u64,
    slot: OwnedSemaphorePermit,
    handshake: OwnedSemaphorePermit,
) {
    let Ok(connecting) = incoming.accept() else {
        return;
    };
    let Ok(Ok(connection)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting).await else {
        return;
    };
    drop(handshake);
    let Some(peer) = presented(&connection) else {
        connection.close(1_u32.into(), b"identity");
        return;
    };
    if peer == state.node_id {
        connection.close(1_u32.into(), b"self identity");
        return;
    }
    let lease = match &state.pairing {
        Some(window) => Some(window.clone()),
        None => state.book.get(peer),
    };
    let Some(lease) = lease else {
        connection.close(1_u32.into(), b"admission");
        return;
    };
    if !state.active.load(Ordering::Acquire)
        || !lease.valid()
        || generation != state.book.generation.load(Ordering::Acquire)
    {
        connection.close(1_u32.into(), b"admission changed");
        return;
    }
    if lease.attach(&connection, state.pairing.is_none()).is_err() {
        return;
    }
    let ready = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let mut stream = connection.open_uni().await.map_err(|_| LanError::Closed)?;
        stream
            .write_all(READY)
            .await
            .map_err(|_| LanError::Closed)?;
        stream.finish().map_err(|_| LanError::Closed)?;
        if stream
            .stopped()
            .await
            .map_err(|_| LanError::Closed)?
            .is_some()
        {
            return Err(LanError::Closed);
        }
        Ok::<_, LanError>(())
    })
    .await;
    if !matches!(ready, Ok(Ok(())))
        || !state.active.load(Ordering::Acquire)
        || !lease.valid()
        || generation != state.book.generation.load(Ordering::Acquire)
    {
        connection.close(1_u32.into(), b"admission ended");
        lease.detach(connection.stable_id());
        return;
    }
    let guard = make_session(
        connection,
        state.active.clone(),
        lease,
        state.pairing.is_some(),
        slot,
    );
    if let Err(error) = sender.try_send(Inbound { peer, guard }) {
        error
            .into_inner()
            .guard
            .connection
            .close(1_u32.into(), b"accept queue full");
    }
}

fn make_session(
    connection: quinn::Connection,
    active: Arc<AtomicBool>,
    lease: Arc<Lease>,
    pairing: bool,
    slot: OwnedSemaphorePermit,
) -> Arc<SessionGuard> {
    let deadline = pairing.then(|| Instant::now() + MAX_PAIRING_SESSION);
    let guard = Arc::new(SessionGuard {
        endpoint_active: active,
        lease,
        deadline,
        connection: connection.clone(),
    });
    let expires = deadline
        .unwrap_or(guard.lease.deadline)
        .min(guard.lease.deadline);
    let cleanup = guard.lease.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = connection.closed() => {},
            _ = connection.accept_uni() => { connection.close(1_u32.into(), b"unexpected control stream"); },
            _ = tokio::time::sleep_until(expires.into()) => { connection.close(1_u32.into(), b"session lifetime"); },
        }
        cleanup.detach(connection.stable_id());
        drop(slot);
    });
    guard
}

fn presented(connection: &quinn::Connection) -> Option<NodeId> {
    let identity = connection
        .peer_identity()?
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .ok()?;
    if identity.len() != 1 {
        return None;
    }
    node_id_from_spki(identity[0].as_ref())
}
pub(super) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn classify(error: quinn::ConnectionError) -> LanError {
    match error {
        quinn::ConnectionError::TimedOut => LanError::Timeout,
        quinn::ConnectionError::TransportError(error)
            if (0x100..=0x1ff).contains(&u64::from(error.code)) =>
        {
            LanError::Identity
        }
        quinn::ConnectionError::LocallyClosed => LanError::Closed,
        _ => LanError::Connection,
    }
}
