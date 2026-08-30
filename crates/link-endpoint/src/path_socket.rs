//! The path socket of spec 4.1 and the signed probing of 4.2.
//!
//! QUIC only ever sees a peer's synthetic address.  Underneath, each datagram
//! goes out over the relay or over a direct UDP address this side has proved.

use std::collections::HashMap;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use link_core::card::unmap_ipv6;
use link_core::id::{NodeId, TransportKey};
use link_core::wire::{
    MAX_DATAGRAM, PROBE_ID_BYTES, PROBE_KEY_BYTES, PROBE_PING, PROBE_PONG, Probe, REFLECT_MAGIC,
    REFLECT_REPLY_BYTES, parse_reflect_reply, reflect_request,
};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use rand::RngCore;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tracing::{debug, trace};

use crate::relay_client::QueueOutcome;

/// A direct path counts as usable only while its proof is this fresh, spec 4.1.
pub const DIRECT_FRESH: Duration = Duration::from_secs(15);
/// A probe whose pong has not arrived within this is forgotten, spec 4.3.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// At most one probe back per address per interval, so two peers cannot get
/// into a ping storm.
const COUNTER_PROBE_INTERVAL: Duration = Duration::from_secs(1);
/// At most one pong per source address per interval, so a replayed ping is
/// a nuisance rather than a reflector, spec 4.2.
const PONG_INTERVAL: Duration = Duration::from_secs(1);
/// An address learnt from a valid ping is probed for this long; if it never
/// proves it is forgotten, so a replayed ping cannot pad the candidate list.
pub const LEARNED_TTL: Duration = Duration::from_secs(10);
/// Bounded inbound queue.  Roughly 700 KiB at the 1350 byte datagram cap.
const INBOUND_CAPACITY: usize = 512;

type ProbeKeyId = [u8; PROBE_ID_BYTES];
type ProbeKey = [u8; PROBE_KEY_BYTES];

struct Inbound {
    from: SocketAddr,
    data: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
pub struct Proven {
    pub addr: SocketAddr,
    pub proved_at: Instant,
}

#[derive(Default)]
struct Peer {
    candidates: Vec<SocketAddr>,
    /// How many candidate lists the peer has sent: one for the initial
    /// exchange, one more per re-announcement.
    updates: u32,
    /// Nonces this side issued, with the address probed and when.
    pending: HashMap<[u8; 16], (SocketAddr, Instant)>,
    /// When this side last pinged each address.
    last_ping: HashMap<SocketAddr, Instant>,
    /// When this side last answered a ping from each address.
    last_pong: HashMap<SocketAddr, Instant>,
    /// Addresses a valid ping arrived from that are not in the peer's list,
    /// with when they were last seen; probed until `LEARNED_TTL` passes.
    learned: HashMap<SocketAddr, Instant>,
    /// The session's probe key and its id, from the TLS exporter, spec 4.2.
    probe_key: Option<(ProbeKeyId, ProbeKey)>,
    direct: Option<Proven>,
}

#[derive(Default)]
struct Inner {
    peers: HashMap<NodeId, Peer>,
    by_synthetic: HashMap<SocketAddr, NodeId>,
    by_direct: HashMap<SocketAddr, NodeId>,
    /// Which peer's session a probe key id belongs to.
    by_key_id: HashMap<ProbeKeyId, NodeId>,
}

/// Everything the path socket knows, shared with the sessions above it.
pub struct Paths {
    key: TransportKey,
    udp: Arc<UdpSocket>,
    relay: crate::relay_client::RelayClient,
    inner: Mutex<Inner>,
    inbound_tx: mpsc::Sender<Inbound>,
    reflexive: Mutex<Option<SocketAddr>>,
    /// The nonce of the outstanding reflector request; a reply must echo it.
    reflector_nonce: Mutex<Option<[u8; 16]>>,
    /// The reflector to ask again after an interface change, spec 3.2.
    reflector: Option<SocketAddr>,
    /// The interface monitor's generation, spec 4.2; sessions subscribe.
    net: watch::Receiver<u64>,
    local_synthetic: SocketAddr,
    udp_local: SocketAddr,
}

impl std::fmt::Debug for Paths {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Paths({})", self.key.node_id())
    }
}

impl Paths {
    pub fn node_id(&self) -> NodeId {
        self.key.node_id()
    }

    pub fn udp_local(&self) -> SocketAddr {
        self.udp_local
    }

    pub fn relay(&self) -> &crate::relay_client::RelayClient {
        &self.relay
    }

    /// Make the peer routable.  Called before `connect` and on the first inbound
    /// relay datagram from an unknown node.
    pub fn register_peer(&self, peer: NodeId) {
        let mut inner = self.inner.lock().expect("paths");
        inner.peers.entry(peer).or_default();
        inner.by_synthetic.insert(peer.synthetic_addr(), peer);
    }

    pub fn peer_for_synthetic(&self, addr: SocketAddr) -> Option<NodeId> {
        self.inner
            .lock()
            .expect("paths")
            .by_synthetic
            .get(&addr)
            .copied()
    }

    /// Candidates the peer sent on the control stream, spec 4.2.
    pub fn set_peer_candidates(&self, peer: NodeId, candidates: Vec<SocketAddr>) {
        let usable: Vec<SocketAddr> = candidates
            .into_iter()
            .map(unmap_ipv6)
            .filter(|addr| self.can_reach(*addr))
            .collect();
        let mut inner = self.inner.lock().expect("paths");
        let entry = inner.peers.entry(peer).or_default();
        entry.candidates = usable;
        entry.updates += 1;
    }

    /// How many candidate lists `peer` has sent this endpoint: one for the
    /// initial exchange and one per re-announcement.
    pub fn candidate_updates(&self, peer: NodeId) -> u32 {
        self.inner
            .lock()
            .expect("paths")
            .peers
            .get(&peer)
            .map(|p| p.updates)
            .unwrap_or(0)
    }

    pub fn peer_candidates(&self, peer: NodeId) -> Vec<SocketAddr> {
        self.inner
            .lock()
            .expect("paths")
            .peers
            .get(&peer)
            .map(|p| p.candidates.clone())
            .unwrap_or_default()
    }

    /// The current direct proof, if any, regardless of freshness.
    pub fn proven_direct(&self, peer: NodeId) -> Option<Proven> {
        self.inner
            .lock()
            .expect("paths")
            .peers
            .get(&peer)
            .and_then(|p| p.direct)
    }

    /// Forget the direct path, which puts the peer back on the relay.
    pub fn drop_direct(&self, peer: NodeId) {
        let mut inner = self.inner.lock().expect("paths");
        if let Some(entry) = inner.peers.get_mut(&peer)
            && let Some(proven) = entry.direct.take()
        {
            inner.by_direct.remove(&proven.addr);
        }
    }

    fn can_reach(&self, addr: SocketAddr) -> bool {
        // A socket bound to IPv4 cannot address a real IPv6 peer and the reverse.
        self.udp_local.is_ipv4() == addr.is_ipv4()
    }

    /// Give a session its probe key, spec 4.2: both ends exported the same
    /// bytes from the TLS session, so a probe sealed under it authenticates
    /// the live session and names nobody.  Until this is called the peer is
    /// neither probed nor answered.
    pub fn register_probe_key(&self, peer: NodeId, key_id: ProbeKeyId, key: ProbeKey) {
        let mut inner = self.inner.lock().expect("paths");
        if let Some(previous) = inner
            .peers
            .entry(peer)
            .or_default()
            .probe_key
            .replace((key_id, key))
        {
            inner.by_key_id.remove(&previous.0);
        }
        inner.by_key_id.insert(key_id, peer);
    }

    /// Forget a session's probe key when the session ends, so nothing sealed
    /// under it is ever answered again.
    pub fn unregister_probe_key(&self, key_id: ProbeKeyId) {
        let mut inner = self.inner.lock().expect("paths");
        if let Some(peer) = inner.by_key_id.remove(&key_id)
            && let Some(entry) = inner.peers.get_mut(&peer)
            && entry.probe_key.is_some_and(|(id, _)| id == key_id)
        {
            entry.probe_key = None;
        }
    }

    /// Every address the next round pings: the peer's own list, then any
    /// address a valid ping arrived from within `LEARNED_TTL`.
    pub fn probe_targets(&self, peer: NodeId) -> Vec<SocketAddr> {
        let inner = self.inner.lock().expect("paths");
        let Some(entry) = inner.peers.get(&peer) else {
            return Vec::new();
        };
        let now = Instant::now();
        let mut out = entry.candidates.clone();
        for (addr, seen) in &entry.learned {
            if now.duration_since(*seen) < LEARNED_TTL && !out.contains(addr) {
                out.push(*addr);
            }
        }
        out
    }

    /// Forget learnt addresses older than `LEARNED_TTL` as of `now`.  A
    /// replayed ping therefore buys its sender at most ten seconds of probes.
    pub fn prune_learned(&self, peer: NodeId, now: Instant) {
        let mut inner = self.inner.lock().expect("paths");
        if let Some(entry) = inner.peers.get_mut(&peer) {
            entry
                .learned
                .retain(|_, seen| now.duration_since(*seen) < LEARNED_TTL);
        }
    }

    /// Send a sealed ping to every probe target of the peer, spec 4.2.
    pub fn send_probes(&self, peer: NodeId) -> usize {
        let now = Instant::now();
        {
            let mut inner = self.inner.lock().expect("paths");
            let entry = inner.peers.entry(peer).or_default();
            entry
                .pending
                .retain(|_, (_, sent)| now.duration_since(*sent) < PROBE_TIMEOUT);
        }
        self.prune_learned(peer, now);
        let mut sent = 0;
        for addr in self.probe_targets(peer) {
            if self.send_ping(peer, addr) {
                sent += 1;
            }
        }
        sent
    }

    fn send_ping(&self, peer: NodeId, addr: SocketAddr) -> bool {
        let mut nonce = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let wire = {
            let mut inner = self.inner.lock().expect("paths");
            let entry = inner.peers.entry(peer).or_default();
            // No session key yet means no session yet: nothing to prove.
            let Some((key_id, key)) = entry.probe_key else {
                return false;
            };
            entry.pending.insert(nonce, (addr, Instant::now()));
            entry.last_ping.insert(addr, Instant::now());
            Probe {
                kind: PROBE_PING,
                key_id,
                nonce,
            }
            .seal(&key)
        };
        if self.udp.try_send_to(&wire, addr).is_ok() {
            trace!(peer = %peer, %addr, "probe ping sent");
            true
        } else {
            false
        }
    }

    /// Ask the reflector for this node's reflexive candidate, spec 3.2.
    pub fn query_reflector(&self, reflector: SocketAddr) {
        let mut nonce = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        *self.reflector_nonce.lock().expect("reflector nonce") = Some(nonce);
        let _ = self.udp.try_send_to(&reflect_request(&nonce), reflector);
    }

    /// Ask the configured reflector again, after an interface change.  The
    /// old reflexive result is kept until the reply replaces it, so a
    /// candidate list sent in the meantime is stale rather than empty.
    pub fn requery_reflector(&self) {
        if let Some(reflector) = self.reflector {
            self.query_reflector(reflector);
        }
    }

    /// The interface monitor's generation counter, spec 4.2.  It advances
    /// whenever the host's address set changes.
    pub fn net_generation(&self) -> watch::Receiver<u64> {
        self.net.clone()
    }

    pub fn reflexive(&self) -> Option<SocketAddr> {
        *self.reflexive.lock().expect("reflexive")
    }

    /// Local interface candidates plus the reflector result, spec 4.2.
    pub fn local_candidates(&self) -> Vec<SocketAddr> {
        let mut out = Vec::new();
        if self.udp_local.ip().is_unspecified() {
            for ip in local_addresses(self.udp_local.is_ipv4()) {
                out.push(SocketAddr::new(ip, self.udp_local.port()));
            }
        } else {
            out.push(self.udp_local);
        }
        if let Some(reflexive) = self.reflexive()
            && !out.contains(&reflexive)
        {
            out.push(reflexive);
        }
        out
    }

    /// The session a probe's key id belongs to, with its key, spec 4.2.
    fn probe_session(&self, key_id: &ProbeKeyId) -> Option<(NodeId, ProbeKey)> {
        let inner = self.inner.lock().expect("paths");
        let peer = *inner.by_key_id.get(key_id)?;
        let (_, key) = inner.peers.get(&peer)?.probe_key?;
        Some((peer, key))
    }

    /// A probe that opened under `peer`'s session key, from `from`.
    fn handle_probe(&self, peer: NodeId, key: ProbeKey, probe: Probe, from: SocketAddr) {
        match probe.kind {
            PROBE_PING => {
                let now = Instant::now();
                let (answer, probe_back) = {
                    let mut inner = self.inner.lock().expect("paths");
                    let entry = inner.peers.entry(peer).or_default();
                    // One pong per source address per second: a replayed
                    // ping is answered once, not once per replay.
                    let answer = entry
                        .last_pong
                        .get(&from)
                        .is_none_or(|sent| now.duration_since(*sent) >= PONG_INTERVAL);
                    if answer {
                        entry.last_pong.insert(from, now);
                    }
                    // An address the peer did not list is probed for a while
                    // and forgotten if it never proves.
                    if !entry.candidates.contains(&from) {
                        entry.learned.insert(from, now);
                    }
                    // Spec 4.2 has both sides prove independently, so
                    // answering is not enough: probe back until this side has
                    // its own fresh proof, at most once a second per address.
                    let proved = entry
                        .direct
                        .is_some_and(|p| p.addr == from && p.proved_at.elapsed() < DIRECT_FRESH);
                    let recent = entry
                        .last_ping
                        .get(&from)
                        .is_some_and(|sent| now.duration_since(*sent) < COUNTER_PROBE_INTERVAL);
                    (answer, !proved && !recent)
                };
                if answer {
                    let pong = Probe {
                        kind: PROBE_PONG,
                        key_id: probe.key_id,
                        nonce: probe.nonce,
                    }
                    .seal(&key);
                    let _ = self.udp.try_send_to(&pong, from);
                }
                if probe_back {
                    self.send_ping(peer, from);
                }
            }
            PROBE_PONG => {
                let mut inner = self.inner.lock().expect("paths");
                let Some(entry) = inner.peers.get_mut(&peer) else {
                    return;
                };
                // Proved only for a nonce this side issued, spec 4.2.
                if entry.pending.remove(&probe.nonce).is_none() {
                    return;
                }
                let previous = entry.direct.map(|p| p.addr);
                entry.direct = Some(Proven {
                    addr: from,
                    proved_at: Instant::now(),
                });
                entry.learned.remove(&from);
                if previous != Some(from) {
                    debug!(peer = %peer, addr = %from, "direct path proved");
                }
                inner.by_direct.insert(from, peer);
            }
            _ => {}
        }
    }

    fn deliver(&self, from: SocketAddr, data: &[u8]) {
        // A full queue is loss, never unbounded buffering.
        let _ = self.inbound_tx.try_send(Inbound {
            from,
            data: data.to_vec(),
        });
    }
}

/// At most this many local addresses are offered.  A card has 16 hint slots
/// and relay hints take some of them; a control-stream list allows 255 but a
/// peer probes every entry, so the list stays short.
pub const MAX_LOCAL_CANDIDATES: usize = 8;

/// The address the default route would use for the given family, learnt by
/// connecting a UDP socket to a documentation address: no traffic is sent,
/// but the OS chooses a route and reports the source it would use.
fn default_route_address(v4: bool) -> Option<IpAddr> {
    let (target, bind) = if v4 {
        ("192.0.2.1:9", "0.0.0.0:0")
    } else {
        ("[2001:db8::1]:9", "[::]:0")
    };
    let target: SocketAddr = target.parse().ok()?;
    let bind: SocketAddr = bind.parse().ok()?;
    let socket = std::net::UdpSocket::bind(bind).ok()?;
    socket.connect(target).ok()?;
    let local = socket.local_addr().ok()?;
    (!local.ip().is_unspecified()).then_some(local.ip())
}

/// Link-local addresses are never useful to a peer: an IPv6 one needs a
/// scope the wire cannot carry, and an IPv4 one means no address was
/// assigned at all.
fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// Every address a peer might reach this host on, spec 4.2: the address the
/// default route would use first, then every other interface of the same
/// family, loopback last so a same-host peer still works.  A default-route
/// only list was the recorded cause of a LAN pair falling back to the relay
/// whenever a VPN held the default route (acceptance record, 27 August 2026):
/// the tunnel address was the only candidate, and the LAN address that would
/// have worked was never offered.
pub fn local_addresses(v4: bool) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    let offer = |ip: IpAddr, out: &mut Vec<IpAddr>| {
        if ip.is_ipv4() == v4 && !out.contains(&ip) {
            out.push(ip);
        }
    };
    if let Some(routed) = default_route_address(v4) {
        offer(routed, &mut out);
    }
    if let Ok(interfaces) = if_addrs::get_if_addrs() {
        for interface in interfaces {
            let ip = interface.ip();
            if ip.is_loopback() || ip.is_unspecified() || is_link_local(ip) {
                continue;
            }
            offer(ip, &mut out);
        }
    }
    out.truncate(MAX_LOCAL_CANDIDATES - 1);
    let loopback = if v4 {
        IpAddr::from([127, 0, 0, 1])
    } else {
        IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
    };
    offer(loopback, &mut out);
    out
}

/// The `AsyncUdpSocket` quinn drives.
pub struct PathSocket {
    paths: Arc<Paths>,
    inbound_rx: Mutex<mpsc::Receiver<Inbound>>,
}

impl std::fmt::Debug for PathSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PathSocket({})", self.paths.node_id())
    }
}

/// Build the path socket and start its two receive tasks.
pub async fn build(
    key: TransportKey,
    bind: SocketAddr,
    relays: Vec<crate::relay_client::RelaySpec>,
    book: Option<Arc<crate::rendezvous_book::TagBook>>,
    reflector: Option<SocketAddr>,
    net: watch::Receiver<u64>,
) -> io::Result<(Arc<PathSocket>, Arc<Paths>)> {
    let udp = Arc::new(UdpSocket::bind(bind).await?);
    let udp_local = udp.local_addr()?;
    let (inbound_tx, inbound_rx) = mpsc::channel::<Inbound>(INBOUND_CAPACITY);
    let (relay_inbound_tx, mut relay_inbound_rx) =
        mpsc::channel::<(NodeId, Vec<u8>)>(INBOUND_CAPACITY);
    let relay = crate::relay_client::spawn(key.clone(), relays, relay_inbound_tx, book);

    let local_synthetic = key.node_id().synthetic_addr();
    let paths = Arc::new(Paths {
        key,
        udp: udp.clone(),
        relay,
        inner: Mutex::new(Inner::default()),
        inbound_tx,
        reflexive: Mutex::new(None),
        reflector_nonce: Mutex::new(None),
        reflector,
        net,
        local_synthetic,
        udp_local,
    });

    // Relay inbound: attribute by the relay's source node ID, spec 4.1.
    {
        let paths = paths.clone();
        tokio::spawn(async move {
            while let Some((source, datagram)) = relay_inbound_rx.recv().await {
                paths.register_peer(source);
                paths.deliver(source.synthetic_addr(), &datagram);
            }
        });
    }

    // Direct inbound: probes, reflector replies, and datagrams from proven addresses.
    {
        let paths = paths.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let (len, from) = match udp.recv_from(&mut buf).await {
                    Ok(pair) => pair,
                    Err(e) => {
                        debug!(error = %e, "direct socket receive failed");
                        continue;
                    }
                };
                let from = unmap_ipv6(from);
                let data = &buf[..len];
                if let Some(key_id) = Probe::peek_key_id(data) {
                    // A probe names a session by key id; one that opens under
                    // that session's key is handled, anything else is silence.
                    if let Some((peer, key)) = paths.probe_session(&key_id)
                        && let Some(probe) = Probe::open(data, &key)
                    {
                        paths.handle_probe(peer, key, probe, from);
                    }
                    continue;
                }
                if len == REFLECT_REPLY_BYTES && data[..4] == REFLECT_MAGIC {
                    if let Some((nonce, observed)) = parse_reflect_reply(data) {
                        // Only the reply to this node's own outstanding request
                        // counts; anything else could plant a false reflexive
                        // candidate.
                        let matched = paths
                            .reflector_nonce
                            .lock()
                            .expect("reflector nonce")
                            .take_if(|expected| *expected == nonce)
                            .is_some();
                        if matched {
                            *paths.reflexive.lock().expect("reflexive") =
                                Some(unmap_ipv6(observed));
                        }
                    }
                    continue;
                }
                // A datagram from an unproven address is dropped, spec 4.1.
                let peer = paths
                    .inner
                    .lock()
                    .expect("paths")
                    .by_direct
                    .get(&from)
                    .copied();
                match peer {
                    Some(peer) => paths.deliver(peer.synthetic_addr(), data),
                    None => trace!(%from, "dropped datagram from an unproven address"),
                }
            }
        });
    }

    let socket = Arc::new(PathSocket {
        paths: paths.clone(),
        inbound_rx: Mutex::new(inbound_rx),
    });
    Ok((socket, paths))
}

/// Write-readiness across both paths: the real UDP socket for direct sends and
/// the bounded relay queue for relayed sends.
struct Poller {
    paths: Arc<Paths>,
    id: u64,
}

impl std::fmt::Debug for Poller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Poller({})", self.id)
    }
}

impl Drop for Poller {
    fn drop(&mut self) {
        self.paths.relay.readiness().unregister(self.id);
    }
}

impl UdpPoller for Poller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        match self.paths.udp.poll_send_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        if self.paths.relay.has_capacity() {
            return Poll::Ready(Ok(()));
        }
        self.paths.relay.readiness().register(self.id, cx.waker());
        // Re-check after registering so a concurrent drain cannot be missed.
        if self.paths.relay.has_capacity() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

impl AsyncUdpSocket for PathSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        let id = self.paths.relay.readiness().new_id();
        Box::pin(Poller {
            paths: self.paths.clone(),
            id,
        })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        if transmit.contents.len() > MAX_DATAGRAM {
            // The transport config caps the MTU, so this should be unreachable.
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "datagram above the relay frame bound",
            ));
        }
        let Some(peer) = self.paths.peer_for_synthetic(transmit.destination) else {
            // Nothing is addressed by anything except a synthetic address.
            return Ok(());
        };
        let direct = self
            .paths
            .proven_direct(peer)
            .filter(|p| p.proved_at.elapsed() < DIRECT_FRESH);
        match direct {
            Some(proven) => {
                match self.paths.udp.try_send_to(transmit.contents, proven.addr) {
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        trace!("direct send buffer full, datagram dropped");
                    }
                    Err(e) => return Err(e),
                }
                Ok(())
            }
            None => match self.paths.relay.try_send(peer, transmit.contents) {
                QueueOutcome::Queued | QueueOutcome::Dropped => Ok(()),
                // Real backpressure while the relay is up, so nothing is buffered
                // above the bounded queue and nothing is needlessly dropped.
                QueueOutcome::WouldBlock => Err(io::ErrorKind::WouldBlock.into()),
            },
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut rx = self.inbound_rx.lock().expect("inbound");
        let slots = bufs.len().min(meta.len());
        let mut filled = 0;
        while filled < slots {
            match rx.poll_recv(cx) {
                Poll::Ready(Some(inbound)) => {
                    let len = inbound.data.len().min(bufs[filled].len());
                    bufs[filled][..len].copy_from_slice(&inbound.data[..len]);
                    meta[filled] = RecvMeta {
                        addr: inbound.from,
                        len,
                        stride: len,
                        ecn: None,
                        dst_ip: Some(self.paths.local_synthetic.ip()),
                    };
                    filled += 1;
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::other("path socket closed")));
                }
                Poll::Pending => break,
            }
        }
        if filled == 0 {
            Poll::Pending
        } else {
            Poll::Ready(Ok(filled))
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.paths.local_synthetic)
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod candidates {
    use super::*;

    /// Every routable interface address is offered, not only the one the
    /// default route would use.  A default-route-only list was the recorded
    /// cause of a LAN pair falling back to the relay whenever a VPN held the
    /// default route (acceptance record, 27 August 2026).
    #[test]
    fn every_routable_interface_address_is_offered() {
        let offered = local_addresses(true);
        let expected: Vec<IpAddr> = if_addrs::get_if_addrs()
            .expect("interfaces")
            .into_iter()
            .map(|interface| interface.ip())
            .filter(|ip| ip.is_ipv4() && !ip.is_loopback() && !is_link_local(*ip))
            .collect();
        for ip in &expected {
            assert!(offered.contains(ip), "{ip} is missing from {offered:?}");
        }
        assert_eq!(
            offered.last().copied(),
            Some(IpAddr::from([127, 0, 0, 1])),
            "loopback is offered last so a same-host peer still works"
        );
        assert!(offered.len() <= MAX_LOCAL_CANDIDATES);
        assert!(
            offered.iter().all(|ip| ip.is_ipv4()),
            "one family per socket"
        );
    }

    #[test]
    fn link_local_and_the_wrong_family_are_never_offered() {
        for ip in local_addresses(false) {
            assert!(ip.is_ipv6(), "{ip} is not IPv6");
            assert!(!is_link_local(ip), "{ip} is link-local");
        }
        assert!(is_link_local("169.254.1.1".parse::<IpAddr>().unwrap()));
        assert!(is_link_local("fe80::1".parse::<IpAddr>().unwrap()));
        assert!(!is_link_local("fd00::1".parse::<IpAddr>().unwrap()));
    }
}

#[cfg(test)]
mod probes {
    use super::*;
    use crate::netmon::NetMonitor;
    use link_core::wire::{PROBE_ID_BYTES, PROBE_KEY_BYTES};

    async fn paths() -> Arc<Paths> {
        let net = NetMonitor::spawn(Duration::ZERO, Vec::new);
        let (_socket, paths) = build(
            TransportKey::generate(),
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            None,
            None,
            net,
        )
        .await
        .expect("path socket binds");
        paths
    }

    async fn received_within(socket: &UdpSocket, window: Duration) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let deadline = tokio::time::Instant::now() + window;
        let mut buf = [0u8; 2048];
        loop {
            match tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await {
                Ok(Ok((len, _))) => out.push(buf[..len].to_vec()),
                _ => return out,
            }
        }
    }

    fn count(replies: &[Vec<u8>], key: &[u8; PROBE_KEY_BYTES], kind: u8) -> usize {
        replies
            .iter()
            .filter(|bytes| Probe::open(bytes, key).is_some_and(|probe| probe.kind == kind))
            .count()
    }

    /// A valid ping replayed from one address earns one pong and one
    /// counter-probe a second, not one per replay, and the address it came
    /// from is a candidate only until the learnt-address window passes
    /// without a proof.
    #[tokio::test]
    async fn a_replayed_ping_earns_one_pong_a_second_and_a_candidate_that_expires() {
        let paths = paths().await;
        let peer = NodeId([9u8; 32]);
        let key = [0x42u8; PROBE_KEY_BYTES];
        let key_id = [0x24u8; PROBE_ID_BYTES];
        paths.register_peer(peer);
        paths.register_probe_key(peer, key_id, key);

        let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ping = Probe {
            kind: PROBE_PING,
            key_id,
            nonce: [7u8; 16],
        }
        .seal(&key);
        for _ in 0..5 {
            attacker.send_to(&ping, paths.udp_local()).await.unwrap();
        }
        let replies = received_within(&attacker, Duration::from_millis(300)).await;
        assert_eq!(
            count(&replies, &key, PROBE_PONG),
            1,
            "one pong per source address per second, replies: {}",
            replies.len()
        );
        assert_eq!(
            count(&replies, &key, PROBE_PING),
            1,
            "one counter-probe per source address per second"
        );

        let from = attacker.local_addr().unwrap();
        assert!(
            paths.probe_targets(peer).contains(&from),
            "an address that sent a valid ping is probed back"
        );
        paths.prune_learned(peer, Instant::now() + LEARNED_TTL + Duration::from_secs(1));
        assert!(
            !paths.probe_targets(peer).contains(&from),
            "a learnt address that never proved is forgotten"
        );
    }

    /// A probe under the wrong key for its key id, or under a key id no
    /// session has, earns nothing: no pong, no counter-probe, no candidate.
    #[tokio::test]
    async fn a_probe_under_an_unknown_or_wrong_key_is_ignored() {
        let paths = paths().await;
        let peer = NodeId([9u8; 32]);
        paths.register_peer(peer);
        paths.register_probe_key(peer, [1u8; PROBE_ID_BYTES], [2u8; PROBE_KEY_BYTES]);

        let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let wrong_key = Probe {
            kind: PROBE_PING,
            key_id: [1u8; PROBE_ID_BYTES],
            nonce: [7u8; 16],
        }
        .seal(&[3u8; PROBE_KEY_BYTES]);
        attacker
            .send_to(&wrong_key, paths.udp_local())
            .await
            .unwrap();
        let unknown_id = Probe {
            kind: PROBE_PING,
            key_id: [8u8; PROBE_ID_BYTES],
            nonce: [7u8; 16],
        }
        .seal(&[2u8; PROBE_KEY_BYTES]);
        attacker
            .send_to(&unknown_id, paths.udp_local())
            .await
            .unwrap();

        assert!(
            received_within(&attacker, Duration::from_millis(300))
                .await
                .is_empty(),
            "nothing is sent back to a forger"
        );
        assert!(
            !paths
                .probe_targets(peer)
                .contains(&attacker.local_addr().unwrap()),
            "a forger's address is never a candidate"
        );
    }
}
