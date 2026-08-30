//! `Session` and `Stream` of spec section 5, and the state machine of 4.3.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use link_core::card::{Hint, to_ipv6};
use link_core::id::NodeId;
use link_core::path::{FailReason, PathReport, PathStatus};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::path_socket::{DIRECT_FRESH, Paths};
use crate::relay_client::RelayStatus;

/// How long a `Probing` round runs before it records `direct_failed`, spec 4.3.
const PROBE_ROUND: Duration = Duration::from_secs(5);
/// After a failed round, wait this long before probing again.
const PROBE_COOLDOWN: Duration = Duration::from_secs(30);
/// While `Direct`, re-prove at this interval so the proof stays inside 15 s.
const REPROVE_INTERVAL: Duration = Duration::from_secs(5);
/// State machine tick.
const TICK: Duration = Duration::from_millis(100);
/// Bounded queue of inbound application streams.
const STREAM_QUEUE: usize = 16;
/// Bounded transition history, so a test or an operator can read what happened
/// rather than try to catch a state in flight.
const HISTORY_CAP: usize = 256;
/// Bounded queue of requests to the control-stream writer.
const CONTROL_QUEUE: usize = 8;

/// Nobody has asked for a probing round.
const PROBE_IDLE: u8 = 0;
/// This side asked: `request_direct`, `reannounce`, or the network monitor.
const PROBE_LOCAL: u8 = 1;
/// The peer asked with a `punch-now` control message.
const PROBE_PEER: u8 = 2;

/// One bidirectional QUIC stream, a plain read and write pair.
pub struct Stream {
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
}

impl Stream {
    /// Finish the send direction so the peer sees clean end of stream.
    pub async fn finish(&mut self) -> Result<(), quinn::ClosedStream> {
        self.send.finish()
    }
}

impl tokio::io::AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl tokio::io::AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

pub(crate) struct SessionInner {
    peer: NodeId,
    conn: quinn::Connection,
    paths: Arc<Paths>,
    allow_direct: bool,
    report: Mutex<PathReport>,
    history: Mutex<Vec<PathReport>>,
    /// `PROBE_IDLE`, `PROBE_LOCAL` or `PROBE_PEER`: who asked for a probing
    /// round, consumed by the state machine on its next tick.
    probe_now: AtomicU8,
    /// Requests to the control-stream writer: re-send candidates, punch now.
    control_tx: mpsc::Sender<ControlSend>,
    /// How many `punch-now` messages the peer has sent this session.
    punch_requests: AtomicU32,
}

impl SessionInner {
    fn transition(&self, status: PathStatus, cause: impl Into<String>) {
        let cause = cause.into();
        let relay = match self.paths.relay().status() {
            RelayStatus::Up(url) => Some(url),
            _ => None,
        };
        let direct = match status {
            PathStatus::Direct => self.paths.proven_direct(self.peer).map(|p| p.addr),
            _ => None,
        };
        let mut report = self.report.lock().expect("report");
        if report.status == status {
            // Not a transition, only refresh the observed path details.
            report.relay = relay;
            report.direct = direct;
            return;
        }
        // Spec 4.3: every transition is logged with its cause.
        info!(
            peer = %self.peer,
            from = %report.status,
            to = %status,
            %cause,
            relay = relay.as_deref().unwrap_or("none"),
            direct = direct.map(|a| a.to_string()).unwrap_or_else(|| "none".into()),
            "path transition"
        );
        *report = PathReport {
            status,
            relay,
            direct,
            since: Instant::now(),
            cause,
        };
        let recorded = report.clone();
        drop(report);
        let mut history = self.history.lock().expect("history");
        if history.len() < HISTORY_CAP {
            history.push(recorded);
        }
    }

    /// Every transition so far, oldest first, starting at the initial state.
    fn history(&self) -> Vec<PathReport> {
        self.history.lock().expect("history").clone()
    }

    fn status(&self) -> PathStatus {
        self.report.lock().expect("report").status
    }
}

/// One QUIC connection to one peer.
pub struct Session {
    inner: Arc<SessionInner>,
    streams: tokio::sync::Mutex<mpsc::Receiver<Stream>>,
}

impl Session {
    pub(crate) async fn start(
        peer: NodeId,
        conn: quinn::Connection,
        paths: Arc<Paths>,
        allow_direct: bool,
        probe_delay: Duration,
    ) -> Session {
        let relay = match paths.relay().status() {
            RelayStatus::Up(url) => Some(url),
            _ => None,
        };
        let initial = PathReport {
            status: PathStatus::Rendezvous,
            relay,
            direct: None,
            since: Instant::now(),
            cause: "connect".into(),
        };
        let (control_tx, control_rx) = mpsc::channel::<ControlSend>(CONTROL_QUEUE);
        let inner = Arc::new(SessionInner {
            peer,
            conn,
            paths,
            allow_direct,
            probe_now: AtomicU8::new(PROBE_IDLE),
            control_tx,
            punch_requests: AtomicU32::new(0),
            report: Mutex::new(initial.clone()),
            history: Mutex::new(vec![initial]),
        });
        inner.transition(PathStatus::Relayed, "QUIC handshake over relay ok");

        // Spec 4.2 makes the control stream the first stream each side opens.
        // Opening it here, before the session reaches the application, is what
        // makes that true: spawning the opener instead let an application stream
        // win the race for the lower stream ID under load, and the peer then
        // routed the application stream into the control reader and reset it.
        let control = inner.conn.open_bi().await.ok();

        let (tx, rx) = mpsc::channel(STREAM_QUEUE);
        tokio::spawn(accept_loop(inner.clone(), tx));
        if let Some((send, recv)) = control {
            tokio::spawn(control_initiator(inner.clone(), send, recv, control_rx));
        }
        tokio::spawn(drive(inner.clone(), probe_delay));

        Session {
            inner,
            streams: tokio::sync::Mutex::new(rx),
        }
    }

    pub fn peer(&self) -> NodeId {
        self.inner.peer
    }

    /// The exact current path.  Never inferred from a successful transfer.
    pub fn path(&self) -> PathReport {
        self.inner.report.lock().expect("report").clone()
    }

    /// Every transition this session has made, oldest first.  Reading this is
    /// how an observer sees a short-lived state such as `Reconnecting` without
    /// having to catch it in flight.
    pub fn history(&self) -> Vec<PathReport> {
        self.inner.history()
    }

    /// Ask for a direct-path attempt now rather than waiting out the settle
    /// delay or the cooldown, and tell the peer to do the same (`punch-now`,
    /// spec 4.2), so both ends probe in the same round.
    pub fn request_direct(&self) {
        self.inner.probe_now.store(PROBE_LOCAL, Ordering::SeqCst);
        let _ = self.inner.control_tx.try_send(ControlSend::PunchNow);
    }

    /// Tell the peer this side's addresses may have changed: re-send the
    /// candidate list, ask for a punching round, and start one here.  The
    /// endpoint's network monitor calls this on an interface change; an
    /// application with a platform connectivity callback calls it itself.
    pub fn reannounce(&self) {
        let _ = self.inner.control_tx.try_send(ControlSend::Candidates);
        self.request_direct();
    }

    /// How many times the peer has asked this side for a probing round with
    /// `punch-now`.  An operator reading a session that never left `Relayed`
    /// can tell "the peer never asked" from "the peer asked and every probe
    /// was lost".
    pub fn punch_requests(&self) -> u32 {
        self.inner.punch_requests.load(Ordering::SeqCst)
    }

    pub async fn open_stream(&self) -> anyhow::Result<Stream> {
        let (send, recv) = self.inner.conn.open_bi().await?;
        Ok(Stream { send, recv })
    }

    pub async fn accept_stream(&self) -> anyhow::Result<Stream> {
        let mut streams = self.streams.lock().await;
        streams
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("connection closed"))
    }

    pub async fn close(&self, reason: u32) {
        self.inner.conn.close(reason.into(), b"closed");
        self.inner.conn.closed().await;
    }
}

/// Route inbound streams.  The first one the peer opens is its control stream.
async fn accept_loop(inner: Arc<SessionInner>, tx: mpsc::Sender<Stream>) {
    let mut control_seen = false;
    loop {
        match inner.conn.accept_bi().await {
            Ok((send, recv)) => {
                if !control_seen {
                    control_seen = true;
                    tokio::spawn(control_acceptor(inner.clone(), send, recv));
                } else if tx.send(Stream { send, recv }).await.is_err() {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

// ---------------------------------------------------------------------------
// Control stream, spec 4.2.  Candidates never travel through the relay frames.
// ---------------------------------------------------------------------------

/// Control message kinds, spec 4.2.  Each message is a `u32` big-endian
/// length, then the kind byte, then the body.
const CONTROL_CANDIDATES: u8 = 0x01;
/// No body: start a probing round now, so both ends punch together.
const CONTROL_PUNCH_NOW: u8 = 0x02;
const CONTROL_MAX_BYTES: usize = 4096;

/// A decoded control message.
enum Control {
    Candidates(Vec<SocketAddr>),
    PunchNow,
    /// A kind this version does not know; ignored, never fatal.
    Unknown,
}

/// What the control-stream writer can be asked to send after the initial
/// candidate list.
pub(crate) enum ControlSend {
    Candidates,
    PunchNow,
}

fn punch_now_message() -> Vec<u8> {
    vec![0, 0, 0, 1, CONTROL_PUNCH_NOW]
}

fn candidates_message(candidates: &[SocketAddr]) -> Vec<u8> {
    let mut body = Vec::with_capacity(2 + candidates.len() * 18);
    body.push(CONTROL_CANDIDATES);
    body.push(candidates.len().min(255) as u8);
    for addr in candidates.iter().take(255) {
        body.extend_from_slice(&to_ipv6(addr.ip()).octets());
        body.extend_from_slice(&addr.port().to_be_bytes());
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

fn parse_control(body: &[u8]) -> Option<Control> {
    let (&kind, rest) = body.split_first()?;
    match kind {
        CONTROL_CANDIDATES => parse_candidates(rest).map(Control::Candidates),
        CONTROL_PUNCH_NOW => Some(Control::PunchNow),
        _ => Some(Control::Unknown),
    }
}

fn parse_candidates(rest: &[u8]) -> Option<Vec<SocketAddr>> {
    let (&count, rest) = rest.split_first()?;
    if rest.len() != count as usize * 18 {
        return None;
    }
    let mut out = Vec::with_capacity(count as usize);
    // The length was checked above, so every 18-byte candidate is whole.
    let (chunks, _remainder) = rest.as_chunks::<18>();
    for chunk in chunks {
        let hint = Hint {
            kind: link_core::card::HINT_UDP,
            value: chunk.to_vec(),
        };
        out.push(hint.as_udp()?);
    }
    Some(out)
}

async fn control_initiator(
    inner: Arc<SessionInner>,
    mut send: quinn::SendStream,
    recv: quinn::RecvStream,
    mut requests: mpsc::Receiver<ControlSend>,
) {
    // With direct paths declined the peer is told so by an empty candidate list.
    let candidates = |inner: &SessionInner| {
        if inner.allow_direct {
            inner.paths.local_candidates()
        } else {
            Vec::new()
        }
    };
    let first = candidates(&inner);
    info!(
        peer = %inner.peer,
        count = first.len(),
        allow_direct = inner.allow_direct,
        "sending candidates on the control stream"
    );
    if send.write_all(&candidates_message(&first)).await.is_err() {
        return;
    }
    let _ = send.flush().await;
    // Stay on the stream for the life of the session: a re-announcement or a
    // punch-now can be asked for at any time, and holding both halves means
    // neither direction is reset while the session lives.
    loop {
        let message = tokio::select! {
            request = requests.recv() => match request {
                Some(ControlSend::Candidates) => {
                    let fresh = candidates(&inner);
                    info!(peer = %inner.peer, count = fresh.len(), "re-announcing candidates");
                    candidates_message(&fresh)
                }
                Some(ControlSend::PunchNow) => punch_now_message(),
                None => break,
            },
            _ = inner.conn.closed() => break,
        };
        if send.write_all(&message).await.is_err() {
            break;
        }
        let _ = send.flush().await;
    }
    inner.conn.closed().await;
    drop((send, recv));
}

async fn control_acceptor(
    inner: Arc<SessionInner>,
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) {
    loop {
        let mut header = [0u8; 4];
        if recv.read_exact(&mut header).await.is_err() {
            break;
        }
        let len = u32::from_be_bytes(header) as usize;
        if len == 0 || len > CONTROL_MAX_BYTES {
            break;
        }
        let mut body = vec![0u8; len];
        if recv.read_exact(&mut body).await.is_err() {
            break;
        }
        match parse_control(&body) {
            Some(Control::Candidates(candidates)) => {
                info!(peer = %inner.peer, count = candidates.len(), "peer candidates received");
                inner.paths.set_peer_candidates(inner.peer, candidates);
            }
            Some(Control::PunchNow) => {
                // The peer is probing now; probe back in the same instant so
                // both NATs see outbound traffic at once, spec 4.2.
                inner.punch_requests.fetch_add(1, Ordering::SeqCst);
                inner.probe_now.store(PROBE_PEER, Ordering::SeqCst);
            }
            Some(Control::Unknown) => {}
            None => break,
        }
    }
    // Hold both halves until the connection ends rather than dropping them,
    // because dropping a RecvStream sends STOP_SENDING and a reset is not the
    // right answer to a control stream that simply went quiet.
    inner.conn.closed().await;
    drop((send, recv));
}

// ---------------------------------------------------------------------------
// State machine, spec 4.3
// ---------------------------------------------------------------------------

async fn drive(inner: Arc<SessionInner>, probe_delay: Duration) {
    let mut previous_before_reconnect = PathStatus::Relayed;
    let mut reconnect_since: Option<Instant> = None;
    let mut probe_round_ends: Option<Instant> = None;
    let mut next_probe_attempt = Instant::now() + probe_delay;
    let mut last_probe_sent = Instant::now() - REPROVE_INTERVAL;
    let mut candidates_announced = false;
    // Why the next probing round starts, for the transition record.
    let mut round_cause = "settle delay elapsed";
    // The interface monitor, spec 4.2.  On a change the reflector is asked
    // again first, and the re-announcement follows once its reply has had a
    // moment to arrive.
    let mut net = inner.paths.net_generation();
    net.borrow_and_update();
    let mut net_alive = true;
    let mut reannounce_at: Option<Instant> = None;
    const REFLECTOR_GRACE: Duration = Duration::from_millis(300);

    // Relay state is consumed as an ordered event stream, never sampled.  A
    // failover can complete in tens of milliseconds, which a tick would step
    // straight over, and spec 4.3 requires the Reconnecting transition to be
    // recorded whatever its duration.
    let mut events = inner.paths.relay().subscribe();
    let mut relay_state = inner.paths.relay().status();

    loop {
        let mut relay_event = None;
        tokio::select! {
            reason = inner.conn.closed() => {
                let status = inner.status();
                if !matches!(status, PathStatus::Failed(_)) {
                    match reason {
                        quinn::ConnectionError::LocallyClosed
                        | quinn::ConnectionError::ApplicationClosed(_) => {}
                        quinn::ConnectionError::TimedOut => {
                            inner.transition(PathStatus::Failed(FailReason::Timeout), "QUIC idle timeout");
                        }
                        other => {
                            inner.transition(
                                PathStatus::Failed(FailReason::Relay),
                                format!("connection ended: {other}"),
                            );
                        }
                    }
                }
                return;
            }
            event = events.recv() => relay_event = Some(event),
            changed = net.changed(), if net_alive => match changed {
                Ok(()) => {
                    info!(peer = %inner.peer, "interface change: re-querying the reflector");
                    inner.paths.requery_reflector();
                    reannounce_at = Some(Instant::now() + REFLECTOR_GRACE);
                }
                Err(_) => net_alive = false,
            },
            _ = tokio::time::sleep(TICK) => {}
        }

        if let Some(event) = relay_event {
            match event {
                Ok(next) => relay_state = next,
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    warn!(missed, "relay status events lagged, resynchronising");
                    relay_state = inner.paths.relay().status();
                }
                Err(broadcast::error::RecvError::Closed) => {}
            }
        }

        let status = inner.status();
        if matches!(status, PathStatus::Failed(_)) {
            return;
        }

        // Relay availability first: it drives Reconnecting for both Relayed and Direct.
        match relay_state.clone() {
            RelayStatus::Failed => {
                inner.transition(
                    PathStatus::Failed(FailReason::Relay),
                    "no relay within 60 s",
                );
                return;
            }
            RelayStatus::Reconnecting | RelayStatus::Connecting => {
                if status != PathStatus::Reconnecting {
                    previous_before_reconnect = status;
                    reconnect_since = Some(Instant::now());
                    inner.transition(PathStatus::Reconnecting, "relay session lost");
                }
                continue;
            }
            RelayStatus::Up(_) => {
                if status == PathStatus::Reconnecting {
                    let waited = reconnect_since
                        .map(|t| t.elapsed().as_millis() as u64)
                        .unwrap_or(0);
                    inner.transition(
                        previous_before_reconnect,
                        format!("new relay welcome after {waited} ms"),
                    );
                    reconnect_since = None;
                }
            }
        }

        let status = inner.status();

        if !inner.allow_direct {
            // Owner declined direct paths.  Relay-only is a first-class outcome.
            if status == PathStatus::Relayed && !candidates_announced {
                candidates_announced = true;
                inner.transition(PathStatus::Relayed, "owner declined direct paths");
            }
            continue;
        }

        if reannounce_at.is_some_and(|at| Instant::now() >= at) {
            reannounce_at = None;
            info!(peer = %inner.peer, "interface change: re-announcing candidates");
            let _ = inner.control_tx.try_send(ControlSend::Candidates);
            let _ = inner.control_tx.try_send(ControlSend::PunchNow);
            inner.probe_now.store(PROBE_LOCAL, Ordering::SeqCst);
        }

        let peer_candidates = inner.paths.peer_candidates(inner.peer);
        let proven = inner.paths.proven_direct(inner.peer);
        let asked = inner.probe_now.swap(PROBE_IDLE, Ordering::SeqCst);
        if asked != PROBE_IDLE {
            next_probe_attempt = Instant::now();
            round_cause = if asked == PROBE_PEER {
                "punch-now from peer"
            } else {
                "requested here"
            };
            // While Direct, a request re-proves at once rather than waiting
            // for the next re-prove interval.
            last_probe_sent = Instant::now() - REPROVE_INTERVAL;
        }

        match status {
            PathStatus::Relayed => {
                // The path socket sends direct as soon as a fresh proof exists, so
                // the report follows the socket rather than the other way round.
                if let Some(proven) = proven
                    && proven.proved_at.elapsed() < DIRECT_FRESH
                {
                    inner.transition(
                        PathStatus::Direct,
                        format!("signed pong proved {}", proven.addr),
                    );
                    continue;
                }
                if peer_candidates.is_empty() {
                    if !candidates_announced {
                        candidates_announced = true;
                        inner.transition(PathStatus::Relayed, "peer offered no candidates");
                    }
                    continue;
                }
                if Instant::now() < next_probe_attempt {
                    continue;
                }
                inner.transition(
                    PathStatus::Probing,
                    format!("{} peer candidates, {round_cause}", peer_candidates.len()),
                );
                round_cause = "cooldown elapsed";
                probe_round_ends = Some(Instant::now() + PROBE_ROUND);
                inner.paths.send_probes(inner.peer);
                last_probe_sent = Instant::now();
            }
            PathStatus::Probing => {
                if let Some(proven) = proven
                    && proven.proved_at.elapsed() < DIRECT_FRESH
                {
                    inner.transition(
                        PathStatus::Direct,
                        format!("signed pong proved {}", proven.addr),
                    );
                    probe_round_ends = None;
                    continue;
                }
                if last_probe_sent.elapsed() >= Duration::from_millis(500) {
                    inner.paths.send_probes(inner.peer);
                    last_probe_sent = Instant::now();
                }
                if probe_round_ends.is_some_and(|end| Instant::now() >= end) {
                    probe_round_ends = None;
                    next_probe_attempt = Instant::now() + PROBE_COOLDOWN;
                    inner.transition(PathStatus::Relayed, "direct_failed: all probes timed out");
                }
            }
            PathStatus::Direct => {
                let age = proven.map(|p| p.proved_at.elapsed());
                match age {
                    Some(age) if age < DIRECT_FRESH => {
                        if last_probe_sent.elapsed() >= REPROVE_INTERVAL {
                            inner.paths.send_probes(inner.peer);
                            last_probe_sent = Instant::now();
                        }
                    }
                    _ => {
                        inner.paths.drop_direct(inner.peer);
                        next_probe_attempt = Instant::now() + PROBE_COOLDOWN;
                        inner.transition(
                            PathStatus::Relayed,
                            "direct_lost: proof older than 15 s and re-probe failed",
                        );
                    }
                }
            }
            _ => {}
        }
    }
}
