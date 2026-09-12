//! Kotlin's owned boundary to Link: it supplies encrypted persisted route state;
//! Rust owns endpoint, sessions, and WebSocket handles. No Nostr data enters here.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt as _, Full};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use link_core::card::{MAX_CARD_BYTES, MAX_LIFETIME_SECONDS};
use link_core::{Card, NodeId, TransportKey, VerifyContext};
use link_endpoint::{Endpoint, EndpointConfig, MAX_PAIRING_LIFETIME, RelaySpec, Session};
use link_websocket::{IncomingMessage, Socket};
use thiserror::Error;
use tokio::runtime::Runtime;
use url::Url;
use zeroize::{Zeroize as _, Zeroizing};

uniffi::setup_scaffolding!();

#[derive(uniffi::Record, Clone, Debug)]
pub struct LinkConfig {
    pub transport_seed: Vec<u8>,
    pub relay_urls: Vec<String>,
    pub allow_direct: bool,
    pub routes: Vec<LinkRoute>,
}
#[derive(uniffi::Record, Clone)]
pub struct LinkRoute {
    pub route_id: String,
    pub card: Vec<u8>,
    pub paired_route_secret: Vec<u8>,
    pub card_serial: u64,
    /// Unix second at which the signed card was accepted. Persisted cards are
    /// re-verified at this time because they pin the enrolled identity; their
    /// advertisement expiry does not revoke an established route.
    pub card_verified_at: u64,
}
impl std::fmt::Debug for LinkRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkRoute")
            .field("route_id", &self.route_id)
            .field("card", &format_args!("{} bytes", self.card.len()))
            .field("paired_route_secret", &"[redacted]")
            .field("card_serial", &self.card_serial)
            .field("card_verified_at", &self.card_verified_at)
            .finish()
    }
}
#[derive(uniffi::Record, Clone)]
pub struct LinkPairingBundle {
    pub route_id: String,
    pub server_card: Vec<u8>,
    /// The QR's 16 raw capability bytes. It is never retained by this engine.
    pub pairing_secret: Vec<u8>,
    /// The QR's absolute Unix-second deadline.
    pub expires_at: u64,
}
impl std::fmt::Debug for LinkPairingBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkPairingBundle")
            .field("route_id", &self.route_id)
            .field(
                "server_card",
                &format_args!("{} bytes", self.server_card.len()),
            )
            .field("pairing_secret", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}
#[derive(uniffi::Record, Clone, Debug)]
pub struct LinkPath {
    pub status: String,
    pub relay: Option<String>,
    pub direct: Option<String>,
    pub cause: String,
}

#[derive(uniffi::Error, Error, Debug)]
pub enum LinkError {
    #[error("configuration: {0}")]
    Config(String),
    #[error("route: {0}")]
    Route(String),
    #[error("transport: {0}")]
    Transport(String),
    #[error("socket: {0}")]
    Socket(String),
    #[error("the engine is stopped")]
    Stopped,
}

#[uniffi::export(callback_interface)]
pub trait LinkSocketListener: Send + Sync {
    fn on_open(&self);
    fn on_text(&self, text: String);
    fn on_closed(&self, reason: String);
}

struct RouteState {
    node: NodeId,
    serial: u64,
    card: Card,
    session: Option<Arc<Session>>,
}
struct Inner {
    endpoint: Arc<Endpoint>,
    routes: HashMap<String, RouteState>,
    stopped: bool,
}
#[derive(uniffi::Object)]
pub struct LinkEngine {
    runtime: Runtime,
    inner: Mutex<Inner>,
}
#[derive(uniffi::Object)]
pub struct LinkSocket {
    socket: Socket,
    session: Arc<Session>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .unwrap_or(0)
}
fn secret(bytes: &[u8]) -> Result<[u8; 32], LinkError> {
    bytes
        .try_into()
        .map_err(|_| LinkError::Route("paired route secret must be 32 bytes".into()))
}
fn pairing_secret(bytes: &[u8]) -> Result<[u8; 16], LinkError> {
    bytes
        .try_into()
        .map_err(|_| LinkError::Route("pairing secret must be 16 bytes".into()))
}
const PAIRING_CLOCK_SKEW: Duration = Duration::from_secs(60);

fn pairing_lifetime(expires_at: u64, now: u64) -> Result<Duration, LinkError> {
    let remaining = expires_at
        .checked_sub(now)
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs)
        .ok_or_else(|| LinkError::Route("pairing bundle is expired".into()))?;
    if remaining > MAX_PAIRING_LIFETIME + PAIRING_CLOCK_SKEW {
        return Err(LinkError::Route(
            "pairing bundle lifetime is too long".into(),
        ));
    }
    Ok(remaining.min(MAX_PAIRING_LIFETIME))
}
fn node_from_card_bytes(bytes: &[u8]) -> Result<NodeId, LinkError> {
    bytes
        .get(5..37)
        .and_then(NodeId::from_slice)
        .ok_or_else(|| LinkError::Route("card has no node id".into()))
}
/// Persisted cards are re-verified at their retained serial, not treated as new arrivals.
fn verify_route(route: &LinkRoute) -> Result<(NodeId, Card), LinkError> {
    if route.route_id.is_empty() {
        return Err(LinkError::Route("route id must not be empty".into()));
    }
    let node = node_from_card_bytes(&route.card)?;
    let previous = route
        .card_serial
        .checked_sub(1)
        .ok_or_else(|| LinkError::Route("card serial must be positive".into()))?;
    let card = Card::verify(
        &route.card,
        &VerifyContext::new(route.card_verified_at)
            .expecting(node)
            .after_serial(previous),
    )
    .map_err(|error| LinkError::Route(error.to_string()))?;
    if card.serial != route.card_serial {
        return Err(LinkError::Route(
            "card serial does not match retained serial".into(),
        ));
    }
    Ok((node, card))
}

const ROUTE_MAGIC: &[u8; 4] = b"EVR1";
const ROUTE_PREFIX_BYTES: usize = ROUTE_MAGIC.len() + 2;
const MAX_ROUTE_FRAME_BYTES: usize = ROUTE_PREFIX_BYTES + MAX_CARD_BYTES;

fn route_frame(card: &[u8]) -> Vec<u8> {
    let length = u16::try_from(card.len()).expect("Link cards fit in u16");
    let mut frame = Vec::with_capacity(ROUTE_PREFIX_BYTES + card.len());
    frame.extend_from_slice(ROUTE_MAGIC);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(card);
    frame
}

fn route_card(frame: &[u8]) -> Result<&[u8], LinkError> {
    if frame.len() < ROUTE_PREFIX_BYTES || &frame[..4] != ROUTE_MAGIC {
        return Err(LinkError::Route(
            "server returned a malformed route frame".into(),
        ));
    }
    let length = usize::from(u16::from_be_bytes([frame[4], frame[5]]));
    if length > MAX_CARD_BYTES || frame.len() != ROUTE_PREFIX_BYTES + length {
        return Err(LinkError::Route(
            "server returned a malformed route frame".into(),
        ));
    }
    Ok(&frame[ROUTE_PREFIX_BYTES..])
}

async fn collect_bounded(mut body: hyper::body::Incoming) -> Result<Bytes, LinkError> {
    let mut bytes = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| LinkError::Transport(error.to_string()))?;
        if let Ok(data) = frame.into_data() {
            if bytes.len().saturating_add(data.len()) > MAX_ROUTE_FRAME_BYTES {
                return Err(LinkError::Route(
                    "server route response is too large".into(),
                ));
            }
            bytes.extend_from_slice(&data);
        }
    }
    Ok(bytes.freeze())
}
fn path(session: &Session) -> LinkPath {
    let report = session.path();
    LinkPath {
        status: report.status.outcome(),
        relay: report.relay,
        direct: report.direct.map(|address| address.to_string()),
        cause: report.cause,
    }
}

#[uniffi::export]
impl LinkEngine {
    #[uniffi::constructor]
    pub fn start(config: LinkConfig) -> Result<Arc<Self>, LinkError> {
        let seed: [u8; 32] = config
            .transport_seed
            .as_slice()
            .try_into()
            .map_err(|_| LinkError::Config("transport seed must be 32 bytes".into()))?;
        let mut routes = HashMap::new();
        let mut paired_routes = HashMap::new();
        for route in &config.routes {
            let (node, card) = verify_route(route)?;
            if routes.contains_key(&route.route_id) {
                return Err(LinkError::Config("duplicate route id".into()));
            }
            paired_routes.insert(node, Zeroizing::new(secret(&route.paired_route_secret)?));
            routes.insert(
                route.route_id.clone(),
                RouteState {
                    node,
                    serial: route.card_serial,
                    card,
                    session: None,
                },
            );
        }
        let mut endpoint_config = EndpointConfig::new(TransportKey::from_seed(seed));
        endpoint_config.relays = config.relay_urls.iter().map(RelaySpec::plain).collect();
        endpoint_config.allow_direct = config.allow_direct;
        // Mobile DNS, TLS and WebSocket setup can be delayed by Android's
        // process and network scheduling. Give it the relay driver's existing
        // reconnect window before declaring first contact unavailable.
        endpoint_config.rendezvous_timeout = Duration::from_secs(60);
        // Always tag mode, including the empty case: no identity registration on later upsert.
        endpoint_config.paired_routes = Some(paired_routes);
        endpoint_config.net_poll = Duration::ZERO;
        let runtime = Runtime::new().map_err(|error| LinkError::Transport(error.to_string()))?;
        let endpoint = runtime
            .block_on(Endpoint::open(endpoint_config))
            .map_err(|error| LinkError::Transport(error.to_string()))?;
        Ok(Arc::new(Self {
            runtime,
            inner: Mutex::new(Inner {
                endpoint: Arc::new(endpoint),
                routes,
                stopped: false,
            }),
        }))
    }

    pub fn open_socket(
        &self,
        virtual_url: String,
        route_id: String,
        listener: Box<dyn LinkSocketListener>,
    ) -> Result<Arc<LinkSocket>, LinkError> {
        let url = Url::parse(&virtual_url).map_err(|error| LinkError::Socket(error.to_string()))?;
        let session = {
            // Keep the short engine lock through the first dial. This is
            // deliberate: it makes simultaneous opens coalesce before Link's
            // own newest-session-wins rule could supersede the first one.
            let mut inner = self.inner.lock().expect("engine lock");
            if inner.stopped {
                return Err(LinkError::Stopped);
            }
            let route = inner
                .routes
                .get(&route_id)
                .ok_or_else(|| LinkError::Route("route is not installed".into()))?;
            link_websocket::validate_virtual_url(&url, route.node)
                .map_err(|error| LinkError::Socket(error.to_string()))?;
            if let Some(session) = &route.session {
                session.clone()
            } else {
                let card = route.card.clone();
                let endpoint = inner.endpoint.clone();
                let session = Arc::new(
                    self.runtime
                        .block_on(endpoint.connect(&card))
                        .map_err(|error| LinkError::Transport(error.to_string()))?,
                );
                // `route` was only borrowed above and the engine lock means
                // it cannot have been removed or replaced during this dial.
                inner
                    .routes
                    .get_mut(&route_id)
                    .expect("route retained by engine lock")
                    .session = Some(session.clone());
                session
            }
        };
        let (socket, mut incoming) = self
            .runtime
            .block_on(link_websocket::open(&session, url))
            .map_err(|error| LinkError::Socket(error.to_string()))?;
        listener.on_open();
        self.runtime.spawn(async move {
            while let Some(message) = incoming.recv().await {
                match message {
                    IncomingMessage::Text(text) => listener.on_text(text),
                    IncomingMessage::Closed(reason) => {
                        listener.on_closed(reason);
                        return;
                    }
                }
            }
        });
        Ok(Arc::new(LinkSocket { socket, session }))
    }

    /// Ask the paired server to retire this route. Local credentials remain
    /// installed until the product durably records the acknowledged outcome.
    pub fn retire_route(&self, route_id: String) -> Result<(), LinkError> {
        self.delete_route(route_id, "/events/route".into(), "route retirement".into())
    }

    /// Remove the paired transport after the product has durably recorded
    /// logical retirement. The caller may safely treat transport failure as a
    /// lost final acknowledgement: application authority was revoked by
    /// `retire_route`, and this method never removes local credentials.
    pub fn finalize_route(&self, route_id: String) -> Result<(), LinkError> {
        self.delete_route(
            route_id,
            "/events/route/finalize".into(),
            "route finalisation".into(),
        )
    }

    fn delete_route(
        &self,
        route_id: String,
        path: String,
        operation: String,
    ) -> Result<(), LinkError> {
        let (session, node) = {
            let mut inner = self.inner.lock().expect("engine lock");
            if inner.stopped {
                return Err(LinkError::Stopped);
            }
            let route = inner
                .routes
                .get(&route_id)
                .ok_or_else(|| LinkError::Route("route is not installed".into()))?;
            let node = route.node;
            let session = if let Some(session) = &route.session {
                session.clone()
            } else {
                let card = route.card.clone();
                let session = Arc::new(
                    self.runtime
                        .block_on(inner.endpoint.connect(&card))
                        .map_err(|error| LinkError::Transport(error.to_string()))?,
                );
                inner
                    .routes
                    .get_mut(&route_id)
                    .expect("route retained by engine lock")
                    .session = Some(session.clone());
                session
            };
            (session, node)
        };
        self.runtime.block_on(async {
            let stream = session
                .open_stream()
                .await
                .map_err(|error| LinkError::Transport(error.to_string()))?;
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream))
                    .await
                    .map_err(|error| LinkError::Transport(error.to_string()))?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            let request = Request::builder()
                .method(Method::DELETE)
                .uri(path)
                .header(hyper::header::HOST, node.to_base32())
                .body(Full::new(Bytes::new()))
                .map_err(|error| LinkError::Route(error.to_string()))?;
            let response = sender
                .send_request(request)
                .await
                .map_err(|error| LinkError::Transport(error.to_string()))?;
            if response.status() != StatusCode::NO_CONTENT {
                return Err(LinkError::Route(format!(
                    "server refused {operation} with {}",
                    response.status()
                )));
            }
            collect_bounded(response.into_body()).await?;
            Ok(())
        })
    }

    /// Enrol one durable event route over Link's quarantined provisional
    /// session, install it in the running engine, and return the exact record
    /// the Kotlin vault must commit atomically.
    pub fn pair_route(&self, mut bundle: LinkPairingBundle) -> Result<LinkRoute, LinkError> {
        if bundle.route_id.is_empty() {
            return Err(LinkError::Route("route id must not be empty".into()));
        }
        let now = now_unix();
        let lifetime = pairing_lifetime(bundle.expires_at, now)?;
        let raw_pairing = Zeroizing::new(pairing_secret(&bundle.pairing_secret)?);
        bundle.pairing_secret.zeroize();
        let server_node = node_from_card_bytes(&bundle.server_card)?;
        let offered_card = Card::verify(
            &bundle.server_card,
            &VerifyContext::new(now).expecting(server_node),
        )
        .map_err(|error| LinkError::Route(error.to_string()))?;
        let endpoint = {
            let inner = self.inner.lock().expect("engine lock");
            if inner.stopped {
                return Err(LinkError::Stopped);
            }
            if inner
                .routes
                .get(&bundle.route_id)
                .is_some_and(|existing| existing.node != server_node)
            {
                return Err(LinkError::Route(
                    "route id is already bound to another node".into(),
                ));
            }
            inner.endpoint.clone()
        };

        // UniFFI calls this synchronous method from an ordinary Kotlin worker.
        // Pairing registration arms an expiry task, so it must enter the
        // engine-owned runtime just like the network exchange below.
        let registration = self
            .runtime
            .block_on(async { endpoint.register_pairing_secret(*raw_pairing, lifetime) })
            .map_err(|error| LinkError::Route(error.to_string()))?;
        let caller_card = endpoint.card(Duration::from_secs(MAX_LIFETIME_SECONDS), Vec::new());
        let request_body = route_frame(caller_card.as_bytes());
        let secret_header = hex::encode(raw_pairing.as_ref());

        let paired = self.runtime.block_on(async {
            let session = endpoint
                .connect_pairing(&offered_card, &registration)
                .await
                .map_err(|error| {
                    let activity = endpoint.pairing_relay_activity(&registration);
                    LinkError::Transport(format!("{error}; {activity}"))
                })?;
            let result = async {
                let route_secret = session
                    .paired_route_secret()
                    .map_err(|error| LinkError::Route(error.to_string()))?;
                let stream = session
                    .open_stream()
                    .await
                    .map_err(|error| LinkError::Transport(error.to_string()))?;
                let (mut sender, connection) =
                    hyper::client::conn::http1::handshake(TokioIo::new(stream))
                        .await
                        .map_err(|error| LinkError::Transport(error.to_string()))?;
                tokio::spawn(async move {
                    let _ = connection.await;
                });
                let request = Request::builder()
                    .method(Method::PUT)
                    .uri("/events/route")
                    .header(hyper::header::HOST, server_node.to_base32())
                    .header(hyper::header::CONTENT_TYPE, "application/octet-stream")
                    .header("x-bothy-pairing-secret", secret_header)
                    .body(Full::new(Bytes::from(request_body)))
                    .map_err(|error| LinkError::Route(error.to_string()))?;
                let response = sender
                    .send_request(request)
                    .await
                    .map_err(|error| LinkError::Transport(error.to_string()))?;
                if response.status() != StatusCode::OK {
                    return Err(LinkError::Route(format!(
                        "server refused route enrolment with {}",
                        response.status()
                    )));
                }
                let answer = collect_bounded(response.into_body()).await?;
                let response_card_bytes = route_card(&answer)?.to_vec();
                let response_verified_at = now_unix();
                let response_card = Card::verify(
                    &response_card_bytes,
                    &VerifyContext::new(response_verified_at).expecting(server_node),
                )
                .map_err(|error| LinkError::Route(error.to_string()))?;
                if response_card.serial < offered_card.serial {
                    return Err(LinkError::Route(
                        "server returned an older card than the pairing bundle".into(),
                    ));
                }
                Ok((response_card, route_secret, response_verified_at))
            }
            .await;
            session.close().await;
            result
        })?;

        let route = LinkRoute {
            route_id: bundle.route_id,
            card: paired.0.as_bytes().to_vec(),
            paired_route_secret: paired.1.to_vec(),
            card_serial: paired.0.serial,
            card_verified_at: paired.2,
        };
        let previous_session = {
            let mut inner = self.inner.lock().expect("engine lock");
            if inner.stopped {
                return Err(LinkError::Stopped);
            }
            let prior = inner
                .routes
                .get(&route.route_id)
                .map(|existing| {
                    if existing.node != paired.0.node_id {
                        return Err(LinkError::Route(
                            "route id is already bound to another node".into(),
                        ));
                    }
                    if route.card_serial < existing.serial {
                        return Err(LinkError::Route(
                            "server card serial moved backwards".into(),
                        ));
                    }
                    Ok(existing.session.clone())
                })
                .transpose()?;
            inner
                .endpoint
                .rendezvous_book()
                .expect("tag mode")
                .upsert_paired(paired.0.node_id, secret(&route.paired_route_secret)?);
            inner.routes.insert(
                route.route_id.clone(),
                RouteState {
                    node: paired.0.node_id,
                    serial: route.card_serial,
                    card: paired.0,
                    session: None,
                },
            );
            prior.flatten()
        };
        if let Some(session) = previous_session {
            self.runtime.block_on(session.close(1));
        }
        Ok(route)
    }

    pub fn upsert_route(&self, route: LinkRoute) -> Result<(), LinkError> {
        let (node, card) = verify_route(&route)?;
        let route_secret = secret(&route.paired_route_secret)?;
        let previous_session = {
            let mut inner = self.inner.lock().expect("engine lock");
            if inner.stopped {
                return Err(LinkError::Stopped);
            }
            let previous = inner
                .routes
                .get(&route.route_id)
                .map(|existing| {
                    if route.card_serial <= existing.serial {
                        return Err(LinkError::Route("live card serial must increase".into()));
                    }
                    Ok((existing.node, existing.session.clone()))
                })
                .transpose()?;
            if let Some((old_node, _)) = previous.as_ref() {
                inner
                    .endpoint
                    .rendezvous_book()
                    .expect("tag mode")
                    .remove_paired(*old_node);
            }
            inner
                .endpoint
                .rendezvous_book()
                .expect("tag mode")
                .upsert_paired(node, route_secret);
            inner.routes.insert(
                route.route_id,
                RouteState {
                    node,
                    serial: route.card_serial,
                    card,
                    session: None,
                },
            );
            previous.and_then(|(_, session)| session)
        };
        // The cached session is no longer authorised for this route. Its
        // streams observe closure and each reports its terminal callback.
        if let Some(session) = previous_session {
            self.runtime.block_on(session.close(1));
        }
        Ok(())
    }
    pub fn remove_route(&self, route_id: String) -> Result<(), LinkError> {
        let session = {
            let mut inner = self.inner.lock().expect("engine lock");
            if inner.stopped {
                return Err(LinkError::Stopped);
            }
            let route = inner
                .routes
                .remove(&route_id)
                .ok_or_else(|| LinkError::Route("route is not installed".into()))?;
            inner
                .endpoint
                .rendezvous_book()
                .expect("tag mode")
                .remove_paired(route.node);
            route.session
        };
        if let Some(session) = session {
            self.runtime.block_on(session.close(1));
        }
        Ok(())
    }
    pub fn reannounce(&self) -> Result<(), LinkError> {
        let sessions: Vec<_> = {
            let inner = self.inner.lock().expect("engine lock");
            if inner.stopped {
                return Err(LinkError::Stopped);
            }
            inner
                .routes
                .values()
                .filter_map(|route| route.session.clone())
                .collect()
        };
        for session in sessions {
            session.reannounce();
        }
        Ok(())
    }
    pub fn stop(&self) {
        let sessions: Vec<_> = {
            let mut inner = self.inner.lock().expect("engine lock");
            if inner.stopped {
                return;
            }
            inner.stopped = true;
            inner
                .routes
                .values_mut()
                .filter_map(|route| route.session.take())
                .collect()
        };
        for session in sessions {
            self.runtime.block_on(session.close(1));
        }
    }
}
#[uniffi::export]
impl LinkSocket {
    pub fn send_text(&self, text: String) -> Result<(), LinkError> {
        self.socket
            .send_text(text)
            .map_err(|error| LinkError::Socket(error.to_string()))
    }
    /// Close the application stream. This is deliberately not named `close`:
    /// UniFFI's Kotlin object already implements `AutoCloseable.close()` for
    /// native-object disposal, and exporting the same name makes the generated
    /// Android binding uncompilable.
    pub fn disconnect(&self) -> Result<(), LinkError> {
        self.socket
            .close()
            .map_err(|error| LinkError::Socket(error.to_string()))
    }
    pub fn path(&self) -> LinkPath {
        path(&self.session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use link_endpoint::AcceptedSession;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    #[test]
    fn starts_in_tag_mode_with_no_routes() {
        let engine = LinkEngine::start(LinkConfig {
            transport_seed: vec![9; 32],
            relay_urls: Vec::new(),
            allow_direct: false,
            routes: Vec::new(),
        })
        .expect("empty paired route map is a valid tag-mode start");
        engine.stop();
    }

    #[test]
    fn route_secret_is_exactly_32_bytes() {
        assert!(secret(&[0; 31]).is_err());
        assert!(secret(&[0; 32]).is_ok());
    }

    #[test]
    fn pairing_lifetime_tolerates_bounded_clock_skew_without_extending_admission() {
        assert_eq!(
            pairing_lifetime(1_601, 1_000).expect("one second of skew is accepted"),
            MAX_PAIRING_LIFETIME,
        );
        assert!(pairing_lifetime(1_000, 1_000).is_err());
        assert!(pairing_lifetime(1_661, 1_000).is_err());
    }

    #[test]
    fn persisted_route_reverifies_at_its_acceptance_time() {
        let key = TransportKey::generate();
        let card = Card::sign(&key, 100, 200, 7, Vec::new());
        let route = LinkRoute {
            route_id: "durable".into(),
            card: card.as_bytes().to_vec(),
            paired_route_secret: vec![0x25; 32],
            card_serial: 7,
            card_verified_at: 150,
        };
        let (node, verified) = verify_route(&route).expect("persisted identity pin");
        assert_eq!(node, key.node_id());
        assert_eq!(verified, card);
    }

    #[test]
    fn route_and_pairing_debug_never_print_secrets() {
        let route = LinkRoute {
            route_id: "room".into(),
            card: vec![1, 2],
            paired_route_secret: vec![0x7b; 32],
            card_serial: 1,
            card_verified_at: 2,
        };
        let bundle = LinkPairingBundle {
            route_id: "room".into(),
            server_card: vec![3, 4],
            pairing_secret: vec![0x6a; 16],
            expires_at: 3,
        };
        assert!(!format!("{route:?}").contains(&"7b".repeat(32)));
        assert!(!format!("{bundle:?}").contains(&"6a".repeat(16)));
    }

    #[test]
    fn pair_route_refuses_a_conflicting_node_before_dialling() {
        let now = now_unix();
        let existing_key = TransportKey::generate();
        let existing_card = Card::sign(&existing_key, now, now + 600, 1, Vec::new());
        let engine = LinkEngine::start(LinkConfig {
            transport_seed: vec![0x19; 32],
            relay_urls: Vec::new(),
            allow_direct: false,
            routes: vec![LinkRoute {
                route_id: "circle-main".into(),
                card: existing_card.as_bytes().to_vec(),
                paired_route_secret: vec![0x28; 32],
                card_serial: 1,
                card_verified_at: now,
            }],
        })
        .expect("engine");
        let other_key = TransportKey::generate();
        let other_card = Card::sign(&other_key, now, now + 600, 1, Vec::new());

        let error = engine
            .pair_route(LinkPairingBundle {
                route_id: "circle-main".into(),
                server_card: other_card.as_bytes().to_vec(),
                pairing_secret: vec![0x39; 16],
                expires_at: now + 600,
            })
            .expect_err("a route id cannot move to another node");
        assert_eq!(
            error.to_string(),
            "route: route id is already bound to another node"
        );
        engine.stop();
    }

    #[test]
    fn failed_retirement_keeps_the_local_route_for_retry() {
        let now = now_unix();
        let server_key = TransportKey::generate();
        let server_card = Card::sign(&server_key, now, now + 600, 1, Vec::new());
        let engine = LinkEngine::start(LinkConfig {
            transport_seed: vec![0x41; 32],
            relay_urls: Vec::new(),
            allow_direct: false,
            routes: vec![LinkRoute {
                route_id: "route-to-retire".into(),
                card: server_card.as_bytes().to_vec(),
                paired_route_secret: vec![0x51; 32],
                card_serial: 1,
                card_verified_at: now,
            }],
        })
        .expect("engine");

        assert!(engine.retire_route("route-to-retire".into()).is_err());
        assert!(engine.finalize_route("route-to-retire".into()).is_err());
        assert!(
            engine
                .inner
                .lock()
                .expect("engine")
                .routes
                .contains_key("route-to-retire")
        );
        engine.stop();
    }

    async fn serve_route_once(
        endpoint: Arc<Endpoint>,
        server_card: Card,
        expected_secret: String,
    ) -> [u8; 32] {
        let session = match endpoint.accept_any().await.expect("pairing arrives") {
            AcceptedSession::Pairing(session) => session,
            AcceptedSession::Pinned(_) => panic!("route enrolment must be provisional"),
        };
        let exporter = session
            .paired_route_secret()
            .expect("server exporter secret");
        let mut stream = session.accept_stream().await.expect("one route request");
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let byte = stream.read_u8().await.expect("request head");
            head.push(byte);
            assert!(head.len() < 8 * 1024, "request head is bounded");
        }
        let head_text = std::str::from_utf8(&head).expect("ASCII request head");
        assert!(head_text.starts_with("PUT /events/route HTTP/1.1\r\n"));
        assert!(
            head_text
                .to_ascii_lowercase()
                .contains(&format!("x-bothy-pairing-secret: {}\r\n", expected_secret))
        );
        let content_length = head_text
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .and_then(|value| value.parse::<usize>().ok())
            })
            .expect("content length");
        let mut body = vec![0; content_length];
        stream.read_exact(&mut body).await.expect("request body");
        let caller_card = Card::verify(
            route_card(&body).expect("caller card frame"),
            &VerifyContext::new(now_unix()).expecting(session.peer()),
        )
        .expect("caller card matches provisional key");
        assert_eq!(caller_card.node_id, session.peer());

        let response = route_frame(server_card.as_bytes());
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response.len()
        );
        stream
            .write_all(head.as_bytes())
            .await
            .expect("response head");
        stream.write_all(&response).await.expect("response body");
        stream.shutdown().await.expect("finish response");
        let secret = *exporter;
        let _ = session.closed().await;
        secret
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pair_route_exchanges_and_replaces_the_tls_exporter() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let relay = link_relay::start(link_relay::RelayConfig {
            ws_bind: "127.0.0.1:0".parse().expect("ws bind"),
            udp_bind: "127.0.0.1:0".parse().expect("udp bind"),
            hosts: vec!["127.0.0.1".into()],
            tls: None,
            bytes_per_second: 0,
            max_sessions: 16,
            max_sessions_per_source: 0,
            reflector_per_second: 100.0,
        })
        .await
        .expect("relay");
        let relay_url = relay.url("127.0.0.1");
        let mut server_config = EndpointConfig::new(TransportKey::generate());
        server_config.relays = vec![RelaySpec::plain(&relay_url)];
        server_config.allow_direct = false;
        server_config.bind = "127.0.0.1:0".parse().expect("server bind");
        server_config.rendezvous = Some(HashMap::new());
        let server = Arc::new(Endpoint::open(server_config).await.expect("server"));
        let server_card = server.card(Duration::from_secs(600), Vec::new());
        let _warm_registration = server
            .register_pairing_secret([0x44; 16], Duration::from_secs(600))
            .expect("warm server registration");
        tokio::time::timeout(
            Duration::from_secs(15),
            server.paths().relay().home().wait_up(),
        )
        .await
        .expect("server relay connects before the QR tag is added")
        .expect("server relay is up");
        let raw_pairing = [0x4d; 16];
        let _server_registration = server
            .register_pairing_secret(raw_pairing, Duration::from_secs(600))
            .expect("server registration");
        let engine = tokio::task::spawn_blocking({
            move || {
                LinkEngine::start(LinkConfig {
                    transport_seed: vec![0x35; 32],
                    relay_urls: Vec::new(),
                    allow_direct: false,
                    routes: Vec::new(),
                })
                .expect("engine")
            }
        })
        .await
        .expect("engine task");

        let pair_once = |server: Arc<Endpoint>, card: Card, engine: Arc<LinkEngine>| async move {
            let expected = hex::encode(raw_pairing);
            let serving = tokio::spawn(serve_route_once(server, card.clone(), expected));
            let route = tokio::task::spawn_blocking(move || {
                engine.pair_route(LinkPairingBundle {
                    route_id: "circle-main".into(),
                    server_card: card.as_bytes().to_vec(),
                    pairing_secret: raw_pairing.to_vec(),
                    expires_at: now_unix() + 600,
                })
            })
            .await
            .expect("pair task")
            .expect("pair route");
            let server_secret = serving.await.expect("server task");
            (route, server_secret)
        };

        let (first, server_first) =
            pair_once(server.clone(), server_card.clone(), engine.clone()).await;
        assert_eq!(first.paired_route_secret, server_first);
        assert_eq!(first.card, server_card.as_bytes());
        let (second, server_second) = pair_once(server.clone(), server_card, engine.clone()).await;
        assert_eq!(second.paired_route_secret, server_second);
        assert_ne!(first.paired_route_secret, second.paired_route_secret);
        assert!(
            engine
                .inner
                .lock()
                .expect("engine")
                .routes
                .contains_key("circle-main"),
            "the returned route is also installed in the live engine",
        );
        engine.stop();
        tokio::task::spawn_blocking(move || drop(engine))
            .await
            .expect("engine drop");
    }
}
