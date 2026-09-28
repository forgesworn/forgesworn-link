//! The paired-route engine: the application-facing half of Link that both
//! link-ffi (Kotlin/Android) and link-web (a browser) expose.
//!
//! The host supplies encrypted persisted route state; this crate owns the
//! endpoint, the one session per route, the bounded JSON request, pairing
//! enrolment and the event WebSocket.  Cadence authorization and JSON cross
//! as opaque bytes; Link interprets no Nostr event or application authority.
//! Everything here is async and runs on `link_endpoint::rt`, so the same
//! checks and the same protocol run natively and in a browser; the
//! wrappers only adapt calling conventions.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Body;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use link_core::card::{MAX_CARD_BYTES, MAX_LIFETIME_SECONDS};
use link_core::{Card, NodeId, PathStatus, TransportKey, VerifyContext};
use link_endpoint::rt;
use link_endpoint::{Endpoint, EndpointConfig, MAX_PAIRING_LIFETIME, RelaySpec, Session};
use link_websocket::{IncomingMessage, Socket};
use thiserror::Error;
use tokio::sync::{Mutex, mpsc};
use url::Url;
use zeroize::{Zeroize as _, Zeroizing};

/// What the host starts an engine with.
pub struct EngineConfig {
    pub transport_seed: Vec<u8>,
    pub relay_urls: Vec<String>,
    pub allow_direct: bool,
    pub routes: Vec<Route>,
}

impl Drop for EngineConfig {
    fn drop(&mut self) {
        self.transport_seed.zeroize();
    }
}

/// One persisted paired route, exactly as the host stores it.
#[derive(Clone)]
pub struct Route {
    pub route_id: String,
    pub card: Vec<u8>,
    pub paired_route_secret: Vec<u8>,
    pub card_serial: u64,
    /// Unix second at which the signed card was accepted. Persisted cards are
    /// re-verified at this time because they pin the enrolled identity; their
    /// advertisement expiry does not revoke an established route.
    pub card_verified_at: u64,
}

impl Drop for Route {
    fn drop(&mut self) {
        self.paired_route_secret.zeroize();
    }
}

impl std::fmt::Debug for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Route")
            .field("route_id", &self.route_id)
            .field("card", &format_args!("{} bytes", self.card.len()))
            .field("paired_route_secret", &"[redacted]")
            .field("card_serial", &self.card_serial)
            .field("card_verified_at", &self.card_verified_at)
            .finish()
    }
}

/// A scanned pairing QR.
pub struct PairingBundle {
    pub route_id: String,
    pub server_card: Vec<u8>,
    /// The QR's 16 raw capability bytes. It is never retained by this engine.
    pub pairing_secret: Vec<u8>,
    /// The QR's absolute Unix-second deadline.
    pub expires_at: u64,
}

impl std::fmt::Debug for PairingBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingBundle")
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

impl Drop for PairingBundle {
    fn drop(&mut self) {
        self.pairing_secret.zeroize();
    }
}

/// The exact current path of a session, as the host reports it.
#[derive(Clone, Debug)]
pub struct PathInfo {
    pub status: String,
    pub relay: Option<String>,
    pub direct: Option<String>,
    pub cause: String,
}

/// One JSON request sent over an already paired Link route.
///
/// The route selects a pinned peer. The engine supplies `Host` and
/// `Content-Type`, so the host application cannot redirect this call or
/// change its transport identity.
#[derive(Clone)]
pub struct JsonRequest {
    pub route_id: String,
    pub method: String,
    pub path: String,
    pub authorization: String,
    pub body: Vec<u8>,
}

impl std::fmt::Debug for JsonRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonRequest")
            .field("route_id", &"[redacted]")
            .field("method", &self.method)
            .field("path", &"[redacted]")
            .field("authorization", &"[redacted]")
            .field("body", &format_args!("{} bytes", self.body.len()))
            .finish()
    }
}

/// A bounded JSON response and the Link path that carried it.
#[derive(Clone)]
pub struct JsonResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub path: PathInfo,
}

impl std::fmt::Debug for JsonResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonResponse")
            .field("status", &self.status)
            .field("body", &format_args!("{} bytes", self.body.len()))
            .field("path", &self.path)
            .finish()
    }
}

#[derive(Error, Debug)]
pub enum EngineError {
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

pub const PAIRING_CLOCK_SKEW: Duration = Duration::from_secs(60);
pub const ROUTE_MAGIC: &[u8; 4] = b"EVR1";
pub const ROUTE_PREFIX_BYTES: usize = ROUTE_MAGIC.len() + 2;
pub const MAX_ROUTE_FRAME_BYTES: usize = ROUTE_PREFIX_BYTES + MAX_CARD_BYTES;
pub const MAX_HTTP_PATH_BYTES: usize = 2_048;
pub const MAX_HTTP_AUTHORIZATION_BYTES: usize = 48 * 1_024;
pub const MAX_HTTP_BODY_BYTES: usize = 256 * 1_024;
pub const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub fn secret(bytes: &[u8]) -> Result<[u8; 32], EngineError> {
    bytes
        .try_into()
        .map_err(|_| EngineError::Route("paired route secret must be 32 bytes".into()))
}

pub fn pairing_secret(bytes: &[u8]) -> Result<[u8; 16], EngineError> {
    bytes
        .try_into()
        .map_err(|_| EngineError::Route("pairing secret must be 16 bytes".into()))
}

pub fn pairing_lifetime(expires_at: u64, now: u64) -> Result<Duration, EngineError> {
    let remaining = expires_at
        .checked_sub(now)
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs)
        .ok_or_else(|| EngineError::Route("pairing bundle is expired".into()))?;
    if remaining > MAX_PAIRING_LIFETIME + PAIRING_CLOCK_SKEW {
        return Err(EngineError::Route(
            "pairing bundle lifetime is too long".into(),
        ));
    }
    Ok(remaining.min(MAX_PAIRING_LIFETIME))
}

pub fn node_from_card_bytes(bytes: &[u8]) -> Result<NodeId, EngineError> {
    bytes
        .get(5..37)
        .and_then(NodeId::from_slice)
        .ok_or_else(|| EngineError::Route("card has no node id".into()))
}

/// Persisted cards are re-verified at their retained serial, not treated as new arrivals.
pub fn verify_route(route: &Route) -> Result<(NodeId, Card), EngineError> {
    if route.route_id.is_empty() {
        return Err(EngineError::Route("route id must not be empty".into()));
    }
    let node = node_from_card_bytes(&route.card)?;
    let previous = route
        .card_serial
        .checked_sub(1)
        .ok_or_else(|| EngineError::Route("card serial must be positive".into()))?;
    let card = Card::verify(
        &route.card,
        &VerifyContext::new(route.card_verified_at)
            .expecting(node)
            .after_serial(previous),
    )
    .map_err(|error| EngineError::Route(error.to_string()))?;
    if card.serial != route.card_serial {
        return Err(EngineError::Route(
            "card serial does not match retained serial".into(),
        ));
    }
    Ok((node, card))
}

/// The enrolment body: `EVR1`, a big-endian `u16` length, then a card.
pub fn route_frame(card: &[u8]) -> Vec<u8> {
    let length = u16::try_from(card.len()).expect("Link cards fit in u16");
    let mut frame = Vec::with_capacity(ROUTE_PREFIX_BYTES + card.len());
    frame.extend_from_slice(ROUTE_MAGIC);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(card);
    frame
}

pub fn route_card(frame: &[u8]) -> Result<&[u8], EngineError> {
    if frame.len() < ROUTE_PREFIX_BYTES || &frame[..4] != ROUTE_MAGIC {
        return Err(EngineError::Route(
            "server returned a malformed route frame".into(),
        ));
    }
    let length = usize::from(u16::from_be_bytes([frame[4], frame[5]]));
    if length > MAX_CARD_BYTES || frame.len() != ROUTE_PREFIX_BYTES + length {
        return Err(EngineError::Route(
            "server returned a malformed route frame".into(),
        ));
    }
    Ok(&frame[ROUTE_PREFIX_BYTES..])
}

async fn collect_bounded<B>(mut body: B, limit: usize, label: &str) -> Result<Bytes, EngineError>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let mut bytes = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| EngineError::Transport(error.to_string()))?;
        if let Ok(data) = frame.into_data() {
            if bytes.len().saturating_add(data.len()) > limit {
                return Err(EngineError::Route(format!(
                    "server {label} response is too large"
                )));
            }
            bytes.extend_from_slice(&data);
        }
    }
    Ok(bytes.freeze())
}

pub fn validate_http_request(request: &JsonRequest) -> Result<Method, EngineError> {
    let method = match request.method.as_str() {
        "POST" => Method::POST,
        "PUT" => Method::PUT,
        _ => {
            return Err(EngineError::Route(
                "cadence request method must be POST or PUT".into(),
            ));
        }
    };
    let path = request.path.as_bytes();
    if path.is_empty()
        || path.len() > MAX_HTTP_PATH_BYTES
        || !request.path.starts_with("/cadence/v1/")
        || path.contains(&b'?')
        || path.contains(&b'#')
        || !path.iter().all(u8::is_ascii_graphic)
    {
        return Err(EngineError::Route(
            "cadence request path is not canonical".into(),
        ));
    }
    let authorization = request.authorization.as_bytes();
    let encoded = authorization.strip_prefix(b"Nostr ").unwrap_or_default();
    if authorization.len() > MAX_HTTP_AUTHORIZATION_BYTES
        || encoded.is_empty()
        || !encoded
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    {
        return Err(EngineError::Route(
            "cadence authorization is not one bounded Nostr value".into(),
        ));
    }
    if request.body.len() > MAX_HTTP_BODY_BYTES {
        return Err(EngineError::Route(
            "cadence request body is too large".into(),
        ));
    }
    Ok(method)
}

pub async fn decode_http_response<B>(response: Response<B>) -> Result<(u16, Vec<u8>), EngineError>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    if response.status().is_redirection() {
        return Err(EngineError::Route(
            "cadence response must not redirect".into(),
        ));
    }
    let content_type = response
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .filter(|value| value.eq_ignore_ascii_case("application/json"));
    if content_type.is_none() {
        return Err(EngineError::Route(
            "cadence response is not application/json".into(),
        ));
    }
    let status = response.status().as_u16();
    let body = collect_bounded(response.into_body(), MAX_HTTP_BODY_BYTES, "cadence").await?;
    Ok((status, body.to_vec()))
}

pub fn path(session: &Session) -> PathInfo {
    let report = session.path();
    PathInfo {
        status: report.status.outcome(),
        relay: report.relay,
        direct: report.direct.map(|address| address.to_string()),
        cause: report.cause,
    }
}

/// An HTTP/1.1 client over a fresh application stream on `session`, with
/// its connection driven in the background.
async fn http_sender(
    session: &Session,
) -> Result<hyper::client::conn::http1::SendRequest<Full<Bytes>>, EngineError> {
    let stream = session
        .open_stream()
        .await
        .map_err(|error| EngineError::Transport(error.to_string()))?;
    let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|error| EngineError::Transport(error.to_string()))?;
    rt::spawn(async move {
        let _ = connection.await;
    });
    Ok(sender)
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

/// The engine.  One lock covers the route table and every first dial, so
/// simultaneous callers coalesce onto Link's one session per peer before
/// Link's own newest-session-wins rule could supersede the first one.
pub struct Engine {
    inner: Mutex<Inner>,
}

impl Engine {
    pub async fn start(config: EngineConfig) -> Result<Engine, EngineError> {
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
            config
                .transport_seed
                .as_slice()
                .try_into()
                .map_err(|_| EngineError::Config("transport seed must be 32 bytes".into()))?,
        );
        let mut routes = HashMap::new();
        let mut paired_routes = HashMap::new();
        for route in &config.routes {
            let (node, card) = verify_route(route)?;
            if routes.contains_key(&route.route_id) {
                return Err(EngineError::Config("duplicate route id".into()));
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
        let mut endpoint_config = EndpointConfig::new(TransportKey::from_seed(*seed));
        endpoint_config.relays = config.relay_urls.iter().map(RelaySpec::plain).collect();
        endpoint_config.allow_direct = config.allow_direct;
        // Mobile DNS, TLS and WebSocket setup can be delayed by Android's
        // process and network scheduling. Give it the relay driver's existing
        // reconnect window before declaring first contact unavailable.
        endpoint_config.rendezvous_timeout = Duration::from_secs(60);
        // Always tag mode, including the empty case: no identity registration on later upsert.
        endpoint_config.paired_routes = Some(paired_routes);
        endpoint_config.net_poll = Duration::ZERO;
        let endpoint = Endpoint::open(endpoint_config)
            .await
            .map_err(|error| EngineError::Transport(error.to_string()))?;
        Ok(Engine {
            inner: Mutex::new(Inner {
                endpoint: Arc::new(endpoint),
                routes,
                stopped: false,
            }),
        })
    }

    /// Open the route's event WebSocket.  The virtual URL must name the
    /// route's pinned peer, as `link_websocket::validate_virtual_url` rules.
    pub async fn open_socket(
        &self,
        virtual_url: &str,
        route_id: &str,
    ) -> Result<(Socket, mpsc::Receiver<IncomingMessage>, Arc<Session>), EngineError> {
        let url =
            Url::parse(virtual_url).map_err(|error| EngineError::Socket(error.to_string()))?;
        let session = {
            // Keep the engine lock through the first dial. This is deliberate:
            // it makes simultaneous opens coalesce before Link's own
            // newest-session-wins rule could supersede the first one.
            let mut inner = self.inner.lock().await;
            if inner.stopped {
                return Err(EngineError::Stopped);
            }
            let route = inner
                .routes
                .get(route_id)
                .ok_or_else(|| EngineError::Route("route is not installed".into()))?;
            link_websocket::validate_virtual_url(&url, route.node)
                .map_err(|error| EngineError::Socket(error.to_string()))?;
            if let Some(session) = &route.session {
                session.clone()
            } else {
                let card = route.card.clone();
                let endpoint = inner.endpoint.clone();
                let session = Arc::new(
                    endpoint
                        .connect(&card)
                        .await
                        .map_err(|error| EngineError::Transport(error.to_string()))?,
                );
                // `route` was only borrowed above and the engine lock means
                // it cannot have been removed or replaced during this dial.
                inner
                    .routes
                    .get_mut(route_id)
                    .expect("route retained by engine lock")
                    .session = Some(session.clone());
                session
            }
        };
        let (socket, incoming) = link_websocket::open(&session, url)
            .await
            .map_err(|error| EngineError::Socket(error.to_string()))?;
        Ok((socket, incoming, session))
    }

    /// Send one bounded cadence JSON request over the route's pinned Link
    /// session. The application supplies neither a network URL nor a `Host`.
    pub async fn request_json(
        &self,
        request: JsonRequest,
        timeout: Duration,
    ) -> Result<JsonResponse, EngineError> {
        let method = validate_http_request(&request)?;
        let started = rt::Instant::now();
        let (session, node) = {
            // Match `open_socket`: holding the engine lock through a first dial
            // coalesces callers onto Link's one session for this peer.
            let mut inner = self.inner.lock().await;
            if inner.stopped {
                return Err(EngineError::Stopped);
            }
            let route = inner
                .routes
                .get(&request.route_id)
                .ok_or_else(|| EngineError::Route("route is not installed".into()))?;
            let node = route.node;
            let current = route
                .session
                .as_ref()
                .filter(|session| !matches!(session.path().status, PathStatus::Failed(_)));
            let session = if let Some(session) = current {
                session.clone()
            } else {
                let card = route.card.clone();
                let endpoint = inner.endpoint.clone();
                let session = Arc::new(
                    rt::timeout(timeout, endpoint.connect(&card))
                        .await
                        .map_err(|_| EngineError::Transport("cadence request timed out".into()))?
                        .map_err(|error| EngineError::Transport(error.to_string()))?,
                );
                inner
                    .routes
                    .get_mut(&request.route_id)
                    .expect("route retained by engine lock")
                    .session = Some(session.clone());
                session
            };
            (session, node)
        };
        let remaining = timeout
            .checked_sub(started.elapsed())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| EngineError::Transport("cadence request timed out".into()))?;
        let (status, body) = rt::timeout(remaining, async {
            let mut sender = http_sender(&session).await?;
            let outgoing = Request::builder()
                .method(method)
                .uri(request.path)
                .header(hyper::header::HOST, node.to_base32())
                .header(hyper::header::CONTENT_TYPE, "application/json")
                .header(hyper::header::AUTHORIZATION, request.authorization)
                .header(hyper::header::CONNECTION, "close")
                .body(Full::new(Bytes::from(request.body)))
                .map_err(|error| EngineError::Route(error.to_string()))?;
            let response = sender
                .send_request(outgoing)
                .await
                .map_err(|error| EngineError::Transport(error.to_string()))?;
            decode_http_response(response).await
        })
        .await
        .map_err(|_| EngineError::Transport("cadence request timed out".into()))??;
        Ok(JsonResponse {
            status,
            body,
            path: path(&session),
        })
    }

    /// Ask the paired server to retire this route. Local credentials remain
    /// installed until the product durably records the acknowledged outcome.
    pub async fn retire_route(&self, route_id: &str) -> Result<(), EngineError> {
        self.delete_route(route_id, "/events/route", "route retirement")
            .await
    }

    /// Remove the paired transport after the product has durably recorded
    /// logical retirement. The caller may safely treat transport failure as a
    /// lost final acknowledgement: application authority was revoked by
    /// `retire_route`, and this method never removes local credentials.
    pub async fn finalize_route(&self, route_id: &str) -> Result<(), EngineError> {
        self.delete_route(route_id, "/events/route/finalize", "route finalisation")
            .await
    }

    /// Enrol one durable event route over Link's quarantined provisional
    /// session, install it in the running engine, and return the exact record
    /// the host must commit atomically.
    pub async fn pair_route(&self, mut bundle: PairingBundle) -> Result<Route, EngineError> {
        if bundle.route_id.is_empty() {
            return Err(EngineError::Route("route id must not be empty".into()));
        }
        let now = rt::unix_now();
        let lifetime = pairing_lifetime(bundle.expires_at, now)?;
        let raw_pairing = Zeroizing::new(pairing_secret(&bundle.pairing_secret)?);
        bundle.pairing_secret.zeroize();
        let server_node = node_from_card_bytes(&bundle.server_card)?;
        let offered_card = Card::verify(
            &bundle.server_card,
            &VerifyContext::new(now).expecting(server_node),
        )
        .map_err(|error| EngineError::Route(error.to_string()))?;
        let endpoint = {
            let inner = self.inner.lock().await;
            if inner.stopped {
                return Err(EngineError::Stopped);
            }
            if inner
                .routes
                .get(&bundle.route_id)
                .is_some_and(|existing| existing.node != server_node)
            {
                return Err(EngineError::Route(
                    "route id is already bound to another node".into(),
                ));
            }
            inner.endpoint.clone()
        };

        let registration = endpoint
            .register_pairing_secret(*raw_pairing, lifetime)
            .map_err(|error| EngineError::Route(error.to_string()))?;
        let caller_card = endpoint.card(Duration::from_secs(MAX_LIFETIME_SECONDS), Vec::new());
        let request_body = route_frame(caller_card.as_bytes());
        let secret_header = Zeroizing::new(hex::encode(raw_pairing.as_ref()));

        let session = endpoint
            .connect_pairing(&offered_card, &registration)
            .await
            .map_err(|error| {
                let activity = endpoint.pairing_relay_activity(&registration);
                EngineError::Transport(format!("{error}; {activity}"))
            })?;
        let result = async {
            let route_secret = session
                .paired_route_secret()
                .map_err(|error| EngineError::Route(error.to_string()))?;
            let stream = session
                .open_stream()
                .await
                .map_err(|error| EngineError::Transport(error.to_string()))?;
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream))
                    .await
                    .map_err(|error| EngineError::Transport(error.to_string()))?;
            rt::spawn(async move {
                let _ = connection.await;
            });
            let request = Request::builder()
                .method(Method::PUT)
                .uri("/events/route")
                .header(hyper::header::HOST, server_node.to_base32())
                .header(hyper::header::CONTENT_TYPE, "application/octet-stream")
                .header("x-bothy-pairing-secret", secret_header.as_str())
                .body(Full::new(Bytes::from(request_body)))
                .map_err(|error| EngineError::Route(error.to_string()))?;
            let response = sender
                .send_request(request)
                .await
                .map_err(|error| EngineError::Transport(error.to_string()))?;
            if response.status() != StatusCode::OK {
                return Err(EngineError::Route(format!(
                    "server refused route enrolment with {}",
                    response.status()
                )));
            }
            let answer =
                collect_bounded(response.into_body(), MAX_ROUTE_FRAME_BYTES, "route").await?;
            let response_card_bytes = route_card(&answer)?.to_vec();
            let response_verified_at = rt::unix_now();
            let response_card = Card::verify(
                &response_card_bytes,
                &VerifyContext::new(response_verified_at).expecting(server_node),
            )
            .map_err(|error| EngineError::Route(error.to_string()))?;
            if response_card.serial < offered_card.serial {
                return Err(EngineError::Route(
                    "server returned an older card than the pairing bundle".into(),
                ));
            }
            Ok((response_card, route_secret, response_verified_at))
        }
        .await;
        session.close().await;
        let (paired_card, route_secret, verified_at) = result?;

        let route = Route {
            route_id: bundle.route_id.clone(),
            card: paired_card.as_bytes().to_vec(),
            paired_route_secret: route_secret.to_vec(),
            card_serial: paired_card.serial,
            card_verified_at: verified_at,
        };
        let previous_session = {
            let mut inner = self.inner.lock().await;
            if inner.stopped {
                return Err(EngineError::Stopped);
            }
            let prior = inner
                .routes
                .get(&route.route_id)
                .map(|existing| {
                    if existing.node != paired_card.node_id {
                        return Err(EngineError::Route(
                            "route id is already bound to another node".into(),
                        ));
                    }
                    if route.card_serial < existing.serial {
                        return Err(EngineError::Route(
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
                .upsert_paired(paired_card.node_id, *route_secret);
            inner.routes.insert(
                route.route_id.clone(),
                RouteState {
                    node: paired_card.node_id,
                    serial: route.card_serial,
                    card: paired_card,
                    session: None,
                },
            );
            prior.flatten()
        };
        if let Some(session) = previous_session {
            session.close(1).await;
        }
        Ok(route)
    }

    pub async fn upsert_route(&self, route: Route) -> Result<(), EngineError> {
        let (node, card) = verify_route(&route)?;
        let route_secret = Zeroizing::new(secret(&route.paired_route_secret)?);
        let previous_session = {
            let mut inner = self.inner.lock().await;
            if inner.stopped {
                return Err(EngineError::Stopped);
            }
            let previous = inner
                .routes
                .get(&route.route_id)
                .map(|existing| {
                    if route.card_serial <= existing.serial {
                        return Err(EngineError::Route("live card serial must increase".into()));
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
                .upsert_paired(node, *route_secret);
            inner.routes.insert(
                route.route_id.clone(),
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
            session.close(1).await;
        }
        Ok(())
    }

    pub async fn remove_route(&self, route_id: &str) -> Result<(), EngineError> {
        let session = {
            let mut inner = self.inner.lock().await;
            if inner.stopped {
                return Err(EngineError::Stopped);
            }
            let route = inner
                .routes
                .remove(route_id)
                .ok_or_else(|| EngineError::Route("route is not installed".into()))?;
            inner
                .endpoint
                .rendezvous_book()
                .expect("tag mode")
                .remove_paired(route.node);
            route.session
        };
        if let Some(session) = session {
            session.close(1).await;
        }
        Ok(())
    }

    pub async fn reannounce(&self) -> Result<(), EngineError> {
        let sessions: Vec<_> = {
            let inner = self.inner.lock().await;
            if inner.stopped {
                return Err(EngineError::Stopped);
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

    /// Refuse every later call and close the cached sessions.  Installed
    /// route credentials stay with the endpoint until the engine is dropped;
    /// [`Engine::wipe`] removes them at once.
    pub async fn stop(&self) {
        let sessions: Vec<_> = {
            let mut inner = self.inner.lock().await;
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
            session.close(1).await;
        }
    }

    /// Stop, then forget every route: each paired-route secret leaves the
    /// rendezvous book (which zeroises it), the route table is emptied, and
    /// the endpoint closes its relays and connections.
    pub async fn wipe(&self) {
        self.stop().await;
        let endpoint = {
            let mut inner = self.inner.lock().await;
            let routes = std::mem::take(&mut inner.routes);
            if let Some(book) = inner.endpoint.rendezvous_book() {
                for route in routes.values() {
                    book.remove_paired(route.node);
                }
            }
            inner.endpoint.clone()
        };
        endpoint.close().await;
    }

    /// The cached session for a route, for tests.  Panics if another call
    /// holds the engine; it never waits.
    #[doc(hidden)]
    pub fn cached_session(&self, route_id: &str) -> Option<Arc<Session>> {
        let inner = self.inner.try_lock().expect("engine is idle");
        inner.routes.get(route_id)?.session.clone()
    }

    /// Whether a route is installed, for tests.  Panics if another call
    /// holds the engine; it never waits.
    #[doc(hidden)]
    pub fn has_route(&self, route_id: &str) -> bool {
        let inner = self.inner.try_lock().expect("engine is idle");
        inner.routes.contains_key(route_id)
    }

    async fn delete_route(
        &self,
        route_id: &str,
        path: &str,
        operation: &str,
    ) -> Result<(), EngineError> {
        let (session, node) = {
            let mut inner = self.inner.lock().await;
            if inner.stopped {
                return Err(EngineError::Stopped);
            }
            let route = inner
                .routes
                .get(route_id)
                .ok_or_else(|| EngineError::Route("route is not installed".into()))?;
            let node = route.node;
            let session = if let Some(session) = &route.session {
                session.clone()
            } else {
                let card = route.card.clone();
                let session = Arc::new(
                    inner
                        .endpoint
                        .connect(&card)
                        .await
                        .map_err(|error| EngineError::Transport(error.to_string()))?,
                );
                inner
                    .routes
                    .get_mut(route_id)
                    .expect("route retained by engine lock")
                    .session = Some(session.clone());
                session
            };
            (session, node)
        };
        let mut sender = http_sender(&session).await?;
        let request = Request::builder()
            .method(Method::DELETE)
            .uri(path)
            .header(hyper::header::HOST, node.to_base32())
            .body(Full::new(Bytes::new()))
            .map_err(|error| EngineError::Route(error.to_string()))?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|error| EngineError::Transport(error.to_string()))?;
        if response.status() != StatusCode::NO_CONTENT {
            return Err(EngineError::Route(format!(
                "server refused {operation} with {}",
                response.status()
            )));
        }
        collect_bounded(response.into_body(), MAX_ROUTE_FRAME_BYTES, "route").await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Full;

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
        let route = Route {
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

    fn valid_http_request() -> JsonRequest {
        JsonRequest {
            route_id: "circle-main".into(),
            method: "POST".into(),
            path: "/cadence/v1/status".into(),
            authorization: "Nostr YQ==".into(),
            body: br#"{"v":1}"#.to_vec(),
        }
    }

    #[test]
    fn cadence_request_boundary_is_narrow_and_redacted() {
        let request = valid_http_request();
        assert_eq!(validate_http_request(&request).unwrap(), Method::POST);
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("YQ=="));
        assert!(!rendered.contains(r#"{"v":1}"#));
        assert!(!rendered.contains("circle-main"));
        assert!(!rendered.contains("/cadence/v1/status"));

        let mut put = request.clone();
        put.method = "PUT".into();
        assert_eq!(validate_http_request(&put).unwrap(), Method::PUT);

        for method in ["GET", "post", "DELETE"] {
            let mut changed = request.clone();
            changed.method = method.into();
            assert!(validate_http_request(&changed).is_err(), "method {method}");
        }
        for path in [
            "cadence/v1/status",
            "/events",
            "/cadence/v1/status?room=secret",
            "/cadence/v1/status#fragment",
            "/cadence/v1/status\nX-Injected: yes",
            "/cadence/v1/é",
        ] {
            let mut changed = request.clone();
            changed.path = path.into();
            assert!(validate_http_request(&changed).is_err(), "path {path:?}");
        }
        let mut long_path = request.clone();
        long_path.path = format!("/cadence/v1/{}", "a".repeat(MAX_HTTP_PATH_BYTES));
        assert!(validate_http_request(&long_path).is_err());

        for authorization in [
            "",
            "Bearer YQ==",
            "Nostr ",
            "Nostr YQ==\r\nX-Injected: yes",
            "Nostr YQ==,Nostr Yg==",
        ] {
            let mut changed = request.clone();
            changed.authorization = authorization.into();
            assert!(
                validate_http_request(&changed).is_err(),
                "authorization {authorization:?}"
            );
        }
        let mut long_authorization = request.clone();
        long_authorization.authorization =
            format!("Nostr {}", "A".repeat(MAX_HTTP_AUTHORIZATION_BYTES));
        assert!(validate_http_request(&long_authorization).is_err());

        let mut largest_body = request.clone();
        largest_body.body = vec![0; MAX_HTTP_BODY_BYTES];
        assert!(validate_http_request(&largest_body).is_ok());
        largest_body.body.push(0);
        assert!(validate_http_request(&largest_body).is_err());
    }

    #[tokio::test]
    async fn cadence_response_requires_bounded_json_and_never_redirects() {
        let response = Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header(
                hyper::header::CONTENT_TYPE,
                "application/json; charset=utf-8",
            )
            .body(Full::new(Bytes::from_static(br#"{"v":1,"code":"scope"}"#)))
            .unwrap();
        let (status, body) = decode_http_response(response).await.unwrap();
        assert_eq!(status, 403);
        assert_eq!(body, br#"{"v":1,"code":"scope"}"#);

        let redirect = Response::builder()
            .status(StatusCode::TEMPORARY_REDIRECT)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert!(decode_http_response(redirect).await.is_err());

        let wrong_type = Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "text/plain")
            .body(Full::new(Bytes::from_static(b"{}")))
            .unwrap();
        assert!(decode_http_response(wrong_type).await.is_err());

        let oversized = Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(vec![0; MAX_HTTP_BODY_BYTES + 1])))
            .unwrap();
        assert!(decode_http_response(oversized).await.is_err());

        let response = JsonResponse {
            status: 200,
            body: b"response-secret".to_vec(),
            path: PathInfo {
                status: "relayed".into(),
                relay: None,
                direct: None,
                cause: "fixture".into(),
            },
        };
        assert!(!format!("{response:?}").contains("response-secret"));
    }

    #[test]
    fn route_and_pairing_debug_never_print_secrets() {
        let route = Route {
            route_id: "room".into(),
            card: vec![1, 2],
            paired_route_secret: vec![0x7b; 32],
            card_serial: 1,
            card_verified_at: 2,
        };
        let bundle = PairingBundle {
            route_id: "room".into(),
            server_card: vec![3, 4],
            pairing_secret: vec![0x6a; 16],
            expires_at: 3,
        };
        assert!(!format!("{route:?}").contains(&"7b".repeat(32)));
        assert!(!format!("{bundle:?}").contains(&"6a".repeat(16)));
    }

    #[test]
    fn a_route_frame_round_trips_and_rejects_malformed_frames() {
        let card = vec![0x5a; 40];
        let frame = route_frame(&card);
        assert_eq!(&frame[..4], ROUTE_MAGIC);
        assert_eq!(route_card(&frame).unwrap(), card.as_slice());
        let mut long = frame.clone();
        long.push(0);
        assert!(route_card(&long).is_err(), "trailing bytes");
        assert!(route_card(&frame[..frame.len() - 1]).is_err(), "short");
        let mut magic = frame.clone();
        magic[0] = b'X';
        assert!(route_card(&magic).is_err(), "wrong magic");
        let mut oversize = ROUTE_MAGIC.to_vec();
        oversize.extend_from_slice(&u16::try_from(MAX_CARD_BYTES + 1).unwrap().to_be_bytes());
        oversize.resize(ROUTE_PREFIX_BYTES + MAX_CARD_BYTES + 1, 0);
        assert!(route_card(&oversize).is_err(), "above the card bound");
    }
}
