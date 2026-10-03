//! The paired-route engine: the application-facing half of Link that both
//! link-ffi (Kotlin/Android) and link-web (a browser) expose.
//!
//! The host supplies encrypted persisted route state; this crate owns the
//! endpoint, the one session per route, the bounded allowlisted request,
//! pairing enrolment and the event WebSocket.  Cadence and VMLS
//! authorization and bodies cross as opaque bytes; Link interprets no Nostr
//! event, VMLS envelope or application authority.
//! Everything here is async and runs on `link_endpoint::rt`, so the same
//! checks and the same protocol run natively and in a browser; the
//! wrappers only adapt calling conventions.

use std::collections::HashMap;
use std::future::Future;
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
use tokio::sync::{Mutex, mpsc, watch};
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

/// One allowlisted HTTP request sent over an already paired Link route. The
/// name predates the VMLS routes, some of which carry raw bytes.
///
/// The route selects a pinned peer. The engine supplies `Host` and
/// `Content-Type` from the allowlist, so the host application cannot redirect
/// this call, change its transport identity or relabel its body. Witness
/// routes take an empty `authorization`.
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

/// A bounded response and the Link path that carried it. A VMLS or witness
/// refusal without a body has an empty `body`.
#[derive(Clone)]
pub struct JsonResponse {
    pub status: u16,
    pub body: Vec<u8>,
    /// True only for a witness-route 403 carrying `vmls-witness: refused`
    /// (Bothy's deliberate refusal). Any other 403 means "unavailable".
    pub witness_refused: bool,
    pub path: PathInfo,
}

impl std::fmt::Debug for JsonResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonResponse")
            .field("status", &self.status)
            .field("body", &format_args!("{} bytes", self.body.len()))
            .field("witness_refused", &self.witness_refused)
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

/// What a request body must be. The engine, not the host, writes the
/// matching `Content-Type`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestBody {
    Json,
    Octets,
    /// No body and no `Content-Type`.
    Empty,
}

/// What a route answers with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseBody {
    /// Every answer is bounded JSON (cadence).
    Json,
    /// A success is bounded JSON; a refusal is JSON or has no body (a box
    /// without VMLS answers 404 with nothing, and the client must see that
    /// status rather than a transport failure).
    JsonOrEmptyRefusal,
    /// A witness receipt: exactly [`WITNESS_RECEIPT_BYTES`] of
    /// `application/octet-stream`, or a refusal status with no body.
    WitnessReceipt,
}

/// One allowlisted route's bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpRoute {
    pub body: RequestBody,
    pub max_body_bytes: usize,
    /// Whether the request carries one Nostr authorization value. Witness
    /// routes carry none: the witness authenticates the Link peer.
    pub nostr_authorization: bool,
    pub response: ResponseBody,
    pub max_response_bytes: usize,
}

/// Bothy's `MAX_VMLS_JSON_BYTES`.
pub const MAX_VMLS_JSON_BYTES: usize = 128 * 1_024;
/// Bothy's `MAX_ENVELOPE_BYTES`: a canonical VMLS envelope's 44 header bytes
/// and at most 1,048,576 ciphertext bytes.
pub const MAX_VMLS_ENVELOPE_BYTES: usize = 44 + 1_048_576;
/// A fetch page holds at most 1 MiB of envelopes (or one larger envelope),
/// base64-encoded, with up to 64 records' names and a cursor.
pub const MAX_VMLS_FETCH_RESPONSE_BYTES: usize = 2 * 1_024 * 1_024;
/// The witness request bound (contract §4.2).
pub const MAX_WITNESS_REQUEST_BYTES: usize = 256;
/// A witness receipt's fixed length (contract §4.2).
pub const WITNESS_RECEIPT_BYTES: usize = 170;
/// A body-less refusal may carry at most this much, which is discarded.
const MAX_DISCARDED_REFUSAL_BYTES: usize = 1_024;

const CADENCE_ROUTE: HttpRoute = HttpRoute {
    body: RequestBody::Json,
    max_body_bytes: MAX_HTTP_BODY_BYTES,
    nostr_authorization: true,
    response: ResponseBody::Json,
    max_response_bytes: MAX_HTTP_BODY_BYTES,
};

const fn vmls_route(body: RequestBody, max_response_bytes: usize) -> HttpRoute {
    HttpRoute {
        body,
        max_body_bytes: match body {
            RequestBody::Json => MAX_VMLS_JSON_BYTES,
            RequestBody::Octets => MAX_VMLS_ENVELOPE_BYTES,
            RequestBody::Empty => 0,
        },
        nostr_authorization: true,
        response: ResponseBody::JsonOrEmptyRefusal,
        max_response_bytes,
    }
}

const WITNESS_ROUTE: HttpRoute = HttpRoute {
    body: RequestBody::Octets,
    max_body_bytes: MAX_WITNESS_REQUEST_BYTES,
    nostr_authorization: false,
    response: ResponseBody::WitnessReceipt,
    max_response_bytes: WITNESS_RECEIPT_BYTES,
};

fn lower_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Bothy's `parse_attempt`: a canonical decimal `u32`.
fn canonical_u32(value: &str) -> bool {
    !value.is_empty()
        && (value.len() == 1 || !value.starts_with('0'))
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u32>().is_ok()
}

/// The allowlist: cadence as before, Bothy's exact `/vmls/v1/` routes and
/// the two witness routes. Anything else is refused before a dial.
fn allowlisted(method: &Method, path: &str) -> Option<HttpRoute> {
    if path.starts_with("/cadence/v1/") {
        return (*method == Method::POST || *method == Method::PUT).then_some(CADENCE_ROUTE);
    }
    if path == "/vmls-witness/v1/read" || path == "/vmls-witness/v1/advance" {
        return (*method == Method::POST).then_some(WITNESS_ROUTE);
    }
    let segments: Vec<&str> = path.strip_prefix("/vmls/v1/")?.split('/').collect();
    let json = vmls_route(RequestBody::Json, MAX_HTTP_BODY_BYTES);
    match (method.as_str(), segments.as_slice()) {
        ("PUT", ["mailboxes", mailbox, "records"]) if lower_hex_32(mailbox) => {
            Some(vmls_route(RequestBody::Octets, MAX_HTTP_BODY_BYTES))
        }
        ("POST", ["fetch"]) => Some(vmls_route(RequestBody::Json, MAX_VMLS_FETCH_RESPONSE_BYTES)),
        ("POST", ["ack"]) => Some(json),
        ("PUT", ["packages", package]) if lower_hex_32(package) => Some(json),
        ("DELETE", ["packages", package]) if lower_hex_32(package) => {
            Some(vmls_route(RequestBody::Empty, MAX_HTTP_BODY_BYTES))
        }
        ("PUT", ["slots", slot, attempt]) if lower_hex_32(slot) && canonical_u32(attempt) => {
            Some(vmls_route(RequestBody::Octets, MAX_HTTP_BODY_BYTES))
        }
        ("POST", ["slots", slot, attempt, "status"])
            if lower_hex_32(slot) && canonical_u32(attempt) =>
        {
            Some(json)
        }
        ("GET", ["capabilities"]) => Some(vmls_route(RequestBody::Empty, MAX_HTTP_BODY_BYTES)),
        _ => None,
    }
}

pub fn validate_http_request(request: &JsonRequest) -> Result<(Method, HttpRoute), EngineError> {
    let method = match request.method.as_str() {
        "GET" => Method::GET,
        "POST" => Method::POST,
        "PUT" => Method::PUT,
        "DELETE" => Method::DELETE,
        _ => {
            return Err(EngineError::Route(
                "request method must be GET, POST, PUT or DELETE".into(),
            ));
        }
    };
    let path = request.path.as_bytes();
    if path.is_empty()
        || path.len() > MAX_HTTP_PATH_BYTES
        || path.contains(&b'?')
        || path.contains(&b'#')
        || !path.iter().all(u8::is_ascii_graphic)
    {
        return Err(EngineError::Route("request path is not canonical".into()));
    }
    let route = allowlisted(&method, &request.path)
        .ok_or_else(|| EngineError::Route("request method and path are not allowlisted".into()))?;
    let authorization = request.authorization.as_bytes();
    if route.nostr_authorization {
        let encoded = authorization.strip_prefix(b"Nostr ").unwrap_or_default();
        if authorization.len() > MAX_HTTP_AUTHORIZATION_BYTES
            || encoded.is_empty()
            || !encoded
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        {
            return Err(EngineError::Route(
                "authorization is not one bounded Nostr value".into(),
            ));
        }
    } else if !authorization.is_empty() {
        return Err(EngineError::Route(
            "witness requests carry no authorization".into(),
        ));
    }
    // An empty-body route's limit is 0.
    if request.body.len() > route.max_body_bytes {
        return Err(EngineError::Route("request body is too large".into()));
    }
    Ok((method, route))
}

/// Bothy's witness refusal header and its one value.
const WITNESS_REFUSAL_HEADER: &str = "vmls-witness";
const WITNESS_REFUSAL_VALUE: &[u8] = b"refused";

/// Whether a reply is Bothy's deliberate witness refusal: the witness route,
/// status 403, and exactly one `vmls-witness` header whose value is exactly
/// `refused`. The header name is case-insensitive (`HeaderMap`); the value is
/// compared byte for byte, so `Refused` or `refused!` do not match. hyper has
/// already stripped the optional whitespace around a field value, and nothing
/// further is trimmed. Repeated headers are ambiguous and do not match.
pub fn is_witness_refusal(
    route: &HttpRoute,
    status: StatusCode,
    headers: &hyper::HeaderMap,
) -> bool {
    if route.response != ResponseBody::WitnessReceipt || status != StatusCode::FORBIDDEN {
        return false;
    }
    let mut values = headers.get_all(WITNESS_REFUSAL_HEADER).iter();
    matches!(
        (values.next(), values.next()),
        (Some(value), None) if value.as_bytes() == WITNESS_REFUSAL_VALUE
    )
}

pub async fn decode_http_response<B>(
    response: Response<B>,
    route: &HttpRoute,
) -> Result<(u16, Vec<u8>), EngineError>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    if response.status().is_redirection() {
        return Err(EngineError::Route("response must not redirect".into()));
    }
    let status = response.status();
    let content_type = response
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .map(str::to_ascii_lowercase);
    let expected = match route.response {
        ResponseBody::Json | ResponseBody::JsonOrEmptyRefusal => "application/json",
        ResponseBody::WitnessReceipt => "application/octet-stream",
    };
    let receipt_status = matches!(
        status,
        StatusCode::OK | StatusCode::CONFLICT | StatusCode::GONE
    );
    let typed = content_type.as_deref() == Some(expected)
        && (route.response != ResponseBody::WitnessReceipt || receipt_status);
    if !typed {
        if route.response == ResponseBody::Json || status.is_success() {
            return Err(EngineError::Route(format!("response is not {expected}")));
        }
        collect_bounded(response.into_body(), MAX_DISCARDED_REFUSAL_BYTES, "refusal").await?;
        return Ok((status.as_u16(), Vec::new()));
    }
    let body = collect_bounded(response.into_body(), route.max_response_bytes, "response").await?;
    if route.response == ResponseBody::WitnessReceipt && body.len() != WITNESS_RECEIPT_BYTES {
        return Err(EngineError::Route(
            "witness receipt is not 170 bytes".into(),
        ));
    }
    Ok((status.as_u16(), body.to_vec()))
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
    routes: HashMap<String, RouteState>,
    stopped: bool,
}

/// The engine.  One lock covers the route table and every first dial, so
/// simultaneous callers coalesce onto Link's one session per peer before
/// Link's own newest-session-wins rule could supersede the first one.  The
/// endpoint and the stop signal live outside the lock, so `stop` never
/// waits behind a dial: every dial races the signal and gives way.
pub struct Engine {
    endpoint: Arc<Endpoint>,
    stop: watch::Sender<bool>,
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
            endpoint: Arc::new(endpoint),
            stop: watch::Sender::new(false),
            inner: Mutex::new(Inner {
                routes,
                stopped: false,
            }),
        })
    }

    /// `work`, unless the engine stops first.
    async fn unless_stopped<T>(
        &self,
        work: impl Future<Output = Result<T, EngineError>>,
    ) -> Result<T, EngineError> {
        let mut stop = self.stop.subscribe();
        tokio::select! {
            biased;
            _ = stop.wait_for(|stopped| *stopped) => Err(EngineError::Stopped),
            result = work => result,
        }
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
                let session = Arc::new(
                    self.unless_stopped(async {
                        self.endpoint
                            .connect(&card)
                            .await
                            .map_err(|error| EngineError::Transport(error.to_string()))
                    })
                    .await?,
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

    /// Send one bounded, allowlisted request (cadence, VMLS or witness) over
    /// the route's pinned Link session. The application supplies neither a
    /// network URL, a `Host` nor a `Content-Type`.
    pub async fn request_json(
        &self,
        request: JsonRequest,
        timeout: Duration,
    ) -> Result<JsonResponse, EngineError> {
        let (method, route) = validate_http_request(&request)?;
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
                let session = Arc::new(
                    self.unless_stopped(async {
                        rt::timeout(timeout, self.endpoint.connect(&card))
                            .await
                            .map_err(|_| EngineError::Transport("request timed out".into()))?
                            .map_err(|error| EngineError::Transport(error.to_string()))
                    })
                    .await?,
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
            .ok_or_else(|| EngineError::Transport("request timed out".into()))?;
        let (status, body, witness_refused) = rt::timeout(remaining, async {
            let mut sender = http_sender(&session).await?;
            let mut outgoing = Request::builder()
                .method(method)
                .uri(request.path)
                .header(hyper::header::HOST, node.to_base32());
            match route.body {
                RequestBody::Json => {
                    outgoing = outgoing.header(hyper::header::CONTENT_TYPE, "application/json");
                }
                RequestBody::Octets => {
                    outgoing =
                        outgoing.header(hyper::header::CONTENT_TYPE, "application/octet-stream");
                }
                RequestBody::Empty => {}
            }
            if route.nostr_authorization {
                outgoing = outgoing.header(hyper::header::AUTHORIZATION, request.authorization);
            }
            let outgoing = outgoing
                .header(hyper::header::CONNECTION, "close")
                .body(Full::new(Bytes::from(request.body)))
                .map_err(|error| EngineError::Route(error.to_string()))?;
            let response = sender
                .send_request(outgoing)
                .await
                .map_err(|error| EngineError::Transport(error.to_string()))?;
            let witness_refused = is_witness_refusal(&route, response.status(), response.headers());
            let (status, body) = decode_http_response(response, &route).await?;
            Ok::<_, EngineError>((status, body, witness_refused))
        })
        .await
        .map_err(|_| EngineError::Transport("request timed out".into()))??;
        Ok(JsonResponse {
            status,
            body,
            witness_refused,
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
            self.endpoint.clone()
        };

        let registration = endpoint
            .register_pairing_secret(*raw_pairing, lifetime)
            .map_err(|error| EngineError::Route(error.to_string()))?;
        let caller_card = endpoint.card(Duration::from_secs(MAX_LIFETIME_SECONDS), Vec::new());
        let request_body = route_frame(caller_card.as_bytes());
        let secret_header = Zeroizing::new(hex::encode(raw_pairing.as_ref()));

        let session = self
            .unless_stopped(async {
                endpoint
                    .connect_pairing(&offered_card, &registration)
                    .await
                    .map_err(|error| {
                        let activity = endpoint.pairing_relay_activity(&registration);
                        EngineError::Transport(format!("{error}; {activity}"))
                    })
            })
            .await?;
        let result = self
            .unless_stopped(async {
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
            })
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
            self.endpoint
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
                self.endpoint
                    .rendezvous_book()
                    .expect("tag mode")
                    .remove_paired(*old_node);
            }
            self.endpoint
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
            self.endpoint
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

    /// Refuse every later call, close the cached sessions and close the
    /// endpoint with its relays.  The stop signal goes first and outside the
    /// lock, so a dial in progress gives way at once rather than making this
    /// wait.  Sessions still close with their own code (1) before the
    /// endpoint closes the rest.  Installed route credentials stay in memory
    /// until the engine is dropped; [`Engine::wipe`] removes them at once.
    pub async fn stop(&self) {
        if self.stop.send_replace(true) {
            return;
        }
        let sessions: Vec<_> = {
            let mut inner = self.inner.lock().await;
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
        self.endpoint.close().await;
    }

    /// Stop, then forget every route: each paired-route secret leaves the
    /// rendezvous book (which zeroises it) and the route table is emptied.
    pub async fn wipe(&self) {
        self.stop().await;
        let mut inner = self.inner.lock().await;
        let routes = std::mem::take(&mut inner.routes);
        if let Some(book) = self.endpoint.rendezvous_book() {
            for route in routes.values() {
                book.remove_paired(route.node);
            }
        }
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
                    self.unless_stopped(async {
                        self.endpoint
                            .connect(&card)
                            .await
                            .map_err(|error| EngineError::Transport(error.to_string()))
                    })
                    .await?,
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
        assert_eq!(validate_http_request(&request).unwrap().0, Method::POST);
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("YQ=="));
        assert!(!rendered.contains(r#"{"v":1}"#));
        assert!(!rendered.contains("circle-main"));
        assert!(!rendered.contains("/cadence/v1/status"));

        let mut put = request.clone();
        put.method = "PUT".into();
        assert_eq!(validate_http_request(&put).unwrap().0, Method::PUT);

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
        let (status, body) = decode_http_response(response, &CADENCE_ROUTE)
            .await
            .unwrap();
        assert_eq!(status, 403);
        assert_eq!(body, br#"{"v":1,"code":"scope"}"#);

        let redirect = Response::builder()
            .status(StatusCode::TEMPORARY_REDIRECT)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert!(
            decode_http_response(redirect, &CADENCE_ROUTE)
                .await
                .is_err()
        );

        let wrong_type = Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "text/plain")
            .body(Full::new(Bytes::from_static(b"{}")))
            .unwrap();
        assert!(
            decode_http_response(wrong_type, &CADENCE_ROUTE)
                .await
                .is_err()
        );

        let oversized = Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(vec![0; MAX_HTTP_BODY_BYTES + 1])))
            .unwrap();
        assert!(
            decode_http_response(oversized, &CADENCE_ROUTE)
                .await
                .is_err()
        );

        let response = JsonResponse {
            status: 200,
            body: b"response-secret".to_vec(),
            witness_refused: false,
            path: PathInfo {
                status: "relayed".into(),
                relay: None,
                direct: None,
                cause: "fixture".into(),
            },
        };
        assert!(!format!("{response:?}").contains("response-secret"));
    }

    const HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn vmls(method: &str, path: &str, authorization: &str, body: &[u8]) -> JsonRequest {
        JsonRequest {
            route_id: "home".into(),
            method: method.into(),
            path: path.into(),
            authorization: authorization.into(),
            body: body.to_vec(),
        }
    }

    #[test]
    fn vmls_routes_are_exactly_bothys() {
        let nostr = "Nostr YQ==";
        let accepted = [
            (
                "PUT",
                format!("/vmls/v1/mailboxes/{HEX}/records"),
                RequestBody::Octets,
            ),
            ("POST", "/vmls/v1/fetch".into(), RequestBody::Json),
            ("POST", "/vmls/v1/ack".into(), RequestBody::Json),
            ("PUT", format!("/vmls/v1/packages/{HEX}"), RequestBody::Json),
            (
                "DELETE",
                format!("/vmls/v1/packages/{HEX}"),
                RequestBody::Empty,
            ),
            (
                "PUT",
                format!("/vmls/v1/slots/{HEX}/0"),
                RequestBody::Octets,
            ),
            (
                "PUT",
                format!("/vmls/v1/slots/{HEX}/4294967295"),
                RequestBody::Octets,
            ),
            (
                "POST",
                format!("/vmls/v1/slots/{HEX}/7/status"),
                RequestBody::Json,
            ),
            ("GET", "/vmls/v1/capabilities".into(), RequestBody::Empty),
        ];
        for (method, path, body) in accepted {
            let payload: &[u8] = if body == RequestBody::Empty {
                b""
            } else {
                b"x"
            };
            let (_, route) = validate_http_request(&vmls(method, &path, nostr, payload))
                .unwrap_or_else(|error| panic!("{method} {path}: {error}"));
            assert_eq!(route.body, body, "{method} {path}");
            assert!(route.nostr_authorization);
            assert_eq!(route.response, ResponseBody::JsonOrEmptyRefusal);
            assert!(
                validate_http_request(&vmls(method, &path, "", payload)).is_err(),
                "{method} {path} without authorization"
            );
        }

        let upper = HEX.to_ascii_uppercase();
        let refused = [
            ("GET", "/vmls/v1/".to_string()),
            ("GET", "/vmls/v1".into()),
            ("POST", "/vmls/v1/capabilities".into()),
            ("GET", "/vmls/v1/capabilities/".into()),
            ("PUT", "/vmls/v1/fetch".into()),
            ("POST", "/vmls/v1/fetch/".into()),
            ("POST", "/vmls/v2/fetch".into()),
            ("PUT", format!("/vmls/v1/mailboxes/{upper}/records")),
            ("PUT", format!("/vmls/v1/mailboxes/{}/records", &HEX[1..])),
            ("PUT", format!("/vmls/v1/mailboxes/{HEX}0/records")),
            ("PUT", format!("/vmls/v1/mailboxes/{HEX}/records/")),
            ("POST", format!("/vmls/v1/mailboxes/{HEX}/records")),
            ("GET", format!("/vmls/v1/packages/{HEX}")),
            ("PUT", format!("/vmls/v1/slots/{HEX}/01")),
            ("PUT", format!("/vmls/v1/slots/{HEX}/4294967296")),
            ("PUT", format!("/vmls/v1/slots/{HEX}/-1")),
            ("PUT", format!("/vmls/v1/slots/{HEX}/+1")),
            ("PUT", format!("/vmls/v1/slots/{HEX}/")),
            ("PUT", format!("/vmls/v1/slots/{HEX}")),
            ("POST", format!("/vmls/v1/slots/{HEX}/1/state")),
            ("POST", format!("/vmls/v1//slots/{HEX}/1/status")),
            ("POST", "/vmls/v1/fetch?after=x".into()),
            ("POST", "/vmls-witness/v1/fetch".into()),
            ("GET", "/vmls-witness/v1/read".into()),
            ("PUT", "/events".into()),
            ("DELETE", "/cadence/v1/status".into()),
            ("GET", "/cadence/v1/status".into()),
        ];
        for (method, path) in refused {
            assert!(
                validate_http_request(&vmls(method, &path, nostr, b"")).is_err(),
                "{method} {path}"
            );
        }
        assert!(validate_http_request(&vmls("PATCH", "/vmls/v1/ack", nostr, b"")).is_err());
    }

    #[test]
    fn vmls_bodies_are_bounded_per_route() {
        let nostr = "Nostr YQ==";
        let envelope = format!("/vmls/v1/mailboxes/{HEX}/records");
        let mut body = vec![0; MAX_VMLS_ENVELOPE_BYTES];
        assert!(validate_http_request(&vmls("PUT", &envelope, nostr, &body)).is_ok());
        body.push(0);
        assert!(validate_http_request(&vmls("PUT", &envelope, nostr, &body)).is_err());

        let mut json = vec![b' '; MAX_VMLS_JSON_BYTES];
        assert!(validate_http_request(&vmls("POST", "/vmls/v1/fetch", nostr, &json)).is_ok());
        json.push(b' ');
        assert!(validate_http_request(&vmls("POST", "/vmls/v1/fetch", nostr, &json)).is_err());

        for (method, path) in [
            ("GET", "/vmls/v1/capabilities".to_string()),
            ("DELETE", format!("/vmls/v1/packages/{HEX}")),
        ] {
            assert!(validate_http_request(&vmls(method, &path, nostr, b"{}")).is_err());
        }
    }

    #[test]
    fn witness_routes_carry_bytes_and_no_authorization() {
        for path in ["/vmls-witness/v1/read", "/vmls-witness/v1/advance"] {
            let (method, route) =
                validate_http_request(&vmls("POST", path, "", &[0; 256])).unwrap();
            assert_eq!(method, Method::POST);
            assert_eq!(route, WITNESS_ROUTE);
            assert!(validate_http_request(&vmls("POST", path, "", &[0; 257])).is_err());
            assert!(validate_http_request(&vmls("POST", path, "Nostr YQ==", b"x")).is_err());
            assert!(validate_http_request(&vmls("PUT", path, "", b"x")).is_err());
        }
    }

    fn reply(
        status: StatusCode,
        content_type: Option<&str>,
        body: Vec<u8>,
    ) -> Response<Full<Bytes>> {
        let mut builder = Response::builder().status(status);
        if let Some(content_type) = content_type {
            builder = builder.header(hyper::header::CONTENT_TYPE, content_type);
        }
        builder.body(Full::new(Bytes::from(body))).unwrap()
    }

    #[tokio::test]
    async fn witness_replies_are_exact_receipts_or_bare_refusals() {
        let octets = Some("application/octet-stream");
        for status in [StatusCode::OK, StatusCode::CONFLICT, StatusCode::GONE] {
            let receipt = vec![1; WITNESS_RECEIPT_BYTES];
            assert_eq!(
                decode_http_response(reply(status, octets, receipt.clone()), &WITNESS_ROUTE)
                    .await
                    .unwrap(),
                (status.as_u16(), receipt)
            );
            for length in [0, WITNESS_RECEIPT_BYTES - 1, WITNESS_RECEIPT_BYTES + 1] {
                assert!(
                    decode_http_response(reply(status, octets, vec![1; length]), &WITNESS_ROUTE)
                        .await
                        .is_err(),
                    "{status} with {length} bytes"
                );
            }
        }
        // Bothy's refusals, including 409 for an exhausted counter, have no
        // body and no content type.
        for status in [
            StatusCode::CONFLICT,
            StatusCode::FORBIDDEN,
            StatusCode::NOT_FOUND,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            assert_eq!(
                decode_http_response(reply(status, None, Vec::new()), &WITNESS_ROUTE)
                    .await
                    .unwrap(),
                (status.as_u16(), Vec::new())
            );
        }
        for (status, content_type) in [
            (StatusCode::OK, None),
            (StatusCode::OK, Some("application/json")),
            (StatusCode::NO_CONTENT, octets),
            (StatusCode::TEMPORARY_REDIRECT, octets),
        ] {
            assert!(
                decode_http_response(
                    reply(status, content_type, vec![1; WITNESS_RECEIPT_BYTES]),
                    &WITNESS_ROUTE
                )
                .await
                .is_err(),
                "{status} {content_type:?}"
            );
        }
        let chatty = reply(
            StatusCode::FORBIDDEN,
            None,
            vec![0; MAX_DISCARDED_REFUSAL_BYTES + 1],
        );
        assert!(decode_http_response(chatty, &WITNESS_ROUTE).await.is_err());
    }

    #[test]
    fn witness_refusal_needs_the_witness_route_403_and_the_exact_header() {
        let with = |name: &str, value: &str| {
            let mut headers = hyper::HeaderMap::new();
            headers.append(
                hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
            headers
        };
        let refused = with("vmls-witness", "refused");
        let forbidden = StatusCode::FORBIDDEN;
        assert!(is_witness_refusal(&WITNESS_ROUTE, forbidden, &refused));
        // The header name is case-insensitive; surrounding whitespace is
        // stripped by the HTTP parser, never by us.
        assert!(is_witness_refusal(
            &WITNESS_ROUTE,
            forbidden,
            &with("VMLS-Witness", "refused")
        ));
        let none = hyper::HeaderMap::new();
        assert!(!is_witness_refusal(&WITNESS_ROUTE, forbidden, &none));
        for value in ["Refused", "refused!", "unavailable", "", "refused refused"] {
            assert!(
                !is_witness_refusal(&WITNESS_ROUTE, forbidden, &with("vmls-witness", value)),
                "{value:?}"
            );
        }
        let mut twice = refused.clone();
        twice.append("vmls-witness", "refused".parse().unwrap());
        assert!(!is_witness_refusal(&WITNESS_ROUTE, forbidden, &twice));
        for status in [
            StatusCode::OK,
            StatusCode::CONFLICT,
            StatusCode::GONE,
            StatusCode::NOT_FOUND,
        ] {
            assert!(!is_witness_refusal(&WITNESS_ROUTE, status, &refused));
        }
        assert!(!is_witness_refusal(&CADENCE_ROUTE, forbidden, &refused));
    }

    #[tokio::test]
    async fn vmls_replies_are_json_or_bare_refusals() {
        let json = Some("application/json");
        let (_, route) =
            validate_http_request(&vmls("GET", "/vmls/v1/capabilities", "Nostr YQ==", b""))
                .unwrap();
        assert_eq!(
            decode_http_response(reply(StatusCode::OK, json, b"{}".to_vec()), &route)
                .await
                .unwrap(),
            (200, b"{}".to_vec())
        );
        // A box without VMLS answers 404 with nothing; the client must see
        // the status (contract: a missing route is UnsupportedSecurityContract).
        assert_eq!(
            decode_http_response(reply(StatusCode::NOT_FOUND, None, Vec::new()), &route)
                .await
                .unwrap(),
            (404, Vec::new())
        );
        assert!(
            decode_http_response(reply(StatusCode::OK, None, Vec::new()), &route)
                .await
                .is_err()
        );
        assert!(
            decode_http_response(
                reply(
                    StatusCode::OK,
                    Some("application/octet-stream"),
                    b"{}".to_vec()
                ),
                &route
            )
            .await
            .is_err()
        );
        let oversized = vec![b' '; MAX_HTTP_BODY_BYTES + 1];
        assert!(
            decode_http_response(reply(StatusCode::OK, json, oversized.clone()), &route)
                .await
                .is_err()
        );
        // Cadence keeps its rule: every reply is JSON.
        assert!(
            decode_http_response(
                reply(StatusCode::NOT_FOUND, None, Vec::new()),
                &CADENCE_ROUTE
            )
            .await
            .is_err()
        );

        let (_, fetch) =
            validate_http_request(&vmls("POST", "/vmls/v1/fetch", "Nostr YQ==", b"{}")).unwrap();
        assert_eq!(
            decode_http_response(reply(StatusCode::OK, json, oversized), &fetch)
                .await
                .unwrap()
                .1
                .len(),
            MAX_HTTP_BODY_BYTES + 1
        );
        assert!(
            decode_http_response(
                reply(
                    StatusCode::OK,
                    json,
                    vec![b' '; MAX_VMLS_FETCH_RESPONSE_BYTES + 1]
                ),
                &fetch
            )
            .await
            .is_err()
        );
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

    /// `stop` takes effect while another call holds the engine through a
    /// long first dial: the dial gives way and reports the stop.
    #[tokio::test]
    async fn stop_does_not_wait_behind_a_dial() {
        let now = rt::unix_now();
        // A relay nothing listens on: the dial waits out its rendezvous.
        let card = Card::sign(
            &TransportKey::generate(),
            now,
            now + 600,
            1,
            vec![link_core::card::Hint::relay("ws://127.0.0.1:9/link")],
        );
        let engine = Arc::new(
            Engine::start(EngineConfig {
                transport_seed: vec![0x17; 32],
                relay_urls: Vec::new(),
                allow_direct: false,
                routes: vec![Route {
                    route_id: "unreachable".into(),
                    card: card.as_bytes().to_vec(),
                    paired_route_secret: vec![0x29; 32],
                    card_serial: 1,
                    card_verified_at: now,
                }],
            })
            .await
            .expect("engine"),
        );
        let dialling = tokio::spawn({
            let engine = engine.clone();
            async move {
                engine
                    .request_json(
                        JsonRequest {
                            route_id: "unreachable".into(),
                            method: "POST".into(),
                            path: "/cadence/v1/status".into(),
                            authorization: "Nostr YQ==".into(),
                            body: Vec::new(),
                        },
                        Duration::from_secs(60),
                    )
                    .await
            }
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        tokio::time::timeout(Duration::from_secs(5), engine.stop())
            .await
            .expect("stop does not wait behind the dial");
        let dialled = tokio::time::timeout(Duration::from_secs(5), dialling)
            .await
            .expect("the dial gives way")
            .expect("dial task");
        assert!(matches!(dialled, Err(EngineError::Stopped)), "{dialled:?}");
    }
}
