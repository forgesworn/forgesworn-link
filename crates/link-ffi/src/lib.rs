//! Kotlin's owned boundary to Link: it supplies encrypted persisted route state;
//! Rust owns endpoint, sessions, WebSocket handles and bounded HTTP streams.
//! Cadence authorization and JSON cross as opaque bytes; Link interprets no Nostr
//! event or application authority.

use std::sync::Arc;
use std::time::Duration;

use link_endpoint::Session;
use link_engine::{
    Engine, EngineConfig, EngineError, HTTP_REQUEST_TIMEOUT, JsonRequest, JsonResponse,
    PairingBundle, PathInfo, Route,
};
use link_websocket::{IncomingMessage, Socket};
use thiserror::Error;
use tokio::runtime::{Handle, Runtime};

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

/// One JSON request sent over an already paired Link route.
///
/// The route selects a pinned peer. The native boundary supplies `Host` and
/// `Content-Type`, so Kotlin cannot redirect this call or change its transport
/// identity.
#[derive(uniffi::Record, Clone)]
pub struct LinkHttpRequest {
    pub route_id: String,
    pub method: String,
    pub path: String,
    pub authorization: String,
    pub body: Vec<u8>,
}
impl std::fmt::Debug for LinkHttpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkHttpRequest")
            .field("route_id", &"[redacted]")
            .field("method", &self.method)
            .field("path", &"[redacted]")
            .field("authorization", &"[redacted]")
            .field("body", &format_args!("{} bytes", self.body.len()))
            .finish()
    }
}

/// A bounded JSON response and the Link path that carried it.
#[derive(uniffi::Record, Clone)]
pub struct LinkHttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
    /// True only for a witness-route 403 carrying the response header
    /// `vmls-witness: refused` (Bothy's deliberate refusal). Any other 403,
    /// or a header on any other route, leaves it false ("unavailable").
    pub witness_refused: bool,
    pub path: LinkPath,
}
impl std::fmt::Debug for LinkHttpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkHttpResponse")
            .field("status", &self.status)
            .field("body", &format_args!("{} bytes", self.body.len()))
            .field("witness_refused", &self.witness_refused)
            .field("path", &self.path)
            .finish()
    }
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

#[derive(uniffi::Object)]
pub struct LinkEngine {
    /// `Some` until drop, which decides how the runtime may end.
    runtime: Option<Runtime>,
    core: Arc<Engine>,
}
#[derive(uniffi::Object)]
pub struct LinkSocket {
    socket: Socket,
    session: Arc<Session>,
}

// The engine's logic lives in link-engine, shared with link-web; this crate
// adapts it to UniFFI's synchronous calls on the engine-owned runtime.

impl From<EngineError> for LinkError {
    fn from(error: EngineError) -> Self {
        match error {
            EngineError::Config(message) => LinkError::Config(message),
            EngineError::Route(message) => LinkError::Route(message),
            EngineError::Transport(message) => LinkError::Transport(message),
            EngineError::Socket(message) => LinkError::Socket(message),
            EngineError::Stopped => LinkError::Stopped,
        }
    }
}
impl From<LinkRoute> for Route {
    fn from(route: LinkRoute) -> Self {
        Route {
            route_id: route.route_id,
            card: route.card,
            paired_route_secret: route.paired_route_secret,
            card_serial: route.card_serial,
            card_verified_at: route.card_verified_at,
        }
    }
}
impl From<Route> for LinkRoute {
    fn from(mut route: Route) -> Self {
        // `Route` zeroises its secret on drop, so the fields are taken.
        LinkRoute {
            route_id: std::mem::take(&mut route.route_id),
            card: std::mem::take(&mut route.card),
            paired_route_secret: std::mem::take(&mut route.paired_route_secret),
            card_serial: route.card_serial,
            card_verified_at: route.card_verified_at,
        }
    }
}
impl From<LinkHttpRequest> for JsonRequest {
    fn from(request: LinkHttpRequest) -> Self {
        JsonRequest {
            route_id: request.route_id,
            method: request.method,
            path: request.path,
            authorization: request.authorization,
            body: request.body,
        }
    }
}
impl From<PathInfo> for LinkPath {
    fn from(path: PathInfo) -> Self {
        LinkPath {
            status: path.status,
            relay: path.relay,
            direct: path.direct,
            cause: path.cause,
        }
    }
}
impl From<JsonResponse> for LinkHttpResponse {
    fn from(response: JsonResponse) -> Self {
        LinkHttpResponse {
            status: response.status,
            body: response.body,
            witness_refused: response.witness_refused,
            path: response.path.into(),
        }
    }
}

#[uniffi::export]
impl LinkEngine {
    #[uniffi::constructor]
    pub fn start(config: LinkConfig) -> Result<Arc<Self>, LinkError> {
        let config = EngineConfig {
            transport_seed: config.transport_seed,
            relay_urls: config.relay_urls,
            allow_direct: config.allow_direct,
            routes: config.routes.into_iter().map(Route::from).collect(),
        };
        let runtime = Runtime::new().map_err(|error| LinkError::Transport(error.to_string()))?;
        // A fresh runtime cannot be the caller's own, so a caller inside some
        // other runtime is served from a helper thread rather than refused.
        let core = if Handle::try_current().is_ok() {
            std::thread::scope(|scope| {
                scope
                    .spawn(|| runtime.block_on(Engine::start(config)))
                    .join()
                    .expect("engine start panicked")
            })
        } else {
            runtime.block_on(Engine::start(config))
        }?;
        Ok(Arc::new(Self {
            runtime: Some(runtime),
            core: Arc::new(core),
        }))
    }

    pub fn open_socket(
        &self,
        virtual_url: String,
        route_id: String,
        listener: Box<dyn LinkSocketListener>,
    ) -> Result<Arc<LinkSocket>, LinkError> {
        let (socket, mut incoming, session) =
            self.block_on(self.core.open_socket(&virtual_url, &route_id))??;
        listener.on_open();
        self.runtime().spawn(async move {
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

    /// Send one bounded, allowlisted request (cadence, VMLS or witness) over
    /// the route's pinned Link session. The application supplies neither a
    /// network URL, a `Host` nor a `Content-Type`.
    pub fn request_json(&self, request: LinkHttpRequest) -> Result<LinkHttpResponse, LinkError> {
        self.request_json_with_timeout(request, HTTP_REQUEST_TIMEOUT)
    }

    /// Ask the paired server to retire this route. Local credentials remain
    /// installed until the product durably records the acknowledged outcome.
    pub fn retire_route(&self, route_id: String) -> Result<(), LinkError> {
        Ok(self.block_on(self.core.retire_route(&route_id))??)
    }

    /// Remove the paired transport after the product has durably recorded
    /// logical retirement. The caller may safely treat transport failure as a
    /// lost final acknowledgement: application authority was revoked by
    /// `retire_route`, and this method never removes local credentials.
    pub fn finalize_route(&self, route_id: String) -> Result<(), LinkError> {
        Ok(self.block_on(self.core.finalize_route(&route_id))??)
    }

    /// Enrol one durable event route over Link's quarantined provisional
    /// session, install it in the running engine, and return the exact record
    /// the Kotlin vault must commit atomically.
    pub fn pair_route(&self, bundle: LinkPairingBundle) -> Result<LinkRoute, LinkError> {
        let LinkPairingBundle {
            route_id,
            server_card,
            pairing_secret,
            expires_at,
        } = bundle;
        let bundle = PairingBundle {
            route_id,
            server_card,
            pairing_secret,
            expires_at,
        };
        Ok(self.block_on(self.core.pair_route(bundle))??.into())
    }

    pub fn upsert_route(&self, route: LinkRoute) -> Result<(), LinkError> {
        Ok(self.block_on(self.core.upsert_route(route.into()))??)
    }
    pub fn remove_route(&self, route_id: String) -> Result<(), LinkError> {
        Ok(self.block_on(self.core.remove_route(&route_id))??)
    }
    pub fn reannounce(&self) -> Result<(), LinkError> {
        Ok(self.block_on(self.core.reannounce())??)
    }
    /// Stop the engine.  Called from the engine's own runtime (a socket
    /// callback), it cannot wait there, so the stop runs in the background.
    pub fn stop(&self) {
        let core = self.core.clone();
        if self.block_on(async move { core.stop().await }).is_err() {
            let core = self.core.clone();
            self.runtime().spawn(async move { core.stop().await });
        }
    }
}

impl LinkEngine {
    fn runtime(&self) -> &Runtime {
        self.runtime.as_ref().expect("the runtime lives until drop")
    }

    /// Run one engine call for a synchronous UniFFI method, waiting for it.
    ///
    /// Kotlin calls from its own executor, an ordinary thread, which blocks
    /// on the engine-owned runtime.  A call from the engine's own runtime
    /// (a socket callback that calls back in) could only deadlock, so it is
    /// refused with an error.  A call from some other Tokio runtime (Rust
    /// embedding the engine, or a test) cannot block its own thread on a
    /// second runtime, so it waits on a scoped helper thread instead.
    fn block_on<F>(&self, future: F) -> Result<F::Output, LinkError>
    where
        F: std::future::Future + Send,
        F::Output: Send,
    {
        match Handle::try_current() {
            Err(_) => Ok(self.runtime().block_on(future)),
            Ok(current) if current.id() == self.runtime().handle().id() => Err(LinkError::Config(
                "the engine cannot be called from its own runtime (a socket callback); \
                     call it from another thread"
                    .into(),
            )),
            Ok(_) => Ok(std::thread::scope(|scope| {
                scope
                    .spawn(|| self.runtime().block_on(future))
                    .join()
                    .expect("engine call panicked")
            })),
        }
    }

    fn request_json_with_timeout(
        &self,
        request: LinkHttpRequest,
        timeout: Duration,
    ) -> Result<LinkHttpResponse, LinkError> {
        Ok(self
            .block_on(self.core.request_json(request.into(), timeout))??
            .into())
    }
}

impl Drop for LinkEngine {
    fn drop(&mut self) {
        // Dropping a runtime waits for its tasks, which a thread inside a
        // runtime (including this one's, if a task held the last reference)
        // must not do; there it is shut down without waiting.
        if let Some(runtime) = self.runtime.take()
            && Handle::try_current().is_ok()
        {
            runtime.shutdown_background();
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
        link_engine::path(&self.session).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use link_core::{Card, TransportKey, VerifyContext};
    use link_endpoint::rt::unix_now as now_unix;
    use link_endpoint::{AcceptedSession, Endpoint, EndpointConfig, RelaySpec};
    use link_engine::{MAX_HTTP_AUTHORIZATION_BYTES, route_card, route_frame};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use zeroize::Zeroizing;

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

    /// A socket callback runs on the engine's own runtime; a call back into
    /// the engine from there is refused rather than left to deadlock, and a
    /// stop from there still happens, in the background.
    #[test]
    fn a_call_from_the_engines_own_runtime_is_refused() {
        let engine = LinkEngine::start(LinkConfig {
            transport_seed: vec![0x61; 32],
            relay_urls: Vec::new(),
            allow_direct: false,
            routes: Vec::new(),
        })
        .expect("engine");
        let inside = engine.runtime().spawn({
            let engine = engine.clone();
            async move {
                let refused = engine.remove_route("any".into());
                engine.stop();
                refused
            }
        });
        let refused = engine
            .runtime()
            .block_on(inside)
            .expect("callback task")
            .expect_err("refused on the engine's own runtime");
        assert!(refused.to_string().contains("its own runtime"), "{refused}");
        let mut stopped = false;
        for _ in 0..200 {
            if matches!(engine.reannounce(), Err(LinkError::Stopped)) {
                stopped = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(stopped, "the background stop took effect");
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
    fn cadence_request_debug_is_redacted() {
        let request = LinkHttpRequest {
            route_id: "circle-main".into(),
            method: "POST".into(),
            path: "/cadence/v1/status".into(),
            authorization: "Nostr YQ==".into(),
            body: br#"{"v":1}"#.to_vec(),
        };
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("YQ=="));
        assert!(!rendered.contains(r#"{"v":1}"#));
        assert!(!rendered.contains("circle-main"));
        assert!(!rendered.contains("/cadence/v1/status"));
    }

    #[test]
    fn cadence_response_debug_is_redacted() {
        let response = LinkHttpResponse {
            status: 200,
            body: b"response-secret".to_vec(),
            witness_refused: false,
            path: LinkPath {
                status: "relayed".into(),
                relay: None,
                direct: None,
                cause: "fixture".into(),
            },
        };
        assert!(!format!("{response:?}").contains("response-secret"));
    }

    async fn read_http_request(stream: &mut link_endpoint::Stream) -> (String, Vec<u8>) {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(stream.read_u8().await.expect("request head"));
            assert!(head.len() <= MAX_HTTP_AUTHORIZATION_BYTES + 8 * 1_024);
        }
        let head = String::from_utf8(head).expect("HTTP head is ASCII");
        let content_length = head
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .and_then(|value| value.parse::<usize>().ok())
            })
            // hyper sends no length for an empty GET or DELETE.
            .unwrap_or(0);
        let mut body = vec![0; content_length];
        stream.read_exact(&mut body).await.expect("request body");
        (head, body)
    }

    async fn write_json_response(stream: &mut link_endpoint::Stream, status: &str, body: &[u8]) {
        write_response(stream, status, Some("application/json"), body).await;
    }

    async fn write_response(
        stream: &mut link_endpoint::Stream,
        status: &str,
        content_type: Option<&str>,
        body: &[u8],
    ) {
        write_response_with_header(stream, status, content_type, None, body).await;
    }

    async fn write_response_with_header(
        stream: &mut link_endpoint::Stream,
        status: &str,
        content_type: Option<&str>,
        header: Option<&str>,
        body: &[u8],
    ) {
        let content_type = content_type
            .map(|value| format!("Content-Type: {value}\r\n"))
            .unwrap_or_default();
        let header = header
            .map(|value| format!("{value}\r\n"))
            .unwrap_or_default();
        let head = format!(
            "HTTP/1.1 {status}\r\n{content_type}{header}Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(head.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
        stream.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn allowlisted_requests_cross_one_pinned_link_session_with_exact_bytes() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let relay = link_relay::start(link_relay::RelayConfig {
            ws_bind: "127.0.0.1:0".parse().unwrap(),
            udp_bind: "127.0.0.1:0".parse().unwrap(),
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
        let client_seed = [0x35; 32];
        let client_node = TransportKey::from_seed(client_seed).node_id();
        let paired_secret = [0x73; 32];
        let mut server_config = EndpointConfig::new(TransportKey::generate());
        server_config.relays = vec![RelaySpec::plain(&relay_url)];
        server_config.allow_direct = false;
        server_config.bind = "127.0.0.1:0".parse().unwrap();
        server_config.paired_routes = Some(HashMap::from([(
            client_node,
            Zeroizing::new(paired_secret),
        )]));
        let server = Arc::new(Endpoint::open(server_config).await.expect("server"));
        let server_card = server.card(Duration::from_secs(600), Vec::new());
        tokio::time::timeout(
            Duration::from_secs(15),
            server.paths().relay().home().wait_up(),
        )
        .await
        .expect("server relay wait")
        .expect("server relay is up");

        let engine = tokio::task::spawn_blocking(move || {
            LinkEngine::start(LinkConfig {
                transport_seed: client_seed.to_vec(),
                relay_urls: Vec::new(),
                allow_direct: false,
                routes: vec![LinkRoute {
                    route_id: "circle-main".into(),
                    card: server_card.as_bytes().to_vec(),
                    paired_route_secret: paired_secret.to_vec(),
                    card_serial: server_card.serial,
                    card_verified_at: now_unix(),
                }],
            })
            .expect("engine")
        })
        .await
        .expect("engine task");
        let server_node = server.node_id().to_base32();
        let serving = tokio::spawn({
            let server = server.clone();
            let server_node = server_node.clone();
            async move {
                let session = match server.accept_any().await.expect("client session") {
                    AcceptedSession::Pinned(session) => session,
                    AcceptedSession::Pairing(_) => panic!("ordinary request must be pinned"),
                };
                assert_eq!(session.peer(), client_node);

                let mut first = session.accept_stream().await.expect("first request");
                let (head, body) = read_http_request(&mut first).await;
                assert!(head.starts_with("POST /cadence/v1/status HTTP/1.1\r\n"));
                let lower = head.to_ascii_lowercase();
                assert!(lower.contains(&format!("host: {server_node}\r\n")));
                assert!(lower.contains("content-type: application/json\r\n"));
                assert!(head.contains("authorization: Nostr YQ==\r\n"));
                assert_eq!(body, br#"{"v":1,"request":"first"}"#);
                write_json_response(&mut first, "200 OK", br#"{"v":1,"code":"not-ready"}"#).await;

                let mut second = session.accept_stream().await.expect("second request");
                let (head, body) = read_http_request(&mut second).await;
                assert!(head.starts_with(
                    "PUT /cadence/v1/leases/00112233445566778899aabbccddeeff HTTP/1.1\r\n"
                ));
                assert_eq!(body, br#"{"v":1,"request":"second"}"#);
                write_json_response(&mut second, "403 Forbidden", br#"{"v":1,"code":"scope"}"#)
                    .await;

                let mut witness = session.accept_stream().await.expect("witness request");
                let (head, body) = read_http_request(&mut witness).await;
                assert!(head.starts_with("POST /vmls-witness/v1/read HTTP/1.1\r\n"));
                let lower = head.to_ascii_lowercase();
                assert!(lower.contains("content-type: application/octet-stream\r\n"));
                assert!(!lower.contains("authorization:"));
                assert_eq!(body, [0xa1, 0x01, 0x01]);
                write_response(
                    &mut witness,
                    "409 Conflict",
                    Some("application/octet-stream"),
                    &[0x5a; 170],
                )
                .await;

                // Witness refusals: only a 403 with the exact header is
                // deliberate; a bare 403, a wrong value and a 409 are not.
                for (status, header) in [
                    ("403 Forbidden", Some("Vmls-Witness: refused")),
                    ("403 Forbidden", None),
                    ("403 Forbidden", Some("vmls-witness: Refused")),
                    ("409 Conflict", Some("vmls-witness: refused")),
                ] {
                    let mut stream = session.accept_stream().await.expect("witness refusal");
                    let (head, _) = read_http_request(&mut stream).await;
                    assert!(head.starts_with("POST /vmls-witness/v1/advance HTTP/1.1\r\n"));
                    write_response_with_header(&mut stream, status, None, header, b"").await;
                }

                // The same header on a cadence route means nothing.
                let mut cadence = session.accept_stream().await.expect("cadence refusal");
                let _ = read_http_request(&mut cadence).await;
                write_response_with_header(
                    &mut cadence,
                    "403 Forbidden",
                    Some("application/json"),
                    Some("vmls-witness: refused"),
                    br#"{"v":1,"code":"scope"}"#,
                )
                .await;

                let mut capabilities = session.accept_stream().await.expect("capabilities");
                let (head, body) = read_http_request(&mut capabilities).await;
                assert!(head.starts_with("GET /vmls/v1/capabilities HTTP/1.1\r\n"));
                let lower = head.to_ascii_lowercase();
                assert!(!lower.contains("content-type:"));
                assert!(head.contains("authorization: Nostr Yg==\r\n"));
                assert!(body.is_empty());
                // A box without VMLS: axum's bare 404.
                write_response(&mut capabilities, "404 Not Found", None, b"").await;

                let mut stalled = session.accept_stream().await.expect("stalled request");
                let _ = read_http_request(&mut stalled).await;
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        });

        // UniFFI invokes this from an ordinary JVM worker with no ambient
        // Tokio context. A Tokio blocking task would hide reactor-entry bugs.
        let first = std::thread::spawn({
            let engine = engine.clone();
            move || {
                assert!(
                    tokio::runtime::Handle::try_current().is_err(),
                    "regression caller must have no ambient Tokio runtime"
                );
                engine.request_json(LinkHttpRequest {
                    route_id: "circle-main".into(),
                    method: "POST".into(),
                    path: "/cadence/v1/status".into(),
                    authorization: "Nostr YQ==".into(),
                    body: br#"{"v":1,"request":"first"}"#.to_vec(),
                })
            }
        })
        .join()
        .unwrap()
        .expect("first response");
        assert_eq!(first.status, 200);
        assert_eq!(first.body, br#"{"v":1,"code":"not-ready"}"#);
        assert_eq!(first.path.status, "relayed");
        let first_session =
            Arc::as_ptr(&engine.core.cached_session("circle-main").unwrap()) as usize;

        let second = std::thread::spawn({
            let engine = engine.clone();
            move || {
                engine.request_json(LinkHttpRequest {
                    route_id: "circle-main".into(),
                    method: "PUT".into(),
                    path: "/cadence/v1/leases/00112233445566778899aabbccddeeff".into(),
                    authorization: "Nostr YQ==".into(),
                    body: br#"{"v":1,"request":"second"}"#.to_vec(),
                })
            }
        })
        .join()
        .unwrap()
        .expect("second response");
        assert_eq!(second.status, 403);
        assert_eq!(second.body, br#"{"v":1,"code":"scope"}"#);
        let second_session =
            Arc::as_ptr(&engine.core.cached_session("circle-main").unwrap()) as usize;
        assert_eq!(first_session, second_session, "requests reuse one session");

        let witness = std::thread::spawn({
            let engine = engine.clone();
            move || {
                engine.request_json(LinkHttpRequest {
                    route_id: "circle-main".into(),
                    method: "POST".into(),
                    path: "/vmls-witness/v1/read".into(),
                    authorization: String::new(),
                    body: vec![0xa1, 0x01, 0x01],
                })
            }
        })
        .join()
        .unwrap()
        .expect("witness response");
        assert_eq!(witness.status, 409);
        assert_eq!(witness.body, [0x5a; 170]);
        assert!(!witness.witness_refused, "a 409 receipt is not a refusal");

        let advance = |path: &str| {
            let engine = engine.clone();
            let path = path.to_string();
            std::thread::spawn(move || {
                engine.request_json(LinkHttpRequest {
                    route_id: "circle-main".into(),
                    method: "POST".into(),
                    path,
                    authorization: String::new(),
                    body: vec![0xa1, 0x01, 0x01],
                })
            })
            .join()
            .unwrap()
            .expect("witness refusal response")
        };
        let advance_path = "/vmls-witness/v1/advance";
        let refused = advance(advance_path);
        assert_eq!(refused.status, 403);
        assert!(refused.body.is_empty());
        assert!(refused.witness_refused, "403 with the exact header");
        let bare = advance(advance_path);
        assert_eq!(bare.status, 403);
        assert!(!bare.witness_refused, "403 without the header");
        let wrong = advance(advance_path);
        assert_eq!(wrong.status, 403);
        assert!(!wrong.witness_refused, "403 with a wrong value");
        let exhausted = advance(advance_path);
        assert_eq!(exhausted.status, 409);
        assert!(exhausted.body.is_empty());
        assert!(!exhausted.witness_refused, "an empty 409 stays a 409");

        let cadence = std::thread::spawn({
            let engine = engine.clone();
            move || {
                engine.request_json(LinkHttpRequest {
                    route_id: "circle-main".into(),
                    method: "POST".into(),
                    path: "/cadence/v1/status".into(),
                    authorization: "Nostr YQ==".into(),
                    body: br#"{"v":1}"#.to_vec(),
                })
            }
        })
        .join()
        .unwrap()
        .expect("cadence refusal response");
        assert_eq!(cadence.status, 403);
        assert!(!cadence.witness_refused, "header off the witness route");

        let capabilities = std::thread::spawn({
            let engine = engine.clone();
            move || {
                engine.request_json(LinkHttpRequest {
                    route_id: "circle-main".into(),
                    method: "GET".into(),
                    path: "/vmls/v1/capabilities".into(),
                    authorization: "Nostr Yg==".into(),
                    body: Vec::new(),
                })
            }
        })
        .join()
        .unwrap()
        .expect("capabilities response");
        assert_eq!(capabilities.status, 404);
        assert!(capabilities.body.is_empty());

        let timeout = std::thread::spawn({
            let engine = engine.clone();
            move || {
                engine.request_json_with_timeout(
                    LinkHttpRequest {
                        route_id: "circle-main".into(),
                        method: "POST".into(),
                        path: "/cadence/v1/status".into(),
                        authorization: "Nostr YQ==".into(),
                        body: br#"{"v":1,"request":"stalled"}"#.to_vec(),
                    },
                    Duration::from_millis(50),
                )
            }
        })
        .join()
        .unwrap()
        .expect_err("stalled response is bounded");
        assert_eq!(timeout.to_string(), "transport: request timed out");

        serving.await.unwrap();
        tokio::task::spawn_blocking(move || {
            engine.stop();
            drop(engine);
        })
        .await
        .unwrap();
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
        assert!(engine.core.has_route("route-to-retire"));
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
            engine.core.has_route("circle-main"),
            "the returned route is also installed in the live engine",
        );
        engine.stop();
        tokio::task::spawn_blocking(move || drop(engine))
            .await
            .expect("engine drop");
    }
}
