//! End to end: the link-web wasm engine, run in Node 24 (whose global
//! WebSocket stands in for a browser's), pairs with a native Link peer
//! through a real `link-relay`, sends a cadence JSON request and echoes text
//! over the event WebSocket, then restarts from the persisted record.
//!
//! A browser verifies relay certificates against WebPKI, so the relay sits
//! behind a TLS front with a real certificate for the lab name, which the
//! host's `/etc/hosts` points at loopback.  Without that certificate or
//! that hosts entry the test says so and skips.  The key is only read from
//! disk into the TLS front; it never reaches a log or the repository.

#![cfg(not(all(target_family = "wasm", target_os = "unknown")))]

use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use futures_util::{SinkExt as _, StreamExt as _};
use link_core::card::{Card, VerifyContext};
use link_endpoint::rt::unix_now;
use link_endpoint::{
    AcceptedSession, Endpoint, EndpointConfig, NodeId, RelaySpec, Session, Stream, TransportKey,
};
use link_engine::{route_card, route_frame};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;

const LAB_HOST: &str = "link-lab.forgesworn.dev";
const PAIRING_SECRET: [u8; 16] = [0x4d; 16];

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The lab certificate and key, if this host has them.
fn lab_tls() -> Option<(PathBuf, PathBuf)> {
    let dir = match std::env::var_os("LINK_LAB_TLS_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(std::env::var_os("HOME")?)
            .join(".config/vennel-lab/tls/live")
            .join(LAB_HOST),
    };
    let chain = dir.join("fullchain.pem");
    let key = dir.join("privkey.pem");
    (chain.is_file() && key.is_file()).then_some((chain, key))
}

fn lab_host_is_loopback() -> bool {
    (LAB_HOST, 443)
        .to_socket_addrs()
        .map(|mut addrs| addrs.all(|addr| addr.ip().is_loopback()))
        .unwrap_or(false)
}

/// A wasi-sdk (or other wasm32 clang) for ring, from the environment or the
/// usual place on the lab host.
fn wasm_toolchain(command: &mut std::process::Command) {
    if std::env::var_os("CC_wasm32_unknown_unknown").is_some()
        || std::env::var_os("WASI_SDK").is_some()
    {
        return;
    }
    let Some(home) = std::env::var_os("HOME") else {
        return;
    };
    let root = PathBuf::from(home).join(".local/wasi-sdk");
    if let Some(sdk) = std::fs::read_dir(root)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .find(|path| path.join("bin/clang").is_file())
    {
        command.env("WASI_SDK", sdk);
    }
}

/// Build the Node package with the same script a release uses.
fn build_package() -> PathBuf {
    let root = workspace();
    let target_dir = root.join("target/link-web");
    let out = target_dir.join("e2e-pkg");
    let mut command = std::process::Command::new(root.join("scripts/build-link-web.sh"));
    command
        .args(["--target", "nodejs", "--out"])
        .arg(&out)
        .env("LINK_WEB_TARGET_DIR", &target_dir)
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .current_dir(&root);
    wasm_toolchain(&mut command);
    let status = command.status().expect("run scripts/build-link-web.sh");
    assert!(status.success(), "scripts/build-link-web.sh failed");
    out
}

/// A TLS front for the relay with the lab's WebPKI certificate, as a
/// deployed relay would present.  Returns the port it listens on.
async fn tls_front(chain: &Path, key: &Path, upstream: SocketAddr) -> u16 {
    let certs = CertificateDer::pem_file_iter(chain)
        .expect("read the lab certificate chain")
        .collect::<Result<Vec<_>, _>>()
        .expect("parse the lab certificate chain");
    let key = PrivateKeyDer::from_pem_file(key).expect("read the lab key");
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("TLS versions")
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .expect("lab certificate and key agree");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("TLS front");
    let port = listener.local_addr().expect("front address").port();
    tokio::spawn(async move {
        loop {
            let Ok((client, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut client) = acceptor.accept(client).await else {
                    return;
                };
                let Ok(mut relay) = TcpStream::connect(upstream).await else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut client, &mut relay).await;
            });
        }
    });
    port
}

/// What the native peer saw, for the assertions at the end.
#[derive(Default)]
struct Seen {
    pairing_header_matched: bool,
    enrolled_peer: Option<NodeId>,
    returned_card: Option<Card>,
    cadence: Vec<(String, String, Vec<u8>)>,
    socket_texts: Vec<String>,
    deletes: Vec<String>,
}

async fn read_head(stream: &mut Stream) -> Option<String> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await.ok()?);
        if head.len() > 64 * 1024 {
            return None;
        }
    }
    String::from_utf8(head).ok()
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

async fn read_body(stream: &mut Stream, head: &str) -> Vec<u8> {
    let length = header(head, "content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await.expect("request body");
    body
}

async fn respond(stream: &mut Stream, status: &str, content_type: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(body).await;
    let _ = stream.shutdown().await;
}

/// The Bothy side of pairing: check the QR capability, admit the caller's
/// card, install the TLS-exported route, and answer with this node's card.
async fn serve_pairing(
    server: &Endpoint,
    session: link_endpoint::PairingSession,
    seen: &Mutex<Seen>,
) {
    let exporter = session.paired_route_secret().expect("exporter");
    let mut stream = session.accept_stream().await.expect("enrolment stream");
    let head = read_head(&mut stream).await.expect("enrolment head");
    assert!(head.starts_with("PUT /events/route HTTP/1.1\r\n"), "{head}");
    let matched = header(&head, "x-bothy-pairing-secret") == Some(&hex::encode(PAIRING_SECRET));
    let body = read_body(&mut stream, &head).await;
    let caller = Card::verify(
        route_card(&body).expect("caller card frame"),
        &VerifyContext::new(unix_now()).expecting(session.peer()),
    )
    .expect("the caller's card matches its provisional key");
    if !matched {
        respond(&mut stream, "403 Forbidden", "text/plain", b"").await;
        return;
    }
    server
        .rendezvous_book()
        .expect("tag mode")
        .upsert_paired(caller.node_id, *exporter);
    let card = server.card(Duration::from_secs(600), Vec::new());
    {
        let mut seen = seen.lock().unwrap();
        seen.pairing_header_matched = true;
        seen.enrolled_peer = Some(caller.node_id);
        seen.returned_card = Some(card.clone());
    }
    respond(
        &mut stream,
        "200 OK",
        "application/octet-stream",
        &route_frame(card.as_bytes()),
    )
    .await;
    let _ = session.closed().await;
}

async fn serve_stream(mut stream: Stream, seen: Arc<Mutex<Seen>>) {
    let Some(head) = read_head(&mut stream).await else {
        return;
    };
    let request_line = head.lines().next().unwrap_or_default().to_owned();
    let mut parts = request_line.split(' ');
    let (method, path) = (
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
    );
    match (method, path) {
        ("POST" | "PUT", path) if path.starts_with("/cadence/v1/") => {
            let authorization = header(&head, "authorization")
                .unwrap_or_default()
                .to_owned();
            let body = read_body(&mut stream, &head).await;
            seen.lock()
                .unwrap()
                .cadence
                .push((path.to_owned(), authorization, body.clone()));
            respond(&mut stream, "200 OK", "application/json", &body).await;
        }
        ("GET", "/events") => {
            let key = header(&head, "sec-websocket-key").expect("websocket key");
            let accept = derive_accept_key(key.as_bytes());
            let reply = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            );
            stream.write_all(reply.as_bytes()).await.expect("upgrade");
            let mut socket =
                tokio_tungstenite::WebSocketStream::from_raw_socket(stream, Role::Server, None)
                    .await;
            while let Some(Ok(message)) = socket.next().await {
                match message {
                    Message::Text(text) => {
                        seen.lock().unwrap().socket_texts.push(text.clone());
                        let _ = socket.send(Message::Text(format!("echo: {text}"))).await;
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        }
        ("DELETE", "/events/route" | "/events/route/finalize") => {
            seen.lock().unwrap().deletes.push(path.to_owned());
            respond(&mut stream, "204 No Content", "text/plain", b"").await;
        }
        _ => respond(&mut stream, "404 Not Found", "text/plain", b"").await,
    }
}

async fn serve_session(session: Session, seen: Arc<Mutex<Seen>>) {
    while let Ok(stream) = session.accept_stream().await {
        tokio::spawn(serve_stream(stream, seen.clone()));
    }
}

async fn serve(server: Arc<Endpoint>, seen: Arc<Mutex<Seen>>) {
    while let Ok(accepted) = server.accept_any().await {
        match accepted {
            AcceptedSession::Pairing(session) => serve_pairing(&server, session, &seen).await,
            AcceptedSession::Pinned(session) => {
                tokio::spawn(serve_session(session, seen.clone()));
            }
        }
    }
}

/// Run the page side in Node, bounded: it is killed if it has not finished
/// in four minutes.
fn run_driver(driver: &Path, input: &str) -> std::process::Output {
    use std::io::Write as _;
    let mut node = std::process::Command::new("node")
        .arg(driver)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("node (24 or later, for its global WebSocket) is on PATH");
    node.stdin
        .take()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("driver input");
    let pid = node.id();
    let (done, finished) = std::sync::mpsc::channel::<()>();
    let watchdog = std::thread::spawn(move || {
        if finished.recv_timeout(Duration::from_secs(240)).is_err() {
            let _ = std::process::Command::new("kill")
                .arg(pid.to_string())
                .status();
        }
    });
    let output = node.wait_with_output().expect("driver output");
    let _ = done.send(());
    let _ = watchdog.join();
    output
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_browser_engine_pairs_requests_and_echoes_over_a_real_relay() {
    let Some((chain, key)) = lab_tls() else {
        eprintln!(
            "skipping link-web end-to-end: no lab certificate at ~/.config/vennel-lab/tls/live/{LAB_HOST}/ (or LINK_LAB_TLS_DIR)"
        );
        return;
    };
    if !lab_host_is_loopback() {
        eprintln!(
            "skipping link-web end-to-end: {LAB_HOST} does not resolve to loopback (add it to /etc/hosts)"
        );
        return;
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let package = tokio::task::spawn_blocking(build_package)
        .await
        .expect("package build");

    let relay = link_relay::start(link_relay::RelayConfig {
        ws_bind: "127.0.0.1:0".parse().unwrap(),
        udp_bind: "127.0.0.1:0".parse().unwrap(),
        hosts: vec![LAB_HOST.into()],
        tls: None,
        bytes_per_second: 0,
        max_sessions: 64,
        max_sessions_per_source: 0,
        reflector_per_second: 100.0,
    })
    .await
    .expect("relay");
    let port = tls_front(&chain, &key, relay.ws_addr).await;
    let relay_url = format!("wss://{LAB_HOST}:{port}/link");

    let mut config = EndpointConfig::new(TransportKey::generate());
    config.relays = vec![RelaySpec::plain(&relay_url)];
    config.allow_direct = false;
    config.bind = "127.0.0.1:0".parse().unwrap();
    config.rendezvous = Some(HashMap::new());
    let server = Arc::new(Endpoint::open(config).await.expect("native peer"));
    // A tag node with nothing to register stays idle, so hold a warm
    // registration while the relay session comes up.
    let _warm = server
        .register_pairing_secret([0x44; 16], Duration::from_secs(600))
        .expect("warm registration");
    tokio::time::timeout(
        Duration::from_secs(20),
        server.paths().relay().home().wait_up(),
    )
    .await
    .expect("native peer reaches the relay through WebPKI TLS")
    .expect("relay up");
    let _pairing = server
        .register_pairing_secret(PAIRING_SECRET, Duration::from_secs(600))
        .expect("pairing registration");
    let card = server.card(Duration::from_secs(600), Vec::new());
    let seen = Arc::new(Mutex::new(Seen::default()));
    tokio::spawn(serve(server.clone(), seen.clone()));

    let input = serde_json::json!({
        "pkg": package,
        "relayUrl": relay_url,
        "serverCard": base64::engine::general_purpose::STANDARD.encode(card.as_bytes()),
        "pairingSecret": hex::encode(PAIRING_SECRET),
        "expiresAt": unix_now() + 300,
        "serverNode": server.node_id().to_base32(),
        "otherNode": NodeId([7; 32]).to_base32(),
    });
    let driver = workspace().join("crates/link-web/tests/e2e/driver.mjs");
    let output = tokio::task::spawn_blocking(move || run_driver(&driver, &input.to_string()))
        .await
        .expect("driver task");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "driver failed ({}):\n{stdout}\n{stderr}",
        output.status
    );
    let report: serde_json::Value = stdout
        .lines()
        .find_map(|line| line.strip_prefix("E2E_REPORT "))
        .map(|json| serde_json::from_str(json).expect("report JSON"))
        .unwrap_or_else(|| panic!("no report:\n{stdout}\n{stderr}"));

    // Relay-only: a ws:// relay is refused before anything is dialled.
    assert!(
        report["refusedWsRelay"]
            .as_str()
            .is_some_and(|reason| reason.contains("wss://")),
        "{report}"
    );

    // Pairing returned exactly the record to persist, for this server.
    let paired = &report["paired"];
    assert_eq!(paired["routeId"], "box");
    assert_eq!(
        paired["keys"],
        serde_json::json!([
            "card",
            "cardSerial",
            "cardVerifiedAt",
            "pairedRouteSecret",
            "routeId"
        ])
    );
    assert_eq!(paired["secretBytes"], 32);
    {
        let seen = seen.lock().unwrap();
        assert!(seen.pairing_header_matched, "the QR capability arrived");
        assert!(seen.enrolled_peer.is_some());
        // The record carries the card the server answered with, which is
        // at least as new as the QR's.
        let returned = seen.returned_card.as_ref().expect("a card was returned");
        assert_eq!(paired["cardSerial"], returned.serial);
        assert!(returned.serial >= card.serial);
        assert_eq!(
            paired["card"],
            base64::engine::general_purpose::STANDARD.encode(returned.as_bytes())
        );
    }

    // The cadence request crossed the relay with exact bytes and headers.
    let request = &report["request"];
    assert_eq!(request["status"], 200);
    assert_eq!(request["body"], r#"{"v":1,"from":"first"}"#);
    assert_eq!(request["path"]["status"], "relayed");
    assert_eq!(request["path"]["direct"], serde_json::Value::Null);
    assert_eq!(request["path"]["relay"], relay_url.as_str());

    // link-ffi's checks, unchanged: each refusal is the shared rule's.
    let refused = &report["refused"];
    assert_eq!(
        refused["path"],
        "route: cadence request path is not canonical"
    );
    assert_eq!(
        refused["method"],
        "route: cadence request method must be POST or PUT"
    );
    assert_eq!(
        refused["socketPath"],
        "socket: Link WebSocket URL path must be /events"
    );
    assert_eq!(
        refused["socketPeer"],
        "socket: Link WebSocket URL host does not match the connected peer"
    );
    assert_eq!(
        refused["socketScheme"],
        "socket: Link WebSocket URLs must use ws"
    );
    assert_eq!(refused["unknownRoute"], "route: route is not installed");

    // The event socket: open, echo, bounded, closed once.
    let socket = &report["socket"];
    assert_eq!(socket["echo"], "echo: hello over link");
    assert_eq!(socket["path"], "relayed");
    assert_eq!(
        socket["oversize"],
        "socket: outbound WebSocket text exceeds 1048576 bytes"
    );
    assert_eq!(socket["closed"], "closed locally");
    assert_eq!(
        socket["events"],
        serde_json::json!(["open", "text", "closed"])
    );

    assert_eq!(report["refusedAfterStop"], "the engine is stopped");

    // A restarted page needs only the seed and the persisted record.
    assert_eq!(report["restarted"]["status"], 200);
    assert_eq!(report["restarted"]["body"], r#"{"v":1,"from":"restarted"}"#);
    assert_eq!(report["removedRefuses"], "route: route is not installed");

    let seen = seen.lock().unwrap();
    assert_eq!(seen.socket_texts, ["hello over link"]);
    assert_eq!(seen.cadence.len(), 2);
    for (path, authorization, _) in &seen.cadence {
        assert_eq!(path, "/cadence/v1/echo");
        assert_eq!(authorization, "Nostr YQ==");
    }
    assert_eq!(seen.deletes, ["/events/route", "/events/route/finalize"]);
    relay.shutdown();
}
