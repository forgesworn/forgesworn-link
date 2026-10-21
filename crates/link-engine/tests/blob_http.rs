//! Carrier proof with a controlled HTTP peer. Authentication values are opaque
//! fixtures here; real BUD authorisation and encrypted-file composition belong
//! to the Bothy/client journey, not this transport test.

use link_core::{TransportKey, card::Card};
use link_endpoint::{AcceptedSession, Endpoint, EndpointConfig, RelaySpec, Stream};
use link_engine::{Engine, EngineConfig, JsonRequest, Route};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::io::AsyncReadExt;
use zeroize::Zeroizing;

const HASH: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

async fn read_request(stream: &mut Stream) -> (String, Vec<u8>) {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        assert!(head.len() < 8_192);
        head.push(stream.recv.read_u8().await.unwrap());
    }
    let head = String::from_utf8(head).unwrap();
    let length = head
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim().parse::<usize>().unwrap())
        .unwrap_or(0);
    assert!(length <= 5);
    let mut bytes = vec![0; length];
    stream.recv.read_exact(&mut bytes).await.unwrap();
    (head, bytes)
}

async fn reply(stream: &mut Stream, status: &str, media: &str, body: &[u8]) {
    stream.send.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: {media}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await.unwrap();
    stream.send.write_all(body).await.unwrap();
    stream.send.finish().unwrap();
}

fn request(method: &str, auth: &str, body: &[u8]) -> JsonRequest {
    JsonRequest {
        route_id: "selected".into(),
        method: method.into(),
        path: if method == "PUT" {
            "/upload".into()
        } else {
            format!("/{HASH}")
        },
        authorization: auth.into(),
        body: body.to_vec(),
    }
}

async fn wait_for_file_slot(engine: &Engine) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(permit) = engine.reserve_file_request() {
                drop(permit);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("cancelled file driver releases its reservation");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn file_http_roundtrip_cancellation_and_timeout_use_one_pinned_session() {
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
    .unwrap();
    let seed = [0x43; 32];
    let secret = [0x51; 32];
    let mut config = EndpointConfig::new(TransportKey::generate());
    config.relays = vec![RelaySpec::plain(relay.url("127.0.0.1"))];
    config.allow_direct = false;
    config.bind = "127.0.0.1:0".parse().unwrap();
    config.paired_routes = Some(HashMap::from([(
        TransportKey::from_seed(seed).node_id(),
        Zeroizing::new(secret),
    )]));
    let server = Arc::new(Endpoint::open(config).await.unwrap());
    tokio::time::timeout(
        Duration::from_secs(15),
        server.paths().relay().home().wait_up(),
    )
    .await
    .unwrap()
    .unwrap();
    let card: Card = server.card(Duration::from_secs(600), Vec::new());
    let engine = Arc::new(
        Engine::start(EngineConfig {
            transport_seed: seed.to_vec(),
            relay_urls: Vec::new(),
            allow_direct: false,
            routes: vec![Route {
                route_id: "selected".into(),
                card: card.as_bytes().to_vec(),
                paired_route_secret: secret.to_vec(),
                card_serial: card.serial,
                card_verified_at: link_endpoint::rt::unix_now(),
            }],
        })
        .await
        .unwrap(),
    );
    let (started, mut body_started) = tokio::sync::mpsc::channel(2);
    let serving = tokio::spawn({
        let server = server.clone();
        async move {
            let AcceptedSession::Pinned(session) =
                tokio::time::timeout(Duration::from_secs(20), server.accept_any())
                    .await
                    .unwrap()
                    .unwrap()
            else {
                panic!("pinned session required")
            };
            for index in 0..8 {
                let mut stream =
                    tokio::time::timeout(Duration::from_secs(10), session.accept_stream())
                        .await
                        .unwrap()
                        .unwrap();
                let (head, body) = read_request(&mut stream).await;
                assert!(
                    head.to_ascii_lowercase()
                        .contains(&format!("host: {}\r\n", server.node_id().to_base32()))
                );
                match index {
                    0 => {
                        assert!(head.starts_with("PUT /upload HTTP/1.1\r\n"));
                        let lower = head.to_ascii_lowercase();
                        assert!(lower.contains(&format!("x-sha-256: {HASH}\r\n")));
                        assert!(lower.contains("content-length: 5\r\n"));
                        assert!(lower.contains("content-type: application/octet-stream\r\n"));
                        assert!(head.contains("Nostr YQ=="));
                        assert_eq!(body, b"hello");
                        reply(&mut stream, "201 Created", "application/json", b"{}").await;
                    }
                    2 => {
                        assert!(head.starts_with(&format!("DELETE /{HASH} HTTP/1.1\r\n")));
                        assert!(head.contains("Nostr YQ=="));
                        assert!(body.is_empty());
                        reply(
                            &mut stream,
                            "200 OK",
                            "application/json",
                            b"{\"blob_deleted\":false}",
                        )
                        .await;
                    }
                    3 | 4 | 7 => {
                        assert!(head.starts_with(&format!("GET /{HASH} HTTP/1.1\r\n")));
                        assert!(!head.to_ascii_lowercase().contains("authorization:"));
                        stream.send.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 5\r\nConnection: close\r\n\r\nh").await.unwrap();
                        started.send(index).await.unwrap();
                        let mut extra = [0];
                        let closed = tokio::time::timeout(
                            Duration::from_secs(5),
                            AsyncReadExt::read(&mut stream.recv, &mut extra),
                        )
                        .await
                        .unwrap_or_else(|error| {
                            panic!("cancel/timeout/stop closes HTTP stream {index}: {error}")
                        });
                        assert!(matches!(closed, Ok(0) | Err(_)));
                    }
                    _ => {
                        assert!(head.starts_with(&format!("GET /{HASH} HTTP/1.1\r\n")));
                        assert!(!head.to_ascii_lowercase().contains("authorization:"));
                        assert!(body.is_empty());
                        reply(
                            &mut stream,
                            "200 OK",
                            "application/octet-stream",
                            if index == 5 { b"jello" } else { b"hello" },
                        )
                        .await;
                    }
                }
            }
        }
    });

    assert_eq!(
        engine
            .request_json(
                request("PUT", "Nostr YQ==", b"hello"),
                Duration::from_secs(20)
            )
            .await
            .unwrap()
            .status,
        201
    );
    let downloaded = engine
        .request_json(request("GET", "", b""), Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(downloaded.body, b"hello");
    assert_eq!(downloaded.path.status, "relayed");
    assert_eq!(
        engine
            .request_json(request("DELETE", "Nostr YQ==", b""), Duration::from_secs(5))
            .await
            .unwrap()
            .status,
        200
    );
    let cancelled = tokio::spawn({
        let engine = engine.clone();
        async move {
            engine
                .request_json(request("GET", "", b""), Duration::from_secs(20))
                .await
        }
    });
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), body_started.recv())
            .await
            .unwrap(),
        Some(3)
    );
    assert!(engine.reserve_file_request().is_err());
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    wait_for_file_slot(&engine).await;
    let timed = tokio::spawn({
        let engine = engine.clone();
        async move {
            engine
                .request_json(request("GET", "", b""), Duration::from_secs(1))
                .await
        }
    });
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), body_started.recv())
            .await
            .unwrap(),
        Some(4)
    );
    assert!(timed.await.unwrap().is_err());
    wait_for_file_slot(&engine).await;
    assert!(
        engine
            .request_json(request("GET", "", b""), Duration::from_secs(5))
            .await
            .unwrap_err()
            .to_string()
            .contains("digest")
    );
    assert_eq!(
        engine
            .request_json(request("GET", "", b""), Duration::from_secs(5))
            .await
            .unwrap()
            .body,
        b"hello"
    );
    let stopped = tokio::spawn({
        let engine = engine.clone();
        async move {
            engine
                .request_json(request("GET", "", b""), Duration::from_secs(20))
                .await
        }
    });
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), body_started.recv())
            .await
            .unwrap(),
        Some(7)
    );
    engine.stop().await;
    assert!(
        tokio::time::timeout(Duration::from_secs(5), stopped)
            .await
            .expect("engine stop settles the file request")
            .unwrap()
            .is_err()
    );
    tokio::time::timeout(Duration::from_secs(5), serving)
        .await
        .unwrap()
        .unwrap();
    server.close().await;
}
