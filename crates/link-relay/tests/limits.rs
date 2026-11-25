//! Per-source session cap, spec 3.1 and docs/RENDEZVOUS.md section 3: one
//! source address cannot hold every slot.  Tag mode has no authentication,
//! so this cap is what stands between an unauthenticated address and the
//! whole relay.

use std::io::ErrorKind;
use std::time::Duration;

use futures_util::StreamExt;
use link_core::wire::Frame;
use link_relay::{RelayConfig, RelayHandle, TlsMaterial};
use tokio::{io::AsyncReadExt, net::TcpStream};
use tokio_tungstenite::tungstenite::Message;

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>;

async fn start(max_sessions_per_source: usize) -> RelayHandle {
    link_relay::start(RelayConfig {
        ws_bind: "127.0.0.1:0".parse().unwrap(),
        udp_bind: "127.0.0.1:0".parse().unwrap(),
        hosts: vec!["127.0.0.1".into()],
        tls: None,
        bytes_per_second: 0,
        max_sessions: 64,
        max_sessions_per_source,
        reflector_per_second: 100.0,
    })
    .await
    .expect("relay starts")
}

#[test]
fn relay_config_debug_redacts_the_tls_key() {
    let config = RelayConfig {
        tls: Some(TlsMaterial {
            cert_der: vec![1, 2, 3],
            key_der: vec![159, 211, 214],
        }),
        ..RelayConfig::default()
    };
    let debug = format!("{config:?}");
    assert!(debug.contains("[redacted]"));
    assert!(!debug.contains("159, 211, 214"));
}

async fn expect_tcp_closed(mut stream: TcpStream) {
    let result = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut [0; 1]))
        .await
        .expect("TCP connection closed");
    match result {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
            ) => {}
        other => panic!("expected a closed connection, got {other:?}"),
    }
}

async fn begin_upgrade(relay: &RelayHandle) -> TcpStream {
    let pending = TcpStream::connect(relay.ws_addr).await.unwrap();
    // The sole slot is reserved for the first accepted socket.
    let refused = TcpStream::connect(relay.ws_addr).await.unwrap();
    expect_tcp_closed(refused).await;
    pending
}

#[tokio::test]
async fn stalled_upgrades_release_the_slot_at_deadline_and_close_on_shutdown() {
    for tls in [
        None,
        Some(TlsMaterial::self_signed(&["localhost".into()]).unwrap()),
    ] {
        let relay = link_relay::start(RelayConfig {
            tls,
            max_sessions: 1,
            ..RelayConfig::default()
        })
        .await
        .unwrap();
        let pending = begin_upgrade(&relay).await;
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(11)).await;
        tokio::time::resume();
        expect_tcp_closed(pending).await;

        let pending = begin_upgrade(&relay).await;
        relay.shutdown();
        expect_tcp_closed(pending).await;
    }
}

async fn receive_challenge(relay: &RelayHandle) -> Ws {
    let (mut ws, _) = tokio_tungstenite::connect_async(relay.url("127.0.0.1"))
        .await
        .unwrap();
    let challenge = tokio::time::timeout(Duration::from_secs(2), ws.next())
        .await
        .expect("challenge arrived");
    assert!(matches!(challenge, Some(Ok(Message::Binary(bytes)))
        if matches!(Frame::decode(&bytes), Some(Frame::Challenge(_)))));
    ws
}

async fn expect_websocket_closed(mut ws: Ws) {
    let next = tokio::time::timeout(Duration::from_secs(2), ws.next())
        .await
        .expect("WebSocket connection closed");
    assert!(matches!(next, None | Some(Err(_) | Ok(Message::Close(_)))));
}

#[tokio::test]
async fn waiting_for_the_first_link_frame_times_out_and_cancels_on_shutdown() {
    let relay = link_relay::start(RelayConfig {
        max_sessions: 1,
        ..RelayConfig::default()
    })
    .await
    .unwrap();
    let ws = receive_challenge(&relay).await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(11)).await;
    tokio::time::resume();
    expect_websocket_closed(ws).await;

    let ws = receive_challenge(&relay).await;
    relay.shutdown();
    expect_websocket_closed(ws).await;
}

#[tokio::test]
async fn a_source_above_its_cap_is_refused_before_the_handshake() {
    let relay = start(2).await;
    let url = relay.url("127.0.0.1");
    let (a, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("first session from this address");
    let (b, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("second session from this address");
    let third = tokio_tungstenite::connect_async(&url).await;
    assert!(
        third.is_err(),
        "the third session from one address is refused before any frame"
    );
    drop(a);
    drop(b);
    // The slots come back once the sessions end.
    tokio::time::sleep(Duration::from_millis(300)).await;
    tokio_tungstenite::connect_async(&url)
        .await
        .expect("a slot is free again after the earlier sessions ended");
    relay.shutdown();
}

#[tokio::test]
async fn zero_means_no_per_source_cap() {
    let relay = start(0).await;
    let url = relay.url("127.0.0.1");
    let mut held = Vec::new();
    for n in 0..8 {
        held.push(
            tokio_tungstenite::connect_async(&url)
                .await
                .unwrap_or_else(|e| panic!("session {n} refused with no cap: {e}")),
        );
    }
    relay.shutdown();
}
