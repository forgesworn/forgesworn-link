//! Tag-mode relay sessions, spec section 9: registration, routed delivery,
//! self-exclusion, replacement on re-register, silent drops for unknown tags,
//! coexistence with identity sessions, and mode mixing as malformed.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use link_core::TransportKey;
use link_core::rendezvous::Tag;
use link_core::wire::{CLOSE_REASON_SUPERSEDED, Frame, sign_relay_auth};
use link_relay::{RelayConfig, RelayHandle};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>;

async fn start_relay() -> RelayHandle {
    link_relay::start(RelayConfig {
        ws_bind: "127.0.0.1:0".parse().unwrap(),
        udp_bind: "127.0.0.1:0".parse().unwrap(),
        hosts: vec!["127.0.0.1".into()],
        tls: None,
        bytes_per_second: 0,
        max_sessions: 16,
        max_sessions_per_source: 16,
        reflector_per_second: 100.0,
    })
    .await
    .expect("relay starts")
}

fn tag(byte: u8) -> Tag {
    Tag([byte; 16])
}

async fn next_frame(ws: &mut Ws) -> Option<Frame> {
    loop {
        let message = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .ok()??
            .ok()?;
        match message {
            Message::Binary(bytes) => return Frame::decode(&bytes),
            Message::Ping(payload) => {
                ws.send(Message::Pong(payload)).await.ok()?;
            }
            Message::Close(_) => return None,
            _ => continue,
        }
    }
}

/// True when nothing arrives within the window: delivery correctly withheld.
async fn silent(ws: &mut Ws, window: Duration) -> bool {
    tokio::time::timeout(window, ws.next()).await.is_err()
}

async fn connect(url: &str) -> Ws {
    let (ws, _) = tokio_tungstenite::connect_async(url)
        .await
        .expect("connect");
    ws
}

/// Challenge -> Register -> Welcome.  No identity and no signature on the wire.
async fn open_tags(url: &str, tags: Vec<Tag>) -> Ws {
    let mut ws = connect(url).await;
    match next_frame(&mut ws).await {
        Some(Frame::Challenge(_)) => {}
        other => panic!("expected a challenge, got {other:?}"),
    }
    ws.send(Message::Binary(Frame::Register { tags }.encode()))
        .await
        .expect("register");
    match next_frame(&mut ws).await {
        Some(Frame::Welcome(_)) => ws,
        other => panic!("expected a welcome, got {other:?}"),
    }
}

/// Challenge -> Auth -> Welcome, the deployed identity flow.
async fn open_identity(url: &str, key: &TransportKey) -> Ws {
    let mut ws = connect(url).await;
    let challenge = match next_frame(&mut ws).await {
        Some(Frame::Challenge(challenge)) => challenge,
        other => panic!("expected a challenge, got {other:?}"),
    };
    let signature = sign_relay_auth(key, "127.0.0.1", &challenge);
    ws.send(Message::Binary(
        Frame::Auth {
            node_id: key.node_id(),
            signature,
        }
        .encode(),
    ))
    .await
    .expect("auth");
    match next_frame(&mut ws).await {
        Some(Frame::Welcome(_)) => ws,
        other => panic!("expected a welcome, got {other:?}"),
    }
}

#[tokio::test]
async fn tags_route_between_registered_sessions_and_exclude_the_sender() {
    let relay = start_relay().await;
    let url = relay.url("127.0.0.1");
    let shared = tag(7);
    let mut a = open_tags(&url, vec![shared, tag(1)]).await;
    let mut b = open_tags(&url, vec![shared]).await;

    a.send(Message::Binary(
        Frame::SendTag {
            tag: shared,
            datagram: vec![1, 2, 3],
        }
        .encode(),
    ))
    .await
    .unwrap();

    match next_frame(&mut b).await {
        Some(Frame::RecvTag { tag: t, datagram }) => {
            assert_eq!(t, shared);
            assert_eq!(datagram, vec![1, 2, 3]);
        }
        other => panic!("expected a tag delivery, got {other:?}"),
    }
    // The sender never receives its own datagram back.
    assert!(silent(&mut a, Duration::from_millis(300)).await);

    // A tag nobody registered is dropped silently: no delivery, no close.
    a.send(Message::Binary(
        Frame::SendTag {
            tag: tag(99),
            datagram: vec![9],
        }
        .encode(),
    ))
    .await
    .unwrap();
    assert!(silent(&mut b, Duration::from_millis(300)).await);
    relay.shutdown();
}

#[tokio::test]
async fn a_later_register_replaces_the_tag_set() {
    let relay = start_relay().await;
    let url = relay.url("127.0.0.1");
    let first = tag(10);
    let second = tag(20);
    let mut a = open_tags(&url, vec![first]).await;
    let mut b = open_tags(&url, vec![first]).await;

    // b rotates to the second tag; the first stops reaching it.
    b.send(Message::Binary(
        Frame::Register { tags: vec![second] }.encode(),
    ))
    .await
    .unwrap();
    // Give the relay a beat to process the re-register.
    tokio::time::sleep(Duration::from_millis(100)).await;

    a.send(Message::Binary(
        Frame::SendTag {
            tag: first,
            datagram: vec![1],
        }
        .encode(),
    ))
    .await
    .unwrap();
    assert!(silent(&mut b, Duration::from_millis(300)).await);

    // The sender need not be registered with a tag to send on it.
    a.send(Message::Binary(
        Frame::SendTag {
            tag: second,
            datagram: vec![2],
        }
        .encode(),
    ))
    .await
    .unwrap();
    match next_frame(&mut b).await {
        Some(Frame::RecvTag { tag: t, datagram }) => {
            assert_eq!(t, second);
            assert_eq!(datagram, vec![2]);
        }
        other => panic!("expected a tag delivery, got {other:?}"),
    }
    relay.shutdown();
}

#[tokio::test]
async fn identity_sessions_still_work_beside_tag_sessions() {
    let relay = start_relay().await;
    let url = relay.url("127.0.0.1");
    let key_a = TransportKey::generate();
    let key_b = TransportKey::generate();
    let mut a = open_identity(&url, &key_a).await;
    let mut b = open_identity(&url, &key_b).await;
    let mut t = open_tags(&url, vec![tag(5)]).await;

    a.send(Message::Binary(
        Frame::Send {
            destination: key_b.node_id(),
            datagram: vec![4, 5, 6],
        }
        .encode(),
    ))
    .await
    .unwrap();
    match next_frame(&mut b).await {
        Some(Frame::Recv { source, datagram }) => {
            assert_eq!(source, key_a.node_id());
            assert_eq!(datagram, vec![4, 5, 6]);
        }
        other => panic!("expected an identity delivery, got {other:?}"),
    }
    // The tag session saw none of it.
    assert!(silent(&mut t, Duration::from_millis(300)).await);
    relay.shutdown();
}

#[tokio::test]
async fn mode_mixing_is_malformed() {
    let relay = start_relay().await;
    let url = relay.url("127.0.0.1");

    // A tag session sending an identity frame is closed as malformed.
    let mut t = open_tags(&url, vec![tag(3)]).await;
    t.send(Message::Binary(
        Frame::Send {
            destination: TransportKey::generate().node_id(),
            datagram: vec![1],
        }
        .encode(),
    ))
    .await
    .unwrap();
    match next_frame(&mut t).await {
        Some(Frame::Close(reason)) => assert_eq!(reason, 1),
        None => {}
        other => panic!("expected a malformed close, got {other:?}"),
    }

    // An identity session sending a tag frame is closed as malformed.
    let key = TransportKey::generate();
    let mut ident = open_identity(&url, &key).await;
    ident
        .send(Message::Binary(
            Frame::SendTag {
                tag: tag(3),
                datagram: vec![1],
            }
            .encode(),
        ))
        .await
        .unwrap();
    match next_frame(&mut ident).await {
        Some(Frame::Close(reason)) => assert_eq!(reason, 1),
        None => {}
        other => panic!("expected a malformed close, got {other:?}"),
    }
    relay.shutdown();
}

/// A second identity session for the same node ID wins, and the first is told
/// with `Close(2)` so it can reconnect rather than sit on a dead route.
#[tokio::test]
async fn a_second_identity_session_supersedes_the_first_with_a_close() {
    let relay = start_relay().await;
    let url = relay.url("127.0.0.1");
    let key = TransportKey::generate();
    let mut first = open_identity(&url, &key).await;
    let _second = open_identity(&url, &key).await;
    match next_frame(&mut first).await {
        Some(Frame::Close(reason)) => assert_eq!(reason, CLOSE_REASON_SUPERSEDED),
        other => panic!("expected Close(2) on the superseded session, got {other:?}"),
    }
    relay.shutdown();
}

/// A tag has two ends.  A third registrant evicts the oldest with `Close(2)`,
/// and delivery continues between the two that remain.
#[tokio::test]
async fn a_third_tag_registrant_evicts_the_oldest() {
    let relay = start_relay().await;
    let url = relay.url("127.0.0.1");
    let t = tag(0x42);
    let mut a = open_tags(&url, vec![t]).await;
    let mut b = open_tags(&url, vec![t]).await;
    let mut c = open_tags(&url, vec![t]).await;
    match next_frame(&mut a).await {
        Some(Frame::Close(reason)) => assert_eq!(reason, CLOSE_REASON_SUPERSEDED),
        other => panic!("expected the oldest registrant to be evicted, got {other:?}"),
    }
    c.send(Message::Binary(
        Frame::SendTag {
            tag: t,
            datagram: vec![1, 2, 3],
        }
        .encode(),
    ))
    .await
    .unwrap();
    match next_frame(&mut b).await {
        Some(Frame::RecvTag { tag, datagram }) => {
            assert_eq!(tag, t);
            assert_eq!(datagram, vec![1, 2, 3]);
        }
        other => panic!("b should still receive on the tag, got {other:?}"),
    }
    relay.shutdown();
}
