//! Relay logging with a dedicated test process and subscriber.

use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use link_core::rendezvous::Tag;
use link_core::wire::Frame;
use link_relay::RelayConfig;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>;

async fn next_frame(ws: &mut Ws) -> Option<Frame> {
    let message = tokio::time::timeout(Duration::from_secs(2), ws.next())
        .await
        .ok()??
        .ok()?;
    match message {
        Message::Binary(bytes) => Frame::decode(&bytes),
        _ => None,
    }
}

async fn open_tags(url: &str, tag: Tag) -> Ws {
    let (mut ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();
    assert!(matches!(
        next_frame(&mut ws).await,
        Some(Frame::Challenge(_))
    ));
    ws.send(Message::Binary(
        Frame::Register { tags: vec![tag] }.encode(),
    ))
    .await
    .unwrap();
    assert!(matches!(next_frame(&mut ws).await, Some(Frame::Welcome(_))));
    ws
}

#[derive(Clone, Default)]
struct LogCapture(Arc<Mutex<Vec<u8>>>);

impl Write for LogCapture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn relay_reports_activity_in_aggregate_while_connections_are_live() {
    let log = LogCapture::default();
    let writer = log.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    let read_log = || String::from_utf8(log.0.lock().unwrap().clone()).unwrap();

    let relay = link_relay::start(RelayConfig {
        max_sessions_per_source: 2,
        ..RelayConfig::default()
    })
    .await
    .unwrap();
    let url = relay.url("127.0.0.1");
    let shared = Tag([7; 16]);
    let mut a = open_tags(&url, shared).await;
    let mut b = open_tags(&url, shared).await;
    assert!(tokio_tungstenite::connect_async(&url).await.is_err());

    let payload = b"fixture".to_vec();
    for tag in [shared, Tag([8; 16])] {
        a.send(Message::Binary(
            Frame::SendTag {
                tag,
                datagram: payload.clone(),
            }
            .encode(),
        ))
        .await
        .unwrap();
    }
    assert_eq!(
        next_frame(&mut b).await,
        Some(Frame::RecvTag {
            tag: shared,
            datagram: payload,
        })
    );
    a.send(Message::Binary(Frame::Ping([0; 8]).encode()))
        .await
        .unwrap();
    assert_eq!(next_frame(&mut a).await, Some(Frame::Pong([0; 8])));
    assert_eq!(read_log().lines().count(), 1, "only the startup event");

    tokio::time::pause();
    // Flush the live sessions' counters before the relay's reporting tick.
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert_eq!(read_log().lines().count(), 1, "no early activity event");
    // Wake one second after the deadline so Tokio polls the report timer first.
    tokio::time::sleep(Duration::from_secs(291)).await;

    let output = read_log();
    let mut lines = output.lines();
    assert!(lines.next().unwrap().contains("relay listening"));
    let report = lines.next().expect("five-minute report");
    assert!(lines.next().is_none());
    for expected in [
        "relay activity",
        "active=2",
        "accepted=2",
        "refused_source=1",
        "frames_in=3",
        "frames_out=1",
        "bytes_in=14",
        "dropped=1",
    ] {
        assert!(report.contains(expected), "missing field {expected}");
    }
    for field in ["token=", "source=127.", "tag=", "node_id=", "fixture"] {
        assert!(!output.contains(field), "unexpected log field {field}");
    }
    tokio::time::sleep(Duration::from_secs(300)).await;
    let output = read_log();
    assert_eq!(output.lines().count(), 3);
    let next_report = output.lines().last().unwrap();
    for expected in [
        "active=2",
        "accepted=0",
        "frames_in=0",
        "frames_out=0",
        "bytes_in=0",
        "dropped=0",
    ] {
        assert!(next_report.contains(expected), "missing field {expected}");
    }
    relay.shutdown();
}
