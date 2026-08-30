//! Per-source session cap, spec 3.1 and docs/RENDEZVOUS.md section 3: one
//! source address cannot hold every slot.  Tag mode has no authentication,
//! so this cap is what stands between an unauthenticated address and the
//! whole relay.

use std::time::Duration;

use link_relay::{RelayConfig, RelayHandle};

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
