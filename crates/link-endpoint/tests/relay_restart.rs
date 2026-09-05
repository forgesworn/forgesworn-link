//! A relay outage may fail an individual transfer, but must not permanently
//! disable a long-lived endpoint. Reproduce the Android observation in #37
//! with the real relay and production reconnect deadline, without a device.

mod harness;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use harness::{MIB, exchange_card, init_tracing, send_and_verify, spawn_sink, start_relay};
use link_endpoint::{
    Endpoint, EndpointConfig, PathStatus, RelaySpec, RelayStatus, RendezvousPeer, TagCase,
    TransportKey,
};
use link_relay::RelayConfig;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

async fn wait_for_status(endpoint: &Endpoint, expected: impl Fn(&RelayStatus) -> bool) {
    let mut status = endpoint.paths().relay().home().watch();
    tokio::time::timeout(Duration::from_secs(100), async {
        loop {
            if expected(&status.borrow_and_update()) {
                return;
            }
            status
                .changed()
                .await
                .expect("relay driver must remain alive");
        }
    })
    .await
    .expect("relay status within the production retry bounds");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tag_endpoint_recovers_after_the_relay_outage_failed_its_session() {
    init_tracing();
    let relay = start_relay().await;
    let address = relay.ws_addr;
    let url = relay.url("127.0.0.1");
    let keys = [TransportKey::generate(), TransportKey::generate()];
    let material = RendezvousPeer {
        case: TagCase::Both,
        static_x: [0x61; 32],
        eph_x: [0x62; 32],
    };
    let mut endpoints = Vec::new();
    for i in 0..2 {
        let mut config = EndpointConfig::new(keys[i].clone());
        config.relays = vec![RelaySpec::plain(url.clone())];
        config.bind = "127.0.0.1:0".parse().unwrap();
        config.allow_direct = false;
        config.rendezvous = Some(HashMap::from([(keys[1 - i].node_id(), material)]));
        endpoints.push(Endpoint::open(config).await.expect("endpoint opens"));
    }
    let a = &endpoints[0];
    let b = &endpoints[1];
    let card = exchange_card(b);
    let (old_a, old_b) = tokio::join!(a.connect(&card), b.accept());
    let old_a = old_a.expect("initial connect");
    let old_b = Arc::new(old_b.expect("initial accept"));
    let sink = spawn_sink(old_b.clone(), 1);
    send_and_verify(&old_a, 31, MIB)
        .await
        .expect("initial transfer");
    assert_eq!(sink.await.unwrap(), 1);

    relay.shutdown();
    // Let the *real* sixty-second retry budget expire. A short flap never
    // exercised the permanent driver exit that stranded the Android service.
    tokio::join!(
        wait_for_status(a, |s| *s == RelayStatus::Failed),
        wait_for_status(b, |s| *s == RelayStatus::Failed),
    );
    assert!(matches!(old_a.path().status, PathStatus::Failed(_)));
    assert!(matches!(old_b.path().status, PathStatus::Failed(_)));

    let restarted = link_relay::start(RelayConfig {
        ws_bind: address,
        udp_bind: "127.0.0.1:0".parse().unwrap(),
        hosts: vec!["127.0.0.1".into()],
        tls: None,
        bytes_per_second: 0,
        max_sessions: 64,
        max_sessions_per_source: 0,
        reflector_per_second: 100.0,
    })
    .await
    .expect("relay restarts on the same address");
    tokio::join!(
        wait_for_status(a, |s| matches!(s, RelayStatus::Up(_))),
        wait_for_status(b, |s| matches!(s, RelayStatus::Up(_))),
    );
    // Reconnect the same endpoint objects, without restarting either node,
    // replacing its key or re-inserting its rendezvous material.
    let (fresh_a, fresh_b) = tokio::time::timeout(Duration::from_secs(15), async {
        tokio::join!(a.connect(&card), b.accept())
    })
    .await
    .expect("a fresh user operation connects after relay recovery");
    let fresh_a = fresh_a.expect("new connect");
    let fresh_b = Arc::new(fresh_b.expect("new accept"));
    let sink = spawn_sink(fresh_b, 1);
    send_and_verify(&fresh_a, 32, MIB)
        .await
        .expect("recovered transfer");
    assert_eq!(sink.await.unwrap(), 1);
    assert_eq!(fresh_a.path().status, PathStatus::Relayed);
    // The endpoint may reconnect its transport; the failed operation is never
    // resurrected or replayed on the application's behalf (spec 4.3).
    assert!(matches!(old_a.path().status, PathStatus::Failed(_)));
    assert!(matches!(old_b.path().status, PathStatus::Failed(_)));
    a.close().await;
    b.close().await;
    restarted.shutdown();
}

#[tokio::test]
async fn a_stalled_websocket_handshake_does_not_prevent_relay_failover() {
    init_tracing();
    let stalled = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stalled_url = format!("ws://{}/link", stalled.local_addr().unwrap());
    let relay = start_relay().await;
    let url = relay.url("127.0.0.1");
    let (inbound, _received) = tokio::sync::mpsc::channel(16);
    let pool = link_endpoint::relay_client::spawn(
        TransportKey::generate(),
        vec![RelaySpec::plain(stalled_url), RelaySpec::plain(url.clone())],
        inbound,
        None,
    );
    // Accept TCP and retain the socket, but never answer the HTTP upgrade.
    let (_socket, _) = stalled.accept().await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(15), pool.home().wait_up())
            .await
            .expect("whole handshake is bounded"),
        Some(url),
    );
    pool.close();
    relay.shutdown();
}

#[tokio::test]
async fn closing_the_pool_cancels_a_handshake_and_refuses_new_drivers() {
    init_tracing();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (inbound, _received) = tokio::sync::mpsc::channel(16);
    let pool = link_endpoint::relay_client::spawn(
        TransportKey::generate(),
        vec![RelaySpec::plain(format!(
            "ws://{}/link",
            listener.local_addr().unwrap()
        ))],
        inbound,
        None,
    );
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut status = pool.home().watch();
    pool.close();
    tokio::time::timeout(Duration::from_secs(2), async {
        while *status.borrow_and_update() != RelayStatus::Failed {
            status.changed().await.unwrap();
        }
        let mut request = Vec::new();
        socket
            .read_to_end(&mut request)
            .await
            .expect("client closes TCP");
    })
    .await
    .expect("shutdown does not wait for the handshake deadline");
    assert_eq!(
        pool.driver_for(&[RelaySpec::plain("ws://127.0.0.1:9/other")])
            .id(),
        pool.home().id(),
        "a closed pool must not spawn a driver for a peer's relay hint",
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .is_err()
    );
}
