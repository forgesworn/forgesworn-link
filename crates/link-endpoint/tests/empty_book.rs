//! A peerless tag-mode node: opening with an empty rendezvous book must idle,
//! not die, and the first upsert must bring the relay session up and register.
//! This is the fresh-node journey: the shell learns the first pair from a
//! Nostr claim only after the endpoint is open.

mod harness;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use harness::{MIB, exchange_card, init_tracing, send_and_verify, spawn_sink, start_relay};
use link_endpoint::{
    Endpoint, EndpointConfig, RelaySpec, RelayStatus, RendezvousPeer, TagCase, TransportKey,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_empty_book_idles_then_registers_on_the_first_upsert() {
    init_tracing();
    let relay = start_relay().await;
    let url = relay.url("127.0.0.1");

    let key_a = TransportKey::generate();
    let key_b = TransportKey::generate();
    let node_a = key_a.node_id();
    let node_b = key_b.node_id();
    let material = RendezvousPeer {
        case: TagCase::Both,
        static_x: [0x31; 32],
        eph_x: [0x32; 32],
    };

    // A opens tag mode with NO pairs at all.
    let mut config_a = EndpointConfig::new(key_a);
    config_a.relays = vec![RelaySpec::plain(url.clone())];
    config_a.allow_direct = false;
    config_a.bind = "127.0.0.1:0".parse().unwrap();
    config_a.rendezvous = Some(HashMap::new());
    let a = Endpoint::open(config_a).await.expect("a opens peerless");

    // B knows A from the start.
    let mut config_b = EndpointConfig::new(key_b);
    config_b.relays = vec![RelaySpec::plain(url)];
    config_b.allow_direct = false;
    config_b.bind = "127.0.0.1:0".parse().unwrap();
    config_b.rendezvous = Some(HashMap::from([(node_a, material)]));
    let b = Endpoint::open(config_b).await.expect("b opens");

    // Well past the old failure path's first backoffs: the peerless node must
    // still be idling in Connecting, not Failed.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_ne!(
        a.paths().relay().home().status(),
        RelayStatus::Failed,
        "a peerless tag node must idle, not die"
    );

    // The shell learns the pair (the Nostr claim arrives) and upserts it.
    a.rendezvous_book()
        .expect("tag mode")
        .upsert(node_b, material);

    // The driver's next pass connects and registers; then a full transfer
    // proves the registration is live in both directions.
    let card_b = exchange_card(&b);
    let (session_a, session_b) = tokio::join!(a.connect(&card_b), b.accept());
    let session_a = session_a.expect("connect after the first upsert");
    let session_b = Arc::new(session_b.expect("accept"));

    let sink = spawn_sink(session_b.clone(), 1);
    send_and_verify(&session_a, 11, MIB)
        .await
        .expect("transfer");
    assert_eq!(sink.await.expect("sink"), 1);
    relay.shutdown();
}
