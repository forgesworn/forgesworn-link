//! Tag-mode loopback, spec section 9: a full QUIC transfer over a relay that
//! never learns a node ID, a Nostr key, or a signature.

mod harness;

use std::collections::HashMap;
use std::sync::Arc;

use harness::{MIB, exchange_card, init_tracing, send_and_verify, spawn_sink, start_relay};
use link_endpoint::{
    Endpoint, EndpointConfig, PathStatus, RelaySpec, RendezvousPeer, TagCase, TransportKey,
};

#[tokio::test]
async fn a_transfer_flows_over_tag_mode_rendezvous() {
    init_tracing();
    let relay = start_relay().await;
    let url = relay.url("127.0.0.1");

    let key_a = TransportKey::generate();
    let key_b = TransportKey::generate();
    let node_a = key_a.node_id();
    let node_b = key_b.node_id();
    // Fabricated pair material: in production the shell derives these
    // x-coordinates by ECDH from the pair's Nostr keys and cards.  The
    // transport only needs both ends to hold the same bytes.
    let material = RendezvousPeer {
        case: TagCase::Both,
        static_x: [0x11; 32],
        eph_x: [0x22; 32],
    };

    let mut config_a = EndpointConfig::new(key_a);
    config_a.relays = vec![RelaySpec::plain(url.clone())];
    config_a.allow_direct = false;
    config_a.bind = "127.0.0.1:0".parse().unwrap();
    config_a.rendezvous = Some(HashMap::from([(node_b, material)]));

    let mut config_b = EndpointConfig::new(key_b);
    config_b.relays = vec![RelaySpec::plain(url)];
    config_b.allow_direct = false;
    config_b.bind = "127.0.0.1:0".parse().unwrap();
    config_b.rendezvous = Some(HashMap::from([(node_a, material)]));

    let a = Endpoint::open(config_a).await.expect("a opens");
    let b = Endpoint::open(config_b).await.expect("b opens");

    let card_b = exchange_card(&b);
    let (session_a, session_b) = tokio::join!(a.connect(&card_b), b.accept());
    let session_a = session_a.expect("connect over tags");
    let session_b = Arc::new(session_b.expect("accept over tags"));

    let sink = spawn_sink(session_b.clone(), 1);
    send_and_verify(&session_a, 7, MIB).await.expect("transfer");
    assert_eq!(sink.await.expect("sink"), 1);

    // Direct paths are declined, so the whole transfer rode the tag-routed
    // relay; the report must say so.
    assert_eq!(session_a.path().status, PathStatus::Relayed);
    relay.shutdown();
}
