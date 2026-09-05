//! Explicit operator acceptance: synthetic traffic through the deployed relay.
//! Normal tests never contact this service. No hardware or keeper keys are used.

mod harness;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use harness::{MIB, exchange_card, init_tracing, send_and_verify, spawn_sink};
use link_endpoint::{
    Endpoint, EndpointConfig, PathStatus, RelaySpec, RendezvousPeer, TagCase, TransportKey,
};

#[tokio::test]
#[ignore = "requires explicit LINK_PUBLIC_RELAY=wss://link1.forgesworn.dev/link"]
async fn public_founders_relay_delivers_a_verified_mebibyte_over_tags() {
    let url = std::env::var("LINK_PUBLIC_RELAY").expect("explicit public relay consent required");
    assert_eq!(url, "wss://link1.forgesworn.dev/link");
    init_tracing();
    tokio::time::timeout(Duration::from_secs(120), async {
        let key_a = TransportKey::generate();
        let key_b = TransportKey::generate();
        let node_a = key_a.node_id();
        let node_b = key_b.node_id();
        // Synthetic shared material, unique per run to avoid colliding tags.
        // These public transport IDs are not keeper or signer keys.
        let material = RendezvousPeer {
            case: TagCase::Both,
            static_x: node_a.0,
            eph_x: node_b.0,
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

        let a = Endpoint::open(config_a)
            .await
            .expect("a opens with trusted TLS");
        let b = Endpoint::open(config_b)
            .await
            .expect("b opens with trusted TLS");
        let card_b = exchange_card(&b);
        let (session_a, session_b) = tokio::join!(a.connect(&card_b), b.accept());
        let session_a = session_a.expect("connect over public tags");
        let session_b = Arc::new(session_b.expect("accept over public tags"));
        let sink = spawn_sink(session_b.clone(), 1);
        send_and_verify(&session_a, 7, MIB)
            .await
            .expect("verified transfer");
        assert_eq!(sink.await.expect("sink"), 1);
        assert_eq!(session_a.path().status, PathStatus::Relayed);
        assert_eq!(session_b.path().status, PathStatus::Relayed);
    })
    .await
    .expect("public transfer must finish within two minutes");
}
