//! A connect either has a rendezvous route and reaches QUIC, or fails within
//! a caller-visible bound.  Missing shell state must never become a silent
//! wait in `RelayDriver::wait_up`.

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use link_core::card::Card;
use link_core::path::FailReason;
use link_endpoint::{Endpoint, EndpointConfig, RelaySpec, TransportKey};

fn card_for(key: &TransportKey) -> Card {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    Card::sign(key, now, now + 300, 1, Vec::new())
}

#[tokio::test]
async fn tag_mode_without_the_peer_fails_before_touching_the_relay() {
    let mut config = EndpointConfig::new(TransportKey::generate());
    config.relays = vec![RelaySpec::plain("ws://192.0.2.1:9/link")];
    config.allow_direct = false;
    config.bind = "127.0.0.1:0".parse().unwrap();
    config.rendezvous = Some(HashMap::new());
    config.rendezvous_timeout = Duration::from_secs(10);
    let endpoint = Endpoint::open(config).await.expect("endpoint opens");
    let peer = TransportKey::generate();

    let started = Instant::now();
    assert!(matches!(
        endpoint.connect(&card_for(&peer)).await,
        Err(FailReason::Rendezvous)
    ));
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "a missing local route must fail immediately"
    );
    endpoint.close().await;
}

#[tokio::test]
async fn a_relay_welcome_wait_has_a_deadline() {
    let mut config = EndpointConfig::new(TransportKey::generate());
    config.relays = vec![RelaySpec::plain("ws://192.0.2.1:9/link")];
    config.allow_direct = false;
    config.bind = "127.0.0.1:0".parse().unwrap();
    config.rendezvous_timeout = Duration::from_millis(50);
    let endpoint = Endpoint::open(config).await.expect("endpoint opens");
    let peer = TransportKey::generate();

    let started = Instant::now();
    assert!(matches!(
        endpoint.connect(&card_for(&peer)).await,
        Err(FailReason::Timeout)
    ));
    assert!(started.elapsed() < Duration::from_secs(1));
    endpoint.close().await;
}
