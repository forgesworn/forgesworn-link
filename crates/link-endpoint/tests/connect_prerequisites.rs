//! A connect either has a rendezvous route and reaches QUIC, or fails within
//! a caller-visible bound.  Missing shell state must never become a silent
//! wait in `RelayDriver::wait_up`.

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use link_core::card::{Card, Hint};
use link_core::path::FailReason;
use link_endpoint::{Endpoint, EndpointConfig, RelaySpec, RendezvousPeer, TagCase, TransportKey};
use tokio::net::{TcpListener, UdpSocket};

fn card_for(key: &TransportKey, hints: Vec<Hint>) -> Card {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    Card::sign(key, now, now + 300, 1, hints)
}

#[tokio::test]
async fn defaults_are_relay_only_and_require_a_paired_peer() {
    let endpoint = Endpoint::open(EndpointConfig::new(TransportKey::generate()))
        .await
        .expect("endpoint opens");
    let peer = TransportKey::generate();

    assert!(
        endpoint.rendezvous_book().is_some(),
        "tag mode is the default"
    );
    assert!(!endpoint.allow_direct());
    assert!(endpoint.paths().is_relay_only());
    let started = Instant::now();
    assert!(matches!(
        endpoint.connect(&card_for(&peer, Vec::new())).await,
        Err(FailReason::Rendezvous)
    ));
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "a missing local route must fail immediately"
    );
    endpoint.close().await;
}

#[tokio::test]
async fn relay_only_ignores_a_configured_udp_reflector_and_omits_udp_hints() {
    let reflector = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let reflector_addr = reflector.local_addr().unwrap();
    let mut config = EndpointConfig::new(TransportKey::generate());
    config.allow_direct = false;
    config.reflector = Some(reflector_addr);
    let endpoint = Endpoint::open(config).await.expect("endpoint opens");

    assert!(endpoint.paths().is_relay_only());
    assert!(endpoint.paths().local_candidates().is_empty());
    assert!(
        endpoint
            .card(Duration::from_secs(60), vec![Hint::udp(reflector_addr)])
            .udp_candidates()
            .is_empty()
    );
    endpoint.paths().requery_reflector();
    let mut packet = [0u8; 64];
    assert!(
        tokio::time::timeout(Duration::from_millis(100), reflector.recv(&mut packet))
            .await
            .is_err()
    );
    endpoint.close().await;
}

#[tokio::test]
async fn ordinary_and_pairing_dials_refuse_an_unconfigured_relay() {
    let forbidden = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/link", forbidden.local_addr().unwrap());
    let peer = TransportKey::generate();
    let card = card_for(&peer, vec![Hint::relay(&url)]);
    let mut config = EndpointConfig::new(TransportKey::generate());
    config.rendezvous = Some(HashMap::from([(
        peer.node_id(),
        RendezvousPeer {
            case: TagCase::Both,
            static_x: [1; 32],
            eph_x: [2; 32],
        },
    )]));
    config.rendezvous_timeout = Duration::from_millis(200);
    let endpoint = Endpoint::open(config).await.expect("endpoint opens");
    let registration = endpoint
        .register_pairing_secret([3; 16], Duration::from_secs(60))
        .unwrap();

    assert!(matches!(
        endpoint.connect(&card).await,
        Err(FailReason::Rendezvous)
    ));
    assert!(matches!(
        endpoint.connect_pairing(&card, &registration).await,
        Err(FailReason::Rendezvous)
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), forbidden.accept())
            .await
            .is_err()
    );
    endpoint.close().await;
}

#[tokio::test]
async fn a_relay_welcome_wait_has_a_deadline() {
    let stalled = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = EndpointConfig::legacy_identity(TransportKey::generate());
    config.relays = vec![RelaySpec::plain(format!(
        "ws://{}/link",
        stalled.local_addr().unwrap()
    ))];
    config.rendezvous_timeout = Duration::from_millis(50);
    let endpoint = Endpoint::open(config).await.expect("endpoint opens");
    let peer = TransportKey::generate();

    let started = Instant::now();
    assert!(matches!(
        endpoint.connect(&card_for(&peer, Vec::new())).await,
        Err(FailReason::Timeout)
    ));
    assert!(started.elapsed() < Duration::from_secs(1));
    endpoint.close().await;
}
