//! Native cold starts with an unresolvable primary and a pinned IP relay.

mod harness;

use std::collections::HashMap;
use std::time::Duration;

use harness::{MIB, exchange_card, init_tracing, send_and_verify, sink_one_stream};
use link_endpoint::{
    AcceptedSession, Endpoint, EndpointConfig, PathReport, PathStatus, RelaySpec, TransportKey,
};
use link_relay::{RelayConfig, TlsMaterial};
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(25);

fn assert_relay(path: PathReport, backup_url: &str) {
    assert_eq!(path.status, PathStatus::Relayed);
    assert_eq!(path.relay.as_deref(), Some(backup_url));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unresolved_primary_falls_back_to_pinned_ip_for_pairing_and_reconnect() {
    init_tracing();
    let ip = "127.0.0.1";
    let relay = link_relay::start(RelayConfig {
        tls: Some(TlsMaterial::self_signed(&[ip.into()]).unwrap()),
        ..RelayConfig::default()
    })
    .await
    .unwrap();
    let backup_url = relay.url(ip);
    let relays = vec![
        RelaySpec::plain("wss://primary.link-dns-test.invalid/link"),
        RelaySpec::pinned(&backup_url, relay.tls_fingerprint.as_deref().unwrap()),
    ];
    let [mut sender_config, mut receiver_config] = [(), ()].map(|()| EndpointConfig {
        relays: relays.clone(),
        ..EndpointConfig::new(TransportKey::generate())
    });
    let sender = Endpoint::open(sender_config.clone()).await.unwrap();
    let receiver = Endpoint::open(receiver_config.clone()).await.unwrap();
    let sender_card = exchange_card(&sender);
    let receiver_card = exchange_card(&receiver);
    let invite = [0x51; 16];
    let sender_invite = sender
        .register_pairing_secret(invite, Duration::from_secs(60))
        .unwrap();
    let receiver_invite = receiver
        .register_pairing_secret(invite, Duration::from_secs(60))
        .unwrap();

    let (dialled, accepted) = timeout(WAIT, async {
        tokio::join!(
            sender.connect_pairing(&receiver_card, &sender_invite),
            receiver.accept_any()
        )
    })
    .await
    .expect("pairing completes during hostname failure");
    let dialled = dialled.expect("dialler paired through the backup relay");
    let AcceptedSession::Pairing(accepted) = accepted.unwrap() else {
        panic!("expected a provisional pairing");
    };
    assert_eq!(dialled.peer(), receiver_card.node_id);
    assert_eq!(accepted.peer(), sender_card.node_id);
    assert_relay(dialled.path(), &backup_url);
    assert_relay(accepted.path(), &backup_url);
    let sender_secret = dialled.paired_route_secret().unwrap();
    let receiver_secret = accepted.paired_route_secret().unwrap();
    assert!(*sender_secret == *receiver_secret);

    drop(sender_invite);
    drop(receiver_invite);
    tokio::join!(sender.close(), receiver.close());

    // Restore the same keys, signed cards and route secrets on fresh endpoints.
    sender_config.paired_routes = Some(HashMap::from([(receiver_card.node_id, sender_secret)]));
    receiver_config.paired_routes = Some(HashMap::from([(sender_card.node_id, receiver_secret)]));
    let sender = Endpoint::open(sender_config).await.unwrap();
    let receiver = Endpoint::open(receiver_config).await.unwrap();
    let (dialled, accepted) = timeout(WAIT, async {
        tokio::join!(sender.connect(&receiver_card), receiver.accept())
    })
    .await
    .expect("saved pairing reconnects during hostname failure");
    let dialled = dialled.unwrap();
    let accepted = accepted.unwrap();
    assert_relay(dialled.path(), &backup_url);
    assert_relay(accepted.path(), &backup_url);
    let (sent, received) = timeout(WAIT, async {
        tokio::join!(
            send_and_verify(&dialled, 0x5eed, MIB),
            sink_one_stream(&accepted, None)
        )
    })
    .await
    .expect("relayed transfer finishes");
    sent.expect("the peer's SHA-256 matches the payload");
    assert_eq!(received.unwrap(), MIB);

    tokio::join!(sender.close(), receiver.close());
    relay.shutdown();
}
