//! First contact over case 0x03, with neither side pre-booking the other's
//! node ID.  This is transport evidence only: the application-level raw-secret
//! check that authorises `PUT /bothy/claim` belongs to Bothy.

mod harness;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use harness::{exchange_card, init_tracing, start_relay};
use link_endpoint::{
    AcceptedSession, Endpoint, EndpointConfig, FailReason, PairingSession, RelaySpec, TransportKey,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn pairing_endpoint(relay: &str) -> Endpoint {
    let mut config = EndpointConfig::new(TransportKey::generate());
    config.relays = vec![RelaySpec::plain(relay)];
    config.allow_direct = false;
    config.bind = "127.0.0.1:0".parse().unwrap();
    config.rendezvous = Some(HashMap::new());
    Endpoint::open(config).await.expect("endpoint opens")
}

async fn accept_pairing(endpoint: Arc<Endpoint>) -> PairingSession {
    match endpoint.accept_any().await.expect("accept") {
        AcceptedSession::Pairing(session) => session,
        AcceptedSession::Pinned(_) => panic!("first contact must be explicitly provisional"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_nodes_meet_from_the_pairing_secret_alone() {
    init_tracing();
    let relay = start_relay().await;
    let url = relay.url("127.0.0.1");
    let box_endpoint = Arc::new(pairing_endpoint(&url).await);
    let keeper_endpoint = pairing_endpoint(&url).await;
    let box_card = exchange_card(&box_endpoint);
    let secret = [0x5a; 16];

    // Neither ordinary book knows the other node.  Normal connect therefore
    // fails visibly; only the bounded pairing API may use case 0x03.
    let box_registration = box_endpoint
        .register_pairing_secret(secret, Duration::from_secs(600))
        .expect("box pairing registration");
    let keeper_registration = keeper_endpoint
        .register_pairing_secret(secret, Duration::from_secs(600))
        .expect("keeper pairing registration");
    assert!(matches!(
        keeper_endpoint.connect(&box_card).await,
        Err(FailReason::Rendezvous)
    ));

    let accepting = tokio::spawn(accept_pairing(box_endpoint.clone()));
    let keeper = keeper_endpoint
        .connect_pairing(&box_card, &keeper_registration)
        .await
        .expect("pairing connect");
    let box_session = accepting.await.expect("accept task");

    assert!(box_session.path().direct.is_none());

    let serving = tokio::spawn(async move {
        let mut stream = box_session.accept_stream().await.expect("one claim stream");
        let mut request = [0u8; 5];
        stream.read_exact(&mut request).await.expect("claim bytes");
        assert_eq!(&request, b"claim");
        stream.write_all(b"ok").await.expect("response");
        stream.shutdown().await.expect("finish response");
    });
    let mut stream = keeper.open_stream().await.expect("one application stream");
    stream.write_all(b"claim").await.expect("request");
    stream.shutdown().await.expect("finish request");
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await.expect("response");
    assert_eq!(&response, b"ok");
    serving.await.expect("server task");

    assert!(
        keeper.open_stream().await.is_err(),
        "a provisional connection exposes no second application stream"
    );
    keeper.close().await;
    drop((box_registration, keeper_registration));
    relay.shutdown();
}

#[tokio::test]
async fn pairing_registration_requires_tag_mode_and_a_bounded_lifetime() {
    let mut config = EndpointConfig::new(TransportKey::generate());
    config.allow_direct = false;
    config.bind = "127.0.0.1:0".parse().unwrap();
    let endpoint = Endpoint::open(config).await.expect("endpoint opens");
    assert!(
        endpoint
            .register_pairing_secret([1; 16], Duration::from_secs(600))
            .is_err()
    );
    endpoint.close().await;

    let mut config = EndpointConfig::new(TransportKey::generate());
    config.allow_direct = false;
    config.bind = "127.0.0.1:0".parse().unwrap();
    config.rendezvous = Some(HashMap::new());
    let endpoint = Endpoint::open(config).await.expect("tag endpoint opens");
    assert!(
        endpoint
            .register_pairing_secret([1; 16], Duration::ZERO)
            .is_err()
    );
    assert!(
        endpoint
            .register_pairing_secret([1; 16], Duration::from_secs(601))
            .is_err()
    );
    endpoint.close().await;
}
