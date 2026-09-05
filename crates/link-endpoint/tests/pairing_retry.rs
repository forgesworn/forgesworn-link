//! Reproduction for the Bothy finding of 2026-09-01: after one provisional
//! exchange on a case-0x03 route, a SECOND `connect_pairing` on the same
//! registration (the keeper's retry after a refused or unanswered claim) was
//! observed to stall at rendezvous roughly half the time.  Every attempt here
//! must come up inside a bound that is far below the rendezvous deadline.

mod harness;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use harness::{exchange_card, init_tracing, start_relay};
use link_endpoint::{
    AcceptedSession, Endpoint, EndpointConfig, PairingSession, RelaySpec, TransportKey,
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

/// One request/response on a fresh provisional connection, closed by the
/// dialler, with the listener observing the close.  Returns how long the
/// rendezvous plus handshake took.
async fn one_exchange(
    box_endpoint: &Arc<Endpoint>,
    keeper_endpoint: &Endpoint,
    box_card: &link_core::card::Card,
    registration: &link_endpoint::PairingRegistration,
    attempt: usize,
    wait_for_listener_close: bool,
) -> Duration {
    let accepting = tokio::spawn(accept_pairing(box_endpoint.clone()));
    let started = Instant::now();
    let keeper = tokio::time::timeout(
        Duration::from_secs(15),
        keeper_endpoint.connect_pairing(box_card, registration),
    )
    .await
    .unwrap_or_else(|_| panic!("attempt {attempt}: rendezvous did not come up in 15s"))
    .unwrap_or_else(|reason| panic!("attempt {attempt}: pairing connect failed: {reason}"));
    let came_up = started.elapsed();
    let box_session = Arc::new(accepting.await.expect("accept task"));

    let serving_session = box_session.clone();
    let serving = tokio::spawn(async move {
        let mut stream = serving_session
            .accept_stream()
            .await
            .expect("one claim stream");
        let mut request = [0u8; 5];
        stream.read_exact(&mut request).await.expect("claim bytes");
        assert_eq!(&request, b"claim");
        // A refused claim: the box answers, keeps its registration, and the
        // keeper will be back.
        stream.write_all(b"no").await.expect("response");
        stream.shutdown().await.expect("finish response");
    });
    let mut stream = keeper.open_stream().await.expect("one application stream");
    stream.write_all(b"claim").await.expect("request");
    stream.shutdown().await.expect("finish request");
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await.expect("response");
    assert_eq!(&response, b"no");
    serving.await.expect("server task");

    keeper.close().await;
    if wait_for_listener_close {
        tokio::time::timeout(Duration::from_secs(5), box_session.closed())
            .await
            .unwrap_or_else(|_| panic!("attempt {attempt}: listener never saw the close"));
    }
    came_up
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_retry_on_the_same_pairing_secret_comes_up_every_time() {
    init_tracing();
    let relay = start_relay().await;
    let url = relay.url("127.0.0.1");
    let box_endpoint = Arc::new(pairing_endpoint(&url).await);
    let keeper_endpoint = pairing_endpoint(&url).await;
    let box_card = exchange_card(&box_endpoint);
    let secret = [0x5b; 16];
    let box_registration = box_endpoint
        .register_pairing_secret(secret, Duration::from_secs(600))
        .expect("box pairing registration");
    let keeper_registration = keeper_endpoint
        .register_pairing_secret(secret, Duration::from_secs(600))
        .expect("keeper pairing registration");

    let mut timings = Vec::new();
    for attempt in 0..4 {
        let took = one_exchange(
            &box_endpoint,
            &keeper_endpoint,
            &box_card,
            &keeper_registration,
            attempt,
            true,
        )
        .await;
        timings.push(took);
    }
    eprintln!("rendezvous+handshake per attempt (listener close awaited): {timings:?}");
    drop(keeper_registration);
    drop(box_registration);
    relay.shutdown();
}

/// The same, but the keeper redials the instant its own close returns, before
/// the listener has necessarily observed it — the shape of a real retry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_immediate_retry_on_the_same_pairing_secret_comes_up() {
    init_tracing();
    let relay = start_relay().await;
    let url = relay.url("127.0.0.1");
    let box_endpoint = Arc::new(pairing_endpoint(&url).await);
    let keeper_endpoint = pairing_endpoint(&url).await;
    let box_card = exchange_card(&box_endpoint);
    let secret = [0x5c; 16];
    let box_registration = box_endpoint
        .register_pairing_secret(secret, Duration::from_secs(600))
        .expect("box pairing registration");
    let keeper_registration = keeper_endpoint
        .register_pairing_secret(secret, Duration::from_secs(600))
        .expect("keeper pairing registration");

    let mut timings = Vec::new();
    for attempt in 0..4 {
        let took = one_exchange(
            &box_endpoint,
            &keeper_endpoint,
            &box_card,
            &keeper_registration,
            attempt,
            false,
        )
        .await;
        timings.push(took);
    }
    eprintln!("rendezvous+handshake per attempt (immediate redial): {timings:?}");
    drop(keeper_registration);
    drop(box_registration);
    relay.shutdown();
}
