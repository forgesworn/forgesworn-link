//! Loopback integration.  This proves the contract, not the network: nothing
//! here traverses a NAT, so none of it says anything about carrier paths.
//!
//! Assertions read a session's recorded transition history rather than polling
//! for a live status.  A state such as `Reconnecting` can last well under
//! 100 ms, and catching it in flight is a race a test will eventually lose.

mod harness;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use harness::*;
use link_core::path::{FailReason, PathStatus};
use link_endpoint::RelaySpec;

/// A settle delay long enough that probing only happens when a test asks for it.
const NEVER: Duration = Duration::from_secs(3600);

/// Reach `Relayed`, move 8 MiB through the relay, then upgrade to `Direct` and
/// move another 8 MiB on the same session without a stream breaking.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relayed_transfer_then_direct_upgrade() {
    init_tracing();
    let relay = start_relay().await;
    let url = relay.url("127.0.0.1");
    let options = || EndpointOptions {
        relays: vec![RelaySpec::plain(url.clone())],
        allow_direct: true,
        probe_delay: NEVER,
        reflector: Some(relay.udp_addr),
    };

    let alice = start_endpoint(options()).await;
    let bob = Arc::new(start_endpoint(options()).await);
    let card = exchange_card(&bob);

    let accepting = {
        let bob = bob.clone();
        tokio::spawn(async move { bob.accept().await })
    };
    let session = alice.connect(&card).await.expect("alice connects");
    let bob_session = Arc::new(accepting.await.unwrap().expect("bob accepts"));
    let sink = spawn_sink(bob_session.clone(), 2);

    assert_eq!(
        session.peer(),
        card.node_id,
        "connected to the card's node ID"
    );
    assert_eq!(
        bob_session.peer(),
        alice.node_id(),
        "bob learned alice from the handshake"
    );
    assert_eq!(
        statuses(&session.history()),
        vec![PathStatus::Rendezvous, PathStatus::Relayed],
        "the session starts at Rendezvous and reaches Relayed, nothing else"
    );

    let report = session.path();
    assert!(
        report.direct.is_none(),
        "no direct path is claimed before a probe proved one"
    );
    assert_eq!(
        report.relay.as_deref(),
        Some(url.as_str()),
        "the relay in use is named"
    );

    send_and_verify(&session, 0x5eed_0001, 8 * MIB)
        .await
        .expect("relayed 8 MiB");

    let history = session.history();
    assert!(
        !saw(&history, PathStatus::Probing) && !saw(&history, PathStatus::Direct),
        "the whole first transfer was carried by the relay, history: {}",
        describe(&history)
    );
    assert!(
        session.path().direct.is_none(),
        "a relayed report never carries a direct address"
    );
    assert!(
        alice.paths().proven_direct(session.peer()).is_none(),
        "nothing was proved, so nothing may be claimed"
    );

    // Now let the probes run.  Only alice is nudged: bob probes back by itself
    // when a valid signed ping arrives from an address it has not proved.
    session.request_direct();
    let history = wait_for_history(&session, Duration::from_secs(60), |h| {
        saw(h, PathStatus::Direct)
    })
    .await;
    assert!(
        saw(&history, PathStatus::Direct),
        "direct upgrade on loopback, history: {}",
        describe(&history)
    );
    assert!(
        saw_after(&history, PathStatus::Relayed, PathStatus::Probing),
        "the upgrade went through Probing, history: {}",
        describe(&history)
    );

    let proven = alice
        .paths()
        .proven_direct(session.peer())
        .expect("the path socket holds the proof");
    let entered_direct = history
        .iter()
        .rfind(|r| r.status == PathStatus::Direct)
        .expect("a Direct entry");
    assert_eq!(
        entered_direct.direct,
        Some(proven.addr),
        "the report says direct only because a signed pong proved that address"
    );

    let bob_history = wait_for_history(&bob_session, Duration::from_secs(30), |h| {
        saw(h, PathStatus::Direct)
    })
    .await;
    assert!(
        saw(&bob_history, PathStatus::Direct),
        "both sides prove independently, bob's history: {}",
        describe(&bob_history)
    );

    send_and_verify(&session, 0x5eed_0002, 8 * MIB)
        .await
        .expect("direct 8 MiB");
    assert_eq!(
        session.path().status,
        PathStatus::Direct,
        "still direct after the transfer, history: {}",
        describe(&session.history())
    );
    assert_eq!(
        sink.await.expect("sink"),
        2,
        "both transfers were sunk whole"
    );
    relay.shutdown();
}

/// Owner declined direct paths.  Relay-only is a first-class configuration that
/// must produce the same application behaviour.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_direct_stays_relayed() {
    init_tracing();
    let relay = start_relay().await;
    let url = relay.url("127.0.0.1");

    let alice = start_endpoint(EndpointOptions {
        relays: vec![RelaySpec::plain(url.clone())],
        allow_direct: false,
        probe_delay: Duration::ZERO,
        reflector: Some(relay.udp_addr),
    })
    .await;
    let bob = Arc::new(
        start_endpoint(EndpointOptions {
            relays: vec![RelaySpec::plain(url.clone())],
            allow_direct: true,
            probe_delay: Duration::ZERO,
            reflector: Some(relay.udp_addr),
        })
        .await,
    );
    let card = exchange_card(&bob);

    let accepting = {
        let bob = bob.clone();
        tokio::spawn(async move { bob.accept().await })
    };
    let session = alice.connect(&card).await.expect("alice connects");
    let bob_session = Arc::new(accepting.await.unwrap().expect("bob accepts"));
    let sink = spawn_sink(bob_session.clone(), 1);

    assert_eq!(session.path().status, PathStatus::Relayed);
    send_and_verify(&session, 0x5eed_0003, 8 * MIB)
        .await
        .expect("relayed 8 MiB");

    // Give probing every chance to happen, then prove it did not.
    tokio::time::sleep(Duration::from_secs(3)).await;
    for (who, history) in [("alice", session.history()), ("bob", bob_session.history())] {
        assert!(
            !saw(&history, PathStatus::Probing) && !saw(&history, PathStatus::Direct),
            "{who} never probed and never went direct, history: {}",
            describe(&history)
        );
        assert!(
            history.iter().all(|report| report.direct.is_none()),
            "{who} never reported a direct address, history: {}",
            describe(&history)
        );
    }
    assert_eq!(
        session.path().status,
        PathStatus::Relayed,
        "declined direct paths stay Relayed"
    );
    assert_eq!(
        bob_session.path().status,
        PathStatus::Relayed,
        "the peer that allowed direct paths also stays Relayed"
    );
    assert!(
        alice.paths().proven_direct(session.peer()).is_none()
            && bob.paths().proven_direct(bob_session.peer()).is_none(),
        "no direct path was proved on either side"
    );

    assert_eq!(
        sink.await.expect("sink"),
        1,
        "the transfer completed through the relay"
    );
    relay.shutdown();
}

/// Two relays.  Kill the first mid-session and the endpoints move to the second.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_loss_reconnects_to_the_second_relay() {
    init_tracing();
    let first = start_relay().await;
    let second = start_relay().await;
    let first_url = first.url("127.0.0.1");
    let second_url = second.url("127.0.0.1");
    let relays = vec![
        RelaySpec::plain(first_url.clone()),
        RelaySpec::plain(second_url.clone()),
    ];

    // Direct paths off, so the relay is the only route and the loss is visible.
    let options = || EndpointOptions {
        relays: relays.clone(),
        allow_direct: false,
        probe_delay: Duration::ZERO,
        reflector: None,
    };
    let alice = start_endpoint(options()).await;
    let bob = Arc::new(start_endpoint(options()).await);
    let card = exchange_card(&bob);

    let accepting = {
        let bob = bob.clone();
        tokio::spawn(async move { bob.accept().await })
    };
    let session = Arc::new(alice.connect(&card).await.expect("alice connects"));
    let bob_session = Arc::new(accepting.await.unwrap().expect("bob accepts"));

    let total = 32 * MIB;
    let received = Arc::new(AtomicUsize::new(0));
    let sink = spawn_sink_counting(bob_session.clone(), 1, Some(received.clone()));

    assert_eq!(session.path().status, PathStatus::Relayed);
    assert_eq!(session.path().relay.as_deref(), Some(first_url.as_str()));

    let transfer = {
        let session = session.clone();
        tokio::spawn(async move { send_and_verify(&session, 0x5eed_0004, total).await })
    };

    // Kill the relay at a point tied to progress, not to a wall clock: wait
    // until the peer has actually taken delivery of 2 MiB of the 32 MiB.
    let mark = 2 * MIB;
    assert!(
        wait_until(Duration::from_secs(120), || received.load(Ordering::SeqCst)
            >= mark)
        .await,
        "the transfer never reached {mark} bytes, so there was nothing to interrupt"
    );
    let at_kill = received.load(Ordering::SeqCst);
    assert!(
        at_kill < total,
        "the relay must be killed while the transfer is still in flight, \
         {at_kill} of {total} bytes had already arrived"
    );
    first.shutdown();

    let history = wait_for_history(&session, Duration::from_secs(60), |h| {
        saw_after(h, PathStatus::Reconnecting, PathStatus::Relayed) || saw_failed(h)
    })
    .await;
    assert!(
        saw(&history, PathStatus::Reconnecting),
        "losing the relay is an explicit Reconnecting, never a silent stall, history: {}",
        describe(&history)
    );
    assert!(
        saw_after(&history, PathStatus::Reconnecting, PathStatus::Relayed),
        "the endpoint came back on a relay rather than failing, history: {}",
        describe(&history)
    );
    let back = history
        .iter()
        .rfind(|r| r.status == PathStatus::Relayed)
        .expect("a Relayed entry after the outage");
    assert_eq!(
        back.relay.as_deref(),
        Some(second_url.as_str()),
        "it is the second configured relay that took over, history: {}",
        describe(&history)
    );
    println!(
        "relay_loss killed_at_bytes={at_kill} of {total}; history: {}",
        describe(&history)
    );

    // The application stream either continues or fails explicitly.  It never
    // hangs and it never silently drops bytes: the digest is checked either way.
    let outcome = tokio::time::timeout(Duration::from_secs(180), transfer)
        .await
        .expect("the transfer neither hung nor was abandoned")
        .expect("transfer task");
    match outcome {
        Ok(()) => {
            assert_eq!(sink.await.expect("sink"), 1, "the whole transfer arrived");
            assert_eq!(
                received.load(Ordering::SeqCst),
                total,
                "every byte was delivered across the relay outage"
            );
        }
        Err(e) => {
            let history = session.history();
            assert!(
                saw(&history, PathStatus::Failed(FailReason::Relay)),
                "an aborted transfer must leave an explicit Failed(Relay), \
                 history: {} after {e}",
                describe(&history)
            );
        }
    }
    second.shutdown();
}

/// Peak RSS must not track transfer size.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn memory_stays_flat_between_8_and_64_mib() {
    init_tracing();
    let relay = start_relay().await;
    let url = relay.url("127.0.0.1");
    let options = || EndpointOptions {
        relays: vec![RelaySpec::plain(url.clone())],
        allow_direct: false,
        probe_delay: Duration::ZERO,
        reflector: None,
    };
    let alice = start_endpoint(options()).await;
    let bob = Arc::new(start_endpoint(options()).await);
    let card = exchange_card(&bob);

    let accepting = {
        let bob = bob.clone();
        tokio::spawn(async move { bob.accept().await })
    };
    let session = alice.connect(&card).await.expect("alice connects");
    let bob_session = Arc::new(accepting.await.unwrap().expect("bob accepts"));
    let sink = spawn_sink(bob_session.clone(), 2);

    send_and_verify(&session, 0x5eed_0005, 8 * MIB)
        .await
        .expect("8 MiB");
    let after_small = peak_rss_bytes();

    send_and_verify(&session, 0x5eed_0006, 64 * MIB)
        .await
        .expect("64 MiB");
    let after_large = peak_rss_bytes();

    let growth = after_large.saturating_sub(after_small);
    println!(
        "peak_rss_after_8mib={after_small} peak_rss_after_64mib={after_large} growth={growth}"
    );
    assert!(
        growth < 24 * MIB as u64,
        "peak RSS grew by {growth} bytes between an 8 MiB and a 64 MiB transfer, \
         so something is buffering the whole transfer"
    );

    assert_eq!(sink.await.expect("sink"), 2);
    relay.shutdown();
}

/// Junk and forged probes from unproven addresses are dropped, spec 4.1 and 4.2.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unproven_addresses_and_forged_probes_are_dropped() {
    init_tracing();
    let relay = start_relay().await;
    let url = relay.url("127.0.0.1");
    let options = || EndpointOptions {
        relays: vec![RelaySpec::plain(url.clone())],
        allow_direct: true,
        probe_delay: NEVER,
        reflector: None,
    };
    let alice = start_endpoint(options()).await;
    let bob = Arc::new(start_endpoint(options()).await);
    let bob_udp = bob.paths().udp_local();
    let alice_id = alice.node_id();
    let bob_id = bob.node_id();
    let card = exchange_card(&bob);

    let accepting = {
        let bob = bob.clone();
        tokio::spawn(async move { bob.accept().await })
    };
    let session = alice.connect(&card).await.expect("alice connects");
    let bob_session = Arc::new(accepting.await.unwrap().expect("bob accepts"));
    let sink = spawn_sink(bob_session.clone(), 1);

    // A third party sprays bob's direct socket with QUIC-shaped junk.
    let attacker = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for _ in 0..50 {
        attacker.send_to(&[0xa5u8; 1200], bob_udp).await.unwrap();
    }
    // A probe with the right shape, signed by the wrong key.
    let mut forged = link_core::wire::Probe {
        kind: link_core::wire::PROBE_PING,
        sender: alice_id,
        receiver: bob_id,
        nonce: [7u8; 16],
    }
    .sign(&link_core::id::TransportKey::generate());
    forged[5..37].copy_from_slice(alice_id.as_bytes());
    assert_eq!(
        link_core::wire::Probe::parse_verified(&forged),
        None,
        "the forged probe does not verify"
    );
    attacker.send_to(&forged, bob_udp).await.unwrap();

    // The session is untouched by any of it.
    send_and_verify(&session, 0x5eed_0007, MIB)
        .await
        .expect("1 MiB despite the noise");
    let history = bob_session.history();
    assert!(
        bob.paths().proven_direct(bob_id).is_none()
            && history.iter().all(|report| report.direct.is_none()),
        "junk from an unproven address never becomes a path, history: {}",
        describe(&history)
    );
    assert!(
        !saw_failed(&history),
        "junk from an unproven address never fails the session, history: {}",
        describe(&history)
    );
    assert_eq!(sink.await.expect("sink"), 1);
    relay.shutdown();
}
