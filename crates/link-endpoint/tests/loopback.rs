//! Loopback integration.  This proves the contract, not the network: nothing
//! here traverses a NAT, so none of it says anything about carrier paths.
//!
//! Assertions read a session's recorded transition history rather than polling
//! for a live status.  A state such as `Reconnecting` can last well under
//! 100 ms, and catching it in flight is a race a test will eventually lose.

mod harness;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use harness::*;
use link_core::path::{FailReason, PathStatus};
use link_endpoint::{RelaySpec, TransportKey};

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
    // The report follows the socket (spec 5): if bob's punch-now round proves
    // alice's path before her own tick starts a round, her history goes
    // straight from Relayed to Direct, which is honest.  What must hold is
    // that Direct came only after the request, never before it.
    assert!(
        saw_after(&history, PathStatus::Relayed, PathStatus::Direct),
        "Direct came after Relayed, history: {}",
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

/// Peak RSS must not track transfer size.  The measurement uses `getrusage`,
/// so this runs on Unix; the bounded-buffer property it checks is platform
/// independent.
#[cfg(unix)]
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
    // A probe with the right shape, sealed under a key no session has.
    let forged = link_core::wire::Probe {
        kind: link_core::wire::PROBE_PING,
        key_id: [7u8; 8],
        nonce: [7u8; 16],
    }
    .seal(&[7u8; 32]);
    assert_eq!(
        link_core::wire::Probe::peek_key_id(&forged),
        Some([7u8; 8]),
        "the forged probe has a probe's shape"
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

/// A `request_direct` on one side makes the *other* side start its own
/// probing round at once (the `punch-now` control message, spec 4.2), rather
/// than only answering pings.  Both ends punching in the same instant is what
/// a NAT mapping needs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn punch_now_starts_a_round_on_the_peer() {
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

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        bob_session.punch_requests(),
        0,
        "nobody has asked bob for a round yet, history: {}",
        describe(&bob_session.history())
    );
    assert!(
        !saw(&session.history(), PathStatus::Probing),
        "alice is idle until asked, history: {}",
        describe(&session.history())
    );

    session.request_direct();
    assert!(
        wait_until(Duration::from_secs(5), || bob_session.punch_requests() >= 1).await,
        "bob received alice's punch-now on the control stream, history: {}",
        describe(&bob_session.history())
    );
    // Alice's own round is recorded when it happens.  If bob's punch-now
    // round proves alice's path before her tick starts one, her history goes
    // straight from Relayed to Direct: the report follows the socket (spec 5).
    let history = wait_for_history(&session, Duration::from_secs(10), |h| {
        saw(h, PathStatus::Direct)
    })
    .await;
    assert!(
        saw_after(&history, PathStatus::Relayed, PathStatus::Direct),
        "alice reached Direct after the request, history: {}",
        describe(&history)
    );
    if let Some(probing) = history
        .iter()
        .find(|report| report.status == PathStatus::Probing)
    {
        assert!(
            probing.cause.contains("requested here"),
            "alice's round records who asked, cause: {}",
            probing.cause
        );
    }
    // Both sides reach Direct: bob by answering alice's pings and, had a NAT
    // eaten those, by the round the punch-now started.
    let bob_history = wait_for_history(&bob_session, Duration::from_secs(10), |h| {
        saw(h, PathStatus::Direct)
    })
    .await;
    assert!(
        saw(&bob_history, PathStatus::Direct),
        "bob: {}",
        describe(&bob_history)
    );
    relay.shutdown();
}

/// `reannounce` re-sends this side's candidates on the control stream and
/// the peer records the update, spec 4.2.  This is what the network monitor
/// does on an interface change, and what an application does from a
/// connectivity callback.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reannounce_resends_candidates() {
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

    assert!(
        wait_until(Duration::from_secs(5), || {
            bob.paths().candidate_updates(alice.node_id()) == 1
        })
        .await,
        "the initial exchange is one update, saw {}",
        bob.paths().candidate_updates(alice.node_id())
    );

    session.reannounce();
    assert!(
        wait_until(Duration::from_secs(5), || {
            bob.paths().candidate_updates(alice.node_id()) == 2
        })
        .await,
        "bob received the re-announcement, saw {}",
        bob.paths().candidate_updates(alice.node_id())
    );
    assert!(
        wait_until(Duration::from_secs(5), || bob_session.punch_requests() >= 1).await,
        "a re-announcement is followed by a punch-now"
    );
    relay.shutdown();
}

/// Two endpoints configured with different relays still meet: the card names
/// the callee's relay, the caller dials it, and the callee replies on the
/// relay the caller's datagrams arrived on.  Convergence needs no shared
/// configuration, spec 3.1.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peers_converge_on_the_callee_relay_hints() {
    init_tracing();
    let relay_a = start_relay().await;
    let relay_b = start_relay().await;
    let url_a = relay_a.url("127.0.0.1");
    let url_b = relay_b.url("127.0.0.1");

    let alice = start_endpoint(EndpointOptions {
        relays: vec![RelaySpec::plain(url_a.clone())],
        allow_direct: false,
        probe_delay: NEVER,
        reflector: None,
    })
    .await;
    let bob = Arc::new(
        start_endpoint(EndpointOptions {
            relays: vec![RelaySpec::plain(url_b.clone())],
            allow_direct: false,
            probe_delay: NEVER,
            reflector: None,
        })
        .await,
    );
    let card = exchange_card(&bob);
    assert_eq!(
        card.relay_urls(),
        vec![url_b.clone()],
        "bob's card names bob's relay"
    );

    let accepting = {
        let bob = bob.clone();
        tokio::spawn(async move { bob.accept().await })
    };
    let session = tokio::time::timeout(Duration::from_secs(20), alice.connect(&card))
        .await
        .expect("alice reaches bob within 20 s by dialing the relay his card names")
        .expect("alice connects");
    let bob_session = Arc::new(accepting.await.unwrap().expect("bob accepts"));
    let sink = spawn_sink(bob_session.clone(), 1);

    assert_eq!(
        session.path().relay.as_deref(),
        Some(url_b.as_str()),
        "alice's session rides bob's relay, not her own"
    );
    assert_eq!(
        bob_session.path().relay.as_deref(),
        Some(url_b.as_str()),
        "bob answers on the relay alice arrived on"
    );
    send_and_verify(&session, 0x5eed_0009, 8 * MIB)
        .await
        .expect("8 MiB over the converged relay");
    assert_eq!(sink.await.expect("sink"), 1);
    relay_a.shutdown();
    relay_b.shutdown();
}

/// The same node reconnecting while its previous session is still alive on
/// the other side (an app restart, a relay flap) must not stall.  Per-peer
/// path state is keyed by node ID, so the old session's `direct_lost` used
/// to drop the new session's proof and the new session's direct datagrams
/// were then discarded as unproven: a 256 MiB transfer that took 1.5 s took
/// 22 s.  The rule now: a new session from the same node ID supersedes the
/// old one, which is closed, and the path state starts clean.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reconnecting_node_supersedes_its_old_session_and_does_not_stall() {
    init_tracing();
    let relay = start_relay().await;
    let url = relay.url("127.0.0.1");
    let options = || EndpointOptions {
        relays: vec![RelaySpec::plain(url.clone())],
        allow_direct: true,
        probe_delay: Duration::ZERO,
        reflector: Some(relay.udp_addr),
    };
    let bob = Arc::new(start_endpoint(options()).await);
    let card = exchange_card(&bob);

    // Alice's first process: connect, go direct, then vanish without closing,
    // which is what a crash or a kill looks like to bob.
    let alice_key = TransportKey::generate();
    let first = start_endpoint_with_key(options(), alice_key.clone()).await;
    let accepting = {
        let bob = bob.clone();
        tokio::spawn(async move { bob.accept().await })
    };
    let session_1 = first.connect(&card).await.expect("first connect");
    let bob_session_1 = Arc::new(accepting.await.unwrap().expect("bob accepts the first"));
    let _sink_1 = spawn_sink(bob_session_1.clone(), 1);
    wait_for_history(&session_1, Duration::from_secs(10), |h| {
        saw(h, PathStatus::Direct)
    })
    .await;
    assert!(
        saw(&bob_session_1.history(), PathStatus::Direct)
            || wait_for_history(&bob_session_1, Duration::from_secs(10), |h| saw(
                h,
                PathStatus::Direct
            ))
            .await
            .iter()
            .any(|r| r.status == PathStatus::Direct),
        "the first session went direct on both sides"
    );
    // Vanish: drop the endpoint without closing the connection.
    std::mem::forget(session_1);
    drop(first);

    // Alice's second process, same node ID, before the first has idled out.
    let second = start_endpoint_with_key(options(), alice_key).await;
    let accepting = {
        let bob = bob.clone();
        tokio::spawn(async move { bob.accept().await })
    };
    // Before the fix this connect timed out at 30 s: bob's handshake replies
    // were routed by the proof of the first process's socket.
    let dialled = Instant::now();
    let session_2 = second.connect(&card).await.expect("second connect");
    let handshake = dialled.elapsed();
    assert!(
        handshake < Duration::from_secs(5),
        "the second handshake was not routed by a stale proof: took {handshake:?}"
    );
    let bob_session_2 = Arc::new(accepting.await.unwrap().expect("bob accepts the second"));
    let sink_2 = spawn_sink(bob_session_2.clone(), 1);

    // The old session on bob's side is told it was superseded and ends.
    let old = wait_for_history(&bob_session_1, Duration::from_secs(10), saw_failed).await;
    assert!(
        old.last().is_some_and(
            |r| matches!(r.status, PathStatus::Failed(_)) && r.cause.contains("supersed")
        ),
        "bob's first session with alice was superseded, history: {}",
        describe(&old)
    );

    // The new session moves 64 MiB.  The bound is loose on purpose: what the
    // defect broke was the handshake, asserted tightly above; a loaded CI
    // runner has carried this transfer in 14 s over a direct path, which is
    // slow but not the stall.
    let started = Instant::now();
    send_and_verify(&session_2, 0x5eed_0011, 64 * MIB)
        .await
        .expect("64 MiB on the second session");
    let took = started.elapsed();
    assert!(
        took < Duration::from_secs(30),
        "the reconnected session did not stall: took {took:?}, history: {}",
        describe(&session_2.history())
    );
    assert_eq!(sink_2.await.expect("sink"), 1);
    relay.shutdown();
}

/// The same node reconnecting after a *clean* close, while bob's proof of its
/// old socket is still fresh, must not stall either.  A new session never
/// inherits path state: the proof pointed at a socket the new process does
/// not own, and bob's handshake replies went there until it aged out, so a
/// handshake that takes milliseconds took 21 s in the release CLI.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reconnect_after_a_clean_close_starts_with_clean_path_state() {
    init_tracing();
    let relay = start_relay().await;
    let url = relay.url("127.0.0.1");
    let options = || EndpointOptions {
        relays: vec![RelaySpec::plain(url.clone())],
        allow_direct: true,
        probe_delay: Duration::ZERO,
        reflector: Some(relay.udp_addr),
    };
    let bob = Arc::new(start_endpoint(options()).await);
    let card = exchange_card(&bob);
    let alice_key = TransportKey::generate();

    let first = start_endpoint_with_key(options(), alice_key.clone()).await;
    let accepting = {
        let bob = bob.clone();
        tokio::spawn(async move { bob.accept().await })
    };
    let session_1 = first.connect(&card).await.expect("first connect");
    let bob_session_1 = Arc::new(accepting.await.unwrap().expect("bob accepts the first"));
    let _sink_1 = spawn_sink(bob_session_1.clone(), 1);
    wait_for_history(&bob_session_1, Duration::from_secs(10), |h| {
        saw(h, PathStatus::Direct)
    })
    .await;
    assert!(
        bob.paths().proven_direct(first.node_id()).is_some(),
        "bob holds a proof of alice's first socket"
    );
    // A clean close, then the process is gone; bob's proof is still fresh.
    session_1.close(0).await;
    drop(first);

    let second = start_endpoint_with_key(options(), alice_key).await;
    let accepting = {
        let bob = bob.clone();
        tokio::spawn(async move { bob.accept().await })
    };
    let started = Instant::now();
    let session_2 = second.connect(&card).await.expect("second connect");
    let handshake = started.elapsed();
    let bob_session_2 = Arc::new(accepting.await.unwrap().expect("bob accepts the second"));
    let sink_2 = spawn_sink(bob_session_2.clone(), 1);
    assert!(
        handshake < Duration::from_secs(5),
        "the second handshake was not routed by the stale proof: took {handshake:?}"
    );
    send_and_verify(&session_2, 0x5eed_0012, 8 * MIB)
        .await
        .expect("8 MiB on the second session");
    assert_eq!(sink_2.await.expect("sink"), 1);
    relay.shutdown();
}
