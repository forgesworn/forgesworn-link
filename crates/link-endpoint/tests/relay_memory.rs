//! Run the process-wide RSS measurement in its own test executable.
#![cfg(unix)]

mod harness;

use std::sync::Arc;
use std::time::Duration;

use harness::*;
use link_endpoint::RelaySpec;

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
    let sink = spawn_sink(bob_session, 2);

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
        "peak RSS grew by {growth} bytes between an 8 MiB and a 64 MiB transfer"
    );

    assert_eq!(sink.await.expect("sink"), 2);
    relay.shutdown();
}
