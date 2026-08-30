//! `Endpoint::card` under hint pressure and clock pressure: the caller's
//! extra hints survive a full card, and serials stay strictly increasing when
//! the wall clock runs ahead of the counter.

use std::time::Duration;

use link_core::card::{HINT_EPHEMERAL, Hint, MAX_HINTS};
use link_endpoint::{Endpoint, EndpointConfig, RelaySpec, TransportKey};

async fn endpoint_with_relays(count: usize) -> Endpoint {
    let mut config = EndpointConfig::new(TransportKey::generate());
    config.relays = (0..count)
        .map(|i| RelaySpec::plain(format!("wss://relay{i}.example/link")))
        .collect();
    config.allow_direct = false;
    config.bind = "127.0.0.1:0".parse().unwrap();
    Endpoint::open(config).await.expect("endpoint opens")
}

#[tokio::test]
async fn the_callers_ephemeral_hint_survives_a_full_card() {
    // Enough of the endpoint's own hints to fill the card on their own.
    let endpoint = endpoint_with_relays(MAX_HINTS + 4).await;
    let ephemeral = Hint {
        kind: HINT_EPHEMERAL,
        // Any 33 bytes: card signing does not validate hints, verification does.
        value: vec![0x02; 33],
    };
    let card = endpoint.card(Duration::from_secs(300), vec![ephemeral.clone()]);
    assert_eq!(card.hints.len(), MAX_HINTS, "the card is exactly full");
    assert!(
        card.hints.contains(&ephemeral),
        "the caller's 0x04 hint survives hint pressure"
    );
    assert_eq!(
        card.hints
            .iter()
            .filter(|hint| hint.kind == HINT_EPHEMERAL)
            .count(),
        1
    );
    endpoint.close().await;
}

#[tokio::test]
async fn serials_stay_strictly_increasing_when_the_clock_runs_ahead() {
    let endpoint = endpoint_with_relays(1).await;
    // Let the wall clock move past the counter's seed, then sign two cards in
    // the same second.  The old max(counter, now) clamped both to `now`.
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let first = endpoint.card(Duration::from_secs(300), Vec::new());
    let second = endpoint.card(Duration::from_secs(300), Vec::new());
    assert!(
        first.serial < second.serial,
        "serials must be strictly increasing: {} then {}",
        first.serial,
        second.serial
    );
    endpoint.close().await;
}
