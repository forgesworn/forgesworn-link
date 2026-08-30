//! Loopback integration for the Blossom lane.
//!
//! This proves the request protocol end to end over a real relay and two real
//! endpoints on 127.0.0.1 with plain `ws://`, which is what the relay allows on
//! loopback.  Nothing here traverses a NAT, so it says nothing about carrier
//! paths; it says the codec, the serving side and the fetcher agree.
//!
//! The whole file is gated behind the `shelter-kit` feature, because the fetcher
//! implements `shelter_kit::BlobFetcher`.

#![cfg(feature = "shelter-kit")]

use std::sync::Arc;
use std::time::Duration;

use futures_util::TryStreamExt;
use link_blossom::{LinkFetcher, MapBlobSource, MapCardResolver, serve, serve_stream};
use link_core::card::{Card, VerifyContext};
use link_endpoint::{Endpoint, EndpointConfig, RelaySpec, TransportKey};
use link_relay::{RelayConfig, RelayHandle};
use sha2::{Digest, Sha256};
use shelter_kit::{BlobFetcher, FetchError, FetchPath, FetchRequest};
use url::Url;

/// Long enough that a session never probes for a direct path on its own, so the
/// reported path stays a deterministic `Relayed` for the assertion.
const NEVER: Duration = Duration::from_secs(3600);

fn init() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("link_blossom=info,link_endpoint=warn,link_relay=warn")
        .with_test_writer()
        .try_init();
}

async fn start_relay() -> RelayHandle {
    link_relay::start(RelayConfig {
        ws_bind: "127.0.0.1:0".parse().unwrap(),
        udp_bind: "127.0.0.1:0".parse().unwrap(),
        hosts: vec!["127.0.0.1".into()],
        tls: None,
        bytes_per_second: 0,
        max_sessions: 64,
        reflector_per_second: 100.0,
    })
    .await
    .expect("relay starts")
}

async fn start_endpoint(relay_url: &str) -> Endpoint {
    let mut config = EndpointConfig::new(TransportKey::generate());
    config.relays = vec![RelaySpec::plain(relay_url.to_string())];
    config.allow_direct = true;
    config.probe_delay = NEVER;
    config.bind = "127.0.0.1:0".parse().unwrap();
    Endpoint::open(config).await.expect("endpoint opens")
}

/// Sign a card and verify its exact bytes, which is what a pairing flow does.
fn card_of(endpoint: &Endpoint) -> Card {
    let card = endpoint.card(Duration::from_secs(300), Vec::new());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    Card::verify(
        card.as_bytes(),
        &VerifyContext::new(now).expecting(endpoint.node_id()),
    )
    .expect("a freshly signed card verifies")
}

/// Deterministic bytes, so the test needs no fixture and can recompute the hash.
fn deterministic_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut state = seed | 1;
    for chunk in out.chunks_mut(8) {
        let mut x = state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        state = x;
        let bytes = x.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fetch_over_link_round_trips_a_5_mib_blob() {
    init();
    let relay = start_relay().await;
    let url = relay.url("127.0.0.1");

    // The server serves; the client fetches.  Different keys, so the identity
    // rule is genuinely exercised.
    let server = Arc::new(start_endpoint(&url).await);
    let client = Arc::new(start_endpoint(&url).await);

    // A known 5 MiB blob with its computed digest.
    let blob = deterministic_bytes(5 * 1024 * 1024, 0xB105_0001);
    let want_hash = hex::encode(Sha256::digest(&blob));

    let source = Arc::new(MapBlobSource::new().with_blob(
        want_hash.clone(),
        Some("application/octet-stream".to_owned()),
        blob.clone(),
    ));

    // Serve on the server endpoint in the background.
    let serving = tokio::spawn(serve(server.clone(), source.clone()));

    // The client resolves the server's node id to the server's card.
    let resolver = Arc::new(MapCardResolver::new().with_card(card_of(&server)));
    let fetcher = LinkFetcher::new(client, resolver);

    let node = server.node_id().to_base32();

    // The happy path: an fsl source for the known blob.
    let source_url = Url::parse(&format!("fsl://{node}/{want_hash}")).expect("valid fsl url");
    let fetched = fetcher
        .fetch(FetchRequest {
            source: source_url,
            sha256: want_hash.clone(),
            expected_size: Some(blob.len() as u64),
        })
        .await
        .expect("the fetch succeeds");

    assert_eq!(
        fetched.size,
        blob.len() as u64,
        "the declared size matches the blob length"
    );
    assert!(
        matches!(fetched.path, FetchPath::Direct | FetchPath::Relayed),
        "the path is Direct or Relayed, never a foreign transport, got {:?}",
        fetched.path
    );
    assert_ne!(fetched.path, FetchPath::Tor, "the lane never claims Tor");
    assert_ne!(
        fetched.path,
        FetchPath::Https,
        "the lane never claims Https"
    );
    assert_ne!(
        fetched.path,
        FetchPath::Loopback,
        "the lane reports transport, not the test environment"
    );

    // Drain the whole body and prove it hashes to the digest we asked for.
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    let mut body = fetched.body;
    while let Some(chunk) = body.try_next().await.expect("a body chunk, not an error") {
        total += chunk.len() as u64;
        hasher.update(&chunk);
    }
    assert_eq!(total, blob.len() as u64, "the whole body arrived");
    assert_eq!(
        hex::encode(hasher.finalize()),
        want_hash,
        "the drained body hashes to the expected sha256"
    );

    // An unknown hash is a not-found status, mapped to 404.
    let missing = "0".repeat(64);
    let missing_url = Url::parse(&format!("fsl://{node}/{missing}")).expect("valid fsl url");
    let miss = fetcher
        .fetch(FetchRequest {
            source: missing_url,
            sha256: missing,
            expected_size: None,
        })
        .await;
    assert!(
        matches!(miss, Err(FetchError::UnusableStatus(404))),
        "an unknown hash yields 404, got {miss:?}"
    );

    // A non-fsl source is unsupported, so a dispatcher can try another fetcher.
    let http = Url::parse("https://example.com/blob").expect("valid url");
    let unsupported = fetcher
        .fetch(FetchRequest {
            source: http,
            sha256: want_hash,
            expected_size: None,
        })
        .await;
    assert!(
        matches!(unsupported, Err(FetchError::UnsupportedSource)),
        "a non-fsl source is unsupported, got {unsupported:?}"
    );

    serving.abort();
    relay.shutdown();
}

/// The multi-protocol path: the caller owns the accept loop, demultiplexes on
/// the four magic bytes it reads itself, and hands the stream plus that prefix
/// to `serve_stream`.  This is what a node serving HTTP-over-Link beside FSLB
/// does; the fetcher on the other end must not be able to tell the difference.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_demultiplexing_accept_loop_serves_fslb_via_serve_stream() {
    init();
    let relay = start_relay().await;
    let url = relay.url("127.0.0.1");

    let server = Arc::new(start_endpoint(&url).await);
    let client = Arc::new(start_endpoint(&url).await);

    let blob = deterministic_bytes(256 * 1024, 0xB105_0002);
    let want_hash = hex::encode(Sha256::digest(&blob));
    let source = Arc::new(MapBlobSource::new().with_blob(
        want_hash.clone(),
        Some("application/octet-stream".to_owned()),
        blob.clone(),
    ));

    let serving = {
        let server = server.clone();
        let source = source.clone();
        tokio::spawn(async move {
            while let Ok(session) = server.accept().await {
                let source = source.clone();
                tokio::spawn(async move {
                    while let Ok(mut stream) = session.accept_stream().await {
                        let source = source.clone();
                        tokio::spawn(async move {
                            let mut prefix = [0u8; 4];
                            if stream.recv.read_exact(&mut prefix).await.is_err() {
                                return;
                            }
                            if prefix == *b"FSLB" {
                                let _ = serve_stream(stream, source.as_ref(), &prefix).await;
                            }
                        });
                    }
                });
            }
        })
    };

    let resolver = Arc::new(MapCardResolver::new().with_card(card_of(&server)));
    let fetcher = LinkFetcher::new(client, resolver);
    let node = server.node_id().to_base32();
    let source_url = Url::parse(&format!("fsl://{node}/{want_hash}")).expect("valid fsl url");
    let fetched = fetcher
        .fetch(FetchRequest {
            source: source_url,
            sha256: want_hash.clone(),
            expected_size: Some(blob.len() as u64),
        })
        .await
        .expect("the demultiplexed fetch succeeds");

    let mut hasher = Sha256::new();
    let mut body = fetched.body;
    while let Some(chunk) = body.try_next().await.expect("a body chunk") {
        hasher.update(&chunk);
    }
    assert_eq!(
        hex::encode(hasher.finalize()),
        want_hash,
        "the demultiplexed body hashes to the expected sha256"
    );

    serving.abort();
    relay.shutdown();
}
