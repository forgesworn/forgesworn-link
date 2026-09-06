#![cfg(all(feature = "experimental-lan", feature = "shelter-kit"))]

use futures_util::TryStreamExt;
use link_blossom::{
    MapBlobSource, Request, ResponseHeader,
    lan::{
        LanBlobLimits, LanFetchPeer, LanFetcher, ShelterBlobSource, fetch_blob_over_lan, serve_lan,
        serve_lan_stream,
    },
};
use link_core::id::TransportKey;
use link_endpoint::lan::{LanAdmission, LanBinding, LanEndpoint};
use sha2::{Digest, Sha256};
use shelter_kit::{BlobFetcher, FetchError, FetchRequest};
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;

struct Pair {
    client: Arc<LanEndpoint>,
    server: Arc<LanEndpoint>,
    to_server: Arc<LanAdmission>,
    _to_client: LanAdmission,
}
impl Pair {
    fn new() -> Self {
        let client =
            Arc::new(LanEndpoint::open(TransportKey::generate(), LanBinding::default()).unwrap());
        let server =
            Arc::new(LanEndpoint::open(TransportKey::generate(), LanBinding::default()).unwrap());
        let to_server = Arc::new(
            client
                .admit_peer(
                    server.node_id(),
                    server.card(Duration::from_secs(300), 1).unwrap().as_bytes(),
                    None,
                )
                .unwrap(),
        );
        let to_client = server
            .admit_peer(
                client.node_id(),
                client.card(Duration::from_secs(300), 1).unwrap().as_bytes(),
                None,
            )
            .unwrap();
        Self {
            client,
            server,
            to_server,
            _to_client: to_client,
        }
    }
    fn fetcher(&self) -> LanFetcher {
        LanFetcher::new(
            self.client.clone(),
            vec![LanFetchPeer::new(
                self.to_server.clone(),
                self.server.local_addr().unwrap(),
            )],
            LanBlobLimits::default(),
        )
        .unwrap()
    }
    fn request(&self, bytes: &[u8]) -> FetchRequest {
        let hash = hex::encode(Sha256::digest(bytes));
        FetchRequest {
            source: Url::parse(&format!("fsl://{}/{hash}.bin", self.server.node_id())).unwrap(),
            sha256: hash,
            expected_size: Some(bytes.len() as u64),
        }
    }
}
impl Drop for Pair {
    fn drop(&mut self) {
        self.client.close();
        self.server.close();
    }
}

#[tokio::test]
async fn exact_fslb_bytes_stream_on_a_held_session_and_concurrent_streams_preserve_it() {
    let pair = Pair::new();
    let bytes = (0..5 * 1024 * 1024 + 31)
        .map(|n| (n % 251) as u8)
        .collect::<Vec<_>>();
    let request = pair.request(&bytes);
    let source = Arc::new(MapBlobSource::new().with_blob(
        &request.sha256,
        Some("application/octet-stream".into()),
        bytes.clone(),
    ));
    let serving = tokio::spawn(serve_lan(
        pair.server.clone(),
        source,
        LanBlobLimits::default(),
    ));
    let session = Arc::new(
        pair.client
            .connect(&pair.to_server, pair.server.local_addr().unwrap())
            .await
            .unwrap(),
    );
    let hash = Sha256::digest(&bytes).into();
    let mut first = fetch_blob_over_lan(
        &session,
        hash,
        Some(bytes.len() as u64),
        LanBlobLimits::default(),
    )
    .await
    .unwrap();
    let mut second = fetch_blob_over_lan(
        &session,
        hash,
        Some(bytes.len() as u64),
        LanBlobLimits::default(),
    )
    .await
    .unwrap();
    for fetched in [&mut first, &mut second] {
        assert_eq!(fetched.path, shelter_kit::FetchPath::Direct);
        let mut hasher = Sha256::new();
        let mut size = 0;
        while let Some(chunk) = fetched.body.try_next().await.unwrap() {
            assert!(chunk.len() <= 64 * 1024);
            hasher.update(&chunk);
            size += chunk.len();
        }
        assert_eq!(size, bytes.len());
        assert_eq!(<[u8; 32]>::from(hasher.finalize()), hash);
    }
    assert!(session.is_live());
    let missing = fetch_blob_over_lan(&session, [0; 32], None, LanBlobLimits::default()).await;
    assert!(matches!(missing, Err(FetchError::UnusableStatus(404))));
    assert!(session.is_live());
    serving.abort();
}

#[tokio::test]
async fn a_busy_fetch_is_refused_without_supersession_and_dropping_it_releases_the_peer() {
    let pair = Pair::new();
    let bytes = vec![42; 1024 * 1024];
    let request = pair.request(&bytes);
    let serving = tokio::spawn(serve_lan(
        pair.server.clone(),
        Arc::new(MapBlobSource::new().with_blob(&request.sha256, None, bytes.clone())),
        LanBlobLimits::default(),
    ));
    let fetcher = pair.fetcher();
    let first = fetcher.fetch(request.clone()).await.unwrap();
    let busy = fetcher.fetch(request.clone()).await.unwrap_err();
    assert!(busy.to_string().contains("active fetch"));
    drop(first);
    let second = fetcher.fetch(request).await.unwrap();
    let returned = second
        .body
        .map_ok(|chunk| chunk.to_vec())
        .try_concat()
        .await
        .unwrap();
    assert_eq!(returned, bytes);
    serving.abort();
}

#[tokio::test]
async fn source_policy_and_size_mismatches_fail_before_any_lan_send() {
    let pair = Pair::new();
    let fetcher = pair.fetcher();
    let base = pair.request(b"test");
    let node = pair.server.node_id();
    let hash = &base.sha256;
    for url in [
        format!("fsl://user@{node}/{hash}"),
        format!("fsl://{node}:42/{hash}"),
        format!("fsl://{node}/{hash}?next=elsewhere"),
        format!("fsl://{node}/{hash}#fragment"),
        format!("fsl://{node}/{hash}/extra"),
        format!("fsl://{node}/{hash}.bin.extra"),
        format!("fsl://{node}/{}", "a".repeat(64)),
        format!("fsl://{}/{hash}", TransportKey::generate().node_id()),
    ] {
        assert!(
            fetcher
                .fetch(FetchRequest {
                    source: Url::parse(&url).unwrap(),
                    ..base.clone()
                })
                .await
                .is_err()
        );
    }
    assert!(
        fetcher
            .fetch(FetchRequest {
                expected_size: Some(2 * 1024 * 1024 * 1024),
                ..base.clone()
            })
            .await
            .is_err()
    );
    assert!(matches!(
        fetcher
            .fetch(FetchRequest {
                source: Url::parse("https://example.test/blob").unwrap(),
                ..base
            })
            .await,
        Err(FetchError::UnsupportedSource)
    ));
    assert_eq!(pair.client.traffic().sent_datagrams, 0);
}

#[tokio::test]
async fn a_pinned_peer_cannot_complete_a_corrupt_short_extra_or_unterminated_body() {
    for (payload, finish, expected_error) in [
        (b"wrong".as_slice(), true, "digest"),
        (b"sh".as_slice(), true, "truncated"),
        (b"right!".as_slice(), true, "exceeded"),
        (b"right".as_slice(), false, "deadline"),
    ] {
        let pair = Pair::new();
        let server = pair.server.clone();
        let serving = tokio::spawn(async move {
            let session = server.accept().await.unwrap();
            let mut stream = session.accept_stream().await.unwrap();
            let mut request = [0; 37];
            stream.read_exact(&mut request).await.unwrap();
            let mut extra = [0];
            assert_eq!(stream.read(&mut extra).await.unwrap(), 0);
            stream
                .write_all(
                    &ResponseHeader::Ok {
                        size: 5,
                        content_type: None,
                    }
                    .encode(),
                )
                .await
                .unwrap();
            stream.write_all(payload).await.unwrap();
            if finish {
                let _ = stream.finish().await;
            } else {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
        let session = Arc::new(
            pair.client
                .connect(&pair.to_server, pair.server.local_addr().unwrap())
                .await
                .unwrap(),
        );
        let fetched = fetch_blob_over_lan(
            &session,
            Sha256::digest(b"right").into(),
            Some(5),
            LanBlobLimits::new(1024, Duration::from_secs(1)).unwrap(),
        )
        .await
        .unwrap();
        let error = fetched.body.try_collect::<Vec<_>>().await.unwrap_err();
        assert!(error.to_string().contains(expected_error), "{error}");
        serving.abort();
    }
}

#[tokio::test]
async fn the_client_bounds_headers_and_refuses_an_unexpected_declared_size() {
    for header in [
        ResponseHeader::Ok {
            size: 4096,
            content_type: None,
        }
        .encode(),
        ResponseHeader::Ok {
            size: 2,
            content_type: None,
        }
        .encode(),
        vec![0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0], // 256-byte type, before its bytes exist.
        vec![99],
    ] {
        let pair = Pair::new();
        let server = pair.server.clone();
        let serving = tokio::spawn(async move {
            let session = server.accept().await.unwrap();
            let mut stream = session.accept_stream().await.unwrap();
            let mut request = [0; 37];
            stream.read_exact(&mut request).await.unwrap();
            stream.write_all(&header).await.unwrap();
            let _ = stream.finish().await;
        });
        let session = Arc::new(
            pair.client
                .connect(&pair.to_server, pair.server.local_addr().unwrap())
                .await
                .unwrap(),
        );
        assert!(
            fetch_blob_over_lan(
                &session,
                [1; 32],
                Some(1),
                LanBlobLimits::new(1024, Duration::from_secs(1)).unwrap()
            )
            .await
            .is_err()
        );
        serving.abort();
    }
}

#[tokio::test]
async fn a_network_consent_change_refuses_even_buffered_blob_bytes() {
    let pair = Pair::new();
    let bytes = vec![21; 4096];
    let request = pair.request(&bytes);
    let serving = tokio::spawn(serve_lan(
        pair.server.clone(),
        Arc::new(MapBlobSource::new().with_blob(&request.sha256, None, bytes)),
        LanBlobLimits::default(),
    ));
    let mut fetched = pair.fetcher().fetch(request).await.unwrap();
    pair.client.close();
    assert!(fetched.body.try_next().await.is_err());
    serving.abort();
}

#[tokio::test]
async fn a_preread_protocol_prefix_uses_the_existing_admitted_stream() {
    let pair = Pair::new();
    let bytes = b"one held stream";
    let request = pair.request(bytes);
    let source = MapBlobSource::new().with_blob(&request.sha256, None, bytes.as_slice());
    let server = pair.server.clone();
    let serving = tokio::spawn(async move {
        let session = server.accept().await.unwrap();
        let mut stream = session.accept_stream().await.unwrap();
        let mut magic = [0; 4];
        stream.read_exact(&mut magic).await.unwrap();
        assert_eq!(&magic, b"FSLB");
        serve_lan_stream(stream, &source, &magic, LanBlobLimits::default())
            .await
            .unwrap();
    });
    let fetched = pair.fetcher().fetch(request).await.unwrap();
    assert_eq!(
        fetched
            .body
            .map_ok(|chunk| chunk.to_vec())
            .try_concat()
            .await
            .unwrap(),
        bytes
    );
    serving.await.unwrap();
}

#[tokio::test]
async fn request_framing_and_server_limits_precede_source_bytes() {
    let pair = Pair::new();
    let bytes = b"small file";
    let hash = Sha256::digest(bytes).into();
    let source =
        Arc::new(MapBlobSource::new().with_blob(hex::encode(hash), None, bytes.as_slice()));
    let serving = tokio::spawn(serve_lan(
        pair.server.clone(),
        source,
        LanBlobLimits::new(1, Duration::from_secs(1)).unwrap(),
    ));
    let session = Arc::new(
        pair.client
            .connect(&pair.to_server, pair.server.local_addr().unwrap())
            .await
            .unwrap(),
    );
    assert!(matches!(
        fetch_blob_over_lan(&session, hash, None, LanBlobLimits::default()).await,
        Err(FetchError::UnusableStatus(500))
    ));
    let mut stream = session.open_stream().await.unwrap();
    let mut request = Request::new(hash).encode();
    request[4] = 2;
    stream.write_all(&request).await.unwrap();
    stream.finish().await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, ResponseHeader::UnsupportedVersion.encode());
    let mut stream = session.open_stream().await.unwrap();
    stream
        .write_all(&Request::new(hash).encode())
        .await
        .unwrap();
    stream.write_all(b"extra").await.unwrap();
    // The server may stop the malformed request before its FIN is acknowledged.
    let _ = stream.finish().await;
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response).await;
    assert!(response.is_empty());
    serving.abort();
}

// The full storage journey uses the same pinned Shelter Kit version as the
// Wildbloom daemon. Router calls are local, with synthetic external signatures.
use axum::{
    body::Body,
    http::{Request as HttpRequest, StatusCode},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http_body_util::BodyExt;
use nostr::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag, Timestamp};
use shelter_kit::{AppState, BlossomConfig, Store, StoreConfig, router};
use tower::ServiceExt;

fn config(owner: &Keys) -> BlossomConfig {
    BlossomConfig {
        server_metadata: Default::default(),
        public_base_url: Url::parse("https://storage.example.test").unwrap(),
        accepted_server_names: vec!["storage.example.test".into()],
        allowed_pubkeys: vec![owner.public_key().to_hex()],
        friend_grants: vec![],
        open_shelter: false,
        max_concurrent_writes: 2,
        mirror_proxy: None,
    }
}
fn authorization(owner: &Keys, hash: &str, server: &str) -> String {
    let event = EventBuilder::new(Kind::Custom(24242), "synthetic local storage acceptance")
        .tags([
            Tag::parse(["t", "upload"]).unwrap(),
            Tag::parse(["x", hash]).unwrap(),
            Tag::parse(["server", server]).unwrap(),
            Tag::parse([
                "expiration",
                &(Timestamp::now().as_secs() + 120).to_string(),
            ])
            .unwrap(),
        ])
        .finalize(owner)
        .unwrap();
    format!(
        "Nostr {}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&event).unwrap())
    )
}
fn upload(body: Body, size: usize, hash: &str, auth: &str) -> HttpRequest<Body> {
    HttpRequest::builder()
        .method("PUT")
        .uri("/upload")
        .header("content-type", "application/octet-stream")
        .header("content-length", size)
        .header("x-sha-256", hash)
        .header("authorization", auth)
        .body(body)
        .unwrap()
}

#[tokio::test]
async fn signed_upload_from_lan_repairs_after_loss_and_recovers_from_the_restarted_copy() {
    storage_journey(false).await;
}

#[tokio::test]
#[ignore = "requires the Shelter Kit native-mirror candidate via an explicit Cargo patch; see the LAN guide"]
async fn native_bud04_mirror_and_repair_keep_authorisation_and_recover_after_original_loss() {
    storage_journey(true).await;
}

async fn storage_journey(native_mirror: bool) {
    let owner = Keys::parse(&format!("{:064x}", 17)).unwrap();
    let original_dir = tempfile::tempdir().unwrap();
    let replica_dir = tempfile::tempdir().unwrap();
    let original_config = StoreConfig {
        root: original_dir.path().to_path_buf(),
        quota_bytes: 4 * 1024 * 1024,
        max_blob_bytes: 2 * 1024 * 1024,
    };
    let replica_config = StoreConfig {
        root: replica_dir.path().to_path_buf(),
        ..original_config.clone()
    };
    let original = Store::open(original_config).unwrap();
    let replica = Store::open(replica_config.clone()).unwrap();
    let pair = Pair::new();
    let fetcher = Arc::new(pair.fetcher());
    let original_state = AppState::new(original.clone(), config(&owner)).unwrap();
    let replica_state =
        AppState::with_fetcher(replica.clone(), config(&owner), fetcher.clone()).unwrap();
    let bytes = (0..1024 * 1024 + 47)
        .map(|n| (n % 251) as u8)
        .collect::<Vec<_>>();
    let request = pair.request(&bytes);
    let auth = authorization(&owner, &request.sha256, "storage.example.test");
    assert_eq!(
        router(original_state.clone())
            .oneshot(upload(
                Body::from(bytes.clone()),
                bytes.len(),
                &request.sha256,
                &auth
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    let serving = tokio::spawn(serve_lan(
        pair.server.clone(),
        Arc::new(ShelterBlobSource::new(original.clone())),
        LanBlobLimits::default(),
    ));
    let bad_scope = authorization(&owner, &request.sha256, "wrong.example.test");
    let rejected_request = if native_mirror {
        HttpRequest::builder()
            .method("PUT")
            .uri("/mirror")
            .header("content-type", "application/json")
            .header("authorization", &bad_scope)
            .body(Body::from(
                serde_json::json!({ "url": request.source.as_str() }).to_string(),
            ))
            .unwrap()
    } else {
        let fetched = fetcher.fetch(request.clone()).await.unwrap();
        upload(
            Body::from_stream(fetched.body),
            bytes.len(),
            &request.sha256,
            &bad_scope,
        )
    };
    assert_eq!(
        router(replica_state.clone())
            .oneshot(rejected_request)
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(replica.stats().unwrap().blobs, 0);
    if native_mirror {
        assert_eq!(pair.client.traffic().sent_datagrams, 0);
    }
    let accepted_request = if native_mirror {
        HttpRequest::builder()
            .method("PUT")
            .uri("/mirror")
            .header("content-type", "application/json")
            .header("authorization", &auth)
            .body(Body::from(
                serde_json::json!({ "url": request.source.as_str() }).to_string(),
            ))
            .unwrap()
    } else {
        let fetched = fetcher.fetch(request.clone()).await.unwrap();
        upload(
            Body::from_stream(fetched.body),
            bytes.len(),
            &request.sha256,
            &auth,
        )
    };
    assert_eq!(
        router(replica_state.clone())
            .oneshot(accepted_request)
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    if !native_mirror {
        // Only after the complete signed upload verified the bytes does the
        // local controller record its selected source for repair. BUD-04
        // records the verified source inside the router itself.
        replica
            .record_repair_source(&request.sha256, request.source.as_str())
            .unwrap();
    }
    let sources = replica.repair_sources(&request.sha256).unwrap();
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].source_url, request.source.as_str());
    std::fs::remove_file(replica.blob_path(&request.sha256)).unwrap();
    let repair = replica_state.repair_once().await.unwrap();
    assert_eq!(repair.repaired, 1);
    assert_eq!(
        std::fs::read(replica.blob_path(&request.sha256)).unwrap(),
        bytes
    );
    // Stop the original transport and release its store before recovery.
    serving.abort();
    let _ = serving.await;
    pair.server.close();
    drop(original_state);
    drop(original);
    drop(replica_state);
    drop(replica);
    let restarted = Store::open(replica_config).unwrap();
    let recovered_pair = Pair::new();
    let serving = tokio::spawn(serve_lan(
        recovered_pair.server.clone(),
        Arc::new(ShelterBlobSource::new(restarted.clone())),
        LanBlobLimits::default(),
    ));
    let fetched = recovered_pair
        .fetcher()
        .fetch(recovered_pair.request(&bytes))
        .await
        .unwrap();
    assert_eq!(
        fetched
            .body
            .map_ok(|bytes| bytes.to_vec())
            .try_concat()
            .await
            .unwrap(),
        bytes
    );
    let response = router(AppState::new(restarted, config(&owner)).unwrap())
        .oneshot(
            HttpRequest::builder()
                .uri(format!("/{}", request.sha256))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        bytes
    );
    serving.abort();
}
