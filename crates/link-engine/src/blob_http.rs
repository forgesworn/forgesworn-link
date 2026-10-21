//! Existing Blossom operations over a pinned, authenticated Link session.
//! The box's Full-peer policy authorises remote reads; writes still need BUD
//! authorisation. A media label does not establish that a caller encrypted data.

use std::sync::Arc;

use bytes::Bytes;
use hyper::body::Body;
use hyper::header::{
    CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, TRANSFER_ENCODING,
};
use hyper::{Method, Response, StatusCode};
use sha2::{Digest, Sha256};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::{
    EngineError, HttpRoute, MAX_DISCARDED_REFUSAL_BYTES, MAX_HTTP_BODY_BYTES, RequestBody,
    ResponseBody, collect_bounded, lower_hex_32,
};

/// Ciphertext limit matching Bothy's default, not a plaintext or device-memory
/// guarantee. One request per engine bounds its in-flight file buffers.
pub const MAX_BLOB_BYTES: usize = 64 * 1024 * 1024;
pub const LEGACY_ENCRYPTED_MEDIA_TYPE: &str = "application/vnd.forgesworn.encrypted";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlobResponse {
    Upload,
    Download([u8; 32]),
    Delete,
}

/// A non-cloneable reservation, taken before a browser copies file bytes.
/// The transport driver retains its private guard until cancellation settles.
pub struct FileRequestPermit {
    pub(super) guard: Arc<FileRequestGuard>,
}

pub(super) struct FileRequestGuard {
    pub(super) gate: Arc<Semaphore>,
    _permit: OwnedSemaphorePermit,
}

impl FileRequestPermit {
    pub(super) fn acquire(gate: &Arc<Semaphore>) -> Result<Self, EngineError> {
        let permit = gate
            .clone()
            .try_acquire_owned()
            .map_err(|_| EngineError::Route("another file request is still active".into()))?;
        Ok(Self {
            guard: Arc::new(FileRequestGuard {
                gate: gate.clone(),
                _permit: permit,
            }),
        })
    }
}

pub(super) fn route(method: &Method, path: &str) -> Option<HttpRoute> {
    let (body, max_body_bytes, authorization, response, max_response_bytes) =
        if *method == Method::PUT && path == "/upload" {
            (
                RequestBody::Octets,
                MAX_BLOB_BYTES,
                true,
                BlobResponse::Upload,
                MAX_HTTP_BODY_BYTES,
            )
        } else {
            let hash = path.strip_prefix('/')?;
            if !lower_hex_32(hash) {
                return None;
            }
            let mut digest = [0; 32];
            hex::decode_to_slice(hash, &mut digest).ok()?;
            match *method {
                Method::GET => (
                    RequestBody::Empty,
                    0,
                    false,
                    BlobResponse::Download(digest),
                    MAX_BLOB_BYTES,
                ),
                Method::DELETE => (
                    RequestBody::Empty,
                    0,
                    true,
                    BlobResponse::Delete,
                    MAX_HTTP_BODY_BYTES,
                ),
                _ => return None,
            }
        };
    Some(HttpRoute {
        body,
        max_body_bytes,
        nostr_authorization: authorization,
        response: ResponseBody::Blob(response),
        max_response_bytes,
    })
}

fn one_header(
    headers: &hyper::HeaderMap,
    name: hyper::header::HeaderName,
) -> Result<Option<&str>, EngineError> {
    let mut values = headers.get_all(name).iter();
    match (values.next(), values.next()) {
        (None, None) => Ok(None),
        (Some(value), None) => value
            .to_str()
            .map(Some)
            .map_err(|_| EngineError::Route("file response header is not text".into())),
        _ => Err(EngineError::Route(
            "file response header is ambiguous".into(),
        )),
    }
}

pub(super) async fn decode<B>(
    response: Response<B>,
    kind: BlobResponse,
) -> Result<(u16, Vec<u8>), EngineError>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let status = response.status();
    if !status.is_success() {
        collect_bounded(
            response.into_body(),
            MAX_DISCARDED_REFUSAL_BYTES,
            "file refusal",
        )
        .await?;
        return Ok((status.as_u16(), Vec::new()));
    }
    let valid_status = match kind {
        BlobResponse::Upload => matches!(status, StatusCode::OK | StatusCode::CREATED),
        _ => status == StatusCode::OK,
    };
    if !valid_status {
        return Err(EngineError::Route("unexpected file response status".into()));
    }
    let headers = response.headers();
    if headers.contains_key(CONTENT_RANGE) {
        return Err(EngineError::Route(
            "file response must not contain a range".into(),
        ));
    }
    if one_header(headers, CONTENT_ENCODING)?
        .is_some_and(|value| !value.eq_ignore_ascii_case("identity"))
    {
        return Err(EngineError::Route(
            "file response must not be encoded".into(),
        ));
    }
    let media = one_header(headers, CONTENT_TYPE)?
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if let BlobResponse::Download(expected_hash) = kind {
        if media != LEGACY_ENCRYPTED_MEDIA_TYPE && media != "application/octet-stream" {
            return Err(EngineError::Route(
                "file response is not encrypted or opaque bytes".into(),
            ));
        }
        if headers.contains_key(TRANSFER_ENCODING) {
            return Err(EngineError::Route(
                "file response must use an exact length".into(),
            ));
        }
        let length_text = one_header(headers, CONTENT_LENGTH)?
            .ok_or_else(|| EngineError::Route("file response has no length".into()))?;
        if length_text.is_empty() || !length_text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(EngineError::Route("file response length is invalid".into()));
        }
        let length: usize = length_text
            .parse()
            .map_err(|_| EngineError::Route("file response length is invalid".into()))?;
        if length.to_string() != length_text {
            return Err(EngineError::Route(
                "file response length is not canonical".into(),
            ));
        }
        if length > MAX_BLOB_BYTES {
            return Err(EngineError::Route("file response is too large".into()));
        }
        let body = collect_bounded(response.into_body(), length, "file response").await?;
        if body.len() != length || <[u8; 32]>::from(Sha256::digest(&body)) != expected_hash {
            return Err(EngineError::Route(
                "file response length or digest does not match".into(),
            ));
        }
        Ok((status.as_u16(), body.to_vec()))
    } else {
        if media != "application/json" {
            return Err(EngineError::Route("file result is not JSON".into()));
        }
        let body =
            collect_bounded(response.into_body(), MAX_HTTP_BODY_BYTES, "file result").await?;
        Ok((status.as_u16(), body.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Engine, EngineConfig, JsonRequest, outgoing_http_request, validate_http_request,
        validate_http_request_length,
    };
    use http_body_util::Full;

    const HASH: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    fn request(method: &str, path: &str, auth: &str, body: &[u8]) -> JsonRequest {
        JsonRequest {
            route_id: "selected".into(),
            method: method.into(),
            path: path.into(),
            authorization: auth.into(),
            body: body.to_vec(),
        }
    }

    fn response(status: u16, media: &str, body: &'static [u8]) -> Response<Full<Bytes>> {
        Response::builder()
            .status(status)
            .header(CONTENT_TYPE, media)
            .header(CONTENT_LENGTH, body.len())
            .body(Full::new(Bytes::from_static(body)))
            .unwrap()
    }

    fn download_route() -> HttpRoute {
        validate_http_request(&request("GET", &format!("/{HASH}"), "", b""))
            .unwrap()
            .1
    }

    #[test]
    fn file_http_paths_methods_authorisation_and_body_sizes_are_exact() {
        for (method, path, auth, body) in [
            ("GET", format!("/{HASH}"), "", b"".as_slice()),
            ("DELETE", format!("/{HASH}"), "Nostr YQ==", b"".as_slice()),
            ("PUT", "/upload".into(), "Nostr YQ==", b"hello".as_slice()),
        ] {
            assert!(validate_http_request(&request(method, &path, auth, body)).is_ok());
        }
        for path in [
            format!("/{HASH}/"),
            format!("//{HASH}"),
            format!("/{HASH}.bin"),
            format!("/{HASH}?x=1"),
            format!("/{HASH}#x"),
            format!("/{}", HASH.to_uppercase()),
            format!("/{}%34", &HASH[..63]),
            format!("https://elsewhere/{HASH}"),
        ] {
            assert!(
                validate_http_request(&request("GET", &path, "", b"")).is_err(),
                "{path}"
            );
        }
        for method in ["GET", "POST", "DELETE"] {
            assert!(
                validate_http_request(&request(method, "/upload", "Nostr YQ==", b"hello")).is_err()
            );
        }
        assert!(
            validate_http_request(&request("GET", &format!("/{HASH}"), "Nostr YQ==", b"")).is_err()
        );
        assert!(validate_http_request(&request("GET", &format!("/{HASH}"), "", b"x")).is_err());
        let upload = request("PUT", "/upload", "Nostr YQ==", b"");
        assert!(validate_http_request_length(&upload, MAX_BLOB_BYTES).is_ok());
        assert!(validate_http_request_length(&upload, MAX_BLOB_BYTES + 1).is_err());
        assert!(validate_http_request_length(&upload, 0).is_err());
    }

    #[tokio::test]
    async fn file_http_upload_headers_and_bytes_are_derived_from_the_pinned_request() {
        let input = request("PUT", "/upload", "Nostr YQ==", b"hello");
        let (method, route) = validate_http_request(&input).unwrap();
        let node = link_core::NodeId([3; 32]);
        let outgoing = outgoing_http_request(input, method, &route, node).unwrap();
        assert_eq!(outgoing.uri(), "/upload");
        assert_eq!(outgoing.headers()[hyper::header::HOST], node.to_base32());
        assert_eq!(outgoing.headers()[CONTENT_TYPE], "application/octet-stream");
        assert_eq!(outgoing.headers()[CONTENT_LENGTH], "5");
        assert_eq!(outgoing.headers()["x-sha-256"], HASH);
        assert_eq!(
            outgoing.headers()[hyper::header::AUTHORIZATION],
            "Nostr YQ=="
        );
        assert_eq!(
            http_body_util::BodyExt::collect(outgoing.into_body())
                .await
                .unwrap()
                .to_bytes(),
            b"hello".as_slice()
        );
    }

    #[tokio::test]
    async fn file_http_download_verifies_status_type_framing_length_and_requested_hash() {
        let route = download_route();
        for media in [LEGACY_ENCRYPTED_MEDIA_TYPE, "application/octet-stream"] {
            assert_eq!(
                crate::decode_http_response(response(200, media, b"hello"), &route)
                    .await
                    .unwrap(),
                (200, b"hello".to_vec())
            );
        }
        for status in [201, 204, 206, 301, 302, 307, 308] {
            assert!(
                crate::decode_http_response(
                    response(status, LEGACY_ENCRYPTED_MEDIA_TYPE, b"hello"),
                    &route
                )
                .await
                .is_err(),
                "{status}"
            );
        }
        for media in ["application/json", "text/html", ""] {
            assert!(
                crate::decode_http_response(response(200, media, b"hello"), &route)
                    .await
                    .is_err()
            );
        }
        for (header, value) in [
            (CONTENT_RANGE, "bytes 0-4/5"),
            (CONTENT_ENCODING, "gzip"),
            (TRANSFER_ENCODING, "chunked"),
            (CONTENT_LENGTH, "4"),
            (CONTENT_LENGTH, "6"),
            (CONTENT_LENGTH, "+5"),
            (CONTENT_LENGTH, "0005"),
            (CONTENT_LENGTH, "5, 5"),
        ] {
            let mut reply = response(200, LEGACY_ENCRYPTED_MEDIA_TYPE, b"hello");
            reply.headers_mut().insert(header, value.parse().unwrap());
            assert!(
                crate::decode_http_response(reply, &route).await.is_err(),
                "{value}"
            );
        }
        let mut missing = response(200, LEGACY_ENCRYPTED_MEDIA_TYPE, b"hello");
        missing.headers_mut().remove(CONTENT_LENGTH);
        assert!(crate::decode_http_response(missing, &route).await.is_err());
        let mut duplicate = response(200, LEGACY_ENCRYPTED_MEDIA_TYPE, b"hello");
        duplicate
            .headers_mut()
            .append(CONTENT_LENGTH, "5".parse().unwrap());
        assert!(
            crate::decode_http_response(duplicate, &route)
                .await
                .is_err()
        );
        let mut oversized = response(200, LEGACY_ENCRYPTED_MEDIA_TYPE, b"");
        oversized.headers_mut().insert(
            CONTENT_LENGTH,
            (MAX_BLOB_BYTES + 1).to_string().parse().unwrap(),
        );
        assert!(
            crate::decode_http_response(oversized, &route)
                .await
                .unwrap_err()
                .to_string()
                .contains("too large")
        );
        assert!(
            crate::decode_http_response(
                response(200, LEGACY_ENCRYPTED_MEDIA_TYPE, b"jello"),
                &route
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn file_http_refusals_never_get_the_file_success_body_budget() {
        for route in [
            download_route(),
            route(&Method::PUT, "/upload").unwrap(),
            route(&Method::DELETE, &format!("/{HASH}")).unwrap(),
        ] {
            for status in [401, 403, 404, 413, 429, 500, 507] {
                for media in [
                    "application/json",
                    "application/octet-stream",
                    LEGACY_ENCRYPTED_MEDIA_TYPE,
                ] {
                    let reply = Response::builder()
                        .status(status)
                        .header(CONTENT_TYPE, media)
                        .body(Full::new(Bytes::from(vec![
                            0;
                            MAX_DISCARDED_REFUSAL_BYTES + 1
                        ])))
                        .unwrap();
                    assert!(crate::decode_http_response(reply, &route).await.is_err());
                    assert_eq!(
                        crate::decode_http_response(response(status, media, b"refused"), &route)
                            .await
                            .unwrap(),
                        (status, Vec::new())
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn file_http_write_success_statuses_are_not_interchangeable() {
        let upload = route(&Method::PUT, "/upload").unwrap();
        let delete = route(&Method::DELETE, &format!("/{HASH}")).unwrap();
        for status in [200, 201] {
            assert!(
                crate::decode_http_response(response(status, "application/json", b"{}"), &upload)
                    .await
                    .is_ok()
            );
        }
        assert!(
            crate::decode_http_response(response(200, "application/json", b"{}"), &delete)
                .await
                .is_ok()
        );
        for status in [201, 202, 204, 206] {
            assert!(
                crate::decode_http_response(response(status, "application/json", b"{}"), &delete)
                    .await
                    .is_err()
            );
        }
        assert!(
            crate::decode_http_response(response(204, "application/json", b"{}"), &upload)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn file_http_reservations_are_exclusive_and_cannot_cross_engines_or_request_types() {
        async fn engine(seed: u8) -> Engine {
            Engine::start(EngineConfig {
                transport_seed: vec![seed; 32],
                relay_urls: Vec::new(),
                allow_direct: false,
                routes: Vec::new(),
            })
            .await
            .unwrap()
        }
        let first = engine(2).await;
        let other = engine(3).await;
        let permit = first.reserve_file_request().unwrap();
        assert!(first.reserve_file_request().is_err());
        let upload = request("PUT", "/upload", "Nostr YQ==", b"hello");
        assert!(
            other
                .request_json_reserved(upload, std::time::Duration::from_secs(1), Some(permit))
                .await
                .unwrap_err()
                .to_string()
                .contains("reservation")
        );
        let permit = first.reserve_file_request().unwrap();
        let nonfile = request("POST", "/cadence/v1/status", "Nostr YQ==", b"{}");
        assert!(
            first
                .request_json_reserved(nonfile, std::time::Duration::from_secs(1), Some(permit))
                .await
                .unwrap_err()
                .to_string()
                .contains("reservation")
        );
        let upload = request("PUT", "/upload", "Nostr YQ==", b"hello");
        assert!(
            first
                .request_json_reserved(upload, std::time::Duration::from_secs(1), None)
                .await
                .unwrap_err()
                .to_string()
                .contains("reservation")
        );
        first.stop().await;
        other.stop().await;
        assert!(matches!(
            first.reserve_file_request(),
            Err(EngineError::Stopped)
        ));
    }
}
