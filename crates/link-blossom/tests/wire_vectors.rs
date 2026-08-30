//! The frozen FSLB vectors, `vectors/fslb.json`.  The request and every
//! response header decode and re-encode byte-identically; hostile entries fail
//! with the stated class.

use std::path::PathBuf;

use link_blossom::wire::{Request, ResponseHeader, WireError};
use serde_json::Value;

fn load() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/fslb.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("cannot parse {}: {e}", path.display()))
}

fn bytes(entry: &Value) -> Vec<u8> {
    hex::decode(entry["bytesHex"].as_str().expect("bytesHex")).expect("hex")
}

#[test]
fn the_request_vector_round_trips() {
    let v = load();
    let wire = bytes(&v["request"]);
    let sha256: [u8; 32] = hex::decode(v["request"]["sha256Hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let request = Request::decode(&wire).expect("decodes");
    assert_eq!(request.sha256, sha256);
    assert_eq!(Request::new(sha256).encode().to_vec(), wire);
}

#[test]
fn every_response_vector_round_trips() {
    let v = load();
    for entry in v["responses"].as_array().expect("responses") {
        let name = entry["name"].as_str().unwrap();
        let wire = bytes(entry);
        let (header, consumed) = ResponseHeader::decode(&wire)
            .unwrap_or_else(|e| panic!("{name}: must decode, got {e}"));
        assert_eq!(consumed, wire.len(), "{name}: consumes the whole header");
        assert_eq!(header.encode(), wire, "{name}: canonical re-encode");
        match &header {
            ResponseHeader::Ok { size, content_type } => {
                assert_eq!(Some(*size), entry["size"].as_u64(), "{name}: size");
                assert_eq!(
                    content_type.as_deref(),
                    entry["contentType"].as_str(),
                    "{name}: content type"
                );
            }
            ResponseHeader::NotFound => assert_eq!(name, "not-found"),
            ResponseHeader::Error => assert_eq!(name, "error"),
            ResponseHeader::UnsupportedVersion => assert_eq!(name, "unsupported-version"),
        }
    }
}

#[test]
fn every_hostile_vector_fails_with_the_stated_class() {
    let v = load();
    for entry in v["hostile"].as_array().expect("hostile") {
        let name = entry["name"].as_str().unwrap();
        let wire = bytes(entry);
        match name {
            "request-bad-magic" => {
                assert_eq!(Request::decode(&wire), Err(WireError::BadMagic), "{name}")
            }
            "request-future-version" => {
                assert_eq!(
                    Request::decode(&wire),
                    Err(WireError::BadVersion(0x02)),
                    "{name}: the server answers status 0x03 to this"
                )
            }
            "request-short" => {
                assert!(
                    matches!(Request::decode(&wire), Err(WireError::Short { .. })),
                    "{name}"
                )
            }
            "response-bad-status" => {
                assert_eq!(
                    ResponseHeader::decode(&wire),
                    Err(WireError::BadStatus(0x09)),
                    "{name}"
                )
            }
            "response-content-type-too-long" => {
                assert_eq!(
                    ResponseHeader::decode(&wire),
                    Err(WireError::ContentTypeTooLong(300)),
                    "{name}"
                )
            }
            "response-truncated-content-type" => {
                assert!(
                    matches!(ResponseHeader::decode(&wire), Err(WireError::Short { .. })),
                    "{name}"
                )
            }
            other => panic!("unknown hostile vector {other}: add an assertion for it"),
        }
    }
}
