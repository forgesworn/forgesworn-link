//! The frozen relay-frame and reflector vectors: `vectors/relay-frames.json`
//! and `vectors/reflector.json`.  Every valid entry decodes and re-encodes
//! byte-identically; every hostile entry fails to decode.

use std::net::SocketAddr;
use std::path::PathBuf;

use link_core::wire::{
    Frame, parse_reflect_reply, parse_reflect_request, reflect_reply, reflect_request,
};
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../vectors/{name}"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("cannot parse {}: {e}", path.display()))
}

fn bytes(entry: &Value) -> Vec<u8> {
    hex::decode(entry["bytesHex"].as_str().expect("bytesHex")).expect("hex")
}

#[test]
fn every_valid_relay_frame_decodes_and_reencodes_byte_identically() {
    let v = load("relay-frames.json");
    for entry in v["valid"].as_array().expect("valid") {
        let name = entry["name"].as_str().unwrap();
        let wire = bytes(entry);
        let frame = Frame::decode(&wire).unwrap_or_else(|| panic!("{name}: must decode"));
        assert_eq!(frame.encode(), wire, "{name}: canonical re-encode");
    }
}

#[test]
fn every_hostile_relay_frame_is_rejected() {
    let v = load("relay-frames.json");
    for entry in v["hostile"].as_array().expect("hostile") {
        let name = entry["name"].as_str().unwrap();
        assert_eq!(
            Frame::decode(&bytes(entry)),
            None,
            "{name}: must not decode"
        );
    }
}

#[test]
fn reflector_vectors_match_and_hostile_forms_are_dropped() {
    let v = load("reflector.json");

    let nonce: [u8; 16] = hex::decode(v["request"]["nonceHex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let request = bytes(&v["request"]);
    assert_eq!(reflect_request(&nonce).to_vec(), request);
    assert_eq!(parse_reflect_request(&request), Some(nonce));

    let observed: SocketAddr = v["reply"]["observed"].as_str().unwrap().parse().unwrap();
    let reply = bytes(&v["reply"]);
    assert_eq!(reflect_reply(&nonce, observed).to_vec(), reply);
    let (echoed, parsed) = parse_reflect_reply(&reply).expect("reply parses");
    assert_eq!(echoed, nonce);
    assert_eq!(link_core::card::unmap_ipv6(parsed), observed);

    for entry in v["hostile"].as_array().expect("hostile") {
        let name = entry["name"].as_str().unwrap();
        let wire = bytes(entry);
        assert!(
            parse_reflect_request(&wire).is_none() && parse_reflect_reply(&wire).is_none(),
            "{name}: must parse as neither request nor reply"
        );
    }
}
