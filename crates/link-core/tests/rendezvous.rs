//! The frozen rendezvous known-answer vectors of docs/RENDEZVOUS.md section 5.
//! Every intermediate and all six tags must reproduce byte-for-byte.

use std::path::PathBuf;

use link_core::rendezvous::{
    EPOCH_SECONDS, TAG_BYTES, TagCase, derive_tag, ecdh_x, epoch_index, valid_compressed_point,
};
use serde_json::Value;

fn load() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/rendezvous.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("cannot parse {}: {e}", path.display()))
}

fn hex32(value: &Value, pointer: &str) -> [u8; 32] {
    let text = value
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing {pointer}"));
    hex::decode(text).unwrap().try_into().unwrap()
}

fn hex33(value: &Value, pointer: &str) -> [u8; 33] {
    let text = value
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing {pointer}"));
    hex::decode(text).unwrap().try_into().unwrap()
}

#[test]
fn constants_match_the_frozen_vectors() {
    let v = load();
    assert_eq!(v["epochSeconds"].as_u64(), Some(EPOCH_SECONDS));
    assert_eq!(v["tagBytes"].as_u64(), Some(TAG_BYTES as u64));
    assert_eq!(
        v["saltUtf8"].as_str(),
        Some("forgesworn-link/rendezvous/v1")
    );
    assert_eq!(epoch_index(1_793_588_888), 498_219, "floor() case");
    assert_eq!(
        epoch_index(v["epochUnix"].as_u64().unwrap()),
        v["epochIndex"].as_u64().unwrap()
    );
}

#[test]
fn intermediates_reproduce_and_are_symmetric() {
    let v = load();
    let nostr_a = hex32(&v, "/testOnlyKeys/nostrAPrivHex");
    let nostr_b = hex32(&v, "/testOnlyKeys/nostrBPrivHex");
    let nostr_a_pub = hex33(&v, "/testOnlyKeys/nostrAPubCompressedHex");
    let nostr_b_pub = hex33(&v, "/testOnlyKeys/nostrBPubCompressedHex");
    let eph_a = hex32(&v, "/testOnlyKeys/ephAPrivHex");
    let eph_b = hex32(&v, "/testOnlyKeys/ephBPrivHex");
    let eph_a_pub = hex33(&v, "/testOnlyKeys/ephAPubCompressedHex");
    let eph_b_pub = hex33(&v, "/testOnlyKeys/ephBPubCompressedHex");

    for public in [&nostr_a_pub, &nostr_b_pub, &eph_a_pub, &eph_b_pub] {
        assert!(valid_compressed_point(public.as_slice()));
    }

    let static_x = ecdh_x(&nostr_a, &nostr_b_pub).expect("static ECDH");
    assert_eq!(static_x, hex32(&v, "/intermediates/staticXHex"));
    assert_eq!(
        static_x,
        ecdh_x(&nostr_b, &nostr_a_pub).unwrap(),
        "symmetry"
    );

    let eph_both_x = ecdh_x(&eph_a, &eph_b_pub).expect("both-ephemeral ECDH");
    assert_eq!(eph_both_x, hex32(&v, "/intermediates/ephBothXHex"));
    assert_eq!(eph_both_x, ecdh_x(&eph_b, &eph_a_pub).unwrap(), "symmetry");

    let eph_one_x = ecdh_x(&eph_a, &nostr_b_pub).expect("one-sided ECDH");
    assert_eq!(eph_one_x, hex32(&v, "/intermediates/ephOneXHex"));
    assert_eq!(eph_one_x, ecdh_x(&nostr_b, &eph_a_pub).unwrap(), "symmetry");
}

#[test]
fn all_six_tags_reproduce() {
    let v = load();
    let static_x = hex32(&v, "/intermediates/staticXHex");
    let eph_both_x = hex32(&v, "/intermediates/ephBothXHex");
    let eph_one_x = hex32(&v, "/intermediates/ephOneXHex");
    let zeros = [0u8; 32];
    let default_host = v["relayHost"].as_str().unwrap();

    let cases = v["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 6, "six frozen cases");
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let tag_case = TagCase::from_byte(case["caseByte"].as_u64().unwrap() as u8)
            .unwrap_or_else(|| panic!("{name}: bad case byte"));
        let eph_x = match tag_case {
            TagCase::Both => &eph_both_x,
            TagCase::One => &eph_one_x,
            TagCase::None => &zeros,
        };
        let host = case["relayHost"].as_str().unwrap_or(default_host);
        let epoch = case["epochIndex"].as_u64().unwrap();
        let derived = derive_tag(tag_case, &static_x, eph_x, host, epoch);
        assert_eq!(
            hex::encode(derived.0),
            case["tagHex"].as_str().unwrap(),
            "{name}"
        );
    }
}

#[test]
fn rejects_an_invalid_point() {
    // 0x04-prefixed (uncompressed marker) and a not-on-curve x both fail.
    assert!(!valid_compressed_point(&[0x04; 33]));
    let mut bad = [0x02u8; 33];
    bad[1..].fill(0xff);
    assert!(!valid_compressed_point(&bad));
    assert!(!valid_compressed_point(&[0x02; 32]));
}

#[test]
fn rejects_the_sec1_compact_spelling_of_a_real_point() {
    // Tag 0x05 (SEC1 compact, even-Y) parses in a bare from_sec1_bytes call
    // and carries a genuine on-curve x, so this is the regression case: one
    // point must have exactly one spelling inside signed card bytes.
    let v = load();
    let mut compact = hex33(&v, "/testOnlyKeys/nostrAPubCompressedHex");
    compact[0] = 0x05;
    assert!(!valid_compressed_point(&compact));
    let scalar = hex32(&v, "/testOnlyKeys/nostrBPrivHex");
    assert_eq!(ecdh_x(&scalar, &compact), None, "ecdh_x refuses it too");
}

#[test]
fn a_compact_spelling_in_a_card_fails_rule_three() {
    use link_core::card::{Card, HINT_EPHEMERAL, Hint, VerifyContext};
    use link_core::id::TransportKey;
    let v = load();
    let mut compact = hex33(&v, "/testOnlyKeys/nostrAPubCompressedHex");
    compact[0] = 0x05;
    let key = TransportKey::generate();
    let card = Card::sign(
        &key,
        1_000,
        2_000,
        1,
        vec![Hint {
            kind: HINT_EPHEMERAL,
            value: compact.to_vec(),
        }],
    );
    let err = Card::verify(card.as_bytes(), &VerifyContext::new(1_000))
        .expect_err("a compact ephemeral spelling fails the whole card");
    assert_eq!(err.rule, 3, "refused under the hint rule: {err}");
}
