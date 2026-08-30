//! The frozen vectors are the contract.  These tests load them from
//! `vectors/` beside the workspace root and must never be relaxed.

use std::path::PathBuf;

use link_core::card::{Card, VerifyContext};
use link_core::id::{NodeId, TransportKey, node_id_from_spki};
use link_core::wire::{Probe, sign_relay_auth, verify_relay_auth};
use serde_json::Value;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors")
}

fn load(name: &str) -> Value {
    let path = vectors_dir().join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("cannot parse {}: {e}", path.display()))
}

fn hex_field(value: &Value, key: &str) -> Vec<u8> {
    hex::decode(
        value[key]
            .as_str()
            .unwrap_or_else(|| panic!("missing {key}")),
    )
    .expect("hex")
}

fn node_a() -> TransportKey {
    let meta = load("meta.json");
    let seed: [u8; 32] = hex_field(&meta["keys"]["node_a"], "seed_hex")
        .try_into()
        .unwrap();
    TransportKey::from_seed(seed)
}

fn node_b() -> TransportKey {
    let meta = load("meta.json");
    let seed: [u8; 32] = hex_field(&meta["keys"]["node_b"], "seed_hex")
        .try_into()
        .unwrap();
    TransportKey::from_seed(seed)
}

#[test]
fn meta_keys_derive_the_stated_node_ids() {
    let meta = load("meta.json");
    for (name, key) in [("node_a", node_a()), ("node_b", node_b())] {
        let entry = &meta["keys"][name];
        assert_eq!(
            key.node_id().to_hex(),
            entry["node_id_hex"].as_str().unwrap(),
            "{name} hex"
        );
        assert_eq!(
            key.node_id().to_base32(),
            entry["node_id_base32"].as_str().unwrap(),
            "{name} base32"
        );
        assert_eq!(key.node_id().to_base32().len(), 52, "{name} base32 length");
        assert_eq!(
            NodeId::from_base32(&key.node_id().to_base32()).unwrap(),
            key.node_id(),
            "{name} base32 round trip"
        );
    }
}

#[test]
fn card_valid_vectors_accept_and_reencode_byte_identically() {
    let vectors = load("card-valid.json");
    let entries = vectors.as_array().expect("array");
    assert!(!entries.is_empty());
    for entry in entries {
        let name = entry["name"].as_str().unwrap();
        let bytes = hex_field(entry, "card_hex");
        let ctx = VerifyContext {
            now: entry["now"].as_u64().unwrap(),
            highest_seen_serial: entry["highest_seen_serial"].as_u64().unwrap(),
            expected_node_id: entry["expected_node_id"]
                .as_str()
                .map(|s| NodeId::from_hex(s).unwrap()),
        };
        let card =
            Card::verify(&bytes, &ctx).unwrap_or_else(|e| panic!("{name} should accept, got {e}"));

        assert_eq!(
            card.as_bytes(),
            bytes.as_slice(),
            "{name} re-encodes byte-identically"
        );
        assert_eq!(
            card.signing_input(),
            hex_field(entry, "signing_input_hex"),
            "{name} input"
        );
        assert_eq!(
            card.signature().to_vec(),
            hex_field(entry, "signature_hex"),
            "{name} sig"
        );
        assert_eq!(
            card.hints.len() as u64,
            entry["hints"].as_u64().unwrap(),
            "{name} hints"
        );

        // Signing the same inputs afresh must reproduce the frozen bytes exactly.
        let resigned = Card::sign(
            &node_a(),
            card.issued_at,
            card.expires_at,
            card.serial,
            card.hints.clone(),
        );
        assert_eq!(
            resigned.as_bytes(),
            bytes.as_slice(),
            "{name} re-signs identically"
        );
    }
}

#[test]
fn card_hostile_vectors_report_exactly_the_stated_rule() {
    let vectors = load("card-hostile.json");
    let entries = vectors.as_array().expect("array");
    assert!(!entries.is_empty());
    let mut seen_rules = std::collections::BTreeSet::new();
    for entry in entries {
        let name = entry["name"].as_str().unwrap();
        let expected_rule = entry["rule"].as_u64().unwrap() as u8;
        seen_rules.insert(expected_rule);
        let bytes = hex_field(entry, "card_hex");
        let ctx = VerifyContext {
            now: entry["now"].as_u64().unwrap(),
            highest_seen_serial: entry["highest_seen_serial"].as_u64().unwrap(),
            expected_node_id: entry["expected_node_id"]
                .as_str()
                .map(|s| NodeId::from_hex(s).unwrap()),
        };
        match Card::verify(&bytes, &ctx) {
            Ok(_) => panic!("{name} should reject with rule {expected_rule}, it accepted"),
            Err(violation) => assert_eq!(
                violation.rule, expected_rule,
                "{name} should report rule {expected_rule}, reported {} ({})",
                violation.rule, violation.detail
            ),
        }
    }
    assert_eq!(
        seen_rules.into_iter().collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
        "every rule of spec 2.3 has at least one fixture"
    );
}

#[test]
fn spki_and_synthetic_address_match_the_vector() {
    let vector = load("spki.json");
    let node_id = NodeId::from_hex(vector["node_id_hex"].as_str().unwrap()).unwrap();
    let der = hex_field(&vector, "spki_der_hex");

    assert_eq!(node_id.spki_der().to_vec(), der, "SPKI DER");
    assert_eq!(node_id_from_spki(&der), Some(node_id), "SPKI round trip");
    assert_eq!(
        vector["key_offset"].as_u64().unwrap() as usize,
        12,
        "key offset within the SPKI"
    );
    assert_eq!(
        &der[12..12 + 32],
        node_id.as_bytes(),
        "key bytes at the stated offset"
    );

    let addr = node_id.synthetic_addr();
    assert_eq!(
        addr.port(),
        vector["synthetic_port"].as_u64().unwrap() as u16
    );
    let expected: std::net::Ipv6Addr = vector["synthetic_ipv6"].as_str().unwrap().parse().unwrap();
    assert_eq!(addr.ip(), std::net::IpAddr::V6(expected), "synthetic IPv6");
}

#[test]
fn the_self_signed_leaf_carries_the_node_id_as_its_spki() {
    let key = node_a();
    let leaf = link_core::tls::node_certificate(&key).expect("leaf");
    assert_eq!(
        link_core::id::node_id_from_cert_der(leaf.cert_der.as_ref()),
        Some(key.node_id()),
        "the leaf SPKI is the node ID"
    );
}

#[test]
fn relay_auth_vector_matches() {
    let vector = load("relay-auth.json");
    let key = node_a();
    let host = vector["relay_host"].as_str().unwrap();
    let challenge: [u8; 32] = hex_field(&vector, "challenge_hex").try_into().unwrap();

    assert_eq!(
        key.node_id().to_hex(),
        vector["node_id_hex"].as_str().unwrap()
    );
    assert_eq!(
        link_core::wire::relay_auth_signing_input(host, &challenge),
        hex_field(&vector, "signing_input_hex"),
        "relay auth signing input"
    );
    let signature = sign_relay_auth(&key, host, &challenge);
    assert_eq!(
        signature.to_vec(),
        hex_field(&vector, "signature_hex"),
        "relay auth signature"
    );
    assert!(verify_relay_auth(
        &key.node_id(),
        host,
        &challenge,
        &signature
    ));
    assert!(
        !verify_relay_auth(&key.node_id(), "other.example", &challenge, &signature),
        "a captured handshake must not replay to another relay"
    );
}

#[test]
fn probe_vectors_match() {
    let vector = load("probe.json");
    let a = node_a();
    let b = node_b();

    for (name, kind, signer, sender, receiver) in [
        (
            "ping",
            link_core::wire::PROBE_PING,
            &a,
            a.node_id(),
            b.node_id(),
        ),
        (
            "pong",
            link_core::wire::PROBE_PONG,
            &b,
            b.node_id(),
            a.node_id(),
        ),
    ] {
        let entry = &vector[name];
        let body = hex_field(entry, "bytes_hex");
        let nonce: [u8; 16] = body[69..85].try_into().unwrap();
        let probe = Probe {
            kind,
            sender,
            receiver,
            nonce,
        };

        assert_eq!(probe.body().to_vec(), body, "{name} body");
        assert_eq!(
            probe.signing_input(),
            hex_field(entry, "signing_input_hex"),
            "{name} input"
        );
        let wire = probe.sign(signer);
        assert_eq!(
            wire[85..].to_vec(),
            hex_field(entry, "signature_hex"),
            "{name} signature"
        );
        assert_eq!(wire.to_vec(), hex_field(entry, "wire_hex"), "{name} wire");
        assert_eq!(Probe::parse_verified(&wire), Some(probe), "{name} verifies");

        let mut tampered = wire;
        tampered[70] ^= 0x01;
        assert_eq!(
            Probe::parse_verified(&tampered),
            None,
            "{name} tampered nonce rejects"
        );
    }
}

#[test]
fn relay_frames_round_trip_and_bound_datagrams() {
    use link_core::wire::{Frame, MAX_DATAGRAM};
    let a = node_a().node_id();
    let frames = vec![
        Frame::Challenge([7u8; 32]),
        Frame::Auth {
            node_id: a,
            signature: [9u8; 64],
        },
        Frame::Welcome([3u8; 16]),
        Frame::Send {
            destination: a,
            datagram: vec![1, 2, 3],
        },
        Frame::Recv {
            source: a,
            datagram: vec![4; MAX_DATAGRAM],
        },
        Frame::Ping([1u8; 8]),
        Frame::Pong([2u8; 8]),
        Frame::Close(1),
    ];
    for frame in frames {
        let bytes = frame.encode();
        assert_eq!(
            Frame::decode(&bytes),
            Some(frame.clone()),
            "round trip {frame:?}"
        );
    }

    let oversize = Frame::Send {
        destination: a,
        datagram: vec![0; MAX_DATAGRAM + 1],
    }
    .encode();
    assert_eq!(
        Frame::decode(&oversize),
        None,
        "oversize datagram is malformed"
    );
    let empty = Frame::Send {
        destination: a,
        datagram: Vec::new(),
    }
    .encode();
    assert_eq!(Frame::decode(&empty), None, "empty datagram is malformed");
    assert_eq!(
        Frame::decode(&[0xee, 0x00]),
        None,
        "unknown tag is malformed"
    );
    assert_eq!(Frame::decode(&[]), None, "empty frame is malformed");
}

#[test]
fn reflector_messages_round_trip() {
    use link_core::wire::{
        REFLECT_REPLY_BYTES, REFLECT_REQUEST_BYTES, parse_reflect_reply, parse_reflect_request,
        reflect_reply, reflect_request,
    };
    let nonce = [0x5au8; 16];
    let request = reflect_request(&nonce);
    assert_eq!(request.len(), REFLECT_REQUEST_BYTES, "21 bytes in");
    assert_eq!(parse_reflect_request(&request), Some(nonce));

    let observed: std::net::SocketAddr = "198.51.100.7:4433".parse().unwrap();
    let reply = reflect_reply(&nonce, observed);
    assert_eq!(reply.len(), REFLECT_REPLY_BYTES, "39 bytes out");
    let (got_nonce, got_addr) = parse_reflect_reply(&reply).unwrap();
    assert_eq!(got_nonce, nonce);
    assert_eq!(
        link_core::card::unmap_ipv6(got_addr),
        observed,
        "v4-mapped round trip"
    );
}

#[test]
fn the_identity_rule_accepts_only_the_pinned_node_id() {
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{ServerName, UnixTime};
    use rustls::server::danger::ClientCertVerifier;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let a = node_a();
    let b = node_b();
    let leaf_a = link_core::tls::node_certificate(&a).expect("leaf a");
    let leaf_b = link_core::tls::node_certificate(&b).expect("leaf b");

    let name = ServerName::try_from("ignored.example").expect("name");
    // Names, dates and chains are ignored: a far future clock changes nothing.
    let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(4_102_444_800));

    let server_verifier = link_core::tls::PinnedServerVerifier::new(a.node_id());
    assert!(
        server_verifier
            .verify_server_cert(&leaf_a.cert_der, &[], &name, &[], now)
            .is_ok(),
        "the pinned node ID is accepted whatever the name or date says"
    );
    assert!(
        server_verifier
            .verify_server_cert(&leaf_b.cert_der, &[], &name, &[], now)
            .is_err(),
        "any other key fails closed"
    );

    let client_verifier = link_core::tls::PinnedClientVerifier::new(b.node_id());
    assert!(
        client_verifier.offer_client_auth(),
        "client auth is offered"
    );
    assert!(
        client_verifier.client_auth_mandatory(),
        "client auth is mandatory"
    );
    assert!(
        client_verifier
            .verify_client_cert(&leaf_b.cert_der, &[], now)
            .is_ok()
    );
    assert!(
        client_verifier
            .verify_client_cert(&leaf_a.cert_der, &[], now)
            .is_err(),
        "the server side fails closed on the wrong key too"
    );
    assert_eq!(
        server_verifier.supported_verify_schemes(),
        vec![rustls::SignatureScheme::ED25519],
        "only Ed25519 is offered, so a downgrade has nothing to pick"
    );
}
