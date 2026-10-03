//! Full TLS 1.3 handshakes against the identity rule, driven in memory through
//! the same `client_config` and `server_config` the endpoint hands to quinn.
//!
//! The endpoint API deliberately cannot be told to present a key other than
//! its own, so a liar is built here at the rustls layer: a `CertifiedKey`
//! whose raw public key is one node's SPKI and whose signer is another's.
//! `CertifiedKey::new` does not check that the two agree, which is exactly
//! what a hostile peer gets to choose.

use std::sync::Arc;

use link_core::id::TransportKey;
use link_core::tls::{
    PinnedClientVerifier, ProvisionalClientVerifier, RefusingClientVerifier, client_config,
    node_identity, server_config,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::danger::ClientCertVerifier;
use rustls::sign::CertifiedKey;
use rustls::{CertificateError, ClientConnection, Connection, Error, ServerConnection};

const ALPN: &[u8] = b"fsl-test";

fn key(byte: u8) -> TransportKey {
    TransportKey::from_seed([byte; 32])
}

/// Presents `claimed`'s raw public key but signs CertificateVerify with
/// `signer`'s private key: a peer that knows a node ID but not its key.
fn impostor(claimed: &TransportKey, signer: &TransportKey) -> Arc<CertifiedKey> {
    let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signer.pkcs8_der().to_vec()));
    let signing = rustls::crypto::ring::sign::any_supported_type(&private).expect("signer");
    let spki = CertificateDer::from(claimed.node_id().spki_der().to_vec());
    Arc::new(CertifiedKey::new(vec![spki], signing))
}

struct Outcome {
    client: Result<(), Error>,
    server: Result<(), Error>,
    client_conn: Connection,
    server_conn: Connection,
}

/// Moves whatever `from` has queued into `to` and lets `to` process it.
fn transfer(from: &mut Connection, to: &mut Connection) -> Result<(), Error> {
    let mut wire = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut wire).expect("write to a Vec");
    }
    let mut pending = &wire[..];
    while !pending.is_empty() {
        if to.read_tls(&mut pending).is_err() {
            break;
        }
    }
    to.process_new_packets().map(|_| ())
}

fn handshake(
    client_identity: Arc<CertifiedKey>,
    pinned_server: &TransportKey,
    server_identity: Arc<CertifiedKey>,
    verifier: Arc<dyn ClientCertVerifier>,
) -> Outcome {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = client_config(client_identity, pinned_server.node_id(), ALPN).expect("client");
    let server = server_config(server_identity, verifier, ALPN).expect("server");
    // The name is ignored by the pinned verifier; the key is the identity.
    let name = ServerName::try_from("ignored.example").expect("name");
    let mut client_conn = Connection::Client(
        ClientConnection::new(Arc::new(client), name).expect("client connection"),
    );
    let mut server_conn =
        Connection::Server(ServerConnection::new(Arc::new(server)).expect("server connection"));

    let mut client_err = None;
    let mut server_err = None;
    // Bounded, so a regression that stalls fails here instead of hanging.
    for _ in 0..10 {
        if let Err(e) = transfer(&mut client_conn, &mut server_conn) {
            server_err.get_or_insert(e);
        }
        if let Err(e) = transfer(&mut server_conn, &mut client_conn) {
            client_err.get_or_insert(e);
        }
    }
    let settle = |err: Option<Error>, conn: &Connection, side: &str| match err {
        Some(e) => Err(e),
        None if conn.is_handshaking() => panic!("the {side} neither finished nor failed"),
        None => Ok(()),
    };
    Outcome {
        client: settle(client_err, &client_conn, "client"),
        server: settle(server_err, &server_conn, "server"),
        client_conn,
        server_conn,
    }
}

fn pinned(peer: &TransportKey) -> Arc<dyn ClientCertVerifier> {
    PinnedClientVerifier::new(peer.node_id())
}

fn assert_rejected(result: &Result<(), Error>, expected: CertificateError, what: &str) {
    match result {
        Err(Error::InvalidCertificate(got)) if *got == expected => {}
        other => panic!("{what}: expected InvalidCertificate({expected:?}), got {other:?}"),
    }
}

/// The control.  If raw public keys, ALPN or the verifiers were wired wrong,
/// every refusal below could pass for the wrong reason; this one must succeed.
#[test]
fn the_honest_pair_completes_and_each_sees_the_others_key() {
    let (a, b) = (key(1), key(2));
    let out = handshake(
        node_identity(&a).unwrap(),
        &b,
        node_identity(&b).unwrap(),
        pinned(&a),
    );
    assert!(out.client.is_ok(), "client: {:?}", out.client);
    assert!(out.server.is_ok(), "server: {:?}", out.server);
    let seen_by_client = out.client_conn.peer_certificates().expect("server key");
    let seen_by_server = out.server_conn.peer_certificates().expect("client key");
    assert_eq!(seen_by_client.len(), 1, "one raw public key, no chain");
    assert_eq!(
        seen_by_client[0].as_ref(),
        b.node_id().spki_der().as_slice()
    );
    assert_eq!(seen_by_server.len(), 1, "one raw public key, no chain");
    assert_eq!(
        seen_by_server[0].as_ref(),
        a.node_id().spki_der().as_slice()
    );
    assert_eq!(out.client_conn.alpn_protocol(), Some(ALPN));
}

#[test]
fn a_server_with_another_key_is_refused_by_the_client() {
    let (a, b, c) = (key(1), key(2), key(3));
    // The client pinned B; C answers with its own, honestly signed key.
    let out = handshake(
        node_identity(&a).unwrap(),
        &b,
        node_identity(&c).unwrap(),
        pinned(&a),
    );
    assert_rejected(
        &out.client,
        CertificateError::ApplicationVerificationFailure,
        "client",
    );
    assert!(out.server.is_err(), "the server hears the client's alert");
}

#[test]
fn a_client_with_another_key_is_refused_by_the_server() {
    let (a, b, c) = (key(1), key(2), key(3));
    // The server expected A; C dials with its own, honestly signed key.  In
    // TLS 1.3 the client's certificate arrives after the server's Finished,
    // so the server is the side that must refuse.
    let out = handshake(
        node_identity(&c).unwrap(),
        &b,
        node_identity(&b).unwrap(),
        pinned(&a),
    );
    assert_rejected(
        &out.server,
        CertificateError::ApplicationVerificationFailure,
        "server",
    );
    assert!(
        out.client.is_err(),
        "the client hears the server's alert instead of a usable connection"
    );
}

#[test]
fn a_server_claiming_the_pinned_key_without_holding_it_is_refused() {
    let (a, b, c) = (key(1), key(2), key(3));
    // The presented key passes the pin; only CertificateVerify can catch it.
    let out = handshake(node_identity(&a).unwrap(), &b, impostor(&b, &c), pinned(&a));
    assert_rejected(&out.client, CertificateError::BadSignature, "client");
    assert!(out.server.is_err(), "the server hears the client's alert");
}

#[test]
fn a_client_claiming_the_pinned_key_without_holding_it_is_refused() {
    let (a, b, c) = (key(1), key(2), key(3));
    let out = handshake(impostor(&a, &c), &b, node_identity(&b).unwrap(), pinned(&a));
    assert_rejected(&out.server, CertificateError::BadSignature, "server");
    assert!(out.client.is_err(), "the client hears the server's alert");
}

#[test]
fn the_default_server_config_refuses_even_the_right_key() {
    let (a, b) = (key(1), key(2));
    let out = handshake(
        node_identity(&a).unwrap(),
        &b,
        node_identity(&b).unwrap(),
        RefusingClientVerifier::new(),
    );
    assert_rejected(
        &out.server,
        CertificateError::ApplicationVerificationFailure,
        "server",
    );
}

#[test]
fn pairing_accepts_any_key_but_still_demands_its_signature() {
    let (b, c, d) = (key(2), key(3), key(4));
    // On the pairing ALPN the client is not yet known, so any honest key is in.
    let honest = handshake(
        node_identity(&c).unwrap(),
        &b,
        node_identity(&b).unwrap(),
        ProvisionalClientVerifier::new(),
    );
    assert!(honest.server.is_ok(), "server: {:?}", honest.server);
    assert!(honest.client.is_ok(), "client: {:?}", honest.client);

    // A key the client cannot sign for is still refused.
    let forged = handshake(
        impostor(&c, &d),
        &b,
        node_identity(&b).unwrap(),
        ProvisionalClientVerifier::new(),
    );
    assert_rejected(&forged.server, CertificateError::BadSignature, "server");
}
