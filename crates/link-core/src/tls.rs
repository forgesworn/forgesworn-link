//! The one identity rule of spec section 1, expressed as rustls verifiers and
//! an RFC 7250 raw-public-key identity.
//!
//! Nothing here is a certificate.  What an endpoint presents in the TLS
//! `Certificate` message is the SubjectPublicKeyInfo of its Ed25519 node key
//! and nothing else, and the only checks on either side are that the
//! presented SPKI byte-equals the expected node ID's SPKI and that the TLS 1.3
//! CertificateVerify signature validates under that key.  There is no chain,
//! no name, no validity window and no extension to ignore, because none is
//! sent; card expiry governs freshness.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls13_signature_with_raw_key};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer,
    UnixTime,
};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::sign::CertifiedKey;
use rustls::{DigitallySignedStruct, DistinguishedName, Error as TlsError, SignatureScheme};

use crate::id::{NodeId, TransportKey, node_id_from_spki};

/// The identity an endpoint presents on every handshake, client or server:
/// the node ID's SPKI as the single entry of the certificate list (RFC 7250)
/// with the transport key beside it to sign CertificateVerify.  Built once
/// per endpoint and shared by every connection.
pub fn node_identity(key: &TransportKey) -> Result<Arc<CertifiedKey>, TlsError> {
    let pkcs8 = key.pkcs8_der();
    let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.to_vec()));
    let signing = rustls::crypto::ring::sign::any_supported_type(&private)?;
    let spki = CertificateDer::from(key.node_id().spki_der().to_vec());
    Ok(Arc::new(CertifiedKey::new(vec![spki], signing)))
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The rule.  Under RFC 7250 the bytes rustls hands a verifier as the
/// "certificate" are the raw SPKI, so this is a parse of the 44-byte
/// id-Ed25519 SPKI and a byte comparison, nothing more.
fn check_pinned(expected: NodeId, presented: &CertificateDer<'_>) -> Result<NodeId, TlsError> {
    let presented = node_id_from_spki(presented.as_ref()).ok_or(TlsError::InvalidCertificate(
        rustls::CertificateError::BadEncoding,
    ))?;
    if presented != expected {
        return Err(TlsError::InvalidCertificate(
            rustls::CertificateError::ApplicationVerificationFailure,
        ));
    }
    Ok(presented)
}

fn verify_signature(
    provider: &CryptoProvider,
    message: &[u8],
    presented: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, TlsError> {
    verify_tls13_signature_with_raw_key(
        message,
        &SubjectPublicKeyInfoDer::from(presented.as_ref()),
        dss,
        &provider.signature_verification_algorithms,
    )
}

/// Client side: the server must present exactly the node ID from the card.
#[derive(Debug)]
pub struct PinnedServerVerifier {
    expected: NodeId,
    provider: Arc<CryptoProvider>,
}

impl PinnedServerVerifier {
    pub fn new(expected: NodeId) -> Arc<Self> {
        Arc::new(PinnedServerVerifier {
            expected,
            provider: provider(),
        })
    }
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        check_pinned(self.expected, end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        check_pinned(self.expected, cert)?;
        verify_signature(&self.provider, message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// Server side: client authentication is mandatory and the pin is too.  The
/// expected node ID is always known ahead of the handshake, because quinn hands
/// over the synthetic source address before `accept_with` builds this verifier.
/// There is deliberately no unpinned mode: an endpoint that does not yet know
/// who it is accepting uses [`RefusingClientVerifier`] and completes nothing.
#[derive(Debug)]
pub struct PinnedClientVerifier {
    expected: NodeId,
    provider: Arc<CryptoProvider>,
    empty: Vec<DistinguishedName>,
}

impl PinnedClientVerifier {
    pub fn new(expected: NodeId) -> Arc<Self> {
        Arc::new(PinnedClientVerifier {
            expected,
            provider: provider(),
            empty: Vec::new(),
        })
    }
}

/// The placeholder verifier for an endpoint's default server configuration,
/// which quinn requires at bind time before any peer is known.  Every inbound
/// handshake is served through `accept_with` and a [`PinnedClientVerifier`]
/// built for that connection's expected node ID; this verifier exists only so
/// the default path can never authenticate anyone.  It refuses every client.
#[derive(Debug)]
pub struct RefusingClientVerifier {
    empty: Vec<DistinguishedName>,
}

impl RefusingClientVerifier {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Arc<Self> {
        Arc::new(RefusingClientVerifier { empty: Vec::new() })
    }
}

impl ClientCertVerifier for RefusingClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.empty
    }

    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        Err(TlsError::InvalidCertificate(
            rustls::CertificateError::ApplicationVerificationFailure,
        ))
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::InvalidCertificate(
            rustls::CertificateError::ApplicationVerificationFailure,
        ))
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

impl ClientCertVerifier for PinnedClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.empty
    }

    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        check_pinned(self.expected, end_entity)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        check_pinned(self.expected, cert)?;
        verify_signature(&self.provider, message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}
