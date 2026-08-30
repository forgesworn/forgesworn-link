//! The one identity rule of spec section 1, expressed as rustls verifiers, plus
//! the self-signed Ed25519 leaf that carries the node ID as its SPKI.
//!
//! Chain, names, validity dates and extensions are ignored.  The only checks are
//! that the presented SPKI byte-equals the expected node ID's SPKI and that the
//! TLS 1.3 CertificateVerify signature validates under that key.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as TlsError, SignatureScheme};

use crate::id::{NodeId, TransportKey, node_id_from_cert_der};

/// A self-signed leaf whose SubjectPublicKeyInfo is exactly the node public key.
pub struct NodeCertificate {
    pub cert_der: CertificateDer<'static>,
    pub key_der: PrivateKeyDer<'static>,
}

/// Build the leaf for a transport key.  The subject name is a placeholder: no
/// verifier on either side ever reads it.
pub fn node_certificate(key: &TransportKey) -> Result<NodeCertificate, rcgen::Error> {
    let pkcs8 = key.pkcs8_der();
    let key_pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(pkcs8.as_slice()),
        &rcgen::PKCS_ED25519,
    )?;
    let mut params =
        rcgen::CertificateParams::new(vec![format!("{}.node.invalid", key.node_id())])?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let cert = params.self_signed(&key_pair)?;
    Ok(NodeCertificate {
        cert_der: cert.der().clone(),
        key_der: PrivateKeyDer::try_from(pkcs8.to_vec())
            .map_err(|_| rcgen::Error::CouldNotParseKeyPair)?,
    })
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn check_pinned(expected: NodeId, cert: &CertificateDer<'_>) -> Result<NodeId, TlsError> {
    let presented = node_id_from_cert_der(cert.as_ref()).ok_or(TlsError::InvalidCertificate(
        rustls::CertificateError::BadEncoding,
    ))?;
    if presented.spki_der() != expected.spki_der() {
        return Err(TlsError::InvalidCertificate(
            rustls::CertificateError::ApplicationVerificationFailure,
        ));
    }
    Ok(presented)
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
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
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
/// the default path can never authenticate anyone.  It refuses every client
/// certificate.
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
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}
