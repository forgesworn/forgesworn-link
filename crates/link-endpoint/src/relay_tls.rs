//! Client-side TLS for `wss://` relays.
//!
//! The spike does not ship a root certificate store, so a relay leaf is either
//! pinned by its SHA-256 fingerprint or, with an explicit development flag,
//! accepted unchecked.  A deployed relay presents an ordinary WebPKI leaf and a
//! product build would use the platform trust store here instead.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use sha2::{Digest, Sha256};

use crate::relay_client::RelaySpec;

pub fn connector(spec: &RelaySpec) -> anyhow::Result<tokio_rustls::TlsConnector> {
    let expected = match (&spec.cert_sha256, spec.insecure_tls) {
        (Some(fingerprint), _) => Some(fingerprint.to_lowercase()),
        (None, true) => {
            tracing::warn!(relay = %spec.url, "accepting any relay certificate, development only");
            None
        }
        (None, false) => anyhow::bail!(
            "a wss:// relay needs --relay-cert-sha256 or --relay-insecure-tls in the spike"
        ),
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedRelayVerifier { expected, provider }))
        .with_no_client_auth();
    config.alpn_protocols.clear();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

#[derive(Debug)]
struct PinnedRelayVerifier {
    expected: Option<String>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedRelayVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if let Some(expected) = &self.expected {
            let seen: String = Sha256::digest(end_entity.as_ref())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            if &seen != expected {
                return Err(TlsError::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                ));
            }
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
