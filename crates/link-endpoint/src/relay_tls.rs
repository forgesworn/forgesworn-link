//! Client-side TLS for `wss://` relays, three modes by `RelaySpec`:
//!
//! * no pin, no flag -- ordinary WebPKI verification against the bundled
//!   Mozilla roots (`webpki-roots`), the deployed default: a relay behind an
//!   ordinary Let's Encrypt certificate just works, and renewal changes
//!   nothing.  A platform trust store (`rustls-platform-verifier`) is the
//!   planned upgrade when Android system roots and revocation matter.
//! * `cert_sha256` -- the leaf pinned by fingerprint, for a relay that ships
//!   no WebPKI name (the spike's mode).
//! * `insecure_tls` -- any leaf accepted, development only, and it says so in
//!   the logs.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use sha2::{Digest, Sha256};

use crate::relay_client::RelaySpec;

pub fn connector(spec: &RelaySpec) -> anyhow::Result<tokio_rustls::TlsConnector> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = match (&spec.cert_sha256, spec.insecure_tls) {
        (None, false) => {
            // The deployed default: ordinary WebPKI verification, so a relay
            // behind an ordinary renewing certificate needs no pin.
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots)
                .with_no_client_auth()
        }
        (expected, insecure) => {
            let expected = match (expected, insecure) {
                (Some(fingerprint), _) => Some(fingerprint.to_lowercase()),
                (None, _) => {
                    tracing::warn!(relay = %spec.url, "accepting any relay certificate, development only");
                    None
                }
            };
            rustls::ClientConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinnedRelayVerifier {
                    expected,
                    provider,
                }))
                .with_no_client_auth()
        }
    };
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
