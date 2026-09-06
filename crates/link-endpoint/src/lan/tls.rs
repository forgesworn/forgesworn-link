use super::{LanError, admission::Book};
use link_core::{
    id::{NodeId, node_id_from_spki},
    tls::{PinnedClientVerifier, PinnedServerVerifier, ProvisionalClientVerifier},
};
use rustls::{
    DigitallySignedStruct, DistinguishedName, Error, SignatureScheme,
    client::{AlwaysResolvesClientRawPublicKeys, danger::HandshakeSignatureValid},
    pki_types::{CertificateDer, UnixTime},
    server::{
        AlwaysResolvesServerRawPublicKeys,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
    sign::CertifiedKey,
};
use std::sync::Arc;

// Provisional identity consistency is confined to its own UDP listener/ALPN.
pub const LAN_ALPN: &[u8] = b"fsl-lan-candidate/0";
pub const PAIRING_ALPN: &[u8] = b"fsl-lan-pair-candidate/0";

struct AdmittedVerifier {
    book: Arc<Book>,
    empty: Vec<DistinguishedName>,
}
impl std::fmt::Debug for AdmittedVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AdmittedLanVerifier")
    }
}
impl AdmittedVerifier {
    fn peer(&self, certificate: &CertificateDer<'_>) -> Result<NodeId, Error> {
        let peer = node_id_from_spki(certificate.as_ref()).ok_or(Error::InvalidCertificate(
            rustls::CertificateError::BadEncoding,
        ))?;
        self.book.get(peer).ok_or(Error::InvalidCertificate(
            rustls::CertificateError::ApplicationVerificationFailure,
        ))?;
        Ok(peer)
    }
}
impl ClientCertVerifier for AdmittedVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.empty
    }
    fn offer_client_auth(&self) -> bool {
        true
    }
    fn client_auth_mandatory(&self) -> bool {
        true
    }
    fn requires_raw_public_keys(&self) -> bool {
        true
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
    fn verify_client_cert(
        &self,
        end: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        PinnedClientVerifier::new(self.peer(end)?).verify_client_cert(end, intermediates, now)
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        PinnedClientVerifier::new(self.peer(cert)?).verify_tls13_signature(message, cert, signature)
    }
}

fn transport(pairing: bool, server: bool) -> quinn::TransportConfig {
    let mut config = quinn::TransportConfig::default();
    config
        .max_concurrent_bidi_streams((if pairing { u32::from(server) } else { 8 }).into())
        .max_concurrent_uni_streams(u32::from(!server).into())
        .datagram_receive_buffer_size(None)
        .stream_receive_window((1_u32 << 20).into())
        .receive_window((4_u32 << 20).into())
        .send_window(4 << 20)
        .keep_alive_interval(None)
        .max_idle_timeout(Some(
            std::time::Duration::from_secs(15)
                .try_into()
                .expect("timeout"),
        ))
        .initial_mtu(1200)
        .min_mtu(1200)
        .mtu_discovery_config(None);
    config
}

pub(super) fn server(
    identity: Arc<CertifiedKey>,
    book: Arc<Book>,
    pairing: bool,
) -> Result<quinn::ServerConfig, LanError> {
    let verifier: Arc<dyn ClientCertVerifier> = if pairing {
        ProvisionalClientVerifier::new()
    } else {
        Arc::new(AdmittedVerifier {
            book,
            empty: Vec::new(),
        })
    };
    let mut crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|_| LanError::Identity)?
    .with_client_cert_verifier(verifier)
    .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(identity)));
    crypto.alpn_protocols = vec![if pairing { PAIRING_ALPN } else { LAN_ALPN }.to_vec()];
    crypto.max_early_data_size = 0;
    crypto.send_tls13_tickets = 0;
    crypto.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
            .map_err(|_| LanError::Identity)?,
    ));
    config
        .transport_config(Arc::new(transport(pairing, true)))
        .migration(false)
        .max_incoming(16)
        .incoming_buffer_size(16 * 1024)
        .incoming_buffer_size_total(256 * 1024)
        .retry_token_lifetime(std::time::Duration::from_secs(5));
    Ok(config)
}

pub(super) fn client(
    identity: Arc<CertifiedKey>,
    expected: NodeId,
    pairing: bool,
) -> Result<quinn::ClientConfig, LanError> {
    let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|_| LanError::Identity)?
    .dangerous()
    .with_custom_certificate_verifier(PinnedServerVerifier::new(expected))
    .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(identity)));
    crypto.alpn_protocols = vec![if pairing { PAIRING_ALPN } else { LAN_ALPN }.to_vec()];
    crypto.enable_early_data = false;
    crypto.resumption = rustls::client::Resumption::disabled();
    let mut config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .map_err(|_| LanError::Identity)?,
    ));
    config.transport_config(Arc::new(transport(pairing, false)));
    Ok(config)
}
