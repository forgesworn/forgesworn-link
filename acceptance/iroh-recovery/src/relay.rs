use std::net::SocketAddr;

use anyhow::{Context, Result};
use iroh::RelayUrl;
use iroh_relay::server::{CertConfig, RelayConfig, Server, ServerConfig, TlsConfig};
use iroh_relay::tls::CaTlsConfig;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

pub async fn start_relay(bind: SocketAddr) -> Result<(Server, RelayUrl, CaTlsConfig)> {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec![bind.ip().to_string()])?;
    let cert = cert.der().clone();
    let ca_tls = CaTlsConfig::custom_roots([cert.clone()]);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    let mut relay_config = RelayConfig::new(bind);
    relay_config.tls = Some(TlsConfig::new(bind, CertConfig::Manual { server_config }));
    let mut config = ServerConfig::default();
    config.relay = Some(relay_config);
    let relay = Server::spawn(config).await?;
    let addr = relay.https_addr().context("missing Iroh relay address")?;
    Ok((relay, format!("https://{addr}").parse()?, ca_tls))
}
