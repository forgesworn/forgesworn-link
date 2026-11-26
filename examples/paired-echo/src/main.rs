use std::time::Duration;

use anyhow::{Context, Result, ensure};
use link_endpoint::{
    Endpoint, EndpointConfig, NodeId, PathStatus, RelaySpec, Session, TransportKey,
};
use link_relay::{RelayConfig, TlsMaterial};
use rand::{RngCore, rngs::OsRng};
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;
use zeroize::Zeroizing;

const MESSAGE: &str = "hello, Link!";
const MAX_MESSAGE_BYTES: usize = 1024;

#[tokio::main]
async fn main() -> Result<()> {
    let mut config = RelayConfig::default();
    let tls = TlsMaterial::self_signed(&config.hosts)?;
    let pin = tls.fingerprint();
    config.tls = Some(tls);
    let relay = link_relay::start(config)
        .await
        .context("start loopback WSS relay")?;
    let approved_relay = RelaySpec::pinned(relay.url("127.0.0.1"), pin);

    let result = timeout(Duration::from_secs(20), run_echo(approved_relay)).await;
    relay.shutdown();
    result.context("paired echo timed out")??;
    println!("Verified echo: {MESSAGE} (path=relayed)");
    Ok(())
}

async fn run_echo(relay: RelaySpec) -> Result<()> {
    let client_key = TransportKey::generate();
    let server_key = TransportKey::generate();
    let client_id = client_key.node_id();
    let server_id = server_key.node_id();

    // Provision the demo pair in memory. An app loads its authorised peer
    // IDs and route secrets from persisted pairing state.
    let mut route_secret = Zeroizing::new([0; 32]);
    OsRng.fill_bytes(route_secret.as_mut());
    let (client, server) = tokio::try_join!(
        open_peer(client_key, relay.clone(), server_id, route_secret.clone()),
        open_peer(server_key, relay, client_id, route_secret),
    )?;
    let server_card = server.card(Duration::from_secs(60), Vec::new());
    let (client_session, server_session) =
        tokio::try_join!(client.connect(&server_card), server.accept())?;
    ensure!(server_session.peer() == client_id, "unexpected echo client");
    ensure!(client_session.peer() == server_id, "unexpected echo server");

    let (reply, ()) = tokio::try_join!(send_message(&client_session), echo_once(&server_session))?;
    ensure!(
        reply == MESSAGE.as_bytes(),
        "echo did not match the request"
    );
    ensure!(
        client_session.path().status == PathStatus::Relayed
            && server_session.path().status == PathStatus::Relayed,
        "both peers should report a relayed path"
    );
    tokio::join!(client.close(), server.close());
    Ok(())
}

async fn open_peer(
    key: TransportKey,
    relay: RelaySpec,
    peer: NodeId,
    route_secret: Zeroizing<[u8; 32]>,
) -> Result<Endpoint> {
    let mut config = EndpointConfig::new(key);
    config.relays = vec![relay];
    config.paired_routes = Some([(peer, route_secret)].into());
    Endpoint::open(config).await
}

async fn send_message(session: &Session) -> Result<Vec<u8>> {
    let mut stream = session.open_stream().await?;
    stream.write_all(MESSAGE.as_bytes()).await?;
    stream.finish().await?;
    Ok(stream.recv.read_to_end(MAX_MESSAGE_BYTES).await?)
}

async fn echo_once(session: &Session) -> Result<()> {
    let mut stream = session.accept_stream().await?;
    let message = stream.recv.read_to_end(MAX_MESSAGE_BYTES).await?;
    stream.write_all(&message).await?;
    stream.finish().await?;
    Ok(())
}
