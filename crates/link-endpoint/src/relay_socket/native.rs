//! The native relay socket: TCP, TLS by `relay_tls`, then tungstenite.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;

use super::WsMessage;
use crate::relay_client::RelaySpec;

pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

/// A native socket is always `send_ready`, so this never completes.
pub fn send_retry() -> std::future::Pending<()> {
    std::future::pending()
}

pub struct RelaySocket(tokio_tungstenite::WebSocketStream<Box<dyn Duplex>>);

impl RelaySocket {
    pub async fn open(
        spec: &RelaySpec,
        _shutdown: &super::SocketShutdown,
    ) -> anyhow::Result<RelaySocket> {
        let (tls, host, port, path) = spec.parts()?;
        let stream = crate::rt::timeout(
            Duration::from_secs(10),
            TcpStream::connect((host.as_str(), port)),
        )
        .await??;
        stream.set_nodelay(true).ok();

        let transport: Box<dyn Duplex> = if tls {
            let connector = crate::relay_tls::connector(spec)?;
            let server_name = rustls::pki_types::ServerName::try_from(host.clone())?;
            Box::new(connector.connect(server_name, stream).await?)
        } else {
            Box::new(stream)
        };

        let request = format!("{}://{host}:{port}{path}", if tls { "wss" } else { "ws" });
        let (ws, _) = tokio_tungstenite::client_async(request, transport).await?;
        Ok(RelaySocket(ws))
    }

    /// Always: tungstenite's `send` waits for the socket itself.
    pub fn send_ready(&self) -> bool {
        true
    }

    pub async fn send(&mut self, bytes: Vec<u8>) -> anyhow::Result<()> {
        Ok(self.0.send(Message::Binary(bytes)).await?)
    }

    pub async fn pong(&mut self, payload: Vec<u8>) -> anyhow::Result<()> {
        Ok(self.0.send(Message::Pong(payload)).await?)
    }

    pub async fn next(&mut self) -> Option<anyhow::Result<WsMessage>> {
        let message = self.0.next().await?;
        Some(
            message
                .map_err(anyhow::Error::from)
                .map(|message| match message {
                    Message::Binary(bytes) => WsMessage::Binary(bytes),
                    Message::Ping(payload) => WsMessage::Ping(payload),
                    Message::Pong(_) => WsMessage::Pong,
                    _ => WsMessage::Other,
                }),
        )
    }
}
