//! WebSocket framing over an already-open ForgeSworn Link application stream.
//!
//! The virtual URL names a Link peer; it is validated before a stream is opened
//! and is never resolved by DNS.  This crate owns WebSocket control frames so
//! callers only exchange bounded text messages.

use futures_util::{SinkExt, StreamExt};
use link_core::NodeId;
use link_endpoint::Session;
use thiserror::Error;
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::protocol::Message;
use url::Url;

/// Maximum encoded text payload accepted in either direction.
pub const MAX_TEXT_BYTES: usize = 1_048_576;
/// Maximum queued application commands per socket.
pub const OUTBOUND_QUEUE: usize = 64;
const INBOUND_QUEUE: usize = 64;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SocketError {
    #[error("Link WebSocket URLs must use ws")]
    Scheme,
    #[error("Link WebSocket URL must not contain credentials, a port, query, or fragment")]
    Authority,
    #[error("Link WebSocket URL path must be /events")]
    Path,
    #[error("Link WebSocket URL host must be a canonical Link node id")]
    Host,
    #[error("Link WebSocket URL host does not match the connected peer")]
    PeerMismatch,
    #[error("outbound WebSocket text exceeds {MAX_TEXT_BYTES} bytes")]
    TextTooLarge,
    #[error("outbound WebSocket queue is full")]
    QueueFull,
    #[error("WebSocket is closed")]
    Closed,
    #[error("could not open Link stream: {0}")]
    Stream(String),
    #[error("could not complete WebSocket upgrade: {0}")]
    Upgrade(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum IncomingMessage {
    Text(String),
    Closed(String),
}

enum Command {
    Text(String),
    Close,
}

/// A handle for sending text to a WebSocket that uses a Link stream.
#[derive(Clone)]
pub struct Socket {
    commands: mpsc::Sender<Command>,
    overflow: watch::Sender<bool>,
}

impl Socket {
    /// Queues one text frame without blocking the Android/UI caller.
    pub fn send_text(&self, text: String) -> Result<(), SocketError> {
        if text.len() > MAX_TEXT_BYTES {
            return Err(SocketError::TextTooLarge);
        }
        self.commands
            .try_send(Command::Text(text))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => {
                    let _ = self.overflow.send(true);
                    SocketError::QueueFull
                }
                mpsc::error::TrySendError::Closed(_) => SocketError::Closed,
            })
    }

    /// Starts a normal close.  The driver reports one terminal event.
    pub fn close(&self) -> Result<(), SocketError> {
        self.commands
            .try_send(Command::Close)
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => {
                    let _ = self.overflow.send(true);
                    SocketError::QueueFull
                }
                mpsc::error::TrySendError::Closed(_) => SocketError::Closed,
            })
    }
}

/// Validates the only virtual URL form that may be carried over a Link session.
pub fn validate_virtual_url(url: &Url, peer: NodeId) -> Result<(), SocketError> {
    if url.scheme() != "ws" {
        return Err(SocketError::Scheme);
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(SocketError::Authority);
    }
    if url.path() != "/events" {
        return Err(SocketError::Path);
    }
    let host = url.host_str().ok_or(SocketError::Host)?;
    let node = NodeId::from_base32(host).ok_or(SocketError::Host)?;
    if node != peer {
        return Err(SocketError::PeerMismatch);
    }
    Ok(())
}

/// Opens an HTTP/1.1 WebSocket upgrade over a fresh application stream on
/// `session`. `client_async` receives the stream directly, so no DNS or TCP
/// connection can occur here.
pub async fn open(
    session: &Session,
    virtual_url: Url,
) -> Result<(Socket, mpsc::Receiver<IncomingMessage>), SocketError> {
    validate_virtual_url(&virtual_url, session.peer())?;
    let stream = session
        .open_stream()
        .await
        .map_err(|error| SocketError::Stream(error.to_string()))?;
    let (websocket, _) = tokio_tungstenite::client_async(virtual_url.as_str(), stream)
        .await
        .map_err(|error| SocketError::Upgrade(error.to_string()))?;
    let (commands, command_rx) = mpsc::channel(OUTBOUND_QUEUE);
    let (overflow, overflow_rx) = watch::channel(false);
    let (incoming_tx, incoming_rx) = mpsc::channel(INBOUND_QUEUE);
    tokio::spawn(drive(websocket, command_rx, overflow_rx, incoming_tx));
    Ok((Socket { commands, overflow }, incoming_rx))
}

async fn close_once<S>(websocket: &mut tokio_tungstenite::WebSocketStream<S>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let _ = websocket.send(Message::Close(None)).await;
}

async fn terminal(incoming: &mpsc::Sender<IncomingMessage>, reason: impl Into<String>) {
    let _ = incoming.send(IncomingMessage::Closed(reason.into())).await;
}

async fn drive<S>(
    mut websocket: tokio_tungstenite::WebSocketStream<S>,
    mut commands: mpsc::Receiver<Command>,
    mut overflow: watch::Receiver<bool>,
    incoming: mpsc::Sender<IncomingMessage>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        tokio::select! {
            changed = overflow.changed() => {
                if changed.is_ok() && *overflow.borrow() {
                    close_once(&mut websocket).await;
                    terminal(&incoming, "outbound queue overflow").await;
                    return;
                }
                if changed.is_err() {
                    close_once(&mut websocket).await;
                    terminal(&incoming, "closed locally").await;
                    return;
                }
            }
            command = commands.recv() => match command {
                Some(Command::Text(text)) => {
                    if websocket.send(Message::Text(text)).await.is_err() {
                        terminal(&incoming, "write failed").await;
                        return;
                    }
                }
                Some(Command::Close) | None => {
                    close_once(&mut websocket).await;
                    terminal(&incoming, "closed locally").await;
                    return;
                }
            },
            message = websocket.next() => match message {
                Some(Ok(Message::Text(text))) => {
                    if text.len() > MAX_TEXT_BYTES {
                        close_once(&mut websocket).await;
                        terminal(&incoming, "text frame exceeds limit").await;
                        return;
                    }
                    if incoming.try_send(IncomingMessage::Text(text)).is_err() {
                        close_once(&mut websocket).await;
                        terminal(&incoming, "inbound queue overflow").await;
                        return;
                    }
                }
                Some(Ok(Message::Ping(payload))) => {
                    if websocket.send(Message::Pong(payload)).await.is_err() {
                        terminal(&incoming, "pong failed").await;
                        return;
                    }
                }
                Some(Ok(Message::Pong(_))) => {}
                Some(Ok(Message::Close(_))) => {
                    close_once(&mut websocket).await;
                    terminal(&incoming, "closed by peer").await;
                    return;
                }
                Some(Ok(Message::Binary(_))) | Some(Ok(Message::Frame(_))) => {
                    close_once(&mut websocket).await;
                    terminal(&incoming, "binary frames are not supported").await;
                    return;
                }
                Some(Err(_)) => {
                    terminal(&incoming, "WebSocket protocol error").await;
                    return;
                }
                None => {
                    terminal(&incoming, "connection ended").await;
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node() -> NodeId {
        NodeId([7; 32])
    }

    fn url(suffix: &str) -> Url {
        Url::parse(&format!("ws://{}{}", node().to_base32(), suffix)).unwrap()
    }

    #[test]
    fn accepts_only_the_peer_events_url() {
        assert_eq!(validate_virtual_url(&url("/events"), node()), Ok(()));
    }

    #[test]
    fn rejects_noncanonical_or_unrelated_url_parts() {
        assert_eq!(
            validate_virtual_url(&url("/other"), node()),
            Err(SocketError::Path)
        );
        assert_eq!(
            validate_virtual_url(&url("/events?q=1"), node()),
            Err(SocketError::Authority)
        );
        assert_eq!(
            validate_virtual_url(&Url::parse("wss://example.com/events").unwrap(), node()),
            Err(SocketError::Scheme)
        );
        assert_eq!(
            validate_virtual_url(&Url::parse("ws://example.com/events").unwrap(), node()),
            Err(SocketError::Host)
        );
    }

    #[test]
    fn rejects_a_different_peer() {
        let other = NodeId([8; 32]);
        assert_eq!(
            validate_virtual_url(&url("/events"), other),
            Err(SocketError::PeerMismatch)
        );
    }
}
