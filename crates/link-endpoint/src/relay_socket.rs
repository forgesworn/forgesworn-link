//! The relay byte transport: one WebSocket to one relay, carrying binary
//! messages.  This is the only part of a relay session that differs between
//! a native and a browser build.  The protocol on top of it (challenge, auth
//! or registration, welcome, send, receive, ping, close, backoff and
//! refresh) is `relay_client`'s, written once.
//!
//! Both builds offer the same `RelaySocket`:
//!
//! * `open(spec)` -- a WebSocket to the relay, ready for the challenge.  The
//!   caller bounds it with its connect timeout.
//! * `send_ready()` -- whether to take another datagram off the queue.
//!   Always true natively, where `send` itself waits for the socket; in a
//!   browser, whether the page's send buffer is below its high-water mark.
//!   The session keeps reading while it is false, and `send_retry()`
//!   wakes it to look again (never, natively).
//! * `send(bytes)` -- one binary message.
//! * `pong(payload)` -- answer a WebSocket-level ping (native only: a
//!   browser answers pings itself and never surfaces one).
//! * `next()` -- the next message, `None` once the socket has ended.  Cancel
//!   safe, so it may sit in a `select!` arm.
//!
//! A native build dials TCP itself and runs TLS with `relay_tls`.  A browser
//! build opens the page's `WebSocket`, which does its own WebPKI
//! verification and therefore accepts only a plain `wss://` spec.

#[cfg(any(wasm_browser, test))]
mod inbound;
#[cfg(not(wasm_browser))]
mod native;
#[cfg(wasm_browser)]
mod web;

#[cfg(not(wasm_browser))]
pub use native::{Duplex, RelaySocket, send_retry};
#[cfg(wasm_browser)]
pub use web::{RelaySocket, send_retry};

/// One WebSocket message, as far as the relay protocol cares.
pub enum WsMessage {
    Binary(Vec<u8>),
    /// WebSocket-level ping and pong.  A browser handles these itself and
    /// never surfaces one.
    #[cfg(not(wasm_browser))]
    Ping(Vec<u8>),
    #[cfg(not(wasm_browser))]
    Pong,
    /// Text, a close or a raw frame: nothing a relay sends on a live session.
    Other,
}

/// Tracks browser sockets whose close handshake outlives the relay future.
/// Native TCP streams close synchronously when their driver is dropped.
#[derive(Clone, Debug)]
pub struct SocketShutdown(tokio::sync::watch::Sender<usize>);

impl Default for SocketShutdown {
    fn default() -> Self {
        Self(tokio::sync::watch::Sender::new(0))
    }
}

impl SocketShutdown {
    #[cfg(wasm_browser)]
    fn opened(&self) -> SocketGuard {
        self.0.send_modify(|count| *count += 1);
        SocketGuard(self.clone())
    }

    pub async fn wait(&self) {
        let mut pending = self.0.subscribe();
        let _ = pending.wait_for(|count| *count == 0).await;
    }
}

#[cfg(wasm_browser)]
struct SocketGuard(SocketShutdown);

#[cfg(wasm_browser)]
impl Drop for SocketGuard {
    fn drop(&mut self) {
        self.0.0.send_modify(|count| *count -= 1);
    }
}
