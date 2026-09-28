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
//! * `send(bytes)` -- one binary message.
//! * `pong(payload)` -- answer a WebSocket-level ping (native only: a
//!   browser answers pings itself and never surfaces one).
//! * `next()` -- the next message, `None` once the socket has ended.  Cancel
//!   safe, so it may sit in a `select!` arm.
//!
//! A native build dials TCP itself and runs TLS with `relay_tls`.  A browser
//! build opens the page's `WebSocket`, which does its own WebPKI
//! verification and therefore accepts only a plain `wss://` spec.

#[cfg(not(wasm_browser))]
mod native;
#[cfg(wasm_browser)]
mod web;

#[cfg(not(wasm_browser))]
pub use native::{Duplex, RelaySocket};
#[cfg(wasm_browser)]
pub use web::RelaySocket;

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
