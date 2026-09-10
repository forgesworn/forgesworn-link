# Android WebSocket bridge implementation

This is the implementation handover for Vennel G3/G4. The wire and authority
contract remains `vennel/docs/gate/2026-09-10-g3-g4-integration-contracts.md`.

## Crate boundary

`link-websocket` owns an HTTP/1.1 WebSocket upgrade over a
`link_endpoint::Stream`. Its public opener takes a `Session` and a virtual URL.
It accepts only canonical `ws://<52-character node id>/events`, requires that
host to equal `Session::peer()`, and passes the already-open Link stream to
`tokio_tungstenite::client_async`; it never resolves the virtual host through
DNS.

The socket driver owns the WebSocket and exposes a synchronous, cloneable send
handle plus one asynchronous inbound receiver. The outbound command channel is
bounded at 64 text frames. Text over the relay frame limit, binary input,
queue overflow and protocol failure close the driver once with a bounded
reason. The driver answers ping, ignores pong, echoes close and emits one
terminal close notification. Dropping every handle closes the Link stream.

`link-ffi` is a `cdylib`, `staticlib` and Rust library using UniFFI library
mode. It owns one multi-thread Tokio runtime and one app-wide `Endpoint`.
Generated Kotlin uses package `dev.forgesworn.link.ffi`; the Android build and
binding scripts follow Bothy's existing cargo-ndk and UniFFI pattern.

## FFI surface

The records passed to `LinkEngine.start` are:

- `LinkConfig`: 32-byte transport seed, relay URLs, direct-path consent and a
  list of routes;
- `LinkRoute`: opaque product `route_id`, verified card bytes, 32-byte paired
  route secret and the retained card serial;
- `LinkPath`: status, route name and any public socket address already present
  in Link's `PathReport`; it contains no rendezvous material.

The object surface is:

```text
LinkEngine.start(config)
LinkEngine.open_socket(virtual_url, route_id, listener) -> LinkSocket
LinkEngine.upsert_route(route)
LinkEngine.remove_route(route_id)
LinkEngine.reannounce()
LinkEngine.stop()

LinkSocket.send_text(text)
LinkSocket.close()
LinkSocket.path() -> LinkPath

LinkSocketListener.on_open()
LinkSocketListener.on_text(text)
LinkSocketListener.on_closed(reason)
```

`start` re-verifies every persisted card's signature, expected node, lifetime
and exact recorded serial without treating that same persisted card as a new
arrival. A live `upsert_route` requires a strictly greater serial than the
route already holds. Start always supplies `Some(paired_routes)`, including an
empty map, so later route additions remain in tag mode. It zeroises decoded
route material after ownership passes to Link. `upsert_route` validates before
replacing the route and updates the endpoint's `TagBook`; `remove_route`
removes the tag first, closes that route's cached session and then drops the
record. Kotlin persists encrypted route state; Link never writes it.

## Session manager

Each route owns an async dial lock and an optional cached `Arc<Session>`.
Simultaneous socket opens for one peer therefore share one dial and one
session, while unrelated peers may dial concurrently. Every WebSocket opens a
new application stream on that session. A stream failure or superseded session
closes every dependent socket once, clears the cached session by generation,
and returns control to KithMoot's existing `RelayPool` reconnect loop. The
bridge never reconnects a product socket itself.

The listener receives `on_open` only after the WebSocket 101 response. NIP-42
application readiness remains KithMoot's next slice, so physical open cannot be
treated as an authenticated relay there.

## Proof

The implementation is finished when tests prove:

1. the virtual host is not resolved and must equal the pinned session peer;
2. two sockets to one route use one session and separate streams;
3. simultaneous opens coalesce one dial;
4. bounded text crosses a real Link loopback and WebSocket server both ways;
5. binary, oversize, overflow and remote close produce one terminal callback;
6. session supersession closes every dependent socket and permits a later
   fresh dial;
7. route removal zeroises/removes rendezvous material and blocks later opens;
8. UniFFI bindings generate, JVM callback tests pass, and
   `aarch64-linux-android` builds;
9. the existing macOS, Ubuntu and Windows workspace checks remain green.
