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
Generated Kotlin uses package `dev.forgesworn.link.ffi`. Run
`scripts/build-android-bundle.sh` from a clean Link checkout to create the
KithMoot hand-off: stripped API-26 arm64-v8a and x86_64 libraries, generated
Kotlin, and a SHA-256 manifest naming the exact source commit. The Android
bundle workflow uploads this directory as `link-ffi-android-<commit>` and
records the immutable artifact digest in its job summary. KithMoot must pin
both that commit and digest before extracting it into its generated build
directory.

## FFI surface

The records passed to `LinkEngine.start` are:

- `LinkConfig`: 32-byte transport seed, relay URLs, direct-path consent and a
  list of routes;
- `LinkRoute`: opaque product `route_id`, verified card bytes, 32-byte paired
  route secret, retained card serial and the time that card was accepted;
- `LinkPairingBundle`: route id, server card, the QR's 16 raw pairing-secret
  bytes and its absolute expiry. The pairing secret is zeroised after Link
  registers the bounded provisional route and is never retained;
- `LinkPath`: status, route name and any public socket address already present
  in Link's `PathReport`; it contains no rendezvous material.

The object surface is:

```text
LinkEngine.start(config)
LinkEngine.pair_route(bundle) -> LinkRoute
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

`start` re-verifies every persisted card's signature, expected node and exact
recorded serial at the retained acceptance time, without treating that same
persisted identity pin as a new arrival. The card's advertisement expiry does
not revoke an enrolled route. A live `upsert_route` requires a strictly greater
serial than the route already holds. Start always supplies
`Some(paired_routes)`, including an empty map, so later route additions remain
in tag mode. It zeroises decoded route material after ownership passes to Link.

`pair_route` verifies and pins the QR's server card, opens Link's one-stream
provisional session, sends the caller's signed card to `PUT /events/route`,
checks the returned server card against the same node, derives the shared TLS
exporter route and closes the provisional session only after reading the whole
bounded response. It installs the route in the live `TagBook` and returns the
exact `LinkRoute` Kotlin must commit to its encrypted vault. Retrying the same
route may replace its exporter while retaining the same server card serial.
`upsert_route` validates before replacing the route and updates the endpoint's
`TagBook`; `remove_route` removes the tag first, closes that route's cached
session and then drops the record. Kotlin persists encrypted route state; Link
never writes it.

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
10. provisional route enrolment and same-capability retry produce exporter
    secrets that agree at both ends, and the retry replaces the live route.
