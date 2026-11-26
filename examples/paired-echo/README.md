# Paired echo in Rust

Run this starter from its directory with Rust 1.94.1.

```sh
cargo run --locked
```

It starts a loopback WSS relay, connects two already paired Link peers and
checks that the client gets its message back over a relayed path. After Cargo
has fetched the dependencies, the demo uses only loopback. It generates keys
in memory and exits after the echo.

```text
Verified echo: hello, Link! (path=relayed)
```

Copy this directory into a new project to use it as a starting point. Its
manifest and lockfile resolve Link from GitHub at an exact revision.

## Add Link to an existing app

For native Rust streams, add `link-endpoint` from your app directory.

```sh
cargo add link-endpoint --git https://github.com/forgesworn/forgesworn-link.git --rev 3e0c0e3f5f6faab53b3c5bebddb11f5bfa847a4a
```

Follow [`src/main.rs`](src/main.rs) for the connection and stream code.

1. Create an `EndpointConfig` with the app's transport key. Set `relays` to
   the user's approved WSS relay specs. `RelaySpec::plain` uses normal TLS
   verification for a `wss://` URL. The starter uses `RelaySpec::pinned` for
   the loopback relay's self-signed certificate.
2. Load your saved route secret under the enrolled peer's `NodeId` in
   `paired_routes`. The starter provisions both peers in memory. For real
   enrolment, use your application's authorised pairing flow and keep the
   transport key and route secret in protected storage. [Paired rendezvous](https://github.com/forgesworn/forgesworn-link/blob/main/docs/PAIRED-RENDEZVOUS.md)
3. Verify a received card with `Card::verify` and
   `VerifyContext::new(now).expecting(enrolled_peer_id)`, with `now` in Unix seconds.
   Dial the verified card with `Endpoint::connect`. The peer uses
   `Endpoint::accept` and checks `Session::peer()` against its application
   permissions. Use `open_stream` and `accept_stream` for app traffic.

The starter embeds `link-relay` to bring up its own loopback fixture. For a
two-machine setup and a standalone relay, see the [paired file quickstart](https://github.com/forgesworn/forgesworn-link/blob/main/docs/paired-quickstart.md).
