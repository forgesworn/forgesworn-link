# ForgeSworn Link

A wide-area transport lane for ForgeSworn storage: two nodes find a route,
attempt a direct QUIC path, and fall back to an opaque relay. Rust workspace,
edition 2024, unpublished (`publish = false` at the workspace level; the
library crates set `publish.workspace = true` and are unpublished by
inheritance). Every crypto primitive, the TLS stack and the QUIC stack are
independently maintained crates (`quinn`, `rustls`, `ed25519-dalek`, `sha2`,
`hkdf`, `tokio`, `tokio-tungstenite`); this project owns only the protocol
contract on top of them.

## Build & Test

| Command | Purpose |
|---------|---------|
| `cargo build --release` | Build the workspace, including the `link-relay` and `link-spike` binaries |
| `cargo fmt --all --check` | Check formatting |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | Lint |
| `cargo test --workspace --all-features` | Run the test suite |
| `python3 -m unittest discover -s deploy/founders -p 'test_*.py' -v` | Test the deployment scripts |
| `scripts/build-link-web.sh [--target web\|bundler\|nodejs]` | Build the browser package (needs wasi-sdk 34.0 via `WASI_SDK`; `--check` reports missing inputs) |

Toolchain is pinned at `1.94.1` in `rust-toolchain.toml`. CI (`.github/workflows/ci.yml`) runs format, clippy and test on Linux, Windows and macOS.

## Structure

```
crates/link-core/       node identity, FSL-CARD-1 card, wire formats, TLS identity rule, PathStatus/PathReport
crates/link-endpoint/   Endpoint, Session, Stream, the path socket, rendezvous book
crates/link-relay/      link-relay binary: WebSocket datagram relay + UDP reflector
crates/link-websocket/  WebSocket transport glue
crates/link-blossom/    hash-addressed blob-fetch protocol over a Session, optional shelter-kit adapter
crates/link-engine/     the paired-route engine shared by link-ffi and link-web
crates/link-ffi/        uniffi bindings (Kotlin/Android)
crates/link-web/        wasm-bindgen browser engine, relay-only
crates/link-spike/      link-spike binary: keygen, card, serve, send (demo/acceptance CLI)
vectors/                frozen JSON test vectors that are the contract for link-core
acceptance/             recorded real-network acceptance runs
docs/                   rendezvous, pairing and Android bridge design notes
deploy/founders/        deployment scripts and systemd unit for the founders relay
SPEC.md                 the Phase 0 protocol specification
```

## Conventions

- British English in prose and comments.
- `vectors/` is a frozen contract: `link-core`'s tests assert against it byte for byte. Do not change expected values there.
- Deviations from `SPEC.md` are recorded in the README under "Deviations from the spec", not silently implemented.
- No claim in the README is made without a recorded run; see "Recorded loopback runs" and `acceptance/`.

## Key Files

| File | Purpose |
|------|---------|
| `crates/link-core/src/card.rs` | `Card` encode/verify, the `FSL-CARD-1` rules |
| `crates/link-endpoint/src/endpoint.rs` | `Endpoint`, `EndpointConfig`, pairing |
| `crates/link-endpoint/src/path_socket.rs` | The `AsyncUdpSocket` implementation that moves between relay and direct |
| `SPEC.md` | Protocol specification |
| `vectors/` | Frozen card and wire-format test vectors |

## Common Pitfalls

- Plain `ws://` relay mode (`--insecure-ws`) is loopback-only; do not suggest it for a real deployment.
- A direct path requires both sides to have probed each other; an unproven address is never trusted with traffic (see README "Deviations from the spec", point 6).
- Session state is keyed per peer and superseded at dial/accept time; do not assume a reconnecting session reuses the old direct proof.
- A browser build (`wasm32-unknown-unknown`) is relay-only by construction: no UDP, no direct path, `wss://` WebPKI relays only. Do not add a fallback transport to it.
- `link-ffi` and the Android bundle (`scripts/build-android-bundle.sh`) prove native compilation only, not real device behaviour (doze, carrier handover); do not cite them as proof of mobile operation.
