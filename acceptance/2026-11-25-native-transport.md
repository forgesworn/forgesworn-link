# Native transport checks on 25 November 2026

## Setup

Rust 1.94.1 release builds on an Apple M4 Max running macOS 26.6.2.
Two endpoints used a paired route and a pinned local WSS relay. Direct
paths were enabled on both endpoints only for the UDP cases. The probe
verified the selected path, SHA-256 and end of stream. Both builds used
the same probe, compiler, relay settings and payload sizes.

The shaped tests forwarded UDP through a loopback gateway with 20 ms delay
in each direction and a drop every 200 packets per direction. Separate
address families forced traffic through the gateway. The relay stayed
reachable on loopback. A silent outage disabled the old gateway. The
handover test also supplied each endpoint with a new candidate and
requested a fresh proof. Recovery ended when both sides reached the
expected path and a 1 KiB request completed with the expected digest.

Build the [probe](../crates/link-endpoint/examples/native_path_probe.rs)
with the same source on both revisions. Run the throughput cases in
baseline, candidate, candidate, baseline order. The second argument sets
the number of measured bulk samples or recovery trials.

```sh
cargo build --locked --release -p link-endpoint --example native_path_probe
target/release/examples/native_path_probe direct 10
target/release/examples/native_path_probe relay 10
target/release/examples/native_path_probe relay-roster 8
target/release/examples/native_path_probe shaped 2
target/release/examples/native_path_probe handover 20
target/release/examples/native_path_probe blackhole 20
```

The bulk cases use 64 MiB for direct and single-route relay, 8 MiB for
relay with 32 idle paired routes per endpoint, and 4 MiB for shaped UDP.
Each process warms up on two bulk transfers. Each latency observation is
the first read of a warm 1 KiB response. Process user plus system CPU per
GiB includes both endpoints, hashing, setup, warm-up, and the relay or
gateway in that run. Percentiles use the nearest rank.

## Privacy and admission

- Pinned WSS and a local SOCKS fixture exercised pairing, saved-route
  reconnect, failover, TLS host and certificate checks and a hash-verified
  transfer. The fixture saw the relay hostname. Refused or stalled proxy
  negotiation exercised cancellation and verified that the relay received
  no direct connection. Tor isolation used a different label per
  WebSocket. [Configuration and test scope](../docs/native-proxy-routing.md)
- The relay completed full tag registrations and data exchange with
  bounded handshake and write waits. The logging checks captured only
  aggregate activity, including with the binary set to trace.
- A separate source review traced pinned and provisional TLS, pairing
  expiry and cleanup, and relay admission. Existing TLS tests cover
  wrong keys and provisional key possession. Operator admission for a
  private tag relay and the availability of a live session during inbound
  replacement remain review items. [Security boundaries](../SECURITY.md) ·
  [Founders' relay status](../deploy/founders/README.md)

These are local tests. Live Tor, handset handover, independent external
review and audio handover at both venues require their own acceptance runs.
