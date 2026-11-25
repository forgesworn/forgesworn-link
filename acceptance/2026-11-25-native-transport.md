# Native transport checks on 25 November 2026

## Setup

Rust 1.94.1 release builds on an Apple M4 Max running macOS 26.6.2.
The baseline was `5f8d49c2f1834e9bccfaa485887b55ee27a8bc09` and the
candidate was `1a7cde99bcbf318d01867a65c14a2fec80a1cae3`.
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

## Results

| Path | Bulk samples per build | Median MiB/s, baseline → candidate | Range MiB/s, baseline → candidate | First-byte p95, baseline → candidate | Median CPU seconds/GiB, baseline → candidate |
| --- | ---: | ---: | ---: | ---: | ---: |
| Relay with 32 idle routes | 16 | 77.9 → 205.5 | 44.9–112.9 → 193.7–223.7 | 214 → 99 µs | 29.4 → 20.5 |
| Relay with one route | 32 | 214.5 → 204.1 | 105.4–219.0 → 197.2–210.1 | 109 → 110 µs | 18.9 → 20.5 |
| Direct UDP | 32 | 206.1 → 199.0 | 154.1–231.3 → 183.8–224.4 | 256 → 64 µs | 15.9 → 17.0 |
| Shaped direct UDP | 4 | 0.459 → 0.458 | 0.458–0.460 → 0.452–0.464 | 46.6 → 46.3 ms | 37.5 → 38.4 |

The single-route relay and direct UDP cases each had a second set of four
process runs with six measured transfers per process. First-byte p95 uses
248 observations per build for those two cases and 124 for the others.
CPU medians use two process measurements per build, or four where repeated.

Relay throughput with 32 idle routes rose 2.6 times. The baseline re-derived
tags until it found the active route, so its timing varied with the book's
iteration order. The candidate indexes tags per live relay connection,
rebuilding on route changes, epoch changes and pairing expiry. The
single-route relay median was about 5% lower. Direct throughput ranges
overlapped and its latency varied between runs. Direct receive and
relay-copy experiments were dropped after mixed timings.

| Recovery case | Samples per build | Baseline p95 | Candidate p95 |
| --- | ---: | ---: | ---: |
| Direct handover with replacement candidates available | 20 | 306 ms | 326 ms |
| Silent loss of the direct path with relay fallback | 20 | 18.75 s | 18.78 s |

Recovery trials ran in groups of up to four independent endpoint pairs.
Silent loss still has a substantially longer outage than the case with
replacement addresses available.

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
