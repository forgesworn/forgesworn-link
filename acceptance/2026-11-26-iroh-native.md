# Native Link and Iroh comparison, 26 November 2026

## Setup

Rust 1.94.1 release build on an Apple M4 Max running macOS 26.6.2.
The comparison uses the Link transport source at
`5408317de549da97c4a591ad2a4fa3f06b46811b` and Iroh and iroh-relay
1.5.0. Link uses the same Quinn 0.11.11, quinn-proto 0.11.18 and
quinn-udp 0.5.15 versions as that revision's workspace. Iroh enables its
Apple fast datapath. The probe uses one acceptance lockfile and four
Tokio worker threads. [Link source](https://github.com/forgesworn/forgesworn-link/tree/5408317de549da97c4a591ad2a4fa3f06b46811b) · [Iroh release](https://github.com/n0-computer/iroh/releases/tag/v1.5.0)

Each process runs one implementation's endpoints and its TLS relay on
IPv4 loopback. Both use explicit relay addresses and local trust. Link
uses a pinned relay leaf and a prepared paired route. Iroh uses a local
trust root, explicit peer addresses and its standard relay identity
routing. Relay admission is open on loopback for both fixtures. The relay
stays available in the direct test. Link starts its session through the
relay and upgrades to direct UDP. Both endpoints must select the
expected path before a bulk transfer is counted.

Each cold trial starts with a listening relay and fresh endpoint
configurations. The clock starts before the endpoints bind. The probe
waits for both endpoints to report relay readiness, then dials and
accepts the QUIC connection. It stops the clock after the first complete
1 KiB response passes the SHA-256 and size checks. The probe also records
the time from just before QUIC dial to that response. Relay creation and
endpoint key generation are outside both timings. Cold trials use
relay-only transports.

Each bulk process warms up with two 64 MiB responses, then measures
eight more on the same session. Goodput uses elapsed time from opening
the application stream through end of stream and SHA-256 verification.
Link checks both endpoint path histories throughout, and Iroh checks
both selections and the receiver's byte count on the selected path.
CPU seconds per GiB include both endpoints, the relay, hashing, setup and
teardown. The denominator includes the two verified warm-up responses.

## Results

Six alternating blocks per case gave 120 cold trials and 48 measured
bulk transfers per path per implementation. Cold p95 uses the nearest
rank. CPU figures are medians of the six process measurements.

| Cold relay timing | Link p50 | Link p95 | Iroh p50 | Iroh p95 |
| --- | ---: | ---: | ---: | ---: |
| Endpoint startup to verified response | 2.845 ms | 4.410 ms | 216.442 ms | 221.983 ms |
| Endpoint startup through relay readiness | 1.273 ms | 1.936 ms | 214.211 ms | 218.919 ms |
| QUIC dial after readiness to verified response | 1.554 ms | 2.275 ms | 2.368 ms | 3.559 ms |

| Warm path | Link MiB/s median (range) | Iroh MiB/s median (range) | Link CPU s/GiB | Iroh CPU s/GiB |
| --- | ---: | ---: | ---: | ---: |
| Direct UDP | 191.8 (183.5–199.9) | 226.1 (212.3–250.5) | 13.49 | 11.69 |
| TLS relay | 285.1 (218.0–319.7) | 234.6 (176.0–255.5) | 15.97 | 18.19 |

The relay-readiness stage accounts for most of the cold-start gap. On
the warm relay path Link delivered 22% higher median goodput with 12%
less process CPU per GiB. On direct UDP Link delivered 15% lower median
goodput and used 15% more CPU per GiB. All six block medians followed
the same goodput ordering for each path.

A four-block repeat added 80 cold trials and 32 bulk transfers per path
per implementation. Cold startup p95 was 4.071 ms for Link and
221.369 ms for Iroh. After relay readiness, dial-to-response p95 was
2.238 ms and 3.582 ms respectively. Direct goodput medians were
192.3 and 226.3 MiB/s, and relayed medians were 294.3 and 236.1 MiB/s.
CPU per GiB again favoured Iroh on direct UDP (11.74 vs 13.47 s/GiB)
and Link on the relay (15.76 vs 18.40 s/GiB).

These measurements cover native IPv4 loopback and one pair at a time.
Cross-network relay behaviour, handset handover and venue audio
latency require field measurements.

## Reproduce

Run the [locked native probe](iroh-recovery/README.md#fresh-connections-and-sustained-transfers).
The runner emits per-sample times, per-process CPU and summary statistics
as JSON.
