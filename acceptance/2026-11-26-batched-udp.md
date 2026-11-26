# Linux UDP batching on Raspberry Pi 5, 26 November 2026

## Setup

A Raspberry Pi 5 ran Debian 12 arm64, Linux 6.6.74 and glibc 2.36.
Rust 1.94.1 and GCC 15.2.0 cross-compiled locked release builds.
SHA-256 verified all binaries after transfer. The baseline is Link
`3edd85ac6f813b09e7e65f24bd33fa4b5e1feef4`. The receive-only build is
`b2064df6eb2d5ba657a3546ddf52a89db63945f8`. The tested send-and-receive
build is `0a43e0149f674402c2658942b3c7dc2aaad7fe91`. The
[matched probe](iroh-recovery/README.md#fresh-connections-and-sustained-transfers)
locks Iroh and iroh-relay at 1.5.0.

Each process ran one authenticated pair on IPv4 loopback with a local
TLS relay. Each bulk process verified two warm-ups and eight measured
64 MiB responses through SHA-256 and end of stream. The direct
comparisons used each of the six orders of baseline, candidate and
Iroh, giving 48 measured responses per build. CPU seconds per GiB
include both endpoints, the relay, hashing and the warm-up bytes.

The Pi's `rmem_default` was 212,992 and its `rmem_max` was 10,485,760.
Traces confirmed that each Link build successfully requested 262,144
bytes on each direct socket. Iroh used its normal 7 MiB request.
[Quinn UDP implementation](https://github.com/quinn-rs/quinn/blob/a96949f6cd257c665f544626af4e8ce668a40b30/quinn-udp/src/unix.rs)
· [Iroh socket buffer setup](https://github.com/n0-computer/net-tools/blob/334793cfdaf3487db0c721b9312179a8ae3b0dcb/netwatch/src/udp.rs#L900-L911)

## Receive batching

| Direct UDP | Median MiB/s (range) | Median CPU s/GiB | Median `RcvbufErrors` per 640 MiB process |
| --- | ---: | ---: | ---: |
| Link baseline | 101.49 (97.20–105.76) | 21.83 | 11,604 |
| Link receive batches | 102.09 (98.17–106.97) | 21.81 | 8,563 |
| Iroh 1.5.0 | 150.39 (132.59–166.22) | 12.00 | 0 |

Receive batching reduced the median receive-buffer error count by
26%. Throughput and CPU ranged across the baseline results. Link
still sent one datagram per socket call in this trial.

## Send and receive batching

| Direct UDP | Median MiB/s (range) | Median CPU s/GiB | Median `RcvbufErrors` per 640 MiB process |
| --- | ---: | ---: | ---: |
| Link baseline | 101.91 (97.71–106.27) | 21.80 | 9,785.5 |
| Link send and receive batches | 143.20 (133.83–146.69) | 12.69 | 1,473.5 |
| Iroh 1.5.0 | 150.98 (141.69–167.49) | 12.06 | 0 |

The final comparison gave 40.5% higher median goodput and 41.8% lower
CPU per GiB. Both improved in every block. The counters are host-wide
kernel receive-buffer errors around the loopback workload. A
coalesced receive can represent several UDP datagrams. The initial
send-and-receive candidate also measured 142.82 MiB/s and 12.75 CPU
s/GiB against its baseline of 101.28 MiB/s and 22.03 CPU s/GiB.

The opted-in Linux direct path uses Quinn's existing UDP layer for
batched reads and socket-supported segmentation on writes. There
are eight receive slots sized for the detected receive offload limit.
With 64 segments per slot, the receive task allocates 1 MiB per socket.
Each datagram goes through Link's probe, reflector and proven-address
checks. Direct sends use individual datagrams when the socket rejects
segmentation. When a prepared batch takes the relay path, the driver
reserves every queue slot before enqueuing a datagram and keeps the
existing frame format.

The diagnostic traces counted UDP socket calls including calls returning
`EAGAIN`. Each trace used two warm-ups and one measured response. The
throughput and CPU figures came from untraced processes.

| Traced 192 MiB process | Send calls | Receive calls |
| --- | ---: | ---: |
| Link baseline | 161,917 | 190,526 |
| Link receive batches | 163,508 | 191,266 |
| Link send and receive batches | 21,651 | 34,529 |
| Iroh 1.5.0 | 25,712 | 47,929 |

## Same-session recovery

The [native path probe](2026-11-25-native-transport.md#setup) forwarded
UDP through a loopback gateway with 40 ms round trip and one dropped
packet per 200 in each direction. There were 32 trials per build per
case, run in groups of four. The clock stopped once the original QUIC
session returned a verified 1 KiB response and both sides selected the
expected path.

| Case | Baseline p95 | Send and receive batches p95 |
| --- | ---: | ---: |
| Silent direct loss to relay | 831.4 ms | 831.4 ms |
| Replacement direct address | 313.8 ms | 322.2 ms |

Replacement-address p95 rose by 8.4 ms in the final comparison and
fell by 3.5 ms in the pilot. The medians were within 1 ms of their
baselines in both runs.

The Pi passed the existing wrong-key, unknown-key, replay and relay-only
checks. A burst test used a correct proof, a packet from an unproven
address, and a coalesced receive with a short final segment. The kernel
trace recorded a receive with GRO metadata. The relay backpressure test
filled the queue to one slot short, checked that the entire transmit
waited, then verified both frames on retry. The shaped loss test also
verified a 64 MiB response on the original session after traffic moved
to the relay.

The single-route relay-only check ran 32 verified responses per build.
Median goodput was 84.48 MiB/s at baseline and 84.25 MiB/s with the
candidate. The sample ranges overlapped.

These are same-host transport measurements on physical hardware. WAN,
handset handover and venue soundcheck evidence require field trials.

## Reproduce

Build the [matched native probe](iroh-recovery/README.md#fresh-connections-and-sustained-transfers)
and [recovery probe](2026-11-25-native-transport.md#setup) at each recorded
revision with the pinned toolchain. Keep the baseline and candidate
executables, interleave `iroh-native link direct 8` at each Link revision
with `iroh-native iroh direct 8`, and use each order once. Sample
`Udp: RcvbufErrors` in `/proc/net/snmp` before and after each process.
Run alternating groups of `native_path_probe blackhole 8` and
`native_path_probe handover 8`. The probes check the transfer digest
and selected path before they emit a sample.
