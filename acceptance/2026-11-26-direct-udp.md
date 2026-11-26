# Direct UDP profiling and physical Linux comparison, 26 November 2026

The baseline is Link `5b6901a47729c638588746f1440d9208697fd687`. The
[matched native probe](iroh-recovery/README.md#fresh-connections-and-sustained-transfers)
uses one peer pair on IPv4 loopback, an approved TLS relay and an authenticated
direct path for the direct measurements. All 64 MiB responses are verified
through end of stream. Each bulk run uses two warm-up responses and eight
measured responses. Each block runs baseline Link, candidate Link and
Iroh 1.5.0 in a different order. The exploratory comparisons use all six
orders for 48 measured responses per build. The selected buffer request
uses four blocks for 32 responses per build. CPU is
process user plus system time, including both peers, hashing and relay work
with the warm-up bytes counted.

Builds use locked release dependencies and Rust 1.94.1. The desktop runs use
an Apple M4 Max on macOS 26.6.2 with Iroh's Apple fast datapath enabled. The
physical runs use a Raspberry Pi 5 on Debian 12 arm64 with glibc 2.36 and
Linux 6.6.74. Those executables were cross-compiled with GCC 15.2 and
transferred to the Pi with their SHA-256 digests checked before running.

## Profile and rejected changes

Two nine-second macOS process stack samples during steady direct transfer
showed the per-datagram send and receive calls, Link's inbound queue, and
SHA-256 address derivation in Link's UDP receive task. The samples include
waiting threads. The bench also hashes application payloads on both
implementations, so total SHA-256 activity is not a routing cost estimate.

Caching the synthetic peer address at proof time left direct goodput
essentially flat on both hosts. macOS CPU seconds/GiB were 14.38 before and
14.45 after, and the Pi measured 21.71 and 21.59. Bypassing the direct receive
queue and reading into Quinn's buffers reduced aggregate CPU seconds/GiB
from 13.95 to 13.66 on the Mac and from 21.75 to 21.61 on the Pi. On the Pi
that change raised the median host-wide Linux UDP `RcvbufErrors` delta from
14,425 to 18,216 per 640 MiB process. All six Iroh deltas were zero. Both
experiments were reverted.

## Linux receive buffer

On the Pi, the kernel receive buffer overflowed during sustained direct
transfers. Link `aff5646ccce1b201d83cabda6f472ff3639e38d4` requests
256 KiB on an opt-in Linux direct socket when the reported capacity is below
that threshold. This is a best-effort per-socket request. Linux doubles the
value for bookkeeping and applies the host limit. The Pi's `rmem_default`
was 212,992 and its `rmem_max` was 10,485,760 bytes. The experiments used
those existing settings.
[Linux socket(7)](https://man7.org/linux/man-pages/man7/socket.7.html)

| Pi 5 direct path | Median MiB/s (range) | Median CPU s/GiB (range) | Median UDP `RcvbufErrors` per 640 MiB process |
| --- | ---: | ---: | ---: |
| Link baseline | 102.75 (98.16–109.20) | 21.76 (21.54–21.93) | 14,974 |
| Link with 256 KiB request | 103.14 (100.28–107.09) | 21.42 (21.16–21.48) | 9,703 |
| Iroh 1.5.0 | 156.95 (148.00–168.73) | 11.66 (11.42–12.12) | 0 |

Read the `RcvbufErrors` field of the `Udp:` counters in
`/proc/net/snmp` immediately before and after each process. These are
host-wide counts recorded while the loopback workload was the active UDP
transfer. In block order, the baseline deltas were 13,621, 16,327, 13,530
and 17,949. The tuned deltas were 11,548, 7,267, 9,691 and 9,714. All four
Iroh deltas were zero.

With the 256 KiB request, median receive-buffer drops fell 35% and CPU per
GiB fell 1.6%. Both improved in all four blocks. Goodput ranges overlapped
between the two Link builds. Iroh led on direct goodput and CPU efficiency.

A separate six-block comparison with a 512 KiB request reduced median
receive-buffer drops from 14,342 to 2,543, with goodput moving from 102.01 to
103.46 MiB/s and CPU from 21.77 to 21.39 s/GiB. The smaller request delivered
a similar CPU saving with a lower kernel queue limit and closely matched
silent-loss recovery timing in its own comparison.

## Relay check

Four blocks on the Pi gave 32 verified relayed responses per build. Link
baseline, the 512 KiB preview and Iroh respectively measured 85.72, 84.48 and 85.28
MiB/s, with overlapping goodput ranges. Median process CPU was 36.25,
36.72 and 38.49 s/GiB respectively. A single-block check of the selected
256 KiB build verified all eight measured relayed responses at 85.30 MiB/s,
compared with 84.33 MiB/s at baseline. The relay-only fixture opens no
direct UDP socket.

## Shaped path recovery

The [native path probe](2026-11-25-native-transport.md#setup) ran four pairs
at a time with a simulated 40 ms round-trip delay and one packet lost per
200 in each direction. The clock stops after the original session returns a
verified 1 KiB response and both endpoints report the expected path. The
replacement-path case supplies a new candidate when the old path stops.

| Host and samples per build | Case | Receive buffer request | Baseline p95 | Candidate p95 |
| --- | --- | ---: | ---: | ---: |
| Pi 5, 24 | Silent UDP loss to relay | 256 KiB | 832.5 ms | 833.3 ms |
| Pi 5, 20 | Replacement direct path | 256 KiB | 312.9 ms | 314.7 ms |
| Pi 5, 20 | Silent UDP loss to relay | 512 KiB | 468.0 ms | 831.1 ms |
| Pi 5, 40 | Silent UDP loss to relay, repeat | 512 KiB | 760.8 ms | 761.6 ms |
| Pi 5, 20 | Replacement direct path | 512 KiB | 320.5 ms | 312.9 ms |
| Debian arm64 VM, 24 | Silent UDP loss to relay | 512 KiB | 466.9 ms | 471.0 ms |

In the first Pi run at 512 KiB, delayed verified responses after relay
selection were more common in the tuned build. The p95 time for both
peers to select the relay was about 467 ms for both builds in that run and the
repeat. Across all 60 Pi blackhole trials per build, baseline and tuned
response-and-path p95 were 760.8 and 828.2 ms. The slowest tuned trial finished
in 831.1 ms. The VM repeated the same binaries on Debian 12 with a 212,992-byte
`rmem_max` cap.

The comparisons use synthetic data and one host at a time. Independent
network and handset trials remain open.
