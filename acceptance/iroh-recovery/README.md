# Link and Iroh native transport comparisons

## Session recovery

This local comparison starts two endpoints on a WSS relay with a fixture
certificate, proves a direct UDP path and completes a warm 1 KiB request.
The same loopback gateway
forwards both implementations' packets with 20 ms delay and one dropped
packet per 200 in each direction. The endpoints bind different address
families to force direct traffic through the gateway.

Each trial stops forwarding UDP and starts another 1 KiB request on the
same connection. The probe checks the response length and SHA-256 and waits
for each endpoint to report a relay path. Iroh uses its normal path
selection, a loopback-only relay and explicit candidate addresses. The
comparison crate locks Iroh and its dependencies independently of Link.

From the Link workspace, build with the pinned toolchain and run alternating
groups from each implementation.

```sh
cargo build --locked --release -p link-endpoint --example native_path_probe
cargo build --locked --release --manifest-path acceptance/iroh-recovery/Cargo.toml --target-dir target --bin iroh-recovery
target/release/examples/native_path_probe blackhole 4
target/release/iroh-recovery 4
```

Each row contains the case name and three values in milliseconds after the
outage. These are the time for both conditions to hold, the time to receive
the correct response and the time for both endpoints to report the relay.
Trials run in groups of up to four independent pairs. To compare older Link
transport code, build it with this revision's
[native probe](../../crates/link-endpoint/examples/native_path_probe.rs)
and [gateway](../../crates/link-endpoint/examples/support/gateway.rs).
WAN, mobile and venue audio behaviour require separate field tests.

## Fresh connections and sustained transfers

Build the native probe with the same acceptance lockfile. The Python 3
runner uses macOS or Linux process CPU accounting and runs the two
implementations in alternating order. It emits every measured sample
and the aggregates as JSON.

```sh
mkdir -p target/tmp
TMPDIR="$PWD/target/tmp" cargo build --locked --release \
  --manifest-path acceptance/iroh-recovery/Cargo.toml --target-dir target --bin iroh-native
python3 acceptance/iroh-recovery/run-native.py target/release/iroh-native > target/iroh-native.json
```

The probe uses two native endpoints and an in-process TLS relay on
IPv4 loopback. Each fresh relay-only trial measures from endpoint
startup to the first complete, SHA-256-verified 1 KiB response. It
records relay readiness and QUIC dial plus response separately. The
steady-state tests verify 64 MiB responses after two warm-up transfers
on the selected direct or relay path. See the
[recorded native comparison](../2026-11-26-iroh-native.md) for the
configuration, results and scope.
