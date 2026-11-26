# Link and Iroh recovery comparison

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
cargo build --locked --release --manifest-path acceptance/iroh-recovery/Cargo.toml --target-dir target
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
