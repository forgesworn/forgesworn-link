# Send a file with a paired Link invite

The receiver creates an invite for one file transfer. The sender uses it to
authenticate first contact, then sends the file on a separate paired Link
session. The demo generates fresh transport keys for the transfer. Keep
the five-minute invite private and share it over a trusted channel.

For a copyable Rust app that reuses the pairing on a later run, see
[Paired file transfers in Rust](../examples/paired-files/README.md).

Build on both machines from the repository root.

```sh
cargo build --locked --release -p link-spike -p link-relay
```

Choose a WSS relay that both machines can reach. To try it on one machine,
start this loopback relay in a separate terminal.

```sh
./target/release/link-relay --ws-bind 127.0.0.1:7443 --host 127.0.0.1
```

Use the relay's printed `relay_url` and `tls_sha256` on both sides. Obtain
the fingerprint through a trusted channel when the relay is on another
machine. A relay with a normally trusted HTTPS certificate needs only
`--relay`.

On the receiving machine, choose a new output path.

```sh
./target/release/link-spike pair-receive \
  --relay wss://127.0.0.1:7443/link \
  --relay-cert-sha256 '<printed SHA-256>' \
  ./received.txt
```

On the sending machine, choose an existing file. Use your relay's reachable
URL in place of the loopback URL if the two machines are separate.

```sh
printf 'hello from Link\n' > ./hello.txt
./target/release/link-spike pair-send \
  --relay wss://127.0.0.1:7443/link \
  --relay-cert-sha256 '<printed SHA-256>' \
  ./hello.txt
```

Paste the value after `invite` into the sender's prompt and press Enter.
Both ends print the byte count, SHA-256 and `path=relayed`. The receiver
saves the file after verifying it and reserves the output path without
overwriting an existing file.

## What the relay sees

| At the relay | Inside end-to-end QUIC |
| --- | --- |
| Pair-scoped rendezvous tags, relay challenges and session tokens | Peer authentication and the invite proof |
| Opaque datagrams and their sizes | The file bytes and its SHA-256 |
| Connecting IPs, timing and traffic volume | The authenticated peer session |

The relay can associate tags that use one connection. The standalone relay
reports instance-wide counters in five-minute intervals. [Security model](../SECURITY.md)

Watch the synthetic fixture inspect decoded frames after WSS termination.
It checks the saved file and prints the count of tag registrations and
routed frames, with assertions for zero identity frames and clear file
markers.

```sh
cargo test --locked -p link-spike --test paired_transfer -- --nocapture
```

The [recovery probe](../acceptance/iroh-recovery/README.md) exercises a
separate case with direct paths enabled and a simulated UDP outage.
