# Native relay failover during DNS failure

The 26–27 November 2026 runs used Rust 1.94.1, locked dependencies and
[Link d9e9d0a](https://github.com/forgesworn/forgesworn-link/tree/d9e9d0aa375818359a9a08c78a63499299e68d5f).
Both peers used tag routing and advertised the same two owner-approved
relays in their signed cards. The primary used a reserved `.invalid`
hostname. The backup used a literal IPv4 loopback address and a pinned
TLS leaf. [RFC 6761](https://www.rfc-editor.org/rfc/rfc6761.html#section-6.4)

## Results

| Environment | Primary attempt | Observed outcome |
| --- | --- | --- |
| macOS 26.6.2, arm64 | The system resolver returned a lookup error | Both peers registered on the IP relay about one second later in each phase. |
| Debian trixie container, arm64 | A loopback DNS fixture discarded all queries | All four primary attempts reached Link's ten-second deadline. Both peers registered on the IP relay about one second after each deadline. |

In both runs the first-contact handshake derived the same paired-route
secret at both peers. The test closed both endpoints, restored the same
keys, signed cards and route secrets in fresh endpoints, and verified a
1 MiB transfer by SHA-256. Both endpoints reported the pinned IP relay in
both phases.

The Linux container ran with `--network none` and only `127.0.0.1` as its
resolver. The UDP receiver on port 53 observed 32 queries for the fixture
hostname and sent zero replies. The resolver was configured for four
five-second attempts so that Link's own deadline elapsed during lookup.

## Repeat the test

```sh
RUST_LOG=link_endpoint::relay_client=debug \
  cargo test --locked -p link-endpoint --test dns_failover -- --nocapture
```

For the silent DNS case, run the compiled test in an isolated Linux network
namespace with loopback enabled. Set its only resolver to `127.0.0.1` with
`timeout:5 attempts:4`. Bind a UDP receiver to `127.0.0.1:53` inside that
namespace and discard the queries. Check that the fixture sees the primary
hostname, that four relay attempts reach the deadline and that the test passes.

These runs used two native endpoints and a relay on loopback in one test
process. Outage recovery on a WAN, on a handset and in a browser still
requires its own acceptance run.
