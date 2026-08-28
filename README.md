# ForgeSworn Link

A wide-area transport lane for ForgeSworn storage: two authorised nodes find a
route, attempt a direct QUIC path, and fall back to an opaque relay, without
renting one company's endpoint IDs, DNS service or public relay estate.  It is
the native lane a Bothy box or a Tor-less Wildbloom node uses to mirror and
repair between machines.

We own the small contract that matters -- how a node identifies itself, how two
nodes discover a route, how they attempt a direct connection, how they fall back
to a relay, and how a transport plugs into the same Blossom store -- and nothing
beneath the socket.  Every cryptographic primitive, the TLS stack and the QUIC
stack come from standard, independently maintained crates: `quinn`, `rustls`,
`rcgen`, `ed25519-dalek`, `sha2`, `x509-parser`, `tokio`, `tokio-tungstenite`.
Licensed MIT.

The design is the Phase 0 specification: the `FSL-CARD-1` address card, the
WebSocket relay and UDP reflector, the path socket with its synthetic addressing
and signed probes, the single TLS identity rule, and the narrow `Endpoint` /
`Session` / `Stream` surface.  `link-blossom` adds a hash-addressed blob-fetch
protocol over that surface and an optional `shelter-kit` `BlobFetcher` adapter,
so a storage node mirrors and repairs over the lane through the same interface
it uses for Tor and HTTPS.

## Status

The Phase 0 contract passed on loopback and on the open internet.  The
real-network acceptance record is in [`acceptance/`](acceptance/): direct-path
upgrades from a home NAT and from a commercial VPN egress to a public host, a
direct LAN path, relay-only by choice, relay failover killed mid-transfer and
recovered on the second relay in 258 ms, a UDP-blocked network falling back to
the relay, flat memory across a four-times-larger transfer, and zero plaintext
in a capture of a deliberately unencrypted relay hop.  What is still not proven
is listed under [What this does NOT prove](#what-this-does-not-prove).

## Crates

| Crate | What it holds |
| --- | --- |
| `link-core` | Node identity and base32 node IDs, `FSL-CARD-1` encode and verify, SPKI helpers, the synthetic IPv6 address, relay-auth and probe signing, relay frame codec, the rustls verifiers that carry the one identity rule, the `PathStatus` and `PathReport` types |
| `link-relay` | The `link-relay` binary: bounded WebSocket datagram relay plus the stateless UDP reflector |
| `link-endpoint` | `Endpoint`, `Session`, `Stream`, the path socket implementing quinn's `AsyncUdpSocket`, candidate exchange on the control stream, signed UDP probing, and the state machine with its recorded transition history |
| `link-blossom` | The hash-addressed blob-fetch protocol over a `Session` stream, a transport-neutral `BlobSource` serving trait, and an optional `LinkFetcher` (behind the `shelter-kit` feature) implementing `shelter_kit::BlobFetcher` for mirror and repair |
| `link-spike` | The `link-spike` binary: `keygen`, `card`, `serve`, `send` |

## Running the loopback demo

Build first:

```sh
cargo build --release
```

Start a relay.  Plain `ws://` is only allowed with `--insecure-ws`, and only
makes sense on loopback:

```sh
./target/release/link-relay \
  --ws-bind 127.0.0.1:9701 --udp-bind 127.0.0.1:9702 \
  --host 127.0.0.1 --insecure-ws
```

Mint two transport keys.  The seed files are written with owner-only
permissions and are ignored by git:

```sh
./target/release/link-spike keygen --out a.key
./target/release/link-spike keygen --out b.key
```

Serve on one key.  It prints its own card, which is what the other side needs:

```sh
./target/release/link-spike serve \
  --key-file b.key \
  --relay ws://127.0.0.1:9701/link \
  --reflector 127.0.0.1:9702 \
  --bind 127.0.0.1:0 --sessions 1
```

Send from the other key, pasting the `card_b64` value the server printed:

```sh
./target/release/link-spike send \
  --key-file a.key \
  --relay ws://127.0.0.1:9701/link \
  --reflector 127.0.0.1:9702 \
  --bind 127.0.0.1:0 \
  --card <card_b64> --mib 256 --settle 0
```

Both sides print a `PathReport` as JSON on every transition and a final report
with the SHA-256 of the payload.  `--settle N` holds the session on the relay
for N seconds before the first probing round, which is how you watch a transfer
run over the relay and then upgrade.  `--no-direct` on either side declines
direct paths entirely: the session stays `Relayed` and the transfer still
succeeds.

To watch relay failover, start a second relay and pass `--relay` twice in the
same order on both sides, then kill the first relay mid-transfer.

Useful flags on `link-relay`: `--bytes-per-second` for the operator's per-session
budget, `--max-sessions`, `--reflector-per-second`.  Without `--insecure-ws` the
relay generates a self-signed leaf and prints its SHA-256; a client then needs
`--relay-cert-sha256 <hex>` or, for development only, `--relay-insecure-tls`.

## Tests

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

`link-core`'s tests load the frozen JSON in `vectors/` and are the contract:
every `card-valid` entry accepts and re-encodes byte-identically, every
`card-hostile` entry rejects with exactly the rule number it states, and the
SPKI, synthetic address, relay-auth and probe fixtures match byte for byte.

`link-endpoint`'s loopback tests assert on each session's recorded transition
history rather than on a status caught in flight, and the relay-loss test kills
the relay at a point tied to delivered bytes rather than to a wall clock.  They
run a relay and two endpoints in one process and cover: a relayed 8 MiB transfer then a proved upgrade to `Direct` and
another 8 MiB; a declined-direct pair that stays `Relayed`; relay loss with two
relays configured; peak RSS between an 8 MiB and a 64 MiB transfer; and junk
plus forged probes arriving from unproven addresses.

## Recorded loopback runs

One macOS host, `rustc 1.94.1`, debug build for the tests and release for the
demo.  These are the only runs behind any claim in this repository.

| What | Result |
| --- | --- |
| Relayed 8 MiB, then proved upgrade, then direct 8 MiB | Both digests matched; `Relayed` for the first transfer with `direct: null`, `Direct` with the proved address for the second |
| Both sides prove independently | Each side reached `Direct` naming the other side's real UDP address |
| Owner declined direct paths | Stayed `Relayed`, 8 MiB moved, nothing was ever proved on either side |
| Relay loss with two relays | The first relay is killed once the peer has taken delivery of exactly 2 MiB of a 32 MiB transfer, so the kill is tied to progress rather than a wall clock.  Recorded history: `rendezvous (connect) -> relayed (QUIC handshake over relay ok) -> reconnecting (relay session lost) -> relayed (new relay welcome after 32 ms)`.  The in-flight transfer **continued to completion** and its digest matched |
| Peak RSS, 8 MiB then 64 MiB in one process | 15,400,960 bytes then 17,235,968 bytes, growth 1,835,008 bytes, roughly 1.75 MiB for an eightfold larger transfer |
| Release CLI, 256 MiB over a proved direct path | 7.1 s, digests matched on both sides |
| Relay counters, 64 MiB relayed transfer | 58,259 frames in, 78,133,920 bytes, 584 dropped by the relay's 64-frame outbound bound; QUIC recovered all of them |
| Flake hunt | Five concurrent runs of the whole suite: 5 of 5 passed.  Three serial runs with `--test-threads=1`: 3 of 3 passed.  Before the two defects above were fixed, the same five concurrent runs gave 0 of 5 |

## Running this on real machines

Nothing above tells you anything about a network.  To get the Phase 0
acceptance record of spec section 7, a person has to do the following by hand.

1. **Put the relay on a public host.**  Give it a DNS name and a real
   certificate, drop `--insecure-ws`, and open the WebSocket port and the
   reflector UDP port.  Pass `--host <that name>` so relay auth is bound to the
   name the clients dial.  Set `--bytes-per-second` and `--max-sessions` to
   whatever the box can carry, then leave them there for every run.
2. **Cross-compile or build on each machine.**  `cargo build --release` on each
   of the two desktops.  Nothing in the workspace is macOS specific, but no
   Windows or Linux run has happened, so expect to fix something.
3. **Mint one key per device with `keygen --out`,** and keep the seed files.  A
   new key is a new node ID and a new card.
4. **Run the matrix, one row at a time,** recording each outcome separately and
   never inferring one from another: home NAT to home NAT, home NAT to carrier
   CGNAT, VPN egress, a network with UDP blocked outbound, and a LAN pair.  For
   each, run `serve` on one side and `send --mib 256` on the other, and keep
   both sides' JSON output.  The `status` field is the outcome; do not read
   success as evidence of a direct path.
5. **Force the relay-only row** with `--no-direct` on one side.  It must still
   succeed, and both reports must say `relayed`.
6. **Force the failover row** by configuring two relays in the same order on
   both sides and killing the first mid-transfer.
7. **Capture on the relay host** while a transfer runs, and confirm the payload
   frames are opaque.  That capture is a Phase 0 go condition and this
   repository has none.
8. **Android.**  There is no Android build here at all.  The endpoint crate is
   plain tokio and quinn, so an `aarch64-linux-android` build of a small JNI or
   `cargo-ndk` wrapper around `Endpoint`, `Session` and `Stream` is the smallest
   thing that would work.  Then the questions that matter are whether a
   background service keeps the WebSocket session alive across doze, what the
   carrier does to a long-lived outbound WSS connection, and whether the direct
   path survives a Wi-Fi to mobile handover.  Nothing in this spike answers any
   of them, and the state machine has no handling for an interface change: see
   the second open problem below.

Record every row against the table in spec section 7 and treat any missing row
as a no-go, not as a pass.

## What this does NOT prove

The `acceptance/` runs cover a home NAT, a commercial VPN egress, a LAN pair, a
UDP-blocked host and a mid-transfer relay failover, across macOS and Linux.
They do not cover:

- **Two hostile NATs at once.**  Every direct path proved so far is either
  inside one home LAN or to a host with a public address.  A direct hole-punch
  between two carrier-grade or otherwise hostile NATs has not been run.
- **Carrier-grade NAT from a phone.**  The runs used a laptop and a Linux box
  on home broadband, not a handset on a mobile network.
- **Windows.**  Recorded runs are macOS and Linux.
- **Android**, background operation, battery or radio behaviour.  There is no
  Android build here yet; the endpoint is plain tokio and quinn, so an
  `aarch64-linux-android` wrapper is the smallest next step.
- **The relay under sustained multi-tenant load** or deliberate abuse.  The
  capture that showed zero plaintext was a single transfer, not a loaded relay.
- **A full security review.**  The identity rule is implemented and tested for
  the positive case and by unit assertions; there is no adversarial TLS test
  that drives a full handshake with a mismatched key.

## Deviations from the spec

The spec will be corrected from these findings.  Nothing below was done for
convenience alone.

1. **`PathReport.relay` is a `String`, not a `Url`.**  Pulling in a URL crate
   for a spike was not worth it.  The relay client parses `ws://` and `wss://`
   authorities itself.

2. **`PathReport` carries a `cause`.**  Spec 5 lists `status`, `relay`,
   `direct` and `since`.  Spec 4.3 requires every transition to be logged with
   its cause, so the cause is kept on the report as well; otherwise an operator
   reading a report cannot tell `Relayed` after `direct_failed` from `Relayed`
   because the owner declined.

3. **`PathStatus` has an `Idle` variant.**  Spec 4.3 names `Idle` in the state
   machine but spec 5 omits it from the enum.

4. **Which host is signed for relay auth.**  Spec 3.1 says "the lowercase host
   the node believes it connected to" without saying whether the port is part
   of it.  This implementation signs the host only, with no port, and the relay
   verifies against its configured `--host` list rather than the WebSocket
   `Host` header, because a header the client controls proves nothing about
   which relay it reached.

5. **Relay hint length, now closed.**  An earlier draft of 2.3 rule 3 did not
   enumerate the 1 to 255 byte bound that 2.2 states for a relay hint value, so
   the first cut of `Card::verify` did not enforce it.  Rule 3 now names the
   bound, `Card::verify` checks it during hint parsing, and the frozen vectors
   cover both ends with `r3-relay-hint-empty` and `r3-relay-hint-too-long`.  No
   deviation remains here; it is recorded because it changed the spec.

6. **Both sides must probe before either can use a direct path.**  Spec 4.1
   drops "a datagram from an unproven address", and spec 4.2 only makes an
   address proved when a signed pong for a nonce *this side* issued arrives.
   Together those mean a peer that answers pings but never sends its own will
   drop every direct datagram the other side sends it.  The implementation
   therefore probes back, rate-limited to one ping per address per second,
   whenever a valid signed ping arrives from an address it has no fresh proof
   for.  The spec should say this explicitly, or say that a verified inbound
   ping is itself sufficient to accept traffic from that address.

7. **The status follows the socket, not the other way round.**  A session in
   `Relayed` that acquires a fresh proof transitions straight to `Direct`
   without passing through `Probing`, because the path socket starts sending
   direct the moment a fresh proof exists.  The alternative would let a report
   say `Relayed` while bytes went direct, which spec 5 forbids.

8. **`EndpointConfig.probe_delay`, `Session::request_direct()` and
   `Session::history()` are additions.**  The delay holds a session on the relay
   before the first probing round; `request_direct` asks for a round now rather
   than after the 30 second cooldown; `history()` returns every transition the
   session has made, oldest first, bounded at 256 entries.  Spec 4.3 requires
   every transition to be logged with its cause, and a log line is not readable
   by the process that needs to act on it: a state such as `Reconnecting` can
   last 32 ms, so anything that samples `path()` will miss it.  The spec should
   say that the transition record is part of the interface, not only of the log.

9. **Client-side relay TLS pins a fingerprint.**  The spike ships no root
   certificate store, so a `wss://` relay is either pinned by the SHA-256 of
   its DER leaf or accepted unchecked behind an explicit development flag.  A
   deployed relay presents an ordinary WebPKI leaf and a product build would use
   the platform trust store.

10. **`Failed(Timeout)` is reachable from QUIC, not only from the relay.**
    Spec 4.3 only produces `Failed(relay)` and `Failed(identity)`, yet spec 5
    defines a `Timeout` reason.  A QUIC idle timeout maps to it here.

11. **Backpressure rather than loss when the relay queue is full.**  Spec 3.1
    bounds the relay's own outbound queue at 64 frames and says a full queue is
    loss.  The *client's* queue is not specified.  Reporting loss upward from a
    full client queue collapsed throughput, so `try_send` returns `WouldBlock`
    while a relay session is up and the `UdpPoller` wakes quinn when the queue
    drains below half.  When no relay session is up, the datagram is dropped as
    loss, so a reconnect can never deadlock the QUIC driver.

## Defects the spike found in itself

Both were invisible in a quiet single run and showed up only when five copies of
the suite ran at once.  Both are spec lessons, not only code fixes.

1. **The control stream was "first" only by luck.**  Spec 4.2 says candidates
   travel on "the first stream each side opens".  The first implementation
   opened it from a spawned task, so under load an application stream could win
   the race for the lower QUIC stream ID.  The peer then routed the application
   stream into the control reader, read the payload's length prefix as a control
   frame, gave up and dropped the receive half, and the sender saw
   `sending stopped by peer: error 0` part way through an 8 MiB transfer.  The
   fix is to open the control stream inside session setup and await it before
   the session is handed to the application, so no application stream can
   precede it.  **The spec should say the control stream must be opened before
   the session is usable**, because "the first stream each side opens" is a
   property an implementation has to enforce, not one it gets for free.

2. **A relay failover faster than the state machine's tick was never recorded.**
   The state machine sampled relay status on a 100 ms tick.  A failover on
   loopback completes in about 32 ms, so `Relayed -> Reconnecting -> Relayed`
   happened on the wire and in the relay logs while the session's own status
   never left `Relayed`.  Spec 4.3 requires that transition to be recorded, and
   an implementation that samples cannot honour that.  The relay client now
   publishes every distinct status on an ordered broadcast queue and the state
   machine consumes it as an event stream; only the direct-path timers are still
   driven by the tick.  **The spec should say the relay transition is observed,
   not polled.**

## Open problems

- **Relay convergence is by convention.**  Each endpoint keeps one relay session
  at a time and both sides walk the same configured list in the same order, so
  they converge.  Nothing forces that.  A real deployment needs per-peer relay
  selection from the peer's card hints, or endpoints registered on several
  relays at once.  The spec does not decide this.
- **Candidates are exchanged once.**  A new interface or a new reflexive result
  after the handshake is never announced.  A long-lived session on a device that
  changes network will not re-offer candidates.
- **The reflector result is a single value with no source check.**  Anything
  that can reach the direct socket can set it by sending a well-formed reply.
  It only ever becomes a candidate the peer is asked to probe, so the cost of a
  lie is a wasted probe, but it should be nonce-matched.
- **No adversarial TLS handshake test.**  The one identity rule is exercised in
  the positive direction end to end and asserted directly on the verifier.  A
  test that drives a handshake where the presented key differs from the pin
  needs an endpoint that can be told to lie, which the API deliberately does
  not allow.
- **Inbound queue overflow is silent.**  The path socket's inbound queue is 512
  datagrams; a full queue drops, which QUIC treats as loss.  There is no counter
  for it, so a saturated receiver looks like a lossy network.
- **The relay replaces a duplicate registration silently.**  Two sessions
  authenticating as the same node ID leave the newest registered and the oldest
  with a dead route.  The spec does not say what should happen.
- **Card serials come from the wall clock.**  `Endpoint::card` seeds the serial
  from Unix seconds and increments.  A clock that goes backwards across a
  restart produces a card that a verifier will reject under rule 8, correctly
  but confusingly.  Persisting the last serial is the real answer.
