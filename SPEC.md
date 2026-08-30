# ForgeSworn Link specification

**Version:** 1 (`FSL1` cards, ALPN `fsl/0`).
**Status:** Normative.

This document specifies the ForgeSworn Link transport: the endpoint address
card, the relay and reflector contract, the path model and state machine, the
narrow session interface, and the vectors that freeze the wire. It is what the
`link-core`, `link-relay`, `link-endpoint` and `link-blossom` crates implement
and what an independent implementation builds to. Not in scope: storage,
authority, retention, Nostr envelope kinds, browser code, Android packaging.

## Conformance

The keywords MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT and
MAY are to be interpreted as in RFC 2119. The numbered and imperative rules in
this document are normative requirements: in particular the node-identity and
canonical-encoding rules of §1, the verification order and every "fail the whole
card" clause of §2, the relay and reflector bounds of §3, and the connection
state machine of §4.3. An implementation that does not enforce them is
non-conformant. The known-answer vectors of §6 freeze the wire: a conformant
implementation reproduces every positive vector byte-for-byte and rejects each
hostile vector with the stated rule.

## 0. Design in one paragraph

Each node owns an Ed25519 transport key.  Its public key is the node ID.  A
node publishes a short-lived, signed **address card** carrying relay hints and,
only with the owner's consent, network candidates.  Two nodes talk over one
IETF QUIC connection (Quinn, rustls, TLS 1.3) whose certificate check is a
single rule: the peer's presented public key byte-equals the node ID in the
card.  QUIC never learns which path it is on.  Beneath it, a **path socket**
delivers QUIC datagrams either through a **relay** (opaque, bounded frames over
WebSocket Secure) or over a **direct** UDP path it has proved with signed
probes.  The relay also runs a **reflector** so nodes can learn their public
UDP address.  Standard Blossom over Tor or HTTPS is a separate, independently
configured route and is never touched by this document.

That is the same shape as iroh's magic socket and Tailscale's disco layer.  The
difference is that every piece is ours or standard: no third-party endpoint
IDs, DNS discovery, public relay estate or moving Rust API sits inside the
contract.

## 1. Node identity

- **Transport key.**  Ed25519, generated on first run, stored in the
  platform's protected per-user application state with `0600` (or the
  platform's closest equivalent).  It is never derived from, wrapped by or
  published next to the owner's Nostr key.
- **Node ID.**  The 32-byte Ed25519 public key.  Canonical text form is
  lowercase RFC 4648 base32 with no padding, 52 characters, which fits a DNS
  label.  Hex (64 characters) is permitted in logs and vectors.
- **Canonical decoding.**  52 base32 characters carry 260 bits; the low 4 bits
  of the final character are padding and MUST be zero.  A decoder MUST require
  exactly 52 lowercase characters and MUST reject any input whose value does not
  re-encode to the same string, so that each node has exactly one textual name.
  Without this, 16 spellings decode to one node and any allowlist, cache or
  dedup keyed on the text is bypassable.
- **TLS binding.**  Every QUIC endpoint presents a self-signed X.509 leaf whose
  SubjectPublicKeyInfo is exactly the Ed25519 node public key
  (`id-Ed25519`, OID 1.3.101.112, RFC 8410).  Verification, on both client and
  server sides, is one rule: **the presented SPKI byte-equals the expected node
  ID's SPKI, and the TLS 1.3 CertificateVerify signature validates under that
  key.**  Chain, names, validity dates and extensions are ignored; card expiry
  governs freshness.  An endpoint that presents any other key fails closed.
  RFC 7250 raw public keys satisfy the same rule and may replace X.509 later
  without changing the contract.
- **Rotation.**  A new transport key is a new node ID.  It requires a new card
  and re-pairing; it does not change any stored blob claim, which belong to
  Nostr signers, not transport keys.

## 2. Address card, `FSL-CARD-1`

A card is a fixed binary structure.  It is transported opaquely (base64 inside
a Nostr envelope, a QR code, a local pairing exchange) and signed over its
exact bytes, so no language needs canonical JSON or CBOR.

### 2.1 Layout

All integers are big-endian.

| Offset | Size | Field | Rule |
| --- | --- | --- | --- |
| 0 | 4 | `magic` | ASCII `FSL1` |
| 4 | 1 | `version` | `0x01` |
| 5 | 32 | `node_id` | Ed25519 public key |
| 37 | 8 | `issued_at` | Unix seconds |
| 45 | 8 | `expires_at` | Unix seconds; `issued_at < expires_at <= issued_at + 604800` |
| 53 | 8 | `serial` | Strictly increasing per node ID across every card it ever signs |
| 61 | 1 | `hint_count` | `0..=16` |
| 62 | var | `hints` | `hint_count` entries, see 2.2 |
| 62 + hints | 64 | `signature` | Always the final 64 bytes of the card.  Ed25519 over `DOMAIN || bytes[0 .. len - 64]` |

`DOMAIN` is the 23-byte ASCII string `forgesworn-link/card/v1` followed by a
single `0x00`, 24 bytes in all.  A card is at most 4096 bytes.  Because the
signature is a fixed-size trailer, the hint region must end exactly 64 bytes
before the end of the card; a verifier locates the signature before it parses
a single hint.

### 2.2 Hints

Each hint is `kind: u8`, `length: u16`, `value: length bytes`.

| Kind | Name | Value | Notes |
| --- | --- | --- | --- |
| `0x01` | relay | UTF-8 `wss://` URL, 1..=255 bytes | Where the node keeps an outbound session.  Several allowed.  No ForgeSworn hostname is mandatory or default in the wire format |
| `0x02` | udp | 16-byte IPv6 address (IPv4 as `::ffff:a.b.c.d`) followed by `u16` port, exactly 18 bytes | A local or reflected candidate.  **Present only when the owner has opted into direct paths for this card** |
| `0x03` | onion | 56-byte v3 onion hostname without `.onion`, followed by `u16` port, exactly 58 bytes | Pointer to the independent Tor route for the same node |

Unknown kinds are skipped by readers and remain inside the signed bytes.  A
hint whose `length` disagrees with the fixed size for its kind, or runs past
the card, fails the whole card.

### 2.3 Verification, fail closed

A verifier holds `now`, an allowed clock skew of 300 seconds, and the highest
`serial` it has previously accepted for each node ID.  It checks these rules
in this order and reports the first that fails:

1. length < 126 (the minimum with zero hints) or > 4096;
2. `magic` or `version` differ;
3. `hint_count > 16`, a hint runs past `len - 64`, a fixed-size kind has the
   wrong `length`, a relay hint is empty or longer than 255 bytes, or the
   hints do not end exactly at `len - 64`;
4. the signature does not verify under `node_id` over the domain-prefixed body;
5. `issued_at > now + 300`;
6. `expires_at <= now`;
7. `expires_at <= issued_at` or `expires_at - issued_at > 604800`;
8. `serial <= highest_seen(node_id)` (a stale or replayed card);
9. the node ID is not the one the verifier was told to expect, when it was
   told to expect one.

Rule 8 makes replay of an old card fail even while it is unexpired.  Rule 9 is
how a pairing flow binds a card to the peer the owner chose.  There is no
partial acceptance, and a verifier never accepts a card it cannot fully parse.

### 2.4 Owner endorsement

Pairing may attach a Nostr endorsement: the owner's key signs, inside a NIP-44
encrypted envelope to the invitee, the statement "this node ID is mine for this
purpose".  The endorsement is a separate object.  It is never placed in the
card, never published, and never required by the transport.  Its event kind
and shape belong to a later revision with the Bothy pairing flow.

## 3. Relay and reflector

One self-hostable binary, `link-relay`, offers two services.  Operators may
run several from different organisations; a client may remove every
ForgeSworn-operated instance and still work.

### 3.1 Relay session over WebSocket Secure

- The node opens a WSS connection outbound.  Every home firewall and carrier
  network permits this.
- **Authentication.**  The relay sends `challenge` (32 random bytes).  The node
  replies with `node_id` and an Ed25519 signature over
  `forgesworn-link/relay-auth/v1\0 || u16 len || relay_host || challenge`,
  where `relay_host` is the lowercase host name the node believes it
  connected to, without a port, length-prefixed so the input cannot be
  re-split, so a captured handshake cannot be replayed to another relay.
  *Spike finding:* the relay verifies against the host names it was
  configured to answer for, never against a client-supplied `Host` header.  The relay verifies and
  assigns a **routing token**: 16 random bytes valid for the WSS session only.
- **Frames.**  Binary WebSocket messages:

  | Byte 0 | Frame | Body |
  | --- | --- | --- |
  | `0x01` | challenge | 32 bytes |
  | `0x02` | auth | 32-byte node ID, 64-byte signature |
  | `0x03` | welcome | 16-byte routing token |
  | `0x10` | send | 32-byte destination node ID, then a QUIC datagram of 1..=1350 bytes |
  | `0x11` | recv | 32-byte source node ID, then the datagram |
  | `0x20` | ping / `0x21` pong | 8 bytes opaque |
  | `0x7f` | close | `u16` reason |

  The relay forwards `send` to the WSS session currently registered under the
  destination node ID, rewriting it as `recv` with the sender's node ID.  It
  never inspects, reorders or retries datagrams; QUIC does that.  A destination
  with no session is dropped silently, which QUIC treats as loss.
- **Bounds.**  Per session: at most 64 queued outbound frames, a per-second
  byte budget the operator sets, and idle close after 90 seconds without a
  ping.  Per relay: a cap on concurrent sessions, and a cap on concurrent
  sessions per source address, both counted from accept so an unauthenticated
  handshake cannot slip under them; a tag session (section 9) presents no
  identity, so the per-source cap is what stops one address holding every
  slot.  Oversize or malformed frames close the session with reason `1`.
- **Superseded sessions.**  A node ID is registered by at most one identity
  session and a tag by at most two tag sessions (the two ends of one pair).
  A newer registration wins: the relay sends the oldest holder `close` with
  reason `2` and ends that session, so a node that reconnected before its
  previous session died is not left with a dead route, and nothing is
  silently replaced.  A client that receives reason `2` waits 30 seconds
  before it reconnects, because two live instances of one node ID would
  otherwise supersede each other in a loop.
- **What the relay learns.**  Node IDs of registered endpoints and who they
  talk to, source IP addresses of WSS sessions, timing and byte counts.  It
  must log only routing tokens and counters, and must not persist node IDs past
  the session.  It cannot learn anything inside a datagram: those are QUIC
  packets protected by the TLS 1.3 keys of the two endpoints.
- **What it never learns.**  Nostr keys or events, blob plaintext or envelope
  keys, retention tier, content hashes unless an application puts them on the
  wire deliberately, or the social identity behind a node ID.  Blinding node
  IDs from the relay is future work, not a Phase 0 requirement.

### 3.2 UDP reflector

- The relay binary also listens on UDP.  A node sends
  `FSLR` || `0x01` || 16-byte nonce.  The reflector replies
  `FSLR` || `0x02` || the same nonce || 16-byte observed IPv6 (v4-mapped) ||
  `u16` observed port.  No state, no authentication, 21 bytes in, 39 bytes
  out.  Rate-limited by source address.
- A node uses the reply to learn its reflexive candidate, exactly as STUN
  binding does.  It is a hint, not proof: a symmetric NAT will hand out a
  different port to the peer.

## 4. Path model

### 4.1 Path socket

QUIC runs over a path socket that implements Quinn's `AsyncUdpSocket`.  Each
peer is addressed inside QUIC by a **stable synthetic address**: an IPv6
unique-local address derived from the node ID (`fd00:` prefix followed by the
first 14 bytes of `SHA-256("forgesworn-link/addr/v1\0" || node_id)`), port
`7`.  QUIC never sees a real address, so switching between relay and direct
is invisible to it: no migration, no connection ID change, no application
event.  The socket keeps, per peer:

- the relay session to use (`relay` path), and
- an optional proven direct address (`direct` path) with the time it was last
  proved.

Outbound datagrams go direct when a proven direct path is fresh (proved within
the last 15 seconds), otherwise via relay.  Inbound datagrams are accepted from
either and attributed to the peer by the relay's source node ID or by the
direct address that was proved for that peer.  A datagram from an unproven
address is dropped.

*Spike finding, queues.*  While a relay session is up and the socket's outbound
queue is full, the socket applies backpressure to QUIC (it reports
would-block and wakes QUIC when the queue half-drains) rather than dropping;
reporting loss upward collapsed throughput.  With no relay session up it drops,
so a reconnect can never deadlock the QUIC driver.  Inbound overflow drops and
must be counted; the spike counts only at the relay, which is a gap.

### 4.2 Probing

Direct candidates travel **inside** the QUIC connection on a dedicated
bidirectional control stream (the first stream each side opens), so the relay
never sees them and only an authenticated peer receives them.  *Spike
finding:* "first stream" is a rule the implementation must enforce, not hope
for.  A session is handed to the application only after its control stream
has been opened; otherwise an application stream can win the lower stream ID
under load, be mistaken for the control stream and reset mid-transfer.  A
control stream that goes quiet is held open, never dropped.  Each side sends
its candidate list: every interface address of the socket's family that is
neither loopback nor link-local, the default route's address first and at
most eight, then loopback, then the reflector result.  *Spike finding:* a
list holding only the default route's address made a LAN pair fall back to
the relay whenever a VPN held the default route, because the LAN address was
never offered.  Each side then sends signed probes over UDP to every
candidate of the other side:

- `FSLP` || `0x01` || 32-byte sender node ID || 32-byte receiver node ID ||
  16-byte nonce || Ed25519 signature over `forgesworn-link/probe/v1\0` and
  the preceding fields;
- the receiver, if the signature verifies under the sender node ID it already
  knows from QUIC and the receiver node ID is its own, replies with `0x02` and
  the same nonce, signed the same way;
- a path is **proved** for a peer when a signed pong for a nonce this side
  issued arrives from an address.  Both sides prove independently.
- *Spike finding, one-sided proving.*  A side that receives a valid signed
  ping from an address it holds no fresh proof for sends its own probe to that
  address at once, rate-limited to one per address per second.  Without this a
  peer that answers pings but never issues its own is proved by nobody, and
  every direct datagram it sends is dropped under 4.1.

The control stream carries two message kinds, each a `u32` big-endian length
followed by a kind byte and a body: `0x01 candidates` (a `u8` count, then
18-byte address entries as in the `udp` hint) and `0x02 punch-now` (no body).
A side MAY re-send `candidates` whenever its addresses change and SHOULD
follow it with `punch-now`.  On receiving `punch-now` a side starts a probing
round at once, so both ends punch in the same instant, which is what a NAT
mapping needs: a round started by one side's timer alone reaches a peer whose
own round is on a different timer only if the peer's NAT happens to be open,
and after one failed round the two cooldowns drift apart.  A side counts the
`punch-now` messages it receives, so an operator can tell "the peer never
asked" from "the peer asked and every probe was lost".  Unknown kinds are
ignored.

Probes carry node IDs in clear, which an on-path observer can read.  They
never carry anything else.  Encrypting them is future work.

### 4.3 State machine

Per peer session.  Every transition is logged with its cause.

```text
Idle
  connect() ------------------------> Rendezvous
Rendezvous   (WSS open, welcome received, peer card verified)
  QUIC handshake over relay ok ----> Relayed
  relay unreachable / auth refused -> Failed(relay)
  identity rule fails --------------> Failed(identity)
Relayed      (application usable; bytes flow via relay)
  owner allows direct and candidates exchanged -> Probing
Probing      (bytes still flow via relay)
  a direct address proved ---------> Direct
  all probes time out (5 s) --------> Relayed   [record: direct_failed]
Direct       (bytes flow direct; relay session kept alive)
  proof older than 15 s and re-probe fails -> Relayed   [record: direct_lost]
Relayed | Direct
  relay session lost --------------> Reconnecting (next configured relay,
                                       then the same one, backoff 1..30 s)
Reconnecting
  new relay welcome ----------------> previous state
  no relay within 60 s -------------> Failed(relay)
Failed(reason)
  application is told once, with the reason.  Nothing is retried on its
  behalf; the standard Blossom-over-Tor/HTTPS route is a separate decision
  above this layer.
```

*Spike findings on the diagram.*  `Idle` exists before `connect()` and is a
reportable status.  `Probing` can be too brief to observe: the socket sends
direct the moment a fresh proof exists and the report follows the socket, so
`Relayed -> Direct` is a valid observed transition and a report never says
`Relayed` while bytes go direct.  `Failed(Timeout)` is produced when QUIC's
idle timeout fires with no usable path.  Every transition carries its cause
in the report, and tests assert on the recorded transition history, not on
catching a status in flight.  *Spike finding:* relay session changes are
delivered to the state machine as ordered events, never sampled; a loopback
failover completes in about 35 ms and a 100 ms poll recorded nothing.

Rules the spike must demonstrate:

- entering or leaving `Direct` never stalls, duplicates or corrupts an open
  QUIC stream;
- `Failed` is explicit, once, with a reason; there is no half-open state that
  looks like success;
- relay-only (owner declined direct paths) is a first-class configuration and
  produces the same application behaviour, just via `Relayed`.

## 5. Narrow interface

The Rust surface the storage adapter will consume.  Other languages implement
the wire, not this signature.

```rust
pub struct Endpoint;           // owns the transport key, the path socket and relays
pub struct Session;            // one QUIC connection to one peer
pub struct Stream;             // one bidirectional QUIC stream

pub enum PathStatus { Idle, Rendezvous, Relayed, Probing, Direct, Reconnecting, Failed(FailReason) }
pub enum FailReason { Relay, Identity, Timeout }
pub struct PathReport {
    pub status: PathStatus,
    pub relay: Option<String>,      // the relay URL in use, as text
    pub direct: Option<SocketAddr>, // only ever a proved address
    pub cause: String,              // why the last transition happened
    pub since: Instant,
}

impl Endpoint {
    pub fn open(config: EndpointConfig) -> Result<Self>;                       // key, relays, direct-paths consent
    pub fn card(&self, ttl: Duration, hints: Hints) -> Card;                   // signs a fresh FSL-CARD-1
    pub async fn connect(&self, card: &Card) -> Result<Session, FailReason>;   // verifies card, rendezvous, QUIC
    pub async fn accept(&self) -> Result<Session, FailReason>;                 // inbound, identity already enforced
    pub async fn close(&self);
}

impl Session {
    pub fn peer(&self) -> NodeId;
    pub fn path(&self) -> PathReport;                                          // exact current path, never inferred
    pub fn history(&self) -> Vec<PathReport>;                                  // bounded, ordered transition record
    pub fn request_direct(&self);                                              // owner consent, per session
    pub async fn open_stream(&self) -> Result<Stream>;
    pub async fn accept_stream(&self) -> Result<Stream>;
    pub async fn close(&self, reason: u32);
}
```

`Stream` is a plain `AsyncRead + AsyncWrite` pair.  There is no message type,
no framing above QUIC and no knowledge of Blossom.  The storage core's
`BlobFetcher` adapter for this lane will open a stream, write a hash-addressed
request, and stream the reply through the same length-and-digest gate every
other fetcher uses.

## 6. Vectors

`vectors/` freezes the wire in language-neutral JSON so the Rust daemon, the
Android client and any browser code verify the same bytes.

- `card-valid.json`: deterministic seed, node ID (hex and base32), the full
  card hex with zero, one and three hints, the signing input hex, the
  signature hex.
- `card-hostile.json`: for each rule in 2.3, at least one fixture that trips
  that rule and no earlier one, with the rule number a verifier must report.
  Fixtures for rules other than 4 carry a valid signature over their hostile
  bytes, so the reported rule is the one under test rather than a side effect.
- `spki.json`: the DER SubjectPublicKeyInfo for the vector key, the byte
  offsets of the 32-byte key within it, and the synthetic IPv6 address from
  4.1.
- `relay-auth.json` and `probe.json`: challenge, host, nonce, the signing
  input and signature for each.

The generator is a short script with no dependencies beyond an Ed25519
implementation.  Vectors are regenerated only when the version byte changes.
The first frozen set lives beside the spike; on a passing spike it moves to the
provider repository's `vectors/` directory, published separately from the
implementation.

## 7. Spike acceptance record

Every run records, separately, and never infers one from another:

| Field | Values |
| --- | --- |
| pair | desktop A / desktop B / Android |
| network | home NAT / carrier CGNAT / VPN egress / UDP blocked / LAN |
| outcome | `direct` / `relayed` / `failed(reason)` |
| relay | which relay, and whether a second relay took over |
| transfer | one exact Blossom mirror then a deliberate-loss repair through this path, hash and length checked by the store |
| memory | peak RSS while streaming a blob larger than RAM headroom |
| capture | a packet capture on the relay host showing only opaque datagrams |

Go and no-go conditions are the ones in the parent document and are not
restated here so they cannot drift.

## 8. Explicitly not decided here

- Nostr event kinds for card delivery and endorsement.
- Probe encryption.
- Multipath or simultaneous relay plus direct sending.
- Anything about tiers, claims, quotas or repair.  The lane moves bytes.

Open problems the spike surfaced, to settle before Phase 1:

- Relay convergence is by convention: both sides walk the same relay list in
  the same order.  Nothing enforces it, and per-peer relay selection from a
  card's hints is undecided.
- Candidates are exchanged once and never re-announced.  An interface change
  (Wi-Fi to mobile on a phone) is the first real-network case expected to
  break; the state machine needs a re-announce and re-probe rule.
- The reflector reply is unauthenticated and not matched to its nonce.
- Card serials come from the wall clock in the spike; a node must persist its
  highest issued serial or a clock step can reissue a stale one.
- `wss://` relay TLS in the spike pins a leaf fingerprint because it ships no
  root store; production relays use ordinary WebPKI certificates.

## 9. Rendezvous-tag routing

Whether node IDs are blinded from relays is decided: they are, always.
[`docs/RENDEZVOUS.md`](docs/RENDEZVOUS.md) is the normative rendezvous
section of this specification, accepted by both owners and frozen at that
acceptance. In summary, and normatively: a relay MUST route by the pair-scoped,
per-epoch rendezvous tag and MUST NOT receive a node ID, a Nostr key, or a
signature on the relay wire; a card MAY carry the ephemeral hint `0x04`
(secp256k1, 33 bytes) for forward-secret tags; the tag derivation, its case
byte, the epoch and erasure rules, and the six frozen known-answer vectors
(`vectors/rendezvous.json`) are as that document states. The identity-
authenticated relay protocol of §3.1 is superseded by tag registration when
the rendezvous wire change lands behind its version bump; until then §3.1
remains the deployed behaviour and `SECURITY.md` states the gap.
