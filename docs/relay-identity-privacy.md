# Design: closing the relay identity leak

**Status:** Design, not implemented. This raises a decision for the owners and
does not change any wire format.

## The problem

`SECURITY.md` and the joint contract (T5) promise the relay learns only routing
tokens, source addresses, timing and byte counts, and specifically **not** "the
long-term identity behind a transport token." The implementation does not meet
that promise.

The relay routes by the persistent node ID:

- `serve_session` authenticates the client by its `NodeId` (a signature over the
  challenge) and registers the session as `sessions.insert(node_id, tx)`
  (`crates/link-relay/src/lib.rs`).
- A `Send` frame carries `destination: NodeId`, and the relay routes it with
  `sessions.get(&destination)`.
- The 16-byte `Welcome` token exists, is sent to the client and logged, but is
  **never used for routing.**

So at runtime the relay holds, for every pair it carries, both endpoints'
persistent transport identities and the fact that `NodeId A` is talking to
`NodeId B`. It never logs the node ID and drops it when the session ends, but
while the session is live it *is* the who-talks-to-whom graph. A curious or
compromised relay, or one compelled to log, learns the social graph of transport
identities — exactly what T5 says it must not.

The payload is still opaque (QUIC under the endpoints' TLS 1.3 keys), and TLS
identity is safe (pinned to the raw key). This is a **metadata** leak, not a
content or impersonation one. But for a privacy-first transport it is the leak
that matters most, because the metadata graph is often more sensitive than the
bytes.

## What a fix must achieve

The relay must be able to deliver a datagram from A to B without learning that
the endpoints are `NodeId A` and `NodeId B`, while still:

- authenticating that a connecting endpoint is entitled to a routing slot (so
  the relay is not an open reflector for spoofed traffic);
- letting A address B without a prior round-trip through the relay for every
  datagram;
- surviving B reconnecting with a new relay session;
- keeping the relay stateless-ish and cheap.

## Candidate approaches

### A. Route by the ephemeral token, resolved out of band

Keep the `Welcome` token, make it the routing key, and have the two endpoints
learn each other's *current* token over their already-encrypted control stream
(or the card) rather than putting node IDs on relay frames.

- The relay registers `token -> tx` and routes `Send { destination_token }`.
- A and B exchange current tokens inside the QUIC control stream, which the
  relay cannot read.
- **Gap:** bootstrapping. Before the QUIC session exists there is no control
  stream to exchange tokens over, and the whole point of the relay is to carry
  the *first* packets. So the first contact still needs the relay to map "reach
  the node behind this card" to a session, which reintroduces an identifier the
  relay can correlate. Workable only if pairing pre-establishes a rendezvous
  identifier (see C).

### B. Blinded per-session node identifier

The client authenticates with its real `NodeId` but registers under a blinded
identifier `H(node_id || relay_epoch_nonce)` that rotates per relay per epoch.
The sender addresses B by the same blinded identifier, which it can compute from
B's card plus the relay's published epoch nonce.

- The relay never stores the raw node ID, only the blinded one, and the blinded
  value differs per relay and per epoch, so cross-relay and cross-time
  correlation is broken.
- **Gap:** within one relay in one epoch the blinded identifier is still a
  stable pseudonym, so the relay still sees "pseudonym X talks to pseudonym Y"
  for the epoch's duration. It raises the cost of graph-building (no cross-relay
  linkage, bounded time windows) without eliminating it. Cheap to implement.

### C. Pairing-time rendezvous tag (recommended direction)

At pairing, the two owners already exchange cards over a private channel. Have
them also derive a **shared rendezvous secret** for the pair. Each session then
registers under a short-lived tag `HKDF(rendezvous_secret, relay_epoch)` that
**both** endpoints can compute but no one else can, and that reveals neither
node ID.

- The relay matches two endpoints presenting the same tag and bridges them; it
  learns "two endpoints share tag T this epoch," not who they are, and the tag
  is unlinkable across relays and epochs.
- Authentication becomes "prove knowledge of a tag" rather than "prove a node
  ID," so the relay still resists open-reflector abuse via a per-tag rate limit.
- **Cost:** it changes pairing (a rendezvous secret per peer) and the relay
  registration model (tag-keyed, two-sided match rather than one-sided address).
  It is the most invasive but the only one that actually meets T5 for a paired
  pair. It fits the existing model where Link is used between paired peers, not
  as an open address book.

## Recommendation and the decision

For the paired-peer case Link actually serves, **C** is the design that meets the
T5 promise; **B** is a cheap partial mitigation that could ship first (bounded,
per-epoch, per-relay pseudonyms) while C is specified. **A** alone does not
close the bootstrap leak.

This is an owner/architecture decision because it changes pairing and the relay
protocol, and because it trades implementation cost against how completely the
metadata promise is kept:

- Ship **B** now as a bounded mitigation and correct `SECURITY.md`/T5 to state
  the residual (per-epoch per-relay pseudonym), then specify **C**; or
- hold for **C** directly and, until then, state honestly in `SECURITY.md` that
  the relay currently learns the transport-identity graph of the pairs it
  carries.

Either way, `SECURITY.md` and T5 must be corrected now to match the code:
the relay **does** currently learn the identity pairing, and the claim otherwise
is aspirational until one of these lands.
