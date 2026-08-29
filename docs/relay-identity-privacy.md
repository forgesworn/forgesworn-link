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

## The decision

For the paired-peer case Link serves, only **C** actually meets the T5 promise:
**A** does not close the bootstrap leak, and **B** leaves a per-epoch per-relay
pseudonym the relay can still graph within an epoch.

**Decided by the ForgeSworn owner, 2026-08-29: maximum anonymity — approach C.**
The interim **B** is not shipped as a stepping stone. We implement the full
rendezvous-tag design so a relay learns neither node identity nor any stable
pseudonym, only that two endpoints share a per-epoch tag it cannot link across
relays or epochs. The directive also sets the default posture wherever the
choice recurs: prefer the anonymity-maximising option.

What follows from "as anonymous as possible":

- **Relay routing is by rendezvous tag, never by node ID.** The `Send` frame's
  destination and the relay registry key become the tag; a node ID never reaches
  a relay. Specified next as a normative addition to `SPEC.md`.
- **The rendezvous secret is derived, not newly exchanged.** It is the ECDH
  shared secret over the two owners' Nostr keys, which both sides already hold
  from the claim, status and invite exchange (the same key agreement NIP-44
  uses). Each epoch tag is `HKDF(ECDH(nostr_a, nostr_b), relay_epoch)`. Pairing,
  the invite and the address card do not change; only the relay routing and the
  endpoint's tag derivation do. The one trade is that the rendezvous layer is
  derived from the Nostr identity rather than the transport key, re-coupling them
  internally; the relay still sees only the opaque tag, so no identity reaches
  it, and this is an accepted trade for leaving pairing untouched. (Agreed
  direction with the Bothy owner, 2026-08-29.)
- **Forward secrecy for the tags.** ECDH over long-term Nostr keys alone gives
  the tags no forward secrecy: a later compromise of either long-term key reveals
  every past and future tag for that pair, so an adversary who also logged the
  relay's tag traffic could retroactively link past sessions to the pair. Because
  the directive is maximum anonymity and the card is not yet shipped, we take the
  stronger option rather than accept the residual: the card carries a per-card
  ephemeral X25519 public key, and the tag mixes `ECDH(ephemeral_a, ephemeral_b)`
  into the HKDF, so the tags of an expired card cannot be re-derived from a
  long-term key compromise. This is a small addition to the shared card format,
  pinned byte-exactly in the SPEC.md rendezvous section and agreed with the Bothy
  owner. Tags route rather than protect content, so this is defence in depth, not
  a load-bearing secret.
- **Direct paths and UDP candidates stay opt-in and off by default.** A direct
  path reveals peer IPs to each other, so the anonymous default is relay-only or
  Tor; a card carries UDP candidates only on explicit consent (already the rule
  in §2.2).
- **Tor is the strongest posture.** A relay reached over Tor sees no source IP,
  and with rendezvous tags it also sees no identity, so a Tor-fronted relay
  learns only tag, timing and byte counts. Timing and volume correlation remain
  a residual that only cover traffic would close; that is out of scope for now
  and stated as a residual.

`SECURITY.md` states the current gap honestly until rendezvous-tag routing
lands; this document is the design it points to.
