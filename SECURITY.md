# Security policy

ForgeSworn Link is transport code that sits on internet-facing sockets. Treat
node identity, the relay boundary and the TLS identity rule as security
boundaries.

## Reporting

Report a suspected vulnerability privately through this repository's GitHub
"Report a vulnerability" advisory flow. Please do not open a public issue for a
security problem. Include the version or commit, the affected crate, and the
smallest reproduction you have. Describe the class of problem rather than a
working exploit or a step-by-step extraction path.

## Boundaries

- A node's transport key is its identity. It is generated on first run, stored
  with restrictive permissions, and is never the owner's Nostr key.
- The single TLS rule is that the peer's presented public key must byte-equal
  the expected node ID and its TLS 1.3 signature must validate. An endpoint that
  presents any other key fails closed.
- **Authentication is not authorisation.** In identity mode any node with a
  relay session can start a handshake with any node ID it knows, and the
  transport pins the handshake to that ID; whether that node may talk to this
  one is the application's decision, made on `Session::peer()` against its own
  pairing set, exactly as with any other key-addressed transport. In tag mode
  the relay path is authorised by construction: only a paired peer can derive
  the rendezvous tag, so nobody else can reach the endpoint through the relay
  at all.
- A relay may learn routing tokens, source addresses, timing and byte counts. It
  must not learn Nostr keys, application authorisation, blob plaintext, retention
  tier, or content hashes the application did not deliberately expose. Relay
  frames are bounded, authenticated and opaque; the payload is QUIC, encrypted
  end to end between the two endpoints.
- **Identity at the relay is mode-dependent.** In tag mode (spec section 9,
  [`docs/RENDEZVOUS.md`](docs/RENDEZVOUS.md), implemented end to end) a relay
  session carries no node ID, Nostr key or signature at all: the relay matches
  pair-scoped, per-epoch rendezvous tags it cannot link across relays or hours,
  and never logs them. In identity mode -- the original spec 3.1 behaviour,
  still the default -- the relay routes by the persistent node ID, so while a
  session is live that relay sees which node IDs talk to each other. This is
  metadata only (the payload stays opaque, TLS identity is unaffected), and the
  design history is in
  [`docs/relay-identity-privacy.md`](docs/relay-identity-privacy.md). The mode
  is a per-deployment choice (`EndpointConfig.rendezvous`); a deployment that
  wants the relay blind runs tag mode.
- The lane moves an authorised byte stream. It never promotes a storage claim,
  and relay success is never proof of durable custody.

## Scope and status

The Phase 0 contract is exercised on loopback and on the open internet (see
`acceptance/`). There has been no third-party security audit and no adversarial
TLS test that drives a full handshake with a mismatched key. Do not rely on this
for a hostile-network deployment until that gate is met.
