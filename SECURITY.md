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
- A relay may learn routing tokens, source addresses, timing and byte counts. It
  must not learn Nostr keys, application authorisation, blob plaintext, retention
  tier, or content hashes the application did not deliberately expose. Relay
  frames are bounded, authenticated and opaque; the payload is QUIC, encrypted
  end to end between the two endpoints.
- **Known gap (metadata).** The intended boundary also forbids the relay from
  learning the long-term identity behind a transport token, but the current
  relay routes by the persistent node ID, so while a session is live it does
  learn that one node ID is talking to another. This is a metadata leak, not a
  content or impersonation one: the payload stays opaque and TLS identity is
  unaffected. Closing it is designed in
  [`docs/relay-identity-privacy.md`](docs/relay-identity-privacy.md) and is an
  open owner decision. Until it lands, treat the transport-identity graph of the
  pairs a relay carries as visible to that relay.
- The lane moves an authorised byte stream. It never promotes a storage claim,
  and relay success is never proof of durable custody.

## Scope and status

The Phase 0 contract is exercised on loopback and on the open internet (see
`acceptance/`). There has been no third-party security audit and no adversarial
TLS test that drives a full handshake with a mismatched key. Do not rely on this
for a hostile-network deployment until that gate is met.
