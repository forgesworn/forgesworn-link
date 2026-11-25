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
- Direct-path probes authenticate the live session, not the long-term key:
  both ends derive the probe key from the TLS session (RFC 8446 exporter),
  a probe carries a key id and a MAC and no node ID, and the key dies with
  the session. A captured probe opens under no other session; a replay into
  the same session earns at most one pong a second and a candidate that
  lapses in ten seconds.
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
- **Relay identity.** The default tag mode sends pair-scoped, per-epoch
  [rendezvous tags](docs/RENDEZVOUS.md) to the relay and keeps node IDs and Nostr
  keys off that wire. A relay can associate tags registered on the same
  connection and observe IPs, timing and traffic volume. The original
  identity mode is an explicit configuration and routes by persistent node ID.
- **Network destinations.** The default accepts only owner-configured relays.
  A signed card selects among permitted destinations. Native relay-only mode
  binds no UDP socket, including when a reflector is configured. Enable
  direct paths with consent to disclose network addresses to the peer.
- The lane moves an authorised byte stream. It never promotes a storage claim,
  and relay success is never proof of durable custody.

## Scope and status

The Phase 0 contract is exercised on loopback and on the open internet (see
`acceptance/`). There has been no third-party security audit and no adversarial
TLS test that drives a full handshake with a mismatched key. Do not rely on this
for a hostile-network deployment until that gate is met.
