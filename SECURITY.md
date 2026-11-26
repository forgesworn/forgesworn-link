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
- **Relay admission.** In identity mode the relay verifies the connecting
  node's signature. Ordinary tag mode admits nonempty registrations within
  global and per-source limits. The optional private listener requires a
  challenge-bound proof of an operator-issued key before registration.
  Removing the key closes its active relay connections and refuses it on
  reconnect. The relay can correlate connections using the same grant.
  [Private relay setup and wire format](docs/relay-admission.md)
- **Pairing.** Rendezvous tags grant reachability and are visible to the
  relay. Pinned TLS authenticates the transport peer. A provisional pairing
  session authenticates the listener's pinned key and verifies the dialler's
  connection key. The application must validate its pairing secret inside
  that session before granting authority. [Pairing contract](docs/PAIRING-RENDEZVOUS-DRAFT.md)
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
- **Direct candidates.** By default, native candidate gathering skips local
  addresses on interfaces detected by point-to-point flags and common tunnel
  names. With interface enumeration unavailable, automatic advertisements
  are limited to same-host loopback. `allow_overlay_candidates` opts in to
  disclosing those overlay addresses. Callers control extra hints they supply
  to signed cards. With direct UDP enabled, a peer may see the actual packet
  source, and a configured reflector may report a VPN's public egress address.
- **Required proxy.** Native Rust callers can require that every relay
  connection use a configured SOCKS5 or Tor proxy. Relay DNS resolution
  happens at the proxy. Destination checks and relay TLS verification still
  apply during reconnect and failover. [Native proxy routing](docs/native-proxy-routing.md)
- **Relay logs.** The relay binary reports listener addresses at startup and
  five-minute aggregate activity across the relay instance. Precise session
  times, source addresses, routing tokens, tags and frames stay out of those
  logs. Low-traffic intervals can still reveal the presence of activity.
  Hosts embedding the library control dependency logging and can enable
  `link_relay::summary` alone.
- The lane moves an authorised byte stream. It never promotes a storage claim,
  and relay success is never proof of durable custody.

## Scope and status

The Phase 0 contract is exercised on loopback and on the open internet.
Full TLS 1.3 tests verify wrong-key rejection on both sides and require a
valid signature from the provisional dialler. Third-party security review
remains an acceptance gate for hostile-network deployment.
[Network acceptance](acceptance/) · [TLS tests](crates/link-core/tests/tls_handshake.rs)
