# Paired rendezvous route, case `0x04`

**Status: RATIFIED FOR IMPLEMENTATION — accepted by the Bothy owner (decented)
and the ForgeSworn owner (TheCryptoDonkey) on 2026-09-10.** This is the
bounded extension required for the KithMoot Android private-conversation
journey. It does not change cases `0x00` through `0x03`.

## 1. Derivation and persistence

After a provisional pairing connection has completed the product's pinned,
secret-authenticated request, either endpoint MAY export 32 bytes with TLS
exporter label `EXPORTER-FSL-paired-route-v1`. The product stores the bytes
only after that request succeeds, bound to the two Link node IDs, and erases the
one-time pairing secret. Link receives only the raw 32 bytes.

```text
paired_tag = HKDF-SHA256(
  ikm  = 0x04 || paired_route_secret,
  salt = "forgesworn-link/rendezvous/v1",
  info = relay_host || 0x00 || u64be(epoch_index),
  L    = 16,
)
```

The previous, current and next epochs are registered. The route secret is
zeroised when Link removes it. A product restart may restore it through the
endpoint configuration; Link does not write product state itself.

## 2. Trust boundary

The paired route is reachability only. It does not admit a provisional
connection, identify a Nostr account, grant a Bothy capability, or replace
NIP-42 and a circle-event grant. TLS still pins each Link node ID. A card node
ID change requires explicit pairing again.

## 3. Acceptance evidence

`vectors/paired-rendezvous.json` is the deterministic independent vector.
Required implementation evidence is a loopback pairing that completes one
product stream, exports equal secrets at both ends, installs them as durable
routes and completes a subsequent ordinary pinned session after the provisional
admission is removed.
