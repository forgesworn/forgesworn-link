# Pairing rendezvous, case `0x03`

**Status: RATIFIED FOR IMPLEMENTATION — accepted by both named owners on
2026-08-31; acceptance evidence in §5 remains pending.** This extends the
frozen [`RENDEZVOUS.md`](./RENDEZVOUS.md) contract. The exact normative text
accepted by the owners is commit `e69c3cd`; this follow-up changes only its
status and ratification record. It does not claim the hostile-client,
transition or phone-to-box evidence required before final freeze.

Normative words MUST / MUST NOT / SHOULD / MAY are RFC 2119.

## 1. Derivation and encoding

The product presents a pairing secret as exactly 32 lowercase hexadecimal
characters. Link receives the decoded 16 raw bytes; the ASCII hex spelling is
never HKDF input.

```text
pair_tag = HKDF-SHA256(
  ikm  = 0x03 || pairing_secret,                 // 17 bytes
  salt = "forgesworn-link/rendezvous/v1",
  info = relay_host || 0x00 || u64be(epoch_index),
  L    = 16,
)
```

The epoch and relay-host rules are unchanged. Both sides register the previous,
current and next epoch. Independent Node `crypto.hkdfSync` known-answer vector:

```text
pairing_secret = 000102030405060708090a0b0c0d0e0f
relay_host     = relay.example.org
epoch_index    = 498216
pair_tag       = 66dac0233c5404c521a2b2200f1b8211
```

## 2. Trust boundary

The tag is reachability only. The relay sees every registered tag, so a tag
cannot prove possession of the pairing secret against that relay and MUST NOT
grant product authority.

The dialler pins the box's ordinary Link node ID from its verified card. The
box accepts a well-formed Ed25519 raw public key and verifies TLS
CertificateVerify under that same key, but treats it only as a connection-local
key. It is not a keeper identity and is not checked through the normal
card/claim chain.

For Bothy, the sole first-claim authenticator is the raw 16-byte secret inside
the box-pinned TLS request. `X-Bothy-Pairing-Secret` MUST be decoded and
constant-time compared before the claim body is read, stored or applied. The
provisional TLS key grants nothing by itself.

## 3. Bounded Link surface

- Pairing uses ALPN `fsl-pair/0`; ordinary pinned sessions remain `fsl/0`.
- `Endpoint::accept()` remains pinned-only. A pairing-capable product runs one
  `Endpoint::accept_any()` loop and must explicitly match
  `AcceptedSession::Pairing`.
- `PairingSession` is relay-only, exposes exactly one application stream, has
  no direct-path API and is forcibly closed after 60 seconds.
- A pairing registration is valid for 1 to 600 seconds. Link holds its secret
  in zeroising memory. Dropping the `PairingRegistration`, or reaching expiry,
  removes the route and clears Link's send cache.
- A repeated `Register` with zero tags is an explicit empty replacement set.
  The relay MUST accept it only after a non-empty initial registration and
  MUST remove the session's previous tags immediately. An empty first
  registration remains malformed.

The product MUST retain the registration handle until the claim response has
finished over the provisional connection. It then closes the connection and
drops the handle. Removing the tag before the response completes can cut the
only return route; retaining it afterwards needlessly extends first-contact
reachability.

## 4. Transition to ordinary tags

The pairing route and ordinary ECDH routes are separate entries and may
coexist. Accepting a claim does not mutate the active provisional QUIC route.
The product performs this order:

1. authenticate and validate the claim using the raw secret;
2. install the ordinary card/claim-derived rendezvous material;
3. send and finish the claim response on the provisional stream;
4. close the provisional connection;
5. drop the pairing registration and zeroise the product's secret.

Later connections use the ordinary pinned `fsl/0` path. No authority or route
state is promoted from the provisional connection.

## 5. Acceptance evidence

The implementation is not accepted merely because unit tests pass. Before the
contract can be frozen, it needs:

- the independent `0x03` KAT above in Link and Bothy;
- a real relay test where two empty ordinary books meet from the shared secret,
  complete one stream, and expose no second stream or direct path;
- relay tests proving empty replacement unregisters the last tag while empty
  initial registration is refused;
- a hostile provisional TLS client that knows the tag but not the raw secret,
  proving Bothy refuses it before reading the claim body;
- a transition test proving the response completes before the pairing tag is
  removed and the next connection uses ordinary pinned tags;
- the phone-to-box run that originally exposed the deadlock, repeated without
  either book being hand-seeded.

## 6. Ratification

- Bothy owner (decented): **ratified the exact `e69c3cd` text**.
- ForgeSworn owner (TheCryptoDonkey): **ratified the exact `e69c3cd` text**.

Ratification was recorded on 2026-08-31 when decented confirmed it directly to
Quill after the owner-to-owner discussion with TheCryptoDonkey. Tally/Quill
technical agreement and green verification remain evidence, not substitutes
for that owner acceptance.
