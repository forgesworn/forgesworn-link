# Rendezvous-tag routing (draft)

**Status:** Draft for joint review. Nothing on the wire changes until both the
ForgeSworn and Bothy owners accept this document; it is then folded into
`SPEC.md` as a numbered section and the vectors freeze. The design it
implements, and the decision behind it, are in
[`relay-identity-privacy.md`](./relay-identity-privacy.md): the relay MUST
learn neither node identity nor any stable pseudonym — only that two endpoints
share a per-epoch tag it cannot link across relays or epochs.

Normative words MUST / MUST NOT / SHOULD / MAY are RFC 2119.

## 1. The ephemeral hint, kind `0x04`

A card MAY carry one hint of kind `0x04`: an ephemeral **secp256k1** compressed
public key, exactly 33 bytes, inside the signed bytes like every hint.

> **Change from the earlier agreement, flagged for review:** the approved
> proposal said X25519. It is secp256k1 here because the one-sided case below
> must compute an ECDH between the ephemeral and the peer's *static Nostr key*,
> and those are secp256k1; a cross-curve ECDH does not exist. One curve
> everywhere also removes a dependency. The forward-secrecy properties are
> unchanged.

Conditions, without which the forward-secrecy claim is not true:

1. The ephemeral MUST be freshly generated for every card and MUST NOT be
   reused across cards.
2. The ephemeral private key MUST be erased when the card expires or is
   rotated. That erasure **is** the forward secrecy.
3. A card MUST NOT carry more than one `0x04` hint; a verifier treats a second
   as a malformed hint (card rule 3).

## 2. Tag derivation

Definitions:

- `x(P)` — bytes 1..33 of the compressed secp256k1 shared point, i.e. the
  32-byte x-coordinate (the same convention NIP-44 uses).
- `static_x = x(ECDH(nostr_a, nostr_b))` — over the two owners' static Nostr
  keys, which both sides already hold from the claim / status / invite
  exchange. Pairing, the invite and the card do not change.
- `eph_x`, by what the two current cards carry:
  - **both** cards carry `0x04`: `eph_x = x(ECDH(eph_a, eph_b))` — full forward
    secrecy;
  - **one** card carries `0x04` (say A's): `eph_x = x(ECDH(eph_a, nostr_b))` —
    forward-secret **only** against compromise of A, the carrying side; a
    compromise of B's static key still reveals past tags. State this plainly
    wherever the one-sided mode is used;
  - **neither**: `eph_x` is 32 zero bytes — no forward secrecy.
- `epoch_index = floor(unix_seconds / 3600)` (`EPOCH_SECONDS = 3600`).
- `relay_host` — the lowercase hostname without port, exactly as in relay
  authentication today.

The tag is 16 bytes:

```
tag = HKDF-SHA256(
  ikm  = static_x || eph_x,                       // 64 bytes
  salt = "forgesworn-link/rendezvous/v1",         // 29 UTF-8 bytes
  info = relay_host || 0x00 || u64be(epoch_index),
  L    = 16,
)
```

Every input is symmetric, so both ends derive the same tag with no ordering
rule. Including `relay_host` makes tags unlinkable across relays; including
`epoch_index` rotates them hourly. A tag is an unguessable pair-scoped
capability: holding it proves membership of the pair for that relay and hour,
and nothing else.

For an anonymous peer with no prior Nostr key agreement, the fallback is
ephemeral-ECDH per session on both sides: the tag is then one-shot and
unstable, which is correct for a pair with no prior relationship.

## 3. Relay protocol (sketch, normative once accepted)

- Registration replaces identity authentication: after the WebSocket opens, an
  endpoint sends `Register { tags: [tag, ...] }`. There is no node ID and no
  signature on the relay wire at all; a tag is an unguessable capability, so
  knowledge is the authorisation. The relay MUST cap tags per session and
  sessions per source address, and the existing per-session byte budget and
  frame bounds stay.
- `Send { tag, datagram }` is delivered to every *other* session registered
  with that tag (in practice one). A tag nobody has registered is dropped
  silently, exactly as unknown destinations are today, so the relay never
  amplifies.
- An endpoint SHOULD register each pair's tag for the current **and previous**
  epoch, and SHOULD retain the peer's previous card's tag during rotation, so
  an epoch boundary or a card rotation does not drop the pair.
- The relay MUST NOT log tags, and drops every registration with the session.

What the relay now learns: source addresses, timing, byte counts, and that two
endpoints shared an opaque 16-byte value for an hour. What it can no longer
learn: any node ID, any Nostr key, any pseudonym stable across an hour, a
relay, or a card.

## 4. Residual exposure

Timing and volume correlation across sessions remains, as it does for any
relay; only cover traffic would close it, and that is out of scope. A relay
reached over Tor additionally sees no source address, which with tags makes the
strongest posture: tag, timing and byte counts, nothing else.

## 5. Known-answer vectors

[`vectors/rendezvous.json`](../vectors/rendezvous.json), generated by
[`vectors/generate-rendezvous.mjs`](../vectors/generate-rendezvous.mjs).
Deterministic test keys only. Fixed inputs: `relay_host =
"relay.example.org"`, `epoch_unix = 1793577600`, `epoch_index = 498216`.

| Case | Ephemeral mix | Tag |
| --- | --- | --- |
| both-ephemeral | `x(ECDH(eph_a, eph_b))` | `6d9a6a1a1aa9b10d93419db0aa47ce40` |
| one-ephemeral | `x(ECDH(eph_a, nostr_b))` | `27e43f3df17474d4a8212b37a3b16529` |
| no-ephemeral | 32 zero bytes | `5ecc2172a5e5445b6b2b1a2313422626` |
| next-epoch-differs | same pair, epoch + 1 | `66e802651439290d2541cde41cef25e2` |
| other-relay-differs | same pair, `relay2.example.net` | `0b7070849138419fed099d9dc943a975` |

The last two cases exist to prove rotation and per-relay unlinkability: same
pair, different tag. A conformant implementation reproduces all five.

## 6. Acceptance

Both owners accept this document (the Bothy owner's three conditions from the
design discussion are §1.1, §1.2 and the one-sided statement in §2). On
acceptance: the vectors freeze, the relay wire changes land behind a version
bump, and this text moves into `SPEC.md`.
