// Rendezvous-tag vector generator (draft, docs/RENDEZVOUS.md).
// secp256k1 ECDH + HKDF-SHA256 only. Same invocation pattern as generate.mjs:
// NOBLE_NODE_MODULES must point at a node_modules with @noble/curves v2 and
// @noble/hashes v2.
import { writeFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'
const NM = process.env.NOBLE_NODE_MODULES
if (!NM) { console.error('set NOBLE_NODE_MODULES'); process.exit(1) }
const base = pathToFileURL(NM.endsWith('/') ? NM : NM + '/').href
const { secp256k1 } = await import(new URL('@noble/curves/secp256k1.js', base).href)
const { sha256 } = await import(new URL('@noble/hashes/sha2.js', base).href)
const { hkdf } = await import(new URL('@noble/hashes/hkdf.js', base).href)

const te = new TextEncoder()
const hex = (u8) => Buffer.from(u8).toString('hex')
const cat = (...parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let o = 0; for (const p of parts) { out.set(p, o); o += p.length } return out }
const u64 = (n) => { const b = new Uint8Array(8); let v = BigInt(n); for (let i = 7; i >= 0; i--) { b[i] = Number(v & 0xffn); v >>= 8n } return b }

// Constants under review in docs/RENDEZVOUS.md. Frozen only when both owners
// accept the draft.
const RVZ_SALT = te.encode('forgesworn-link/rendezvous/v1')
const EPOCH_SECONDS = 3600
const TAG_BYTES = 16

// x-coordinate of the secp256k1 shared point: byte 1..33 of the compressed
// getSharedSecret output. The same convention NIP-44 uses for its shared point.
const ecdhX = (priv, pub) => secp256k1.getSharedSecret(priv, pub, true).slice(1, 33)

// tag = HKDF-SHA256(ikm = static_x || eph_x, salt = RVZ_SALT,
//                   info = relay_host || 0x00 || u64be(epoch_index), L = 16)
// eph_x is 32 zero bytes when neither card carries an ephemeral.
function tag (staticX, ephX, relayHost, epochIndex) {
  const info = cat(te.encode(relayHost), Uint8Array.of(0), u64(epochIndex))
  return hkdf(sha256, cat(staticX, ephX), RVZ_SALT, info, TAG_BYTES)
}

// Deterministic test keys, public material only. secp256k1 private scalars from
// sha256 of fixed strings (all comfortably below the group order).
const priv = (label) => sha256(te.encode(`forgesworn-link/rendezvous-vectors/1/${label}`))
const nostrA = priv('nostr-a')
const nostrB = priv('nostr-b')
const ephA = priv('eph-a')
const ephB = priv('eph-b')
const pub = (p) => secp256k1.getPublicKey(p, true)

const RELAY_HOST = 'relay.example.org'
const EPOCH_UNIX = 1793577600 // 2026-11-02T00:00:00Z, a fixed instant
const EPOCH_INDEX = Math.floor(EPOCH_UNIX / EPOCH_SECONDS)

const staticX = ecdhX(nostrA, pub(nostrB))
// Symmetry check: both directions must agree, or the construction is broken.
if (hex(staticX) !== hex(ecdhX(nostrB, pub(nostrA)))) throw new Error('static ECDH asymmetric')

const ephBothX = ecdhX(ephA, pub(ephB))
if (hex(ephBothX) !== hex(ecdhX(ephB, pub(ephA)))) throw new Error('eph ECDH asymmetric')

// One-sided: A carries an ephemeral, B does not. Both ends compute
// ECDH(ephA, nostrB) -- A holds ephA_priv, B holds nostrB_priv.
const ephOneX = ecdhX(ephA, pub(nostrB))
if (hex(ephOneX) !== hex(ecdhX(nostrB, pub(ephA)))) throw new Error('one-sided ECDH asymmetric')

const zeros = new Uint8Array(32)

const cases = [
  {
    name: 'both-ephemeral',
    note: 'both cards carry hint 0x04; full forward secrecy',
    ephemeralMix: 'ECDH(ephA, ephB).x',
    tagHex: hex(tag(staticX, ephBothX, RELAY_HOST, EPOCH_INDEX)),
  },
  {
    name: 'one-ephemeral',
    note: 'only node A carries hint 0x04; forward-secret only against compromise of A',
    ephemeralMix: 'ECDH(ephA, nostrB).x',
    tagHex: hex(tag(staticX, ephOneX, RELAY_HOST, EPOCH_INDEX)),
  },
  {
    name: 'no-ephemeral',
    note: 'neither card carries hint 0x04; no forward secrecy, eph_x is 32 zero bytes',
    ephemeralMix: '32 zero bytes',
    tagHex: hex(tag(staticX, zeros, RELAY_HOST, EPOCH_INDEX)),
  },
  {
    name: 'next-epoch-differs',
    note: 'same pair, next epoch index; proves per-epoch rotation',
    ephemeralMix: 'ECDH(ephA, ephB).x',
    tagHex: hex(tag(staticX, ephBothX, RELAY_HOST, EPOCH_INDEX + 1)),
  },
  {
    name: 'other-relay-differs',
    note: 'same pair and epoch, different relay host; proves per-relay unlinkability',
    ephemeralMix: 'ECDH(ephA, ephB).x',
    tagHex: hex(tag(staticX, ephBothX, 'relay2.example.net', EPOCH_INDEX)),
  },
]

const out = {
  format: 'forgesworn-link-rendezvous-known-answer-v1',
  status: 'draft, pending both owners accepting docs/RENDEZVOUS.md',
  saltUtf8: 'forgesworn-link/rendezvous/v1',
  epochSeconds: EPOCH_SECONDS,
  tagBytes: TAG_BYTES,
  relayHost: RELAY_HOST,
  epochUnix: EPOCH_UNIX,
  epochIndex: EPOCH_INDEX,
  testOnlyKeys: {
    nostrAPrivHex: hex(nostrA),
    nostrAPubCompressedHex: hex(pub(nostrA)),
    nostrBPrivHex: hex(nostrB),
    nostrBPubCompressedHex: hex(pub(nostrB)),
    ephAPrivHex: hex(ephA),
    ephAPubCompressedHex: hex(pub(ephA)),
    ephBPrivHex: hex(ephB),
    ephBPubCompressedHex: hex(pub(ephB)),
  },
  intermediates: {
    staticXHex: hex(staticX),
    ephBothXHex: hex(ephBothX),
    ephOneXHex: hex(ephOneX),
  },
  cases,
}

writeFileSync(new URL('./rendezvous.json', import.meta.url), JSON.stringify(out, null, 2) + '\n')
console.log('wrote rendezvous.json')
for (const c of cases) console.log(`  ${c.name}: ${c.tagHex}`)
