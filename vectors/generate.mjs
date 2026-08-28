// FSL-CARD-1 vector generator.  Ed25519 + SHA-256 only.
// Point NOBLE_NODE_MODULES at a node_modules directory holding @noble/curves v2
// and @noble/hashes v2, e.g. NOBLE_NODE_MODULES=../some/node_modules/.
import { writeFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'
const NM = process.env.NOBLE_NODE_MODULES
if (!NM) { console.error('set NOBLE_NODE_MODULES'); process.exit(1) }
const base = pathToFileURL(NM.endsWith('/') ? NM : NM + '/').href
const { ed25519 } = await import(new URL('@noble/curves/ed25519.js', base).href)
const { sha256 } = await import(new URL('@noble/hashes/sha2.js', base).href)

const te = new TextEncoder()
const hex = (u8) => Buffer.from(u8).toString('hex')
const cat = (...parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let o = 0; for (const p of parts) { out.set(p, o); o += p.length } return out }
const u8 = (n) => Uint8Array.of(n)
const u16 = (n) => Uint8Array.of((n >> 8) & 0xff, n & 0xff)
const u64 = (n) => { const b = new Uint8Array(8); let v = BigInt(n); for (let i = 7; i >= 0; i--) { b[i] = Number(v & 0xffn); v >>= 8n } return b }
const B32 = 'abcdefghijklmnopqrstuvwxyz234567'
const base32 = (bytes) => { let bits = 0, val = 0, out = ''; for (const b of bytes) { val = (val << 8) | b; bits += 8; while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5 } } if (bits > 0) out += B32[(val << (5 - bits)) & 31]; return out }
const v6text = (b) => Array.from({ length: 8 }, (_, i) => ((b[2 * i] << 8) | b[2 * i + 1]).toString(16)).join(':')

const CARD_DOMAIN = cat(te.encode('forgesworn-link/card/v1'), u8(0))
const ADDR_DOMAIN = cat(te.encode('forgesworn-link/addr/v1'), u8(0))
const RELAY_DOMAIN = cat(te.encode('forgesworn-link/relay-auth/v1'), u8(0))
const PROBE_DOMAIN = cat(te.encode('forgesworn-link/probe/v1'), u8(0))
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

const seedA = sha256(te.encode('forgesworn-link/vectors/1/node-a'))
const seedB = sha256(te.encode('forgesworn-link/vectors/1/node-b'))
const pubA = ed25519.getPublicKey(seedA)
const pubB = ed25519.getPublicKey(seedB)
const NOW = 1787200500
const ISSUED = 1787200000

const hint = (kind, value) => cat(u8(kind), u16(value.length), value)
const relayHint = (url) => hint(0x01, te.encode(url))
const udpHint = (v6, port) => hint(0x02, cat(v6, u16(port)))
const onionHint = (host, port) => hint(0x03, cat(te.encode(host), u16(port)))
const v4mapped = (a, b, c, d) => Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d)

function body({ magic = 'FSL1', version = 1, node = pubA, issued = ISSUED, expires = ISSUED + 86400, serial = 1, hintCount, hints = [] }) {
  const hintBytes = cat(...hints)
  return cat(te.encode(magic), u8(version), node, u64(issued), u64(expires), u64(serial), u8(hintCount ?? hints.length), hintBytes)
}
function sign(bodyBytes, seed = seedA) { return ed25519.sign(cat(CARD_DOMAIN, bodyBytes), seed) }
function card(opts, seed = seedA) { const b = body(opts); return cat(b, sign(b, seed)) }

const RELAY = 'wss://relay.example/link'
const UDP = udpHint(v4mapped(198, 51, 100, 7), 4433)
const ONION = onionHint('b'.repeat(56), 80)

const valid = [
  { name: 'zero-hints', serial: 1, hints: [] },
  { name: 'one-relay-hint', serial: 2, hints: [relayHint(RELAY)] },
  { name: 'relay-udp-onion', serial: 3, hints: [relayHint(RELAY), UDP, ONION] },
  { name: 'unknown-hint-kind-skipped', serial: 4, hints: [relayHint(RELAY), hint(0x7e, te.encode('future')), UDP] },
].map(({ name, serial, hints }) => {
  const b = body({ serial, hints }); const sig = sign(b)
  return { name, rule: null, expect: 'accept', now: NOW, highest_seen_serial: serial - 1, expected_node_id: hex(pubA), card_hex: hex(cat(b, sig)), signing_input_hex: hex(cat(CARD_DOMAIN, b)), signature_hex: hex(sig), hints: hints.length }
})

const flipSig = (c) => { const x = new Uint8Array(c); x[x.length - 1] ^= 0x01; return x }
const hostile = []
const H = (name, rule, cardBytes, extra = {}) => hostile.push({ name, rule, expect: 'reject', now: NOW, highest_seen_serial: 0, expected_node_id: null, card_hex: hex(cardBytes), ...extra })

H('r1-truncated-125-bytes', 1, card({ serial: 10 }).subarray(0, 125))
H('r1-oversize-16-max-relay-hints', 1, card({ serial: 10, hints: Array.from({ length: 16 }, (_, i) => { const url = 'wss://' + String(i).padStart(3, '0') + '.' + 'r'.repeat(255 - 13) + '.ex'; if (url.length !== 255) throw new Error('relay hint must be exactly 255 bytes'); return relayHint(url) }) }))
H('r3-relay-hint-too-long', 3, card({ serial: 10, hints: [relayHint('wss://' + 'r'.repeat(250))] }))
H('r3-relay-hint-empty', 3, card({ serial: 10, hints: [hint(0x01, new Uint8Array(0))] }))
H('r2-bad-magic', 2, card({ serial: 10, magic: 'FSL0' }))
H('r2-bad-version', 2, card({ serial: 10, version: 2 }))
H('r3-seventeen-hints', 3, card({ serial: 10, hints: Array.from({ length: 17 }, () => relayHint('wss://r.example')) }))
H('r3-udp-hint-wrong-length', 3, card({ serial: 10, hints: [hint(0x02, cat(v4mapped(198, 51, 100, 7), u16(4433), u8(0)))] }))
H('r3-hint-overruns-card', 3, card({ serial: 10, hintCount: 1, hints: [cat(u8(0x01), u16(500), te.encode('wss://short'))] }))
H('r3-garbage-between-hints-and-signature', 3, card({ serial: 10, hintCount: 0, hints: [u8(0x00)] }))
H('r4-signature-bit-flipped', 4, flipSig(card({ serial: 10 })))
H('r4-signed-by-other-key', 4, card({ serial: 10 }, seedB))
H('r5-issued-in-the-future', 5, card({ serial: 10, issued: NOW + 301, expires: NOW + 301 + 3600 }))
H('r6-expired', 6, card({ serial: 10, issued: NOW - 3600, expires: NOW }))
H('r7-lifetime-too-long', 7, card({ serial: 10, issued: NOW - 100, expires: NOW - 100 + 604801 }))
H('r7-expires-before-issued', 7, card({ serial: 10, issued: NOW + 200, expires: NOW + 199 }))
H('r8-serial-replayed', 8, card({ serial: 5 }), { highest_seen_serial: 5 })
H('r8-serial-stale', 8, card({ serial: 4 }), { highest_seen_serial: 5 })
H('r9-unexpected-node-id', 9, card({ serial: 10 }), { expected_node_id: hex(pubB) })

// Check every hostile card signature verifies except the rule-4 ones, so the reported rule is the one under test.
for (const h of hostile) {
  const c = Buffer.from(h.card_hex, 'hex')
  if (c.length < 126) continue
  const ok = ed25519.verify(c.subarray(c.length - 64), cat(CARD_DOMAIN, c.subarray(0, c.length - 64)), c.subarray(5, 37))
  if (ok !== (h.rule !== 4)) throw new Error('signature expectation wrong for ' + h.name)
}

const spkiA = cat(SPKI_PREFIX, pubA)
const addrA = cat(Uint8Array.of(0xfd, 0x00), sha256(cat(ADDR_DOMAIN, pubA)).subarray(0, 14))

const challenge = sha256(te.encode('forgesworn-link/vectors/1/challenge'))
const relayHost = 'relay.example'
const relayInput = cat(RELAY_DOMAIN, u16(relayHost.length), te.encode(relayHost), challenge)
const relaySig = ed25519.sign(relayInput, seedA)

const nonce = sha256(te.encode('forgesworn-link/vectors/1/probe-nonce')).subarray(0, 16)
const ping = cat(te.encode('FSLP'), u8(0x01), pubA, pubB, nonce)
const pingSig = ed25519.sign(cat(PROBE_DOMAIN, ping), seedA)
const pong = cat(te.encode('FSLP'), u8(0x02), pubB, pubA, nonce)
const pongSig = ed25519.sign(cat(PROBE_DOMAIN, pong), seedB)

const meta = { version: 'FSL-CARD-1', generated_for: 'forgesworn-link phase 0 spike', domains: { card: hex(CARD_DOMAIN), addr: hex(ADDR_DOMAIN), relay_auth: hex(RELAY_DOMAIN), probe: hex(PROBE_DOMAIN) }, keys: { node_a: { seed_hex: hex(seedA), node_id_hex: hex(pubA), node_id_base32: base32(pubA) }, node_b: { seed_hex: hex(seedB), node_id_hex: hex(pubB), node_id_base32: base32(pubB) } }, clock_skew_seconds: 300, max_lifetime_seconds: 604800, max_card_bytes: 4096, min_card_bytes: 126 }
const out = (name, data) => writeFileSync(new URL('./' + name, import.meta.url), JSON.stringify(data, null, 2) + '\n')
out('meta.json', meta)
out('card-valid.json', valid)
out('card-hostile.json', hostile)
out('spki.json', { node_id_hex: hex(pubA), spki_der_hex: hex(spkiA), key_offset: SPKI_PREFIX.length, key_length: 32, synthetic_ipv6: v6text(addrA), synthetic_port: 7 })
out('relay-auth.json', { relay_host: relayHost, challenge_hex: hex(challenge), node_id_hex: hex(pubA), signing_input_hex: hex(relayInput), signature_hex: hex(relaySig) })
out('probe.json', { ping: { bytes_hex: hex(ping), signing_input_hex: hex(cat(PROBE_DOMAIN, ping)), signature_hex: hex(pingSig), wire_hex: hex(cat(ping, pingSig)) }, pong: { bytes_hex: hex(pong), signing_input_hex: hex(cat(PROBE_DOMAIN, pong)), signature_hex: hex(pongSig), wire_hex: hex(cat(pong, pongSig)) } })
console.log('node A', base32(pubA), '| valid', valid.length, '| hostile', hostile.length)
console.log('card sizes', valid.map(v => v.card_hex.length / 2).join(','), '| oversize fixture', hostile[1].card_hex.length / 2)
