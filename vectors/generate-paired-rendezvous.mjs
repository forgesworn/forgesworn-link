// Durable paired-route known-answer vector. The secret is deterministic test
// material only; production derives it from a pinned provisional TLS exporter.
import { writeFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'

const NM = process.env.NOBLE_NODE_MODULES
if (!NM) { console.error('set NOBLE_NODE_MODULES'); process.exit(1) }
const base = pathToFileURL(NM.endsWith('/') ? NM : NM + '/').href
const { sha256 } = await import(new URL('@noble/hashes/sha2.js', base).href)
const { hkdf } = await import(new URL('@noble/hashes/hkdf.js', base).href)

const te = new TextEncoder()
const hex = (u8) => Buffer.from(u8).toString('hex')
const cat = (...parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let o = 0; for (const p of parts) { out.set(p, o); o += p.length } return out }
const u64 = (n) => { const b = new Uint8Array(8); let v = BigInt(n); for (let i = 7; i >= 0; i--) { b[i] = Number(v & 0xffn); v >>= 8n } return b }

const salt = te.encode('forgesworn-link/rendezvous/v1')
const secret = sha256(te.encode('forgesworn-link/paired-route-vector/1'))
const relayHost = 'relay.example.org'
const epochIndex = 498216
const tag = hkdf(sha256, cat(Uint8Array.of(0x04), secret), salt, cat(te.encode(relayHost), Uint8Array.of(0), u64(epochIndex)), 16)

const out = {
  format: 'forgesworn-link-paired-route-known-answer-v1',
  status: 'ratified for implementation: docs/PAIRED-RENDEZVOUS.md',
  saltUtf8: 'forgesworn-link/rendezvous/v1',
  caseByte: 4,
  ikm: '0x04 || paired_route_secret (33 bytes)',
  pairedRouteSecretHex: hex(secret),
  relayHost,
  epochIndex,
  tagHex: hex(tag),
}
writeFileSync(new URL('./paired-rendezvous.json', import.meta.url), JSON.stringify(out, null, 2) + '\n')
console.log(`wrote paired-rendezvous.json: ${out.tagHex}`)
