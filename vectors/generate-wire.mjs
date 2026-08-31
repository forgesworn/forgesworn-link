// Language-neutral wire vectors for the halves the card vectors do not cover:
// the relay frames, the UDP reflector, the FSLB blob protocol and the fsl://
// scheme.  Pure byte codecs, no crypto: an Auth frame's signature is opaque at
// the codec layer, so fixed placeholder bytes freeze the framing without a
// signing step.  Run `node generate-wire.mjs` to regenerate.

import { writeFileSync } from 'node:fs'

const hex = (u8) => Buffer.from(u8).toString('hex')
const cat = (...parts) => Buffer.concat(parts.map((p) => Buffer.from(p)))
const u8 = (n) => Buffer.from([n])
const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b }
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b }
const fill = (byte, len) => Buffer.alloc(len, byte)

const B32 = 'abcdefghijklmnopqrstuvwxyz234567'
const base32 = (bytes) => { let bits = 0, val = 0, out = ''; for (const b of bytes) { val = (val << 8) | b; bits += 8; while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5 } } if (bits > 0) out += B32[(val << (5 - bits)) & 31]; return out }

// Deterministic placeholder identities: raw bytes, valid at the codec layer.
const NODE_A = fill(0xa1, 32)
const NODE_B = fill(0xb2, 32)
const SIGNATURE = fill(0x5c, 64)
const TAG_1 = fill(0x71, 16)
const TAG_2 = fill(0x72, 16)
const DATAGRAM = Buffer.from('64617461', 'hex') // "data"
const MAX_DATAGRAM = 1350

// ---------------------------------------------------------------------------
// Relay frames, SPEC.md 3.1 and 9.
// ---------------------------------------------------------------------------

const frames = {
  format: 'forgesworn-link-relay-frame-vectors-1',
  note: 'Exact frame bytes. Hostile entries MUST fail to decode; the session closes with reason 1.',
  maxDatagram: MAX_DATAGRAM,
  valid: [
    { name: 'challenge', bytesHex: hex(cat(u8(0x01), fill(0xc0, 32))) },
    { name: 'auth', bytesHex: hex(cat(u8(0x02), NODE_A, SIGNATURE)) },
    { name: 'welcome', bytesHex: hex(cat(u8(0x03), fill(0xee, 16))) },
    { name: 'send', bytesHex: hex(cat(u8(0x10), NODE_B, DATAGRAM)) },
    { name: 'recv', bytesHex: hex(cat(u8(0x11), NODE_A, DATAGRAM)) },
    { name: 'register-two-tags', bytesHex: hex(cat(u8(0x04), u16(2), TAG_1, TAG_2)) },
    { name: 'register-empty-replacement', note: 'valid only after a non-empty initial Register; removes every tag', bytesHex: hex(cat(u8(0x04), u16(0))) },
    { name: 'send-tag', bytesHex: hex(cat(u8(0x12), TAG_1, DATAGRAM)) },
    { name: 'recv-tag', bytesHex: hex(cat(u8(0x13), TAG_1, DATAGRAM)) },
    { name: 'send-max-datagram', bytesHex: hex(cat(u8(0x10), NODE_B, fill(0xdd, MAX_DATAGRAM))) },
    { name: 'ping', bytesHex: hex(cat(u8(0x20), fill(0x11, 8))) },
    { name: 'pong', bytesHex: hex(cat(u8(0x21), fill(0x22, 8))) },
    { name: 'close-reason-1', bytesHex: hex(cat(u8(0x7f), u16(1))) },
  ],
  hostile: [
    { name: 'unknown-frame-byte', bytesHex: hex(cat(u8(0x09), DATAGRAM)) },
    { name: 'auth-short', bytesHex: hex(cat(u8(0x02), NODE_A, fill(0x5c, 63))) },
    { name: 'send-empty-datagram', bytesHex: hex(cat(u8(0x10), NODE_B)) },
    { name: 'send-oversize-datagram', bytesHex: hex(cat(u8(0x10), NODE_B, fill(0xdd, MAX_DATAGRAM + 1))) },
    { name: 'send-tag-oversize-datagram', bytesHex: hex(cat(u8(0x12), TAG_1, fill(0xdd, MAX_DATAGRAM + 1))) },
    { name: 'send-tag-empty-datagram', bytesHex: hex(cat(u8(0x12), TAG_1)) },
    { name: 'register-count-mismatch', bytesHex: hex(cat(u8(0x04), u16(2), TAG_1)) },
    { name: 'register-over-max', bytesHex: hex(cat(u8(0x04), u16(257), Buffer.concat(Array.from({ length: 257 }, (_, i) => fill(i & 0xff, 16))))) },
    { name: 'challenge-short', bytesHex: hex(cat(u8(0x01), fill(0xc0, 31))) },
    { name: 'close-short', bytesHex: hex(cat(u8(0x7f), u8(1))) },
  ],
}

// ---------------------------------------------------------------------------
// UDP reflector, SPEC.md 3.2.
// ---------------------------------------------------------------------------

const NONCE = fill(0x9e, 16)
// 192.0.2.7:4242 as a v4-mapped IPv6 address.
const OBSERVED_IP = cat(fill(0, 10), fill(0xff, 2), Buffer.from([192, 0, 2, 7]))

const reflector = {
  format: 'forgesworn-link-reflector-vectors-1',
  note: 'A reply MUST echo the nonce of the node’s own outstanding request or be dropped.',
  request: { nonceHex: hex(NONCE), bytesHex: hex(cat('FSLR', u8(0x01), NONCE)) },
  reply: {
    observed: '192.0.2.7:4242',
    bytesHex: hex(cat('FSLR', u8(0x02), NONCE, OBSERVED_IP, u16(4242))),
  },
  hostile: [
    { name: 'request-short', bytesHex: hex(cat('FSLR', u8(0x01), fill(0x9e, 15))) },
    { name: 'request-bad-magic', bytesHex: hex(cat('XSLR', u8(0x01), NONCE)) },
    { name: 'reply-bad-kind', bytesHex: hex(cat('FSLR', u8(0x03), NONCE, OBSERVED_IP, u16(4242))) },
  ],
}

// ---------------------------------------------------------------------------
// FSLB blob protocol, the link-blossom wire.
// ---------------------------------------------------------------------------

const SHA = fill(0x3d, 32)

const fslb = {
  format: 'forgesworn-link-fslb-vectors-1',
  note: 'Request is fixed 37 bytes. Status 0x03 answers a version the server does not speak; bad magic is a stream reset, not a status.',
  request: { sha256Hex: hex(SHA), bytesHex: hex(cat('FSLB', u8(0x01), SHA)) },
  responses: [
    { name: 'ok-with-content-type', size: 5242880, contentType: 'application/octet-stream', bytesHex: hex(cat(u8(0x00), u64(5242880), u16(24), 'application/octet-stream')) },
    { name: 'ok-no-content-type', size: 1, bytesHex: hex(cat(u8(0x00), u64(1), u16(0))) },
    { name: 'not-found', bytesHex: hex(u8(0x01)) },
    { name: 'error', bytesHex: hex(u8(0x02)) },
    { name: 'unsupported-version', bytesHex: hex(u8(0x03)) },
  ],
  hostile: [
    { name: 'request-bad-magic', bytesHex: hex(cat('XSLB', u8(0x01), SHA)) },
    { name: 'request-future-version', note: 'a server answers status 0x03, not a reset', bytesHex: hex(cat('FSLB', u8(0x02), SHA)) },
    { name: 'request-short', bytesHex: hex(cat('FSLB', u8(0x01), fill(0x3d, 31))) },
    { name: 'response-bad-status', bytesHex: hex(u8(0x09)) },
    { name: 'response-content-type-too-long', bytesHex: hex(cat(u8(0x00), u64(1), u16(300))) },
    { name: 'response-truncated-content-type', bytesHex: hex(cat(u8(0x00), u64(1), u16(10), 'text/pla')) },
  ],
}

// ---------------------------------------------------------------------------
// The fsl:// scheme.
// ---------------------------------------------------------------------------

const nodeB32 = base32(NODE_A)
const digest = '4d'.repeat(32)

const scheme = {
  format: 'forgesworn-link-fsl-scheme-vectors-1',
  note: 'Node id: canonical lowercase base32, 52 chars, zero pad bits. Digest: canonical lowercase hex, 64 chars. accept=false entries MUST be rejected.',
  cases: [
    { name: 'valid', url: `fsl://${nodeB32}/${digest}`, accept: true, nodeIdHex: hex(NODE_A), sha256Hex: digest },
    { name: 'valid-with-extension', url: `fsl://${nodeB32}/${digest}.bin`, accept: true, nodeIdHex: hex(NODE_A), sha256Hex: digest },
    { name: 'uppercase-digest', url: `fsl://${nodeB32}/${'4D'.repeat(32)}`, accept: false },
    { name: 'short-digest', url: `fsl://${nodeB32}/${'4d'.repeat(31)}`, accept: false },
    { name: 'non-canonical-node-pad-bits', url: `fsl://${nodeB32.slice(0, 51)}${B32[(B32.indexOf(nodeB32[51]) | 1)]}/${digest}`, accept: false },
    { name: 'short-node', url: `fsl://${nodeB32.slice(0, 51)}/${digest}`, accept: false },
    { name: 'wrong-scheme-is-unsupported-not-broken', url: `https://example.org/${digest}`, accept: false, unsupported: true },
  ],
}

for (const [name, data] of [
  ['relay-frames.json', frames],
  ['reflector.json', reflector],
  ['fslb.json', fslb],
  ['fsl-scheme.json', scheme],
]) {
  writeFileSync(new URL(`./${name}`, import.meta.url), JSON.stringify(data, null, 2) + '\n')
  console.log(`wrote ${name}`)
}
