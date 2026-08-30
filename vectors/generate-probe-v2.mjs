// Known-answer vectors for probe v2, spec 4.2: session-keyed probes.
//
// Node only, no dependencies.  Fixed, deterministic test material: a 32-byte
// probe key, an 8-byte key id and a 16-byte nonce, and the MAC each kind of
// probe carries under them.  Regenerated only when the probe version byte
// changes.  Run: node vectors/generate-probe-v2.mjs

import { createHmac } from "node:crypto";
import { writeFileSync } from "node:fs";

const MAGIC = Buffer.from("FSLP");
const VERSION = 0x02;
const PING = 0x01;
const PONG = 0x02;
const DOMAIN = Buffer.concat([Buffer.from("forgesworn-link/probe/v2"), Buffer.from([0])]);

const key = Buffer.from(
  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  "hex",
);
const keyId = Buffer.from("8899aabbccddeeff", "hex");
const nonce = Buffer.from("00112233445566778899aabbccddeeff", "hex");

function seal(kind) {
  const body = Buffer.concat([MAGIC, Buffer.from([VERSION, kind]), keyId, nonce]);
  const mac = createHmac("sha256", key)
    .update(Buffer.concat([DOMAIN, body]))
    .digest();
  return {
    kind,
    body_hex: body.toString("hex"),
    mac_input_hex: Buffer.concat([DOMAIN, body]).toString("hex"),
    mac_hex: mac.toString("hex"),
    wire_hex: Buffer.concat([body, mac]).toString("hex"),
  };
}

const vectors = {
  version: VERSION,
  wire_bytes: 4 + 1 + 1 + 8 + 16 + 32,
  domain_hex: DOMAIN.toString("hex"),
  export_label: "forgesworn-link/probe/v2",
  export_bytes: 40,
  key_hex: key.toString("hex"),
  key_id_hex: keyId.toString("hex"),
  nonce_hex: nonce.toString("hex"),
  ping: seal(PING),
  pong: seal(PONG),
  hostile: {
    wrong_key_hex: "ff".repeat(32),
    truncated_len: 61,
    flipped_byte: 30,
  },
};

writeFileSync(
  new URL("./probe.json", import.meta.url),
  JSON.stringify(vectors, null, 2) + "\n",
);
console.log("wrote vectors/probe.json (probe v2)");
