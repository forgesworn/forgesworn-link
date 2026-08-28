#!/usr/bin/env python3
"""Search a pcap for any 16-byte window of the link-spike deterministic payload.

The spike fills its stream with xorshift64 starting from 0x5eed_0000_0000_0001
(crates/link-spike/src/main.rs).  If the relay carried plaintext, some window
of that stream would appear verbatim in the capture.  QUIC encrypts every
packet, so the expected result is zero hits.

usage: pcap-leak-check.py <file.pcap> [payload_bytes_to_generate]
Prints one JSON line with packet count, bytes scanned, windows tried, hits.
Plain pcap (not pcapng), any link type: the whole packet payload is scanned.
"""
import json, struct, sys

path = sys.argv[1]
limit = int(sys.argv[2]) if len(sys.argv) > 2 else 4 * 1024 * 1024

# Regenerate the payload prefix.
state = 0x5EED_0000_0000_0001
mask = (1 << 64) - 1
payload = bytearray()
while len(payload) < limit:
    x = state
    x ^= (x << 13) & mask
    x ^= x >> 7
    x ^= (x << 17) & mask
    state = x
    payload += x.to_bytes(8, "little")
payload = bytes(payload[:limit])

# Index every 16-byte window at 8-byte alignment (the stream is 8-byte aligned,
# and QUIC or TCP segmentation can shift where a packet starts, so also index
# at every byte offset for the first 64 KiB to catch unaligned copies).
windows = set()
for off in range(0, len(payload) - 16, 8):
    windows.add(payload[off:off + 16])
for off in range(0, min(len(payload), 65536) - 16):
    windows.add(payload[off:off + 16])

with open(path, "rb") as f:
    data = f.read()
magic = struct.unpack("<I", data[:4])[0]
if magic == 0xA1B2C3D4:
    endian = "<"
elif magic == 0xD4C3B2A1:
    endian = ">"
else:
    raise SystemExit("not a classic pcap file")
pos = 24
packets = 0
scanned = 0
hits = 0
while pos + 16 <= len(data):
    _, _, incl, _ = struct.unpack(endian + "IIII", data[pos:pos + 16])
    pos += 16
    pkt = data[pos:pos + incl]
    pos += incl
    packets += 1
    scanned += len(pkt)
    for off in range(0, max(0, len(pkt) - 16)):
        if pkt[off:off + 16] in windows:
            hits += 1
            break
print(json.dumps({"pcap": path, "packets": packets, "bytes_scanned": scanned,
                  "payload_windows": len(windows), "packets_with_plaintext_window": hits}))
