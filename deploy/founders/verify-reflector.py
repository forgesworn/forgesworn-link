#!/usr/bin/env python3
"""Opt-in public UDP check using the reflector format in link-core/wire.rs."""

import ipaddress
import secrets
import socket

nonce = secrets.token_bytes(16)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
    connection.settimeout(8)
    connection.connect(("link1.forgesworn.dev", 7450))
    connection.send(b"FSLR\x01" + nonce)
    try:
        reply = connection.recv(64)
    except TimeoutError:
        raise SystemExit("No public UDP reflector reply within eight seconds") from None
if len(reply) != 39 or reply[:5] != b"FSLR\x02" or reply[5:21] != nonce:
    raise SystemExit("Invalid UDP reflector response or nonce")
if (ipaddress.IPv6Address(reply[21:37]).ipv4_mapped is None
        or int.from_bytes(reply[37:39], "big") == 0):
    raise SystemExit("Invalid reflected IPv4 socket address")
# The observed client address and nonce are deliberately not logged.
print("link1.forgesworn.dev: public UDP 7450 reflector round trip passed")
