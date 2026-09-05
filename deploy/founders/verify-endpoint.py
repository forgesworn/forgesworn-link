#!/usr/bin/env python3
"""Check the configured public service using the ordinary TLS trust store."""

import base64
import hashlib
import os
import socket
import ssl

HOST = "link1.forgesworn.dev"
key = base64.b64encode(os.urandom(16)).decode("ascii")
expected = base64.b64encode(hashlib.sha1(
    (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
).digest()).decode("ascii")
request = (f"GET /link HTTP/1.1\r\nHost: {HOST}\r\n"
           "Upgrade: websocket\r\nConnection: Upgrade\r\n"
           f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
with socket.create_connection((HOST, 443), timeout=15) as tcp:
    with ssl.create_default_context().wrap_socket(tcp, server_hostname=HOST) as tls:
        tls.sendall(request.encode("ascii"))
        with tls.makefile("rb") as response:
            status = response.readline(4097)
            if len(status) > 4096 or status.split()[:2] != [b"HTTP/1.1", b"101"]:
                raise SystemExit("Public endpoint did not upgrade to WebSocket")
            headers = {}
            total = len(status)
            while True:
                line = response.readline(4097)
                total += len(line)
                if total > 16384 or len(line) > 4096 or not line.endswith(b"\r\n"):
                    raise SystemExit("Invalid WebSocket response headers")
                if line == b"\r\n":
                    break
                name, value = line.decode("ascii").strip().split(":", 1)
                name = name.lower()
                if name in headers:
                    raise SystemExit("Duplicate WebSocket response header")
                headers[name] = value.strip()
            if (headers.get("sec-websocket-accept") != expected
                    or headers.get("upgrade", "").lower() != "websocket"
                    or "upgrade" not in [part.strip() for part in
                                         headers.get("connection", "").lower().split(",")]):
                raise SystemExit("Invalid WebSocket upgrade proof")
print("link1.forgesworn.dev: trusted TLS and /link WebSocket upgrade passed")
