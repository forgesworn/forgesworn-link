#!/usr/bin/env python3
"""Stream one release to the restricted SSH receiver; stdout is binary."""

import hashlib
import json
from pathlib import Path
import re
import sys

if len(sys.argv) != 3 or not re.fullmatch(r"[0-9a-f]{40}", sys.argv[2]):
    raise SystemExit("Usage: stream-release.py BINARY SOURCE_COMMIT")
payload = Path(sys.argv[1]).read_bytes()
if not 0 < len(payload) <= 32 * 1024 * 1024:
    raise SystemExit("Release binary must be at most 32 MiB")
record = {"commit": sys.argv[2], "sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}
sys.stdout.buffer.write(json.dumps(record).encode() + b"\n")
sys.stdout.buffer.write(payload)
