#!/usr/bin/env python3
"""Root-owned receiver for a forced SSH command; accepts only one bounded binary."""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

MAX_BYTES = 32 * 1024 * 1024


def receive(stream, directory):
    header = stream.readline(513)
    if len(header) > 512 or not header.endswith(b"\n"):
        raise ValueError("Invalid release header")
    record = json.loads(header)
    if not isinstance(record, dict) or set(record) != {"commit", "sha256", "bytes"}:
        raise ValueError("Invalid release fields")
    if not isinstance(record["commit"], str) or not re.fullmatch(r"[0-9a-f]{40}", record["commit"]):
        raise ValueError("Invalid source commit")
    if not isinstance(record["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"]):
        raise ValueError("Invalid binary digest")
    if type(record["bytes"]) is not int or not 0 < record["bytes"] <= MAX_BYTES:
        raise ValueError("Invalid binary length")
    digest = hashlib.sha256()
    remaining = record["bytes"]
    binary = directory / "link-relay"
    with binary.open("xb") as output:
        while remaining:
            chunk = stream.read(min(65536, remaining))
            if not chunk:
                raise ValueError("Truncated binary")
            output.write(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
        output.flush()
        os.fsync(output.fileno())
    if stream.read(1):
        raise ValueError("Unexpected trailing data")
    if digest.hexdigest() != record["sha256"]:
        raise ValueError("Binary digest mismatch")
    with binary.open("rb") as source:
        header = source.read(20)
    # ELF64, little endian, executable or PIE, x86-64. Never execute an
    # uploaded file as root; only the sandboxed service may run the result.
    if (header[:6] != b"\x7fELF\x02\x01" or len(header) != 20
            or header[16:18] not in (b"\x02\x00", b"\x03\x00")
            or header[18:20] != b"\x3e\x00"):
        raise ValueError("Expected an x86-64 Linux ELF binary")
    binary.chmod(0o555)
    (directory / "release.json").write_text(json.dumps(record, sort_keys=True) + "\n")
    (directory / "release.json").chmod(0o444)
    return record


def activate(base, release, restart, stop):
    current = base / "current"
    previous = os.readlink(current) if current.is_symlink() else None
    if current.exists() and previous is None:
        raise ValueError("Current release must be a managed symlink")
    pending = base / ".current-next"
    pending.unlink(missing_ok=True)
    pending.symlink_to(release.relative_to(base))
    os.replace(pending, current)
    try:
        restart()
    except Exception:
        if previous is None:
            current.unlink()
            stop()
        else:
            pending.symlink_to(previous)
            os.replace(pending, current)
            restart()
        raise


def restart_service():
    subprocess.run(["systemctl", "restart", "link-relay"], check=True, timeout=30)
    time.sleep(2)
    subprocess.run(["systemctl", "is-active", "--quiet", "link-relay"], check=True, timeout=10)


def main():
    if os.geteuid() != 0 or len(sys.argv) != 1:
        raise ValueError("Receiver requires root and accepts no arguments")
    def deadline_elapsed(*_):
        raise TimeoutError("Upload deadline exceeded")

    signal.signal(signal.SIGALRM, deadline_elapsed)
    signal.alarm(180)
    base = Path("/opt/link-relay")
    releases = base / "releases"
    for directory in (base, releases):
        if directory == releases:
            directory.mkdir(exist_ok=True, mode=0o755)
        info = directory.stat()
        if (directory.is_symlink() or not directory.is_dir()
                or info.st_uid != 0 or info.st_mode & 0o022):
            raise ValueError("Release directories must be root-owned and not group/world writable")
    with (base / ".deploy.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        temporary = Path(tempfile.mkdtemp(prefix=".upload-", dir=releases))
        try:
            record = receive(sys.stdin.buffer, temporary)
            signal.alarm(0)
            destination = releases / (record["commit"] + "-" + record["sha256"])
            if destination.is_symlink():
                raise ValueError("Release must be a managed directory")
            if destination.exists():
                saved = json.loads((destination / "release.json").read_text())
                digest = hashlib.sha256((destination / "link-relay").read_bytes()).hexdigest()
                if saved != record or digest != record["sha256"]:
                    raise ValueError("Existing release does not match its record")
            else:
                temporary.chmod(0o755)
                temporary.rename(destination)
            activate(base, destination, restart_service, lambda: subprocess.run(
                ["systemctl", "stop", "link-relay"], check=True, timeout=30))
            print(json.dumps({"installed": record, "service": "active"}, sort_keys=True))
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # No submitted header/body, SSH command or credential goes into logs.
        print("Release rejected: " + type(error).__name__, file=sys.stderr)
        sys.exit(1)
