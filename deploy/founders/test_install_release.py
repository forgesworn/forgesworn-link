import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("receiver", Path(__file__).with_name("install-release.py"))
receiver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receiver)
PAYLOAD = b"\x7fELF\x02\x01" + bytes(10) + b"\x02\x00\x3e\x00" + bytes(512)


def packet(payload=PAYLOAD, **changes):
    record = {"commit": "a" * 40, "sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}
    record.update(changes)
    return json.dumps(record).encode() + b"\n" + payload


class ReceiverTests(unittest.TestCase):
    def test_verified_binary_and_record_are_written_without_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            record = receiver.receive(io.BytesIO(packet()), base)
            self.assertEqual((base / "link-relay").read_bytes(), PAYLOAD)
            self.assertEqual(json.loads((base / "release.json").read_text()), record)
            self.assertEqual((base / "link-relay").stat().st_mode & 0o777, 0o555)

    def test_bad_length_digest_path_and_extra_data_are_refused(self):
        cases = [packet(bytes=True), packet(bytes=receiver.MAX_BYTES + 1), packet(bytes=0),
                 packet(commit="../escape"), packet(sha256="b" * 64), packet()[:-1],
                 packet() + b"extra", packet(extra="command"), packet(b"not an ELF"), b"x" * 513]
        for value in cases:
            with self.subTest(case=cases.index(value)), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises((ValueError, json.JSONDecodeError)):
                    receiver.receive(io.BytesIO(value), Path(directory))

    def test_failed_restart_restores_previous_release(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            old = base / "old"
            new = base / "new"
            old.mkdir()
            new.mkdir()
            (base / "current").symlink_to("old")
            calls = []

            def restart():
                calls.append((base / "current").resolve())
                if len(calls) == 1:
                    raise RuntimeError("fixture failure")

            with self.assertRaises(RuntimeError):
                receiver.activate(base, new, restart, lambda: self.fail("must restore"))
            self.assertEqual((base / "current").resolve(), old.resolve())
            self.assertEqual(calls, [new.resolve(), old.resolve()])

    def test_failed_first_start_removes_current_and_stops_service(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            new = base / "new"
            new.mkdir()
            stopped = []

            def fail():
                raise RuntimeError("fixture failure")

            with self.assertRaises(RuntimeError):
                receiver.activate(base, new, fail, lambda: stopped.append(True))
            self.assertFalse((base / "current").is_symlink())
            self.assertEqual(stopped, [True])


if __name__ == "__main__":
    unittest.main()
