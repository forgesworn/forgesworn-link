#!/usr/bin/env python3
"""Run a command, sample its peak resident set (VmHWM) every 250 ms, report both.

usage: rss-run.py <label> -- <command...>
Prints the child's stdout/stderr through unchanged, then one JSON line:
{"label":..., "exit":..., "peak_rss_bytes":..., "seconds":...}
"""
import json, os, subprocess, sys, time

label = sys.argv[1]
assert sys.argv[2] == "--"
cmd = sys.argv[3:]
start = time.time()
child = subprocess.Popen(cmd)
peak = 0
while child.poll() is None:
    try:
        with open(f"/proc/{child.pid}/status") as f:
            for line in f:
                if line.startswith("VmHWM:"):
                    kb = int(line.split()[1])
                    peak = max(peak, kb * 1024)
    except FileNotFoundError:
        pass
    time.sleep(0.25)
print(json.dumps({"label": label, "exit": child.returncode,
                  "peak_rss_bytes": peak, "seconds": round(time.time() - start, 2)}), flush=True)
sys.exit(child.returncode)
