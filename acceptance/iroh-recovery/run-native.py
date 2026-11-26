#!/usr/bin/env python3
"""Run alternating local benchmark blocks and emit JSON measurements."""

import argparse
import csv
import json
import math
from pathlib import Path
import resource
import statistics
import subprocess
import sys


def child_cpu_seconds():
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime + usage.ru_stime


def run(binary, implementation, case, count):
    before = child_cpu_seconds()
    proc = subprocess.run(
        [binary, implementation, case, str(count)],
        capture_output=True,
        text=True,
        timeout=180,
    )
    cpu = child_cpu_seconds() - before
    if proc.returncode != 0:
        raise SystemExit(f"{implementation} {case} failed: {proc.stderr.strip()}")
    rows = [
        (phase, int(size), float(seconds), float(startup))
        for phase, size, seconds, startup in csv.reader(proc.stdout.splitlines())
    ]
    cold = case == "cold-relay"
    expected_phases = ["warmup"] * (0 if cold else 2) + ["sample"] * count
    expected_size = 1024 if cold else 64 * 1024**2
    if [phase for phase, _, _, _ in rows] != expected_phases or any(
        size != expected_size
        or not math.isfinite(seconds)
        or not math.isfinite(startup)
        or seconds <= 0
        or (startup <= 0 if cold else startup != 0)
        for _, size, seconds, startup in rows
    ):
        raise SystemExit(f"invalid {implementation} {case} measurements")
    if cold:
        return {
            "total_ms": [(dial + startup) * 1000 for _, _, dial, startup in rows],
            "startup_ms": [startup * 1000 for _, _, _, startup in rows],
            "dial_ms": [dial * 1000 for _, _, dial, _ in rows],
        }
    return {
        "mib_per_second": [
            size / 1024**2 / seconds for phase, size, seconds, _ in rows if phase == "sample"
        ],
        "cpu_seconds_per_gib": cpu * 1024**3 / sum(size for _, size, _, _ in rows),
    }


def latency(samples):
    samples = sorted(samples)
    return {
        "p50_ms": statistics.median(samples),
        "p95_ms": samples[math.ceil(0.95 * len(samples)) - 1],
        "range_ms": [samples[0], samples[-1]],
    }


def summarise(case, runs):
    if case == "cold-relay":
        return {
            key: latency(sample for run in runs for sample in run[key])
            for key in ("total_ms", "startup_ms", "dial_ms")
        }
    goodput = sorted(sample for run in runs for sample in run["mib_per_second"])
    cpu = sorted(run["cpu_seconds_per_gib"] for run in runs)
    return {
        "median_mib_per_second": statistics.median(goodput),
        "range_mib_per_second": [goodput[0], goodput[-1]],
        "median_cpu_seconds_per_gib": statistics.median(cpu),
        "range_cpu_seconds_per_gib": [cpu[0], cpu[-1]],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--blocks", type=int, default=6)
    parser.add_argument("--cold-samples", type=int, default=20)
    parser.add_argument("--bulk-samples", type=int, default=8)
    args = parser.parse_args()
    if min(args.blocks, args.cold_samples, args.bulk_samples) < 1:
        parser.error("counts must be positive")

    binary = args.binary.resolve(strict=True)
    results = {}
    for case in ("cold-relay", "direct", "relay"):
        runs = {"link": [], "iroh": []}
        count = args.cold_samples if case == "cold-relay" else args.bulk_samples
        for block in range(args.blocks):
            order = ["link", "iroh"] if block % 2 == 0 else ["iroh", "link"]
            for implementation in order:
                runs[implementation].append(run(binary, implementation, case, count))
            print(f"{case} block {block + 1}/{args.blocks}", file=sys.stderr, flush=True)
        results[case] = {
            implementation: {"summary": summarise(case, rows), "runs": rows}
            for implementation, rows in runs.items()
        }
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
