#!/usr/bin/env python3
"""Benchmark overhead e latenza CPU della frammentazione PQ-BLE."""

from __future__ import annotations

import argparse
import json
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from src.common.constants import CT_SIZE, PK_SIZE
from src.common.fragmentation import fragment_data, reassemble_data

RESULTS_DIR = Path(__file__).resolve().parent / "results"


def cpu_latency(data: bytes, mtu: int, iterations: int) -> tuple[float, float]:
    frag_times = []
    reasm_times = []

    for _ in range(100):
        fragments = fragment_data(data, mtu=mtu)
        if reassemble_data(fragments) != data:
            raise RuntimeError("Warm-up reassembly mismatch")

    for _ in range(iterations):
        start = time.perf_counter_ns()
        fragments = fragment_data(data, mtu=mtu)
        frag_times.append((time.perf_counter_ns() - start) / 1_000)

        start = time.perf_counter_ns()
        recovered = reassemble_data(fragments)
        reasm_times.append((time.perf_counter_ns() - start) / 1_000)

        if recovered != data:
            raise RuntimeError("Reassembly mismatch")

    return statistics.mean(frag_times), statistics.mean(reasm_times)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=10000)
    args = parser.parse_args()
    if args.iterations <= 0:
        raise ValueError("iterations must be > 0")

    sizes = {
        "ML-KEM-768 ciphertext (actual application write)": CT_SIZE,
        "ML-KEM-768 public key (theoretical app fragmentation)": PK_SIZE,
        "ML-KEM-768 shared secret": 32,
        "ECDH-P256 public key comparison": 64,
        "ML-DSA signature comparison": 2420,
    }

    print("PQ-BLE-HANDSHAKE — Fragmentation Benchmark")
    print("MTU 247: validated hardware value; MTU 512: comparison.")
    print("CPU timings exclude BLE transfer latency.")
    print(
        "The public key uses ATT Long Read/Read Blob in the hardware demo; "
        "its app-fragmentation row is theoretical."
    )

    result = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "cpu_iterations": args.iterations,
        "validated_hardware_mtu": 247,
        "comparison_mtu": 512,
        "public_key_transport_note": (
            "Hardware demo uses ATT Long Read/Read Blob; "
            "app fragmentation is theoretical."
        ),
        "mtus": {},
    }

    for mtu in (247, 512):
        print("\n" + "=" * 100)
        print(f"MTU {mtu} — application payload {mtu - 4} bytes")
        print("=" * 100)
        print(
            f"{'Data type':<55} {'Raw':>6} {'Wire':>7} "
            f"{'Frag':>5} {'Overh.':>8} {'Frag us':>9} {'Reasm us':>9}"
        )
        print("-" * 105)

        rows = {}
        for name, size in sizes.items():
            data = b"x" * size
            fragments = fragment_data(data, mtu=mtu)
            if reassemble_data(fragments) != data:
                raise RuntimeError(f"Reassembly mismatch for {name}")

            wire_bytes = sum(len(fragment) for fragment in fragments)
            overhead_bytes = wire_bytes - size
            overhead_percent = overhead_bytes / size * 100
            frag_us, reasm_us = cpu_latency(data, mtu, args.iterations)

            rows[name] = {
                "raw_bytes": size,
                "wire_bytes": wire_bytes,
                "fragment_payload_bytes": mtu - 4,
                "num_fragments": len(fragments),
                "overhead_bytes": overhead_bytes,
                "overhead_percent": overhead_percent,
                "fragmentation_mean_us": frag_us,
                "reassembly_mean_us": reasm_us,
            }

            print(
                f"{name:<55} {size:>6} {wire_bytes:>7} "
                f"{len(fragments):>5} {overhead_percent:>7.2f}% "
                f"{frag_us:>9.2f} {reasm_us:>9.2f}"
            )

        result["mtus"][str(mtu)] = rows

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    output = RESULTS_DIR / "fragmentation_overhead.json"
    output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"\nJSON saved to: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
