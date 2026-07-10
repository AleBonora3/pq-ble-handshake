#!/usr/bin/env python3
"""Benchmark ML-KEM-768, SAS e HKDF senza includere il trasporto BLE."""

from __future__ import annotations

import argparse
import json
import math
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from src.common.ml_kem import decapsulate, encapsulate, generate_keypair
from src.common.sas import derive_sas
from src.common.session import derive_session_key

RESULTS_DIR = Path(__file__).resolve().parent / "results"


def elapsed_us(function, *args):
    start = time.perf_counter_ns()
    result = function(*args)
    return result, (time.perf_counter_ns() - start) / 1_000


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    rank = max(1, math.ceil(fraction * len(ordered)))
    return ordered[rank - 1]


def stats(values: list[float]) -> dict[str, float]:
    return {
        "min": min(values),
        "mean": statistics.mean(values),
        "median": statistics.median(values),
        "max": max(values),
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
        "stddev": statistics.stdev(values) if len(values) > 1 else 0.0,
    }


def one_handshake() -> dict[str, float]:
    (pk, sk), keygen = elapsed_us(generate_keypair)
    (ct, ss_enc), encaps = elapsed_us(encapsulate, pk)
    ss_dec, decaps = elapsed_us(decapsulate, sk, ct)
    if ss_enc != ss_dec:
        raise RuntimeError("ML-KEM shared-secret mismatch")

    _, sas = elapsed_us(derive_sas, pk, ct, ss_enc)
    key, hkdf = elapsed_us(derive_session_key, ss_enc)
    if len(key) != 32:
        raise RuntimeError("Unexpected session-key size")

    return {
        "keygen": keygen,
        "encaps": encaps,
        "decaps": decaps,
        "sas_derivation": sas,
        "hkdf_derivation": hkdf,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--warmup", type=int, default=20)
    args = parser.parse_args()

    if args.iterations <= 0 or args.warmup < 0:
        raise ValueError("Invalid iteration count")

    print("PQ-BLE-HANDSHAKE — Cryptographic Handshake Benchmark")
    print("Scope: crypto only; BLE scan/connect/GATT are excluded.")
    print(f"Warm-up: {args.warmup}; measured iterations: {args.iterations}")

    for _ in range(args.warmup):
        one_handshake()

    timings = []
    for index in range(args.iterations):
        row = one_handshake()
        row["total"] = sum(row.values())
        timings.append(row)
        if index == 0 or (index + 1) % 100 == 0 or index + 1 == args.iterations:
            print(f"{index + 1:>5}/{args.iterations}: total={row['total']:.2f} us")

    phase_names = [
        "keygen",
        "encaps",
        "decaps",
        "sas_derivation",
        "hkdf_derivation",
    ]
    phase_stats = {
        name: stats([row[name] for row in timings])
        for name in phase_names
    }
    total_stats = stats([row["total"] for row in timings])

    result = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "algorithm": "ML-KEM-768",
        "measurement_scope": "Crypto only; BLE excluded",
        "warmup_iterations": args.warmup,
        "measured_iterations": args.iterations,
        "phases_us": phase_stats,
        "total_us": total_stats,
        "total_ms": {key: value / 1000 for key, value in total_stats.items()},
        "handshakes_per_second_from_mean": 1_000_000 / total_stats["mean"],
    }

    print("\n" + "=" * 72)
    for name in phase_names:
        row = phase_stats[name]
        print(
            f"{name:<18} mean={row['mean']:>9.2f} us "
            f"median={row['median']:>9.2f} us p99={row['p99']:>9.2f} us"
        )
    print("-" * 72)
    print(
        f"{'TOTAL':<18} mean={result['total_ms']['mean']:>9.4f} ms "
        f"median={result['total_ms']['median']:>9.4f} ms "
        f"p99={result['total_ms']['p99']:>9.4f} ms"
    )
    print(
        "Derived throughput: "
        f"{result['handshakes_per_second_from_mean']:.1f} crypto handshakes/s"
    )
    print("=" * 72)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    output = RESULTS_DIR / "handshake_latency.json"
    output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"JSON saved to: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
