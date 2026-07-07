#!/usr/bin/env python3
"""
Benchmark: Handshake Latency.

Measures the time required for each phase of the handshake:
1. ML-KEM-768 key generation
2. ML-KEM-768 encapsulation
3. ML-KEM-768 decapsulation
4. SAS derivation
5. HKDF session key derivation

Runs N iterations and outputs JSON + human-readable summary.
"""

import json
import os
import time
from dataclasses import dataclass, field
from typing import List

from src.common.ml_kem import generate_keypair, encapsulate, decapsulate
from src.common.sas import derive_sas
from src.common.session import derive_session_key


@dataclass
class HandshakeTiming:
    """Timing breakdown for a single handshake."""
    keygen_us: float = 0.0
    encaps_us: float = 0.0
    decaps_us: float = 0.0
    sas_us: float = 0.0
    hkdf_us: float = 0.0


@dataclass
class BenchmarkResult:
    """Aggregate results."""
    iterations: int
    timings: List[HandshakeTiming] = field(default_factory=list)

    @property
    def total_us(self) -> float:
        """Average total handshake time (no BLE)."""
        totals = [sum([t.keygen_us, t.encaps_us, t.decaps_us, t.sas_us, t.hkdf_us])
                  for t in self.timings]
        return sum(totals) / len(totals) if totals else 0


def benchmark_handshake(iterations: int = 100) -> BenchmarkResult:
    """Run the handshake N times and measure each phase."""
    result = BenchmarkResult(iterations=iterations)

    print(f"Running {iterations} handshake iterations...")
    print(f"{'Iter':>5}  {'Keygen':>10}  {'Encaps':>10}  {'Decaps':>10}  {'SAS':>10}  {'HKDF':>10}  {'Total':>10}")
    print("-" * 75)

    for i in range(iterations):
        timing = HandshakeTiming()

        # Phase 1: Keygen
        t0 = time.perf_counter()
        pk, sk = generate_keypair()
        timing.keygen_us = (time.perf_counter() - t0) * 1_000_000

        # Phase 2: Encapsulate
        t0 = time.perf_counter()
        ct, ss_e = encapsulate(pk)
        timing.encaps_us = (time.perf_counter() - t0) * 1_000_000

        # Phase 3: Decapsulate
        t0 = time.perf_counter()
        ss_d = decapsulate(sk, ct)
        timing.decaps_us = (time.perf_counter() - t0) * 1_000_000

        assert ss_e == ss_d, "Shared secret mismatch!"

        # Phase 4: SAS derivation
        t0 = time.perf_counter()
        sas = derive_sas(pk, ct, ss_e)
        timing.sas_us = (time.perf_counter() - t0) * 1_000_000

        # Phase 5: Session key derivation (HKDF)
        t0 = time.perf_counter()
        session_key = derive_session_key(ss_e)
        timing.hkdf_us = (time.perf_counter() - t0) * 1_000_000

        result.timings.append(timing)

        total = sum([timing.keygen_us, timing.encaps_us, timing.decaps_us,
                     timing.sas_us, timing.hkdf_us])

        if i % 10 == 0 or i == iterations - 1:
            print(f"{i+1:>5}  {timing.keygen_us:>8.2f}μs  "
                  f"{timing.encaps_us:>8.2f}μs  {timing.decaps_us:>8.2f}μs  "
                  f"{timing.sas_us:>8.2f}μs  {timing.hkdf_us:>8.2f}μs  "
                  f"{total:>8.2f}μs")

    return result


def compute_stats(values: List[float]):
    """Compute min, mean, max, p99, stddev."""
    if not values:
        return {}
    import statistics
    sorted_v = sorted(values)
    n = len(sorted_v)
    return {
        "min": min(values),
        "mean": statistics.mean(values),
        "max": max(values),
        "p99": sorted_v[int(n * 0.99)],
        "p999": sorted_v[int(n * 0.999)] if n > 100 else sorted_v[-1],
        "stddev": statistics.stdev(values) if n > 1 else 0,
    }


def main():
    iterations = 100
    result = benchmark_handshake(iterations)

    # Compute aggregate stats
    keygen_vals = [t.keygen_us for t in result.timings]
    encaps_vals = [t.encaps_us for t in result.timings]
    decaps_vals = [t.decaps_us for t in result.timings]
    sas_vals = [t.sas_us for t in result.timings]
    hkdf_vals = [t.hkdf_us for t in result.timings]
    total_vals = [sum([t.keygen_us, t.encaps_us, t.decaps_us, t.sas_us, t.hkdf_us])
                  for t in result.timings]

    stats = {
        "iterations": iterations,
        "phases": {
            "keygen": compute_stats(keygen_vals),
            "encaps": compute_stats(encaps_vals),
            "decaps": compute_stats(decaps_vals),
            "sas_derivation": compute_stats(sas_vals),
            "hkdf_derivation": compute_stats(hkdf_vals),
        },
        "total_us": compute_stats(total_vals),
        "total_ms": {k: v / 1000 for k, v in compute_stats(total_vals).items()}
        if total_vals else {},
    }

    # Print summary
    print("\n" + "═" * 50)
    print("  RESULTS SUMMARY")
    print("═" * 50)
    print(f"  Keygen:     {stats['phases']['keygen']['mean']:.1f} μs avg")
    print(f"  Encaps:     {stats['phases']['encaps']['mean']:.1f} μs avg")
    print(f"  Decaps:     {stats['phases']['decaps']['mean']:.1f} μs avg")
    print(f"  SAS:        {stats['phases']['sas_derivation']['mean']:.1f} μs avg")
    print(f"  HKDF:       {stats['phases']['hkdf_derivation']['mean']:.1f} μs avg")
    print(f"  ─────────────────────────────")
    print(f"  TOTAL:      {stats['total_us']['mean']:.1f} μs = {stats['total_ms']['mean']:.2f} ms")
    print(f"  P99:        {stats['total_us']['p99']:.1f} μs = {stats['total_us']['p99']/1000:.2f} ms")
    print(f"  Throughput: {iterations / (stats['total_us']['mean'] * iterations / 1_000_000):.0f} handshakes/sec")
    print("═" * 50)

    # Save to JSON
    output_dir = os.path.join(os.path.dirname(__file__), "results")
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "handshake_latency.json")

    with open(output_path, "w") as f:
        json.dump(stats, f, indent=2)

    print(f"\nResults saved to: {output_path}")


if __name__ == "__main__":
    main()