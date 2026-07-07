#!/usr/bin/env python3
"""
Benchmark: Fragmentation Overhead.

Measures the overhead introduced by the fragmentation protocol
for ML-KEM-768 key sizes (pk=1184B, ct=1088B).

Compares:
- Raw data size (no fragmentation)
- On-wire size (with fragmentation headers)
- Number of GATT packets required
"""

import json
import os

from src.common.fragmentation import fragment_data
from src.common.constants import PK_SIZE, CT_SIZE


def benchmark_fragmentation():
    """Measure fragmentation overhead for key sizes."""
    sizes = {
        "ML-KEM-768 public key": PK_SIZE,
        "ML-KEM-768 ciphertext": CT_SIZE,
        "ML-KEM-768 shared secret": 32,
        "ECDH-P256 public key (BLE standard)": 64,
        "Dilithium2 signature (future)": 2420,
    }

    results = {}

    print(f"{'Data type':<40} {'Raw':>6} {'Wire':>7} {'Packets':>7} {'Overhead':>8}")
    print("-" * 75)

    for name, size in sizes.items():
        data = b"x" * size
        fragments = fragment_data(data, mtu=512)

        wire_size = sum(len(f) for f in fragments)
        overhead = wire_size - size
        overhead_pct = (overhead / size) * 100 if size > 0 else 0

        results[name] = {
            "raw_bytes": size,
            "wire_bytes": wire_size,
            "overhead_bytes": overhead,
            "overhead_percent": round(overhead_pct, 1),
            "num_fragments": len(fragments),
            "num_gatt_packets": len(fragments),
        }

        print(f"{name:<40} {size:>6} {wire_size:>7} {len(fragments):>7} "
              f"{overhead_pct:>6.1f}%")

    return results


def main():
    results = benchmark_fragmentation()

    # Theoretical GATT timing estimate
    print("\n" + "═" * 50)
    print("  GATT TRANSFER TIME ESTIMATE")
    print("═" * 50)
    print("  Assumptions:")
    print("    - Connection interval: 30ms (typical BLE)")
    print("    - 1 packet per connection event")
    print()

    ci_ms = 30  # connection interval

    for name, r in results.items():
        time_ms = r["num_gatt_packets"] * ci_ms
        print(f"  {name}:")
        print(f"    {r['num_gatt_packets']} packets × {ci_ms}ms = {time_ms}ms")

    print()
    print("  ⚠ Note: Write without response can send multiple packets")
    print("    per connection event, reducing actual time.")

    output_dir = os.path.join(os.path.dirname(__file__), "results")
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "fragmentation_overhead.json")

    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nResults saved to: {output_path}")


if __name__ == "__main__":
    main()