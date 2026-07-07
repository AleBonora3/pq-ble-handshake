#!/usr/bin/env python3
"""
Benchmark: Throughput of AES-256-GCM encrypted channel.

Measures KB/s for different payload sizes, with and without encryption.
Compares plaintext throughput vs AES-256-GCM overhead.
"""

import json
import os
import time
from dataclasses import dataclass
from typing import List

from src.common.session import derive_session_key, SecureChannel


@dataclass
class ThroughputResult:
    payload_size: int
    iterations: int
    encrypt_total_s: float
    decrypt_total_s: float
    total_bytes: int

    @property
    def encrypt_kbps(self) -> float:
        return (self.total_bytes / 1024) / self.encrypt_total_s if self.encrypt_total_s > 0 else 0

    @property
    def decrypt_kbps(self) -> float:
        return (self.total_bytes / 1024) / self.decrypt_total_s if self.decrypt_total_s > 0 else 0


def benchmark_throughput() -> List[ThroughputResult]:
    """Test throughput at various payload sizes."""
    session_key = derive_session_key(b"benchmark_throughput_32bytes!")
    channel = SecureChannel(session_key)

    payload_sizes = [64, 256, 512, 1024, 4096, 16384]
    iterations_per_size = {
        64: 1000,
        256: 500,
        512: 200,
        1024: 100,
        4096: 50,
        16384: 20,
    }

    results = []

    print(f"{'Size':>6}  {'Iters':>6}  {'Enc KB/s':>10}  {'Dec KB/s':>10}")
    print("-" * 42)

    for size in payload_sizes:
        n = iterations_per_size[size]
        plaintext = b"x" * size
        total_bytes = size * n

        # Encrypt benchmark
        t0 = time.perf_counter()
        for _ in range(n):
            channel.encrypt(plaintext)
        encrypt_time = time.perf_counter() - t0

        # Decrypt benchmark — pre-generate ciphertexts
        ciphertexts = [channel.encrypt(plaintext) for _ in range(n)]

        t0 = time.perf_counter()
        for ct in ciphertexts:
            channel.decrypt(ct)
        decrypt_time = time.perf_counter() - t0

        result = ThroughputResult(
            payload_size=size,
            iterations=n,
            encrypt_total_s=encrypt_time,
            decrypt_total_s=decrypt_time,
            total_bytes=total_bytes,
        )
        results.append(result)

        print(f"{size:>6}  {n:>6}  {result.encrypt_kbps:>8.0f}   {result.decrypt_kbps:>8.0f}")

    return results


def main():
    results = benchmark_throughput()

    # Summary
    print("\n" + "═" * 50)
    print("  THROUGHPUT SUMMARY")
    print("═" * 50)

    output = {
        "session_key_algorithm": "HKDF-SHA256",
        "cipher": "AES-256-GCM",
        "results": []
    }

    for r in results:
        output["results"].append({
            "payload_size": r.payload_size,
            "iterations": r.iterations,
            "encrypt_kbps": round(r.encrypt_kbps, 1),
            "decrypt_kbps": round(r.decrypt_kbps, 1),
            "overhead_percent": round(
                ((r.payload_size + 28) / r.payload_size - 1) * 100, 1
            ),  # 12 IV + 16 tag = 28 bytes overhead
        })
        print(f"  {r.payload_size:>6}B payload:  "
              f"encrypt {r.encrypt_kbps:>8.0f} KB/s  "
              f"decrypt {r.decrypt_kbps:>8.0f} KB/s")

    output_dir = os.path.join(os.path.dirname(__file__), "results")
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "throughput.json")

    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\nResults saved to: {output_path}")


if __name__ == "__main__":
    main()