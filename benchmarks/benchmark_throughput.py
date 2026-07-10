#!/usr/bin/env python3
"""Benchmark CPU del SecureChannel AES-256-GCM; non misura il link BLE."""

from __future__ import annotations

import argparse
import json
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from src.common.constants import CENTRAL_ROLE, PERIPHERAL_ROLE
from src.common.session import SecureChannel, derive_session_key, generate_session_id

RESULTS_DIR = Path(__file__).resolve().parent / "results"
WIRE_OVERHEAD_BYTES = 8 + 1 + 12 + 16  # seq + msg_type + IV + GCM tag


def kbps(total_plaintext_bytes: int, elapsed_seconds: float) -> float:
    return (total_plaintext_bytes / 1024) / elapsed_seconds


def one_trial(payload: bytes, iterations: int) -> tuple[float, float]:
    key = derive_session_key(b"PQ-BLE throughput benchmark shared secret")
    session_id = generate_session_id()

    sender = SecureChannel(key, session_id=session_id, role=CENTRAL_ROLE)
    start = time.perf_counter_ns()
    for _ in range(iterations):
        sender.encrypt(payload)
    encrypt_seconds = (time.perf_counter_ns() - start) / 1_000_000_000

    sender = SecureChannel(key, session_id=session_id, role=CENTRAL_ROLE)
    receiver = SecureChannel(key, session_id=session_id, role=PERIPHERAL_ROLE)
    ciphertexts = [sender.encrypt(payload) for _ in range(iterations)]

    start = time.perf_counter_ns()
    for ciphertext in ciphertexts:
        if receiver.decrypt(ciphertext) != payload:
            raise RuntimeError("AES-GCM decrypt mismatch")
    decrypt_seconds = (time.perf_counter_ns() - start) / 1_000_000_000

    total_bytes = len(payload) * iterations
    return (
        kbps(total_bytes, encrypt_seconds),
        kbps(total_bytes, decrypt_seconds),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=5)
    args = parser.parse_args()
    if args.trials <= 0:
        raise ValueError("trials must be > 0")

    sizes = [64, 256, 512, 1024, 4096, 16384]
    iterations_map = {
        64: 5000,
        256: 3000,
        512: 2000,
        1024: 1000,
        4096: 500,
        16384: 200,
    }

    print("PQ-BLE-HANDSHAKE — AES-256-GCM CPU Throughput")
    print("Scope: SecureChannel CPU only; BLE radio/GATT excluded.")
    print(f"Trials per payload: {args.trials}")
    print(f"Wire overhead: {WIRE_OVERHEAD_BYTES} bytes/message")
    print()
    print(
        f"{'Payload':>9} {'Iters':>8} "
        f"{'Enc mean':>12} {'Dec mean':>12} {'Overhead':>10}"
    )
    print("-" * 60)

    rows = []
    for size in sizes:
        payload = b"x" * size
        iterations = iterations_map[size]

        # Warm-up excluded from measurements.
        one_trial(payload, min(100, iterations))

        encrypt_values = []
        decrypt_values = []
        for _ in range(args.trials):
            enc, dec = one_trial(payload, iterations)
            encrypt_values.append(enc)
            decrypt_values.append(dec)

        overhead_percent = WIRE_OVERHEAD_BYTES / size * 100
        row = {
            "payload_size_bytes": size,
            "wire_size_bytes": size + WIRE_OVERHEAD_BYTES,
            "wire_overhead_bytes": WIRE_OVERHEAD_BYTES,
            "wire_overhead_percent": overhead_percent,
            "iterations_per_trial": iterations,
            "trials": args.trials,
            "encrypt_kbps": {
                "mean": statistics.mean(encrypt_values),
                "median": statistics.median(encrypt_values),
                "stddev": statistics.stdev(encrypt_values)
                if len(encrypt_values) > 1
                else 0.0,
            },
            "decrypt_kbps": {
                "mean": statistics.mean(decrypt_values),
                "median": statistics.median(decrypt_values),
                "stddev": statistics.stdev(decrypt_values)
                if len(decrypt_values) > 1
                else 0.0,
            },
        }
        rows.append(row)

        print(
            f"{size:>7} B {iterations:>8} "
            f"{row['encrypt_kbps']['mean']:>10.0f} KB/s "
            f"{row['decrypt_kbps']['mean']:>10.0f} KB/s "
            f"{overhead_percent:>8.1f}%"
        )

    result = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "cipher": "AES-256-GCM",
        "aad": "session_id || sender_role || seq_num || msg_type",
        "wire_format": (
            "seq_num(8) || msg_type(1) || iv(12) || ciphertext || tag(16)"
        ),
        "wire_overhead_bytes": WIRE_OVERHEAD_BYTES,
        "measurement_scope": "CPU SecureChannel throughput; BLE excluded",
        "results": rows,
    }

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    output = RESULTS_DIR / "throughput.json"
    output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"\nJSON saved to: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
