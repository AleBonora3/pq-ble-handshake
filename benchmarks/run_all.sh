#!/usr/bin/env bash
# Run all benchmarks and collect results.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "═══════════════════════════════════════════"
echo " PQ-BLE-HANDSHAKE — Benchmark Suite"
echo "═══════════════════════════════════════════"

# Ensure results directory
mkdir -p "$SCRIPT_DIR/results"

cd "$PROJECT_DIR"
export PYTHONPATH="$PROJECT_DIR"

echo ""
echo "[1/3] Handshake Latency Benchmark (100 iterations)..."
python3 "$SCRIPT_DIR/benchmark_handshake.py"

echo ""
echo "[2/3] Throughput Benchmark..."
python3 "$SCRIPT_DIR/benchmark_throughput.py"

echo ""
echo "[3/3] Fragmentation Overhead Benchmark..."
python3 "$SCRIPT_DIR/benchmark_fragmentation.py"

echo ""
echo "═══════════════════════════════════════════"
echo " All benchmarks complete."
echo " Results saved to: benchmarks/results/"
echo "═══════════════════════════════════════════"
ls -la "$SCRIPT_DIR/results/"