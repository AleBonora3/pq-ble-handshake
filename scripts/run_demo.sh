#!/usr/bin/env bash
# Launch both central and peripheral for a complete demo.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_DIR"

echo "═══════════════════════════════════════════"
echo " PQ-BLE-HANDSHAKE — Full Demo"
echo "═══════════════════════════════════════════"
echo ""
echo "Avvio del peripheral (SPERIMENTALE, Linux-only) in background..."
echo "Avvio del central in questo terminale..."
echo ""
echo "⚠️  Questo script usa il peripheral Python (BleakServer, sperimentale)."
echo "    Per la demo reale: flash firmware Zephyr su nRF54L15 DK."
echo "    Vedi README.md > 'Real hardware demo'."

# Start peripheral in background
PYTHONPATH=. python3 -m experimental.peripheral.main &
PERIPHERAL_PID=$!

# Give the peripheral time to start advertising
sleep 3

# Start central (foreground)
python3 -m src.central.main --device PQ-BLE-Device --log-level DEBUG

# Cleanup
kill $PERIPHERAL_PID 2>/dev/null || true
wait $PERIPHERAL_PID 2>/dev/null || true

echo ""
echo "Demo completata."