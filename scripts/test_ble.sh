#!/usr/bin/env bash
set -euo pipefail

echo "═══════════════════════════════════════════"
echo " PQ-BLE-HANDSHAKE — Test Hardware BLE"
echo "═══════════════════════════════════════════"

# 1. Verifica interfacce BLE
echo ""
echo "[1/3] Interfacce BLE disponibili:"
hcitool dev 2>/dev/null || echo "⚠️  hcitool non trovato. Installa: sudo apt install bluez"

# 2. Verifica BLE adapter
echo ""
echo "[2/3] Stato adattatori BLE:"
for dev in $(hciconfig 2>/dev/null | grep -oP 'hci\d+'); do
    echo "  $dev: $(hciconfig $dev | grep 'UP\|DOWN')"
done

# 3. Test scan BLE con bleak
echo ""
echo "[3/3] Test scan BLE con bleak (5 secondi)..."
python3 -c "
import asyncio
from bleak import BleakScanner

async def scan():
    print('  Scansione in corso...')
    devices = await BleakScanner.discover(timeout=5.0)
    if devices:
        print(f'  ✅ Trovati {len(devices)} dispositivi BLE:')
        for d in devices:
            name = d.name or '(senza nome)'
            print(f'     • {name} — {d.address} (RSSI: {d.rssi})')
    else:
        print('  ⚠️  Nessun dispositivo trovato (normale se non ci sono BLE in zona)')
        print('  ✅ Lo scan funziona comunque!')

asyncio.run(scan())
"

echo ""
echo "═══════════════════════════════════════════"
echo " Test hardware BLE completato."
echo " Se vedi dispositivi, il BLE funziona."
echo "═══════════════════════════════════════════"