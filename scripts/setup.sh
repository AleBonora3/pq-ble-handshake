#!/usr/bin/env bash
set -euo pipefail

echo "═══════════════════════════════════════════"
echo " PQ-BLE-HANDSHAKE — Setup Ambiente"
echo "═══════════════════════════════════════════"

# 1. Python dependencies
echo ""
echo "[1/4] Installazione dipendenze Python..."
pip install -r requirements.txt

# 2. liboqs (se non già installata)
if ! ldconfig -p 2>/dev/null | grep -q liboqs; then
    echo ""
    echo "[2/4] Compilazione liboqs..."
    if [ ! -d liboqs ]; then
        git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git liboqs
    fi
    cd liboqs
    mkdir -p build && cd build
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
    make -j"$(nproc)"
    sudo make install
    sudo ldconfig
    cd ../..
else
    echo ""
    echo "[2/4] liboqs già installata — skip"
fi

# 3. liboqs-python
echo ""
echo "[3/4] Installazione liboqs-python..."
if [ ! -d liboqs-python ]; then
    git clone --depth 1 https://github.com/open-quantum-safe/liboqs-python.git liboqs-python
fi
cd liboqs-python && pip install -e . && cd ..

# 4. Verifica
echo ""
echo "[4/4] Verifica installazione..."
python3 -c "
import oqs
kem = oqs.KeyEncapsulation('ML-KEM-768')
pk = kem.generate_keypair()
ct, ss1 = kem.encap_secret(pk)
ss2 = kem.decap_secret(ct)
assert ss1 == ss2, 'ML-KEM FAILED'
print('✅ ML-KEM-768 funzionante')
"

echo ""
echo "═══════════════════════════════════════════"
echo " Setup completato con successo!"
echo " Ora esegui: ./scripts/test_ble.sh"
echo "═══════════════════════════════════════════"
