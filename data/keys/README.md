# Chiavi di test per PQ-BLE-HANDSHAKE

## ⚠️ IMPORTANTE

**Queste chiavi sono per TEST ESCLUSIVAMENTE.**

Non usare mai chiavi hardcoded in produzione.
Ogni sessione del protocollo PQ-BLE-HANDSHAKE genera
chiavi ML-KEM-768 effimere (distrutte dopo l'uso).
Questo garantisce forward secrecy.

## Uso

Questa directory contiene chiavi di test per:
- Unit test deterministici
- Benchmark ripetibili
- Sviluppo e debug

Le chiavi reali vengono generate a runtime da `src/common/ml_kem.py`
e **mai** salvate su disco.