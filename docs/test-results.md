# Test Results

Output reale della suite di test. Generato con:

```bash
python -m pytest tests/ -v | tee docs/test-results.txt
```

## Placeholder

Esegui il comando sopra nella VM Ubuntu per popolare questo file con i risultati reali.

I risultati attesi: **109 passed** su 109 test.

Copertura:
- `test_ml_kem.py` — 6 test: dimensioni corrette pk/ct/ss, roundtrip encaps/decaps, 100 iterazioni
- `test_fragmentation.py` — 14 test: frammenti singoli/multipli, riordino, missing, duplicati, MTU variabili
- `test_sas.py` — 12 test: range 0-999999, determinismo, sensibilità, distribuzione
- `test_session.py` — 22 test: HKDF, AES-GCM roundtrip, AAD direction separation, replay detection, out-of-order rejection, session binding, msg_type binding, tampering, IV uniqueness
- `test_session_store.py` — 23 test: session ID, resume, store, expiry, re-handshake
- `test_handshake_mock.py` — 2 test: pipeline completa con AAD, ruoli e msg_type, 100 iterazioni
- `test_mitm_simulation.py` — 2 test: MITM simulato, SAS mismatch rilevato
- `test_firmware_uuids.py` — 11 test: UUID firmware ↔ Python, device name, SMP disabled, bt_gatt_notify
- `test_central_transport_mock.py` — 17 test: fragmented read/write con mock GATT, header validation, reassembly, MTU variabili