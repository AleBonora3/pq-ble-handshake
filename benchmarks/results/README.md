# Benchmark results

Questa directory contiene risultati misurati sulla macchina descritta in
`environment.txt`.

## Esecuzione Windows PowerShell

Dalla root della repository, con il virtual environment attivo:

```powershell
.\benchmarks\run_all.ps1
```

La configurazione predefinita usa:

- 1000 handshake crittografici misurati;
- 20 iterazioni di warm-up;
- 5 trial per dimensione nel benchmark AES-GCM;
- 10000 iterazioni per la frammentazione/riassemblaggio CPU.

Controllo rapido:

```powershell
.\benchmarks\run_all.ps1 `
    -HandshakeIterations 100 `
    -HandshakeWarmup 10 `
    -ThroughputTrials 2 `
    -FragmentationIterations 1000
```

## File generati

| File | Contenuto |
|---|---|
| `environment.txt` | Commit Git, Python, OS, CPU, RAM e dipendenze |
| `handshake.txt` | Output ML-KEM/SAS/HKDF |
| `handshake_latency.json` | Statistiche strutturate della latenza |
| `throughput.txt` | Output throughput CPU AES-256-GCM |
| `throughput.json` | Risultati strutturati per payload |
| `fragmentation.txt` | MTU 247 e 512, overhead e tempi CPU |
| `fragmentation_overhead.json` | Risultati strutturati |
| `latest.txt` | Ambiente e output aggregato |

## Interpretazione

Il benchmark handshake esclude scan BLE, connessione e trasferimenti GATT.

Il benchmark throughput misura il `SecureChannel` AES-256-GCM sulla CPU del
PC, non il throughput radio BLE.

Il benchmark di frammentazione confronta l'MTU 247 osservato nella demo reale
con l'MTU 512 di confronto. Nel demo hardware la public key usa ATT Long
Read/Read Blob; la relativa riga di frammentazione applicativa è teorica.
