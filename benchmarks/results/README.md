# Benchmarks Results

Placeholder directory per gli output reali dei benchmark.

## Come generare

Nella VM Ubuntu:

```bash
cd pq-ble-handshake
source venv/bin/activate

# Benchmark handshake crittografico (100 iterazioni)
PYTHONPATH=. python benchmarks/benchmark_handshake.py | tee benchmarks/results/handshake.txt

# Benchmark throughput AES-GCM
PYTHONPATH=. python benchmarks/benchmark_throughput.py | tee benchmarks/results/throughput.txt

# Benchmark frammentazione
PYTHONPATH=. python benchmarks/benchmark_fragmentation.py | tee benchmarks/results/fragmentation.txt

# Tutti insieme
bash benchmarks/run_all.sh | tee benchmarks/results/latest.txt
```

## Output attesi

| File | Contenuto |
|---|---|
| `handshake.txt` | Latenza keygen, encaps, decaps, SAS, HKDF in µs (100 iterazioni) |
| `throughput.txt` | Throughput AES-256-GCM a varie dimensioni payload |
| `fragmentation.txt` | Overhead frammentazione per diverse dimensioni dati |
| `latest.txt` | Output completo di `run_all.sh` |