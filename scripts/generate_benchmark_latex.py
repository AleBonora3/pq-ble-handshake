#!/usr/bin/env python3
"""Genera report/benchmark_values.tex dagli artefatti JSON dei benchmark."""

from __future__ import annotations

import argparse
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_RESULTS_DIR = ROOT_DIR / "benchmarks" / "results"
DEFAULT_OUTPUT_FILE = ROOT_DIR / "report" / "benchmark_values.tex"

# Permette di importare src.* anche quando lo script viene eseguito direttamente.
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

try:
    from src.common.constants import (
        CT_SIZE,
        FRAGMENT_HEADER_SIZE,
        PK_SIZE,
        RESUME_OK_NOTIFY,
        SECURE_CHANNEL_OVERHEAD,
        SESSION_ID_SIZE,
        SK_SIZE,
        SS_SIZE,
    )
    from src.common.session import build_resume_request
except ImportError as exc:  # pragma: no cover - errore di ambiente
    raise SystemExit(
        "Impossibile importare i moduli del progetto. "
        "Esegui lo script dalla repository con il virtual environment attivo.\n"
        f"Dettaglio: {exc}"
    ) from exc


class BenchmarkDataError(RuntimeError):
    """Errore nei file JSON o nelle invarianti dei benchmark."""


def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise BenchmarkDataError(f"File richiesto non trovato: {path}")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BenchmarkDataError(
            f"JSON non valido in {path}: riga {exc.lineno}, colonna {exc.colno}"
        ) from exc

    if not isinstance(data, dict):
        raise BenchmarkDataError(f"La radice JSON di {path} deve essere un oggetto")
    return data


def require_mapping(container: dict[str, Any], key: str, context: str) -> dict[str, Any]:
    value = container.get(key)
    if not isinstance(value, dict):
        raise BenchmarkDataError(f"Campo '{key}' mancante o non valido in {context}")
    return value


def require_list(container: dict[str, Any], key: str, context: str) -> list[Any]:
    value = container.get(key)
    if not isinstance(value, list):
        raise BenchmarkDataError(f"Campo '{key}' mancante o non valido in {context}")
    return value


def require_number(container: dict[str, Any], key: str, context: str) -> float:
    value = container.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BenchmarkDataError(f"Campo numerico '{key}' mancante o non valido in {context}")
    value = float(value)
    if not math.isfinite(value):
        raise BenchmarkDataError(f"Campo '{key}' non finito in {context}")
    return value


def require_int(container: dict[str, Any], key: str, context: str) -> int:
    value = require_number(container, key, context)
    if not value.is_integer():
        raise BenchmarkDataError(f"Campo '{key}' deve essere intero in {context}")
    return int(value)


def parse_utc_timestamp(value: Any, context: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise BenchmarkDataError(f"generated_at_utc mancante o non valido in {context}")

    normalized = value.strip().replace("Z", "+00:00")
    try:
        timestamp = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise BenchmarkDataError(
            f"Timestamp ISO-8601 non valido in {context}: {value!r}"
        ) from exc

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc)


def format_italian_datetime(timestamp: datetime) -> str:
    months = (
        "gennaio",
        "febbraio",
        "marzo",
        "aprile",
        "maggio",
        "giugno",
        "luglio",
        "agosto",
        "settembre",
        "ottobre",
        "novembre",
        "dicembre",
    )
    return (
        f"{timestamp.day} {months[timestamp.month - 1]} {timestamp.year}, "
        f"ore {timestamp:%H:%M} UTC"
    )


def format_number(value: float, decimals: int, *, group_thousands: bool = False) -> str:
    if not math.isfinite(float(value)):
        raise BenchmarkDataError(f"Valore numerico non finito: {value}")

    if group_thousands:
        formatted = f"{float(value):,.{decimals}f}"
        integer_part, separator, decimal_part = formatted.partition(".")
        integer_part = integer_part.replace(",", r"\,")
    else:
        formatted = f"{float(value):.{decimals}f}"
        integer_part, separator, decimal_part = formatted.partition(".")

    if decimals == 0:
        return integer_part
    return f"{integer_part},{decimal_part}"


def format_integer(value: int, *, group_thousands: bool = False) -> str:
    if group_thousands:
        return f"{value:,}".replace(",", r"\,")
    return str(value)


def statistic(block: dict[str, Any], name: str, context: str) -> float:
    return require_number(block, name, context)


def throughput_mean(row: dict[str, Any], key: str, context: str) -> float:
    value = row.get(key)
    if isinstance(value, dict):
        return require_number(value, "mean", f"{context}.{key}")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BenchmarkDataError(f"Campo '{key}' non valido in {context}")
    return float(value)


def index_throughput_rows(data: dict[str, Any]) -> dict[int, dict[str, Any]]:
    rows = require_list(data, "results", "throughput.json")
    indexed: dict[int, dict[str, Any]] = {}

    for index, raw_row in enumerate(rows):
        context = f"throughput.json.results[{index}]"
        if not isinstance(raw_row, dict):
            raise BenchmarkDataError(f"Riga non valida in {context}")
        size = require_int(raw_row, "payload_size_bytes", context)
        if size in indexed:
            raise BenchmarkDataError(f"Payload duplicato nel throughput: {size} byte")
        indexed[size] = raw_row

    required_sizes = (64, 256, 512, 1024, 4096, 16384)
    missing = [size for size in required_sizes if size not in indexed]
    if missing:
        raise BenchmarkDataError(
            "Payload mancanti in throughput.json: " + ", ".join(map(str, missing))
        )
    return indexed


def extract_fragment_row(
    data: dict[str, Any], logical_size: int
) -> tuple[dict[str, Any], str]:
    # Nuovo schema introdotto dal benchmark aggiornato.
    groups = data.get("logical_fragment_sizes")
    group_name = "logical_fragment_sizes"

    # Compatibilità con gli artefatti precedenti.
    if not isinstance(groups, dict):
        groups = data.get("mtus")
        group_name = "mtus"

    if not isinstance(groups, dict):
        raise BenchmarkDataError(
            "fragmentation_overhead.json non contiene "
            "'logical_fragment_sizes' né il vecchio campo 'mtus'"
        )

    raw_group = groups.get(str(logical_size))
    context = f"fragmentation_overhead.json.{group_name}.{logical_size}"
    if not isinstance(raw_group, dict):
        raise BenchmarkDataError(f"Configurazione {logical_size} mancante in {context}")

    # Il nuovo/vecchio benchmark può contenere un dizionario di righe nominate.
    candidates: list[tuple[str, dict[str, Any]]] = []
    for name, value in raw_group.items():
        if isinstance(value, dict):
            candidates.append((name, value))

    # In alternativa accetta direttamente la riga come oggetto.
    if not candidates and "raw_bytes" in raw_group:
        candidates.append(("ciphertext", raw_group))

    for name, row in candidates:
        raw_bytes = row.get("raw_bytes")
        if raw_bytes == CT_SIZE or "ciphertext" in name.lower():
            return row, f"{context}.{name}"

    raise BenchmarkDataError(
        f"Riga del ciphertext ML-KEM-768 non trovata in {context}"
    )


def latex_command(name: str, value: str) -> str:
    return rf"\renewcommand{{\{name}}}{{{value}}}"


def generate_latex(
    handshake: dict[str, Any],
    throughput: dict[str, Any],
    fragmentation: dict[str, Any],
) -> str:
    timestamps = [
        parse_utc_timestamp(handshake.get("generated_at_utc"), "handshake_latency.json"),
        parse_utc_timestamp(throughput.get("generated_at_utc"), "throughput.json"),
        parse_utc_timestamp(
            fragmentation.get("generated_at_utc"),
            "fragmentation_overhead.json",
        ),
    ]
    generated_at = format_italian_datetime(max(timestamps))

    crypto_iterations = require_int(
        handshake, "measured_iterations", "handshake_latency.json"
    )
    phases = require_mapping(handshake, "phases_us", "handshake_latency.json")
    total_ms = require_mapping(handshake, "total_ms", "handshake_latency.json")

    keygen = require_mapping(phases, "keygen", "handshake_latency.json.phases_us")
    encaps = require_mapping(phases, "encaps", "handshake_latency.json.phases_us")
    decaps = require_mapping(phases, "decaps", "handshake_latency.json.phases_us")
    sas = require_mapping(
        phases, "sas_derivation", "handshake_latency.json.phases_us"
    )
    hkdf = require_mapping(
        phases, "hkdf_derivation", "handshake_latency.json.phases_us"
    )

    handshake_rate = require_number(
        handshake,
        "handshakes_per_second_from_mean",
        "handshake_latency.json",
    )

    throughput_rows = index_throughput_rows(throughput)
    throughput_overhead = require_int(
        throughput, "wire_overhead_bytes", "throughput.json"
    )
    if throughput_overhead != SECURE_CHANNEL_OVERHEAD:
        raise BenchmarkDataError(
            "Overhead SecureChannel incoerente: "
            f"JSON={throughput_overhead}, costante={SECURE_CHANNEL_OVERHEAD}"
        )

    trial_values = {
        require_int(row, "trials", f"throughput payload {size}")
        for size, row in throughput_rows.items()
        if "trials" in row
    }
    if len(trial_values) > 1:
        raise BenchmarkDataError(
            f"Numero di trial non uniforme in throughput.json: {sorted(trial_values)}"
        )
    throughput_trials = next(iter(trial_values), 5)

    for size, row in throughput_rows.items():
        context = f"throughput payload {size}"
        wire_size = require_int(row, "wire_size_bytes", context)
        row_overhead = require_int(row, "wire_overhead_bytes", context)
        if row_overhead != throughput_overhead or wire_size != size + throughput_overhead:
            raise BenchmarkDataError(
                f"Wire format incoerente per payload {size}: "
                f"wire={wire_size}, overhead={row_overhead}"
            )

    frag_iterations = require_int(
        fragmentation, "cpu_iterations", "fragmentation_overhead.json"
    )
    frag_header = int(
        fragmentation.get("fragment_header_bytes", FRAGMENT_HEADER_SIZE)
    )
    if frag_header != FRAGMENT_HEADER_SIZE:
        raise BenchmarkDataError(
            "Header di frammentazione incoerente: "
            f"JSON={frag_header}, costante={FRAGMENT_HEADER_SIZE}"
        )

    frag_247, frag_247_context = extract_fragment_row(fragmentation, 247)
    frag_512, frag_512_context = extract_fragment_row(fragmentation, 512)

    def parse_fragment_row(
        row: dict[str, Any], context: str, logical_size: int
    ) -> dict[str, float | int]:
        parsed: dict[str, float | int] = {
            "raw": require_int(row, "raw_bytes", context),
            "wire": require_int(row, "wire_bytes", context),
            "payload": require_int(row, "fragment_payload_bytes", context),
            "count": require_int(row, "num_fragments", context),
            "overhead": require_int(row, "overhead_bytes", context),
            "overhead_pct": require_number(row, "overhead_percent", context),
            "frag_us": require_number(row, "fragmentation_mean_us", context),
            "reasm_us": require_number(row, "reassembly_mean_us", context),
        }
        row_logical_size = int(row.get("logical_fragment_size_bytes", logical_size))

        if parsed["raw"] != CT_SIZE:
            raise BenchmarkDataError(
                f"Dimensione ciphertext inattesa in {context}: {parsed['raw']}"
            )
        if row_logical_size != logical_size:
            raise BenchmarkDataError(
                f"Logical fragment size incoerente in {context}: {row_logical_size}"
            )
        if parsed["payload"] != logical_size - frag_header:
            raise BenchmarkDataError(
                f"Payload per frammento incoerente in {context}: {parsed['payload']}"
            )
        expected_wire = int(parsed["raw"]) + int(parsed["count"]) * frag_header
        if parsed["wire"] != expected_wire:
            raise BenchmarkDataError(
                f"Wire size incoerente in {context}: "
                f"{parsed['wire']} != {expected_wire}"
            )
        if parsed["overhead"] != int(parsed["count"]) * frag_header:
            raise BenchmarkDataError(f"Overhead incoerente in {context}")
        return parsed

    f247 = parse_fragment_row(frag_247, frag_247_context, 247)
    f512 = parse_fragment_row(frag_512, frag_512_context, 512)

    public_key = fragmentation.get("public_key")
    if isinstance(public_key, dict):
        pk_transport = str(public_key.get("transport", "ATT Long Read / Read Blob"))
    else:
        pk_transport = "ATT Long Read / Read Blob"

    full_handshake_app_bytes = PK_SIZE + int(f247["wire"])
    kem_exchange_bytes = PK_SIZE + CT_SIZE

    resume_request_bytes = len(build_resume_request(bytes(SESSION_ID_SIZE)))
    resume_response_bytes = len(RESUME_OK_NOTIFY)
    resume_exchange_bytes = resume_request_bytes + resume_response_bytes

    payload_macro_names = {
        64: ("SixtyFour", "SixtyFourPct"),
        256: ("TwoFiftySix", "TwoFiftySixPct"),
        512: ("FiveTwelve", "FiveTwelvePct"),
        1024: ("OneK", "OneKPct"),
        4096: ("FourK", "FourKPct"),
        16384: ("SixteenK", "SixteenKPct"),
    }

    lines = [
        "% =========================================================",
        "% RISULTATI BENCHMARK REALI",
        "% Generato automaticamente dagli artefatti JSON in benchmarks/results/",
        "% Non modificare manualmente: eseguire scripts/generate_benchmark_latex.py",
        "% =========================================================",
        "",
        r"\benchmarkdatatrue",
        "",
        latex_command("BenchGeneratedAt", generated_at),
        "",
        "% Configurazioni dei diversi benchmark",
        latex_command("BenchIterations", str(crypto_iterations)),
        latex_command("BenchCryptoIterations", str(crypto_iterations)),
        latex_command("BenchThroughputTrials", str(throughput_trials)),
        latex_command("BenchFragIterations", str(frag_iterations)),
        "",
        "% ML-KEM-768 / SAS / HKDF: tempi in microsecondi",
        latex_command("BenchKeygenMean", format_number(statistic(keygen, "mean", "keygen"), 2)),
        latex_command("BenchKeygenMedian", format_number(statistic(keygen, "median", "keygen"), 2)),
        latex_command("BenchKeygenPnn", format_number(statistic(keygen, "p99", "keygen"), 2)),
        "",
        latex_command("BenchEncapsMean", format_number(statistic(encaps, "mean", "encaps"), 2)),
        latex_command("BenchEncapsMedian", format_number(statistic(encaps, "median", "encaps"), 2)),
        latex_command("BenchEncapsPnn", format_number(statistic(encaps, "p99", "encaps"), 2)),
        "",
        latex_command("BenchDecapsMean", format_number(statistic(decaps, "mean", "decaps"), 2)),
        latex_command("BenchDecapsMedian", format_number(statistic(decaps, "median", "decaps"), 2)),
        latex_command("BenchDecapsPnn", format_number(statistic(decaps, "p99", "decaps"), 2)),
        "",
        latex_command("BenchSasMean", format_number(statistic(sas, "mean", "sas"), 2)),
        latex_command("BenchSasMedian", format_number(statistic(sas, "median", "sas"), 2)),
        latex_command("BenchSasPnn", format_number(statistic(sas, "p99", "sas"), 2)),
        "",
        latex_command("BenchHkdfMean", format_number(statistic(hkdf, "mean", "hkdf"), 2)),
        latex_command("BenchHkdfMedian", format_number(statistic(hkdf, "median", "hkdf"), 2)),
        latex_command("BenchHkdfPnn", format_number(statistic(hkdf, "p99", "hkdf"), 2)),
        "",
        "% Totale crittografico in millisecondi",
        latex_command("BenchTotalMeanMs", format_number(statistic(total_ms, "mean", "total_ms"), 4)),
        latex_command("BenchTotalMedianMs", format_number(statistic(total_ms, "median", "total_ms"), 4)),
        latex_command("BenchTotalPnnMs", format_number(statistic(total_ms, "p99", "total_ms"), 4)),
        latex_command("BenchHandshakeRate", format_number(handshake_rate, 1, group_thousands=True)),
        "",
        "% Dimensioni del materiale crittografico ML-KEM-768",
        latex_command("BenchPkBytes", format_integer(PK_SIZE)),
        latex_command("BenchSkBytes", format_integer(SK_SIZE)),
        latex_command("BenchCtBytes", format_integer(CT_SIZE)),
        latex_command("BenchSsBytes", format_integer(SS_SIZE)),
        latex_command("BenchKemExchangeBytes", format_integer(kem_exchange_bytes)),
        "",
        "% Throughput AES-256-GCM in KiB/s",
        latex_command("BenchWireOverheadBytes", format_integer(throughput_overhead)),
        "",
    ]

    for size in (64, 256, 512, 1024, 4096, 16384):
        base_name, pct_name = payload_macro_names[size]
        row = throughput_rows[size]
        context = f"throughput payload {size}"
        lines.extend(
            [
                latex_command(
                    f"BenchEnc{base_name}",
                    format_number(
                        throughput_mean(row, "encrypt_kbps", context),
                        0,
                        group_thousands=True,
                    ),
                ),
                latex_command(
                    f"BenchDec{base_name}",
                    format_number(
                        throughput_mean(row, "decrypt_kbps", context),
                        0,
                        group_thousands=True,
                    ),
                ),
                latex_command(
                    f"BenchWire{base_name}",
                    format_integer(require_int(row, "wire_size_bytes", context)),
                ),
                latex_command(
                    f"BenchOverhead{pct_name}",
                    format_number(
                        require_number(row, "wire_overhead_percent", context), 2
                    ),
                ),
                "",
            ]
        )

    lines.extend(
        [
            "% =========================================================",
            "% FRAMMENTAZIONE APPLICATIVA DEL CIPHERTEXT ML-KEM-768",
            "% =========================================================",
            latex_command("BenchFragHeaderBytes", format_integer(frag_header)),
            "",
            "% Configurazione usata nel PoC validato",
            latex_command("BenchFragTwoFourSevenLogicalSize", "247"),
            latex_command("BenchFragTwoFourSevenPayload", format_integer(int(f247["payload"]))),
            latex_command("BenchFragTwoFourSevenCount", format_integer(int(f247["count"]))),
            latex_command("BenchFragTwoFourSevenWireBytes", format_integer(int(f247["wire"]))),
            latex_command("BenchFragTwoFourSevenOverheadBytes", format_integer(int(f247["overhead"]))),
            latex_command("BenchFragTwoFourSevenOverheadPct", format_number(float(f247["overhead_pct"]), 2)),
            latex_command("BenchFragMtuTwoFourSevenUs", format_number(float(f247["frag_us"]), 2)),
            latex_command("BenchReasmMtuTwoFourSevenUs", format_number(float(f247["reasm_us"]), 2)),
            "",
            "% Configurazione di confronto",
            latex_command("BenchFragFiveTwelveLogicalSize", "512"),
            latex_command("BenchFragFiveTwelvePayload", format_integer(int(f512["payload"]))),
            latex_command("BenchFragFiveTwelveCount", format_integer(int(f512["count"]))),
            latex_command("BenchFragFiveTwelveWireBytes", format_integer(int(f512["wire"]))),
            latex_command("BenchFragFiveTwelveOverheadBytes", format_integer(int(f512["overhead"]))),
            latex_command("BenchFragFiveTwelveOverheadPct", format_number(float(f512["overhead_pct"]), 2)),
            latex_command("BenchFragMtuFiveTwelveUs", format_number(float(f512["frag_us"]), 2)),
            latex_command("BenchReasmMtuFiveTwelveUs", format_number(float(f512["reasm_us"]), 2)),
            "",
            "% Public key trasportata tramite ATT Long Read / Read Blob",
            latex_command("BenchPkTransport", pk_transport),
            latex_command("BenchFullHandshakeAppBytes", format_integer(full_handshake_app_bytes)),
            "",
            "% =========================================================",
            "% SESSION RESUMPTION LATO PYTHON",
            "% =========================================================",
            latex_command("BenchResumeRequestBytes", format_integer(resume_request_bytes)),
            latex_command("BenchResumeResponseBytes", format_integer(resume_response_bytes)),
            latex_command("BenchResumeExchangeBytes", format_integer(resume_exchange_bytes)),
            "",
        ]
    )

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Genera report/benchmark_values.tex dai risultati JSON "
            "di handshake, throughput e frammentazione."
        )
    )
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=DEFAULT_RESULTS_DIR,
        help=f"Directory dei JSON (default: {DEFAULT_RESULTS_DIR})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_FILE,
        help=f"File LaTeX di output (default: {DEFAULT_OUTPUT_FILE})",
    )
    args = parser.parse_args()

    results_dir = args.results_dir.resolve()
    output_file = args.output.resolve()

    try:
        handshake = load_json(results_dir / "handshake_latency.json")
        throughput = load_json(results_dir / "throughput.json")
        fragmentation = load_json(results_dir / "fragmentation_overhead.json")
        latex_content = generate_latex(handshake, throughput, fragmentation)
    except BenchmarkDataError as exc:
        print(f"ERRORE: {exc}", file=sys.stderr)
        return 1

    output_file.parent.mkdir(parents=True, exist_ok=True)
    temporary_file = output_file.with_suffix(output_file.suffix + ".tmp")
    temporary_file.write_text(latex_content, encoding="utf-8", newline="\n")
    temporary_file.replace(output_file)

    print(f"Benchmark LaTeX generato: {output_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())