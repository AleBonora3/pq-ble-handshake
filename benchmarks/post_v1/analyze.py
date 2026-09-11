"""Aggregate raw hardware runs without pooling different conditions or rounds."""

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import statistics

from .records import validate, write_json, utc_now


def percentile(values, fraction):
    if not values or not 0 <= fraction <= 1:
        raise ValueError("percentile requires samples and fraction in [0, 1]")
    return sorted(values)[max(0, math.ceil(fraction * len(values)) - 1)]


def stats(values):
    if not values:
        return {"n": 0, **{key: None for key in ("mean", "median", "stddev", "min", "max", "p95", "p25", "p75", "iqr")}}
    if any(not math.isfinite(x) or x < 0 for x in values):
        raise ValueError("invalid statistical sample")
    return {"n": len(values), "mean": statistics.mean(values), "median": statistics.median(values),
        "stddev": statistics.stdev(values) if len(values) > 1 else None,
        "min": min(values), "max": max(values), "p95": percentile(values, .95),
        "p25": percentile(values, .25), "p75": percentile(values, .75),
        "iqr": percentile(values, .75) - percentile(values, .25)}


def conditions(record):
    return {key: record[key] for key in ("scenario", "protocol_profile", "firmware_profile",
        "provenance", "environment", "experiment", "workload", "att_mtu", "resource_metadata",
        "pcap_expected")}


def metrics(record):
    values = {key: value for key, value in record["derived"].items() if key != "application_rtt_ms"}
    # Each run is the independent sample. Preserve round identity; do not pretend
    # two correlated RTTs in one connection are two independent handshake runs.
    for index, value in enumerate(record["derived"]["application_rtt_ms"]):
        values[f"application_rtt_round_{index}_ms"] = value
    phases = {}
    for row in record["phase_timings"]:
        if row["complete"]:
            phases.setdefault(row["name"], []).append((row["end_ns"] - row["start_ns"]) / 1e6)
    for name, samples in phases.items():
        values[f"{name}_sum_ms"] = sum(samples)
    for name, counter in record["gatt_counters"].items():
        for field, value in counter.items():
            values[f"api_{name}_{field}"] = value
    return values


def aggregate(records):
    groups, seen = {}, set()
    excluded = {"warmup": [], "failed": [], "negative": []}
    for row in records:
        validate(row)
        if row["run_id"] in seen:
            raise ValueError("duplicate run_id")
        seen.add(row["run_id"])
        reason = "negative" if row["measurement_kind"] == "negative" else (
            "warmup" if row["warmup"] else "failed" if not row["success"] else None)
        if reason:
            excluded[reason].append(row["run_id"])
            continue
        cond = conditions(row)
        key = hashlib.sha256(json.dumps(cond, sort_keys=True).encode()).hexdigest()[:16]
        group = groups.setdefault(key, {"conditions": cond, "run_ids": [], "samples": {}})
        group["run_ids"].append(row["run_id"])
        for name, value in metrics(row).items():
            group["samples"].setdefault(name, [])
            if value is not None:
                group["samples"][name].append(value)
    for group in groups.values():
        group["metrics"] = {name: stats(samples) for name, samples in group.pop("samples").items()}
        for value in group["metrics"].values():
            value["missing_runs"] = len(group["run_ids"]) - value["n"]
    return {"schema_version": "1.0", "generated_at": utc_now(), "groups": groups,
        "excluded": excluded, "statistics": "nearest-rank percentiles; sample stddev (null for n<2)",
        "limitations": ["Conditions define separate strata; no automatic cross-profile ranking.",
            "Different frozen application workloads are not a matched payload comparison.",
            "Missing values are measurement pending; failures/warm-ups/negatives are excluded."]}


def write_summary(output, summary):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    write_json(output / "summary.json", summary)
    fields = ["group", "scenario", "metric", "n", "missing_runs", "mean", "median", "stddev", "min", "max", "p95", "p25", "p75", "iqr"]
    lines = ["# Post-v1.0 experimental summary", "", summary["statistics"], "",
        "Groups with different experimental conditions remain separate. Raw run IDs are in summary.json.", "",
        "| Group / scenario | Metric | n | Missing | Mean | Median | SD | Min | Max | p95 |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    with (output / "summary.csv").open("x", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for group_id, group in summary["groups"].items():
            scenario = group["conditions"]["scenario"]
            for name, value in sorted(group["metrics"].items()):
                writer.writerow(dict(group=group_id, scenario=scenario, metric=name, **value))
                cells = [f"{group_id} / {scenario}", name, str(value["n"]), str(value["missing_runs"])]
                cells += ["measurement pending" if value[k] is None else f"{value[k]:.3f}"
                          for k in ("mean", "median", "stddev", "min", "max", "p95")]
                lines.append("| " + " | ".join(cells) + " |")
    if not summary["groups"]:
        lines += ["", "measurement pending"]
    lines += ["", "Excluded runs: " + json.dumps(summary["excluded"]), "", *summary["limitations"]]
    with (output / "summary.md").open("x", encoding="utf-8") as stream:
        stream.write("\n".join(lines) + "\n")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("raw", type=Path)
    p.add_argument("--output", required=True, type=Path, help="New directory; never overwritten")
    args = p.parse_args(argv)
    files = sorted(args.raw.rglob("run.json"))
    records = [json.loads(path.read_text(encoding="utf-8")) for path in files]
    summary = aggregate(records)
    summary["input_files"] = [str(path.resolve()) for path in files]
    write_summary(args.output, summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
