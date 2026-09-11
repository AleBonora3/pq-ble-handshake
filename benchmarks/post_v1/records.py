"""Closed raw-result contract, provenance, derived measurements and safe output."""

from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import math
from pathlib import Path
import platform
import re
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = Path(__file__).with_name("schemas") / "run.schema.json"
SCENARIOS = {"v07_hybrid": "v07", "v10_cold": "v10", "v10_bonded": "v10"}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def new_id(scenario):
    return f"{scenario}-{datetime.now(timezone.utc):%Y%m%dT%H%M%S}-{uuid.uuid4().hex[:12]}"


def check_id(value):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,119}", value):
        raise ValueError("run_id must be a safe filename (letters/digits/hyphen/underscore)")
    return value


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def git(*args):
    result = subprocess.run(["git", *args], cwd=ROOT, text=True,
                            capture_output=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else None


def source_hash(directory):
    """Hash source inputs, including uncommitted files; exclude build products."""
    digest = hashlib.sha256()
    for path in sorted((ROOT / directory).rglob("*")):
        relative = path.relative_to(ROOT / directory)
        if not path.is_file() or any(p.startswith("build") or p == "__pycache__"
                                     for p in relative.parts):
            continue
        digest.update(relative.as_posix().encode())
        digest.update(bytes.fromhex(sha256(path)))
    return digest.hexdigest()


def provenance():
    return {"git_commit": git("rev-parse", "HEAD"),
            "git_tag": git("describe", "--tags", "--exact-match"),
            "branch": git("branch", "--show-current"),
            "git_dirty": bool(git("status", "--porcelain")),
            "central_source_sha256": source_hash("src"),
            "benchmark_source_sha256": source_hash("benchmarks/post_v1")}


def environment():
    def version(package):
        try:
            return importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            return None
    # Do not import oqs merely to inspect metadata (some wrappers auto-install).
    return {"central_os": platform.platform(), "python_version": platform.python_version(),
            "bleak_version": version("bleak"), "liboqs_python_version": version("liboqs-python"),
            "cryptography_version": version("cryptography"), "liboqs_version": None}


def write_json(path, value):
    """Exclusive creation: existing evidence is never replaced."""
    serialized = json.dumps(value, indent=2, allow_nan=False) + "\n"
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(serialized)


def validate_shape(value, spec, location="$root"):
    """Validate the JSON Schema vocabulary used by our bundled closed schema.

    No dependency is needed by the Central. The same schema can also be used
    by standard Draft 2020-12 validators. Unsupported keywords are not emitted.
    """
    types = {"object": dict, "array": list, "string": str, "boolean": bool,
             "integer": int, "number": (int, float), "null": type(None)}
    allowed = spec.get("type", list(types))
    allowed = [allowed] if isinstance(allowed, str) else allowed
    matched = any(isinstance(value, types[t]) and
                  not (isinstance(value, bool) and t in ("integer", "number")) for t in allowed)
    if not matched:
        raise ValueError(f"{location}: wrong type")
    if "enum" in spec and value not in spec["enum"]:
        raise ValueError(f"{location}: unknown value")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if not math.isfinite(value) or value < spec.get("minimum", -math.inf):
            raise ValueError(f"{location}: invalid number")
    if isinstance(value, str) and "pattern" in spec and not re.fullmatch(spec["pattern"], value):
        raise ValueError(f"{location}: invalid string")
    if isinstance(value, dict):
        if set(spec.get("required", [])) - value.keys():
            raise ValueError(f"{location}: missing fields")
        for key, item in value.items():
            child = spec.get("properties", {}).get(key, spec.get("additionalProperties", {}))
            if child is False:
                raise ValueError(f"{location}: unexpected field {key}")
            validate_shape(item, child, f"{location}.{key}")
    if isinstance(value, list):
        for item in value:
            validate_shape(item, spec["items"], f"{location}[]")


def validate(record):
    validate_shape(record, json.loads(SCHEMA.read_text(encoding="utf-8")))
    check_id(record["run_id"])
    if SCENARIOS[record["scenario"]] != record["protocol_profile"]:
        raise ValueError("profile/scenario mismatch")
    if record["firmware_profile"] != record["protocol_profile"]:
        raise ValueError("firmware/profile mismatch")
    if record["pcap_filename"] != record["run_id"] + ".pcapng":
        raise ValueError("PCAP must use the run_id")
    for row in record["phase_timings"] + record["gatt_operations"]:
        if row["end_ns"] < row["start_ns"]:
            raise ValueError("negative duration")
    if any(b["offset_ns"] < a["offset_ns"] for a, b in zip(record["events"], record["events"][1:])):
        raise ValueError("non-monotonic event order")
    if record["success"]:
        expected = record["scenario"].removeprefix("v10_") if record["protocol_profile"] == "v10" else "hybrid"
        if record["observed_scenario"] != expected or record["failure_reason"] is not None:
            raise ValueError("success with incompatible scenario/failure")
        if record["att_mtu"] != record["expected_mtu"] or not record["mtu_observations"]:
            raise ValueError("success without expected observed MTU")
        if any(r["value"] != record["att_mtu"] for r in record["mtu_observations"]):
            raise ValueError("MTU changed during run")
        if record["measurement_kind"] == "latency":
            if not any(r["name"] == "app_secure" for r in record["events"]):
                raise ValueError("success without APP_SECURE observation")
            if len(record["derived"]["application_rtt_ms"]) != record["workload"]["rounds"]:
                raise ValueError("missing authenticated application RTTs")
    if record["scenario"] == "v10_cold" and record["derived"]["secure_machine_ms"] is not None:
        raise ValueError("cold machine latency cannot exclude unobserved DK wait")
    if record["measurement_kind"] == "latency" and record["negative_result"] is not None:
        raise ValueError("negative evidence in a latency run")


def derived(recorder, scenario):
    """Only observed endpoints form durations; no absent sample becomes zero."""
    events = {}
    for row in recorder.events:
        events.setdefault(row["name"], []).append(row["offset_ns"])

    def delta(start, end):
        if start not in events or end not in events:
            return None
        return (events[end][0] - events[start][0]) / 1e6

    waits = [r for r in recorder.phase_timings if r["name"] == "interactive_wait"]
    wait_ms = sum((r["end_ns"] - r["start_ns"]) / 1e6 for r in waits if r["complete"])
    wait_ms = wait_ms if waits and all(r["complete"] for r in waits) else None
    wall = delta("connection_request", "app_secure")
    # PC confirmation doesn't capture the other endpoint's NC decision/wait.
    machine = wall if scenario == "v10_bonded" else (
        wall - wait_ms if scenario == "v07_hybrid" and wall is not None and wait_ms is not None else None)
    requests = events.get("application_request", [])
    responses = events.get("application_response_authenticated", [])
    rtts = [(end - start) / 1e6 for start, end in zip(requests, responses) if end >= start]
    return {"secure_wall_ms": wall, "secure_machine_ms": machine,
            "pc_interactive_wait_ms": wait_ms,
            "connection_to_l4_attested_ms": delta("connection_request", "security_ready_attested"),
            "start_to_ready_ms": delta("start_sent", "ready_received"),
            "finished_exchange_ms": delta("finished_c_sent", "finished_p_verified"),
            "application_rtt_ms": rtts}


def counters(operations):
    result = {}
    for row in operations:
        key = f"{row['operation']}_{row['characteristic']}"
        counts = result.setdefault(key, {"attempts": 0, "completed": 0, "completed_value_bytes": 0})
        counts["attempts"] += 1
        if row["success"]:
            counts["completed"] += 1
            counts["completed_value_bytes"] += row["value_bytes"] or 0
    return result
