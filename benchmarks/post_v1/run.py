"""Hardware campaign CLI using the frozen Central runners, one connection/run."""

import argparse
import asyncio
import json
import logging
from pathlib import Path
import sys

from src.central import measurement as measure
from .records import (SCENARIOS, check_id, counters, derived, environment, new_id,
                      provenance, sha256, utc_now, validate, write_json)

NEGATIVES = {
    "pre-l4-only": ("Both bonds deleted; no L4", "Four protected GATT access attempts", "All four denied for security reasons"),
    "nc-reject": ("Both bonds deleted; real Numeric Comparison", "Operator types no on PC", "Explicit NC rejection and closed GATT"),
    "sas-reject": ("v0.7 WAIT_FINISHED_C", "Existing explicit SAS rejection test", "FINISHED withheld and application write denied"),
    "finished-c": ("v0.7 SAS accepted", "Flip FINISHED_C bit", "Exact authentication error and pre-auth denial"),
    "pre-auth": ("v0.7 WAIT_FINISHED_C", "Application write before FINISHED", "Denied, then authenticated traffic succeeds"),
    "c2p-tamper": ("v0.7 authenticated session", "Flip transmitted application tag bit", "Exact error, original sequence still accepted"),
    "c2p-replay": ("v0.7 authenticated session", "Replay transmitted seq=0", "Exact replay error, no duplicate PONG"),
    "p2c-tamper": ("v0.7 authenticated session", "Mutate received copy locally", "Central rejects tag; receive counter unchanged"),
    "p2c-replay": ("v0.7 authenticated session", "Replay received copy locally", "Central rejects replay; receive counter unchanged"),
}


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--scenario", required=True, choices=SCENARIOS)
    p.add_argument("--metadata", required=True, type=Path)
    p.add_argument("--firmware-record", required=True, type=Path)
    p.add_argument("--iterations", type=int)
    p.add_argument("--warmup", type=int)
    p.add_argument("--output", type=Path, default=Path("benchmarks/results/post_v1"))
    p.add_argument("--run-id", help="Exact ID; only for one run with zero warm-up")
    p.add_argument("--expect-pcap", action="store_true", help="Pause before each run for manual capture")
    p.add_argument("--expected-mtu", type=int, default=247, help="Validate observed MTU; does not request MTU")
    p.add_argument("--negative", choices=NEGATIVES)
    p.add_argument("--device-name", default="PQ-BLE-Device")
    p.add_argument("--pairing-timeout", type=float, default=90.0)
    p.add_argument("--notification-timeout", type=float, default=10.0)
    return p


def parse_args(argv=None):
    p = parser()
    args = p.parse_args(argv)
    interactive = args.scenario == "v10_cold" or args.negative is not None
    args.iterations = args.iterations if args.iterations is not None else (1 if interactive else 30)
    args.warmup = args.warmup if args.warmup is not None else (0 if interactive else 3)
    if args.iterations < 1 or args.warmup < 0 or not 23 <= args.expected_mtu <= 517:
        p.error("invalid iterations, warmup or expected MTU")
    if args.pairing_timeout <= 0 or args.notification_timeout <= 0:
        p.error("timeouts must be positive")
    if args.run_id:
        check_id(args.run_id)
        if args.iterations != 1 or args.warmup != 0:
            p.error("--run-id requires --iterations 1 --warmup 0")
    if args.negative and ((args.negative in ("pre-l4-only", "nc-reject")) != (args.scenario == "v10_cold")):
        p.error("CP1 negatives require v10_cold; Phase 7 negatives require v07_hybrid")
    if args.negative and args.scenario == "v10_bonded":
        p.error("negative tests are separate from bonded latency runs")
    return args


class ScenarioMismatch(RuntimeError):
    """Observed Windows bond state differs from the requested population."""


class ScenarioBackend:
    """Check actual Windows bond state before the frozen runner can pair."""
    def __init__(self, backend, expected):
        self.backend, self.expected = backend, expected

    async def inspect_pairing(self, client):
        state = await self.backend.inspect_pairing(client)
        actual = "bonded" if state.is_paired else "cold"
        measure.scenario(actual)
        if actual != self.expected:
            raise ScenarioMismatch("scenario_mismatch")
        return state

    def __getattr__(self, name):
        return getattr(self.backend, name)


async def confirm_nc(pin):
    from src.central.winrt_pairing import read_console_line
    print(f"Numeric Comparison on PC: {pin}. Compare DK; confirm its BUTTON 0 only if equal.")
    measure.mark("auth_prompt_ready")
    with measure.phase("interactive_wait"):
        answer = await read_console_line("Do both values match? [y/N]: ")
    measure.mark("auth_decision_returned")
    return answer.strip().lower() in {"y", "yes"}


async def execute(client, args):
    if args.scenario == "v07_hybrid":
        from src.central.phase7_auth import run_phase7_authenticated_hybrid
        measure.scenario("hybrid")
        return await run_phase7_authenticated_hybrid(client,
            notification_timeout=args.notification_timeout, negative_test=args.negative)
    from src.central import winrt_pairing
    from src.central.v1_cp4 import run_v1_cp4
    from src.central.v1_smp_mlkem import run_v1_cp1
    runner = run_v1_cp1 if args.negative else run_v1_cp4
    return await runner(client, confirm_numeric_comparison=measure.bind_async(confirm_nc),
        pairing_backend=ScenarioBackend(winrt_pairing, args.scenario.removeprefix("v10_")),
        pairing_timeout=args.pairing_timeout, notification_timeout=args.notification_timeout,
        negative_test=args.negative)


def make_record(args, run_id, iteration, warmup, metadata, firmware):
    return {"schema_version": "1.0", "run_id": run_id, "timestamp": utc_now(),
        "provenance": provenance(), "environment": environment(), "experiment": metadata,
        "protocol_profile": SCENARIOS[args.scenario], "scenario": args.scenario,
        "observed_scenario": None, "peer_address": None, "firmware_profile": firmware["profile"],
        "resource_metadata": {"record": str(args.firmware_record.resolve()),
            "sha256": sha256(args.firmware_record), "elf_sha256": firmware["elf_sha256"],
            "firmware_source_sha256": firmware["firmware_source_sha256"],
            "ncs_version": firmware["ncs_version"], "zephyr_version": firmware["zephyr_version"],
            "config_sha256": firmware["config_sha256"]},
        "command": sys.argv, "iteration": iteration, "warmup": warmup,
        "measurement_kind": "negative" if args.negative else "latency",
        "success": False, "failure_reason": "not_started", "events": [],
        "phase_timings": [], "crypto_timings": [], "gatt_operations": [], "gatt_counters": {},
        "fragment_counters": {"ciphertext_write_attempts": 0, "ciphertext_write_completed": 0,
            "public_key_application_fragments": 0, "public_key_att_read_blob_count": None},
        "mtu_observations": [], "att_mtu": None, "expected_mtu": args.expected_mtu,
        "derived": {"secure_wall_ms": None, "secure_machine_ms": None,
            "pc_interactive_wait_ms": None, "connection_to_l4_attested_ms": None,
            "start_to_ready_ms": None, "finished_exchange_ms": None, "application_rtt_ms": []},
        "workload": {"rounds": 3 if args.scenario == "v07_hybrid" else 2,
            "payload_bytes_per_direction": 6 if args.scenario == "v07_hybrid" else 16,
            "frame_bytes_per_direction": 43 if args.scenario == "v07_hybrid" else 51},
        "pcap_filename": run_id + ".pcapng", "pcap_available": False,
        "pcap_expected": args.expect_pcap, "negative_result": None,
        "notes": ["DK crypto durations unavailable in frozen firmware.",
                  "Cold machine time is null: DK Numeric Comparison wait is not independently observable.",
                  "GATT counts are API observations, not ATT/LL packets; energy measurement not performed."]}


async def one_run(args, iteration, warmup, metadata, firmware, *, client_factory=None, runner=execute):
    from src.central.ble_client import BLECentralClient
    from src.central.phase7_auth import Phase7NegativeTestPassed
    from src.central.v1_smp_mlkem import V1NegativeTestPassed
    run_id = args.run_id or new_id(args.scenario)
    directory = args.output / "raw" / run_id
    directory.mkdir(parents=True, exist_ok=False)
    record = make_record(args, run_id, iteration, warmup, metadata, firmware)
    validate(record)
    write_json(directory / "pending.json", record)
    print(f"run_id={run_id}; warmup={warmup}; output={directory}", flush=True)
    if args.expect_pcap or args.scenario == "v10_cold":
        print(f"Capture filename: {args.output / 'pcaps' / record['pcap_filename']}", flush=True)
        if args.scenario == "v10_cold":
            print("Clear BOTH bonds before this run (DK BUTTON 3 while idle; Windows Remove device).")
        await asyncio.to_thread(input, "Prepare capture/bonds as applicable, then press Enter: ")
    client = (client_factory or BLECentralClient)(device_name=args.device_name)
    recorder = measure.Recorder()
    record["timestamp"] = utc_now()  # Wall-clock anchor immediately beside monotonic origin.
    log = logging.FileHandler(directory / "central.log", mode="x", encoding="utf-8")
    log.setFormatter(logging.Formatter(f"{run_id} %(asctime)s %(levelname)s %(message)s"))
    log.setLevel(logging.INFO)
    logging.getLogger().addHandler(log)
    interrupted = False
    try:
        with recorder.activate():
            measure.mark("run_start")
            try:
                if not await client.scan_and_connect():
                    record["failure_reason"] = "device_not_found"
                    raise RuntimeError("device_not_found")
                record["peer_address"] = getattr(client, "address", None)
                if client.mtu_size != args.expected_mtu:
                    record["failure_reason"] = "mtu_mismatch"
                    raise RuntimeError("mtu_mismatch")
                # Real execution imports oqs; querying its version now cannot add an import side effect.
                await runner(client, args)
                if args.negative:
                    raise RuntimeError("negative_test_returned_positive")
                record["success"], record["failure_reason"] = True, None
            except (Phase7NegativeTestPassed, V1NegativeTestPassed):
                if args.negative is None:
                    raise
                record["success"], record["failure_reason"] = True, None
            except BaseException as exc:
                if record["failure_reason"] == "not_started":
                    record["failure_reason"] = type(exc).__name__  # No exception payloads/locals.
                interrupted = isinstance(exc, (KeyboardInterrupt, asyncio.CancelledError))
            finally:
                try:
                    await client.disconnect()
                except Exception:
                    record["success"], record["failure_reason"] = False, "disconnect_failed"
                measure.mark("run_end")
    finally:
        logging.getLogger().removeHandler(log)
        log.close()
    record.update(events=recorder.events, phase_timings=recorder.phase_timings,
                  gatt_operations=recorder.gatt_operations, mtu_observations=recorder.mtu_observations,
                  observed_scenario=recorder.observed_scenario)
    mtus = {row["value"] for row in recorder.mtu_observations}
    record["att_mtu"] = next(iter(mtus)) if len(mtus) == 1 else None
    if mtus != {args.expected_mtu} and (record["success"] or mtus):
        record["success"], record["failure_reason"] = False, "mtu_missing_or_changed"
    record["derived"] = derived(recorder, args.scenario)
    record["gatt_counters"] = counters(recorder.gatt_operations)
    ciphertext = record["gatt_counters"].get("write_ciphertext", {})
    record["fragment_counters"].update(ciphertext_write_attempts=ciphertext.get("attempts", 0),
                                      ciphertext_write_completed=ciphertext.get("completed", 0))
    oqs = sys.modules.get("oqs")
    if oqs is not None and hasattr(oqs, "oqs_version"):
        record["environment"]["liboqs_version"] = oqs.oqs_version()
    record["pcap_available"] = (args.output / "pcaps" / record["pcap_filename"]).is_file()
    if args.negative:
        precondition, fault, expected = NEGATIVES[args.negative]
        record["negative_result"] = {"test_name": args.negative, "precondition": precondition,
            "injected_fault": fault, "expected_behavior": expected,
            "observed_behavior": "Existing runner verified expected rejection" if record["success"] else "Required evidence not established",
            "verdict": "PASS" if record["success"] else "FAIL",
            "session_invalidated": None, "keys_cleared": None,
            "traffic_rejected": True if record["success"] else None,
            "reconnect_needed": None, "log": "central.log"}
    validate(record)
    write_json(directory / "run.json", record)
    print(f"{run_id}: {'PASS' if record['success'] else 'FAIL'}; {directory / 'run.json'}", flush=True)
    if interrupted:
        raise asyncio.CancelledError
    return record


async def campaign(args):
    metadata = json.loads(args.metadata.read_text(encoding="utf-8"))
    firmware = json.loads(args.firmware_record.read_text(encoding="utf-8"))
    if firmware["profile"] != SCENARIOS[args.scenario] or firmware.get("build_success") is not True:
        raise ValueError("firmware record must identify a successful build of the selected profile")
    if metadata.get("firmware_flashed_elf_sha256") != firmware["elf_sha256"]:
        raise ValueError("operator must identify the flashed ELF hash from this firmware record")
    if any("REPLACE_" in str(value) or "TEMPLATE ONLY" in str(value) for value in metadata.values()):
        raise ValueError("complete the experiment metadata template before collecting")
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "pcaps").mkdir(exist_ok=True)
    # Validate metadata before opening any radio connection.
    validate(make_record(args, args.run_id or new_id(args.scenario), 1, False, metadata, firmware))
    for index in range(args.warmup + args.iterations):
        row = await one_run(args, index + 1 if index < args.warmup else index - args.warmup + 1,
                            index < args.warmup, metadata, firmware)
        if not row["success"]:
            return 1  # Keep failure, stop so stale bonds/MTU never contaminate repetitions.
    return 0


def main(argv=None):
    args = parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        return asyncio.run(campaign(args))
    except (KeyboardInterrupt, asyncio.CancelledError):
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
