"""Synthetic software fixtures only. These are never campaign measurements."""

import asyncio
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from benchmarks.post_v1 import analyze, pcap, records, resources, run
from src.central import measurement as measure


@pytest.fixture
def record(tmp_path, monkeypatch):
    monkeypatch.setattr(run, "provenance", lambda: dict(git_commit="a" * 40, git_tag=None,
        branch="test", git_dirty=True, central_source_sha256="b" * 64, benchmark_source_sha256="c" * 64))
    firmware_path = tmp_path / "resources.json"
    firmware_path.write_text("{}")
    args = run.parse_args(["--scenario", "v10_bonded", "--metadata", str(tmp_path / "metadata.json"),
        "--firmware-record", str(firmware_path), "--iterations", "1", "--warmup", "0"])
    metadata = json.loads((records.ROOT / "benchmarks/post_v1/experiment.example.json").read_text())
    firmware = dict(profile="v10", elf_sha256="f" * 64, firmware_source_sha256="d" * 64,
                    ncs_version="test SDK", zephyr_version="test Zephyr", config_sha256="e" * 64)
    row = run.make_record(args, "fixture-bonded-001", 1, False, metadata, firmware)
    row.update(success=True, failure_reason=None, observed_scenario="bonded", att_mtu=247,
        mtu_observations=[{"offset_ns": 0, "value": 247}],
        events=[{"name": name, "offset_ns": t} for name, t in (
            ("run_start", 0), ("connection_request", 1000), ("app_secure", 2000),
            ("application_request", 3000), ("application_response_authenticated", 4000),
            ("application_request", 5000), ("application_response_authenticated", 6000), ("run_end", 7000))])
    row["derived"]["application_rtt_ms"] = [1.0, 2.0]
    records.validate(row)
    return row


def test_serialization_and_no_overwrite(record, tmp_path):
    path = tmp_path / "run.json"
    records.write_json(path, record)
    assert json.loads(path.read_text()) == record
    with pytest.raises(FileExistsError): records.write_json(path, {})
    assert json.loads(path.read_text()) == record


@pytest.mark.parametrize("key", ["SS_MLKEM", "SS_ECDH", "secret_key", "private_key", "ltk", "dhkey", "application_key", "finished_key"])
def test_secret_field_exclusion(record, key):
    record[key] = "must never be exported"
    with pytest.raises(ValueError, match="unexpected field"): records.validate(record)


@pytest.mark.parametrize("mutate", [
    lambda r: r["environment"].update(secret="bad"),
    lambda r: r.update(protocol_profile="v07"),
    lambda r: r.update(firmware_profile="v07"),
    lambda r: r.update(observed_scenario="cold"),
    lambda r: r.update(pcap_filename="another-run.pcapng"),
    lambda r: r.update(att_mtu=512),
    lambda r: r["derived"].update(secure_wall_ms=float("nan")),
    lambda r: r["derived"].update(application_rtt_ms=[1]),
    lambda r: r["mtu_observations"].append({"offset_ns": 2, "value": 512}),
    lambda r: r.update(events=[]),
    lambda r: r.update(iteration=True),
    lambda r: r.update(phase_timings=[dict(name="scan", start_ns=10, end_ns=1, complete=True)]),
])
def test_schema_and_timing_validation(record, mutate):
    mutate(record)
    with pytest.raises(ValueError): records.validate(record)


def test_partial_failure_is_valid(record):
    record.update(success=False, failure_reason="TimeoutError", events=[], observed_scenario=None,
                  att_mtu=None, mtu_observations=[])
    record["derived"]["application_rtt_ms"] = []
    records.validate(record)


def test_cold_cannot_claim_machine_time(record):
    record.update(scenario="v10_cold", observed_scenario="cold")
    record["derived"]["secure_machine_ms"] = 1
    with pytest.raises(ValueError, match="cold machine"): records.validate(record)


def test_ids_unique_and_path_safe():
    assert len({records.new_id("v10_bonded") for _ in range(200)}) == 200
    for value in ("../bad", "a/b", "", "x.pcapng", "a\\b"):
        with pytest.raises(ValueError): records.check_id(value)


def test_statistics_nearest_rank_and_sample_sd():
    s = analyze.stats([1, 2, 3, 4])
    assert s == dict(n=4, mean=2.5, median=2.5, stddev=pytest.approx(1.2909944487),
                     min=1, max=4, p95=4, p25=1, p75=3, iqr=2)
    assert analyze.stats([1])["stddev"] is None
    assert analyze.stats([])["mean"] is None
    assert analyze.percentile(list(range(1, 101)), .95) == 95
    for values in ([float("inf")], [-1]):
        with pytest.raises(ValueError): analyze.stats(values)
    with pytest.raises(ValueError): analyze.percentile([], .95)


def test_aggregation_strata_failures_warmups_missing_and_duplicates(record, tmp_path):
    rows = [deepcopy(record) for _ in range(5)]
    for index, row in enumerate(rows):
        row["run_id"] = f"fixture-{index}"
        row["pcap_filename"] = row["run_id"] + ".pcapng"
    rows[1]["warmup"] = True
    rows[2].update(success=False, failure_reason="TimeoutError")
    rows[3]["measurement_kind"] = "negative"
    rows[4]["experiment"]["location"] = "different location"
    summary = analyze.aggregate(rows)
    assert len(summary["groups"]) == 2
    assert summary["excluded"] == {"warmup": ["fixture-1"], "failed": ["fixture-2"], "negative": ["fixture-3"]}
    group = next(iter(summary["groups"].values()))
    assert group["metrics"]["secure_machine_ms"]["n"] == 0
    assert group["metrics"]["secure_machine_ms"]["missing_runs"] == 1
    assert group["metrics"]["application_rtt_round_0_ms"]["n"] == 1
    with pytest.raises(ValueError, match="duplicate"): analyze.aggregate([record, record])
    analyze.write_summary(tmp_path / "summary", summary)
    assert {p.name for p in (tmp_path / "summary").iterdir()} == {"summary.json", "summary.csv", "summary.md"}
    assert "measurement pending" in (tmp_path / "summary/summary.md").read_text()
    with pytest.raises(FileExistsError): analyze.write_summary(tmp_path / "summary", summary)


def test_empty_summary_pending(tmp_path):
    analyze.write_summary(tmp_path / "summary", analyze.aggregate([]))
    assert "measurement pending" in (tmp_path / "summary/summary.md").read_text()


def test_recorder_context_failure_and_human_separation():
    ticks = iter([0, 100, 300, 800, 900])
    recorder = measure.Recorder(clock=lambda: next(ticks))
    with recorder.activate():
        measure.mark("connection_request")
        with pytest.raises(RuntimeError):
            with measure.phase("scan"):
                raise RuntimeError("secret exception payload")
        measure.mark("app_secure")
    measure.mark("outside_context")
    assert len(recorder.events) == 2
    assert recorder.phase_timings == [dict(name="scan", start_ns=300, end_ns=800, complete=False)]
    assert "secret" not in repr(recorder.__dict__)
    recorder.phase_timings = [dict(name="interactive_wait", start_ns=200, end_ns=400, complete=True)]
    assert records.derived(recorder, "v07_hybrid")["secure_machine_ms"] == pytest.approx(.0006)
    assert records.derived(recorder, "v10_cold")["secure_machine_ms"] is None


@pytest.mark.asyncio
async def test_io_counts_failures_and_never_payloads():
    recorder = measure.Recorder()
    async def denied(): raise ValueError("secret payload")
    with recorder.activate():
        with pytest.raises(ValueError): await measure.io("write", "control", denied(), 40)
        assert await measure.io("read", "public_key", AsyncMock(return_value=b"sensitive")()) == b"sensitive"
    counts = records.counters(recorder.gatt_operations)
    assert counts["write_control"] == dict(attempts=1, completed=0, completed_value_bytes=0)
    assert counts["read_public_key"]["completed_value_bytes"] == 9
    assert "sensitive" not in json.dumps(recorder.gatt_operations)


@pytest.mark.asyncio
async def test_notification_callback_preserves_async_and_thread_context():
    recorder = measure.Recorder()
    seen = []
    with recorder.activate():
        callback = measure.notification_callback(lambda sender, data: seen.append(data))
        async_callback = measure.notification_callback(AsyncMock())
    await asyncio.to_thread(callback, 1, b"abc")
    await async_callback(1, b"defg")
    assert seen == [b"abc"]
    assert [r["value_bytes"] for r in recorder.gatt_operations] == [3, 4]
    callback = lambda *args: None
    assert measure.notification_callback(callback) is callback


@pytest.mark.asyncio
async def test_pairing_callback_retains_recorder_outside_original_context():
    recorder = measure.Recorder()
    async def decision(pin):
        with measure.phase("interactive_wait"):
            await asyncio.sleep(0)
        return False
    with recorder.activate():
        callback = measure.bind_async(decision)
    assert await callback("123456") is False
    assert recorder.phase_timings[0]["complete"]
    assert measure.bind_async(decision) is decision


@pytest.mark.asyncio
async def test_real_transport_counts_logical_fragments():
    from tests.test_central_transport_mock import _make_central_with_mock
    client, raw = _make_central_with_mock(mtu=247)
    recorder = measure.Recorder()
    with recorder.activate():
        public_key = await client.read_fragmented_public_key()
        count = await client.write_fragmented_ciphertext(bytes(1088))
    counts = records.counters(recorder.gatt_operations)
    assert len(public_key) == 1184 and count == 5
    assert counts["write_ciphertext"] == dict(attempts=5, completed=5, completed_value_bytes=1108)
    assert counts["read_public_key"]["attempts"] == 1  # Hidden Read Blob count is not inferred.


@pytest.mark.parametrize("argv", [
    ["--iterations", "0"], ["--warmup", "-1"], ["--expected-mtu", "1"],
    ["--run-id", "one", "--iterations", "2"], ["--negative", "nc-reject"],
    ["--negative", "c2p-tamper"], ["--pairing-timeout", "0"],
])
def test_cli_invalid(argv):
    with pytest.raises(SystemExit):
        run.parse_args(["--scenario", "v10_bonded", "--metadata", "m.json", "--firmware-record", "f.json", *argv])


def test_cli_defaults_and_positive_has_no_auth_bypass():
    for scenario, count, warmup in [("v10_bonded", 30, 3), ("v10_cold", 1, 0), ("v07_hybrid", 30, 3)]:
        args = run.parse_args(["--scenario", scenario, "--metadata", "m", "--firmware-record", "f"])
        assert (args.iterations, args.warmup) == (count, warmup)
    with pytest.raises(SystemExit):
        run.parse_args(["--scenario", "v07_hybrid", "--metadata", "m", "--firmware-record", "f", "--no-sas-confirm"])


@pytest.mark.asyncio
async def test_bond_classification_before_pairing():
    backend = SimpleNamespace(inspect_pairing=AsyncMock(return_value=SimpleNamespace(is_paired=False)),
                              pair_numeric_comparison=AsyncMock())
    with pytest.raises(RuntimeError, match="scenario_mismatch"):
        await run.ScenarioBackend(backend, "bonded").inspect_pairing(object())
    backend.pair_numeric_comparison.assert_not_called()


@pytest.mark.asyncio
async def test_nc_confirmation_requires_explicit_answer(monkeypatch):
    from src.central import winrt_pairing
    for answer, expected in [("", False), ("no", False), ("yes", True)]:
        monkeypatch.setattr(winrt_pairing, "read_console_line", AsyncMock(return_value=answer))
        recorder = measure.Recorder()
        with recorder.activate():
            assert await run.confirm_nc("123456") is expected
        assert recorder.phase_timings[0]["name"] == "interactive_wait"


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig", "utf-16"])
def test_resource_memory_log_encodings(tmp_path, encoding):
    path = tmp_path / "build.log"
    path.write_text("FLASH: 279428 B 1420 KB 19.22%\n RAM: 107 KB 188 KB 56.86%\n", encoding=encoding)
    assert resources.parse_memory_report(resources.read_build_log(path)) == dict(flash_bytes=279428, ram_bytes=109568)


def test_resource_sections_and_missing_reports():
    text = """  [ 2] text PROGBITS 00000480 000580 039180 00 AX 0 0 8
  [23] datas PROGBITS 20000040 0436c8 000a13 00 WA 0 0 8
  [44] bss NOBITS 20000df8 044488 006454 00 WA 0 0 8
"""
    assert resources.parse_sections(text)["text_bytes"] == 0x39180
    assert resources.parse_sections(text)["data_bytes"] == 0xa13
    for parser in (resources.parse_sections, resources.parse_memory_report):
        with pytest.raises(ValueError): parser("not a build report")


def test_stack_watermark_and_static_symbols():
    text = "Estimated cumulative crypto-thread peak (configured - unused): 24264 B\n"
    assert resources.parse_stack_log(text)["max_observed_bytes"] == 24264
    assert resources.parse_stack_log("")["max_observed_bytes"] is None
    symbols = resources.parse_symbols("0000032 0000040 b sample_buffer\n0000012 0000004 T function\n")
    assert symbols == [dict(symbol="sample_buffer", bytes=40, type="b")]


def test_pcap_parser_layer_names_and_missing_fields():
    packets = pcap.parse_tsv("1\t1000.125\t72\t72\t51\t1\tnordic_ble:btle:btatt\n2\t1000.130\t24\t24\t\t\tnordic_ble:btle\n")
    summary = pcap.summarize_packets(packets)
    assert summary["observed_packet_count"] == 2
    assert summary["capture_record_bytes"] == 96
    assert summary["ll_data_payload_length_sum"] == 51
    assert summary["packets_with_ll_data_length"] == 1
    assert packets[1]["nordic_direction_flag"] is None
    assert "energy" not in summary and "airtime" not in summary
    assert pcap.summarize_packets([])["ll_data_payload_length_sum"] is None
    assert pcap.parse_tsv("1\t0\t20\t20\t0\tTrue\tbtle")[0]["nordic_direction_flag"] == 1
    assert pcap.parse_tsv("1\t0\t20\t20\t0\tFalse\tbtle")[0]["nordic_direction_flag"] == 0


def test_inactive_mtu_observer_does_not_read_backend():
    class Backend:
        @property
        def mtu_size(self):
            raise AssertionError("unexpected property access")
    measure.observe_mtu(Backend())


@pytest.mark.parametrize("text", ["bad\trow", "1\tnan\t1\t1\t1\t1\tbtle", "1\t0\t1\t1\t1\t3\tbtle", "1\t0\t1\t1\t999\t1\tbtle"])
def test_pcap_rejects_bad_metadata(text):
    with pytest.raises(ValueError): pcap.parse_tsv(text)


def test_pcap_correlation_filter_and_tools(record, tmp_path, monkeypatch):
    path = tmp_path / record["pcap_filename"]
    path.write_bytes(b"fixture only; mocked TShark")
    calls = []
    def tool(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(stdout="TShark fixture\n" if "--version" in command else "1\t0\t20\t20\t0\t0\tbtle\n")
    monkeypatch.setattr(pcap.subprocess, "run", tool)
    result = pcap.analyze(record, path, tshark="tshark", address="0x12345678", window="full", clock_offset=0)
    assert result["run_id"] == record["run_id"] and result["capture_sha256"] == records.sha256(path)
    assert "-Y" in calls[1] and "-x" not in calls[1]
    assert result["summary"]["observed_packet_count"] == 1
    with pytest.raises(ValueError): pcap.analyze(record, tmp_path / "wrong.pcapng", tshark="tshark", address="0x12345678", window="full", clock_offset=0)
    with pytest.raises(ValueError): pcap.display_filter("0x8e89bed6", 0, 1)
    with pytest.raises(ValueError): pcap.display_filter("0x12345678 || btatt", 0, 1)
    record["events"] = []
    record["success"] = False
    with pytest.raises(ValueError): pcap.capture_window(record, "handshake", 0)


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["success", "failure", "cancel"])
async def test_campaign_raw_run_and_cleanup(record, tmp_path, monkeypatch, outcome):
    args = run.parse_args(["--scenario", "v10_bonded", "--metadata", "unused", "--firmware-record", "unused",
                          "--iterations", "1", "--warmup", "0", "--output", str(tmp_path)])
    row = deepcopy(record)
    row.update(success=False, observed_scenario=None, failure_reason="not_started", events=[], mtu_observations=[], att_mtu=None)
    row["derived"]["application_rtt_ms"] = []
    monkeypatch.setattr(run, "make_record", lambda *a: deepcopy(row))
    monkeypatch.setattr(run, "new_id", lambda *a: record["run_id"])
    class Client:
        mtu_size = 247
        disconnected = False
        def __init__(self, **kwargs): pass
        async def scan_and_connect(self):
            measure.mark("connection_request")
            measure.mtu(247)
            return True
        async def disconnect(self): Client.disconnected = True
    async def runner(client, args):
        measure.scenario("bonded")
        if outcome == "cancel": raise asyncio.CancelledError
        if outcome == "failure": raise ValueError("MUST_NOT_SERIALIZE_SECRET")
        measure.mark("app_secure")
        for _ in range(2):
            measure.mark("application_request")
            measure.mark("application_response_authenticated")
    if outcome == "cancel":
        with pytest.raises(asyncio.CancelledError):
            await run.one_run(args, 1, False, {}, {}, client_factory=Client, runner=runner)
    else:
        await run.one_run(args, 1, False, {}, {}, client_factory=Client, runner=runner)
    assert Client.disconnected
    path = tmp_path / "raw" / record["run_id"] / "run.json"
    saved = json.loads(path.read_text())
    assert saved["success"] == (outcome == "success")
    assert "MUST_NOT_SERIALIZE_SECRET" not in path.read_text()
    assert (path.parent / "pending.json").exists()


def test_v1_existing_protocol_with_instrumentation():
    from src.common.ml_kem import generate_keypair
    from tests.test_v1_cp4 import CP4Client, run_client
    client = CP4Client(generate_keypair())
    recorder = measure.Recorder()
    with recorder.activate():
        result = run_client(client)
    assert result.authenticated_rounds == 2 and result.app_secure
    assert len(records.derived(recorder, "v10_bonded")["application_rtt_ms"]) == 2
    assert recorder.observed_scenario == "bonded"
    assert {r["name"] for r in recorder.phase_timings} >= {"mlkem_encapsulate", "finished_p_verify_app_kdf"}


def test_v07_existing_protocol_with_instrumentation():
    from src.common.ml_kem import generate_keypair
    from src.central.phase7_auth import run_phase7_authenticated_hybrid
    from tests.test_phase7_cp4 import CP4MockClient
    client = CP4MockClient(generate_keypair())
    recorder = measure.Recorder()
    with recorder.activate():
        result = asyncio.run(run_phase7_authenticated_hybrid(client, sas_callback=lambda _: True))
    assert result.rounds == 3
    assert len(records.derived(recorder, "v07_hybrid")["application_rtt_ms"]) == 3
    assert {r["name"] for r in recorder.phase_timings} >= {"p256_ecdh", "hybrid_hkdf", "interactive_wait",
        "finished_c_generate", "finished_p_expected_generate", "sas_compute_format", "finished_p_verify", "application_traffic_kdf"}


@pytest.mark.skipif(sys.platform != "win32", reason="Windows PowerShell helper")
def test_uart_helper_refuses_overwriting_evidence_before_opening_port(tmp_path):
    path = tmp_path / "existing.log"
    path.write_text("preserve this evidence")
    result = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
        str(records.ROOT / "scripts/capture_v1_cp3_uart.ps1"), "-Log", str(path), "-Port", "COM999", "-Seconds", "1"],
        capture_output=True, check=False)
    assert result.returncode != 0
    assert path.read_text() == "preserve this evidence"


@pytest.mark.skipif(sys.platform != "win32" or not Path("C:/ncs/toolchains/0b393f9e1b/environment.json").exists(),
                    reason="Windows NCS helper")
def test_build_helper_rejects_outside_firmware_before_building(tmp_path):
    target = tmp_path / "build_forbidden"
    result = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
        str(records.ROOT / "scripts/build_v1_cp3.ps1"), "-BuildDirectory", str(target),
        "-LogDirectory", str(tmp_path / "logs")], capture_output=True, check=False)
    assert result.returncode != 0 and not target.exists()
    assert not (tmp_path / "logs").exists()
