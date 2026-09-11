"""Fresh profile builds and actual Zephyr/ELF resource reports (no estimates)."""

import argparse
import json
from pathlib import Path
import re
import subprocess

from .records import ROOT, new_id, provenance, sha256, source_hash, utc_now, write_json


def read_build_log(path):
    raw = Path(path).read_bytes()
    return raw.decode("utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig")


def parse_memory_report(text):
    result = {}
    for region, used, unit in re.findall(r"^\s*(FLASH|RAM):\s+(\d+)\s+(B|KB|MB)\b", text, re.M):
        result[region.lower() + "_bytes"] = int(used) * {"B": 1, "KB": 1024, "MB": 1024 ** 2}[unit]
    if set(result) != {"flash_bytes", "ram_bytes"}:
        raise ValueError("build log has no complete FLASH/RAM report")
    return result


def parse_sections(text):
    sections = {}
    for name, kind, size in re.findall(
            r"^\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)\b", text, re.M):
        sections[name] = {"bytes": int(size, 16), "type": kind}
    if not sections:
        raise ValueError("no ELF sections")
    aliases = {"text": (".text", "text"), "data": (".data", "datas", "data"), "bss": (".bss", "bss")}
    selected = {key + "_bytes": next((sections[n]["bytes"] for n in names if n in sections), None)
                for key, names in aliases.items()}
    if any(v is None for v in selected.values()):
        raise ValueError("required text/data/bss sections absent")
    return {"sections": sections, **selected}


def parse_symbols(text):
    symbols = []
    for line in text.splitlines():
        match = re.fullmatch(r"\s*\d+\s+(\d+)\s+([bBdD])\s+(\S+)\s*", line)
        if match:
            size, kind, name = match.groups()
            symbols.append({"symbol": name, "bytes": int(size), "type": kind})
    return sorted(symbols, key=lambda r: (-r["bytes"], r["symbol"]))[:30]


def parse_stack_log(text):
    """Cumulative since boot; never claim a per-handshake stack peak."""
    values = [int(v) for v in re.findall(r"Estimated cumulative crypto-thread peak\s*\(configured - unused\): (\d+) B", text)]
    return {"cumulative_peak_samples_bytes": values, "max_observed_bytes": max(values) if values else None,
            "scope": "Cumulative worker watermark since boot, including startup/self-tests; not per-session"}


def collect(build_dir, build_log, profile, toolchain):
    zephyr = Path(build_dir) / "firmware" / "zephyr"
    config = (zephyr / ".config").read_text(encoding="utf-8")
    expected = "CONFIG_PQ_PROFILE_V07_HYBRID=y" if profile == "v07" else "CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM=y"
    if expected not in config:
        raise ValueError("built profile does not match requested profile")
    if profile == "v07" and "CONFIG_BT_SMP=y" in config:
        raise ValueError("unexpected SMP in v0.7")
    if profile == "v10" and "CONFIG_BT_SMP_SC_ONLY=y" not in config:
        raise ValueError("v1.0 SC-only setting absent")
    stack = re.search(r"^CONFIG_PQ_MLKEM_THREAD_STACK_SIZE=(\d+)$", config, re.M)
    if stack is None:
        raise ValueError("worker stack configuration missing")
    nm = Path(toolchain) / "opt/zephyr-sdk/arm-zephyr-eabi/bin/arm-zephyr-eabi-nm.exe"
    command = [str(nm), "--print-size", "--size-sort", "--radix=d", str(zephyr / "zephyr.elf")]
    symbols = subprocess.run(command, capture_output=True, text=True, check=True)
    return {**parse_memory_report(read_build_log(build_log)),
        **parse_sections((zephyr / "zephyr.stat").read_text(encoding="utf-8")),
        "significant_static_symbols": parse_symbols(symbols.stdout), "nm_command": command,
        "worker_stack_allocated_bytes": int(stack[1]), "worker_stack_peak_bytes": None,
        "elf_sha256": sha256(zephyr / "zephyr.elf"), "config_sha256": sha256(zephyr / ".config"),
        "merged_hex_sha256": sha256(Path(build_dir) / "merged.hex"),
        "map_sha256": sha256(zephyr / "zephyr.map"),
        "build_directory": str(Path(build_dir).resolve()), "build_log": str(Path(build_log).resolve())}


def build(args):
    build_id = new_id("resources")
    output = args.output / build_id
    output.mkdir(parents=True, exist_ok=False)
    source_before = source_hash("firmware")
    start_provenance = provenance()
    records = []
    for profile in ("v07", "v10") if args.profile == "both" else (args.profile,):
        directory = ROOT / "firmware" / f"build_{build_id}_{profile}"
        if directory.exists():
            raise FileExistsError(directory)
        log_dir = output / profile
        log_dir.mkdir()
        helper_profile = "v1" if profile == "v10" else "v07"
        command = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ROOT / "scripts/build_v1_cp3.ps1"),
            "-Profile", helper_profile, "-BuildDirectory", str(directory),
            "-LogDirectory", str(log_dir.resolve()), "-NcsRoot", str(args.ncs_root),
            "-Toolchain", str(args.toolchain)]
        record = {"schema_version": "1.0", "build_id": build_id, "timestamp": utc_now(),
            "profile": profile, "provenance": start_provenance,
            "firmware_source_sha256": source_before, "command": command,
            "board": "nrf54l15dk/nrf54l15/cpuapp", "ncs_root": str(args.ncs_root),
            "toolchain": str(args.toolchain), "build_success": False}
        # Versions are read from SDK files/build evidence, not assumed from names.
        record["ncs_version"] = (args.ncs_root / "nrf" / "VERSION").read_text().strip()
        record["zephyr_version"] = (args.ncs_root / "zephyr" / "VERSION").read_text().strip()
        write_json(log_dir / "build-start.json", record)
        result = subprocess.run(command, cwd=ROOT, check=False)
        if result.returncode != 0:
            record["failure_reason"] = f"build_exit_{result.returncode}"
            write_json(log_dir / "resources.json", record)
            raise RuntimeError(record["failure_reason"])
        if source_before != source_hash("firmware"):
            raise RuntimeError("firmware source changed during build; discard this build from comparisons")
        record.update(collect(directory, log_dir / f"{helper_profile}-build.log", profile, args.toolchain))
        record["build_success"] = True
        write_json(log_dir / "resources.json", record)
        records.append(record)
        print(f"{profile} resource record: {log_dir / 'resources.json'}", flush=True)
    write_json(output / "comparison.json", {"build_id": build_id, "profiles": records,
        "limitations": ["Build footprint, not hardware latency or dynamic RAM usage.",
            "ELF sections do not alone equal FLASH/RAM region totals; noinit and alignment matter.",
            "Worker watermark requires a new DK UART capture; energy measurement not performed."]})
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    commands = p.add_subparsers(dest="command", required=True)
    b = commands.add_parser("build")
    b.add_argument("--profile", choices=("both", "v07", "v10"), default="both")
    b.add_argument("--output", type=Path, default=Path("benchmarks/results/post_v1/resources"))
    b.add_argument("--ncs-root", type=Path, default=Path("C:/ncs/v3.0.0"))
    b.add_argument("--toolchain", type=Path, default=Path("C:/ncs/toolchains/0b393f9e1b"))
    stack = commands.add_parser("stack")
    stack.add_argument("--run", required=True, type=Path)
    stack.add_argument("--log", required=True, type=Path)
    stack.add_argument("--output", required=True, type=Path)
    args = p.parse_args(argv)
    if args.command == "build":
        return build(args)
    from .records import validate
    run = json.loads(args.run.read_text(encoding="utf-8"))
    validate(run)
    if run["run_id"] not in args.log.name:
        p.error("UART log filename must contain run_id; correlate it before importing")
    write_json(args.output, {"run_id": run["run_id"], "log": str(args.log.resolve()),
        "log_sha256": sha256(args.log), **parse_stack_log(args.log.read_text(encoding="utf-8-sig"))})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
