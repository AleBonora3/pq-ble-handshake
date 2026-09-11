"""Optional TShark analysis: metadata only, no payload/key extraction."""

import argparse
import csv
from datetime import datetime
import io
import json
import math
from pathlib import Path
import re
import subprocess

from .records import sha256, validate, write_json

FIELDS = ["frame.number", "frame.time_epoch", "frame.len", "frame.cap_len",
          "btle.data_header.length", "nordic_ble.direction", "frame.protocols"]


def capture_window(record, window, clock_offset):
    validate(record)
    if not math.isfinite(clock_offset):
        raise ValueError("clock offset must be finite")
    events = {}
    for row in record["events"]:
        events.setdefault(row["name"], []).append(row["offset_ns"])
    start_name, end_name = {"full": ("run_start", "run_end"),
        "handshake": ("connection_request", "app_secure"),
        "application": ("application_request", "application_response_authenticated")}[window]
    if start_name not in events or end_name not in events:
        raise ValueError("required window endpoints unavailable")
    anchor = datetime.fromisoformat(record["timestamp"])
    if anchor.tzinfo is None:
        raise ValueError("timestamp needs timezone")
    start = anchor.timestamp() + events[start_name][0] / 1e9 + clock_offset
    end = anchor.timestamp() + events[end_name][-1] / 1e9 + clock_offset
    if end < start:
        raise ValueError("invalid capture window")
    return start, end


def display_filter(address, start, end):
    if not re.fullmatch(r"0x[0-9a-fA-F]{8}", address) or address.lower() == "0x8e89bed6":
        raise ValueError("specify the DUT connection's data Access Address, not advertising address")
    if not all(math.isfinite(x) for x in (start, end)) or end < start:
        raise ValueError("invalid time window")
    return f"btle.access_address == {address} && frame.time_epoch >= {start:.9f} && frame.time_epoch <= {end:.9f}"


def parse_tsv(text):
    packets = []
    for row in csv.reader(io.StringIO(text), delimiter="\t"):
        if not row:
            continue
        if len(row) != len(FIELDS):
            raise ValueError("unexpected TShark field count")
        number, timestamp, length, captured, ll_length, direction, protocols = row
        direction_values = {"": None, "0": 0, "1": 1, "False": 0, "True": 1}
        if direction not in direction_values:
            raise ValueError("unknown Nordic direction flag")
        packet = {"frame_number": int(number), "timestamp_epoch": float(timestamp),
            "capture_record_bytes": int(length), "captured_bytes": int(captured),
            "ll_data_payload_length": int(ll_length) if ll_length else None,
            "nordic_direction_flag": direction_values[direction],
            "att_decoded": "btatt" in protocols.split(":"),
            "smp_decoded": "btsmp" in protocols.split(":")}
        if not math.isfinite(packet["timestamp_epoch"]) or any(packet[k] < 0 for k in
                ("frame_number", "capture_record_bytes", "captured_bytes")):
            raise ValueError("invalid packet metadata")
        if packet["nordic_direction_flag"] not in (None, 0, 1):
            raise ValueError("unknown Nordic direction flag")
        if packet["ll_data_payload_length"] is not None and not 0 <= packet["ll_data_payload_length"] <= 255:
            raise ValueError("invalid LL length")
        packets.append(packet)
    if len({p["frame_number"] for p in packets}) != len(packets):
        raise ValueError("duplicate TShark frame number")
    return packets


def summarize_packets(packets):
    lengths = [p["ll_data_payload_length"] for p in packets if p["ll_data_payload_length"] is not None]
    return {"observed_packet_count": len(packets),
        "capture_record_bytes": sum(p["capture_record_bytes"] for p in packets),
        "captured_bytes": sum(p["captured_bytes"] for p in packets),
        "ll_data_payload_length_sum": sum(lengths) if lengths else None,
        "packets_with_ll_data_length": len(lengths),
        "direction_flags": {str(flag): sum(p["nordic_direction_flag"] == flag for p in packets) for flag in (0, 1, None)},
        "att_decoded_packets": sum(p["att_decoded"] for p in packets),
        "smp_decoded_packets": sum(p["smp_decoded"] for p in packets)}


def analyze(record, capture, *, tshark, address, window, clock_offset):
    capture = Path(capture)
    if capture.name != record["pcap_filename"] or not capture.is_file():
        raise ValueError("capture must exist and match the run_id filename")
    start, end = capture_window(record, window, clock_offset)
    filter_expression = display_filter(address, start, end)
    version = subprocess.run([tshark, "--version"], capture_output=True, text=True, check=True).stdout.splitlines()[0]
    command = [tshark, "-n", "-r", str(capture.resolve()), "-Y", filter_expression,
               "-T", "fields", "-E", "occurrence=f"]
    for field in FIELDS:
        command += ["-e", field]
    output = subprocess.run(command, capture_output=True, text=True, check=True)
    packets = parse_tsv(output.stdout)
    return {"schema_version": "1.0", "run_id": record["run_id"],
        "capture_file": str(capture.resolve()), "capture_sha256": sha256(capture),
        "tool_version": version, "command": command, "display_filter": filter_expression,
        "fields": FIELDS, "window": window, "clock_offset_seconds": clock_offset,
        "window_epoch": [start, end], "summary": summarize_packets(packets), "packets": packets,
        "limitations": ["Packet count is observed, not ground truth; passive capture may lose packets.",
            "frame.len is the capture record including encapsulation, not physical on-air bytes.",
            "LL data length is the dissected header payload length; missing fields are null.",
            "Direction is the raw Nordic flag; verify its mapping in the installed dissector.",
            "Window mapping uses a PC wall-clock anchor plus monotonic offsets; verify alignment manually.",
            "No automatic retransmission, event, fragmentation, airtime or energy inference.",
            "This data-Access-Address filter excludes advertising/CONNECT_IND; inspect setup separately.",
            "Encrypted v1.0 ATT contents may be invisible; no session keys are requested/exported."]}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("run", type=Path)
    p.add_argument("capture", type=Path)
    p.add_argument("--tshark", default="tshark")
    p.add_argument("--access-address", required=True)
    p.add_argument("--window", choices=("full", "handshake", "application"), default="full")
    p.add_argument("--clock-offset-seconds", required=True, type=float,
                   help="Capture clock minus Central PC clock; explicitly use 0 on same PC after checking")
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args(argv)
    record = json.loads(args.run.read_text(encoding="utf-8"))
    result = analyze(record, args.capture, tshark=args.tshark, address=args.access_address,
                     window=args.window, clock_offset=args.clock_offset_seconds)
    write_json(args.output, result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
