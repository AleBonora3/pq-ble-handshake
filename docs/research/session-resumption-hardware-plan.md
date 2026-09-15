# Future v0.8 / v1.1 hardware validation

**HARDWARE VALIDATION PENDING. None of the hardware commands below were executed
as part of this implementation.** They are for the later operator campaign.
Use a visible interactive PowerShell terminal for SAS/Numeric Comparison. Do
not pipe input into the protocol runner or automatically accept authentication.

## Prepare and flash the selected profile (future operator action)

Use the Windows Central, nRF54L15 DK, NCS v3.0.0 and toolchain
`C:\ncs\toolchains\0b393f9e1b`. The recorded DK serial is `1057790967`, UART is
`COM9` at 115200 baud, and the firmware advertises `PQ-BLE-Device`. The nRF52840
Sniffer uses `COM7`; `COM8` is unused. Run from `C:\pq_ble`. Each profile must be
built/flashed separately;
the script's `-Flash` switch is intentionally absent from all software-only
validation commands.

```powershell
Set-Location C:\pq_ble
$captureDir = Join-Path (Get-Location) ('benchmarks/results/session_resumption/hw-' + (Get-Date -Format yyyyMMdd-HHmmss))
New-Item -ItemType Directory -Path $captureDir | Out-Null
Start-Transcript -Path (Join-Path $captureDir 'central.txt')

# Select ONE profile. These commands fresh-build AND FLASH when run later.
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build_v1_cp3.ps1 -Profile v08 -BuildDirectory C:/pq_ble/firmware/build_hw_resume_v08 -LogDirectory $captureDir -Flash -SerialNumber 1057790967
# Or:
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build_v1_cp3.ps1 -Profile v11 -BuildDirectory C:/pq_ble/firmware/build_hw_resume_v11 -LogDirectory $captureDir -Flash -SerialNumber 1057790967
```

In a second visible terminal, start UART capture before protocol testing (replace
the example output path with the same newly created directory; it must exist).
The capture script uses CreateNew, so select a new file for every capture.

```powershell
Set-Location C:\pq_ble
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/capture_v1_cp3_uart.ps1 -Port COM9 -Seconds 600 -Log C:/pq_ble/benchmarks/results/session_resumption/hw-YYYYMMDD-HHMMSS/dk-uart.txt
```

Record firmware HEX/ELF/config SHA-256, board, BLE adapter, software versions,
source-tree hash/dirty state and negotiated MTU. Use MTU 247 when available;
resume requires at least 107. `--mtu` does not guarantee a WinRT MTU request.
Never export `data/keys/resumption/*.json` into evidence or print its roots.

## v0.8 positive full, reconnect, restart and fallback

With v0.8 firmware and UART visible:

```powershell
# Compare SAS with DK UART; accept only when equal.
C:/pq_ble/.venv/Scripts/python.exe -m src.central.main --v08-resume-hybrid --resume-full --log-level INFO
if ($LASTEXITCODE -ne 0) { throw 'v0.8 full failed' }

# Each invocation is a new Python process and BLE connection.
C:/pq_ble/.venv/Scripts/python.exe -m src.central.main --v08-resume-hybrid --log-level INFO
if ($LASTEXITCODE -ne 0) { throw 'v0.8 resume failed' }
C:/pq_ble/.venv/Scripts/python.exe -m src.central.main --v08-resume-hybrid --log-level INFO
```

Require `full` then `resume`, three authenticated PING/PONG rounds on each run,
and increasing resume count in DK logs. Resume must show no ML-KEM decapsulation,
application P-256 operation or SAS prompt. Packet/transport evidence should show
the four exact resume frames and 43-byte Secure Data application frames.

Press DK RESET while disconnected, keeping the Central ticket file. Run the
same resume command: require `RESUME_REJECT` followed by full hybrid/SAS fallback
and replacement ticket. Repeat the resume command: it must now resume successfully.
Reboot fallback is expected, not a resume success sample.

## v1.1 cold pairing and stable bonded identity

To create a cold setup, remove only this test device's Windows bond using
Windows Settings, or the following future command (connects only to the named
test device, unpairs it and disconnects; it does not run a protocol handshake):

```powershell
@'
import asyncio
from src.central.ble_client import BLECentralClient
from src.central.winrt_pairing import unpair
async def main():
    client = BLECentralClient(device_name="PQ-BLE-Device")
    try:
        if not await client.scan_and_connect(timeout=15):
            raise RuntimeError("test DK not found")
        await unpair(client)
    finally:
        await client.disconnect()
asyncio.run(main())
'@ | C:/pq_ble/.venv/Scripts/python.exe -
```

After disconnect, press DK **BUTTON 3** (the `DK_BTN4_MSK` mapping) to delete DK
bonds. Require the UART bond-deleted message. This callback also invalidates the
RAM application ticket. Bond clearing is intentionally refused while connected.

```powershell
# Run while both bonds are absent. Require actual GATT denial of RESUME_INIT.
C:/pq_ble/.venv/Scripts/python.exe -m src.central.main --v11-smp-l4-mlkem-resume --resume-negative-test-only pre-l4 --log-level INFO

# Cold full: compare Numeric Comparison on PC and UART, press DK BUTTON 0
# only if equal, and type yes on PC. BUTTON 1 rejects.
C:/pq_ble/.venv/Scripts/python.exe -m src.central.main --v11-smp-l4-mlkem-resume --resume-full --log-level INFO

# Bonded full baseline within the new profile; no new Numeric Comparison.
C:/pq_ble/.venv/Scripts/python.exe -m src.central.main --v11-smp-l4-mlkem-resume --resume-full --log-level INFO

# Bonded application resume, in a new process/connection; no ML-KEM.
C:/pq_ble/.venv/Scripts/python.exe -m src.central.main --v11-smp-l4-mlkem-resume --log-level INFO
```

Require SEC_INFO = authenticated SC L4, 16-byte BLE key and open gate before any
INIT. Require `bonded resume` and two authenticated CP4 challenge/echo rounds.
Preserve both bonds, press DK RESET while disconnected, and run the last command
again: expect bonded-L4 restoration plus **full ML-KEM fallback** because the
application ticket was RAM-only. The following invocation should resume.

Repeat across the host's normal private-address rotations, with the same bond.
Record the resolved identity in DK logs and, where observable, the separate
on-air address in the sniffer capture. Require matching identity/ticket behavior;
do not force an RPA into a ticket. A changed host lookup address can cause a safe
Central cache miss/full fallback and must be distinguished from DK identity
binding failure. Repeat deletion on both sides and require a new cold ceremony;
the prior application ticket must not resume.

## Resume rejection and lifetime commands

Run each profile's positive full command first to seed a valid ticket. Use these
commands with the corresponding firmware; every negative result must be an
explicit rejection, not a timeout misclassified as PASS.

```powershell
$profileFlag = '--v08-resume-hybrid' # Use '--v11-smp-l4-mlkem-resume' for v1.1.
foreach ($mode in @('init-mac', 'accept-mac', 'replay-init', 'replay-finish')) {
    & C:/pq_ble/.venv/Scripts/python.exe -m src.central.main $profileFlag --resume-negative-test-only $mode --log-level INFO
    if ($LASTEXITCODE -ne 0) { throw "Negative test failed: $mode" }
    # Valid ticket must still work after the rejected attempt.
    & C:/pq_ble/.venv/Scripts/python.exe -m src.central.main $profileFlag --log-level INFO
    if ($LASTEXITCODE -ne 0) { throw "Recovery failed after $mode" }
}

# These alter only the loaded Central metadata for a TEST-ONLY policy check,
# then select full fallback. They do not age or exhaust the actual DK ticket.
& C:/pq_ble/.venv/Scripts/python.exe -m src.central.main $profileFlag --resume-negative-test-only expired --log-level INFO
& C:/pq_ble/.venv/Scripts/python.exe -m src.central.main $profileFlag --resume-negative-test-only max-uses --log-level INFO

# Real DK max-use campaign: seed a new full ticket immediately before this loop.
& C:/pq_ble/.venv/Scripts/python.exe -m src.central.main $profileFlag --resume-full --log-level INFO
for ($resumeIndex = 1; $resumeIndex -le 100; $resumeIndex++) {
    & C:/pq_ble/.venv/Scripts/python.exe -m src.central.main $profileFlag --log-level INFO
    if ($LASTEXITCODE -ne 0) { throw "Resume failed at use $resumeIndex" }
}
# The next invocation must perform full authentication (SAS for v0.8).
& C:/pq_ble/.venv/Scripts/python.exe -m src.central.main $profileFlag --log-level INFO
Stop-Transcript
```

For real 24-hour expiry, seed a new ticket and leave the DK powered without
reboot for more than 24 hours. Start a new Central invocation and require full
fallback; record timestamps and verify no successful resume renewed the deadline.
Native tests exercise the exact boundary without waiting, but are not hardware
expiry evidence.

Notification/send failure and L4 loss during a pending FINISH require an operator
fault-injection transport/controller setup; no dedicated hardware automation is
provided yet. Disconnect between ACCEPT and FINISH, disable notifications, and
exercise actual BLE security loss when that setup is available. Require no
APP_SECURE and no successful-use increment after failed final send; reconnect
and prove the ticket still works. Bond deletion should invalidate the ticket.
Do not claim those real-controller races are covered by an ordinary successful
CLI run. Record RX and crypto-worker stack high-water during the campaign.

## Frozen baseline commands for the separate evaluation

Run later with the corresponding firmware, in separate capture directories:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build_v1_cp3.ps1 -Profile v07 -BuildDirectory C:/pq_ble/firmware/build_hw_resume_v07 -LogDirectory C:/pq_ble/firmware/build_hw_resume_v07_logs -Flash -SerialNumber 1057790967
C:/pq_ble/.venv/Scripts/python.exe -m src.central.main --phase7-auth-hybrid --log-level INFO

powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build_v1_cp3.ps1 -Profile v1 -BuildDirectory C:/pq_ble/firmware/build_hw_resume_v10 -LogDirectory C:/pq_ble/firmware/build_hw_resume_v10_logs -Flash -SerialNumber 1057790967
# Establish a valid bond manually first if needed; record only bonded full here.
C:/pq_ble/.venv/Scripts/python.exe -m src.central.main --v1-smp-l4-mlkem --v1-cp4 --log-level INFO
```

The separate [evaluation plan](../../benchmarks/resumption/README.md) defines
all seven populations and distinguishes application/control bytes, GATT API
operations, latency and radio observations. Complete hardware correctness before
collecting comparative performance samples.
