# Session resumption software validation

Finalization on 2026-09-15: **SOFTWARE PASS; HARDWARE VALIDATION PENDING**.
Results cover the current working tree on `feature/session-resumption-v08-v11`,
based on HEAD `a2c0f01529b3ff5863407fcb14928f8fcd3b7955`.
No hardware tests, flashing, staging, commits or pushes were performed.

| Check | Final result | Evidence |
|---|---|---|
| Five targeted resume suites | 151 passed, 1 warning | [Targeted log](logs/session-resumption-targeted.txt) |
| Complete pytest regression | 1276 passed, 1 skipped, 1 warning | [Regression log](logs/session-resumption-regression.txt) |
| `python -m compileall -q src tests benchmarks` | PASS, exit 0 | [Compileall log](logs/session-resumption-compileall.txt) |
| `git diff --check` | PASS, exit 0 | [Diff-check log](logs/session-resumption-diff-check.txt) |

The warning is the existing native liboqs 0.15.0 / liboqs-python 0.16.0 mismatch.
The skip is the WinRT-unavailable test on a Windows host where WinRT is available.
An earlier regression run reported a timing-sensitive CP4 mock-test failure
(`extra-finished-c`). Without source changes, the focused CP4 rerun passed all
190 tests and the final complete regression passed. No protocol change was needed.

The existing final-check helper produced the software logs above. Its scripts,
temporary directories and local JSON summary remain ignored.

## Fresh firmware builds

The four builds were produced in fresh directories. During finalization, all
recorded firmware input hashes and ELF/merged HEX/config hashes were rechecked
against the current files and matched; no firmware source changed afterward.
The [build manifest](logs/session-resumption-builds.json) records exact commands,
directories, SHA-256 values and ARM ELF symbol sizes. All four exit codes are 0.

| Profile | Result | FLASH (B) | RAM (B) | `merged.hex` |
|---|---|---:|---:|---|
| v0.7 | PASS | 225652 | 106048 | Present |
| v1.0 | PASS | 279428 | 109464 | Present |
| v0.8 | PASS | 229480 | 119792 | Present |
| v1.1 | PASS | 283376 | 122056 | Present |

For both v0.8 and v1.1, the ELF `ticket` object (`pq_resume_ticket`) is **6224 B**
and the `session` object (`pq_resume_session`) is **216 B**.

The quick documentation check confirms the unchanged 43-byte v0.7 data-plane
frames for v0.8, 51-byte CP4 frames for v1.1, and the 256-application-byte resume
exchange. Historical v0.7/v1.0 EVAL evidence remains unchanged.

The next project stage is the separate [hardware validation plan](session-resumption-hardware-plan.md):
DK UART **COM9 at 115200**, nRF52840 Sniffer **COM7**, COM8 unused. No v0.8/v1.1
real-device PASS or performance result is claimed by these software checks.
