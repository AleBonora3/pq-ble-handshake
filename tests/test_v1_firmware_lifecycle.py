"""Execute the actual CP1 C state machine with a small public-API adapter."""

from pathlib import Path
import shutil
import subprocess

import pytest


def test_native_security_lifecycle(tmp_path):
    compiler = shutil.which("gcc")
    if compiler is None:
        pytest.skip("host GCC unavailable; west build and source checks still apply")
    native = Path(__file__).parent / "native_v1"
    for name in ("zephyr/bluetooth/addr.h", "zephyr/bluetooth/bluetooth.h",
                 "zephyr/bluetooth/conn.h", "zephyr/bluetooth/hci.h", "zephyr/kernel.h",
                 "zephyr/logging/log.h", "zephyr/settings/settings.h", "dk_buttons_and_leds.h"):
        header = tmp_path / name
        header.parent.mkdir(parents=True, exist_ok=True)
        header.write_text('#include "security_stub.h"\n', encoding="utf-8")
    executable = tmp_path / "security_lifecycle.exe"
    build = subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-I", str(tmp_path), "-I", str(native),
                            str(native / "security_lifecycle.c"), "-o", str(executable)],
                           capture_output=True, text=True, timeout=30)
    assert build.returncode == 0, build.stdout + build.stderr
    result = subprocess.run([str(executable)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "CP1 native security lifecycle: PASS" in result.stdout
