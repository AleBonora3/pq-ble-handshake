"""Production callback registration and baseline data-plane routing checks."""
from pathlib import Path
import shutil
import subprocess

import pytest


def test_real_bond_callbacks_are_registered_and_invalidate(tmp_path):
    compiler = shutil.which("gcc")
    if compiler is None:
        pytest.skip("host GCC required")
    root = Path(__file__).resolve().parents[1]
    for name in ("zephyr/bluetooth/addr.h", "zephyr/bluetooth/bluetooth.h",
                 "zephyr/bluetooth/conn.h", "zephyr/bluetooth/hci.h", "zephyr/kernel.h",
                 "zephyr/logging/log.h", "zephyr/settings/settings.h", "dk_buttons_and_leds.h",
                 "zephyr/bluetooth/gatt.h"):
        header = tmp_path/name
        header.parent.mkdir(parents=True, exist_ok=True)
        header.write_text('#include "security_stub.h"\nstruct bt_gatt_attr;\n')
    exe = tmp_path/"callbacks.exe"
    build = subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-DCONFIG_PQ_RESUMPTION=1", "-DCONFIG_PQ_PROFILE_V11_SMP_L4_MLKEM_RESUME=1",
        "-I", str(tmp_path), "-I", str(root/"tests/native_v1"),
        str(root/"tests/native_resume/security_callbacks.c"), "-o", str(exe)],
        capture_output=True, text=True, timeout=30)
    assert build.returncode == 0, build.stdout+build.stderr
    run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=10)
    assert run.returncode == 0, run.stdout+run.stderr


def test_frozen_application_worker_and_data_primitives_unchanged():
    root = Path(__file__).resolve().parents[1]
    baseline = "a2c0f01529b3ff5863407fcb14928f8fcd3b7955"
    def original(path):
        return subprocess.run(["git", "show", f"{baseline}:{path}"], cwd=root,
            capture_output=True, text=True, check=True).stdout
    for path in ("src/common/session.py", "src/central/phase7_auth.py", "firmware/src/pq_secure_channel.c"):
        assert (root/path).read_text() == original(path)
    path = "firmware/src/mlkem_session.c"
    def worker_body(text):
        start = text.index("\t\t\tmode ==\n\t\t\tPQ_MLKEM_JOB_PHASE7_APP_C2P) {")
        end = text.index("\n\t\t} else", start)
        return text[start:end]
    assert worker_body((root/path).read_text()) == worker_body(original(path))
