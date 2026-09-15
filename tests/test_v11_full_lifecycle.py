"""Full v1.1 Control dispatch, worker commit and CP4 with real blocking locks."""

import os
from pathlib import Path
import shutil
import subprocess

import pytest

from tests.test_v1_cp3 import production_function


@pytest.fixture(scope="module")
def v11_full_native(tmp_path_factory):
    compiler = shutil.which("gcc")
    if os.name != "nt" or compiler is None:
        pytest.skip("Windows BCrypt, thread events and host GCC required")
    root = Path(__file__).resolve().parents[1]
    firmware = root / "firmware/src"
    build = tmp_path_factory.mktemp("v11_full_lifecycle")
    for name in ("zephyr/kernel.h", "zephyr/bluetooth/conn.h", "zephyr/bluetooth/gatt.h",
                 "zephyr/bluetooth/bluetooth.h", "zephyr/logging/log.h", "zephyr/sys/util.h"):
        path = build / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('#include "service_stub.h"\n')
    (build / "psa").mkdir()
    (build / "psa/crypto.h").write_text('#include "hybrid_psa.h"\n')
    main = (firmware / "main.c").read_text()
    state = main[main.index("#define CTRL_START "):main.index("#define PQM2_MAGIC")]
    state += main[main.index("enum ciphertext_state {"):main.index("static const char *phase7_state_name(")]
    state += main[main.index("enum v1_cp3_state {"):main.index("static void v1_cp3_timeout(")]
    worker = (firmware / "mlkem_session.c").read_text()
    start = worker.index("static uint32_t v1_cp3_epoch")
    state += worker[start:worker.index("#endif", start)]
    (build / "v11_state.inc").write_text(state)
    names = ("clear_transfer_storage_locked", "begin_transfer_locked", "write_ciphertext",
             "invalidate_v1_cp3_locked", "v1_cp3_timeout", "v1_cp3_live_locked",
             "v1_cp4_live_locked", "handle_v1_cp4", "handle_v1_cp3_start",
             "handle_v1_cp3_finished_c", "v1_cp3_result_ready", "handle_v1_cp2_start",
             "handle_v1_control", "write_control")
    # Include the entire dispatcher, including all profile branches. No copied
    # readiness expression or preinstalled APP_SECURE/EMPTY test state.
    (build / "v11_main.inc").write_text("\n".join(production_function(main, n) for n in names))
    names = ("v1_cp3_start_result", "v1_cp3_finished_result", "v1_cp3_job_complete_locked",
             "pq_mlkem_session_reset_v1_cp3", "pq_mlkem_session_submit_v1_cp3",
             "pq_mlkem_session_submit_v1_cp3_finished_c", "pq_mlkem_session_commit_v1_cp3")
    (build / "v11_worker.inc").write_text("\n".join(production_function(worker, n) for n in names))
    mlkem = root / "firmware/third_party/mlkem-native/mlkem"
    cmd = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O1",
           "-DCONFIG_PQ_PROFILE_V11_SMP_L4_MLKEM_RESUME=1", "-DCONFIG_PQ_RESUMPTION=1",
           "-DCONFIG_PQ_V1_CP3_TIMEOUT_MS=30000", "-DCP2_NATIVE_HASH_CAPACITY=4096",
           "-DMLK_CONFIG_PARAMETER_SET=768", "-DMLK_CONFIG_NO_RANDOMIZED_API",
           "-DMLK_CONFIG_NAMESPACE_PREFIX=pqble_mlkem", "-DMLK_CONFIG_INTERNAL_API_QUALIFIER=static"]
    for path in (build, root / "tests/native_resume", root / "tests/native_v1", firmware, mlkem):
        cmd += ["-I", str(path)]
    cmd += [str(root / "tests/native_resume/v11_full_lifecycle.c")]
    cmd += [str(firmware / name) for name in ("pq_resume.c", "pq_v1_cp3.c", "pq_v1_cp4.c", "pq_v1_frame.c")]
    exe = build / "v11_full.exe"
    result = subprocess.run(cmd + [str(mlkem / "mlkem_native.c"), "-lbcrypt", "-o", str(exe)],
                            capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stdout + result.stderr
    return exe


@pytest.mark.parametrize("scenario", [
    "immediate", "delayed", "concurrent", "notify-failure", "bond-failure",
    "pre-commit", "pre-l4", "wrong-version", "wrong-direction", "wrong-sequence",
    "bad-tag", "replay", "cccd-loss", "l4-loss",
])
def test_v11_full_to_cp4(v11_full_native, scenario):
    result = subprocess.run([str(v11_full_native), scenario], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "v1.1 full Control -> CP4: PASS" in result.stdout
