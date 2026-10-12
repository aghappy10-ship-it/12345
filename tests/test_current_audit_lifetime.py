"""The fixed successor must expose real progress before a child terminates.

These are short host-only process tests at the already agreed run_child seam,
not a complete audit or device qualification.
"""
from datetime import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace

import pytest


@pytest.fixture(params=("peer-route-review-20261006-rg509", "peer-route-review-20261007-host-model"),
                ids=("rg509", "host-model"))
def successor(monkeypatch, request):
    root = Path(__file__).resolve().parents[1]
    path = root / "build" / request.param / "run_audit.py"
    spec = importlib.util.spec_from_file_location("recorded_audit_successor", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with tempfile.TemporaryDirectory(prefix="audit-stream-", dir=root / "build") as name:
        monkeypatch.setattr(module, "HERE", Path(name))
        yield module


def test_actual_child_progress_is_readable_before_it_can_finish(successor):
    # A real handshake prevents the child from finishing until its caller has
    # inspected both the progress bytes and kernel process identity receipt.
    release = successor.HERE / "release-child"
    command = [sys.executable, "-B", "-c",
               "import os, pathlib, time; os.write(1, b'RUNNING_BEFORE_RELEASE\\n'); "
               f"p=pathlib.Path({str(release)!r}); "
               "exec('while not p.exists():\\n time.sleep(0.02)'); "
               "os.write(2, b'FINISHED_AFTER_RELEASE\\n')"]
    result, errors = [], []

    def run():
        try:
            result.append(successor.run_child("progress", command, timeout=15))
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=run)
    worker.start()
    log = successor.HERE / "progress.output.log"
    start = successor.HERE / "progress.start.json"
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if log.exists() and b"RUNNING_BEFORE_RELEASE\n" in log.read_bytes() and start.exists():
                break
            if errors:
                raise errors[0]
            time.sleep(0.02)
        assert log.is_file() and b"RUNNING_BEFORE_RELEASE\n" in log.read_bytes()
        receipt = json.loads(start.read_bytes())
        assert receipt["command"] == command
        assert receipt["parent_pid"] == os.getpid()
        assert type(receipt["pid"]) is int and receipt["pid"] > 0
        assert type(receipt["birth_filetime_100ns"]) is int and receipt["birth_filetime_100ns"] > 0
        assert datetime.fromisoformat(receipt["birth_utc"]).utcoffset() is not None
        assert receipt["executable_sha256"] == hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()
        assert receipt["runner_sha256"] == hashlib.sha256(Path(successor.__file__).read_bytes()).hexdigest()
        assert receipt["installable"] is False and receipt["camera_accesses"] == 0
        assert worker.is_alive() and result == []
        assert not (successor.HERE / "progress.process.json").exists()
    finally:
        release.touch()
        worker.join(timeout=20)
    assert not worker.is_alive() and errors == []
    assert len(result) == 1
    record = result[0]
    raw = log.read_bytes()
    assert raw == b"RUNNING_BEFORE_RELEASE\nFINISHED_AFTER_RELEASE\n"
    assert record["outcome"] == "finished" and record["exit_code"] == 0
    assert record["child"] == receipt
    assert record["output_bytes"] == len(raw)
    assert record["output_sha256"] == hashlib.sha256(raw).hexdigest()
    assert json.loads((successor.HERE / "progress.process.json").read_bytes()) == record


def test_new_consumed_successor_is_bound_without_dropping_earlier_inputs(successor):
    from tools.release_identity import AUDIT_INPUTS, source_inputs
    paths = (
        "build/peer-route-review-20261006-rg509/run_audit.py",
        "build/peer-route-review-20261006-rg509/launch_admin_audit_once.py",
        "build/peer-route-review-20261007-host-model/run_audit.py",
        "build/peer-route-review-20261007-host-model/launch_admin_audit_once.py",
    )
    inputs = source_inputs()
    for path in paths:
        assert path in AUDIT_INPUTS and path in inputs
        raw = (successor.ROOT / path).read_bytes()
        assert inputs[path] == {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    assert "build/peer-route-review-20261006-dependency-closure/run_audit.py" in inputs


@pytest.mark.parametrize("relative", (
    "build/peer-route-review-20261007-host-model/run_audit.py",
    "build/peer-route-review-20261007-host-model/launch_admin_audit_once.py",
), ids=("runner", "launcher"))
def test_actual_host_model_copy_bytes_participate_in_public_build_identity(monkeypatch, relative):
    from tools import release_identity

    path = release_identity.ROOT / relative
    original_read = Path.read_bytes
    original_bytes = path.read_bytes()
    inputs = release_identity.source_inputs()
    assert relative in inputs, "actual consumed audit copy is absent from source inputs"
    assert inputs[relative] == {
        "sha256": hashlib.sha256(original_bytes).hexdigest(), "bytes": len(original_bytes),
    }
    # Inert public build-identity inputs only; no renderer, package or executor.
    candidate = {"test_fixture_only": True}
    scripts = {"fixture.sh": "exit 0\n"}
    before = release_identity.build_subject(candidate, scripts, source_hash="a" * 64)
    mutated_bytes = original_bytes + b"\n# host-only read-boundary fault\n"

    def changed_copy(target):
        return mutated_bytes if target == path else original_read(target)

    # Only the file-read boundary changes. The real APIs compute both the
    # source inventory and its subject, and no audit source bytes are written.
    with monkeypatch.context() as patch:
        patch.setattr(Path, "read_bytes", changed_copy)
        changed = release_identity.source_inputs()
        assert changed[relative] == {
            "sha256": hashlib.sha256(mutated_bytes).hexdigest(), "bytes": len(mutated_bytes),
        }
        assert release_identity.build_subject(candidate, scripts, source_hash="a" * 64) != before
    assert path.read_bytes() == original_bytes
    assert release_identity.build_subject(candidate, scripts, source_hash="a" * 64) == before


def test_fixed_launcher_records_actual_child_before_its_terminal_result(successor, monkeypatch):
    path = Path(successor.__file__).with_name("launch_admin_audit_once.py")
    spec = importlib.util.spec_from_file_location("recorded_fixed_launcher", path)
    launcher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(launcher)
    release = successor.HERE / "release-launcher-child"
    runner = successor.HERE / "local-fixture-child.py"
    runner.write_text("import os, pathlib, time\n"
                      "os.write(1, b'LAUNCHER_RUNNING\\n')\n"
                      f"while not pathlib.Path({str(release)!r}).exists():\n time.sleep(0.02)\n"
                      "raise SystemExit(19)\n", encoding="ascii")
    # Only the OS privilege check and fixed file identities are host fixtures;
    # spawning, handles, writes, child outcome and main logic remain real.
    monkeypatch.setattr(launcher, "HERE", successor.HERE)
    monkeypatch.setattr(launcher, "RUNNER", runner)
    monkeypatch.setattr(launcher, "RUNNER_SHA", hashlib.sha256(runner.read_bytes()).hexdigest())
    monkeypatch.setattr(launcher.ctypes.windll, "shell32", SimpleNamespace(IsUserAnAdmin=lambda: True))
    monkeypatch.setattr(sys, "argv", [str(path)])
    results, errors = [], []

    def run():
        try:
            results.append(launcher.main())
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=run)
    worker.start()
    child_start = successor.HERE / "admin-launch-child-start.json"
    output = successor.HERE / "admin-launch-output.log"
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if child_start.exists() and output.exists() and b"LAUNCHER_RUNNING\n" in output.read_bytes():
                break
            if errors:
                raise errors[0]
            time.sleep(0.02)
        assert child_start.is_file()
        child = json.loads(child_start.read_bytes())
        parent = json.loads((successor.HERE / "admin-launch-start.json").read_bytes())
        assert child["parent_pid"] == parent["launcher"]["pid"] == os.getpid()
        assert child["pid"] != os.getpid()
        assert type(child["birth_filetime_100ns"]) is int and child["birth_filetime_100ns"] > 0
        assert child["command"] == parent["command"]
        assert child["executable_sha256"] == parent["python_sha256"]
        assert child["runner_sha256"] == parent["runner_sha256"]
        assert type(parent["launcher"]["in_any_job"]) is bool and type(child["in_any_job"]) is bool
        assert worker.is_alive() and not (successor.HERE / "admin-launch-result.json").exists()
    finally:
        release.touch()
        worker.join(timeout=20)
    assert not worker.is_alive() and errors == [] and results == [19]
    terminal = json.loads((successor.HERE / "admin-launch-result.json").read_bytes())
    assert terminal["exit_code"] == 19 and terminal["child"] == child
    assert terminal["output_sha256"] == hashlib.sha256(output.read_bytes()).hexdigest()
    assert terminal["installable"] is False and terminal["camera_accesses"] == 0


def test_failed_os_birth_read_leaves_a_terminal_failure_without_invented_exit(successor, monkeypatch):
    class FailedTimes:
        def __call__(self, *args):
            return 0

    # Replace only the failing kernel call; launching and termination are real.
    monkeypatch.setattr(successor.ctypes, "WinDLL", lambda *a, **k: SimpleNamespace(GetProcessTimes=FailedTimes()))
    command = [sys.executable, "-B", "-c", "import time; time.sleep(30)"]
    record = successor.run_child("failed-identity", command, timeout=15)
    assert record["outcome"] == "start_record_failure"
    assert record["exit_code"] is None
    assert type(record["termination_exit_code"]) is int
    assert record["start_record_error"]["type"] == "OSError"
    assert "child" not in record
    assert not (successor.HERE / "failed-identity.start.json").exists()
    assert json.loads((successor.HERE / "failed-identity.process.json").read_bytes()) == record


def test_real_timeout_preserves_partial_stream_and_reaps_the_exact_child(successor):
    command = [sys.executable, "-B", "-c",
               "import os, time; os.write(1, b'BEFORE_TIMEOUT\\n'); time.sleep(30)"]
    record = successor.run_child("timeout", command, timeout=0.5)
    assert record["outcome"] == "timeout" and record["exit_code"] is None
    assert type(record["termination_exit_code"]) is int
    assert record["child"] == json.loads((successor.HERE / "timeout.start.json").read_bytes())
    raw = (successor.HERE / "timeout.output.log").read_bytes()
    assert raw == b"BEFORE_TIMEOUT\n"
    assert record["output_sha256"] == hashlib.sha256(raw).hexdigest()
    assert json.loads((successor.HERE / "timeout.process.json").read_bytes()) == record


@pytest.mark.parametrize("exit_code", (0, 47))
def test_real_finished_child_keeps_its_exact_outcome(successor, exit_code):
    command = [sys.executable, "-B", "-c",
               f"import os; os.write(2, b'EXACT_STDERR\\n'); os._exit({exit_code})"]
    record = successor.run_child("normal", command, timeout=15)
    assert record["outcome"] == "finished" and record["exit_code"] == exit_code
    assert type(record["exit_code"]) is int
    assert (successor.HERE / "normal.output.log").read_bytes() == b"EXACT_STDERR\n"
    assert record["child"] == json.loads((successor.HERE / "normal.start.json").read_bytes())


def test_real_missing_executable_never_receives_an_invented_start_or_exit(successor):
    command = [str(successor.HERE / "absent.exe")]
    record = successor.run_child("missing", command, timeout=15)
    assert record["outcome"] == "spawn_failure" and record["exit_code"] is None
    assert record["spawn_error"]["type"] == "FileNotFoundError"
    assert "child" not in record and not (successor.HERE / "missing.start.json").exists()
    assert (successor.HERE / "missing.output.log").read_bytes() == b""


@pytest.mark.parametrize("name", ("output.log", "start.json", "process.json"))
def test_existing_evidence_is_rejected_without_a_new_child_or_file(successor, name):
    existing = successor.HERE / ("preserved." + name)
    existing.write_bytes(b"retained original evidence")
    command = [sys.executable, "-B", "-c", "raise SystemExit(0)"]
    with pytest.raises(ValueError, match="output already exists"):
        successor.run_child("preserved", command, timeout=15)
    assert list(successor.HERE.iterdir()) == [existing]
    assert existing.read_bytes() == b"retained original evidence"
