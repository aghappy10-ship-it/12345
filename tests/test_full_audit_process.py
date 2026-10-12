"""Real local child outcomes must retain exact audit process evidence."""
from datetime import datetime
import errno
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile

import pytest


@pytest.fixture
def process_runner(monkeypatch):
    root = Path(__file__).resolve().parents[1]
    path = root / "build/peer-route-review-20261006-menu-evidence/run_audit.py"
    spec = importlib.util.spec_from_file_location("current_audit_process_runner", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with tempfile.TemporaryDirectory(prefix="audit-child-record-", dir=root / "build") as name:
        monkeypatch.setattr(module, "HERE", Path(name))
        yield module


def _check_record(runner, stage, command, record, expected_output):
    assert type(record) is dict
    assert record["command"] == command
    assert record["output_file"] == stage + ".output.log"
    raw = (runner.HERE / record["output_file"]).read_bytes()
    assert raw == expected_output
    assert record["output_bytes"] == len(raw)
    assert record["output_sha256"] == hashlib.sha256(raw).hexdigest()
    assert json.loads((runner.HERE / (stage + ".process.json")).read_bytes()) == record
    started = datetime.fromisoformat(record["started_utc"])
    finished = datetime.fromisoformat(record["finished_utc"])
    assert started.utcoffset() is not None and finished.utcoffset() is not None
    assert finished >= started
    duration = record["duration_seconds"]
    assert type(duration) in (int, float) and duration >= 0
    return record


@pytest.mark.parametrize("exit_code", (0, 19))
def test_real_finished_child_retains_merged_output_and_exact_exit(process_runner, exit_code):
    command = [sys.executable, "-B", "-c",
               "import os, sys; os.write(1, b'STDOUT_NORMAL\\n'); "
               "os.write(2, b'STDERR_NORMAL\\n'); sys.exit(" + str(exit_code) + ")"]
    record = process_runner.run_child("normal", command, timeout=15)
    _check_record(process_runner, "normal", command, record, b"STDOUT_NORMAL\nSTDERR_NORMAL\n")
    assert record["outcome"] == "finished"
    assert type(record["exit_code"]) is int and record["exit_code"] == exit_code


def test_real_abrupt_exit_preserves_output_and_nonzero_status(process_runner):
    command = [sys.executable, "-B", "-c",
               "import os; os.write(1, b'ABRUPT_STDOUT\\n'); "
               "os.write(2, b'ABRUPT_STDERR\\n'); os._exit(47)"]
    record = process_runner.run_child("abrupt", command, timeout=15)
    _check_record(process_runner, "abrupt", command, record, b"ABRUPT_STDOUT\nABRUPT_STDERR\n")
    assert record["outcome"] == "finished"
    assert type(record["exit_code"]) is int and record["exit_code"] == 47


def test_real_missing_executable_has_spawn_error_without_invented_exit(process_runner):
    command = [str(process_runner.HERE / "missing-audit-child.exe"), "exact-argument"]
    record = process_runner.run_child("missing", command, timeout=15)
    _check_record(process_runner, "missing", command, record, b"")
    assert record["outcome"] == "spawn_failure"
    assert record["exit_code"] is None
    error = record["spawn_error"]
    assert error["type"] == "FileNotFoundError"
    assert type(error["message"]) is str and error["message"]
    assert error["errno"] == errno.ENOENT
    assert error["winerror"] == (2 if sys.platform == "win32" else None)


def test_real_timeout_retains_partial_merged_output_without_invented_exit(process_runner):
    command = [sys.executable, "-B", "-c",
               "import os, time; os.write(1, b'TIMEOUT_STDOUT\\n'); "
               "os.write(2, b'TIMEOUT_STDERR\\n'); time.sleep(30)"]
    record = process_runner.run_child("timeout", command, timeout=2)
    _check_record(process_runner, "timeout", command, record, b"TIMEOUT_STDOUT\nTIMEOUT_STDERR\n")
    assert record["outcome"] == "timeout"
    assert record["exit_code"] is None


@pytest.mark.parametrize("existing", ("output.log", "process.json"))
def test_existing_child_artifact_is_refused_before_launch(process_runner, monkeypatch, existing):
    stage = "preserved"
    prior = process_runner.HERE / (stage + "." + existing)
    prior.write_bytes(b"immutable previous child evidence")
    launches = []

    def refuse_launch(*args, **kwargs):
        launches.append((args, kwargs))
        pytest.fail("existing output was checked after child launch")

    monkeypatch.setattr(subprocess, "run", refuse_launch)
    monkeypatch.setattr(subprocess, "Popen", refuse_launch)
    with pytest.raises(ValueError, match="output already exists"):
        process_runner.run_child(stage, [sys.executable, "-B", "-c", "raise SystemExit(0)"], timeout=15)
    assert launches == []
    assert prior.read_bytes() == b"immutable previous child evidence"
    assert sorted(path.name for path in process_runner.HERE.iterdir()) == [prior.name]


def test_child_boundary_uses_merged_binary_capture_and_unmodified_command(process_runner, monkeypatch):
    command = ["arbitrary-reviewed-child", "literal-argument"]
    calls = []

    def child_io(actual, **kwargs):
        calls.append((actual, kwargs))
        assert actual == command
        assert kwargs["cwd"] == process_runner.ROOT
        assert kwargs["stdout"] is subprocess.PIPE
        assert kwargs["stderr"] is subprocess.STDOUT
        assert kwargs["timeout"] == 3.5
        assert not kwargs.get("text", False)
        assert not kwargs.get("universal_newlines", False)
        return subprocess.CompletedProcess(actual, 0, b"EXACT_MERGED_BOUNDARY\n", None)

    monkeypatch.setattr(subprocess, "run", child_io)
    record = process_runner.run_child("boundary", command, timeout=3.5)
    _check_record(process_runner, "boundary", command, record, b"EXACT_MERGED_BOUNDARY\n")
    assert len(calls) == 1
    assert record["outcome"] == "finished" and record["exit_code"] == 0
