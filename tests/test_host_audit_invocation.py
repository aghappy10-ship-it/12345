"""Actual fixed main invocation seam, not a full audit or camera execution."""
import hashlib
import json
from pathlib import Path
import sys
import types

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "build/peer-route-review-20261011-host-fixed/run_audit.py"


def load_current():
    raw = RUNNER.read_bytes()
    module = types.ModuleType("fixed_audit_invocation_control")
    module.__file__ = str(RUNNER)
    exec(compile(raw, str(RUNNER), "exec"), module.__dict__)
    return module, hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize("action", ("--suite", "--collect"))
def test_actual_main_routes_only_suite_to_new_project_local_basetemp(
        tmp_path, monkeypatch, record_property, action):
    assert sys.dont_write_bytecode and not sys.flags.optimize
    runner, source_hash = load_current()
    runner.HERE = tmp_path
    preflights, calls = [], []
    runner.preflight = lambda label: preflights.append(label) or {"local_control": True}
    def capture(arguments, *, plugins):
        calls.append((arguments, plugins))
        return 37
    monkeypatch.setattr(pytest, "main", capture)
    assert runner.main([action]) == 37
    assert preflights == [action[2:]] and len(calls) == 1
    arguments, plugins = calls[0]
    observed = [argument for argument in arguments if argument.startswith("--basetemp=")]
    expected = ["--basetemp=" + str(tmp_path / "suite-basetemp")] if action == "--suite" else []
    record_property("actual_invocation", json.dumps({"runner_sha256": source_hash,
        "arguments": arguments, "action": action, "observed_basetemp": observed,
        "full_pytest_execution": False, "preflight_modeled": True,
        "camera_accesses": 0, "installable": False}, sort_keys=True))
    assert observed == expected
    expected_arguments = (["--collect-only", "-q", "-p", "no:cacheprovider", "tests"]
        if action == "--collect" else ["-q", "-p", "no:cacheprovider", "tests",
            "--basetemp=" + str(tmp_path / "suite-basetemp"),
            "--junitxml=" + str(tmp_path / "full-offline-suite.xml")])
    assert arguments == expected_arguments
    assert len(plugins) == 1 and not (tmp_path / "suite-basetemp").exists()
    assert type(plugins[0]) is (runner.Collect if action == "--collect" else runner.Execution)
    assert hashlib.sha256(RUNNER.read_bytes()).hexdigest() == source_hash


def test_actual_suite_refuses_preexisting_basetemp_before_preflight_or_pytest(
        tmp_path, monkeypatch):
    runner, source_hash = load_current()
    runner.HERE = tmp_path
    existing = tmp_path / "suite-basetemp"
    existing.mkdir()
    sentinel = existing / "owned-by-user.data"
    sentinel.write_bytes(b"PRESERVE_EXISTING_TEST_DATA\n")
    original_identity = (existing.stat().st_ino, sentinel.stat().st_ino, sentinel.read_bytes())
    calls = []
    runner.preflight = lambda label: calls.append(("preflight", label)) or True
    monkeypatch.setattr(pytest, "main", lambda *a, **kw: calls.append(("pytest", a)) or 0)
    with pytest.raises(ValueError, match="output already exists"):
        runner.main(["--suite"])
    assert calls == []
    assert (existing.stat().st_ino, sentinel.stat().st_ino, sentinel.read_bytes()) == original_identity
    assert hashlib.sha256(RUNNER.read_bytes()).hexdigest() == source_hash


def test_actual_suite_preflight_failure_never_runs_pytest_or_creates_basetemp(
        tmp_path, monkeypatch):
    runner, source_hash = load_current()
    runner.HERE = tmp_path
    calls = []
    runner.preflight = lambda label: None
    monkeypatch.setattr(pytest, "main", lambda *a, **kw: calls.append(a))
    assert runner.main(["--suite"]) == 1
    assert calls == [] and not (tmp_path / "suite-basetemp").exists()
    assert hashlib.sha256(RUNNER.read_bytes()).hexdigest() == source_hash
