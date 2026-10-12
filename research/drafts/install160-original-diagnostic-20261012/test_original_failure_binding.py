"""Public diagnostic-entry controls; no native shell or audit is executed.

Completion admission, filesystem evidence and subprocess.run are substituted
only to reach the independent failure-binding controls. New admission controls
exercise refusal/delegation separately; no audit/workload completion is proved.
"""
import hashlib
import json
from pathlib import Path
import runpy
import subprocess

import pytest


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DRAFT = HERE / "run_original_body_once.py"
FAILURE = ROOT / "build/peer-route-review-20261011-host-fixed/failure-0001.json"
ADMIN = FAILURE.parent / "admin-launch-result.json"
ORIGINAL_RAW = FAILURE.read_bytes()
SHARED = HERE.parent / "receipt360-original-diagnostic-20261012/run_original_sender_once.py"
SIMULATED_COMPLETION = {"scope": "CONTROL_ONLY_NOT_NATIVE_ACTOR_STOP"}


@pytest.fixture(autouse=True)
def exact_control_bindings(record_property):
    record_property("diagnostic_draft_sha256", hashlib.sha256(DRAFT.read_bytes()).hexdigest())
    record_property("control_sha256", hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    record_property("shared_admission_sha256", hashlib.sha256(SHARED.read_bytes()).hexdigest())
    record_property("execution_scope", "pure_boundary_control_not_native_admission")


class NativeExecutionBlocked(RuntimeError):
    pass


def entry(tmp_path, monkeypatch, raw):
    namespace = runpy.run_path(str(DRAFT), run_name="_failure_binding_control")
    context = namespace["main"].__globals__
    context["HERE"] = tmp_path
    context["load_existing_audit_admission"] = lambda: SIMULATED_COMPLETION
    original_read = Path.read_bytes
    original_is_file = Path.is_file

    def read_bytes(path):
        if path == FAILURE:
            if raw is None:
                raise FileNotFoundError(str(path))
            return raw
        return original_read(path)

    def is_file(path):
        if path == ADMIN:
            return True
        return original_is_file(path)

    def block_native(*args, **kwargs):
        raise NativeExecutionBlocked("external process boundary reached; not executed")

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    monkeypatch.setattr(Path, "is_file", is_file)
    monkeypatch.setattr(subprocess, "run", block_native)
    monkeypatch.setattr(context["sys"], "argv", [str(DRAFT)])
    return namespace["main"]


@pytest.mark.parametrize("raw", [None, ORIGINAL_RAW + b" "], ids=["missing", "changed-byte"])
def test_unbound_original_failure_is_refused_before_native_execution(tmp_path, monkeypatch, raw):
    main = entry(tmp_path, monkeypatch, raw)
    with pytest.raises(ValueError, match="original failure"):
        main()
    assert not (tmp_path / "inputs-before.json").exists()
    assert not (tmp_path / "result.json").exists()


def test_original_failure_bytes_are_retained_before_external_process_boundary(tmp_path, monkeypatch):
    main = entry(tmp_path, monkeypatch, ORIGINAL_RAW)
    with pytest.raises(NativeExecutionBlocked):
        main()
    assert (tmp_path / "original-failure-0001.json").read_bytes() == ORIGINAL_RAW
    report = json.loads((tmp_path / "result.json").read_text())
    assert report["original_failure_reference"] == {
        "source": str(FAILURE),
        "sha256": "89dd9c0ca2903bf356102b3fb377a9011272d848ef30971dc7b3c5813b9acea7",
        "saved_file": "original-failure-0001.json",
    }
    assert report["all_original_assertions_completed"] is False


def test_existing_failure_archive_is_preserved_without_native_execution(tmp_path, monkeypatch):
    main = entry(tmp_path, monkeypatch, ORIGINAL_RAW)
    target = tmp_path / "original-failure-0001.json"
    target.write_bytes(b"owned earlier evidence")
    with pytest.raises((ValueError, FileExistsError)):
        main()
    assert target.read_bytes() == b"owned earlier evidence"
    assert not (tmp_path / "result.json").exists()


@pytest.mark.parametrize("failure", [ValueError("audit remains active"), OSError("admission load failed")],
                         ids=["incomplete-audit", "loader-exception"])
def test_completion_refusal_precedes_outputs_fixture_and_native(tmp_path, monkeypatch, failure):
    main = entry(tmp_path, monkeypatch, ORIGINAL_RAW)
    calls = []

    def refuse():
        calls.append("admission")
        raise failure

    def forbidden_fixture():
        pytest.fail("fixture was created before completion admission")

    main.__globals__.update(load_existing_audit_admission=refuse, PeerInstallTests=forbidden_fixture)
    with pytest.raises(type(failure)) as caught:
        main()
    assert caught.value is failure and calls == ["admission"]
    assert list(tmp_path.iterdir()) == []


def test_simulated_completion_is_delegated_before_existing_native_boundary(tmp_path, monkeypatch):
    main = entry(tmp_path, monkeypatch, ORIGINAL_RAW)
    calls = []

    def admit():
        calls.append("admission")
        return SIMULATED_COMPLETION

    main.__globals__["load_existing_audit_admission"] = admit
    with pytest.raises(NativeExecutionBlocked):
        main()
    report = json.loads((tmp_path / "result.json").read_text())
    assert calls == ["admission"] and report["audit_admission"] == SIMULATED_COMPLETION
    assert report["installable"] is False and report["all_original_assertions_completed"] is False


def test_shared_loader_delegates_exact_definitions_without_main(monkeypatch):
    context = runpy.run_path(str(DRAFT), run_name="_admission_loader_control")["main"].__globals__
    calls, runner = [], object()

    def definitions_only(code, namespace):
        assert namespace["__name__"] != "__main__" and Path(namespace["__file__"]) == SHARED
        calls.append("definitions")
        namespace["load_reviewed_runner"] = lambda: runner

        def completed(actual):
            assert actual is runner
            calls.append("existing-gate")
            return SIMULATED_COMPLETION, None, None, None

        namespace["require_completed_audit"] = completed

    context["exec"] = definitions_only  # Only this loader's execution boundary is substituted.
    assert context["load_existing_audit_admission"]() is SIMULATED_COMPLETION
    assert calls == ["definitions", "existing-gate"]


@pytest.mark.parametrize("raw", [None, SHARED.read_bytes() + b" "], ids=["missing", "changed-byte"])
def test_shared_loader_missing_or_changed_bytes_fail_closed(monkeypatch, raw):
    context = runpy.run_path(str(DRAFT), run_name="_admission_load_failure_control")["main"].__globals__
    original_read = Path.read_bytes

    def read_bytes(path):
        if path == SHARED:
            if raw is None:
                raise FileNotFoundError(str(path))
            return raw
        return original_read(path)

    context["exec"] = lambda *args: pytest.fail("unbound admission definitions were executed")
    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    with pytest.raises(FileNotFoundError if raw is None else ValueError):
        context["load_existing_audit_admission"]()


@pytest.mark.parametrize("scenario", [
    "closed", "closed-X", "worker-live", "controller-live", "child-live", "unknown",
    "read-failed", "truncated", "command-error", "command-timeout", "stderr",
    "missing-capture", "changed-capture", "capture-changed-after", "cleanup-incomplete",
])
def test_fixed_original_actor_stop_boundary_is_fail_closed(monkeypatch, scenario):
    context = runpy.run_path(str(SHARED), run_name="_fixed_actor_stop_control")["main"].__globals__
    failure = json.loads((FAILURE.parent / "failure-0005.json").read_bytes())
    captures = {
        "worker": ("1696", "803676787", "proc/1696/host-stat"),
        "controller": ("2414", "803702039", "proc/2414/host-stat"),
        "child": ("8389", "803908014", "test-child-host-stat"),
    }
    archive = ROOT / "build/gui-guardian-failures/fixture-ojn44xoe"
    self_raw = "999 (sampler) S " + "0 " * 18 + "1 0"
    proc_anchor = "PROC_ANCHOR sampler_pid=999 ticks=1 root=available raw=" + self_raw
    output = ["SAMPLE_BEGIN sampler_pid=999 epoch=1.0", proc_anchor]
    for role, (pid, ticks, leaf) in captures.items():
        output.append(f"BEGIN pid={pid} expected_ticks={ticks} epoch=1.1")
        if role == "worker" and scenario not in ("worker-live", "unknown", "read-failed"):
            output.append(f"END pid={pid} epoch=1.2 status=absent")
        elif role == "worker" and scenario in ("unknown", "read-failed"):
            status = "malformed" if scenario == "unknown" else "read_failed"
            output.append(f"END pid={pid} epoch=1.2 status={status}")
        else:
            tail = (archive / leaf).read_text().rsplit(") ", 1)[1].split()
            tail[0] = "S" if scenario == role + "-live" else "Z"
            if role == "child" and scenario == "closed-X":
                tail[0] = "X"
            if role == "controller" and scenario != "controller-live":
                tail[0], tail[19] = "S", "803702040"  # A different birth is not the original actor.
            raw = pid + " (sh) " + " ".join(tail)
            output.append(f"END pid={pid} epoch=1.2 status=observed state={tail[0]} "
                          f"ppid={tail[1]} ticks={tail[19]} expected_ticks={ticks} raw={raw}")
    output += [proc_anchor, "SAMPLE_END sampler_pid=999 epoch=1.3"]
    if scenario == "truncated":
        output.pop()
    calls = []

    def native_boundary(command, **options):
        calls.append((command, options))
        if scenario == "command-timeout":
            raise subprocess.TimeoutExpired(command, 8)
        return subprocess.CompletedProcess(command, 1 if scenario == "command-error" else 0,
            "\n".join(output) + "\n", "unexpected stderr" if scenario == "stderr" else "")

    original_read = Path.read_bytes
    reads = []
    target = archive / "proc/1696/host-stat"

    def evidence_read(path):
        raw = original_read(path)
        if path == target:
            reads.append(path)
            if scenario == "missing-capture":
                raise FileNotFoundError(str(path))
            if scenario == "changed-capture" or (scenario == "capture-changed-after" and len(reads) > 1):
                return raw + b" "
        return raw

    monkeypatch.setattr(subprocess, "run", native_boundary)
    monkeypatch.setattr(Path, "read_bytes", evidence_read)
    if scenario == "cleanup-incomplete":
        failure["longrepr"] += "\nGuardian cleanup incomplete: controlled failure"
    if scenario in ("closed", "closed-X"):
        evidence = context["require_original_actor_stop"](failure)
        assert [row["state"] for row in evidence["actors"]] == ["absent", "reused", "X" if scenario == "closed-X" else "Z"]
        assert evidence["capture_before"] == evidence["capture_after"]
        assert len(evidence["capture_before"]) == 6
        assert evidence["clock_before"] <= evidence["clock_after"]
        assert evidence["only_fixed_original_failure5_actors"] is True
    else:
        expected = subprocess.TimeoutExpired if scenario == "command-timeout" else (
            FileNotFoundError if scenario == "missing-capture" else ValueError)
        with pytest.raises(expected):
            context["require_original_actor_stop"](failure)
    if scenario in ("missing-capture", "changed-capture", "cleanup-incomplete"):
        assert calls == []
    else:
        assert len(calls) == 1
        command, options = calls[0]
        assert command[3:] == ["timestamped-original-failure5-actor-stop", "1696", "803676787",
                               "2414", "803702039", "8389", "803908014"]
        assert "kill" not in command[2] and "wait" not in command[2]
        assert options == {"capture_output": True, "text": True, "timeout": 8}


@pytest.mark.parametrize("availability", ["missing-anchor", "unknown-anchor"])
def test_missing_or_unknown_proc_anchor_cannot_promote_absence(monkeypatch, availability):
    context = runpy.run_path(str(SHARED), run_name="_proc_anchor_control")["main"].__globals__
    failure = json.loads((FAILURE.parent / "failure-0005.json").read_bytes())
    output = ["SAMPLE_BEGIN sampler_pid=999 epoch=1.0"]
    for pid, ticks in (("1696", "803676787"), ("2414", "803702039"), ("8389", "803908014")):
        output += [f"BEGIN pid={pid} expected_ticks={ticks} epoch=1.1",
                   f"END pid={pid} epoch=1.2 status=absent"]
    output.append("SAMPLE_END sampler_pid=999 epoch=1.3")
    if availability == "unknown-anchor":
        output.insert(1, "PROC_ANCHOR sampler_pid=999 ticks=1 root=unknown raw=unavailable")
        output.insert(-1, "PROC_ANCHOR sampler_pid=999 ticks=1 root=unknown raw=unavailable")
    calls = []

    def native_boundary(command, **options):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "\n".join(output) + "\n", "")

    monkeypatch.setattr(subprocess, "run", native_boundary)
    with pytest.raises(ValueError):
        context["require_original_actor_stop"](failure)
    assert len(calls) == 1
