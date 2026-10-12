"""Actual-main transport controls with fake Popen/WinAPI; never native evidence.

The synthetic fixture/body only reaches the draft's existing execute boundary.
Audit completion admission is simulated only to reach that observer; it does
not prove a completed audit or stopped native actors.
Original FAIL-binding controls remain separate and unchanged.
"""
import ctypes
import json
from pathlib import Path
import runpy
import subprocess
from types import SimpleNamespace

import pytest


HERE = Path(__file__).resolve().parent
DRAFT = HERE / "run_original_body_once.py"


def control(tmp_path, monkeypatch, *, wait=0, readers=True, api_error=None,
            timeout=True, cleanup_error=None, first_error=None, own=False,
            creation_error=None):
    context = runpy.run_path(str(DRAFT), run_name="_timeout_lifetime_control")["main"].__globals__
    context["load_existing_audit_admission"] = lambda: {"scope": "CONTROL_ONLY_NOT_NATIVE_ACTOR_STOP"}
    events, outputs, processes, active = [], {}, [], [False]
    source, session = "controlled stdin", b"controlled session"
    (tmp_path / "session-context.data").write_bytes(session)
    primary = subprocess.TimeoutExpired(["controlled"], 160)
    filetimes = (0x100000002, 0x300000004, 0x500000006, 0x700000008)

    class Fixture:
        def __init__(self):
            self.root, self.q = tmp_path, {}
            self.scripts = {name: source for name in context["PHASES"]}
            self.manifest = {"candidate_sha256": "control-only", "candidate": {"files": []}}

        @classmethod
        def setUpClass(cls):
            pass

        def setUp(self):
            pass

        def run_script(self, name, process_runner):
            return process_runner(source, ["controlled-session-path", context["identity"].sha(session)])

    class Reader:
        def __init__(self, name, alive):
            self.name, self.alive = name, alive

        def is_alive(self):
            events.append(("reader", self.name))
            return self.alive

    class Process:
        _handle, pid = 0x1234567887654321, 1234

        def __init__(self, args, **kwargs):
            events.append(("Popen", subprocess.Popen is not factory, args, kwargs))
            if creation_error:
                raise creation_error
            self.args, self.calls, self.returncode = args, 0, None
            if readers:
                self.stdout_thread, self.stderr_thread = Reader("stdout", True), Reader("stderr", False)
            if own:
                self.communicate = self.communicate
            self.before_own = self.__dict__.get("communicate")
            processes.append(self)

        def __enter__(self):
            active[0] = True
            events.append(("enter",))
            return self

        def __exit__(self, *args):
            active[0] = False
            events.append(("exit",))

        def communicate(self, *args, **kwargs):
            self.calls += 1
            events.append(("communicate", args, kwargs,
                           self.__dict__.get("communicate") is not self.before_own))
            if self.calls == 1:
                if first_error:
                    raise first_error
                if timeout:
                    raise primary
                return b"normal stdout", b"normal stderr"
            if cleanup_error:
                raise cleanup_error
            return b"cleanup stdout", b"cleanup stderr"

        def kill(self):
            events.append(("kill",))

        def poll(self):
            events.append(("poll",))
            return 0

    def factory(*args, **kwargs):
        return Process(*args, **kwargs)

    def get_times(handle, *values):
        events.append(("GetProcessTimes", handle))
        if api_error:
            raise api_error
        for pointer, ticks in zip(values, filetimes):
            pointer._obj.dwLowDateTime = ticks & 0xffffffff
            pointer._obj.dwHighDateTime = ticks >> 32
        return True

    def wait_zero(handle, milliseconds):
        events.append(("WaitForSingleObject", handle, milliseconds))
        return wait

    def exit_code(handle):
        events.append(("GetExitCodeProcess", handle))
        return 7 if wait == 0 else 259

    def retain(path, raw):
        # Any observer write before original run exits is an immediate failure.
        if active[0]:
            raise AssertionError("output written inside original run")
        assert subprocess.Popen is factory
        outputs[Path(path).name] = raw

    original_is_file = Path.is_file
    admin = context["ROOT"] / "build/peer-route-review-20261011-host-fixed/admin-launch-result.json"
    monkeypatch.setattr(Path, "is_file", lambda path: True if path == admin
                        else original_is_file(path))
    monkeypatch.setattr(context["sys"], "argv", [str(DRAFT)])
    monkeypatch.setattr(subprocess, "Popen", factory)
    monkeypatch.setattr(ctypes, "WinDLL", lambda *args, **kwargs: SimpleNamespace(GetProcessTimes=get_times))
    monkeypatch.setitem(context["sys"].modules, "_winapi",
                        SimpleNamespace(WaitForSingleObject=wait_zero, GetExitCodeProcess=exit_code))
    context.update(HERE=tmp_path, PeerInstallTests=Fixture, write_output=retain,
                   retain_observation=lambda *args: None,
                   original_body=lambda fixture: fixture.run_script("install-files.sh"))
    return SimpleNamespace(main=context["main"], events=events, outputs=outputs,
                           processes=processes, factory=factory, primary=primary,
                           filetimes=filetimes, source=source)


def restored(case):
    assert subprocess.Popen is case.factory
    for process in case.processes:
        if process.before_own is None:
            assert "communicate" not in process.__dict__
        else:
            assert process.__dict__["communicate"] is process.before_own
    report = json.loads(case.outputs["result.json"])
    frozen = "655e219d41b6c6dd4b6f994ab3a89ed76cf41e0d09d4191d37fe53ba4fec79b5"
    assert report["source_inputs_before_sha256"] == report["source_inputs_after_sha256"] == frozen
    assert report["source_inputs_unchanged"] is True
    return report


@pytest.mark.parametrize("wait,readers", [(0, True), (258, False), (0xffffffff, False)],
                         ids=["exited-reader-alive", "active-readers-unknown", "unknown-wait"])
def test_first_timeout_samples_same_handle_before_original_cleanup(tmp_path, monkeypatch, wait, readers):
    case = control(tmp_path, monkeypatch, wait=wait, readers=readers)
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        case.main()
    assert caught.value is case.primary
    assert (caught.value.stdout, caught.value.stderr) == (b"cleanup stdout", b"cleanup stderr")
    report = restored(case)
    sample = report["calls"][0]["pre_original_timeout_cleanup"]
    assert sample["pid"] == 1234
    assert sample["clock_before"] <= sample["clock_after"]
    assert sample["filetime_100ns"] == dict(zip(("creation", "exit", "kernel", "user"),
                                              map(str, case.filetimes)))
    assert sample["wait_zero_result"] == wait
    assert sample["exit_code_or_still_active"] == (7 if wait == 0 else 259)
    assert sample["reader_threads"] == {
        "stdout_thread": {"exists": readers, "is_alive": True if readers else None},
        "stderr_thread": {"exists": readers, "is_alive": False if readers else None},
    }
    names = [event[0] for event in case.events]
    assert names == ["Popen", "enter", "communicate", *(["reader", "reader"] if readers else []),
                     "GetProcessTimes", "WaitForSingleObject", "GetExitCodeProcess",
                     "kill", "communicate", "exit"]
    assert case.events[0][1] is True
    assert case.events[0][2] == report["calls"][0]["argv"]
    assert case.events[0][3] == {"stdin": subprocess.PIPE, "stdout": subprocess.PIPE, "stderr": subprocess.PIPE}
    communicates = [event for event in case.events if event[0] == "communicate"]
    assert communicates == [("communicate", (case.source.encode("ascii"),), {"timeout": 160}, True),
                            ("communicate", (), {}, True)]
    native = [event for event in case.events if event[0] in
              ("GetProcessTimes", "WaitForSingleObject", "GetExitCodeProcess")]
    assert all(event[1] == case.processes[0]._handle for event in native)
    assert native[1][2] == 0
    assert report["all_original_assertions_completed"] is False


def test_sampling_failure_keeps_original_timeout_cleanup_and_partial_unknowns(tmp_path, monkeypatch):
    case = control(tmp_path, monkeypatch, api_error=OSError("controlled WinAPI failure"))
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        case.main()
    assert caught.value is case.primary
    report = restored(case)
    sample = report["calls"][0]["pre_original_timeout_cleanup"]
    assert sample["filetime_100ns"] is None and sample["wait_zero_result"] is None
    assert sample["exit_code_or_still_active"] is None
    assert sample["clock_before"] <= sample["clock_after"]
    assert "controlled WinAPI failure" in sample["sampling_error"]
    assert len(report["auxiliary_failures"]) == 1
    assert report["diagnostic_retention_complete"] is False
    assert [event[0] for event in case.events][-3:] == ["kill", "communicate", "exit"]
    assert case.processes[0].calls == 2


def test_unformattable_sampling_error_cannot_replace_original_timeout(tmp_path, monkeypatch):
    class BadRepresentation(OSError):
        def __repr__(self):
            raise RuntimeError("auxiliary exception formatting failed")

    case = control(tmp_path, monkeypatch, api_error=BadRepresentation("sample failure"))
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        case.main()
    assert caught.value is case.primary
    report = restored(case)
    assert report["failure"]["type"] == "TimeoutExpired"
    assert report["diagnostic_retention_complete"] is False
    assert "BadRepresentation" in report["calls"][0]["pre_original_timeout_cleanup"]["sampling_error"]
    assert [event[0] for event in case.events][-3:] == ["kill", "communicate", "exit"]
    assert case.processes[0].calls == 2


def test_sampling_error_recording_failure_cannot_change_original_cleanup(tmp_path, monkeypatch):
    class BadName(type):
        failing = True

        def __getattribute__(cls, name):
            if name == "__name__" and BadName.failing:
                raise RuntimeError("diagnostic error typename lookup failed")
            return super().__getattribute__(name)

    class BadDescription(OSError, metaclass=BadName):
        def __repr__(self):
            raise RuntimeError("diagnostic repr failed")

    case = control(tmp_path, monkeypatch, api_error=BadDescription("sample failure"))
    caught = None
    try:
        case.main()
    except BaseException as error:
        caught = error
    finally:
        # Do not let the deliberate metadata fault break pytest's own report
        # formatting or prevent the filesystem/Popen boundary fixture teardown.
        BadName.failing = False
    assert caught is case.primary
    report = restored(case)
    assert report["failure"]["type"] == "TimeoutExpired"
    assert report["diagnostic_retention_complete"] is False
    assert [event[0] for event in case.events][-3:] == ["kill", "communicate", "exit"]
    assert case.processes[0].calls == 2


def test_original_cleanup_failure_is_not_replaced_by_sampling_failure(tmp_path, monkeypatch):
    failure = LookupError("original cleanup failure")
    case = control(tmp_path, monkeypatch, api_error=OSError("sample failure"), cleanup_error=failure)
    with pytest.raises(LookupError) as caught:
        case.main()
    assert caught.value is failure
    report = restored(case)
    assert len(report["auxiliary_failures"]) == 1
    assert [event[0] for event in case.events][-3:] == ["kill", "communicate", "exit"]


@pytest.mark.parametrize("own", [False, True], ids=["inherited-method", "existing-instance-method"])
def test_normal_call_has_no_sample_and_restores_communicate(tmp_path, monkeypatch, own):
    case = control(tmp_path, monkeypatch, timeout=False, own=own)
    case.main()
    report = restored(case)
    assert "pre_original_timeout_cleanup" not in report["calls"][0]
    assert [event[0] for event in case.events] == ["Popen", "enter", "communicate", "poll", "exit"]
    assert case.events[0][1] is True and case.events[2][3] is True


def test_non_timeout_exception_keeps_original_cleanup_and_restoration(tmp_path, monkeypatch):
    failure = RuntimeError("original communicate failure")
    case = control(tmp_path, monkeypatch, first_error=failure)
    with pytest.raises(RuntimeError) as caught:
        case.main()
    assert caught.value is failure
    report = restored(case)
    assert "pre_original_timeout_cleanup" not in report["calls"][0]
    assert [event[0] for event in case.events] == ["Popen", "enter", "communicate", "kill", "exit"]
    assert case.events[0][1] is True and case.events[2][3] is True


def test_constructor_failure_restores_popen_without_invented_sample(tmp_path, monkeypatch):
    failure = OSError("original creation failure")
    case = control(tmp_path, monkeypatch, creation_error=failure)
    with pytest.raises(OSError) as caught:
        case.main()
    assert caught.value is failure
    report = restored(case)
    assert "pre_original_timeout_cleanup" not in report["calls"][0]
    assert len(case.events) == 1 and case.events[0][1] is True
