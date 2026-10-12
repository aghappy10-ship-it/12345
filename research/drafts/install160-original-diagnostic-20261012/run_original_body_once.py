"""Preserve one original install160 failure; no changed shell, budget or camera.

Adapted from the existing original-body diagnostic. Run only after the active
complete audit ends, to avoid contaminating its timing with another shell test.
The original body and assertions run unchanged. This is not release evidence.
"""
from datetime import datetime, timezone
import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tests.test_peer_install import PeerInstallTests, SH
from tests.test_install_core_runtime import (
    test_distinct_capture_owner_normal_install_activate_and_restore as original_body,
)
from tools import release_identity as identity
from tools.output_guard import guard_output

HERE = Path(__file__).resolve().parent
PHASES = ("install-files.sh", "activate-boot.sh", "restore-boot.sh")
EXPECTED_INPUTS_SHA = "655e219d41b6c6dd4b6f994ab3a89ed76cf41e0d09d4191d37fe53ba4fec79b5"
ORIGINAL_NODE = "tests/test_install_core_runtime.py::test_distinct_capture_owner_normal_install_activate_and_restore"
ORIGINAL_FAILURE = ROOT / "build/peer-route-review-20261011-host-fixed/failure-0001.json"
ORIGINAL_FAILURE_SHA = "89dd9c0ca2903bf356102b3fb377a9011272d848ef30971dc7b3c5813b9acea7"
OBSERVATION_FILES = ("operations", "proc/mounts", "gui-service-state",
                     "core-service-state", "session-context.data")


def load_existing_output_writer():
    """Reuse the reviewed Windows no-overwrite writer; never run its audit."""
    path = ROOT / "build/peer-route-review-20261011-host-fixed/run_audit.py"
    raw = path.read_bytes()
    if identity.sha(raw) != "3d45dafca02e42499ef0322c3e23ca750f407824e2ca0f1c1d45c49e6930fb19":
        raise ValueError("reviewed diagnostic output writer changed")
    namespace = {"__name__": "_original_body_output_writer", "__file__": str(path)}
    exec(compile(raw, str(path), "exec"), namespace)
    return namespace["write_output"]


write_output = load_existing_output_writer()


def load_existing_audit_admission():
    """Delegate the pinned completed-audit gate, never the sender diagnostic."""
    path = ROOT / "build/receipt360-original-diagnostic-20261012/run_original_sender_once.py"
    raw = path.read_bytes()
    if identity.sha(raw) != "59c31985f48fab2723cacc5c6f3996c6aa36d2e48a0fb5f9abd4ecae1eddecbf":
        raise ValueError("reviewed shared audit admission source changed")
    namespace = {"__name__": "_shared_original_audit_admission", "__file__": str(path)}
    exec(compile(raw, str(path), "exec"), namespace)
    runner = namespace["load_reviewed_runner"]()
    return namespace["require_completed_audit"](runner)[0]


def save_json(name, value):
    write_output(HERE / name, (json.dumps(value, indent=2) + "\n").encode())


def safe_description(error):
    try:
        return repr(error)
    except BaseException:
        try:
            return "<" + type(error).__name__ + ": repr unavailable>"
        except BaseException:
            return "<auxiliary exception description unavailable>"


def native_sample(process, sample):
    """Sequential same-handle facts only; no process or pipe state is changed."""
    sample.update(pid=process.pid, clock_before=time.monotonic(),
                  filetime_100ns=None, wait_zero_result=None, exit_code_or_still_active=None)
    try:
        import _winapi
        sample["reader_threads"] = {}
        for name in ("stdout_thread", "stderr_thread"):
            thread = getattr(process, name, None)
            sample["reader_threads"][name] = {"exists": hasattr(process, name),
                "is_alive": None if thread is None else thread.is_alive()}
        times = ctypes.WinDLL("kernel32", use_last_error=True).GetProcessTimes
        times.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        times.restype = wintypes.BOOL
        values = [wintypes.FILETIME() for _ in range(4)]
        if not times(process._handle, *(ctypes.byref(value) for value in values)):
            raise ctypes.WinError(ctypes.get_last_error())
        sample["filetime_100ns"] = {name: str((value.dwHighDateTime << 32) | value.dwLowDateTime)
            for name, value in zip(("creation", "exit", "kernel", "user"), values)}
        sample["wait_zero_result"] = _winapi.WaitForSingleObject(process._handle, 0)
        sample["exit_code_or_still_active"] = _winapi.GetExitCodeProcess(process._handle)
    finally:
        sample["clock_after"] = time.monotonic()


def retain_observation(fixture, phase, point):
    """After-return/after-exception observation, NOT an exact deadline snapshot."""
    rows = {}
    for relative in OBSERVATION_FILES:
        path = fixture.root / relative
        if path.is_symlink():
            rows[relative] = {"observed": "nonregular_not_read"}
        elif not path.exists():
            rows[relative] = {"observed": "absent"}
        elif not path.is_file():
            rows[relative] = {"observed": "nonregular_not_read"}
        else:
            raw = path.read_bytes()
            name = phase + "." + relative.replace("/", "-")
            write_output(HERE / name, raw)
            rows[relative] = {"observed": "read", "bytes": len(raw),
                              "sha256": identity.sha(raw), "saved_file": name}
    targets = {}
    for entry in fixture.manifest["candidate"]["files"]:
        path = fixture.root / entry["target"].lstrip("/")
        if path.is_symlink():
            targets[entry["target"]] = {"observed": "nonregular_not_read"}
        elif not path.exists():
            targets[entry["target"]] = {"observed": "absent"}
        elif not path.is_file():
            targets[entry["target"]] = {"observed": "nonregular_not_read"}
        else:
            raw = path.read_bytes()
            targets[entry["target"]] = {"observed": "read", "bytes": len(raw),
                                        "sha256": identity.sha(raw)}
    save_json(phase + ".observation.json", {
        "point": point, "observed_utc": datetime.now(timezone.utc).isoformat(),
        "files": rows, "targets": targets,
        "limits": "Not atomic; no original inode, native lifetime or deadline-state claim",
    })


def main():
    if sys.argv[1:]:
        raise ValueError("this original-body diagnostic takes no arguments")
    try:
        failure_raw = ORIGINAL_FAILURE.read_bytes()
        failure = json.loads(failure_raw)
    except (OSError, ValueError) as error:
        raise ValueError("original failure record is missing or unreadable") from error
    if (identity.sha(failure_raw) != ORIGINAL_FAILURE_SHA or type(failure) is not dict
            or failure.get("nodeid") != ORIGINAL_NODE or failure.get("when") != "call"
            or failure.get("outcome") != "failed" or failure.get("qualification") is not False):
        raise ValueError("original failure record binding differs")
    audit_admission = load_existing_audit_admission()
    for name in ("result.json", "inputs-before.json", "inputs-after.json", "original-failure-0001.json",
                 *(phase + suffix for phase in PHASES for suffix in
                   (".host-source", ".session", ".context.json", ".stdout",
                    ".stderr", ".observation.json")),
                 *(phase + "." + relative.replace("/", "-")
                   for phase in PHASES for relative in OBSERVATION_FILES)):
        guard_output(HERE / name, must_be_new=True)
    before = identity.source_inputs()
    if len(before) != 230 or identity.sha(identity.canonical(before)) != EXPECTED_INPUTS_SHA:
        raise ValueError("original failure source identity changed; do not reuse this diagnostic")
    write_output(HERE / "original-failure-0001.json", failure_raw)
    save_json("inputs-before.json", before)
    report = {
        "scope": "original-body diagnostic only; no release or camera qualification",
        "audit_admission": audit_admission,
        "original_node": ORIGINAL_NODE,
        "original_failure_reference": {"source": str(ORIGINAL_FAILURE), "sha256": ORIGINAL_FAILURE_SHA,
                                       "saved_file": "original-failure-0001.json"},
        "original_test_sha256": identity.sha((ROOT / "tests/test_install_core_runtime.py").read_bytes()),
        "script_sha256": identity.sha(Path(__file__).read_bytes()),
        "shell": {"path": str(SH), "sha256": identity.sha(SH.read_bytes())},
        "source_inputs_before_sha256": identity.sha(identity.canonical(before)),
        "calls": [], "all_original_assertions_completed": False,
        "auxiliary_failures": [],
        "camera_accesses": 0, "installable": False,
        "limits": ["Original subprocess.run Windows timeout/cleanup behavior retained",
                   "Admission samples only three exact old failure5 actors; no all-helper/computer-idle proof",
                   "Post-exception observation is not the exact160-second state",
                   "Pre-kill samples are sequential; not verification, EOF or descendant-state proof",
                   "A PASS cannot erase the original full-audit FAIL"],
    }
    fixture = PeerInstallTests()
    started = time.monotonic()
    auxiliary_errors = []
    sampling_evidence_failed = False

    def remember_auxiliary(error, context):
        auxiliary_errors.append(error)
        report["auxiliary_failures"].append({"context": context, "error": safe_description(error)})

    def execute(source, arguments):
        index = len(report["calls"])
        if index >= len(PHASES):
            raise RuntimeError("unexpected fourth phase")
        phase = PHASES[index]
        data = (fixture.root / "session-context.data").read_bytes()
        if len(arguments) != 2 or arguments[1] != identity.sha(data):
            raise RuntimeError("original session argument mismatch")
        raw = source.encode("ascii")
        write_output(HERE / (phase + ".host-source"), raw)
        write_output(HERE / (phase + ".session"), data)
        save_json(phase + ".context.json", fixture.q)
        row = {"phase": phase, "argv": [str(SH), "-s", "--", *arguments],
               "timeout_seconds": 160 if phase == "install-files.sh" else 120,
               "host_source_sha256": identity.sha(raw), "session_sha256": identity.sha(data),
               "rendered_source_sha256": identity.sha(fixture.scripts[phase].encode("ascii")),
               "started_utc": datetime.now(timezone.utc).isoformat()}
        report["calls"].append(row)
        clock = time.monotonic()
        saved_popen, restorations, missing = subprocess.Popen, [], object()

        def observed_popen(*args, **kwargs):
            process = saved_popen(*args, **kwargs)
            original_communicate = process.communicate
            previous = vars(process).get("communicate", missing)
            first = True

            def communicate(*call_args, **call_kwargs):
                nonlocal first, sampling_evidence_failed
                initial, first = first, False
                try:
                    return original_communicate(*call_args, **call_kwargs)
                except subprocess.TimeoutExpired as original_timeout:
                    if initial:
                        sample = None
                        try:
                            sample = {"point": "first_TimeoutExpired_before_original_run_kill"}
                            row["pre_original_timeout_cleanup"] = sample
                            native_sample(process, sample)
                        except BaseException as secondary:
                            sampling_evidence_failed = True
                            try:
                                if sample is not None:
                                    sample["sampling_error"] = safe_description(secondary)
                                remember_auxiliary(secondary, phase + ": pre-kill sample")
                            except BaseException:
                                try:
                                    original_timeout.add_note("Pre-kill diagnostic recording incomplete")
                                except BaseException:
                                    pass
                    raise

            process.communicate = communicate
            restorations.append((process, previous))
            return process

        try:
            subprocess.Popen = observed_popen
            try:
                result = subprocess.run(row["argv"], input=raw, capture_output=True,
                                        timeout=row["timeout_seconds"])
            finally:
                subprocess.Popen = saved_popen
                for process, previous in restorations:
                    if previous is missing:
                        del process.communicate
                    else:
                        process.communicate = previous
        except subprocess.TimeoutExpired as error:
            row["outcome"] = "ORIGINAL_TIMEOUT"
            # Preserve None as unknown; never turn missing captured bytes into empty output.
            for stream, value in (("stdout", error.output), ("stderr", error.stderr)):
                row[stream] = None if value is None else {
                    "bytes": len(value), "sha256": identity.sha(value)}
                if value is not None:
                    try:
                        write_output(HERE / (phase + "." + stream), value)
                    except BaseException as secondary:
                        remember_auxiliary(secondary, phase + ": " + stream + " retention")
                        try:
                            error.add_note("Output retention failed: " + safe_description(secondary))
                        except BaseException:
                            pass
            try:
                retain_observation(fixture, phase, "after_original_TimeoutExpired_return")
            except BaseException as secondary:
                remember_auxiliary(secondary, phase + ": post-timeout observation")
                try:
                    error.add_note("Fixture observation failed: " + safe_description(secondary))
                except BaseException:
                    pass
            raise
        finally:
            row["elapsed_seconds"] = time.monotonic() - clock
        row.update(outcome="RETURNED", exit_code=result.returncode,
                   stdout={"bytes": len(result.stdout), "sha256": identity.sha(result.stdout)},
                   stderr={"bytes": len(result.stderr), "sha256": identity.sha(result.stderr)})
        for stream, value in (("stdout", result.stdout), ("stderr", result.stderr)):
            try:
                write_output(HERE / (phase + "." + stream), value)
            except BaseException as error:
                remember_auxiliary(error, phase + ": returned " + stream + " retention")
        try:
            retain_observation(fixture, phase, "after_original_subprocess_return")
        except BaseException as error:
            remember_auxiliary(error, phase + ": returned fixture observation")
        # Preserve the original body's result checks even if diagnostics fail.
        return result

    primary = None
    try:
        PeerInstallTests.setUpClass()
        fixture.setUp()
        report["candidate_sha256"] = fixture.manifest["candidate_sha256"]
        original_runner = fixture.run_script
        def diagnostic_runner(name, **kwargs):
            index = len(report["calls"])
            if index >= len(PHASES) or name != PHASES[index]:
                raise RuntimeError("original phase order changed")
            return original_runner(name, process_runner=execute, **kwargs)
        fixture.run_script = diagnostic_runner
        original_body(fixture)
        report["all_original_assertions_completed"] = True
    except BaseException as error:
        primary = error
        report["failure"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        secondary_failure = None
        try:
            if hasattr(fixture, "temp"):
                fixture.tearDown()
        except BaseException as error:
            secondary_failure = error
            report["cleanup_failure"] = safe_description(error)
        try:
            after = identity.source_inputs()
            report["source_inputs_after_sha256"] = identity.sha(identity.canonical(after))
            report["source_inputs_unchanged"] = before == after
            save_json("inputs-after.json", after)
            if before != after:
                raise RuntimeError("source identity changed during original-body diagnostic")
        except BaseException as error:
            report["binding_failure"] = safe_description(error)
            if secondary_failure is None:
                secondary_failure = error
        report["elapsed_seconds"] = time.monotonic() - started
        if secondary_failure is None and auxiliary_errors:
            secondary_failure = auxiliary_errors[0]
        if secondary_failure is None and sampling_evidence_failed:
            secondary_failure = RuntimeError("Pre-kill diagnostic evidence incomplete")
        report["pre_kill_sampling_evidence_failed"] = sampling_evidence_failed
        report["diagnostic_retention_complete"] = secondary_failure is None
        if secondary_failure is not None:
            report["diagnostic_failure"] = safe_description(secondary_failure)
        try:
            save_json("result.json", report)
        except BaseException as error:
            if secondary_failure is None:
                secondary_failure = error
        if secondary_failure is not None:
            if primary is None:
                raise secondary_failure
            try:
                primary.add_note("Diagnostic auxiliary failure: " + safe_description(secondary_failure))
            except BaseException:
                pass


if __name__ == "__main__":
    main()
