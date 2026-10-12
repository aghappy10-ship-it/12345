"""Supervise isolated Qt workers without importing Qt in the observer process.

A worker's observations are provisional. Only a clean process exit, valid
observations and unchanged input hashes allow the observer to publish PASS.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from typing import Callable, Iterable

try:
    from .output_guard import PROJECT, guard_output, output_directory, write_output
except ImportError:
    from output_guard import PROJECT, guard_output, output_directory, write_output


PENDING = "EXECUTED_PENDING_PROCESS_EXIT"
MAX_OBSERVATIONS_BYTES = 4 * 1024 * 1024


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def encoded(value: dict) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def snapshot_inputs(paths: Iterable[Path]) -> dict:
    result = {}
    for path in sorted({Path(os.path.abspath(path)) for path in paths}):
        if not path.is_file():
            raise ValueError("input is not an existing regular file: " + str(path))
        with path.open("rb") as stream:
            before = os.fstat(stream.fileno())
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
            after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError("input changed while hashing: " + str(path))
        result[str(path)] = {"sha256": digest, "bytes": after.st_size}
    return result


def load_observations(run_directory: Path) -> dict:
    path = guard_output(run_directory / "observations.json")
    if not path.is_file() or path.stat().st_size > MAX_OBSERVATIONS_BYTES:
        raise ValueError("missing, non-file or oversized observations")

    def unique_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate observations key: " + key)
            result[key] = value
        return result

    def no_constant(value):
        raise ValueError("non-finite observations value: " + value)

    report = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_keys,
                        parse_constant=no_constant)
    if not isinstance(report, dict) or report.get("result") != PENDING:
        raise ValueError("worker must provide provisional observations, never PASS")
    if report.get("installable") is not False:
        raise ValueError("worker must declare installable=false")
    if type(report.get("cameraAccesses")) is not int or report["cameraAccesses"] != 0:
        raise ValueError("worker must declare integer cameraAccesses=0")
    return report


def publish_final(report: dict, destinations: Iterable[Path], previous_reports: dict[Path, bytes]) -> None:
    """Do not retain this invocation's PASS after a final write/readback error.

    Raw observations and captured output are never removed. Retraction is
    limited to guarded regular files containing exactly our own success bytes;
    a replaced, redirected or otherwise unowned path is not cleanup authority.
    """
    paths = list(destinations)
    data = encoded(report)
    try:
        for path in paths:
            write_output(path, data)
    except Exception as error:
        if report['result'] != 'PASS':
            raise
        retraction_errors = []
        for path in paths:
            try:
                guarded = guard_output(path)
                try:
                    info = guarded.lstat()
                except FileNotFoundError:
                    continue
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError('report destination is no longer a regular file')
                current = guarded.read_bytes()
                if current == data:
                    guarded.unlink()
                elif current != previous_reports.get(path):
                    raise ValueError('report destination no longer contains this invocation\'s bytes')
            except Exception as cleanup_error:
                # Still attempt the other destination when one is unavailable.
                retraction_errors.append(str(path) + ': ' + str(cleanup_error))
        report.update(result='FAIL', failure='REPORT_PUBLICATION_FAILED',
                      error=type(error).__name__ + ': ' + str(error),
                      processExitVerified=False)
        if retraction_errors:
            raise RuntimeError('Cannot retract success evidence: ' + '; '.join(retraction_errors)) from error
        # A persistent output failure may propagate, but our success bytes have
        # already been retracted. A recoverable failure yields a normal FAIL.
        failure_data = encoded(report)
        for path in paths:
            write_output(path, failure_data)


def supervise_worker(script: Path, report_name: str, run_slug: str, timeout: float = 60,
                     *, input_paths: Iterable[Path] = (),
                     input_provider: Callable[[], Iterable[Path]] | None = None) -> dict:
    """Return/persist final evidence; caller prints it and maps PASS to exit 0.

    Output names must be simple names under the literal project build tree.
    Each attempt invalidates the global result before input checks or spawning.
    Failures retain raw stdout/stderr, the command, timestamps and input hashes.
    Unsafe output destinations raise rather than bypassing output_guard.
    """
    name_pattern = r"[A-Za-z0-9][A-Za-z0-9_.-]*"
    if not re.fullmatch(name_pattern, report_name) or not report_name.endswith(".json"):
        raise ValueError("report_name must be a simple .json filename")
    if not re.fullmatch(name_pattern, run_slug):
        raise ValueError("run_slug must be a simple directory name")
    report_path = guard_output(PROJECT / "build" / report_name)
    report = {"schema": "x2dii-isolated-qt-supervision-v1", "result": "FAIL",
              "failure": "WORKER_NOT_COMPLETED", "installable": False, "cameraAccesses": 0,
              "startedUtc": utc_now(), "finishedUtc": None, "runDirectory": None,
              "workerExitCode": None, "processExitVerified": False,
              "sourceInputsUnchanged": False, "inputsBefore": {}, "inputsAfter": {}}
    # This deliberately happens before dependency reads and process creation.
    # An interrupted or invalid attempt cannot leave an earlier global PASS.
    previous_reports = {report_path: encoded(report)}
    write_output(report_path, previous_reports[report_path])
    run_directory = None
    stdout, stderr = b"", b""
    input_files = []
    try:
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be finite and positive")
        root = output_directory(PROJECT / "build" / run_slug)
        run_directory = guard_output(Path(tempfile.mkdtemp(prefix="run-", dir=root)))
        report["runDirectory"] = str(run_directory)
        for path in (run_directory / "RESULT.json", report_path):
            previous_reports[path] = encoded(report)
            write_output(path, previous_reports[path])
        script = Path(os.path.abspath(script))
        input_files = [script, Path(__file__), PROJECT / "tools/output_guard.py",
                       Path(sys.executable), *input_paths]
        # Enumerate dynamic runtime inputs inside the invalidated run, before
        # launch and again after exit. Additions/removals count as changes too.
        report["inputsBefore"] = snapshot_inputs([*input_files, *(input_provider() if input_provider else ())])
        command = [sys.executable, "-B"]
        if sys.flags.optimize:
            command.append("-" + "O" * sys.flags.optimize)
        command += ["-X", "faulthandler", str(script), "--child", str(run_directory)]
        report["workerCommand"] = command
        report["pythonOptimize"] = sys.flags.optimize
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["PYTHONPATH"] = str(PROJECT) + (os.pathsep + environment["PYTHONPATH"] if environment.get("PYTHONPATH") else "")
        with subprocess.Popen(command, cwd=PROJECT, env=environment, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE) as process:
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                report["failure"] = "WORKER_TIMEOUT"
                report["timedOut"] = True
            report["workerExitCode"] = process.returncode
        report["inputsAfter"] = snapshot_inputs([*input_files, *(input_provider() if input_provider else ())])
        report["sourceInputsUnchanged"] = report["inputsBefore"] == report["inputsAfter"]
        if report.get("timedOut"):
            pass
        elif report["workerExitCode"] != 0:
            report["failure"] = "WORKER_NONZERO_EXIT"
        elif not report["sourceInputsUnchanged"]:
            report["failure"] = "INPUTS_CHANGED"
        else:
            try:
                observations = load_observations(run_directory)
            except (ValueError, OSError, UnicodeError) as error:
                report.update(failure="INVALID_OBSERVATIONS", error=str(error))
            else:
                # Supervisor-owned fields cannot be overridden by worker JSON.
                report = {**observations, **report}
                report.update(result="PASS", failure=None, processExitVerified=True)
                report["observationsSha256"] = hashlib.sha256((run_directory / "observations.json").read_bytes()).hexdigest()
    except Exception as error:
        report.update(result="FAIL", failure="SUPERVISOR_EXCEPTION",
                      error=type(error).__name__ + ": " + str(error), processExitVerified=False)
    finally:
        report["finishedUtc"] = utc_now()
        if run_directory is not None:
            try:
                write_output(run_directory / "stdout.txt", stdout)
                write_output(run_directory / "stderr.txt", stderr)
            except Exception as error:
                report.update(result="FAIL", failure="OUTPUT_CAPTURE_FAILED",
                              error=type(error).__name__ + ": " + str(error), processExitVerified=False)
        destinations = ([run_directory / "RESULT.json"] if run_directory is not None else []) + [report_path]
        publish_final(report, destinations, previous_reports)
    return report
