"""Direct native host ownership and failure cleanup; no camera boot proof."""
import hashlib
import json
from pathlib import Path
import subprocess
import threading

import pytest

from tests.test_release_lifecycle import installer
from tests import test_menu_boot_file as boot
from tools import prepare_peer_install as peer


BASE_SHA = "704194c69e394224fe9a26a75fa8460b79572ddfea13b8584fcaa1ebcb621dcd"
HOST_BASH = Path("C:/Program Files/Git/usr/bin/bash.exe")


@pytest.mark.parametrize("staged,wrapped", ((False, False), (True, False),
                                         (False, True), (True, True)))
def test_boot_launch_owns_interpreter_without_changing_worker_contract(
        installer, monkeypatch, record_property, staged, wrapped):
    # Do not run shell_fixture/cygpath merely to inspect this launch boundary.
    installer.posix = "/f" + installer.root.as_posix()[2:]
    stage = installer.root / "blackbox/x2dii-menu-stage" / installer.manifest["candidate_sha256"][:24]
    stage.mkdir(parents=True)
    path = stage / "activate-boot.sh"
    program = peer.render_role_programs(installer.manifest)["activate-boot.sh"].encode("ascii")
    path.write_bytes(program)
    canonical_before = (path.stat().st_ino, path.stat().st_mtime_ns, path.read_bytes())
    raw = peer.session_data(installer.manifest, installer.q)
    session_sha = peer.sha(raw)
    args = [installer.posix + "/" + (stage / f"session-context-{session_sha}.data").relative_to(installer.root).as_posix(),
            session_sha, peer.sha(b"")]
    canonical_posix = installer.posix + "/" + path.relative_to(installer.root).as_posix()
    worker = [canonical_posix, *args]
    if staged:
        worker = ["-c", 'host_source=$1; shift; . "$host_source"', canonical_posix,
                  installer.posix + "/.host-activate-boot.sh", *args]
    if wrapped:
        marker = f"X2DII_BOOT_WORKER_{session_sha[:24]}_activate_RC="
        worker = ["-c", '("$@"); r=$?; printf "\\n' + marker + '%s\\n" "$r"',
                  "status-wrapper", "/usr/bin/sh", *worker]
    expected = [str(HOST_BASH), "--noprofile", "--norc", "-p", *worker]
    launches = []

    class ObservedLaunch(RuntimeError):
        pass

    def refuse_external_launch(command, **kwargs):
        launches.append((command, kwargs))
        raise ObservedLaunch("observed only; no worker process was started")

    monkeypatch.setenv("BASH_ENV", "must-not-be-sourced")
    monkeypatch.setenv("ENV", "must-not-be-sourced")
    monkeypatch.setattr(boot.subprocess, "Popen", refuse_external_launch)
    with pytest.raises(ObservedLaunch):
        boot.boot_dialogue(installer, setup=False, raw=raw,
                           staged_program=staged, wrap_status=wrapped)
    assert len(launches) == 1
    command, kwargs = launches[0]
    adapter_path = installer.root / ".host-activate-boot.sh" if staged else path
    adapter = adapter_path.read_bytes()
    if staged:
        assert (path.stat().st_ino, path.stat().st_mtime_ns, path.read_bytes()) == canonical_before
    assert adapter.count(b"IFS= read -r -t 8 boot_ack") == 1
    assert kwargs["env"]["X2DII_TEST_HOST_PROGRAM_SHA"] == peer.sha(adapter)
    record_property("pending_boot_launch_contract", json.dumps({
        "observed_command": command, "expected_command": expected,
        "canonical_unchanged": staged and canonical_before ==
            (path.stat().st_ino, path.stat().st_mtime_ns, path.read_bytes()),
        "camera_accesses": 0, "transaction_started": False,
        "activation_pass_claimed": False, "installable": False,
        "current_boot_source_sha256": hashlib.sha256(Path(boot.__file__).read_bytes()).hexdigest(),
        "unapplied_draft_source_sha256": getattr(boot, "_unapplied_boot_draft_sha256", None),
        "pending_test_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "original_frozen_base_sha256": BASE_SHA,
    }, sort_keys=True))
    assert command == expected, "Popen must own native Bash, preserving canonical $0 and worker arguments"
    assert not {key.upper() for key in kwargs["env"]} & {"BASH_ENV", "ENV"}
    assert boot.SH == Path("C:/Program Files/Git/bin/sh.exe"), "the shared shell path must not be globally changed"


@pytest.mark.parametrize("reader_started", (False, True))
def test_boot_reader_start_failure_cleans_its_owned_interpreter_and_keeps_primary_error(
        installer, monkeypatch, record_property, reader_started):
    """Fault at the real harness seam; launched shell uses builtins only.

    It cannot prove activation, recovery, or external-descendant cleanup. Any
    diagnostic termination is distinguished from the harness's own cleanup.
    """
    installer.posix = "/f" + installer.root.as_posix()[2:]
    stage = installer.root / "blackbox/x2dii-menu-stage" / installer.manifest["candidate_sha256"][:24]
    stage.mkdir(parents=True)
    before = hashlib.sha256(HOST_BASH.read_bytes()).hexdigest()
    real_popen = subprocess.Popen
    real_thread = threading.Thread
    processes = []
    started_readers = []
    primary = None
    evidence = {"camera_accesses": 0, "transaction_started": False,
                "activation_pass_claimed": False, "installable": False,
                "whole_process_tree_terminal_claimed": False,
                "actual_interpreter_sha256": before,
                "reader_started_before_injected_failure": reader_started}
    sentinel = RuntimeError("INJECTED_BOOT_READER_START_FAILURE")

    def start_builtin_interpreter(command, **kwargs):
        # Only replace the external process boundary, not runner behavior.
        process = real_popen([str(HOST_BASH), "--noprofile", "--norc", "-p", "-c",
                              "IFS= builtin read -r -t 60 held"], **kwargs)
        processes.append(process)
        return process

    class CannotStartReader(real_thread):
        def start(self):
            if reader_started:
                real_thread.start(self)
                started_readers.append(self)
            raise sentinel

    monkeypatch.setattr(boot.subprocess, "Popen", start_builtin_interpreter)
    monkeypatch.setattr(boot.threading, "Thread", CannotStartReader)
    try:
        # Pytest includes Python3.11 exception notes in regex matching. Verify
        # the actual exception object/args instead; cleanup notes are allowed.
        with pytest.raises(RuntimeError) as caught:
            boot.boot_dialogue(installer, setup=False)
        assert len(processes) == 1
        evidence["same_primary_exception_preserved"] = caught.value is sentinel
        assert caught.value is sentinel
        assert caught.value.args == ("INJECTED_BOOT_READER_START_FAILURE",)
        evidence["harness_owned_process_exit_code"] = processes[0].poll()
        evidence["harness_failure_evidence"] = repr(getattr(caught.value, "boot_host_evidence", None))
        assert processes[0].poll() is not None, "reader-start failure left the owned interpreter running"
        assert caught.value.boot_host_evidence["fixture_retained"] is True
        assert caught.value.boot_host_evidence["forced_owned_process_cleanup"] is True
        assert installer.temp._finalizer.alive is False
    except BaseException as error:
        primary = error
        raise
    finally:
        # Independent cleanup prevents a RED reproduction leaking its builtin
        # child. It must never be attributed to the harness under test.
        errors = []

        def attempt(label, operation):
            try:
                return operation()
            except BaseException as error:
                errors.append((label, type(error).__name__))

        def retain_fixture():
            installer.temp._finalizer.detach()
            installer.temp.cleanup = lambda: None

        if primary is not None:
            attempt("retain failed diagnostic fixture", retain_fixture)
        for process in processes:
            if attempt("poll diagnostic child", lambda: process.poll()) is None:
                attempt("retain diagnostic fixture", retain_fixture)
                evidence["separate_diagnostic_termination_not_harness_cleanup"] = True
                attempt("separate kill owned child", lambda: process.kill())
                attempt("separate wait owned child", lambda: process.wait(timeout=5))
            for reader in started_readers:
                attempt("separate reader join", lambda reader=reader: real_thread.join(reader, timeout=5))
                if reader.is_alive():
                    errors.append(("separate reader join", "IncompleteStream"))
            for pipe in (process.stdin, process.stdout, process.stderr):
                if pipe is process.stdout and any(reader.is_alive() for reader in started_readers):
                    continue
                # No input is ever buffered by this injected-failure test.
                attempt("separate pipe close", lambda pipe=pipe: pipe.close())
        try:
            evidence["actual_interpreter_unchanged"] = before == hashlib.sha256(HOST_BASH.read_bytes()).hexdigest()
            evidence["current_boot_source_sha256"] = hashlib.sha256(Path(boot.__file__).read_bytes()).hexdigest()
            evidence["unapplied_draft_source_sha256"] = getattr(boot, "_unapplied_boot_draft_sha256", None)
            evidence["owned_process_final_codes"] = [process.poll() for process in processes]
            evidence["pending_test_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
            evidence["separate_diagnostic_errors"] = errors
            record_property("pending_reader_start_failure", json.dumps(evidence, sort_keys=True))
        except BaseException as error:
            errors.append(("separate evidence collection", type(error).__name__))
        if errors:
            if primary is not None:
                attempt("annotate primary diagnostic failure", lambda: primary.add_note(repr(errors)))
            else:
                raise AssertionError(errors)


@pytest.mark.parametrize("fault", ("kill-error-format", "metadata-error"))
def test_boot_auxiliary_failure_cannot_replace_primary_or_skip_owned_wait(
        installer, monkeypatch, record_property, fault):
    """Negative cleanup seam; an error is required, never transaction success."""
    installer.posix = "/f" + installer.root.as_posix()[2:]
    stage = installer.root / "blackbox/x2dii-menu-stage" / installer.manifest["candidate_sha256"][:24]
    stage.mkdir(parents=True)
    real_popen, real_thread = subprocess.Popen, threading.Thread
    processes, events = [], []
    evidence = {"fault": fault, "camera_accesses": 0, "transaction_started": False,
                "installable": False, "whole_process_tree_terminal_claimed": False}
    primary = None

    class UnformattableError(RuntimeError):
        def __str__(self):
            raise RuntimeError("INJECTED_AUXILIARY_STR_FAILURE")

        def __repr__(self):
            raise RuntimeError("INJECTED_AUXILIARY_REPR_FAILURE")

    class PrimaryFailure(RuntimeError):
        def add_note(self, note):
            if fault == "metadata-error":
                events.append("annotation-refused")
                raise UnformattableError()
            return super().add_note(note)

        def __setattr__(self, key, value):
            if fault == "metadata-error" and key.startswith("boot_host_"):
                events.append("evidence-refused")
                raise UnformattableError()
            return super().__setattr__(key, value)

    sentinel = PrimaryFailure("INJECTED_PRIMARY_BOOT_FAILURE")

    class OwnedBuiltinProcess(real_popen):
        def kill(self):
            events.append("harness-kill")
            super().kill()
            if fault == "kill-error-format":
                events.append("kill-raised-after-termination")
                raise UnformattableError()

        def wait(self, timeout=None):
            events.append("harness-wait")
            return super().wait(timeout=timeout)

    def start_builtin(command, **kwargs):
        process = OwnedBuiltinProcess([str(HOST_BASH), "--noprofile", "--norc", "-p", "-c",
                                       "IFS= builtin read -r -t 60 held"], **kwargs)
        processes.append(process)
        return process

    class CannotStartReader(real_thread):
        def start(self):
            raise sentinel

    monkeypatch.setattr(boot.subprocess, "Popen", start_builtin)
    monkeypatch.setattr(boot.threading, "Thread", CannotStartReader)
    try:
        with pytest.raises(PrimaryFailure) as caught:
            boot.boot_dialogue(installer, setup=False)
        assert caught.value is sentinel
        assert caught.value.args == ("INJECTED_PRIMARY_BOOT_FAILURE",)
        assert len(processes) == 1
        evidence["harness_exit_code"] = processes[0].poll()
        assert processes[0].poll() is not None, "auxiliary failure left owned interpreter active"
        assert "harness-kill" in events and "harness-wait" in events
        assert installer.temp._finalizer.alive is False
        if fault == "kill-error-format":
            assert "kill-raised-after-termination" in events
            assert caught.value.boot_host_evidence["cleanup_errors"]
        else:
            assert "annotation-refused" in events and "evidence-refused" in events
            assert not hasattr(caught.value, "boot_host_evidence")
    except BaseException as error:
        primary = error
        raise
    finally:
        errors = []

        def attempt(label, operation):
            try:
                return operation()
            except BaseException as error:
                errors.append((label, type(error).__name__))

        def retain_fixture():
            installer.temp._finalizer.detach()
            installer.temp.cleanup = lambda: None

        attempt("retain negative fixture", retain_fixture)
        for process in processes:
            if attempt("diagnostic poll", lambda: process.poll()) is None:
                evidence["separate_diagnostic_termination_not_harness_cleanup"] = True
                attempt("diagnostic base kill", lambda: real_popen.kill(process))
                attempt("diagnostic base wait", lambda: real_popen.wait(process, timeout=5))
            # This fault never calls the real Thread.start: no competing reader.
            attempt("diagnostic stdin raw close", lambda: process.stdin.raw.close())
            for pipe in (process.stdout, process.stderr):
                attempt("diagnostic pipe close", lambda pipe=pipe: pipe.close())
        try:
            evidence.update(events=events, separate_diagnostic_errors=errors,
                owned_process_final_codes=[process.poll() for process in processes],
                current_boot_source_sha256=hashlib.sha256(Path(boot.__file__).read_bytes()).hexdigest(),
                unapplied_draft_source_sha256=getattr(boot, "_unapplied_boot_draft_sha256", None),
                pending_test_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
            record_property("pending_auxiliary_failure", json.dumps(evidence, sort_keys=True))
        except BaseException as error:
            errors.append(("diagnostic evidence", type(error).__name__))
        if errors:
            if primary is None:
                raise AssertionError(errors)
            attempt("diagnostic annotation", lambda: primary.add_note(repr(errors)))

