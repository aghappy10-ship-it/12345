"""Host stream failures preserve their exact error; not camera boot evidence."""
import hashlib
import json
from pathlib import Path
import subprocess
import threading
import time

import pytest

from tests.test_release_lifecycle import installer
from tests import test_menu_boot_file as boot


@pytest.mark.parametrize("stdout_finishes", (False, True))
def test_stderr_read_failure_wakes_dialogue_and_preserves_exact_primary(
        installer, monkeypatch, record_property, stdout_finishes):
    installer.posix = "/f" + installer.root.as_posix()[2:]
    stage = installer.root / "blackbox/x2dii-menu-stage" / installer.manifest["candidate_sha256"][:24]
    stage.mkdir(parents=True)
    source_before = hashlib.sha256(Path(boot.__file__).read_bytes()).hexdigest()
    runtime_before = hashlib.sha256(boot.HOST_BASH.read_bytes()).hexdigest()
    real_popen = subprocess.Popen
    real_thread = threading.Thread
    stdout_readers = []
    processes, actual_stderr = [], []
    sentinel = OSError("INJECTED_ASYNC_STDERR_READ_FAILURE")
    prefix = b"stderr received before read failure\n"

    class FailedRead:
        def __init__(self, stream):
            self.stream, self.calls = stream, 0

        def read1(self, size):
            self.calls += 1
            if self.calls == 1:
                return prefix
            raise sentinel

        def close(self):
            self.stream.close()

    def launch_builtin(command, **kwargs):
        # Replace only the external process/read boundaries. A builtin-only
        # native interpreter cannot execute a camera transaction or descendants.
        program = "printf 'stdout complete\\n'" if stdout_finishes else "IFS= builtin read -r -t 60 held"
        process = real_popen([str(boot.HOST_BASH), "--noprofile", "--norc", "-p", "-c", program], **kwargs)
        actual_stderr.append(process.stderr)
        process.stderr = FailedRead(process.stderr)
        processes.append(process)
        return process

    monkeypatch.setattr(boot.subprocess, "Popen", launch_builtin)
    class OrderedReader(real_thread):
        def __init__(self, *, target, **kwargs):
            self.reader_role = target.__name__
            super().__init__(target=target, **kwargs)

        def start(self):
            if stdout_finishes and self.reader_role == "stderr_reader":
                # Deliberately put real stdout EOF in the queue before the
                # failing stderr reader starts; no scheduling guess or sleep.
                assert len(stdout_readers) == 1
                stdout_readers[0].join(timeout=5)
                assert not stdout_readers[0].is_alive()
            super().start()
            if self.reader_role == "reader":
                stdout_readers.append(self)

    monkeypatch.setattr(boot.threading, "Thread", OrderedReader)
    started = time.monotonic()
    evidence = {"camera_accesses": 0, "transaction_started": False, "installable": False,
                "stdout_finishes": stdout_finishes, "whole_process_tree_terminal_claimed": False}
    primary = None
    try:
        with pytest.raises(OSError) as caught:
            boot.boot_dialogue(installer, setup=False)
        assert caught.value is sentinel
        assert caught.value.args == ("INJECTED_ASYNC_STDERR_READ_FAILURE",)
        assert len(processes) == 1 and processes[0].stderr.calls == 2
        assert processes[0].poll() is not None
        assert caught.value.boot_host_evidence["observed_stderr"] == prefix
        assert caught.value.boot_host_evidence["reader_errors"] == (sentinel,)
        assert caught.value.boot_host_evidence["fixture_retained"] is True
        assert installer.temp._finalizer.alive is False
        evidence["same_primary_exception_preserved"] = True
        # The existing worker/observer waits are unchanged. A reader error must
        # interrupt the stdout wait rather than be discovered at its deadline.
        assert time.monotonic() - started < 15
    except BaseException as error:
        primary = error
        raise
    finally:
        # Separate RED cleanup is never attributed to the harness under test.
        errors = []
        for process, stream in zip(processes, actual_stderr):
            try:
                if process.poll() is None:
                    evidence["separate_diagnostic_termination"] = True
                    real_popen.kill(process)
                    real_popen.wait(process, timeout=5)
                stream.close()
            except BaseException as error:
                errors.append(type(error).__name__)
        try:
            evidence.update(elapsed_seconds=time.monotonic() - started,
                            owned_process_exit_codes=[process.poll() for process in processes],
                            diagnostic_errors=errors, boot_source_sha256=source_before,
                            native_bash_sha256=runtime_before)
        except BaseException as error:
            errors.append(("collect evidence", type(error).__name__))
        for label, path, expected in (("boot readback", Path(boot.__file__), source_before),
                                       ("native Bash readback", boot.HOST_BASH, runtime_before)):
            try:
                if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                    errors.append((label, "InputChanged"))
            except BaseException as error:
                errors.append((label, type(error).__name__))
        try:
            record_property("host_stderr_failure", json.dumps(evidence, sort_keys=True))
        except BaseException as error:
            errors.append(("publish evidence", type(error).__name__))
        if errors:
            if primary is None:
                raise AssertionError(errors)
            try:
                primary.add_note("Separate diagnostic failures: " + repr(errors))
            except BaseException:
                pass


@pytest.mark.parametrize("delay_seconds", (.1, 6.1))
def test_stdout_eof_keeps_original_outer_wait_before_stderr_completion(
        installer, monkeypatch, delay_seconds):
    installer.posix = "/f" + installer.root.as_posix()[2:]
    stage = installer.root / "blackbox/x2dii-menu-stage" / installer.manifest["candidate_sha256"][:24]
    stage.mkdir(parents=True)
    real_popen = subprocess.Popen
    processes = []

    def launch_builtin(command, **kwargs):
        # Close only stdout, retain stderr while the directly owned native
        # process performs a bounded builtin wait. No camera program runs.
        program = "exec 1>&-; IFS= builtin read -r -t " + str(delay_seconds) + " held; exit 7"
        process = real_popen([str(boot.HOST_BASH), "--noprofile", "--norc", "-p", "-c", program], **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(boot.subprocess, "Popen", launch_builtin)
    result, observations = boot.boot_dialogue(installer, setup=False)
    assert result.returncode == 7 and result.stdout == b"" and result.stderr == b""
    assert len(processes) == 1 and processes[0].poll() == 7
    assert observations == []
