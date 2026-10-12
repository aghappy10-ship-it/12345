"""Bounded real worker dialogue; Windows OS facts are explicit substitutes.

These tests do not claim the host-to-maintenance transport or a camera passed.
They prove that no observed response means no subsequent payload mutation.
"""
import subprocess
import hashlib
import os
import queue
import threading
import time
from functools import partial

import pytest

from tests.test_peer_install import SH
from tests.test_release_lifecycle import installer
from tests.test_temporary_menu_files import run_worker
from tools import temporary_menu_files as files
from tools import menu_maintenance_boundary as boundary


def test_supervised_worker_without_observer_reply_never_remounts_or_creates_payload(installer):
    def run(source, arguments, source_dir):
        script = installer.root / files.worker_path(installer.manifest, 0, session_kind="menu_validation").lstrip("/")
        script.write_text(source, encoding="ascii", newline="\n")
        return subprocess.run([str(SH), installer.posix + "/" + script.relative_to(installer.root).as_posix(), *arguments], input=b"",
                              capture_output=True, timeout=30)

    result = run_worker(installer, renderer=files.render_supervised_preplacement, process_runner=run)
    assert result.returncode == 81, (result.stdout, result.stderr)
    assert b"X2DII_BOUNDARY_REQUEST:0:0:" in result.stdout
    assert not (installer.root / "worker-operations").exists()
    assert not (installer.root / "system/lib64/libx2dii_menu.so").exists()
    assert (installer.root / "gui-service-state").read_text() == "running"
    assert (installer.root / "proc/mounts").read_text() == installer.mount_line


def dialogue(installer, *, reply=None, file_index=0, values=None, setup=True, wrap_status=False,
             session_kind="menu_validation", staged_program=False, use_observer=False, host_wait_seconds=None):
    """Actual process pipe with explicit synthetic external-host responses."""
    observed = []

    def run(source, arguments, source_dir):
        if host_wait_seconds is not None:
            assert (staged_program or use_observer) and host_wait_seconds == 30
            assert source.count("IFS= read -r -t 8 acknowledgement") == 1
            # Explicit Windows-process timing model only; canonical production
            # programs, target 8-second ACK and USB deadlines are unchanged.
            source = source.replace("IFS= read -r -t 8 acknowledgement", "IFS= read -r -t 30 acknowledgement", 1)
        script = installer.root / files.worker_path(installer.manifest, file_index, session_kind=session_kind).lstrip("/")
        original = None
        if staged_program:
            original = (script.stat().st_ino, script.stat().st_mtime_ns, script.read_bytes())
            host_script = installer.root / f".host-worker-{file_index}.sh"
            host_script.write_text(source, encoding="ascii", newline="\n")
        else:
            script.write_text(source, encoding="ascii", newline="\n")
        path = installer.posix + "/" + script.relative_to(installer.root).as_posix()
        environment = os.environ.copy()
        environment["X2DII_TEST_HOST_PROGRAM_SHA"] = hashlib.sha256(source.encode("ascii")).hexdigest()
        command = [str(SH), path, *arguments]
        if staged_program:
            host_path = installer.posix + "/" + host_script.relative_to(installer.root).as_posix()
            command = [str(SH), "-c", 'host_source=$1; shift; . "$host_source"', path, host_path, *arguments]
        if wrap_status:
            marker = f"X2DII_WORKER_{arguments[1][:24]}_{file_index}_RC="
            command = [str(SH), "-c", '("$@"); r=$?; printf "\\n' + marker + '%s\\n" "$r"',
                       "status-wrapper", *(["/usr/bin/sh", *command[1:]])]
        process = subprocess.Popen(command, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
        lines = queue.Queue()

        def read_lines():
            for line in iter(process.stdout.readline, b""):
                lines.put(line)
            lines.put(None)

        reader = threading.Thread(target=read_lines, daemon=True)
        reader.start()
        output = bytearray()
        try:
            while True:
                line = lines.get(timeout=20)
                if line is None:
                    break
                output.extend(line)
                if not line.startswith(b"X2DII_BOUNDARY_REQUEST:"):
                    continue
                parts = line.decode("ascii").strip().split(":")
                assert len(parts) == 4 and parts[1] == str(file_index)
                index = int(parts[2])
                request = (source_dir / f".boundary-{file_index}-{index}.data").read_bytes()
                assert hashlib.sha256(request).hexdigest() == parts[3]
                values = boundary.decode_request(request)
                assert values["boundary_index"] == len(observed) == index
                observed.append(values)
                acknowledgement = (
                    f"X2DII_BOUNDARY_ACK:{parts[3]}:{values['issued_epoch']}:{values['issued_epoch']}\n"
                ).encode()
                if reply is not None:
                    acknowledgement = reply(index, acknowledgement, values)
                if acknowledgement is None:
                    process.stdin.close()
                else:
                    process.stdin.write(acknowledgement)
                    process.stdin.flush()
            process.wait(timeout=20)
            if original is not None:
                assert (script.stat().st_ino, script.stat().st_mtime_ns, script.read_bytes()) == original
            return subprocess.CompletedProcess(process.args, process.returncode, bytes(output), process.stderr.read())
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            reader.join(timeout=5)

    from tools import session_context
    schema = session_context.INSTALL_SCHEMA if session_kind == "install" else session_context.MENU_VALIDATION_SCHEMA
    renderer = partial(files.render_supervised_preplacement, session_kind=session_kind)
    if staged_program:
        def renderer(manifest, *, file_index):
            path = installer.root / files.worker_path(manifest, file_index, session_kind=session_kind).lstrip("/")
            return path.read_bytes().decode("ascii")
    result = run_worker(installer, index=file_index, values=values, setup=setup, schema=schema,
                        renderer=renderer, process_runner=run)
    return result, observed


@pytest.mark.parametrize("use_observer,host_wait_seconds,expected_read", (
    (False, None, 8), (True, None, 8), (True, 30, 30),
))
def test_preplacement_observer_host_wait_is_explicit_and_keeps_exact_host_hash_mapping(
        installer, monkeypatch, use_observer, host_wait_seconds, expected_read):
    installer.shell_fixture()
    original = files.render_supervised_preplacement(installer.manifest, file_index=0,
                                                    session_kind="menu_validation")
    assert original.count("IFS= read -r -t 8 acknowledgement") == 1

    def observe_launch(command, **kwargs):
        # Inspect the real written host adapter at the external launch seam;
        # do not substitute any worker, observer or transaction result.
        path = installer.root / files.worker_path(installer.manifest, 0,
                                                  session_kind="menu_validation").lstrip("/")
        adapter = path.read_bytes()
        assert command[:2] == [str(SH), installer.posix + "/" + path.relative_to(installer.root).as_posix()]
        assert adapter.count(f"IFS= read -r -t {expected_read} acknowledgement".encode()) == 1
        assert b'[ "$((received_epoch-issued_epoch))" -le 8 ] || exit 81' in adapter
        assert kwargs["env"]["X2DII_TEST_HOST_PROGRAM_SHA"] == hashlib.sha256(adapter).hexdigest()
        assert ("printf '" + hashlib.sha256(original.encode("ascii")).hexdigest() + "  %s\\n' \"$1\"").encode() in adapter
        assert b'[ "$1" = "$0" ] && [ "${host_hash%% *}" = "${X2DII_TEST_HOST_PROGRAM_SHA-}" ]' in adapter
        raise RuntimeError("recorded external preplacement launch")

    monkeypatch.setattr(subprocess, "Popen", observe_launch)
    options = {"host_wait_seconds": host_wait_seconds}
    if use_observer:
        options["use_observer"] = True
    with pytest.raises(RuntimeError, match="recorded external preplacement launch"):
        dialogue(installer, setup=False, **options)


@pytest.mark.parametrize("use_observer,host_wait_seconds", ((False, 30), (True, 8), (True, 31)))
def test_preplacement_host_wait_rejects_unselected_or_unsupported_adapter_before_launch(
        installer, monkeypatch, use_observer, host_wait_seconds):
    installer.shell_fixture()
    path = installer.root / files.worker_path(installer.manifest, 0,
                                              session_kind="menu_validation").lstrip("/")
    before = path.read_bytes() if path.exists() else None

    def unexpected_launch(*args, **kwargs):
        pytest.fail("unsupported host wait reached the external process")

    monkeypatch.setattr(subprocess, "Popen", unexpected_launch)
    options = {"host_wait_seconds": host_wait_seconds}
    if use_observer:
        options["use_observer"] = True
    with pytest.raises(AssertionError):
        dialogue(installer, setup=False, **options)
    assert (path.read_bytes() if path.exists() else None) == before


@pytest.mark.parametrize("file_index", range(4))
def test_seven_distinct_boundaries_keep_same_transaction_and_restore_readonly(installer, file_index):
    result, observed = dialogue(installer, file_index=file_index)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert [v["boundary_name"] for v in observed] == [
        "remount_rw", "create_temp", "write_payload", "chmod", "commit_rename", "final_identity", "final_receipt",
    ]
    assert len({v["challenge"] for v in observed}) == 7
    assert len({v["worker_program_sha256"] for v in observed}) == 1
    assert b"maintenance_boundaries=HOST_MEDIATED_SEVEN_MATCHED" in result.stdout
    assert (installer.root / "proc/mounts").read_text() == installer.mount_line
    assert (installer.root / "gui-service-state").read_text() == "running"
    entry = installer.manifest["candidate"]["files"][file_index]
    payload = installer.root / entry["target"].lstrip("/")
    assert hashlib.sha256(payload.read_bytes()).hexdigest() == entry["sha256"]


@pytest.mark.parametrize("fault", ("wrong-hash", "replayed", "eof", "future", "extra-field"))
def test_missing_or_mismatched_second_reply_stops_before_creating_payload(installer, fault):
    first = None

    def respond(index, answer, values):
        nonlocal first
        if index == 0:
            first = answer
            return answer
        assert index == 1
        if fault == "eof":
            return None
        if fault == "replayed":
            return first
        if fault == "wrong-hash":
            parts = answer.decode().split(":")
            parts[1] = "f" * 64
            return ":".join(parts).encode()
        if fault == "extra-field":
            return answer.rstrip(b"\n") + b":unexpected\n"
        return answer.replace(str(values["issued_epoch"]).encode(), str(values["issued_epoch"] + 1).encode())

    result, observed = dialogue(installer, reply=respond)
    assert result.returncode == 81, (result.stdout, result.stderr)
    assert len(observed) == 2
    assert b"ONE_FILE_PREPLACED" not in result.stdout
    assert not (installer.root / "system/lib64/libx2dii_menu.so").exists()
    assert not list((installer.root / "system/lib64").glob(".x2dii-preplace-*"))
    assert (installer.root / "proc/mounts").read_text() == installer.mount_line


def test_open_but_unresponsive_host_times_out_and_restores_owned_mount(installer):
    waiting_at = None

    def respond(index, answer, values):
        nonlocal waiting_at
        if index == 1:
            waiting_at = time.monotonic()
            return b""  # Keep stdin open without sending even a newline.
        return answer

    result, observed = dialogue(installer, reply=respond)
    assert waiting_at is not None and time.monotonic() - waiting_at >= 7.5
    assert result.returncode == 81, (result.stdout, result.stderr)
    assert len(observed) == 2
    assert not (installer.root / "system/lib64/libx2dii_menu.so").exists()
    assert (installer.root / "proc/mounts").read_text() == installer.mount_line


@pytest.mark.parametrize("at_boundary", (3, 4))
def test_ack_wait_cannot_switch_the_inode_chmod_or_rename_will_touch(installer, at_boundary):
    replacement = None

    def respond(index, answer, values):
        nonlocal replacement
        if index == at_boundary:
            [temporary] = list((installer.root / "system/lib64").glob(".x2dii-preplace-*"))
            before = temporary.stat().st_ino
            temporary.rename(temporary.with_name(temporary.name + ".displaced"))
            temporary.write_bytes((temporary.with_name(temporary.name + ".displaced")).read_bytes())
            assert temporary.stat().st_ino != before
            replacement = temporary
        return answer

    result, _ = dialogue(installer, reply=respond)
    assert result.returncode != 0, (result.stdout, result.stderr)
    assert replacement is not None and replacement.exists(), "unexpected inode must stay at its original pathname"
    assert not (installer.root / "system/lib64/libx2dii_menu.so").exists(), "replacement must not be renamed into the target"
    operations = (installer.root / "worker-operations").read_text().splitlines()
    if at_boundary == 3:
        assert not any(line.startswith("chmod:") for line in operations), "must not chmod an unowned replacement"
    assert not any(line.startswith("mv:") for line in operations)
    assert (installer.root / "proc/mounts").read_text() == installer.mount_line
