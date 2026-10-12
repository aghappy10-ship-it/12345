"""Formal /o must be staged by production sources, never supplied by the fixture."""
from dataclasses import replace
from datetime import datetime, timezone
import re
import shlex
import subprocess

import pytest

from tools import stage_menu_delivery as stage, menu_content_transport as content
from tools import menu_maintenance_boundary as boundary, prepare_peer_install as peer, session_context
from tests.test_menu_preparation_transport import preparation_fixture
from tests.test_raw_session_staging import raw_shell
from tests.test_menu_content_transport import native_fixture_source
from tests.test_stage_menu_delivery import maintenance_result


def formal_fixture():
    parent, manifest, raw, _ = preparation_fixture("install")
    values = session_context.decode_session(raw)
    # The older boot-preparation-only fixture is not a two-role observation.
    # Model the separate maintenance observer explicitly, never weaken its guard.
    values["observer_domain"] = "u:r:hbl_camera_service:s0"
    return parent, manifest, session_context.encode_session(values, schema=session_context.INSTALL_SCHEMA)


def mapped_shell(tmp_path, parent, raw):
    destination, run = raw_shell(tmp_path, parent, raw)
    camera_tmp = tmp_path / "camera-tmp"
    camera_tmp.mkdir()
    posix = subprocess.run(["C:/Program Files/Git/bin/sh.exe", "-c", 'cygpath -u "$1"', "test", str(camera_tmp)],
                            capture_output=True, text=True, check=True).stdout.strip()

    def mapped(operation, hook=""):
        result = run(replace(operation, command=operation.command.replace("/tmp", shlex.quote(posix))), hook)
        result.stdout = result.stdout.replace(posix, "/tmp")
        return result
    return destination, camera_tmp, mapped


@pytest.mark.parametrize("state", ("absent", "exact", "unknown"))
def test_actual_formal_observer_is_exclusive_or_exact_read_only(tmp_path, state):
    parent, manifest, raw = formal_fixture()
    prepared = stage.plan_install_observer_staging(parent, manifest, raw)
    destination, camera_tmp, run = mapped_shell(tmp_path, parent, raw)
    (path, source), = prepared.files
    assert path == "/tmp/x2mb-" + manifest["candidate_sha256"][:12] + "/o"
    assert source == boundary.render_observer(manifest, session_kind="install").encode("ascii")
    target = camera_tmp / path.removeprefix("/tmp/")
    before = None
    if state != "absent":
        target.parent.mkdir()
        target.write_bytes(source if state == "exact" else b"UNKNOWN KEEP")
        before = target.stat()
    for step in prepared.steps:
        result = run(step)
        if state == "unknown":
            assert result.returncode != 0 and target.read_bytes() == b"UNKNOWN KEEP"
            assert target.stat().st_ino == before.st_ino and not list(destination.iterdir())
            return
        assert result.returncode == 0 and not result.stderr, (step.label, result.stderr)
        assert result.stdout == step.expected_stdout
    assert target.read_bytes() == source and not prepared.installable
    if state == "exact":
        assert target.stat().st_ino == before.st_ino and target.stat().st_mtime_ns == before.st_mtime_ns
        assert not list(destination.iterdir())


@pytest.mark.parametrize("kind", ("menu_validation", "recovery"))
def test_formal_preparation_never_relabels_other_action(kind):
    parent, manifest, raw, _ = preparation_fixture(kind)
    with pytest.raises(ValueError):
        stage.plan_install_observer_staging(parent, manifest, raw)
    with pytest.raises(ValueError):
        content.plan_install_preparation(parent, manifest, raw)


def test_formal_plan_keeps_stable_archive_and_original_session_immutable():
    parent, manifest, raw = formal_fixture()
    prepared = content.plan_install_preparation(parent, manifest, raw)
    observer = stage.plan_install_observer_staging(parent, manifest, raw)
    assert prepared.purpose == "install_preparation" and prepared.parent_plan == parent
    assert prepared.raw_session == prepared.session.data == raw
    assert prepared.payload_identities is prepared.code_preparation is prepared.cleanup_evidence is None
    assert prepared.plan.phase == "second-window-preparation" and not prepared.plan.include_session_file
    assert len(prepared.plan.steps) == 2 + len(observer.steps) + 1
    assert prepared.plan.steps[2:2+len(observer.steps)] == observer.steps
    assert prepared.plan.member_names == parent.member_names and len(parent.member_names) == 11
    final = prepared.plan.steps[-1]
    for index in range(4):
        assert parent.stage_root + f"/preplace-{index}.sh" in final.command
    assert "menu-validation-preplace" not in final.command
    assert not set(prepared.plan.steps).intersection(parent.steps) and not prepared.installable
    assert content._preparation_scope(prepared) == "FORMAL_CONTEXT_AND_OBSERVER_READY_NOT_FILES_PLACED_USB_RESTORE_UNVERIFIED"
    damaged = replace(prepared, plan=replace(prepared.plan, steps=prepared.plan.steps[:-1]))
    with pytest.raises(ValueError):
        content.SecondWindowPreparationCoordinator(damaged)


@pytest.mark.parametrize("worker_state", ("exact", "missing", "changed"))
def test_formal_preparation_reads_staged_workers_without_replaying_or_executing_them(tmp_path, worker_state):
    parent, manifest, raw = formal_fixture()
    prepared = content.plan_install_preparation(parent, manifest, raw)
    destination, camera_tmp, run = mapped_shell(tmp_path, parent, raw)
    programs = peer.render_role_programs(manifest)
    original = {}
    for index in range(4):
        name = f"preplace-{index}.sh"
        if worker_state == "missing" and index == 2:
            continue
        path = destination / name
        path.write_bytes(b"UNKNOWN KEEP" if worker_state == "changed" and index == 2 else programs[name].encode("ascii"))
        original[name] = (path.read_bytes(), path.stat())
    results = [run(step) for step in prepared.plan.steps]
    assert all(result.returncode == 0 and not result.stderr for result in results[:-1])
    if worker_state == "exact":
        assert results[-1].returncode == 0 and results[-1].stdout == prepared.plan.steps[-1].expected_stdout
    else:
        assert results[-1].returncode != 0 or results[-1].stdout != prepared.plan.steps[-1].expected_stdout
    for name, (source, before) in original.items():
        path = destination / name
        assert path.read_bytes() == source and path.stat().st_ino == before.st_ino
        assert path.stat().st_mtime_ns == before.st_mtime_ns
    assert (camera_tmp / ("x2mb-" + manifest["candidate_sha256"][:12]) / "o").is_file()


def test_formal_native_source_refuses_before_usb_and_model_uses_same_original_window(tmp_path):
    parent, manifest, raw = formal_fixture()
    prepared = content.plan_install_preparation(parent, manifest, raw)
    epoch = prepared.session.observed_epoch
    launch = datetime.fromtimestamp(epoch, timezone.utc)
    host = content.SecondWindowPreparationCoordinator(prepared, clock=lambda: epoch+30)
    while (operation := host.next_preparation) is not None:
        host.accept_preparation(exit_code=0, stdout=operation.expected_stdout, completion_validated=True)
    host.start_window(launch)
    assert host.remaining_window_seconds() == 50
    steps = stage.execution_steps(prepared.plan, dict(prepared.session.context), session=prepared.session)
    source = content.review_preparation_host_source(prepared, launch)
    assert "ContentQualified = false" in source
    namespace = re.search(r"namespace (X2d2ContentStage_[a-f0-9]+)", source)[1]
    path = tmp_path / "formal-closed.cs"
    path.write_text(source, encoding="utf-8")
    script = f'''$ErrorActionPreference='Stop'; Add-Type -Path '{path}';
try {{ [{namespace}.AdbUsbCheck]::RunContentStage(); throw 'unexpected execution' }}
catch {{ $e=$_.Exception;while($e.InnerException){{$e=$e.InnerException}};
if($e.Code -ne 'CONTENT_SOURCE_NOT_QUALIFIED'){{throw}} }}
'''
    closed = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                            capture_output=True, text=True, timeout=30)
    assert closed.returncode == 0, closed.stderr
    model = native_fixture_source(source, steps, prepared.session, fault="none", epoch=epoch+30)
    assert "DllImport(" not in model
    path = tmp_path / "formal-native-disabled.cs"
    path.write_text(model, encoding="utf-8")
    process = subprocess.Popen(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
        f"$ErrorActionPreference='Stop';Add-Type -Path '{path}';[{namespace}.AdbUsbCheck]::RunContentStage()"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    class Maintenance:
        count = 0
        def command(self, label, command):
            operation = host.observer.observations[self.count]
            assert command == operation.command
            self.count += 1
            result = maintenance_result(operation, prepared.session, observer=host.observer, epoch=epoch+30)
            assert result.returncode == 0 and not result.stderr
            return result.stdout
    maintenance = Maintenance()
    try:
        result = content.drive_preparation_process(process, host, maintenance)
        assert result["purpose"] == "install_preparation" and result["worker_followup_allowed"]
        assert result["status"] == content._preparation_scope(prepared)
        assert result["launch_started_utc"] == launch.isoformat()
        assert len(result["retained_adb_payloads"]) == maintenance.count == len(steps)
        assert not result["installable"] and not result["usb_restore_verified"]
    finally:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()
