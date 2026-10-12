"""Second-window preparation reuses fixed native transport, never installation."""
from dataclasses import replace
from datetime import datetime, timezone
import json
import re
import subprocess

import pytest

from tools import menu_content_transport as transport, stage_menu_delivery as stage
from tools import session_context as sc, boot_config as boot, prepare_peer_install as peer
from tests.test_raw_session_staging import raw_fixture, sha
from tests.test_delivery_role_v2 import role_fixture
from tests.test_menu_auxiliary_staging import payload_identities
from tests.test_menu_content_transport import native_fixture_source
from tests.test_stage_menu_delivery import maintenance_result


def preparation_fixture(kind):
    # Payload bytes remain explicitly synthetic, but the actual boot renderer
    # must receive the genuine stock/proposed two-line rc pair and its hashes.
    _, _, raw = raw_fixture("menu_validation" if kind == "ready" else kind)
    members, candidate, _ = role_fixture()
    members["camera-gui.rc.proposed"] = boot.activate(boot.STOCK.read_bytes())
    candidate["rc"]["after"] = sha(members["camera-gui.rc.proposed"])
    digest = sha(json.dumps(candidate, sort_keys=True, separators=(",", ":")).encode("ascii"))
    manifest = {"candidate": candidate, "candidate_sha256": digest}
    programs = peer.render_role_programs(manifest)
    members.update({name: source.encode("ascii") for name, source in programs.items()})
    renderer = (peer.ROOT / "tools/prepare_peer_install.py").read_bytes()
    plan = stage.plan_compressed_role_staging(members=members, candidate=candidate, candidate_sha256=digest,
        script_hashes={name: sha(source.encode("ascii")) for name, source in programs.items()},
        renderer_source=renderer, renderer_source_sha256=sha(renderer))
    if kind in ("menu_validation", "ready"):
        values = sc.decode_session(raw)
        values["candidate_sha256"] = digest
        raw = sc.encode_session(values, schema=sc.MENU_VALIDATION_SCHEMA)
    if kind == "ready":
        code = transport.plan_temporary_preparation(plan, manifest, raw)
        values = sc.decode_session(raw)
        values.update(session_nonce="c" * 32, observed_epoch=values["observed_epoch"] + 200)
        raw = sc.encode_session(values, schema=sc.MENU_VALIDATION_SCHEMA)
        result = transport.plan_temporary_ready(code, raw)
    elif kind == "menu_validation":
        result = transport.plan_temporary_preparation(plan, manifest, raw)
    else:
        result = transport.plan_boot_preparation(plan, manifest, raw,
            action="activate" if kind == "install" else "restore",
            payload_identities=payload_identities(manifest) if kind == "install" else None)
    return plan, manifest, raw, result


@pytest.mark.parametrize("kind,count", (("menu_validation", None), ("install", 19), ("recovery", 18), ("ready", 4)))
def test_second_window_has_new_identity_no_original_stable_steps_and_no_renewed_raw(kind, count):
    parent, manifest, raw, prepared = preparation_fixture(kind)
    assert prepared.parent_plan == parent
    assert prepared.plan.plan_sha256 != parent.plan_sha256
    assert prepared.session.plan_sha256 == prepared.plan.plan_sha256
    assert prepared.session.data == raw
    assert prepared.session.observed_epoch == 1791040000 + (200 if kind == "ready" else 0)
    assert len(prepared.plan.steps) == count if count is not None else len(prepared.plan.steps) > 2
    assert not set(prepared.plan.steps).intersection(parent.steps)
    assert prepared.plan.steps[0].label == "upload-immutable-session-context"
    assert prepared.plan.steps[1].label == "create-immutable-session-context"
    assert not prepared.installable
    original = stage.plan_raw_session_staging(parent, manifest, raw)
    assert prepared.session.data_sha256 == original.data_sha256
    assert prepared.session.binding_sha256 != original.binding_sha256
    assert prepared.parent_plan.plan_sha256 == parent.plan_sha256
    assert prepared.plan.include_session_file is False
    assert parent.phase == "stable-content" and prepared.plan.phase == "second-window-preparation"


def test_second_window_cannot_be_misreported_through_first_window_entry():
    _, _, _, prepared = preparation_fixture("recovery")
    launch = datetime.fromtimestamp(prepared.session.observed_epoch, timezone.utc)
    with pytest.raises(ValueError, match="stable-content"):
        transport.ContentStageCoordinator(prepared.plan, prepared.session)
    with pytest.raises(ValueError, match="stable-content"):
        transport.review_content_host_source(prepared.plan, prepared.session, launch)
    nested = replace(prepared, parent_plan=prepared.plan)
    with pytest.raises(ValueError, match="stable parent"):
        transport.SecondWindowPreparationCoordinator(nested)


def test_ready_window_requires_fresh_nonce_and_only_verifies_prior_code():
    parent, manifest, old_raw, code = preparation_fixture("menu_validation")
    values = sc.decode_session(old_raw)
    values.update(session_nonce="c" * 32, observed_epoch=values["observed_epoch"] + 200)
    fresh_raw = sc.encode_session(values, schema=sc.MENU_VALIDATION_SCHEMA)
    ready = transport.plan_temporary_ready(code, fresh_raw)
    assert ready.purpose == "temporary_menu_ready"
    assert ready.session.data == fresh_raw and ready.session.session_nonce == "c" * 32
    assert ready.parent_plan == parent and ready.code_preparation == code
    assert len(ready.plan.steps) == 4
    assert all(step.label.startswith("verify-existing-") for step in ready.plan.steps[2:])
    for step in ready.plan.steps[2:]:
        assert "mkdir" not in step.command and "tar -" not in step.command and "base64 -d" not in step.command
    with pytest.raises(ValueError, match="fresh"):
        transport.plan_temporary_ready(code, old_raw)


@pytest.mark.parametrize("changes", (
    {"session_nonce": "b" * 32}, {"observed_epoch": 1791039999},
    {"boot_id": "22222222-2222-3333-4444-555555555555"},
    {"mount_namespace": "mnt:[9]", "init_mount_namespace": "mnt:[9]", "observer_mount_namespace": "mnt:[9]",
     "core_gui_mount_namespace": "mnt:[9]", "core_service_mount_namespace": "mnt:[9]", "core_capture_mount_namespace": "mnt:[9]"},
))
def test_ready_rejects_reused_or_older_or_different_runtime_context(changes):
    _, _, raw, code = preparation_fixture("menu_validation")
    values = sc.decode_session(raw)
    values.update(session_nonce="c" * 32, observed_epoch=values["observed_epoch"] + 200)
    values.update(changes)
    with pytest.raises(ValueError, match="fresh"):
        transport.plan_temporary_ready(code, sc.encode_session(values, schema=sc.MENU_VALIDATION_SCHEMA))


def prepared_host(kind, *, elapsed=0):
    _, _, _, prepared = preparation_fixture(kind)
    now = [prepared.session.observed_epoch + elapsed]
    host = transport.SecondWindowPreparationCoordinator(prepared, clock=lambda: now[0])
    while (operation := host.next_preparation) is not None:
        host.accept_preparation(exit_code=0, stdout=operation.expected_stdout, completion_validated=True)
    return prepared, host, now


@pytest.mark.parametrize("kind", ("menu_validation", "ready", "install", "recovery"))
def test_each_second_window_native_source_compiles_but_refuses_before_usb(tmp_path, kind):
    _, _, _, prepared = preparation_fixture(kind)
    launch = datetime.fromtimestamp(prepared.session.observed_epoch, timezone.utc)
    source = transport.review_preparation_host_source(prepared, launch)
    assert transport._preparation_scope(prepared) in source
    namespace = re.search(r"namespace (X2d2ContentStage_[a-f0-9]+)", source)[1]
    filename = tmp_path / "preparation.cs"
    filename.write_text(source, encoding="utf-8")
    script = f'''
$ErrorActionPreference='Stop'
Add-Type -Path '{filename}'
try {{ [{namespace}.AdbUsbCheck]::RunContentStage(); throw 'unexpected execution' }}
catch {{ $e=$_.Exception;while($e.InnerException){{$e=$e.InnerException}};
 if($e.Code -ne 'CONTENT_SOURCE_NOT_QUALIFIED'){{throw}} }}
'PREPARATION_REFUSED_BEFORE_USB'
'''
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0 and "PREPARATION_REFUSED_BEFORE_USB" in result.stdout, result.stderr


@pytest.mark.parametrize("kind,fault", (("menu_validation", "none"), ("ready", "none"), ("install", "none"),
                                      ("recovery", "none"), ("recovery", "maintenance-failed")))
def test_actual_second_window_child_handshake_all_three_flows_without_stable_replay(tmp_path, kind, fault):
    elapsed = 0 if kind == "menu_validation" else 30
    prepared, host, now = prepared_host(kind, elapsed=elapsed)
    session = prepared.session
    launched = datetime.fromtimestamp(session.observed_epoch, timezone.utc)
    host.start_window(launched)
    assert host.remaining_window_seconds() == 80 - elapsed
    steps = stage.execution_steps(prepared.plan, dict(session.context), session=session)
    source = native_fixture_source(transport.review_preparation_host_source(prepared, launched),
                                  steps, session, fault="none", epoch=now[0])
    namespace = re.search(r"namespace (X2d2ContentStage_[a-f0-9]+)", source)[1]
    filename = tmp_path / "preparation-native-edge.cs"
    filename.write_text(source, encoding="utf-8")
    script = f"$ErrorActionPreference='Stop';Add-Type -Path '{filename}';[{namespace}.AdbUsbCheck]::RunContentStage()"
    process = subprocess.Popen(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    class Maintenance:
        count = 0

        def command(self, label, command):
            operation = host.observer.observations[self.count]
            assert command == operation.command and label == f"content-observe-{self.count}"
            self.count += 1
            if fault != "none":
                raise ValueError("recorded maintenance completion failed")
            result = maintenance_result(operation, session, observer=host.observer, epoch=now[0])
            assert result.returncode == 0 and result.stderr == ""
            return result.stdout

    maintenance = Maintenance()
    try:
        if fault == "none":
            result = transport.drive_preparation_process(process, host, maintenance)
            assert result["status"] == transport._preparation_scope(prepared)
            assert result["purpose"] == prepared.purpose
            assert result["launch_started_utc"] == launched.isoformat()
            assert result["worker_followup_allowed"] is (kind != "menu_validation")
            assert len(result["retained_adb_payloads"]) == maintenance.count == len(steps)
            assert host.all_results_validated and process.returncode == 0
            assert not result["installable"] and not result["usb_restore_verified"]
        else:
            with pytest.raises(ValueError, match="maintenance completion failed"):
                transport.drive_preparation_process(process, host, maintenance)
            assert host.failed and not host.all_results_validated and maintenance.count == 1
    finally:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()


@pytest.mark.parametrize("kind", ("menu_validation", "install", "recovery"))
def test_child_start_cannot_restart_common_launch_timer(kind):
    prepared, host, now = prepared_host(kind, elapsed=79)
    launched = datetime.fromtimestamp(prepared.session.observed_epoch, timezone.utc)
    host.start_window(launched)
    assert host.remaining_window_seconds() == 1
    now[0] += 1
    with pytest.raises(ValueError, match="original USB window expired"):
        host.remaining_window_seconds()


@pytest.mark.parametrize("damage", ("steps", "parent-hash", "purpose", "session-epoch", "raw-data"))
def test_preparation_cannot_relabel_parent_or_accept_arbitrary_command_mutation(damage):
    parent, _, _, prepared = preparation_fixture("recovery")
    if damage == "steps":
        prepared = replace(prepared, plan=replace(prepared.plan, steps=parent.steps))
    elif damage == "parent-hash":
        prepared = replace(prepared, plan=replace(prepared.plan, plan_sha256=parent.plan_sha256))
    elif damage == "purpose":
        prepared = replace(prepared, purpose="temporary_menu_preparation")
    elif damage == "session-epoch":
        prepared = replace(prepared, session=replace(prepared.session, observed_epoch=prepared.session.observed_epoch + 1))
    else:
        prepared = replace(prepared, raw_session=prepared.raw_session.replace(b"session_nonce=", b"unknown_nonce="))
    with pytest.raises(ValueError):
        transport.SecondWindowPreparationCoordinator(prepared)


def test_closed_specific_producers_reject_cross_kind_or_unneeded_recovery_dependencies():
    for kind in ("install", "recovery"):
        plan, manifest, raw = raw_fixture(kind)
        with pytest.raises(ValueError):
            transport.plan_temporary_preparation(plan, manifest, raw)
    plan, manifest, raw = raw_fixture("recovery")
    for action, dependencies in (("activate", None), ("restore", payload_identities(manifest)), ("other", None)):
        with pytest.raises(ValueError):
            transport.plan_boot_preparation(plan, manifest, raw, action=action, payload_identities=dependencies)


@pytest.mark.parametrize("cleanup_fails,fail_reply", ((False, False), (True, False), (False, True)))
def test_failed_real_child_retains_prefix_current_bytes_and_original_error(tmp_path, monkeypatch, cleanup_fails, fail_reply):
    prepared, host, now = prepared_host("recovery", elapsed=30)
    session = prepared.session
    launched = datetime.fromtimestamp(session.observed_epoch, timezone.utc)
    host.start_window(launched)
    steps = stage.execution_steps(prepared.plan, dict(session.context), session=session)
    source = native_fixture_source(transport.review_preparation_host_source(prepared, launched),
                                  steps, session, fault="none", epoch=now[0])
    namespace = re.search(r"namespace (X2d2ContentStage_[a-f0-9]+)", source)[1]
    filename = tmp_path / "partial-native-edges.cs"
    filename.write_text(source, encoding="utf-8")
    script = f"$ErrorActionPreference='Stop';Add-Type -Path '{filename}';[{namespace}.AdbUsbCheck]::RunContentStage()"
    process = subprocess.Popen(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    original_error = ValueError("ORIGINAL_STAGE_FAILURE")
    if fail_reply:
        def reject_reply(line):
            raise original_error
        monkeypatch.setattr(host, "accept_su_reply", reject_reply)

    class Maintenance:
        count = 0

        def command(self, label, command):
            operation = host.observer.observations[self.count]
            assert command == operation.command
            self.count += 1
            if self.count == 2:
                raise original_error
            result = maintenance_result(operation, session, observer=host.observer, epoch=now[0])
            assert result.returncode == 0 and not result.stderr
            return result.stdout

    maintenance = Maintenance()
    terminate = process.terminate
    if cleanup_fails:
        def terminate_then_fail():
            terminate()
            raise OSError("HOST_CLEANUP_FAILURE")
        monkeypatch.setattr(process, "terminate", terminate_then_fail)
    try:
        with pytest.raises(ValueError, match="ORIGINAL_STAGE_FAILURE") as caught:
            transport.drive_preparation_process(process, host, maintenance)
        assert caught.value is original_error and host.failed
        evidence = caught.value.partial_evidence
        assert evidence["candidate_sha256"] == prepared.plan.candidate_sha256
        assert evidence["plan_sha256"] == prepared.plan.plan_sha256
        assert evidence["session_data_sha256"] == session.data_sha256
        assert evidence["launch_started_utc"] == launched.isoformat()
        assert evidence["phase"] == ("validate-native-completion" if fail_reply else "maintenance-observation")
        assert len(evidence["retained_adb_payloads"]) == (0 if fail_reply else 1)
        assert evidence["command_index"] == (0 if fail_reply else 1)
        current = evidence["current_adb_payload"]
        assert bool(current) is fail_reply and evidence["current_adb_payload_sha256"] == sha(current)
        if current:
            assert current.startswith(steps[0].expected_stdout.encode("ascii"))
        for row in evidence["retained_adb_payloads"]:
            assert row["sha256"] == sha(row["raw"])
        assert bool(evidence["cleanup_errors"]) is cleanup_fails
        assert not evidence["installable"] and not evidence["usb_restore_verified"]
    finally:
        if process.poll() is None:
            terminate()
        process.wait(timeout=5)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()
