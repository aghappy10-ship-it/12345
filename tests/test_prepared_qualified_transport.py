"""Exact final/recovery admission for prepared operations; no device execution."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import re
import subprocess
from unittest.mock import Mock

import pytest

from tests.test_release_lifecycle import installer, recovery_fixture
from tests.test_prepared_boot_transport import preparation_case, parent_plan_for
from tests.test_menu_owned_cleanup import cleanup_inputs
from tests.test_recovery_role_v2 import role_recovery_context
from tests.test_menu_content_transport import native_fixture_source
from tests.menu_transport_wire_fixture import native_disabled_source
from tests.test_stage_menu_delivery import maintenance_result
from tools import menu_prepared_transport as prepared, menu_content_transport as content
from tools import prepare_peer_install as install, prepare_peer_recovery as recovery
from tools import session_context as sc


def activation_case(installer, *, with_wire=False):
    plan, report, epoch, scripts, responses, options = preparation_case(installer, "activate")
    operation = prepared.PreparedBootOperation(plan, clock=lambda: epoch)
    raw = json.dumps(report, indent=2).encode()
    q = deepcopy(installer.q)
    window = {"approved": True, "purpose": "temporary_adb_fixed_menu_staging",
        "candidate_sha256": operation.manifest["candidate_sha256"], "plan_sha256": plan.plan.plan_sha256,
        "boot_id": q["boot_id"], "session_nonce": q["session_nonce"],
        "session_data_sha256": plan.session.data_sha256,
        "launch_session_sha256": install.sha(raw), "launch_started_utc": report["commands"][0]["utc"]}
    result = operation, raw, q, window, epoch
    return result + (scripts, responses) if with_wire else result


def inert_run_boundary(monkeypatch, operation, epoch, *, damage=None):
    """Only two tiny no-import strings can reach this mocked process boundary."""
    prep = ("private static readonly bool ContentQualified = false;\n"
            f"private const long ContentDeadlineEpoch = {epoch+80};\n")
    worker = ("private static readonly bool SupervisionQualified = false;\n"
              f"private const long OriginalWindowDeadline = {epoch+80};\n")
    monkeypatch.setattr(content, "review_preparation_host_source", lambda *args: prep)
    monkeypatch.setattr(operation, "_worker_source", lambda *args: worker)
    attempted = []
    def original_run(report, maintenance, start):
        for phase, source in (("preparation", prep), (operation._worker_phase, worker)):
            attempted.append(phase)
            start(phase, source + "CHANGED" if damage == phase else source)
        return {"installable": False, "usb_restore_verified": False, "status": "INERT_TEST_NOT_EXECUTED"}
    monkeypatch.setattr(operation, "run", original_run)
    started = []
    def start(phase, source):
        assert "DllImport(" not in source and "extern " not in source
        started.append((phase, source))
        return object()
    return start, started, attempted


def test_actual_final_validator_rejects_synthetic_prepared_before_start(installer, monkeypatch):
    operation, raw, q, window, epoch = activation_case(installer)
    start, started, _ = inert_run_boundary(monkeypatch, operation, epoch)
    with pytest.raises(ValueError, match="synthetic"):
        operation.run_qualified(raw, object(), start, qualification=q, window_authorization=window)
    assert not started


@pytest.mark.parametrize("damage", (None, "preparation", "boot-activate", "late-qualification", "raw-context"))
def test_counterfactual_final_rechecks_before_each_fixed_child_and_keeps_deadline(installer, monkeypatch, damage):
    operation, raw, q, window, epoch = activation_case(installer)
    start, started, _ = inert_run_boundary(monkeypatch, operation, epoch, damage=damage)
    checks = []
    def validate(manifest, qualification, **kwargs):
        checks.append(kwargs)
        if damage == "late-qualification" and len(checks) == 3:
            raise ValueError("late qualification no longer valid")
    monkeypatch.setattr(install, "validate_qualification", validate)
    if damage == "raw-context":
        q["session_nonce"] = "e" * 32
    if damage is None:
        result = operation.run_qualified(raw, object(), start, qualification=q, window_authorization=window)
        assert len(started) == 2 and len(checks) >= 3
        assert "ContentQualified = true" in started[0][1]
        assert "SupervisionQualified = true" in started[1][1]
        assert all(str(epoch+60) in source and str(epoch+80) not in source for _, source in started)
        assert all(check == {"for_publication": True} for check in checks)
        assert not result["installable"] and not result["usb_restore_verified"]
    else:
        with pytest.raises(ValueError):
            operation.run_qualified(raw, object(), start, qualification=q, window_authorization=window)
        assert len(started) == (1 if damage in ("boot-activate", "late-qualification") else 0)


def test_temporary_menu_operation_cannot_enter_formal_qualified_adapter(monkeypatch):
    # Exact type is enough to reject; no candidate or fabricated authorization
    # is needed to reach any renderer or process boundary.
    operation = object.__new__(prepared.PreparedMenuPlacementOperation)
    operation.failed = False
    start = Mock(side_effect=AssertionError("temporary operation reached child"))
    with pytest.raises(ValueError, match="temporary|formal"):
        operation.run_qualified(b"{}", object(), start, qualification={}, window_authorization={})
    start.assert_not_called()


@pytest.mark.parametrize("relative", ("tools/menu_prepared_transport.py", "tools/stage_menu_delivery.py",
    "tools/menu_owned_cleanup.py", "tools/menu_cleanup_transport.py", "tools/menu_stock_boot.py",
    "tools/stage_peer_usb_access.py", "tests/test_prepared_qualified_transport.py",
    "tests/test_menu_preplacement_transport.py", "tests/test_role_end_to_end.py",
    "tests/test_recovery_role_publication.py"))
def test_recovery_build_subject_binds_actual_prepared_cleanup_sources_and_tests(recovery_fixture, monkeypatch, relative):
    _, saved_sha, _ = role_recovery_context(recovery_fixture)
    baseline = recovery.build_subject_sha256(recovery_fixture.saved, saved_sha)
    original = Path.read_bytes
    target = (recovery.ROOT / relative).resolve()
    def changed(path):
        raw = original(path)
        return raw + b"\nINERT BUILD CLOSURE DIFFERENCE\n" if path.resolve() == target else raw
    monkeypatch.setattr(Path, "read_bytes", changed)
    assert recovery.build_subject_sha256(recovery_fixture.saved, saved_sha) != baseline, relative


def recovery_case(installer, action):
    if action == "restore":
        plan, report, epoch, _, _, options = preparation_case(installer, "restore")
        operation = prepared.PreparedBootOperation(plan, backup_identity=options["backup_identity"], clock=lambda: epoch)
        backup = options["backup_identity"]
    else:
        args = cleanup_inputs(installer)
        plan = content.plan_cleanup_preparation(parent_plan_for(installer.manifest), installer.manifest, *args)
        operation = prepared.PreparedCleanupOperation(plan, clock=lambda: sc.decode_session(args[0])["observed_epoch"])
        epoch = plan.session.observed_epoch
        from tests.test_stage_peer_usb_access import recorded_launch_fixture
        report = recorded_launch_fixture()
        report["commands"][0]["utc"] = datetime.fromtimestamp(epoch, timezone.utc).isoformat()
        report["bootId"] = sc.decode_session(plan.raw_session)["boot_id"]
        backup = args[3]["backup_identity"]
    raw = json.dumps(report).encode()
    values = sc.decode_session(plan.raw_session)
    q = {"synthetic": True, "candidate_sha256": operation.manifest["candidate_sha256"],
        "observed_utc": plan.session.observed_utc, "boot_id": values["boot_id"],
        "session_nonce": values["session_nonce"], "mount_namespace": values["mount_namespace"],
        "init_mount_namespace": values["init_mount_namespace"], "backup_identity": backup}
    window = {"approved": True, "purpose": "temporary_adb_fixed_menu_staging",
        "candidate_sha256": operation.manifest["candidate_sha256"], "plan_sha256": plan.plan.plan_sha256,
        "boot_id": q["boot_id"], "session_nonce": q["session_nonce"], "session_data_sha256": plan.session.data_sha256,
        "launch_session_sha256": install.sha(raw), "launch_started_utc": report["commands"][0]["utc"]}
    return operation, raw, q, window, epoch


@pytest.mark.parametrize("action", ("restore", "cleanup"))
def test_counterfactual_recovery_route_uses_only_independent_recovery_validator(installer, monkeypatch, action):
    operation, raw, q, window, epoch = recovery_case(installer, action)
    # Inert boundary only: no saved candidate is read and no qualification is
    # claimed. Actual rejection with synthetic input remains separately tested.
    checks = Mock()
    monkeypatch.setattr(recovery, "validate_qualification", checks)
    monkeypatch.setattr(recovery, "load_saved_candidate", lambda *args: operation.manifest)
    monkeypatch.setattr(recovery, "role_delivery", lambda *args: True)
    monkeypatch.setattr(recovery, "session_data", lambda *args: operation.preparation.raw_session)
    monkeypatch.setattr(install, "validate_qualification", Mock(side_effect=AssertionError("recovery called final install validator")))
    start, started, _ = inert_run_boundary(monkeypatch, operation, epoch)
    result = operation.run_qualified(raw, object(), start, qualification=q, window_authorization=window,
        saved_manifest=Path("inert-not-read.json"), saved_manifest_sha256="d" * 64)
    assert len(started) == 2 and checks.call_count >= 3 and not result["installable"]
    assert all(call.kwargs == {"for_publication": True} for call in checks.call_args_list)


@pytest.mark.parametrize("action", ("restore", "cleanup"))
def test_actual_recovery_validator_rejects_synthetic_without_install_fallback(installer, monkeypatch, action):
    operation, raw, q, window, epoch = recovery_case(installer, action)
    monkeypatch.setattr(install, "validate_qualification", Mock(side_effect=AssertionError("install fallback")))
    start, started, _ = inert_run_boundary(monkeypatch, operation, epoch)
    with pytest.raises(ValueError, match="synthetic recovery"):
        operation.run_qualified(raw, object(), start, qualification=q, window_authorization=window,
            saved_manifest=Path("not-read-for-synthetic.json"), saved_manifest_sha256="d" * 64)
    assert not started and operation.failed


@pytest.mark.parametrize("damage", ("not-bytes", "empty", "oversize", "hash", "duplicate-json", "failed",
    "error", "stager", "decoder", "boot", "missing-start", "reply-time", "unapproved", "plan", "session"))
def test_prepared_launch_and_window_fail_closed_before_any_child(installer, monkeypatch, damage):
    operation, raw, q, window, epoch = activation_case(installer)
    monkeypatch.setattr(install, "validate_qualification", Mock())
    start, started, _ = inert_run_boundary(monkeypatch, operation, epoch)
    report = json.loads(raw)
    if damage == "not-bytes": raw = report
    elif damage == "empty": raw = b""
    elif damage == "oversize": raw = b" " * (1024 * 1024 + 1)
    elif damage == "hash": raw += b" "
    elif damage == "unapproved": window["approved"] = False
    elif damage == "plan": window["plan_sha256"] = "d" * 64
    elif damage == "session": window["session_data_sha256"] = "d" * 64
    else:
        if damage == "failed": report["status"] = "FAILED_OR_UNCERTAIN_DO_NOT_RETRY_AUTOMATICALLY"
        elif damage == "error": report["error"] = "transport failure"
        elif damage == "stager": report["stagerSha256"] = "0" * 64
        elif damage == "decoder": report["replySources"] = {}
        elif damage == "boot": report["bootId"] = "33333333-4444-4555-8666-777777777777"
        elif damage == "missing-start": report["commands"][0].pop("utc")
        elif damage == "reply-time": window["launch_started_utc"] = report["launchUtc"]
        raw = json.dumps(report).encode()
        if damage == "duplicate-json": raw = b'{"bootId":"duplicate",' + raw[1:]
        window["launch_session_sha256"] = install.sha(raw)
    with pytest.raises(ValueError):
        operation.run_qualified(raw, object(), start, qualification=q, window_authorization=window)
    assert not started and operation.failed


@pytest.mark.parametrize("damage", ("missing-manifest", "missing-hash", "manifest", "legacy", "backup", "raw"))
def test_prepared_recovery_exact_saved_inputs_required_before_any_child(installer, monkeypatch, damage):
    operation, raw, q, window, epoch = recovery_case(installer, "restore")
    monkeypatch.setattr(recovery, "validate_qualification", Mock())
    saved = deepcopy(operation.manifest)
    if damage == "manifest": saved["unbound_new_field"] = True
    monkeypatch.setattr(recovery, "load_saved_candidate", lambda *args: saved)
    monkeypatch.setattr(recovery, "role_delivery", lambda *args: damage != "legacy")
    monkeypatch.setattr(recovery, "session_data", lambda *args:
        operation.preparation.raw_session + (b" " if damage == "raw" else b""))
    monkeypatch.setattr(install, "validate_qualification", Mock(side_effect=AssertionError("install fallback")))
    if damage == "backup": q["backup_identity"] = "1:99:81a4:1:1:0:0"
    start, started, _ = inert_run_boundary(monkeypatch, operation, epoch)
    with pytest.raises(ValueError):
        operation.run_qualified(raw, object(), start, qualification=q, window_authorization=window,
            saved_manifest=None if damage == "missing-manifest" else Path("inert-not-read.json"),
            saved_manifest_sha256=None if damage == "missing-hash" else "d" * 64)
    assert not started and operation.failed


@pytest.mark.parametrize("late_rejection", (False, True))
def test_counterfactual_qualified_real_run_preserves_preparation_before_second_child_failure(
        installer, monkeypatch, tmp_path, late_rejection):
    """Actual Python run and child pipes; admission/native observations are inert.

    Every native declaration is removed BEFORE qualified_start can receive a
    source. The only bypass is the explicitly mocked final validator; this is
    not qualification or camera evidence.
    """
    operation, raw, q, window, epoch, scripts, responses = activation_case(installer, with_wire=True)
    plan = operation.preparation
    checks = []
    def validate(*args, **kwargs):
        checks.append(kwargs)
        if late_rejection and len(checks) == 3:
            raise ValueError("second child qualification deliberately invalidated")
    monkeypatch.setattr(install, "validate_qualification", validate)
    original_preparation, original_worker = content.review_preparation_host_source, operation._worker_source

    def inert_preparation(preparation, launch):
        steps = content.stage.execution_steps(plan.plan, dict(plan.session.context), session=plan.session)
        source = native_fixture_source(original_preparation(preparation, launch), steps, plan.session,
                                       fault="none", epoch=epoch)
        assert "DllImport" not in source and "extern " not in source
        return source.replace("ContentQualified = true", "ContentQualified = false")

    def inert_worker(launch):
        source = native_disabled_source(original_worker(launch), epoch)
        # The source arrives with the wrapper's qualified guard already true;
        # this fixture asserts it and never changes the guard by reflection.
        old = ('if((bool)field.GetValue(null)) throw new InvalidOperationException("FIXTURE_EXPECTED_PRODUCTION_REFUSAL");\n'
               '                field.SetValue(null,true);')
        new = 'if(!(bool)field.GetValue(null)) throw new InvalidOperationException("FIXTURE_EXPECTED_QUALIFIED_ADAPTER");'
        assert source.count(old) == 1
        source = source.replace(old, new)
        assert "DllImport" not in source and "extern " not in source
        return source

    monkeypatch.setattr(content, "review_preparation_host_source", inert_preparation)
    monkeypatch.setattr(operation, "_worker_source", inert_worker)

    class Maintenance:
        def command(self, label, command):
            if label.startswith("prepare-observer-"):
                expected = operation.coordinator.next_preparation
                assert command == expected.command
                return expected.expected_stdout
            if label.startswith("content-observe-"):
                expected = operation.coordinator.observer.observations[int(label.rsplit("-", 1)[1])]
                assert command == expected.command
                result = maintenance_result(expected, plan.session, observer=operation.coordinator.observer, epoch=epoch)
                assert result.returncode == 0, result.stderr
                return result.stdout
            return responses[command]

    starts = []
    def start(phase, source):
        assert "DllImport" not in source and "extern " not in source
        starts.append(phase)
        filename = tmp_path / (phase + ".cs")
        filename.write_text(source, encoding="utf-8")
        if phase == "preparation":
            namespace = re.search(r"namespace (X2d2ContentStage_[a-f0-9]+)", source)[1]
            program = f"$ErrorActionPreference='Stop';Add-Type -Path '{filename}';[{namespace}.AdbUsbCheck]::RunContentStage()"
        else:
            namespace = re.search(r"namespace (X2d2MenuBoot_[a-f0-9]+)", source)[1]
            transcript = tmp_path / "scripts.json"
            transcript.write_text(json.dumps(scripts), encoding="ascii")
            program = f"""$ErrorActionPreference='Stop'
Add-Type -Path '{filename}'
[string[]]$frames=Get-Content -LiteralPath '{transcript}' -Raw | ConvertFrom-Json
$result=[{namespace}.WireFixture]::Run($frames,@(),3,$true)
if($result.Error){{[Console]::Error.WriteLine($result.Error);exit 1}}
"""
        return subprocess.Popen(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", program],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    maintenance = Maintenance()
    operation.prepare_observer(maintenance)
    if late_rejection:
        with pytest.raises(ValueError, match="second child qualification") as caught:
            operation.run_qualified(raw, maintenance, start, qualification=q, window_authorization=window)
        evidence = caught.value.prepared_operation_evidence
        assert starts == ["preparation"] and operation.failed
        assert evidence["phase"] == "before-worker" and evidence["worker_result"] is None
        assert evidence["preparation_result"]["status"] == content._preparation_scope(plan)
    else:
        result = operation.run_qualified(raw, maintenance, start, qualification=q, window_authorization=window)
        assert starts == ["preparation", "boot-activate"]
        assert result["preparation_result"]["status"] == content._preparation_scope(plan)
        assert result["worker_result"] is not None and result["qualification_route"] == "final_installation"
        assert not result["installable"] and not result["usb_restore_verified"]
    assert all(row == {"for_publication": True} for row in checks) and len(checks) == 3


@pytest.mark.parametrize("when", ("fresh", "before-first", "before-second", "after-worker-render"))
def test_formal_remaining_budget_counts_only_pending_phases_and_retains_preparation(installer, monkeypatch, when):
    from tests.test_prepared_menu_transport import formal_case
    plan, report, epoch, _, prior = formal_case(installer)
    operation = prepared.PreparedFormalPlacementOperation(plan, clock=lambda: epoch, **prior)
    q = deepcopy(installer.q)
    raw = json.dumps(report).encode()
    launch = datetime.fromtimestamp(epoch, timezone.utc)
    window = {"approved": True, "purpose": "temporary_adb_fixed_menu_staging",
        "candidate_sha256": operation.manifest["candidate_sha256"], "plan_sha256": plan.plan.plan_sha256,
        "boot_id": q["boot_id"], "session_nonce": q["session_nonce"],
        "session_data_sha256": plan.session.data_sha256, "launch_session_sha256": install.sha(raw),
        "launch_started_utc": launch.isoformat()}
    assert len(plan.plan.steps) == 17
    now = [launch + timedelta(seconds=15 if when == "before-first" else 0)]
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return now[0]
    monkeypatch.setattr(prepared, "datetime", Clock)
    monkeypatch.setattr(install, "validate_qualification", Mock())
    prep_source = ("private static readonly bool ContentQualified = false;\n"
                   f"private const long ContentDeadlineEpoch = {epoch+80};\n")
    worker_source = ("private static readonly bool SupervisionQualified = false;\n"
                     f"private const long OriginalWindowDeadline = {epoch+80};\n")
    monkeypatch.setattr(content, "review_preparation_host_source", lambda *args: prep_source)
    def worker(*args):
        if when == "after-worker-render" and now[0] > launch:
            now[0] = launch + timedelta(seconds=32)
        return worker_source
    monkeypatch.setattr(operation, "_worker_source", worker)
    retained = {"status": content._preparation_scope(plan), "installable": False}
    def completed_preparation(*args):
        # External transport is inert. Actual run() preserves its returned
        # evidence if qualification prevents the second child from starting.
        now[0] = launch + timedelta(seconds=32 if when == "before-second" else 30)
        return retained
    monkeypatch.setattr(content, "drive_preparation_process", completed_preparation)
    monkeypatch.setattr(operation, "_drive_worker", lambda *args: {"status": "INERT_WORKER_NOT_EXECUTED"})
    class Maintenance:
        def command(self, label, command):
            expected = operation.coordinator.next_preparation
            assert expected.command == command
            return expected.expected_stdout
    class Child:
        def __init__(self):
            self.stdin, self.stdout, self.stderr = io.BytesIO(), io.BytesIO(), io.BytesIO()
        def poll(self): return 0
        def wait(self, timeout): return 0
    starts = []
    def start(phase, source):
        assert "DllImport" not in source and "extern " not in source
        starts.append(phase)
        return Child()
    operation.prepare_observer(Maintenance())
    if when == "fresh":
        result = operation.run_qualified(raw, Maintenance(), start, qualification=q, window_authorization=window)
        assert starts == ["preparation", "menu-preplacement"] and not result["installable"]
        assert result["preparation_result"] is retained
    else:
        with pytest.raises(ValueError, match="maintenance.*budget|maintenance.*window") as caught:
            operation.run_qualified(raw, Maintenance(), start, qualification=q, window_authorization=window)
        assert operation.failed
        if when == "before-first":
            assert starts == []
        else:
            assert starts == ["preparation"]
            assert caught.value.prepared_operation_evidence["phase"] == "before-worker"
            assert caught.value.prepared_operation_evidence["preparation_result"] is retained


@pytest.mark.parametrize("action", ("restore", "restore-already-official", "cleanup"))
def test_recovery_budget_uses_exact_worker_branch_without_mutable_install_inputs(installer, monkeypatch, action):
    operation, raw, q, window, epoch = recovery_case(installer, "cleanup" if action == "cleanup" else "restore")
    if action == "restore-already-official":
        old = operation.preparation
        values = sc.decode_session(old.raw_session)
        values["rc_sha256"] = operation.manifest["candidate"]["rc"]["before"]
        plan = content.plan_boot_preparation(old.parent_plan, operation.manifest, sc.encode_session(values), action="restore")
        operation = prepared.PreparedBootOperation(plan, backup_identity=q["backup_identity"], clock=lambda: epoch)
        window.update(plan_sha256=plan.plan.plan_sha256, session_data_sha256=plan.session.data_sha256)
    plan = operation.preparation
    # No real recovery qualification is created by this test. Its subject is
    # the fixed downstream phase count and absence of installation dependencies.
    monkeypatch.setattr(recovery, "validate_qualification", Mock())
    monkeypatch.setattr(recovery, "load_saved_candidate", lambda *args: operation.manifest)
    monkeypatch.setattr(recovery, "role_delivery", lambda *args: True)
    monkeypatch.setattr(recovery, "session_data", lambda *args: plan.raw_session)
    monkeypatch.setattr(install, "validate_qualification", Mock(side_effect=AssertionError("install admission reached")))
    monkeypatch.setattr(install, "inventory", Mock(side_effect=AssertionError("mutable install inventory reached")))
    from tools import delivery_files
    monkeypatch.setattr(delivery_files, "assemble_role_delivery", Mock(side_effect=AssertionError("mutable payload assembly reached")))
    mutable = {(install.ROOT / item["source"]).resolve() for item in operation.manifest["candidate"]["files"]}
    mutable.add((install.ROOT / operation.manifest["candidate"]["rc"]["source"]).resolve())
    original_read = Path.read_bytes
    def read(path):
        assert path.resolve() not in mutable, "recovery budget read mutable install payload"
        return original_read(path)
    monkeypatch.setattr(Path, "read_bytes", read)
    original_budget = content.stage._require_maintenance_budget
    counts = []
    def budget(deadline, **kwargs):
        counts.append(kwargs["remaining_commands"])
        return original_budget(deadline, **kwargs)
    monkeypatch.setattr(content.stage, "_require_maintenance_budget", budget)
    start, started, _ = inert_run_boundary(monkeypatch, operation, epoch)
    result = operation.run_qualified(raw, object(), start, qualification=q, window_authorization=window,
        saved_manifest=Path("inert-not-read.json"), saved_manifest_sha256="d" * 64)
    worker_count = {"restore": 8, "restore-already-official": 2, "cleanup": 16}[action]
    assert counts == [len(plan.plan.steps) + worker_count] * 3 + [worker_count] * 2
    assert len(started) == 2 and not result["installable"]
