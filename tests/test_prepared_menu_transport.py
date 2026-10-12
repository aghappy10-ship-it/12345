"""Fresh ready window into four-file placement; all native I/O is disabled.

The public seam is the prepared operation over child pipes. Maintenance and
native USB are external boundary substitutes, not live installation evidence.
"""
from datetime import datetime, timezone
from copy import deepcopy
from dataclasses import replace
import importlib
import re
import subprocess

import pytest

from tests.test_release_lifecycle import installer
from tests.test_prepared_boot_transport import parent_plan_for
from tests.test_menu_preplacement_transport import wire_case
from tests.test_preplacement_host_dialogue import interactive_process
from tests.test_menu_content_transport import native_fixture_source
from tests.test_stage_menu_delivery import maintenance_result
from tests.test_temporary_menu_session import temporary_values
from tests.test_stage_peer_usb_access import recorded_launch_fixture
from tools import menu_content_transport as content, stage_menu_delivery as stage
from tools import menu_preplacement_transport as placement, menu_maintenance_boundary as boundary
from tools import prepare_peer_install as peer, session_context as sc
from tools import stage_peer_usb_access as usb


def ready_case(installer):
    parent = parent_plan_for(installer.manifest)
    _, epoch, scripts, _, _ = wire_case(installer)
    values = temporary_values(installer)
    raw = sc.encode_session(values, schema=sc.MENU_VALIDATION_SCHEMA)
    prior = dict(values, session_nonce="a" * 32, observed_epoch=epoch - 200)
    code = content.plan_temporary_preparation(parent, installer.manifest,
        sc.encode_session(prior, schema=sc.MENU_VALIDATION_SCHEMA))
    prepared = content.plan_temporary_ready(code, raw)
    report = recorded_launch_fixture()
    report["commands"][0]["utc"] = datetime.fromtimestamp(epoch, timezone.utc).isoformat()
    report["bootId"] = values["boot_id"]
    return prepared, report, epoch, scripts


def prior_window_evidence(plan, session, report, epoch):
    """Explicit synthetic prior transport boundary, not a claim of live staging."""
    previous = recorded_launch_fixture()
    old_root = previous["remote"]
    previous["remote"] = "/tmp/x2a-000000abcdef"
    previous["commands"][0]["command"] = previous["commands"][0]["command"].replace(old_root, previous["remote"])
    previous["commands"][0]["utc"] = datetime.fromtimestamp(epoch - 200, timezone.utc).isoformat()
    previous["bootId"] = report["bootId"]
    payloads = []
    for index, item in enumerate(stage.execution_steps(plan, dict(session.context), session=session)):
        raw = (item.expected_stdout + f"\nX2DII_CONTENT_{session.binding_sha256[:24]}_{index}_RC=0\n").encode()
        payloads.append(dict(index=index, raw=raw, sha256=peer.sha(raw)))
    root = report["remote"]
    producers = "".join(f"{digest}  /proc/{i+100}/exe\n" for i, (_, digest) in enumerate(usb.TRANSPORT_PRODUCERS))
    prefix = [
        ("transport-hash", usb.live.QUERIES["transport_hash"], producers),
        ("boot-id", "cat /proc/sys/kernel/random/boot_id", report["bootId"] + "\n"),
        ("usb-state", "getprop sys.usb.config;getprop sys.usb.state;getprop init.svc.adbd", usb.BASE + "\n" + usb.BASE + "\nstopped\n"),
        ("uid", "id -u", "0\n"),
        ("lock-absent", "[ ! -e /tmp/x2dii-peer-adb.lock ] && [ ! -L /tmp/x2dii-peer-adb.lock ]", ""),
        ("recheck-script", f"sha256sum {root}/s", usb.SCRIPT_SHA + "  " + root + "/s\n"),
        ("check-syntax", f"sh -n {root}/s", ""),
    ]
    rows = [dict(label=label, command=command, text=text, exit=0,
        utc=datetime.fromtimestamp(epoch, timezone.utc).isoformat()) for label, command, text in prefix]
    # Real launch records also retain stage's earlier duplicate preflight labels.
    report["commands"] = deepcopy(rows[:5]) + rows + report["commands"]
    return payloads, previous


def previous_code_evidence(prepared, report, epoch):
    code = prepared.code_preparation
    payloads, previous = prior_window_evidence(code.plan, code.session, report, epoch)
    result = dict(status=content._preparation_scope(code), purpose=code.purpose,
        preparation_plan_sha256=code.plan.plan_sha256, session_data_sha256=code.session.data_sha256,
        launch_started_utc=previous["commands"][0]["utc"],
        worker_followup_allowed=False, installable=False, usb_restore_verified=False, retained_adb_payloads=payloads)
    return dict(previous_code_result=result, previous_launch_report=previous)


def formal_case(installer):
    parent = parent_plan_for(installer.manifest)
    _, epoch, scripts, _, _ = wire_case(installer, session_kind="install")
    raw = peer.session_data(installer.manifest, installer.q)
    prepared = content.plan_install_preparation(parent, installer.manifest, raw)
    report = recorded_launch_fixture()
    report["commands"][0]["utc"] = datetime.fromtimestamp(epoch, timezone.utc).isoformat()
    values = sc.decode_session(raw)
    report["bootId"] = values["boot_id"]
    old_raw = sc.encode_session(dict(values, session_nonce="a" * 32, observed_epoch=epoch - 200), schema=sc.INSTALL_SCHEMA)
    previous_session = stage.plan_raw_session_staging(parent, installer.manifest, old_raw)
    payloads, previous = prior_window_evidence(parent, previous_session, report, epoch)
    result = dict(status=content.ContentStageCoordinator.final_scope,
        candidate_sha256=installer.manifest["candidate_sha256"], plan_sha256=parent.plan_sha256,
        session_data_sha256=previous_session.data_sha256, session_binding_sha256=previous_session.binding_sha256,
        launch_started_utc=previous["commands"][0]["utc"], installable=False,
        usb_restore_verified=False, retained_adb_payloads=payloads)
    prior = dict(previous_content_result=result, previous_content_session=previous_session, previous_launch_report=previous)
    return prepared, report, epoch, scripts, prior


@pytest.mark.parametrize("fault", ("none", "preparation", "expired-before-worker", "second-file"))
@pytest.mark.parametrize("kind", ("menu_validation", "install"))
def test_ready_and_placement_share_original_launch_and_retain_four_file_identities(installer, tmp_path, fault, kind):
    module = importlib.import_module("tools.menu_prepared_transport")
    if kind == "install":
        prepared, report, epoch, scripts, prior = formal_case(installer)
        operation_type = module.PreparedFormalPlacementOperation
    else:
        prepared, report, epoch, scripts = ready_case(installer)
        prior = previous_code_evidence(prepared, report, epoch)
        operation_type = module.PreparedMenuPlacementOperation
    launches, now = [], [epoch]
    operation = operation_type(prepared, clock=lambda: now[0], **prior)
    values = sc.decode_session(prepared.raw_session)

    class Maintenance:
        def command(self, label, command):
            if label.startswith("prepare-observer-"):
                expected = operation.coordinator.next_preparation
                assert expected.command == command
                return expected.expected_stdout
            if label.startswith("content-observe-"):
                if fault == "preparation":
                    raise OSError("ready maintenance failed")
                expected = operation.coordinator.observer.observations[int(label.rsplit("-", 1)[1])]
                assert expected.command == command
                result = maintenance_result(expected, prepared.session, observer=operation.coordinator.observer, epoch=epoch)
                assert result.returncode == 0, result.stderr
                return result.stdout
            _, program, data_sha, file_index, boundary_index, request_sha = command.split()
            file_index, boundary_index = int(file_index), int(boundary_index)
            if fault == "second-file" and (file_index, boundary_index) == (1, 0):
                raise OSError("placement maintenance failed after first file")
            assert data_sha == peer.sha(prepared.raw_session)
            assert program == boundary.paths(installer.manifest, file_index, boundary_index,
                session_data_sha256=data_sha, session_kind=kind)["program"]
            program_sha = peer.sha(placement.render_supervised_preplacement(installer.manifest,
                file_index=file_index, session_kind=kind).encode("ascii"))
            challenge = peer.sha(f"{values['boot_id']}:{values['session_nonce']}:{file_index}:{boundary_index}:{program_sha}\n".encode())
            request = boundary.make_request(installer.manifest, prepared.raw_session, worker_session_sha256=data_sha,
                worker_program_sha256=program_sha, file_index=file_index, boundary_index=boundary_index,
                challenge=challenge, issued_epoch=epoch)
            assert request_sha == peer.sha(request)
            response = request.replace(boundary.REQUEST_SCHEMA.encode(), boundary.RESPONSE_SCHEMA.encode(), 1)
            return (response + (f"request_sha256={request_sha}\nstarted_epoch={epoch}\nchecked_epoch={epoch}\n"
                "result=OBSERVED_MATCH\nscope=ONE_BOUNDARY_ONLY_NOT_AUTHORIZATION\n").encode()).decode("ascii")

    def start_process(phase, source):
        launches.append(phase)
        constant = "ContentLaunchEpoch" if phase == "preparation" else "OriginalWindowLaunch"
        assert f"{constant} = {epoch}" in source
        if phase == "preparation":
            steps = stage.execution_steps(prepared.plan, dict(prepared.session.context), session=prepared.session)
            rendered = native_fixture_source(source, steps, prepared.session, fault="none", epoch=epoch)
            namespace = re.search(r"namespace (X2d2ContentStage_[a-f0-9]+)", rendered)[1]
            filename = tmp_path / "ready-native-disabled.cs"
            filename.write_text(rendered, encoding="utf-8")
            script = f"$ErrorActionPreference='Stop';Add-Type -Path '{filename}';[{namespace}.AdbUsbCheck]::RunContentStage()"
            process = subprocess.Popen(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if fault == "expired-before-worker":
                real_wait = process.wait
                def waited(*args, **kwargs):
                    result = real_wait(*args, **kwargs)
                    now[0] = epoch + 81
                    return result
                process.wait = waited
            return process
        assert phase == "menu-preplacement"
        return interactive_process(source, epoch, scripts, tmp_path)

    maintenance = Maintenance()
    operation.prepare_observer(maintenance)
    identities = tuple(
        f"1:{index+2}:81a4:1:{row['bytes']}:0:0"
        for index, row in enumerate(installer.manifest["candidate"]["files"]))
    if fault == "none":
        result = operation.run(report, maintenance, start_process)
        assert launches == ["preparation", "menu-preplacement"]
        assert result["status"] == "PREPARED_MENU_FILES_NOT_LOADED_NOT_FEATURE_VALIDATED"
        assert result["worker_result"]["completed_identities"] == identities
        assert result["session_data_sha256"] == peer.sha(prepared.raw_session)
        assert result["launch_started_utc"] == report["commands"][-1]["utc"]
        assert not result["installable"] and not result["usb_restore_verified"]
    else:
        with pytest.raises((OSError, ValueError)) as caught:
            operation.run(report, maintenance, start_process)
        assert operation.failed
        evidence = caught.value.prepared_operation_evidence
        if fault == "second-file":
            assert str(caught.value) == "placement maintenance failed after first file"
            assert launches == ["preparation", "menu-preplacement"]
            assert evidence["phase"] == "menu-preplacement"
            assert caught.value.partial_evidence["completed_identities"] == identities[:1]
            assert b"ONE_FILE_PREPLACED" in caught.value.partial_evidence["worker_outputs"][0]
        else:
            assert launches == ["preparation"]
            assert evidence["phase"] == ("preparation" if fault == "preparation" else "before-worker")
    with pytest.raises(ValueError, match="already attempted|failed"):
        operation.run(report, maintenance, start_process)


def test_code_only_preparation_cannot_start_placement_in_its_own_window(installer):
    module = importlib.import_module("tools.menu_prepared_transport")
    prepared, _, epoch, _ = ready_case(installer)
    with pytest.raises(ValueError, match="later fresh ready window"):
        module.PreparedMenuPlacementOperation(prepared.code_preparation, clock=lambda: epoch)


@pytest.mark.parametrize("fault", ("missing-code", "code-plan", "code-payload", "same-window", "same-worker",
    "missing-preflight", "old-baseline", "wrong-command", "failed-state", "wrong-state", "bad-time"))
def test_ready_never_starts_a_child_without_completed_code_and_later_actual_preflight(installer, fault):
    module = importlib.import_module("tools.menu_prepared_transport")
    prepared, report, epoch, _ = ready_case(installer)
    prior = previous_code_evidence(prepared, report, epoch)
    if fault == "missing-code":
        prior["previous_code_result"] = None
    elif fault == "code-plan":
        prior["previous_code_result"]["preparation_plan_sha256"] = "0" * 64
    elif fault == "code-payload":
        prior["previous_code_result"]["retained_adb_payloads"][1]["raw"] += b"changed\n"
    elif fault == "same-window":
        prior["previous_launch_report"]["commands"][0]["utc"] = datetime.fromtimestamp(epoch, timezone.utc).isoformat()
    elif fault == "same-worker":
        previous = prior["previous_launch_report"]
        previous["commands"][0]["command"] = previous["commands"][0]["command"].replace(previous["remote"], report["remote"])
        previous["remote"] = report["remote"]
    elif fault == "missing-preflight":
        del report["commands"][-6]
    elif fault == "old-baseline":
        report["commands"][-6]["utc"] = datetime.fromtimestamp(epoch-111, timezone.utc).isoformat()
    elif fault == "wrong-command":
        report["commands"][-6]["command"] = "echo claimed-baseline"
    elif fault == "failed-state":
        report["commands"][-6]["exit"] = 1
    elif fault == "wrong-state":
        report["commands"][-6]["text"] = usb.BASE + ",adb\n" + usb.BASE + ",adb\nrunning\n"
    elif fault == "bad-time":
        report["commands"][-6]["utc"] = "2026-10-05T00:00:00"

    class Maintenance:
        def command(self, label, command):
            return operation.coordinator.next_preparation.expected_stdout
    def forbidden(*args):
        raise AssertionError("invalid transition reached a host child")
    with pytest.raises(ValueError):
        operation = module.PreparedMenuPlacementOperation(prepared, clock=lambda: epoch, **prior)
        maintenance = Maintenance()
        operation.prepare_observer(maintenance)
        operation.run(report, maintenance, forbidden)


def test_independent_same_window_replay_cannot_reach_ready_child(installer):
    """Retain the RG459 process-boundary counterexample after required inputs.

    The earlier frozen implementation reached start_process when only a nonce
    changed. New prior-result inputs are synthetic completed boundary evidence,
    not executed staging; the same original window remains the defect probe.
    """
    module = importlib.import_module("tools.menu_prepared_transport")
    original, report, epoch, _ = ready_case(installer)
    values = sc.decode_session(original.raw_session)
    values["session_nonce"] = "a" * 32
    code = content.plan_temporary_preparation(original.parent_plan, installer.manifest,
        sc.encode_session(values, schema=sc.MENU_VALIDATION_SCHEMA))
    values["session_nonce"] = "c" * 32
    ready = content.plan_temporary_ready(code, sc.encode_session(values, schema=sc.MENU_VALIDATION_SCHEMA))
    original_launch = datetime.fromtimestamp(epoch, timezone.utc)
    code_host = content.SecondWindowPreparationCoordinator(code, clock=lambda: epoch)
    while (step := code_host.next_preparation) is not None:
        code_host.accept_preparation(exit_code=0, stdout=step.expected_stdout, completion_validated=True)
    code_host.start_window(original_launch)
    prior = previous_code_evidence(ready, report, epoch)
    prior["previous_launch_report"]["commands"][0]["utc"] = original_launch.isoformat()
    prior["previous_code_result"]["launch_started_utc"] = original_launch.isoformat()
    operation = module.PreparedMenuPlacementOperation(ready, clock=lambda: epoch, **prior)
    launches = []

    class Maintenance:
        def command(self, label, command):
            expected = operation.coordinator.next_preparation
            assert expected.command == command
            return expected.expected_stdout

    def forbidden(phase, source):
        launches.append(phase)
        raise AssertionError("ready child reached using code window launch without any restoration evidence")

    maintenance = Maintenance()
    operation.prepare_observer(maintenance)
    with pytest.raises(ValueError, match="original code window"):
        operation.run(report, maintenance, forbidden)
    assert operation.failed and launches == []


@pytest.mark.parametrize("fault", ("different-launch", "missing-launch"))
def test_ready_rejects_code_result_from_a_different_original_window(installer, fault):
    """Identical code/session bytes do not identify which timed launch ran them."""
    module = importlib.import_module("tools.menu_prepared_transport")
    prepared, report, epoch, _ = ready_case(installer)
    prior = previous_code_evidence(prepared, report, epoch)
    if fault == "different-launch":
        # Still structurally valid and within the same raw session's 600 s.
        prior["previous_launch_report"]["commands"][0]["utc"] = datetime.fromtimestamp(
            epoch - 199, timezone.utc).isoformat()
    else:
        del prior["previous_code_result"]["launch_started_utc"]
    with pytest.raises(ValueError, match="original launch"):
        module.PreparedMenuPlacementOperation(prepared, clock=lambda: epoch, **prior)


@pytest.mark.parametrize("fault", ("missing-result", "missing-session", "candidate", "plan", "session-data",
    "session-binding", "status", "payload-missing", "payload-changed", "missing-launch", "different-launch",
    "same-window", "same-nonce", "namespace"))
def test_formal_placement_requires_completed_exact_content_in_a_distinct_window(installer, fault):
    module = importlib.import_module("tools.menu_prepared_transport")
    prepared, report, epoch, _, prior = formal_case(installer)
    result = prior["previous_content_result"]
    if fault == "missing-result":
        prior["previous_content_result"] = None
    elif fault == "missing-session":
        prior["previous_content_session"] = None
    elif fault in ("candidate", "plan", "session-data", "session-binding"):
        field = {"candidate": "candidate_sha256", "plan": "plan_sha256",
                 "session-data": "session_data_sha256", "session-binding": "session_binding_sha256"}[fault]
        result[field] = "0" * 64
    elif fault == "status":
        result["status"] = "PREPARATION_READY"
    elif fault == "payload-missing":
        result["retained_adb_payloads"].pop()
    elif fault == "payload-changed":
        record = result["retained_adb_payloads"][0]
        record["raw"] += b"unknown\n"
        record["sha256"] = peer.sha(record["raw"])
    elif fault == "missing-launch":
        result.pop("launch_started_utc")
    elif fault in ("different-launch", "same-window"):
        stamp = datetime.fromtimestamp(epoch if fault == "same-window" else epoch-199, timezone.utc).isoformat()
        prior["previous_launch_report"]["commands"][0]["utc"] = stamp
        if fault == "same-window":
            result["launch_started_utc"] = stamp
    elif fault in ("same-nonce", "namespace"):
        values = sc.decode_session(prepared.raw_session)
        if fault == "same-nonce":
            values["session_nonce"] = "a" * 32
        else:
            for key in values:
                if key == "mount_namespace" or key.endswith("_mount_namespace"):
                    values[key] = "mnt:[999999]"
        prepared = content.plan_install_preparation(prepared.parent_plan, installer.manifest,
            sc.encode_session(values, schema=sc.INSTALL_SCHEMA))

    class Maintenance:
        def command(self, label, command):
            return operation.coordinator.next_preparation.expected_stdout

    def forbidden(*args):
        raise AssertionError("invalid formal transition reached a host child")

    with pytest.raises(ValueError):
        operation = module.PreparedFormalPlacementOperation(prepared, clock=lambda: epoch, **prior)
        maintenance = Maintenance()
        operation.prepare_observer(maintenance)
        operation.run(report, maintenance, forbidden)


def test_formal_placement_cannot_relabel_temporary_ready(installer):
    module = importlib.import_module("tools.menu_prepared_transport")
    prepared, _, epoch, _ = ready_case(installer)
    with pytest.raises(ValueError, match="install preparation"):
        module.PreparedFormalPlacementOperation(prepared, clock=lambda: epoch)


@pytest.mark.parametrize("kind", ("install", "menu_validation"))
@pytest.mark.parametrize("fault", ("empty", "changed-command", "changed-digest"))
def test_placement_rebuilds_stable_parent_instead_of_trusting_its_claimed_digest(installer, kind, fault):
    module = importlib.import_module("tools.menu_prepared_transport")
    if kind == "install":
        original, report, epoch, _, prior = formal_case(installer)
    else:
        original, report, epoch, _ = ready_case(installer)
    parent = original.parent_plan
    if fault == "empty":
        parent = replace(parent, steps=())
    elif fault == "changed-command":
        parent = replace(parent, steps=(replace(parent.steps[0], command="false"), *parent.steps[1:]))
    else:
        parent = replace(parent, plan_sha256="0" * 64)
    if kind == "install":
        prepared = content.plan_install_preparation(parent, installer.manifest, original.raw_session)
        prior["previous_content_session"] = stage.plan_raw_session_staging(parent, installer.manifest,
            prior["previous_content_session"].data)
        if fault == "empty":
            prior["previous_content_result"]["retained_adb_payloads"] = []
        operation = module.PreparedFormalPlacementOperation
    else:
        code = content.plan_temporary_preparation(parent, installer.manifest, original.code_preparation.raw_session)
        prepared = content.plan_temporary_ready(code, original.raw_session)
        prior = previous_code_evidence(prepared, report, epoch)
        operation = module.PreparedMenuPlacementOperation
    with pytest.raises(ValueError, match="complete fixed plan"):
        operation(prepared, clock=lambda: epoch, **prior)
