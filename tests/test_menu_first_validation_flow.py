"""Run fixed stages through external pipe/maintenance models; never camera evidence."""
import base64
import io
import re
from unittest import mock

import pytest

from tests.test_release_lifecycle import installer
from tests.test_prepared_menu_transport import ready_case, previous_code_evidence
from tools import menu_content_transport as content, menu_preplacement_transport as placement
from tools import menu_maintenance_boundary as boundary, prepare_peer_install as peer, session_context as sc
from tools import menu_first_validation as flow, stage_peer_usb_access as usb


class ModelChild:
    """The child-pipe boundary, not an internal coordinator/validator mock."""
    def __init__(self, lines):
        self.stdin = io.BytesIO()
        self.stdout = io.BytesIO(("\n".join(lines) + "\n").encode())
        self.stderr = io.BytesIO()

    def poll(self):
        return 0

    def wait(self, timeout=None):
        return 0

    def terminate(self):
        raise AssertionError("completed model child should not be terminated")


def content_child(coordinator):
    session = coordinator._session
    steps = content.stage.execution_steps(coordinator._plan, dict(session.context), session=session)
    lines = []
    for index, step in enumerate(steps):
        payload = (step.expected_stdout + f"\nX2DII_CONTENT_{session.binding_sha256[:24]}_{index}_RC=0\n").encode()
        encoded = base64.b64encode(payload).decode()
        lines.extend((f"X2DII_CONTENT_NEED:{index}:{session.binding_sha256}:{peer.sha(step.command.encode())}",
                      f"X2DII_CONTENT_BYTES:{index}:{encoded}", f"X2DII_CONTENT_REPLY:{index}:{encoded}"))
    lines.append("X2DII_" + coordinator.final_scope)
    return ModelChild(lines)


def placement_child(outputs):
    lines = []
    for index, output in enumerate(outputs):
        lines.extend("X2DII_HOST_BOUNDARY:" + match.decode() for match in re.findall(
            rb"X2DII_BOUNDARY_REQUEST:([0-3]:[0-6]:[0-9a-f]{64})", output))
        encoded = base64.b64encode(output).decode()
        lines.extend((f"X2DII_WORKER_OUTPUT:{index}:{encoded}", f"X2DII_HOST_FILE_COMPLETE:{index}:{encoded}"))
    lines.append("X2DII_FOUR_FILES_PREPLACED_NOT_MENU_OR_INSTALLATION_VALIDATION")
    return ModelChild(lines)


def model_worker_outputs(manifest, raw, epoch):
    values, digest, outputs = sc.decode_session(raw), peer.sha(raw), []
    for i, file in enumerate(manifest["candidate"]["files"]):
        program_sha = peer.sha(placement.render_supervised_preplacement(manifest, file_index=i,
            session_kind="menu_validation").encode())
        output = b""
        for j in range(7):
            challenge = peer.sha(f"{values['boot_id']}:{values['session_nonce']}:{i}:{j}:{program_sha}\n".encode())
            request = boundary.make_request(manifest, raw, worker_session_sha256=digest,
                worker_program_sha256=program_sha, file_index=i, boundary_index=j,
                challenge=challenge, issued_epoch=epoch)
            output += f"X2DII_BOUNDARY_REQUEST:{i}:{j}:{peer.sha(request)}\n".encode()
        label = values[("library_label", "bootstrap_label", "model_label", "page_label")[i]]
        output += ("schema=x2dii-one-file-preplacement-v1\n"
            f"candidate_sha256={manifest['candidate_sha256']}\nsession_nonce={values['session_nonce']}\n"
            f"file_index={i}\nidentity=1:{2+i}:81a4:1:{file['bytes']}:0:0\nlabel={label}\nsha256={file['sha256']}\n"
            "maintenance_boundaries=HOST_MEDIATED_SEVEN_MATCHED\nX2DII_ONE_FILE_PREPLACED_NOT_RUNTIME_VALIDATED\n\n"
            f"X2DII_WORKER_{digest[:24]}_{i}_RC=0\n").encode()
        outputs.append(output)
    return outputs


class ModelMaintenance:
    def __init__(self, case, outputs, now, *, fault=None):
        self.case, self.outputs, self.now, self.fault = case, outputs, now, fault
        self.report, self.calls, self.reads = {}, [], 0
        self.stop_requested = False

    @property
    def coordinator(self):
        return self.case.operation.coordinator if isinstance(self.case, flow._FirstValidationFlow) else self.case

    def command(self, label, command):
        self.calls.append((label, command))
        c = self.coordinator
        if label.startswith("prepare-observer-"):
            operation = c.next_preparation
            assert command == operation.command
            return operation.expected_stdout
        if label.startswith("content-observe-"):
            step = c.observer.observations[int(label.rsplit("-", 1)[1])]
            assert command == step.command
            return step.expected_stdout + f"{int(self.now[0])}:{int(self.now[0])}\n"
        raw = self.case.operation.preparation.raw_session if isinstance(self.case, flow._FirstValidationFlow) else c._session.data
        values = sc.decode_session(raw)
        if label.startswith("menu-"):
            _, _, data_sha, file_index, stage_index, request_sha = command.split()
            i, j = int(file_index), int(stage_index)
            assert data_sha == peer.sha(raw)
            if self.fault == "placement" and i == 1:
                raise OSError("second file maintenance failed")
            manifest = self.case.operation.manifest
            program_sha = peer.sha(placement.render_supervised_preplacement(manifest,
                file_index=i, session_kind="menu_validation").encode())
            challenge = peer.sha(f"{values['boot_id']}:{values['session_nonce']}:{i}:{j}:{program_sha}\n".encode())
            request = boundary.make_request(manifest, raw, worker_session_sha256=data_sha,
                worker_program_sha256=program_sha, file_index=i, boundary_index=j,
                challenge=challenge, issued_epoch=int(self.now[0]))
            assert request_sha == peer.sha(request)
            return (request.replace(boundary.REQUEST_SCHEMA.encode(), boundary.RESPONSE_SCHEMA.encode(), 1) +
                (f"request_sha256={request_sha}\nstarted_epoch={int(self.now[0])}\nchecked_epoch={int(self.now[0])}\n"
                 "result=OBSERVED_MATCH\nscope=ONE_BOUNDARY_ONLY_NOT_AUTHORIZATION\n").encode()).decode()
        preflight = {
            "transport-hash": "".join(f"{digest}  /proc/{100+i}/exe\n" for i, (_, digest) in enumerate(usb.TRANSPORT_PRODUCERS)),
            "boot-id": values["boot_id"] + "\n", "usb-state": usb.BASE + "\n" + usb.BASE + "\nstopped\n",
            "uid": "0\n", "lock-absent": "",
        }
        if label in preflight:
            if label == "usb-state" and self.fault == "unrestored":
                return usb.BASE + ",adb\n" + usb.BASE + ",adb\nrunning\n"
            return preflight[label]
        digest = peer.sha(raw)
        if label == "lifecycle-launch":
            if self.fault in ("lost-launch", "lost-all"):
                raise OSError("launch reply lost")
            return "X2DII_LIFECYCLE_STARTED_NOT_VALIDATED:" + digest + "\n"
        if label == "lifecycle-stop":
            self.stop_requested = True
            return "X2DII_LIFECYCLE_STOP_REQUESTED_NOT_COMPLETED:" + digest + "\n"
        if label == "lifecycle-menu":
            if self.fault == "lost-menu":
                raise OSError("menu reply lost")
            # External transport fixture only, never real Qt or camera evidence.
            return "X2DII_MENU_SNAPSHOT:" + digest + ":456:77700:" + "c" * 64 + ":1:2:1:1:1:1:1:12:11\n"
        if label == "lifecycle-read":
            self.reads += 1
            if self.fault == "lost-all":
                raise OSError("read reply lost")
            if not self.stop_requested:
                return "X2DII_LIFECYCLE_PENDING:" + digest + ":WORKER_OBSERVED\n"
            status = 78 if self.fault == "exit78" else 0
            receipt = peer.sha(f"{digest}:{status}\n".encode())
            return f"X2DII_LIFECYCLE_FINAL:{digest}:{receipt}:{status}:NOT_FEATURE_VALIDATED\n"
        raise AssertionError((label, command))


def make_case(installer, fault=None):
    ready, report, epoch, _ = ready_case(installer)
    prior = previous_code_evidence(ready, report, epoch)
    outputs = model_worker_outputs(installer.manifest, ready.raw_session, epoch)
    now = [epoch]
    case = flow._FirstValidationFlow(ready, **prior, clock=lambda: now[0],
        sleep=lambda seconds: now.__setitem__(0, now[0] + seconds))
    maintenance = ModelMaintenance(case, outputs, now, fault=fault)
    starts = []

    def start(phase, source):
        starts.append(phase)
        assert "Qualified = false;" in source
        return content_child(case.operation.coordinator) if phase == "preparation" else placement_child(outputs)

    return case, maintenance, start, starts, report, now


def test_public_first_validation_refuses_before_every_external_action():
    class Forbidden:
        def command(self, *args):
            raise AssertionError("maintenance action before first-validation admission")
    with mock.patch("tools.menu_host_process.subprocess.Popen", side_effect=AssertionError("host child started")):
        with pytest.raises(ValueError, match="ADMISSION_NOT_CONNECTED_NO_DEVICE_ACTION"):
            flow.run_first_validation(None, previous_code_result=None, previous_launch_report=None,
                ready_launch_report=None, maintenance_session=Forbidden())


@pytest.mark.parametrize("stamp", (float("nan"), float("inf"), -float("inf"), True))
def test_stage_refuses_nonfinite_or_boolean_observer_completion_before_child(installer, stamp):
    ready, report, epoch, _ = ready_case(installer)
    coordinator = content.SecondWindowPreparationCoordinator(ready, clock=lambda: epoch)
    boundary_model = ModelMaintenance(coordinator, [], [epoch])
    flow._prepare_content_stage(coordinator, boundary_model, clock=lambda: epoch)
    with pytest.raises(ValueError):
        flow._run_content_stage(coordinator, report, boundary_model, observer_completed_at=stamp,
            start_process=lambda *args: pytest.fail("invalid timing started child"))


def test_stage_preparation_completion_cannot_be_reissued_or_fabricated(installer):
    ready, report, epoch, _ = ready_case(installer)
    coordinator = content.SecondWindowPreparationCoordinator(ready, clock=lambda: epoch)
    boundary_model = ModelMaintenance(coordinator, [], [epoch])
    flow._prepare_content_stage(coordinator, boundary_model, clock=lambda: epoch)
    with pytest.raises(ValueError, match="already|attempt"):
        flow._prepare_content_stage(coordinator, boundary_model, clock=lambda: epoch)
    with pytest.raises(ValueError, match="completion|preparation|failed"):
        flow._run_content_stage(coordinator, report, boundary_model, observer_completed_at=epoch - 1,
            start_process=lambda *args: pytest.fail("fabricated completion started child"))


@pytest.mark.parametrize("kind", ("content", "code"))
def test_fixed_stage_helpers_actually_drive_matching_protocol(installer, kind):
    ready, report, epoch, _ = ready_case(installer)
    code = ready.code_preparation
    if kind == "content":
        session = content.stage.plan_raw_session_staging(ready.parent_plan, installer.manifest, ready.raw_session)
        coordinator = content.ContentStageCoordinator(ready.parent_plan, session, clock=lambda: epoch)
    else:
        # Keep this window's original observation, not the later ready fixture.
        epoch = code.session.observed_epoch
        from datetime import datetime, timezone
        report["commands"][0]["utc"] = datetime.fromtimestamp(epoch, timezone.utc).isoformat()
        coordinator = content.SecondWindowPreparationCoordinator(code, clock=lambda: epoch)
    boundary_model = ModelMaintenance(coordinator, [], [epoch])
    prepared_at = flow._prepare_content_stage(coordinator, boundary_model, clock=lambda: epoch)
    started = []

    def start(phase, source):
        started.append(phase)
        assert "ContentQualified = false;" in source
        return content_child(coordinator)

    result = flow._run_content_stage(coordinator, report, boundary_model,
        observer_completed_at=prepared_at, start_process=start)
    assert result["status"] == coordinator.final_scope
    assert len(result["retained_adb_payloads"]) > 0 and not result["installable"]
    assert started == ["stable-content" if kind == "content" else "preparation"]


@pytest.mark.parametrize("fault", (None, "lost-launch", "lost-all", "exit78", "placement", "unrestored", "too-early", "expired"))
def test_fixed_ready_lifecycle_reuses_real_drivers_and_preserves_error_recovery(installer, fault):
    case, maintenance, start, starts, report, now = make_case(installer, fault)
    case.prepare_observer(maintenance)
    if fault == "placement":
        with pytest.raises(OSError, match="second file") as caught:
            case.place(report, maintenance, start_process=start)
        assert caught.value.partial_evidence["completed_identities"]
        assert not any(label.startswith("lifecycle-") for label, _ in maintenance.calls)
        with pytest.raises(ValueError):
            case.launch_temporary(maintenance)
        return
    result = case.place(report, maintenance, start_process=start)
    assert starts == ["preparation", "menu-preplacement"]
    assert len(result["worker_result"]["completed_identities"]) == 4
    now[0] += 89 if fault == "too-early" else 601 if fault == "expired" else 91
    if fault is None:
        started = case.launch_temporary(maintenance)
        assert started["status"] == "TEMPORARY_GUI_STARTED_AWAITING_REAL_UI_CHECK"
        assert not maintenance.stop_requested
        assert case.read_temporary()["status"] == "PENDING"
        result = case.finish_and_restore()
        assert result["status"] == "TEMPORARY_GUI_EXITED_NOT_FUNCTION_QUALIFIED"
        assert not result["installable"] and not result["feature_validated"]
        assert result["lifecycle"][-1]["exit_code"] == 0
        assert result["original_connection_preflight_passed"] is True
    else:
        with pytest.raises((ValueError, OSError)) as caught:
            case.launch_temporary(maintenance)
            case.finish_and_restore()
        evidence = caught.value.first_validation_evidence
        labels = [label for label, _ in maintenance.calls]
        if fault in ("lost-launch", "lost-all"):
            assert str(caught.value) == "launch reply lost"
            assert labels.count("lifecycle-launch") == 1 and labels.count("lifecycle-stop") == 1
            assert evidence["final_receipt"] is None if fault == "lost-all" else evidence["final_receipt"]["exit_code"] == 0
            assert evidence["recovery_verified"] is False
        elif fault == "exit78":
            assert evidence["final_receipt"]["exit_code"] == 78
            assert labels.count("lifecycle-stop") == 1
        else:
            assert "lifecycle-launch" not in labels
        with pytest.raises(ValueError):
            case.launch_temporary(maintenance)


@pytest.mark.parametrize('fault', (None, 'lost-menu'))
def test_ready_route_reads_menu_without_attesting_feature_and_keeps_original_error_recovery(installer, fault):
    case, maintenance, start, starts, report, now = make_case(installer, fault)
    case.prepare_observer(maintenance)
    case.place(report, maintenance, start_process=start)
    now[0] += 91
    case.launch_temporary(maintenance)
    if fault is None:
        snapshot = case.read_temporary_menu()
        assert snapshot['ready'] and not snapshot['feature_validated']
        assert snapshot['candidate_sha256'] == installer.manifest['candidate_sha256']
        assert case.evidence['current_menu_observation'] == snapshot
        assert case.evidence['menu_observations'] == [snapshot]
        assert case.read_temporary()['status'] == 'PENDING'
        result = case.finish_and_restore()
        assert result['status'] == 'TEMPORARY_GUI_EXITED_NOT_FUNCTION_QUALIFIED'
        assert not result['installable'] and not result['feature_validated']
        assert result['current_menu_observation'] is None
    else:
        with pytest.raises(OSError, match='menu reply lost') as caught:
            case.read_temporary_menu()
        evidence = caught.value.first_validation_evidence
        assert evidence['current_menu_observation'] is None
        assert evidence['original_error'] == 'menu reply lost'
        assert evidence['final_receipt']['exit_code'] == 0
        assert not evidence['recovery_verified']
        labels = [label for label, _ in maintenance.calls]
        assert labels.count('lifecycle-menu') == 1 and labels.count('lifecycle-launch') == 1
        assert labels.count('lifecycle-stop') == 1
