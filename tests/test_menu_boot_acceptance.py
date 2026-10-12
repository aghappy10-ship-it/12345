"""Counterfactual public boot acceptance; no report is real camera consent."""
import importlib
import base64
import json
import re
from copy import deepcopy
from datetime import datetime, timezone, timedelta
from unittest import mock
from pathlib import Path

import pytest

from tests.test_menu_first_validation_admission import counterfactual, public_window, next_public_window
from tests.test_release_lifecycle import installer
from tools import prepare_peer_install as peer, release_identity
from tools import menu_first_validation as temporary
from tools import menu_boot_transport as boot, menu_boot_boundary as boundary, session_context as sc
from tests.test_menu_first_validation_flow import ModelChild, ModelMaintenance, content_child, model_worker_outputs
from tests.test_stage_peer_usb_access import recorded_launch_fixture


def admission_inputs(c, module, placement=None):
    args = c["inputs"](c["q"])
    raw = temporary.saved_menu_session(c["manifest"], args["saved_observation"],
        expected_sha256=args["saved_observation_sha256"]).raw_session
    if placement is None:
        outputs = model_worker_outputs(c["manifest"], raw, int(c["now"][0].timestamp()))
        placement = {"schema": "x2dii-boot-validation-placement-v1",
        "candidate_sha256": c["manifest"]["candidate_sha256"],
        "session_data_sha256": peer.sha(raw), "placement_session_ascii": raw.decode("ascii"),
        "completed_identities": [f"1:{i+2}:81a4:1:{f['bytes']}:0:0"
            for i, f in enumerate(c["manifest"]["candidate"]["files"])],
        "placement_result": {"status": "PREPARED_MENU_FILES_NOT_LOADED_NOT_FEATURE_VALIDATED",
            "candidate_sha256": c["manifest"]["candidate_sha256"], "session_data_sha256": peer.sha(raw),
            "worker_result": {"status": "FOUR_FILES_PREPLACED_NOT_FEATURE_VALIDATED",
                "completed_identities": [f"1:{i+2}:81a4:1:{f['bytes']}:0:0"
                    for i, f in enumerate(c["manifest"]["candidate"]["files"])],
                "worker_outputs": [{"encoding": "base64", "data": base64.b64encode(o).decode(), "sha256": peer.sha(o)} for o in outputs]}},
        "ready_launch_report": recorded_launch_fixture(), "ready_launch_report_sha256": "1" * 64,
        "placement_observation_sha256": args["saved_observation_sha256"],
        "placement_observation_sources": args["observation_sources"],
        "temporary_final_receipt": {"status": "EXITED_NOT_FEATURE_VALIDATED", "exit_code": 0},
        "temporary_lifecycle_evidence": {"phase": "ended-not-feature-validated"}, "temporary_feature_validated": False}
        launch = placement["ready_launch_report"]
        launch["commands"][0]["utc"] = c["now"][0].isoformat()
        launch["bootId"] = c["q"]["boot_id"]
        placement["ready_launch_report_utf8"] = json.dumps(launch)
        placement["ready_launch_report_sha256"] = peer.sha(placement["ready_launch_report_utf8"].encode())
        placement["temporary_final_receipt"].update(session_sha256=peer.sha(raw),
            receipt_sha256=peer.sha((peer.sha(raw) + ":0\n").encode()), feature_validated=False)
    receipt = c["save"]("boot-placement.json", placement)
    approval = deepcopy(c["approval"])
    approval.update(schema="x2dii-first-boot-validation-approval-v1", purpose="first_boot_validation",
        action="activate_observe_restore_remove", actions=list(module.BOOT_VALIDATION_ACTIONS),
        placement_receipt_sha256=receipt["evidence_sha256"])
    approval["record"] = c["save"]("boot-approval.json", {k: v for k, v in approval.items() if k != "record"})
    args["prerequisites"]["gates"] = {}
    runtime = peer.runtime_subject_sha256(c["manifest"], c["q"])
    for gate, phases in module.BOOT_VALIDATION_GATES.items():
        args["prerequisites"]["gates"][gate] = {}
        for phase in phases:
            bound = release_identity.gate_bindings(phase,
                candidate_sha256=c["manifest"]["candidate_sha256"],
                build_subject_sha256=approval["build_subject_sha256"], runtime_subject_sha256=runtime,
                boot_id=c["q"]["boot_id"], delivery_identity=args["prerequisites"]["delivery_identity"],
                retained={"placement_receipt_sha256": receipt["evidence_sha256"]})
            reference = c["save"]("boot-" + gate + "-" + phase + ".json",
                {**bound, "result": "PASS", "synthetic": False, "test_fixture_only": False, "gate": gate})
            args["prerequisites"]["gates"][gate][phase] = {**bound, "status": "PASS", **reference}
    args.update(approval=approval, placement_receipt=receipt)
    return args


@pytest.fixture
def boot_input(counterfactual):
    c = counterfactual
    module = importlib.import_module("tools.menu_boot_acceptance")
    args = admission_inputs(c, module)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return c["now"][0] if tz else c["now"][0].replace(tzinfo=None)

    with mock.patch.object(module, "datetime", Clock):
        yield c, module, args


def test_public_boot_validation_refuses_missing_specific_approval_before_io():
    module = importlib.import_module("tools.menu_boot_acceptance")
    with pytest.raises(ValueError, match="boot-validation.*approval"):
        module.prepare_boot_validation({}, None, saved_observation=b"{}",
            saved_observation_sha256="0" * 64, prerequisites={}, approval={},
            observation_sources=(), placement_receipt={})


def test_complete_boot_acceptance_is_data_only_and_requires_saved_intent(boot_input):
    c, module, args = boot_input
    with mock.patch("tools.menu_host_process.subprocess.Popen", side_effect=AssertionError("native child")):
        operation = module.prepare_boot_validation(c["manifest"], c["plan"], **args)
        snapshot = operation.snapshot()
        assert snapshot["schema"] == "x2dii-first-boot-validation-snapshot-v1"
        assert snapshot["status"] == "INTENT_SAVED_REQUIRED_BEFORE_ACTIVATION"
        assert snapshot["installable"] is False and snapshot["activation_receipt"] is None
        assert snapshot["manifest"]["scripts_emitted"] is False
        assert operation.raw_session.startswith(b"schema=x2dii-session-context-v2\nkind=install\n")
        with pytest.raises(ValueError, match="saved acceptance intent"):
            operation.prepare_window(object())


def boot_wire(operation, epoch):
    """External receiver transcript, using actual fixed public wire grammar."""
    raw, manifest = operation.raw_session, operation.manifest
    values, action = sc.decode_session(raw), operation.operation.action
    coordinator = boot.BootCoordinator(manifest, raw, **operation.operation.options)
    lines, output, responses = [], b"", {}
    for index in range(coordinator.first_boundary, len(coordinator.sequence)):
        challenge = peer.sha(f"{values['boot_id']}:{values['session_nonce']}:{action}:{index}:{coordinator.program_sha256}\n".encode())
        request = boundary.make_request(manifest, raw, action=action, worker_session_sha256=peer.sha(raw),
            worker_program_sha256=coordinator.program_sha256, boundary_index=index, challenge=challenge, issued_epoch=epoch)
        digest = peer.sha(request)
        line = f"X2DII_HOST_BOOT_BOUNDARY:{action}:{index}:{digest}"
        command = coordinator.begin_boundary(line)
        response = request.replace(boundary.REQUEST_SCHEMA.encode(), boundary.RESPONSE_SCHEMA.encode(), 1)
        response += (f"request_sha256={digest}\nstarted_epoch={epoch}\nchecked_epoch={epoch}\n"
            "result=OBSERVED_MATCH\nscope=ONE_BOUNDARY_ONLY_NOT_AUTHORIZATION\n").encode()
        coordinator.accept_reply(response, received_epoch=epoch)
        responses[command] = response.decode()
        lines.append(line)
        output += f"X2DII_BOOT_BOUNDARY_REQUEST:{action}:{index}:{digest}\n".encode()
    original = peer.boot.STOCK.read_bytes()
    size = len(peer.boot.activate(original)) if action == "activate" else len(original)
    backup = f"1:9:81a4:1:{len(original)}:0:0"
    output += ("schema=x2dii-rc-file-transaction-v1\n"
        f"action={action}\ncandidate_sha256={manifest['candidate_sha256']}\nsession_data_sha256={peer.sha(raw)}\n"
        f"session_nonce={values['session_nonce']}\nbackup_identity={backup}\nidentity=1:10:81a4:1:{size}:0:0\n"
        f"sha256={manifest['candidate']['rc']['after' if action == 'activate' else 'before']}\n"
        "maintenance_boundaries=HOST_MEDIATED_FIXED_BOOT_MATCHED\nX2DII_RC_FILE_COMMITTED_NOT_LIFECYCLE_VALIDATED\n\n"
        f"X2DII_BOOT_WORKER_{peer.sha(raw)[:24]}_{action}_RC=0\n").encode()
    encoded = base64.b64encode(output).decode()
    lines.extend((f"X2DII_BOOT_WORKER_OUTPUT:{action}:{encoded}", f"X2DII_HOST_BOOT_COMPLETE:{action}:{encoded}",
        "X2DII_BOOT_FILE_TRANSACTION_NOT_LIFECYCLE_VALIDATION"))
    child = ModelChild(lines)
    child.returncode = 0
    return child, responses


def public_run(c, operation, *, fault=None):
    epoch = int(c["now"][0].timestamp())
    boot_child, responses = (cleanup_wire(operation, epoch) if operation.operation._worker_phase == "owned-cleanup"
        else boot_wire(operation, epoch))
    maintenance = ModelMaintenance(operation.operation.coordinator, [], [epoch])
    original = maintenance.command
    maintenance.command = lambda label, command: responses[command] if command in responses else original(label, command)
    operation.prepare_window(maintenance)
    report = recorded_launch_fixture()
    report["commands"][0]["utc"] = c["now"][0].isoformat()
    report["bootId"] = sc.decode_session(operation.raw_session)["boot_id"]
    sources = []

    def popen(args, **kwargs):
        script = base64.b64decode(args[-1]).decode("utf-16le")
        path = Path(re.search(r"ReadAllBytes\('([^']+)'\)", script)[1])
        source = path.read_text(encoding="utf-8")
        assert peer.sha(source.encode()) in script
        assert "Qualified = true;" in source and "Qualified = false;" not in source
        sources.append(source)
        child = content_child(operation.operation.coordinator) if len(sources) == 1 else boot_child
        child.returncode = 0
        if fault:
            fault(child, len(sources))
        return child
    with mock.patch("tools.menu_host_process.subprocess.Popen", side_effect=popen):
        result = operation.run_window(json.dumps(report).encode(), maintenance)
    return result, sources


def test_public_activation_runs_default_fixed_host_and_retains_actual_receipt(boot_input):
    c, module, args = boot_input
    operation = module.prepare_boot_validation(c["manifest"], c["plan"], **args)
    operation.bind_saved_intent(c["save"]("boot-intent.json", operation.snapshot()))
    result, sources = public_run(c, operation)
    assert len(sources) == 2 and "RunBoot()" in sources[-1]
    assert result["status"] == "BOOT_ACTIVATED_AWAITING_SAVED_RECEIPT_AND_EXTERNAL_NEW_BOOT"
    snapshot = operation.snapshot()
    assert snapshot["activation_receipt"]["action"] == "activate"
    assert snapshot["activation_receipt"]["backup_identity"].startswith("1:9:")
    assert result["installable"] is False and result["boot_function_verified"] is False
    preserved = snapshot["activation_result"]["worker_result"]["worker_outputs"][0]
    assert base64.b64decode(preserved["data"], validate=True) == result["worker_result"]["worker_outputs"][0]
    assert peer.sha(snapshot["activation_launch_report_utf8"].encode()) == snapshot["launch_report_sha256"]
    with pytest.raises(ValueError, match="already|attempted|completed"):
        operation.run_window(b"{}", object())


def recovery_inputs(c, module, snapshot, *, boot_id="33333333-4444-4555-8666-777777777777", nonce="e" * 32, cleanup=False, rc_restored=False):
    reference = c["save"]("saved-acceptance-" + nonce + ".json", snapshot)
    q = deepcopy(c["q"])
    q.pop("runtime_observation")
    q.update(candidate_sha256=snapshot["manifest"]["candidate_sha256"],
        saved_manifest_sha256=snapshot["manifest_sha256"], observed_utc=c["now"][0].isoformat(),
        boot_id=boot_id, session_nonce=nonce, recovery_nonce=nonce,
        gui={"state": "absent", "service_state": "stopped"},
        backup_metadata={"official": deepcopy(q["metadata"][peer.boot.TARGET])},
        backup_identity=snapshot["activation_receipt"]["backup_identity"],
        payload_presence={target: True for _, target in peer.FILES},
        rc_sha256=snapshot["manifest"]["candidate"]["rc"]["after"])
    if cleanup or rc_restored:
        q["rc_sha256"] = snapshot["manifest"]["candidate"]["rc"]["before"]
    if cleanup:
        q.update(gui={"state": "present", "service_state": "running", "process": {
                "pid": 234, "start_ticks": "4567", "exe_target": "/system/bin/camera-gui",
                "exe_sha256": snapshot["manifest"]["candidate"]["gui_sha256"],
                "domain": "u:r:hbl_camera_service:s0", "mount_namespace": q["mount_namespace"]}})
    raw = json.dumps(q).encode()
    sources = [c["save"]("recovery-raw-" + nonce + ".bin", b"COUNTERFACTUAL RECOVERY READOUT")]
    prerequisites = {"saved_observation_sha256": peer.sha(raw), "observation_sources": sources, "gates": {}}
    identity = module._recovery_bindings(snapshot, reference, q)
    extra = {}
    if cleanup:
        from tools import menu_stock_boot, prepare_peer_recovery
        from tests.test_menu_stock_boot import DeviceBoundary
        manifest_raw = json.dumps(snapshot["manifest"], sort_keys=True, separators=(",", ":")).encode()
        fresh = prepare_peer_recovery.session_data(snapshot["manifest"], q)
        stock = menu_stock_boot.observe_stock_boot(manifest_raw, snapshot["manifest_sha256"],
            snapshot["restore_session_ascii"].encode(), snapshot["restore_receipt"], fresh,
            DeviceBoundary(snapshot["manifest"], sc.decode_session(fresh)), clock=lambda: c["now"][0].timestamp())
        assert stock["status"] == "OBSERVED_STOCK_GUI_NOT_FUNCTION_VERIFIED"
        extra["stock_readback"] = c["save"]("stock-readback.json", stock)
        identity["retained"]["stock_readback_sha256"] = extra["stock_readback"]["evidence_sha256"]
    for gate, phases in (module.BOOT_CLEANUP_GATES if cleanup else module.BOOT_RECOVERY_GATES).items():
        prerequisites["gates"][gate] = {}
        for phase in phases:
            bound = release_identity.gate_bindings(phase, **identity)
            proof = {**bound, "result": "PASS", "synthetic": False, "test_fixture_only": False, "gate": gate}
            evidence = c["save"]("recovery-" + gate + "-" + phase + ".json", proof)
            prerequisites["gates"][gate][phase] = {**bound, "status": "PASS", **evidence}
    return dict(acceptance_snapshot=reference, saved_observation=raw,
        saved_observation_sha256=peer.sha(raw), prerequisites=prerequisites, observation_sources=sources, **extra)


def test_public_recovery_does_not_require_live_menu_capture_or_unexpired_activation(boot_input):
    c, module, args = boot_input
    activated = module.prepare_boot_validation(c["manifest"], c["plan"], **args)
    activated.bind_saved_intent(c["save"]("recovery-intent.json", activated.snapshot()))
    public_run(c, activated)
    c["now"][0] += timedelta(seconds=1100)
    inputs = recovery_inputs(c, module, activated.snapshot())
    c["docs"][peer.ROOT / args["approval"]["record"]["evidence_file"]] += b"changed after activation"
    original = Path.read_bytes
    payload_paths = {peer.ROOT / file["source"] for file in c["manifest"]["candidate"]["files"]}
    def no_current_payload_read(path):
        assert path not in payload_paths, "recovery must not read current payload bytes"
        return original(path)
    with mock.patch.object(Path, "read_bytes", no_current_payload_read):
        operation = module.prepare_boot_validation_recovery(**inputs)
        result, sources = public_run(c, operation)
    assert len(sources) == 2 and result["installable"] is False
    assert result["status"] == "OFFICIAL_RC_RESTORED_AWAITING_EXTERNAL_NEW_BOOT"
    assert operation.snapshot()["restore_receipt"]["action"] == "restore"


@pytest.mark.parametrize("when", ("before-validated-commit", "after-validated-commit"))
def test_public_repeated_restore_failure_keeps_one_coherent_commit_and_prior_evidence(boot_input, when):
    c, module, args = boot_input
    activated = module.prepare_boot_validation(c["manifest"], c["plan"], **args)
    activated.bind_saved_intent(c["save"]("repeat-restore-intent.json", activated.snapshot()))
    public_run(c, activated)
    c["now"][0] += timedelta(seconds=100)
    first = module.prepare_boot_validation_recovery(**recovery_inputs(c, module, activated.snapshot()))
    public_run(c, first)
    previous = first.snapshot()
    c["now"][0] += timedelta(seconds=100)
    inputs = recovery_inputs(c, module, previous, nonce="f" * 32, rc_restored=True)
    repeated = module.prepare_boot_validation_recovery(**inputs)

    def fault(child, index):
        if index == (1 if when == "before-validated-commit" else 2):
            child.wait = lambda timeout=None: 1

    with pytest.raises(ValueError) as caught:
        public_run(c, repeated, fault=fault)
    snapshot = caught.value.boot_acceptance_snapshot
    fields = ("restore_receipt", "restore_session_ascii", "restore_launch_report_utf8",
        "restore_launch_report_sha256", "restore_result", "recovery_failure")
    if when == "before-validated-commit":
        assert all(snapshot.get(key) == previous.get(key) for key in fields)
    c["now"][0] += timedelta(seconds=100)
    resumed = module.prepare_boot_validation_recovery(**recovery_inputs(
        c, module, snapshot, nonce="a" * 32, rc_restored=True))
    selected = (previous["restore_receipt"] if when == "before-validated-commit" else
        snapshot["restore_attempt"]["recovery_failure"]["partial"]["completed_receipt"])
    assert resumed.snapshot()["restore_receipt"] == selected
    assert snapshot["restore_attempt"]["basis_snapshot_reference"] == inputs["acceptance_snapshot"]
    assert snapshot["restore_attempt"]["restore_session_ascii"] == repeated.raw_session.decode("ascii")
    assert snapshot["restore_attempt"]["recovery_failure"]["partial"] is not None
    if when == "after-validated-commit":
        retained = snapshot["previous_restore_evidence"]
        assert retained["basis_snapshot_reference"] == inputs["acceptance_snapshot"]
        assert all(retained["snapshot_fields"].get(key) == previous.get(key) for key in fields)
        assert snapshot["restore_result"] is None
        assert snapshot["restore_receipt"]["session_data_sha256"] == peer.sha(repeated.raw_session)
    result, _ = public_run(c, resumed)
    assert result["status"] == "OFFICIAL_RC_RESTORED_AWAITING_EXTERNAL_NEW_BOOT"
    assert result["installable"] is False


def test_temporary_public_export_retains_actual_ready_outputs_and_finished_lifecycle(counterfactual):
    c = counterfactual
    operation = temporary.prepare_first_validation(c["manifest"], c["plan"],
        approval=c["approval"], **c["inputs"](c["q"]))
    with pytest.raises(ValueError, match="completed.*temporary"):
        operation.boot_validation_record()
    for phase in ("content", "code", "ready"):
        maintenance, ready = public_window(c, operation, [])
        if phase != "ready":
            next_public_window(c, operation)
    c["now"][0] += timedelta(seconds=91)
    operation.launch_temporary(maintenance)
    operation.finish_and_restore()
    record = operation.boot_validation_record()
    assert record["completed_identities"] == list(ready["worker_result"]["completed_identities"])
    for preserved, original in zip(record["placement_result"]["worker_result"]["worker_outputs"], ready["worker_result"]["worker_outputs"]):
        assert base64.b64decode(preserved["data"], validate=True) == original
    assert record["temporary_final_receipt"]["exit_code"] == 0
    assert record["temporary_feature_validated"] is False
    c["q"] = deepcopy(operation._q)
    c["q"]["observed_utc"] = c["now"][0].isoformat()
    c["q"]["session_nonce"] = "f" * 32
    module = importlib.import_module("tools.menu_boot_acceptance")
    args = admission_inputs(c, module, record)
    with mock.patch.object(module, "datetime", temporary.datetime):
        accepted = module.prepare_boot_validation(c["manifest"], c["plan"], **args)
        assert accepted.snapshot()["placement"] == record
        accepted.bind_saved_intent(c["save"]("full-chain-intent.json", accepted.snapshot()))
        public_run(c, accepted)
        c["now"][0] += timedelta(seconds=100)
        restored = module.prepare_boot_validation_recovery(**recovery_inputs(c, module, accepted.snapshot()))
        public_run(c, restored)
        c["now"][0] += timedelta(seconds=100)
        cleanup = module.prepare_boot_validation_cleanup(**recovery_inputs(c, module, restored.snapshot(),
            cleanup=True, boot_id="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", nonce="a" * 32))
        result, _ = public_run(c, cleanup)
        assert len(result["worker_result"]["completed_receipts"]) == 4 and result["installable"] is False


def cleanup_wire(operation, epoch):
    from tools import menu_owned_cleanup as cleanup
    raw, manifest = operation.raw_session, operation.manifest
    coordinator = cleanup.CleanupCoordinator(manifest, raw, *operation.operation.options)
    values, lines, responses = sc.decode_session(raw), [], {}
    for index in range(4):
        output = b""
        for stage in range(4):
            request = coordinator.expected_request(issued_epoch=epoch)
            digest = peer.sha(request)
            line = f"X2DII_HOST_CLEANUP_BOUNDARY:{index}:{stage}:{digest}"
            command = coordinator.begin_boundary(line)
            response = cleanup.encode_response(dict(cleanup.decode_request(request), schema=cleanup.RESPONSE_SCHEMA,
                request_sha256=digest, started_epoch=epoch, checked_epoch=epoch, result="OBSERVED_MATCH", scope=cleanup.SCOPE))
            coordinator.accept_reply(response, received_epoch=epoch)
            responses[command] = response.decode()
            lines.append(line)
            output += f"X2DII_CLEANUP_BOUNDARY_REQUEST:{index}:{stage}:{digest}\n".encode()
        output += ("schema=x2dii-one-file-cleanup-v1\n"
            f"candidate_sha256={manifest['candidate_sha256']}\nsession_data_sha256={peer.sha(raw)}\n"
            f"session_nonce={values['session_nonce']}\nfile_index={index}\n"
            f"original_identity={coordinator.identities[index]}\nsha256={manifest['candidate']['files'][index]['sha256']}\n"
            "maintenance_boundaries=HOST_MEDIATED_FOUR_CLEANUP_MATCHED\nX2DII_ONE_OWNED_FILE_REMOVED_NOT_FUNCTION_VALIDATED\n\n"
            f"X2DII_CLEANUP_WORKER_{peer.sha(raw)[:24]}_{index}_RC=0\n").encode()
        coordinator.finish_file(file_index=index, decoded_output=output, stream_completed=True)
        encoded = base64.b64encode(output).decode()
        lines.extend((f"X2DII_CLEANUP_WORKER_OUTPUT:{index}:{encoded}", f"X2DII_HOST_CLEANUP_COMPLETE:{index}:{encoded}"))
    lines.append("X2DII_FOUR_OWNED_FILES_REMOVED_NOT_FUNCTION_VALIDATED")
    child = ModelChild(lines)
    child.returncode = 0
    return child, responses


def test_public_cleanup_needs_actual_restore_new_boot_and_fixed_default_host(boot_input):
    c, module, args = boot_input
    activation = module.prepare_boot_validation(c["manifest"], c["plan"], **args)
    activation.bind_saved_intent(c["save"]("cleanup-intent.json", activation.snapshot()))
    public_run(c, activation)
    c["now"][0] += timedelta(seconds=100)
    restored = module.prepare_boot_validation_recovery(**recovery_inputs(c, module, activation.snapshot()))
    public_run(c, restored)
    c["now"][0] += timedelta(seconds=100)
    inputs = recovery_inputs(c, module, restored.snapshot(), cleanup=True,
        boot_id="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", nonce="d" * 32)
    operation = module.prepare_boot_validation_cleanup(**inputs)
    result, sources = public_run(c, operation)
    assert len(sources) == 2 and "RunCleanup()" in sources[-1]
    assert result["status"] == "OWNED_PAYLOADS_REMOVED_NOT_FUNCTION_OR_INSTALLATION_QUALIFIED"
    assert len(result["worker_result"]["completed_receipts"]) == 4 and result["installable"] is False


@pytest.mark.parametrize("fault", ("temporary-approval", "missing-gate", "fixture-gate", "changed-observation-source",
    "expired", "changed-placement-output", "inode-only-placement", "manifest-installable"))
def test_public_activation_rejects_unreviewed_or_mixed_inputs_without_device_io(boot_input, fault):
    c, module, args = boot_input
    manifest = deepcopy(c["manifest"])
    if fault == "temporary-approval":
        args["approval"] = c["approval"]
    elif fault == "missing-gate":
        del args["prerequisites"]["gates"]["temporary_menu_keys_capture_and_persistence"]
    elif fault == "fixture-gate":
        proof = args["prerequisites"]["gates"]["complete_offline_audit"]["build"]
        path = peer.ROOT / proof["evidence_file"]
        saved = json.loads(c["docs"][path])
        saved["test_fixture_only"] = True
        c["docs"][path] = json.dumps(saved).encode()
        proof["evidence_sha256"] = peer.sha(c["docs"][path])
    elif fault == "changed-observation-source":
        c["docs"][peer.ROOT / args["observation_sources"][0]["evidence_file"]] += b"changed"
    elif fault == "expired":
        c["now"][0] += timedelta(seconds=1001)
    elif fault == "manifest-installable":
        manifest.update(scripts_emitted=True, status="QUALIFIED_DELIVERY_NOT_EXECUTED", package_created=True)
    else:
        raw = c["docs"][peer.ROOT / args["placement_receipt"]["evidence_file"]]
        record = json.loads(raw)
        if fault == "changed-placement-output":
            record["placement_result"]["worker_result"]["worker_outputs"][0]["data"] = base64.b64encode(b"false receipt").decode()
        else:
            record = {key: record[key] for key in ("schema", "candidate_sha256", "session_data_sha256",
                "placement_session_ascii", "completed_identities")}
        args = admission_inputs(c, module, record)
    with mock.patch("tools.menu_host_process.subprocess.Popen", side_effect=AssertionError("unexpected child")):
        with pytest.raises(ValueError):
            module.prepare_boot_validation(manifest, c["plan"], **args)


def test_public_activation_stops_between_preparation_writes_if_approval_expires(boot_input):
    c, module, args = boot_input
    operation = module.prepare_boot_validation(c["manifest"], c["plan"], **args)
    operation.bind_saved_intent(c["save"]("expires-intent.json", operation.snapshot()))
    maintenance = ModelMaintenance(operation.operation.coordinator, [], [int(c["now"][0].timestamp())])
    original = maintenance.command
    def command(label, source):
        value = original(label, source)
        if label.startswith("prepare-observer-"):
            c["now"][0] += timedelta(seconds=1001)
        return value
    maintenance.command = command
    with pytest.raises(ValueError, match="stale|expired|future"):
        operation.prepare_window(maintenance)
    assert len([label for label, _ in maintenance.calls if label.startswith("prepare-observer-")]) == 1


@pytest.mark.parametrize("when", ("before-second-child", "after-validated-commit", "unknown-worker-output"))
def test_public_activation_failure_retains_receipt_only_if_actual_coordinator_completed(boot_input, when):
    c, module, args = boot_input
    operation = module.prepare_boot_validation(c["manifest"], c["plan"], **args)
    operation.bind_saved_intent(c["save"]("failed-intent.json", operation.snapshot()))
    starts = []
    def fault(child, index):
        starts.append(index)
        if when == "before-second-child" and index == 1:
            original = child.wait
            def wait(timeout=None):
                c["now"][0] += timedelta(seconds=1001)
                return original(timeout)
            child.wait = wait
        elif when == "after-validated-commit" and index == 2:
            child.wait = lambda timeout=None: 1
        elif when == "unknown-worker-output" and index == 2:
            import io
            child.stdout = io.BytesIO(b"unexpected worker output\n")
    with pytest.raises(ValueError) as caught:
        public_run(c, operation, fault=fault)
    snapshot = caught.value.boot_acceptance_snapshot
    assert snapshot["status"] == "FAILED_OR_UNCERTAIN_RETAIN_EVIDENCE_NO_AUTOMATIC_REBOOT"
    assert (snapshot["activation_receipt"] is not None) == (when == "after-validated-commit")
    assert starts == ([1] if when == "before-second-child" else [1, 2])
    if when == "after-validated-commit":
        c["now"][0] += timedelta(seconds=100)
        restored = module.prepare_boot_validation_recovery(**recovery_inputs(c, module, snapshot))
        assert restored.snapshot()["activation_failure"]["partial"]["worker_outputs"]
    else:
        reference = c["save"]("unknown-backup.json", snapshot)
        with pytest.raises(ValueError, match="actual completed activate receipt"):
            module.prepare_boot_validation_recovery(acceptance_snapshot=reference, saved_observation=b"{}",
                saved_observation_sha256=peer.sha(b"{}"), prerequisites={}, observation_sources=())


def test_public_activation_cannot_swap_new_observation_into_existing_prepared_operation(boot_input):
    c, module, args = boot_input
    operation = module.prepare_boot_validation(c["manifest"], c["plan"], **args)
    operation.bind_saved_intent(c["save"]("immutable-intent.json", operation.snapshot()))
    previous = operation.snapshot()["placement"]
    c["q"]["session_nonce"] = "f" * 32
    operation.inputs = admission_inputs(c, module, previous)
    class Forbidden:
        report = {}
        def command(self, *args):
            pytest.fail("changed prepared context reached maintenance I/O")
    with pytest.raises(ValueError, match="prepared.*changed|differs"):
        operation.prepare_window(Forbidden())


@pytest.mark.parametrize("fault", ("activation-identities", "recovery-backup", "recovery-action", "recovery-phase"))
def test_public_preparation_rejects_changed_actual_execution_options_before_any_io(boot_input, fault):
    c, module, args = boot_input
    operation = module.prepare_boot_validation(c["manifest"], c["plan"], **args)
    operation.bind_saved_intent(c["save"]("options-intent.json", operation.snapshot()))
    if fault == "activation-identities":
        values = list(operation.operation.options["payload_identities"])
        values[0] = values[0].replace("1:2:", "1:99:")
        operation.operation.options["payload_identities"] = tuple(values)
    else:
        public_run(c, operation)
        c["now"][0] += timedelta(seconds=100)
        operation = module.prepare_boot_validation_recovery(**recovery_inputs(c, module, operation.snapshot()))
        if fault == "recovery-backup":
            operation.operation.options["backup_identity"] = operation.operation.options["backup_identity"].replace("1:9:", "1:99:")
        elif fault == "recovery-action":
            operation.operation.action = "activate"
        else:
            operation.operation._worker_phase = "boot-activate"
    class Forbidden:
        report = {}
        def command(self, *args):
            pytest.fail("changed worker ownership reached maintenance I/O")
    with pytest.raises(ValueError, match="fixed.*options|execution.*changed"):
        operation.prepare_window(Forbidden())


@pytest.mark.parametrize("fault", ("activation-output", "activation-rehashed-grammar", "activation-launch"))
def test_public_recovery_refuses_changed_retained_success_provenance(boot_input, fault):
    c, module, args = boot_input
    activated = module.prepare_boot_validation(c["manifest"], c["plan"], **args)
    activated.bind_saved_intent(c["save"]("provenance-intent.json", activated.snapshot()))
    public_run(c, activated)
    snapshot = activated.snapshot()
    if fault == "activation-output":
        snapshot["activation_result"]["worker_result"]["worker_outputs"][0]["data"] = base64.b64encode(b"wrong actual output").decode()
    elif fault == "activation-rehashed-grammar":
        saved = snapshot["activation_result"]["worker_result"]["worker_outputs"][0]
        malformed = base64.b64decode(saved["data"], validate=True).replace(
            b"maintenance_boundaries=HOST_MEDIATED_FIXED_BOOT_MATCHED", b"maintenance_boundaries=UNVERIFIED")
        saved.update(data=base64.b64encode(malformed).decode(), sha256=peer.sha(malformed))
        snapshot["activation_receipt"]["output_sha256"] = peer.sha(malformed)
        snapshot["activation_result"]["worker_result"]["completed_receipt"]["output_sha256"] = peer.sha(malformed)
    else:
        snapshot["activation_launch_report_utf8"] += "changed"
    c["now"][0] += timedelta(seconds=100)
    inputs = recovery_inputs(c, module, snapshot)
    with mock.patch("tools.menu_host_process.subprocess.Popen", side_effect=AssertionError("unexpected child")):
        with pytest.raises(ValueError, match="retained|launch|output"):
            module.prepare_boot_validation_recovery(**inputs)
