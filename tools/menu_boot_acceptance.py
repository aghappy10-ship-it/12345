"""Narrow first-boot acceptance, separate from temporary and final authority.

Saved records bind reviewed bytes; they cannot authenticate camera observations
or human consent. None of these entry points qualifies a release or reboots.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
import json
import base64
import re

from . import prepare_peer_install as peer, prepare_peer_recovery as recovery
from . import menu_first_validation as temporary, menu_content_transport as content
from . import menu_prepared_transport as prepared, session_context as sc, release_identity
from . import menu_boot_transport as boot, stage_peer_usb_access as usb
from .regression_manifest import strict_json
from .runtime_observation import normalize_observation


BOOT_VALIDATION_ACTIONS = (
    "activate_boot_rc", "observe_new_boot", "restore_boot_rc",
    "observe_stock_new_boot", "remove_owned_payloads",
)
BOOT_VALIDATION_GATES = {
    **{key: value for key, value in temporary.FIRST_VALIDATION_GATES.items()
       if key != "temporary_payload_targets_absent"},
    "temporary_menu_keys_capture_and_persistence": ("runtime",),
    "temporary_gui_finished_original_restored": ("runtime",),
    "four_placement_receipts_and_current_owned_payloads": ("runtime",),
}
BOOT_RECOVERY_GATES = {
    **{key: value for key, value in recovery.GATE_PHASES.items() if key != "saved_installed_candidate"},
    "saved_boot_acceptance_and_actual_backup_receipt": ("runtime",),
}
BOOT_CLEANUP_GATES = {**BOOT_RECOVERY_GATES, "new_boot_stock_gui_readback": ("runtime",)}


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _need(ok, reason):
    if not ok:
        raise ValueError("boot-validation: " + reason)


def _approval_scope(approval, *, read_record=True):
    fields = {"schema", "approved", "purpose", "action", "actions", "candidate_sha256",
        "build_subject_sha256", "boot_id", "operation_nonce", "approved_utc", "expires_utc",
        "reviewed_by", "source_message_id", "record", "placement_receipt_sha256"}
    _need(type(approval) is dict and set(approval) == fields and
        approval["schema"] == "x2dii-first-boot-validation-approval-v1" and
        approval["purpose"] == "first_boot_validation" and
        approval["action"] == "activate_observe_restore_remove" and
        approval["actions"] == list(BOOT_VALIDATION_ACTIONS) and approval["approved"] is True and
        approval["reviewed_by"] == "human_user" and type(approval["source_message_id"]) is str and
        0 < len(approval["source_message_id"]) <= 256 and
        re.fullmatch(r"[0-9a-f]{32}", str(approval["operation_nonce"])),
        "explicit boot-validation human approval scope required")
    if read_record:
        _need(strict_json(temporary._read_reference(approval["record"])) ==
            {k: v for k, v in approval.items() if k != "record"}, "saved human approval differs")


def _time(q, approval=None):
    now = datetime.now(timezone.utc)
    observed = datetime.fromisoformat(q["observed_utc"])
    _need(observed.tzinfo is not None and 0 <= (now - observed).total_seconds() <= 600,
        "current observation is stale or future")
    if approval is not None:
        start, end = (datetime.fromisoformat(approval[k]) for k in ("approved_utc", "expires_utc"))
        _need(start.tzinfo is not None and end.tzinfo is not None and start <= now < end,
            "human approval is stale or future")


def _sources(raw, digest, prerequisites, sources):
    _need(type(raw) is bytes and 0 < len(raw) <= 1024 * 1024 and peer.sha(raw) == digest,
        "bounded exact current observation bytes/hash required")
    _need(type(sources) in (tuple, list) and sources and
        len({row.get("evidence_file") for row in sources if type(row) is dict}) == len(sources),
        "nonempty unique original observation sources required")
    for reference in sources:
        temporary._read_reference(reference)
    _need(prerequisites.get("saved_observation_sha256") == digest and
        prerequisites.get("observation_sources") == list(sources), "observation source binding differs")
    q = strict_json(raw)
    _need(type(q) is dict and q.get("synthetic") is False and q.get("test_fixture_only", False) is False,
        "real reviewed observation required")
    _time(q)
    return q


def _roots(q, candidate):
    roots = q["init_scan_roots"]
    _need(type(roots) is list and roots and q["init_scan_roots_complete"] is True and
        all(type(root) is str for root in roots) and len(roots) == len(set(roots)) and
        "/system/etc/init" in roots, "complete unique init scan roots required")
    base = candidate[:24]
    places = ("/blackbox/x2dii-menu-stage/" + base, "/system/.x2dii-menu-stage/" + base,
        "/system/etc/x2dii-menu-backup/" + base, "/system/etc/.x2dii-boot-" + base + ".original",
        *("/system/etc/.x2dii-boot-" + base + "-" + q["session_nonce"] + "-" + action + ".stage"
          for action in ("activate", "restore")))
    for root in roots:
        _need(re.fullmatch(r"/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+", root) and
            not any(part in (".", "..") for part in root.split("/")) and
            all(p != root and not p.startswith(root + "/") for p in places),
            "invalid or overlapping init scan root")


def _placement(manifest, reference, current):
    value = strict_json(temporary._read_reference(reference))
    return _placement_record(manifest, value, current)


def _placement_record(manifest, value, current):
    _need(type(value) is dict and set(value) == {"schema", "candidate_sha256", "session_data_sha256",
        "placement_session_ascii", "completed_identities", "placement_result", "ready_launch_report",
        "ready_launch_report_utf8", "ready_launch_report_sha256", "placement_observation_sha256",
        "placement_observation_sources", "temporary_final_receipt", "temporary_lifecycle_evidence",
        "temporary_feature_validated"} and
        value["schema"] == "x2dii-boot-validation-placement-v1" and
        value["candidate_sha256"] == manifest["candidate_sha256"], "exact retained placement receipt required")
    raw = value["placement_session_ascii"].encode("ascii")
    previous = sc.decode_session(raw)
    _need(peer.sha(raw) == value["session_data_sha256"] and previous["kind"] == "menu_validation" and
        previous["candidate_sha256"] == manifest["candidate_sha256"] and
        all(previous[k] == current[k] for k in ("boot_id", "active_slot", "official_slot")) and
        previous["observed_epoch"] <= current["observed_epoch"], "placement session lineage differs")
    from .menu_boot_file import encode_payload_identities
    encode_payload_identities(manifest, value["completed_identities"])
    result = value["placement_result"]
    _need(result.get("status") == "PREPARED_MENU_FILES_NOT_LOADED_NOT_FEATURE_VALIDATED" and
        result.get("candidate_sha256") == manifest["candidate_sha256"] and
        result.get("session_data_sha256") == peer.sha(raw), "actual completed placement result required")
    worker = result.get("worker_result", {})
    outputs = worker.get("worker_outputs")
    _need(worker.get("status") == "FOUR_FILES_PREPLACED_NOT_FEATURE_VALIDATED" and
        worker.get("completed_identities") == value["completed_identities"] and type(outputs) is list and len(outputs) == 4,
        "four actual retained worker outputs required")
    for index, saved in enumerate(outputs):
        _need(type(saved) is dict and set(saved) == {"encoding", "data", "sha256"} and saved["encoding"] == "base64",
            "bounded exact placement worker bytes required")
        output = base64.b64decode(saved["data"], validate=True)
        _need(0 < len(output) <= 32768 and peer.sha(output) == saved["sha256"], "placement worker bytes changed")
        parts = output.replace(b"\r\n", b"\n").split(b"schema=x2dii-one-file-preplacement-v1\n")
        file = manifest["candidate"]["files"][index]
        label = previous[("library_label", "bootstrap_label", "model_label", "page_label")[index]]
        expected = (f"candidate_sha256={manifest['candidate_sha256']}\nsession_nonce={previous['session_nonce']}\n"
            f"file_index={index}\nidentity={value['completed_identities'][index]}\nlabel={label}\nsha256={file['sha256']}\n"
            "maintenance_boundaries=HOST_MEDIATED_SEVEN_MATCHED\nX2DII_ONE_FILE_PREPLACED_NOT_RUNTIME_VALIDATED\n\n"
            f"X2DII_WORKER_{peer.sha(raw)[:24]}_{index}_RC=0\n").encode()
        _need(len(parts) == 2 and parts[1] == expected and
            re.fullmatch(b"".join(f"X2DII_BOUNDARY_REQUEST:{index}:{stage}:[0-9a-f]{{64}}\\n".encode()
                for stage in range(7)), parts[0]) is not None, "retained placement output/ownership differs")
    launch_raw = value["ready_launch_report_utf8"].encode("utf-8")
    launch = strict_json(launch_raw)
    _need(peer.sha(launch_raw) == value["ready_launch_report_sha256"] and launch == value["ready_launch_report"] and
        launch.get("bootId") == previous["boot_id"] and
        launch.get("status") == "LAUNCH_REQUESTED_AWAITING_REAL_USB_EVIDENCE" and "error" not in launch,
        "retained ready launch bytes differ")
    # Saved transport source hashes are historical evidence, not required to
    # equal a later recovery implementation's source hashes.
    usb.recorded_launch_start(launch)
    final = value["temporary_final_receipt"]
    _need(final == {"status": "EXITED_NOT_FEATURE_VALIDATED", "session_sha256": peer.sha(raw),
        "receipt_sha256": peer.sha((peer.sha(raw) + ":0\n").encode()), "exit_code": 0, "feature_validated": False} and
        value["temporary_lifecycle_evidence"].get("phase") == "ended-not-feature-validated" and
        value["temporary_feature_validated"] is False, "completed temporary lifecycle result required, not feature PASS")
    return value


def prepare_boot_validation(manifest, parent_plan, *, saved_observation,
                            saved_observation_sha256, prerequisites, approval,
                            observation_sources, placement_receipt):
    """Prepare one explicitly approved first-boot acceptance; no camera I/O."""
    _approval_scope(approval)
    return BootValidationSession(manifest, parent_plan, saved_observation=saved_observation,
        saved_observation_sha256=saved_observation_sha256, prerequisites=prerequisites,
        approval=approval, observation_sources=observation_sources, placement_receipt=placement_receipt)


class BootValidationSession:
    """One fixed activation window, with independently retained recovery intent."""
    def __init__(self, manifest, parent_plan, **inputs):
        self.manifest, self.parent_plan = deepcopy(manifest), deepcopy(parent_plan)
        self.inputs = deepcopy(inputs)
        self.failed = False
        self._intent_reference = self._maintenance = self._launch_raw = None
        self._starts = []
        self._validate()
        self.operation = prepared.PreparedBootOperation(self._preparation, clock=self._clock)
        self._snapshot = self._make_snapshot()

    @staticmethod
    def _clock():
        return datetime.now(timezone.utc).timestamp()

    def _validate(self):
        _need(not self.failed, "failed session cannot start new work")
        _need(self.manifest.get("scripts_emitted") is False and
            self.manifest.get("package_created", False) is False and
            self.manifest.get("installable", False) is False and
            not str(self.manifest.get("status", "")).startswith("QUALIFIED"),
            "first-boot acceptance requires a non-qualified candidate, not final installation authority")
        args = self.inputs
        approval = args["approval"]
        _approval_scope(approval)
        q = _sources(args["saved_observation"], args["saved_observation_sha256"],
            args["prerequisites"], args["observation_sources"])
        temporary.saved_menu_session(self.manifest, args["saved_observation"],
            expected_sha256=args["saved_observation_sha256"])
        _time(q, approval)
        observation = normalize_observation(q, self.manifest["candidate"]["gui_sha256"])
        release_identity.validate_runtime_references(observation)
        _need(type(q.get("uid")) is int and q["uid"] == 0 and q.get("domain") == "u:r:su:s0" and
            observation["gui"]["service_state"] == observation["service"]["service_state"] == "running",
            "current stock GUI/service and distinct su role required")
        _need(set(q["metadata"]) == set(peer.LABEL_FIELDS), "complete observed target metadata required")
        for meta in q["metadata"].values():
            recovery._metadata(meta, "644")
        _roots(q, self.manifest["candidate_sha256"])
        raw = peer.session_data(self.manifest, q)
        values = sc.decode_session(raw)
        receipt = _placement(self.manifest, args["placement_receipt"], values)
        preparation = content.plan_boot_preparation(self.parent_plan, self.manifest, raw,
            action="activate", payload_identities=receipt["completed_identities"])
        prepared._check_current_install_parent(preparation)
        from .delivery_files import assemble_role_delivery
        delivery = assemble_role_delivery(self.manifest["candidate"], self.manifest["candidate_sha256"],
            peer.render_role_programs(self.manifest))
        build = peer.build_subject_sha256(self.manifest)
        expected = {"candidate_sha256": self.manifest["candidate_sha256"], "build_subject_sha256": build,
            "boot_id": q["boot_id"], "placement_receipt_sha256": args["placement_receipt"]["evidence_sha256"]}
        _need(self.manifest["renderer_source_sha256"] == peer.renderer_source_sha256() and
            all(approval[k] == v for k, v in expected.items()), "approval candidate/build/boot/placement differs")
        _need(args["prerequisites"].get("delivery_identity") == delivery["delivery_identity"],
            "fixed role content identity differs")
        release_identity.validate_gates(args["prerequisites"].get("gates", {}), BOOT_VALIDATION_GATES,
            candidate_sha256=self.manifest["candidate_sha256"], build_subject_sha256=build,
            runtime_subject_sha256=peer.runtime_subject_sha256(self.manifest, q), boot_id=q["boot_id"],
            delivery_identity=delivery["delivery_identity"],
            retained={"placement_receipt_sha256": args["placement_receipt"]["evidence_sha256"]}, for_publication=True)
        self.raw_session, self._q, self._preparation, self._delivery = raw, q, preparation, delivery
        self._placement = receipt

    def _make_snapshot(self):
        manifest = deepcopy(self.manifest)
        manifest.update(delivery_identity=self._delivery["delivery_identity"],
            delivery_members=self._delivery["content_manifest"],
            script_hashes={name: peer.sha(source.encode("ascii")) for name, source in
                peer.render_role_programs(self.manifest).items()})
        return strict_json(_canonical({"schema": "x2dii-first-boot-validation-snapshot-v1",
            "status": "INTENT_SAVED_REQUIRED_BEFORE_ACTIVATION", "installable": False,
            "manifest": manifest, "manifest_sha256": peer.sha(_canonical(manifest)),
            "parent_plan": asdict(self.parent_plan), "approval": deepcopy(self.inputs["approval"]),
            "activation_session_ascii": self.raw_session.decode("ascii"),
            "placement": deepcopy(self._placement), "placement_reference": deepcopy(self.inputs["placement_receipt"]),
            "placement_record_utf8": temporary._read_reference(self.inputs["placement_receipt"]).decode("utf-8"),
            "activation_observation_sha256": self.inputs["saved_observation_sha256"],
            "activation_receipt": None, "restore_receipt": None, "restore_session_ascii": None}))

    def snapshot(self):
        return deepcopy(self._snapshot)

    def bind_saved_intent(self, reference):
        """Read back caller-retained intent before any persistent camera write."""
        self._validate()
        _need(strict_json(temporary._read_reference(reference)) == self._snapshot,
            "saved acceptance intent differs")
        self._intent_reference = deepcopy(reference)

    def prepare_window(self, maintenance_session):
        self._validate()
        self._check_operation()
        _need(self._intent_reference is not None, "saved acceptance intent required before any preparation")
        _need(not self.operation._observer_attempted, "window already prepared or attempted")
        _need(strict_json(temporary._read_reference(self._intent_reference)) == self._snapshot,
            "saved acceptance intent changed")
        self._maintenance = maintenance_session
        try:
            _need(usb.preflight(maintenance_session) == self._q["boot_id"], "current maintenance boot differs")
            self._validate()
            self._check_operation()
            from types import SimpleNamespace
            def guarded(label, command):
                self._check_time()
                return maintenance_session.command(label, command)
            self.operation.prepare_observer(SimpleNamespace(command=guarded))
        except Exception:
            self.failed = True
            raise

    def _check_time(self):
        _time(self._q, self.inputs["approval"])

    def _check_operation(self):
        _need(self.operation.preparation == self._preparation and self.operation.manifest == self.manifest and
            self.operation.preparation.raw_session == self.raw_session,
            "prepared operation context changed after construction")
        if type(self) is BootValidationCleanup:
            evidence = strict_json(self._preparation.cleanup_evidence)
            options = (self._preparation.payload_identities, evidence["stock_readback"], evidence["restore_receipt"])
            _need(type(self.operation) is prepared.PreparedCleanupOperation and
                self.operation.options == options and self.operation._worker_phase == "owned-cleanup",
                "fixed cleanup execution options changed")
        else:
            action = "activate" if type(self) is BootValidationSession else "restore"
            options = dict(action=action, payload_identities=self._preparation.payload_identities,
                backup_identity=None if action == "activate" else self._saved_basis["activation_receipt"]["backup_identity"])
            _need(type(self.operation) is prepared.PreparedBootOperation and self.operation.options == options and
                self.operation.action == action and self.operation._worker_phase == "boot-" + action,
                "fixed boot execution options changed")

    def _deadline(self, original):
        return min(original, int(datetime.fromisoformat(self.inputs["approval"]["expires_utc"]).timestamp()))

    def _bind_launch(self, raw):
        _need(type(raw) is bytes and 0 < len(raw) <= 1024 * 1024, "bounded exact saved launch bytes required")
        report = strict_json(raw)
        launch = prepared._recorded_launch(report)
        _need(report.get("status") == "LAUNCH_REQUESTED_AWAITING_REAL_USB_EVIDENCE" and
            "error" not in report and report.get("bootId") == self._q["boot_id"] and
            self.operation._observer_completed_at is not None and
            launch.timestamp() >= self.operation._observer_completed_at,
            "successful current original launch after observer preparation required")
        return report, launch

    def _native_source(self, phase, source):
        self._validate()
        self._check_operation()
        _, launch = self._bind_launch(self._launch_raw)
        sequence = ("preparation", self.operation._worker_phase)
        _need(len(self._starts) < 2 and phase == sequence[len(self._starts)], "native child repeated or out of order")
        first = phase == "preparation"
        expected = (content.review_preparation_host_source(self.operation.preparation, launch) if first
            else self.operation._worker_source(launch))
        _need(type(source) is str and source == expected, "child differs from exact current fixed renderer")
        original = int(content.original_window_deadline(self.operation.preparation.session.observed_epoch, launch))
        deadline = self._deadline(original)
        cleanup = type(self.operation) is prepared.PreparedCleanupOperation
        if cleanup:
            remaining = 16  # Four exact-owned files, four current observation boundaries each.
        else:
            worker = boot.BootCoordinator(self.manifest, self.raw_session, **self.operation.options)
            remaining = len(worker.sequence) - worker.first_boundary
        if first:
            plan, session = self.operation.preparation.plan, self.operation.preparation.session
            remaining += len(content.stage.execution_steps(plan, dict(session.context), session=session))
        content.stage._require_maintenance_budget(datetime.fromtimestamp(deadline, timezone.utc),
            now=datetime.now(timezone.utc), remaining_commands=remaining)
        flag = "ContentQualified" if first else "SupervisionQualified"
        name = "ContentDeadlineEpoch" if first else "OriginalWindowDeadline"
        admitted = content.usb.replace_once(source, f"private const long {name} = {original};",
            f"private const long {name} = {deadline};")
        admitted = content.usb.replace_once(admitted, f"private static readonly bool {flag} = false;",
            f"private static readonly bool {flag} = true;")
        self._starts.append(phase)
        return admitted, ("X2d2ContentStage_" if first else "X2d2MenuCleanup_" if cleanup else "X2d2MenuBoot_"), (
            "RunContentStage" if first else "RunCleanup" if cleanup else "RunBoot"), f"private static readonly bool {flag} = true;"

    def run_window(self, saved_launch_report, maintenance_session):
        _need(not self.operation._run_attempted, "window already attempted or completed")
        self._validate()
        self._check_operation()
        _need(maintenance_session is self._maintenance and self._intent_reference is not None,
            "same prepared maintenance session and saved intent required")
        _need(strict_json(temporary._read_reference(self._intent_reference)) == self._snapshot,
            "saved acceptance intent changed")
        try:
            report, _ = self._bind_launch(saved_launch_report)
            self._launch_raw = saved_launch_report
            self._snapshot["activation_launch_report_utf8"] = saved_launch_report.decode("utf-8")
            self._snapshot["launch_report_sha256"] = peer.sha(saved_launch_report)
            result = self.operation.run(report, maintenance_session, _BootValidationHost(self).start)
            self._snapshot["activation_result"] = _retain(result)
            self._snapshot["activation_receipt"] = deepcopy(result["worker_result"]["completed_receipt"])
            self._snapshot["status"] = "ACTIVATION_RECEIPT_MUST_BE_SAVED_BEFORE_EXTERNAL_REBOOT"
            self._snapshot["intent_reference"] = deepcopy(self._intent_reference)
            self._snapshot["launch_report_sha256"] = peer.sha(saved_launch_report)
            return {**result, "status": "BOOT_ACTIVATED_AWAITING_SAVED_RECEIPT_AND_EXTERNAL_NEW_BOOT",
                "boot_function_verified": False, "installable": False}
        except Exception as error:
            self.failed = True
            partial = getattr(error, "partial_evidence", {})
            completed = partial.get("completed_receipt") if type(partial) is dict else None
            # Only the actual coordinator's validated completion is accepted;
            # arbitrary incomplete output is retained, never parsed as ownership.
            if completed is None:
                evidence = getattr(error, "prepared_operation_evidence", {})
                completed = (evidence.get("worker_result") or {}).get("completed_receipt")
            self._snapshot["activation_receipt"] = deepcopy(completed)
            self._snapshot["status"] = "FAILED_OR_UNCERTAIN_RETAIN_EVIDENCE_NO_AUTOMATIC_REBOOT"
            self._snapshot["activation_failure"] = {"error": str(error),
                "partial": _retain(partial), "operation": _retain(getattr(error, "prepared_operation_evidence", {}))}
            error.boot_acceptance_snapshot = self.snapshot()
            raise


def _retain(value):
    if type(value) is bytes:
        return {"encoding": "base64", "data": base64.b64encode(value).decode("ascii"), "sha256": peer.sha(value)}
    if isinstance(value, datetime):
        return value.isoformat()
    if type(value) is dict:
        return {k: _retain(v) for k, v in value.items()}
    if type(value) in (tuple, list):
        return [_retain(v) for v in value]
    return value


class _BootValidationHost:
    """No public caller source, callback-only executor, or general bypass flag."""
    def __init__(self, session):
        _need(type(session) in (BootValidationSession, BootValidationRecovery, BootValidationCleanup),
            "specific boot-validation session required")
        self.session = session

    def start(self, phase, source):
        from .menu_host_process import _spawn_fixed
        fixed, prefix, entry, guard = self.session._native_source(phase, source)
        return _spawn_fixed(fixed, prefix=prefix, entry=entry, closed_guard=guard)


def _receipt(manifest, raw_session, value, action, *, backup=None):
    fields = {"candidate_sha256", "session_data_sha256", "action", "backup_identity", "identity", "sha256", "output_sha256"}
    stock = peer.boot.STOCK.read_bytes()
    size = len(peer.boot.activate(stock)) if action == "activate" else len(stock)
    _need(type(value) is dict and set(value) == fields and value["action"] == action and
        value["candidate_sha256"] == manifest["candidate_sha256"] and value["session_data_sha256"] == peer.sha(raw_session) and
        value["sha256"] == manifest["candidate"]["rc"]["after" if action == "activate" else "before"] and
        boot._identity(value["identity"], size) and boot._identity(value["backup_identity"], len(stock)) and
        (backup is None or value["backup_identity"] == backup) and
        type(value["output_sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", value["output_sha256"]),
        "exact actual completed " + action + " receipt required; unknown backup cannot be guessed")


def _validate_boot_provenance(snapshot, action):
    """Check preserved bytes with the same receipt grammar as the real driver.

    This proves only internal consistency. Reviewed external evidence, fresh
    recovery observations and every live worker boundary are still required.
    """
    prefix = "activation" if action == "activate" else "restore"
    raw_session = snapshot[prefix + "_session_ascii"].encode("ascii")
    receipt = snapshot[prefix + "_receipt"]
    raw_launch = snapshot.get(prefix + "_launch_report_utf8", "").encode("utf-8")
    launch_hash = snapshot.get("launch_report_sha256" if action == "activate" else "restore_launch_report_sha256")
    _need(0 < len(raw_launch) <= 1024 * 1024 and peer.sha(raw_launch) == launch_hash,
        "retained exact " + prefix + " launch bytes/hash required")
    launch = strict_json(raw_launch)
    values = sc.decode_session(raw_session)
    _need(type(launch) is dict and launch.get("bootId") == values["boot_id"] and
        launch.get("status") == "LAUNCH_REQUESTED_AWAITING_REAL_USB_EVIDENCE" and "error" not in launch,
        "retained boot launch context differs")
    content.original_window_deadline(values["observed_epoch"], usb.recorded_launch_start(launch))
    result = snapshot.get(prefix + "_result")
    if result is not None:
        _need(type(result) is dict and result.get("status") == "PREPARED_BOOT_FILE_TRANSACTION_NOT_LIFECYCLE_VALIDATED" and
            result.get("candidate_sha256") == snapshot["manifest"]["candidate_sha256"] and
            result.get("session_data_sha256") == peer.sha(raw_session), "retained completed boot result differs")
        worker = result.get("worker_result", {})
        _need(worker.get("status") == "BOOT_FILE_TRANSACTION_NOT_LIFECYCLE_VALIDATED",
            "retained completed worker status differs")
    else:
        failure = snapshot.get("activation_failure" if action == "activate" else "recovery_failure", {})
        worker = (failure.get("operation", {}).get("worker_result") or failure.get("partial", {}))
    _need(type(worker) is dict and worker.get("completed_receipt") == receipt,
        "retained actual worker receipt differs")
    outputs = worker.get("worker_outputs")
    _need(type(outputs) is list and len(outputs) == 1, "one retained actual boot worker output required")
    saved = outputs[0]
    _need(type(saved) is dict and set(saved) == {"encoding", "data", "sha256"} and saved["encoding"] == "base64",
        "retained boot output encoding differs")
    output = base64.b64decode(saved["data"], validate=True)
    _need(0 < len(output) <= 32768 and peer.sha(output) == saved["sha256"], "retained actual boot output changed")
    try:
        parsed = boot._completed_boot_receipt(snapshot["manifest"], raw_session, action=action,
            decoded_output=output, backup_identity=None if action == "activate" else snapshot["activation_receipt"]["backup_identity"])
    except ValueError as error:
        raise ValueError("boot-validation: retained boot output invalid: " + str(error)) from error
    _need(parsed == receipt, "retained actual boot output does not bind the saved receipt")


def _load_snapshot(reference):
    snapshot = strict_json(temporary._read_reference(reference))
    _need(type(snapshot) is dict and snapshot.get("schema") == "x2dii-first-boot-validation-snapshot-v1" and
        snapshot.get("installable") is False and snapshot.get("status") in (
            "ACTIVATION_RECEIPT_MUST_BE_SAVED_BEFORE_EXTERNAL_REBOOT",
            "FAILED_OR_UNCERTAIN_RETAIN_EVIDENCE_NO_AUTOMATIC_REBOOT",
            "RESTORE_RECEIPT_MUST_BE_SAVED_BEFORE_EXTERNAL_NEW_BOOT"), "saved boot acceptance snapshot required")
    manifest = snapshot["manifest"]
    _need(peer.sha(_canonical(manifest)) == snapshot["manifest_sha256"] and
        manifest.get("schema") == "x2dii-peer-script-source-v2" and
        manifest.get("scripts_emitted") is False and manifest.get("package_created", False) is False and
        not str(manifest.get("status", "")).startswith("QUALIFIED") and
        manifest.get("candidate_sha256") == peer.sha(_canonical(manifest["candidate"])),
        "non-qualified saved candidate identity required")
    release_identity.validate_delivery_identity(manifest["delivery_identity"])
    recovery._saved_role_content(manifest)
    programs = peer.render_role_programs(manifest)
    _need(manifest["script_hashes"]["restore-boot.sh"] == peer.sha(programs["restore-boot.sh"].encode("ascii")),
        "saved fixed restore program differs from current recovery renderer")
    approval = snapshot["approval"]
    _approval_scope(approval, read_record=False)
    raw = snapshot["activation_session_ascii"].encode("ascii")
    values = sc.decode_session(raw)
    _need(values["kind"] == "install" and approval["candidate_sha256"] == manifest["candidate_sha256"] and
        approval["boot_id"] == values["boot_id"] and
        approval["placement_receipt_sha256"] == snapshot["placement_reference"]["evidence_sha256"],
        "saved approval/activation lineage differs")
    _receipt(manifest, raw, snapshot["activation_receipt"], "activate")
    _validate_boot_provenance(snapshot, "activate")
    if snapshot.get("restore_receipt") is not None:
        restore_raw = (snapshot.get("restore_session_ascii") or "").encode("ascii")
        _receipt(manifest, restore_raw, snapshot["restore_receipt"], "restore",
            backup=snapshot["activation_receipt"]["backup_identity"])
        _validate_boot_provenance(snapshot, "restore")
    elif snapshot["status"] == "RESTORE_RECEIPT_MUST_BE_SAVED_BEFORE_EXTERNAL_NEW_BOOT":
        raise ValueError("boot-validation: restored snapshot lacks actual restore receipt")
    placement = snapshot["placement"]
    placement_raw = snapshot["placement_record_utf8"].encode("utf-8")
    _need(peer.sha(placement_raw) == snapshot["placement_reference"]["evidence_sha256"] and
        placement == strict_json(placement_raw), "embedded original placement bytes changed")
    _placement_record(manifest, placement, values)
    plan = snapshot["parent_plan"]
    _need(type(plan) is dict and plan.get("installable") is False and
        plan.get("transport_invocation_available") is False and plan.get("phase") == "stable-content" and
        plan.get("candidate_sha256") == manifest["candidate_sha256"] and plan.get("include_session_file") is False,
        "saved stable parent plan differs")
    parent = content.stage.StagingPlan(**{key: value for key, value in plan.items()
        if key not in ("installable", "transport_invocation_available", "steps", "member_names")},
        member_names=tuple(plan["member_names"]), steps=tuple(content.stage.StageStep(**step) for step in plan["steps"]))
    return snapshot, manifest, parent


def _recovery_bindings(snapshot, reference, q):
    """Recovery audit closure excludes mutable payload/native-build sources."""
    from . import peer_usb_access
    paths = {p for directory in ("tools", "tests") for p in (peer.ROOT / directory).rglob("*")
        if p.is_file() and "__pycache__" not in p.parts}
    paths.add(peer_usb_access.REFERENCE)
    paths.update(peer.ROOT / name for name in ("AGENTS.md", "pytest.ini", "work/reverse/X2DII_REGRESSION_GATES.json",
        *release_identity.REVIEW_INPUTS, *release_identity.AUDIT_INPUTS))
    _need(all(not p.is_symlink() and p.resolve().is_relative_to(peer.ROOT) for p in paths),
        "recovery source inputs redirect outside project")
    inputs = {p.relative_to(peer.ROOT).as_posix(): peer.sha(p.read_bytes()) for p in sorted(paths)}
    stock = peer.boot.STOCK.read_bytes()
    _need(peer.sha(stock) == peer.boot.STOCK_SHA256, "pinned official rc source changed")
    inputs["pinned_official_camera_gui_rc"] = peer.sha(stock)
    manifest = snapshot["manifest"]
    build = release_identity.build_subject(manifest["candidate"],
        {"restore-boot.sh": peer.render_role_programs(manifest)["restore-boot.sh"]},
        source_hash=peer.sha(Path(__file__).read_bytes()), inputs=inputs,
        retained={"saved_acceptance_snapshot_sha256": reference["evidence_sha256"]})
    runtime = peer.sha(_canonical({"schema": "x2dii-boot-acceptance-recovery-runtime-v1",
        "build_subject_sha256": build,
        "context": {key: q[key] for key in (*recovery.RUNTIME_FIELDS, "backup_identity")}}))
    return dict(candidate_sha256=manifest["candidate_sha256"], build_subject_sha256=build,
        runtime_subject_sha256=runtime, boot_id=q["boot_id"], delivery_identity=manifest["delivery_identity"],
        retained={"saved_acceptance_snapshot_sha256": reference["evidence_sha256"]})


def prepare_boot_validation_recovery(*, acceptance_snapshot, saved_observation,
        saved_observation_sha256, prerequisites, observation_sources):
    """Continue only exact accepted rc restoration; no new activation authority."""
    return BootValidationRecovery(acceptance_snapshot=acceptance_snapshot, saved_observation=saved_observation,
        saved_observation_sha256=saved_observation_sha256, prerequisites=prerequisites,
        observation_sources=observation_sources)


class BootValidationRecovery(BootValidationSession):
    _gates = BOOT_RECOVERY_GATES
    def __init__(self, **inputs):
        self.inputs = deepcopy(inputs)
        self.failed, self._starts = False, []
        self._snapshot, self.manifest, self.parent_plan = _load_snapshot(inputs["acceptance_snapshot"])
        self._saved_basis = deepcopy(self._snapshot)
        self._intent_reference = deepcopy(inputs["acceptance_snapshot"])
        self._maintenance = self._launch_raw = None
        self._validate()
        self.operation = self._make_operation()

    def _make_operation(self):
        return prepared.PreparedBootOperation(self._preparation,
            backup_identity=self._snapshot["activation_receipt"]["backup_identity"], clock=self._clock)

    def _gate_identity(self, snapshot, q):
        return _recovery_bindings(snapshot, self.inputs["acceptance_snapshot"], q)

    def _validate(self):
        _need(not self.failed, "failed recovery session cannot start new work")
        args = self.inputs
        snapshot, manifest, parent = _load_snapshot(args["acceptance_snapshot"])
        _need(snapshot == self._saved_basis and manifest == self.manifest and parent == self.parent_plan,
            "saved acceptance changed after construction")
        q = _sources(args["saved_observation"], args["saved_observation_sha256"],
            args["prerequisites"], args["observation_sources"])
        recovery._context(manifest, snapshot["manifest_sha256"], q)
        recovery._execution_gui(manifest, q)
        _roots(q, manifest["candidate_sha256"])
        old = sc.decode_session(snapshot["activation_session_ascii"].encode("ascii"))
        _need(q["backup_identity"] == snapshot["activation_receipt"]["backup_identity"] and
            q["session_nonce"] != old["session_nonce"] and
            int(datetime.fromisoformat(q["observed_utc"]).timestamp()) >= old["observed_epoch"] and
            all(q[k] == old[k] for k in ("active_slot", "official_slot")), "fresh recovery ownership or slot lineage differs")
        release_identity.validate_gates(args["prerequisites"].get("gates", {}), self._gates,
            for_publication=True, **self._gate_identity(snapshot, q))
        raw = recovery.session_data(manifest, q)
        preparation = content.plan_boot_preparation(parent, manifest, raw, action="restore")
        self._q, self.raw_session, self._preparation = q, raw, preparation

    def _check_time(self):
        _time(self._q)

    def _deadline(self, original):
        return original  # Original 90-second USB/600-second observation limits remain.

    def bind_saved_intent(self, reference):
        raise ValueError("boot-validation: recovery consumes its existing saved snapshot only")

    def _record_restore_attempt(self, attempt):
        # The saved basis preserves older attempts without a mutable history
        # chain. Only a genuinely validated commit may replace selected proof.
        self._snapshot["restore_attempt"] = deepcopy(attempt)
        if attempt["restore_receipt"] is None:
            return
        fields = ("restore_receipt", "restore_session_ascii", "restore_launch_report_utf8",
            "restore_launch_report_sha256", "restore_result", "recovery_failure")
        if self._snapshot.get("restore_receipt") is not None:
            self._snapshot["previous_restore_evidence"] = {
                "basis_snapshot_reference": deepcopy(self.inputs["acceptance_snapshot"]),
                "snapshot_fields": {key: deepcopy(self._snapshot.get(key)) for key in fields}}
        self._snapshot.update({key: deepcopy(attempt[key]) for key in fields})

    def run_window(self, saved_launch_report, maintenance_session):
        _need(not self.operation._run_attempted, "recovery window already attempted or completed")
        self._validate()
        self._check_operation()
        _need(maintenance_session is self._maintenance, "same prepared recovery maintenance session required")
        attempt = {"basis_snapshot_reference": deepcopy(self.inputs["acceptance_snapshot"]),
            "restore_session_ascii": self.raw_session.decode("ascii"), "restore_receipt": None,
            "restore_result": None, "recovery_failure": None,
            "restore_launch_report_utf8": None, "restore_launch_report_sha256": None}
        try:
            report, _ = self._bind_launch(saved_launch_report)
            self._launch_raw = saved_launch_report
            attempt["restore_launch_report_utf8"] = saved_launch_report.decode("utf-8")
            attempt["restore_launch_report_sha256"] = peer.sha(saved_launch_report)
            result = self.operation.run(report, maintenance_session, _BootValidationHost(self).start)
            attempt["restore_result"] = _retain(result)
            attempt["restore_receipt"] = deepcopy(result["worker_result"]["completed_receipt"])
            self._record_restore_attempt(attempt)
            self._snapshot["status"] = "RESTORE_RECEIPT_MUST_BE_SAVED_BEFORE_EXTERNAL_NEW_BOOT"
            return {**result, "status": "OFFICIAL_RC_RESTORED_AWAITING_EXTERNAL_NEW_BOOT",
                "boot_function_verified": False, "installable": False}
        except Exception as error:
            self.failed = True
            partial = getattr(error, "partial_evidence", {})
            completed = partial.get("completed_receipt") if type(partial) is dict else None
            if completed is None:
                evidence = getattr(error, "prepared_operation_evidence", {})
                completed = (evidence.get("worker_result") or {}).get("completed_receipt")
            attempt["restore_receipt"] = deepcopy(completed)
            attempt["recovery_failure"] = {"error": str(error), "partial": _retain(partial),
                "operation": _retain(getattr(error, "prepared_operation_evidence", {}))}
            self._record_restore_attempt(attempt)
            self._snapshot["status"] = "FAILED_OR_UNCERTAIN_RETAIN_EVIDENCE_NO_AUTOMATIC_REBOOT"
            error.boot_acceptance_snapshot = self.snapshot()
            raise


def prepare_boot_validation_cleanup(*, acceptance_snapshot, saved_observation,
        saved_observation_sha256, prerequisites, observation_sources, stock_readback):
    """Exact-owned cleanup only after retained restore and actual new stock boot."""
    return BootValidationCleanup(acceptance_snapshot=acceptance_snapshot, saved_observation=saved_observation,
        saved_observation_sha256=saved_observation_sha256, prerequisites=prerequisites,
        observation_sources=observation_sources, stock_readback=stock_readback)


class BootValidationCleanup(BootValidationRecovery):
    _gates = BOOT_CLEANUP_GATES

    def _make_operation(self):
        return prepared.PreparedCleanupOperation(self._preparation, clock=self._clock)

    def _gate_identity(self, snapshot, q):
        identity = super()._gate_identity(snapshot, q)
        identity["retained"]["stock_readback_sha256"] = self.inputs["stock_readback"]["evidence_sha256"]
        return identity

    def _validate(self):
        super()._validate()
        snapshot = self._saved_basis
        raw_previous = (snapshot.get("restore_session_ascii") or "").encode("ascii")
        _need(raw_previous, "actual retained restore session required before cleanup")
        _receipt(self.manifest, raw_previous, snapshot["restore_receipt"], "restore",
            backup=snapshot["activation_receipt"]["backup_identity"])
        previous, current = sc.decode_session(raw_previous), sc.decode_session(self.raw_session)
        _need(previous["kind"] == "recovery" and current["boot_id"] != previous["boot_id"] and
            current["session_nonce"] != previous["session_nonce"] and
            all(current[k] == previous[k] for k in ("active_slot", "official_slot")),
            "cleanup requires actual different stock boot and fresh session")
        stock = strict_json(temporary._read_reference(self.inputs["stock_readback"]))
        _need(stock.get("saved_manifest_sha256") == snapshot["manifest_sha256"] and
            stock.get("previous_boot_id") == previous["boot_id"] and
            type(stock.get("queries")) is list and len(stock["queries"]) >= 40,
            "retained complete original-GUI readback provenance required")
        self._preparation = content.plan_cleanup_preparation(self.parent_plan, self.manifest, self.raw_session,
            snapshot["placement"]["completed_identities"], stock, snapshot["restore_receipt"])

    def run_window(self, saved_launch_report, maintenance_session):
        _need(not self.operation._run_attempted, "cleanup window already attempted or completed")
        self._validate()
        self._check_operation()
        _need(maintenance_session is self._maintenance, "same prepared cleanup maintenance session required")
        try:
            report, _ = self._bind_launch(saved_launch_report)
            self._launch_raw = saved_launch_report
            self._snapshot["cleanup_launch_report_utf8"] = saved_launch_report.decode("utf-8")
            self._snapshot["cleanup_launch_report_sha256"] = peer.sha(saved_launch_report)
            result = self.operation.run(report, maintenance_session, _BootValidationHost(self).start)
            self._snapshot["cleanup_result"] = _retain(result)
            self._snapshot["status"] = "OWNED_PAYLOADS_REMOVED_NOT_FUNCTION_OR_INSTALLATION_QUALIFIED"
            return {**result, "status": self._snapshot["status"], "boot_function_verified": False, "installable": False}
        except Exception as error:
            self.failed = True
            self._snapshot["cleanup_failure"] = {"error": str(error),
                "partial": _retain(getattr(error, "partial_evidence", {})),
                "operation": _retain(getattr(error, "prepared_operation_evidence", {}))}
            error.boot_acceptance_snapshot = self.snapshot()
            raise
