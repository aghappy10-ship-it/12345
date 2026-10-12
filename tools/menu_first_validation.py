"""Fixed first menu-validation data/sequence; never installation authority.

Saved bytes cannot authenticate an observation. Conversion preserves its exact
time and context; no old identity-only readout is promoted to complete data.
The specific temporary-entry route requires complete externally reviewed
prerequisites and human approval; it grants no final-installation authority.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from copy import deepcopy
import json
import math
from pathlib import Path
import re
import time

from . import prepare_peer_install as peer, session_context as sc
from .menu_maintenance_boundary import _candidate, session_kind_for_context
from .regression_manifest import strict_json
from .runtime_observation import normalize_observation
from . import menu_content_transport as content, menu_prepared_transport as prepared
from . import stage_peer_usb_access as usb
from .menu_host_process import FixedContentHost, FixedPreparedHost
from .menu_lifecycle_transport import TemporaryLifecycle
from . import release_identity
from .output_guard import guard_output


# These are first-entry prerequisites, NOT the final installation obligations.
# The runtime witnesses concern the STOCK camera and already authorized harmless
# temporary tool/service tests. No new-menu function result is presumed here.
FIRST_VALIDATION_GATES = {
    "complete_offline_audit": ("build",),
    "all_applicable_historical_regressions": ("build",),
    "package_integrity_and_roundtrip": ("build",),
    **{name: ("runtime",) for name in (
        "actual_su_domain_access", "independent_recovery_official_slot",
        "target_shell_tools_and_sync_rename", "init_stop_inhibits_restart",
        "current_slot_mount_namespace", "exclusive_maintenance_session",
        "official_runtime_baseline", "official_rc_metadata_and_payload_policy",
        "temporary_payload_targets_absent")},
}
FIRST_VALIDATION_ACTIONS = (
    "stage_fixed_content", "stage_temporary_programs", "place_four_extension_files",
    "run_temporary_gui", "restore_original_gui",
)


def _read_reference(reference):
    if type(reference) is not dict or set(reference) != {"evidence_file", "evidence_sha256"}:
        raise ValueError("exact saved evidence reference required")
    name = reference["evidence_file"]
    if (type(name) is not str or not re.fullmatch(r"build/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", name) or
        any(part in (".", "..") for part in name.split("/"))):
        raise ValueError("saved evidence must remain inside build")
    path = guard_output(peer.ROOT / name)
    raw = path.read_bytes()
    if not 0 < len(raw) <= 16 * 1024 * 1024 or peer.sha(raw) != reference["evidence_sha256"]:
        raise ValueError("saved evidence bytes/hash changed")
    return raw


def _validate_first_entry(manifest, raw_observation, observation_sha256, prerequisites,
                          approval, observation_sources, *, now):
    """Validate externally reviewed facts; hashes do not authenticate consent."""
    if type(prerequisites) is not dict or type(approval) is not dict:
        raise ValueError("first-validation prerequisites and human approval required")
    required = {"schema", "approved", "purpose", "action", "actions", "candidate_sha256", "build_subject_sha256",
                "boot_id", "operation_nonce", "approved_utc", "expires_utc", "reviewed_by", "source_message_id", "record"}
    if (set(approval) != required or approval["schema"] != "x2dii-first-menu-validation-approval-v1" or
        approval["approved"] is not True or approval["purpose"] != "temporary_menu_validation" or
        approval["action"] != "run_and_restore" or approval["actions"] != list(FIRST_VALIDATION_ACTIONS) or
        approval["reviewed_by"] != "human_user" or type(approval["source_message_id"]) is not str or
        not 0 < len(approval["source_message_id"]) <= 256 or
        not re.fullmatch(r"[0-9a-f]{32}", str(approval["operation_nonce"]))):
        raise ValueError("explicit fixed first-menu human approval scope required")
    record = strict_json(_read_reference(approval["record"]))
    if record != {key: value for key, value in approval.items() if key != "record"}:
        raise ValueError("saved human approval record differs")
    approved, expires = (datetime.fromisoformat(approval[key]) for key in ("approved_utc", "expires_utc"))
    if (now.tzinfo is None or approved.tzinfo is None or expires.tzinfo is None or
        not approved <= now < expires):
        raise ValueError("first-menu human approval is stale or future")
    saved = saved_menu_session(manifest, raw_observation, expected_sha256=observation_sha256)
    q = strict_json(raw_observation)
    observed = datetime.fromisoformat(q["observed_utc"])
    if q.get("synthetic") is not False or type(q.get("uid")) is not int or q["uid"] != 0 or q.get("domain") != "u:r:su:s0":
        raise ValueError("real complete observation and distinct su write identity required")
    if not 0 <= (now - observed).total_seconds() <= 600:
        raise ValueError("complete observation is stale or future")
    if (type(observation_sources) not in (list, tuple) or not observation_sources or
        len({row.get("evidence_file") for row in observation_sources if type(row) is dict}) != len(observation_sources)):
        raise ValueError("nonempty unique original observation source records required")
    for reference in observation_sources:
        _read_reference(reference)
    if (prerequisites.get("saved_observation_sha256") != observation_sha256 or
        prerequisites.get("observation_sources") != list(observation_sources)):
        raise ValueError("reviewed observation bytes/source binding differs")
    observation = normalize_observation(q, manifest["candidate"]["gui_sha256"])
    release_identity.validate_runtime_references(observation)
    if observation["gui"]["service_state"] != "running" or observation["service"]["service_state"] != "running":
        raise ValueError("stock GUI and camera service must be observed running")
    expected_metadata = {peer.boot.TARGET, *(target for _, target in peer.FILES)}
    if type(q["metadata"]) is not dict or set(q["metadata"]) != expected_metadata:
        raise ValueError("official rc metadata and four payload policies required")
    for item in q["metadata"].values():
        if (type(item) is not dict or item.get("uid") != 0 or item.get("gid") != 0 or
            item.get("mode") != "644" or item.get("xattr_names") != ["security.selinux"]):
            raise ValueError("unsupported official metadata/payload policy")
    roots = q["init_scan_roots"]
    if (q["init_scan_roots_complete"] is not True or type(roots) is not list or not roots or
        any(type(root) is not str for root in roots) or len(roots) != len(set(roots)) or
        "/system/etc/init" not in roots):
        raise ValueError("complete actual init scan roots required")
    # Same complete-root and path-disjoint policy as the existing role delivery;
    # a legitimate additional init root is not a reason to reject the camera.
    base = manifest["candidate_sha256"][:24]
    boot_prefix = "/system/etc/.x2dii-boot-" + base
    locations = ("/blackbox/x2dii-menu-stage/" + base, "/system/.x2dii-menu-stage/" + base,
        "/system/etc/x2dii-menu-backup/" + base, boot_prefix + ".original",
        *(boot_prefix + "-" + q["session_nonce"] + "-" + action + ".stage" for action in ("activate", "restore")))
    for root in roots:
        if (not re.fullmatch(r"/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+", root) or
            any(part in (".", "..") for part in root.split("/"))):
            raise ValueError("invalid init scan root")
        if any(path == root.rstrip("/") or path.startswith(root.rstrip("/") + "/") for path in locations):
            raise ValueError("work or backup path lies inside an init scan root")
    build = peer.build_subject_sha256(manifest)
    runtime = peer.runtime_subject_sha256(manifest, q)
    if (manifest["renderer_source_sha256"] != peer.renderer_source_sha256() or
        any(approval[key] != value for key, value in (("candidate_sha256", manifest["candidate_sha256"]),
             ("build_subject_sha256", build), ("boot_id", q["boot_id"])))):
        raise ValueError("human approval candidate/build/boot differs")
    from .delivery_files import assemble_role_delivery
    identity = assemble_role_delivery(manifest["candidate"], manifest["candidate_sha256"],
        peer.render_role_programs(manifest))["delivery_identity"]
    if prerequisites.get("delivery_identity") != identity:
        raise ValueError("first-menu fixed delivery identity differs")
    release_identity.validate_gates(prerequisites.get("gates", {}), FIRST_VALIDATION_GATES,
        candidate_sha256=manifest["candidate_sha256"], build_subject_sha256=build,
        runtime_subject_sha256=runtime, boot_id=q["boot_id"], delivery_identity=identity, for_publication=True)
    return saved, q, expires


@dataclass(frozen=True)
class SavedMenuSession:
    raw_session: bytes
    saved_observation_sha256: str
    raw_session_sha256: str
    installable: bool = field(default=False, init=False)
    authorization_granted: bool = field(default=False, init=False)


def saved_menu_session(manifest, raw_observation, *, expected_sha256):
    """Convert a complete saved current context through the existing codec.

    The expected hash binds the caller's exact saved input, not its truth or
    freshness. Missing records must be supplied, never invented or refreshed.
    This returns data only, not a temporary-test or final-installation grant.
    """
    candidate = _candidate(manifest)
    if (type(raw_observation) is not bytes or not 0 < len(raw_observation) <= 1024 * 1024 or
        peer.sha(raw_observation) != expected_sha256):
        raise ValueError("exact bounded saved observation bytes/hash required")
    q = strict_json(raw_observation)
    if type(q) is not dict:
        raise ValueError("complete saved observation object required")
    missing = sorted(set((*peer.EXECUTION_CONTEXT_FIELDS, "runtime_observation")) - q.keys())
    if missing:
        raise ValueError("saved observation missing fields: " + ", ".join(missing))
    if q.get("synthetic") is True or q.get("test_fixture_only") is True:
        raise ValueError("synthetic saved observation cannot supply a camera session")
    try:
        observed = datetime.fromisoformat(q["observed_utc"])
        if observed.tzinfo is None:
            raise ValueError("saved observed_utc requires timezone")
        observation = normalize_observation(q, manifest["candidate"]["gui_sha256"])
        if observation["test_fixture_only"]:
            raise ValueError("fixture observation cannot supply a camera session")
        peer.validate_session_context(q)
        values = sc.decode_session(peer.session_data(manifest, q))
    except (KeyError, TypeError) as error:
        raise ValueError("saved observation missing or invalid field: " + str(error)) from error
    values.update(kind="menu_validation", purpose="temporary_menu_validation",
                  action="run_and_restore", candidate_sha256=candidate)
    raw = sc.encode_session(values, schema=sc.MENU_VALIDATION_SCHEMA)
    session_kind_for_context(manifest, raw)  # Existing two-role observer contract.
    return SavedMenuSession(raw, expected_sha256, peer.sha(raw))


def run_first_validation(preparation, *, previous_code_result=None, previous_launch_report=None,
                         ready_launch_report=None, maintenance_session=None):
    """Execute the prepared fixed window only through its complete admission.

    Historical loose arguments cannot admit a first-validation action. A real
    caller creates the specific object below and prepares its observer before
    the existing USB worker's original launch. No USB window is opened here.
    """
    if (type(preparation) is not FirstValidationSession or previous_code_result is not None or
        previous_launch_report is not None):
        raise ValueError("FIRST_MENU_VALIDATION_ADMISSION_NOT_CONNECTED_NO_DEVICE_ACTION")
    return preparation.run_window(ready_launch_report, maintenance_session)


def _prepare_content_stage(coordinator, maintenance_session, *, clock=time.time):
    """Internal fixed preparation, only after independent live admission.

    Separate from run because the existing original USB worker must be launched
    AFTER observer preparation. This helper never opens or launches USB.
    """
    if type(coordinator) not in (content.ContentStageCoordinator, content.SecondWindowPreparationCoordinator):
        raise ValueError("fixed content/preparation coordinator required")
    if getattr(coordinator, "_first_validation_preparation_attempted", False):
        raise ValueError("fixed observer preparation already attempted")
    coordinator._first_validation_preparation_attempted = True
    try:
        while (operation := coordinator.next_preparation) is not None:
            output = maintenance_session.command("prepare-observer-" + str(operation.index), operation.command)
            coordinator.accept_preparation(exit_code=0, stdout=output, completion_validated=True)
        completed = clock()
        if type(completed) not in (int, float) or not math.isfinite(completed):
            raise ValueError("finite observer completion time required")
        coordinator._first_validation_preparation_completed_at = completed
        return completed
    except Exception:
        coordinator.failed = True
        raise


def _run_content_stage(coordinator, launch_report, maintenance_session, *, observer_completed_at,
                       start_process=None):
    """Actual coordinator/host/driver link; default review hosts stay closed.

    The public specific-admission session supplies its own exact validated host.
    """
    if type(coordinator) not in (content.ContentStageCoordinator, content.SecondWindowPreparationCoordinator):
        raise ValueError("fixed content/preparation coordinator required")
    if getattr(coordinator, "_first_validation_run_attempted", False):
        raise ValueError("fixed content stage already attempted")
    coordinator._first_validation_run_attempted = True
    process = None
    evidence = {"phase": "launch-binding", "installable": False, "result": None,
        "candidate_sha256": coordinator._plan.candidate_sha256,
        "plan_sha256": coordinator._plan.plan_sha256,
        "session_data_sha256": coordinator._session.data_sha256}
    active_error = None
    try:
        launch = prepared._recorded_launch(launch_report)
        if (launch_report.get("status") != "LAUNCH_REQUESTED_AWAITING_REAL_USB_EVIDENCE" or
            "error" in launch_report or launch_report.get("bootId") != dict(coordinator._session.context)["boot_id"] or
            type(observer_completed_at) not in (int, float) or not math.isfinite(observer_completed_at) or
            observer_completed_at != getattr(coordinator, "_first_validation_preparation_completed_at", None) or
            launch.timestamp() < observer_completed_at):
            raise ValueError("successful original launch after observer preparation required")
        coordinator.start_window(launch)
        if type(coordinator) is content.ContentStageCoordinator:
            host = FixedContentHost(coordinator._plan, coordinator._session, launch)
            source = content.review_content_host_source(coordinator._plan, coordinator._session, launch)
            phase, driver = "stable-content", content.drive_content_process
        else:
            host = FixedPreparedHost(coordinator.preparation, launch)
            source = content.review_preparation_host_source(coordinator.preparation, launch)
            phase, driver = "preparation", content.drive_preparation_process
        evidence["phase"] = phase
        process = (host.start if start_process is None else start_process)(phase, source)
        evidence["result"] = driver(process, coordinator, maintenance_session)
        return evidence["result"]
    except Exception as error:
        coordinator.failed = True
        active_error = error
        error.first_validation_stage_evidence = evidence
        raise
    finally:
        cleanup = prepared._PreparedOperation._close_child(process)
        if cleanup:
            coordinator.failed = True
            evidence["cleanup_errors"] = cleanup
            if active_error is None:
                error = ValueError("fixed stage host cleanup failed")
                error.first_validation_stage_evidence = evidence
                raise error


class _FirstValidationFlow:
    """Internal fixed ready -> original USB -> temporary GUI flow.

    No publication, USB launcher, boot activation or authorization flag. A real
    caller needs separate first-validation admission BEFORE constructing or
    invoking this path. Local integration replaces only external I/O/time.
    """
    def __init__(self, preparation, *, previous_code_result, previous_launch_report,
                 clock=time.time, sleep=time.sleep):
        self.operation = prepared.PreparedMenuPlacementOperation(preparation,
            previous_code_result=previous_code_result, previous_launch_report=previous_launch_report, clock=clock)
        self._clock, self._sleep = clock, sleep
        self._placement = self._launch = self._lifecycle = None
        self._stop_attempted = False
        self._lifecycle_deadline = None
        self.failed = False
        self.evidence = {"installable": False, "feature_validated": False, "phase": "ready",
                         "placement": None, "lifecycle": [], "recovery_errors": []}

    def prepare_observer(self, maintenance_session):
        try:
            self.operation.prepare_observer(maintenance_session)
        except Exception as error:
            self.failed = True
            error.first_validation_evidence = self.evidence
            raise

    def place(self, launch_report, maintenance_session, *, start_process=None):
        if self.failed or self._placement is not None:
            raise ValueError("first validation flow already placed or failed")
        try:
            launch = prepared._recorded_launch(launch_report)
            host = FixedPreparedHost(self.operation.preparation, launch)
            self._placement = self.operation.run(launch_report, maintenance_session,
                host.start if start_process is None else start_process)
            self._launch = launch
            self.evidence.update(phase="original-usb-restoration-required", placement=deepcopy(self._placement))
            return deepcopy(self._placement)
        except Exception as error:
            self.failed = True
            error.first_validation_evidence = self.evidence
            raise

    def _poll_final(self, deadline, *, recovering):
        errors = 0
        for _ in range(150):
            if self._clock() >= deadline:
                break
            try:
                result = self._lifecycle.read()
                self.evidence["lifecycle"].append(result)
                if result["status"] == "EXITED_NOT_FEATURE_VALIDATED":
                    return result
            except Exception as error:
                if not recovering:
                    raise
                self.evidence["recovery_errors"].append({"action": "read", "error": str(error)})
                errors += 1
                if errors == 3:
                    break
            self._sleep(1)
        raise ValueError("bounded lifecycle final receipt unavailable; recovery is unverified")

    def _recover_attempted(self, deadline):
        if self._lifecycle.final is not None:
            return
        try:
            result = self._lifecycle.read()
            self.evidence["lifecycle"].append(result)
            if self._lifecycle.final is not None:
                return
        except Exception as error:
            self.evidence["recovery_errors"].append({"action": "read", "error": str(error)})
        if not self._stop_attempted:
            try:
                self._request_stop()
            except Exception as error:
                # A lost launch reply may precede transaction creation. Never
                # retry launch or kill a guessed PID; bounded recovery remains.
                self.evidence["recovery_errors"].append({"action": "stop", "error": str(error)})
        try:
            self._poll_final(deadline, recovering=True)
        except Exception as error:
            self.evidence["recovery_errors"].append({"action": "final-receipt", "error": str(error)})

    def _request_stop(self):
        self._stop_attempted = True
        self.evidence["lifecycle"].append(self._lifecycle.stop())

    def _failed_lifecycle(self, error):
        self.failed = True
        self.evidence["current_menu_observation"] = None
        self.evidence["original_error"] = str(error)
        if self._lifecycle is not None and self._lifecycle.launch_attempted:
            self._recover_attempted(self._lifecycle_deadline)
            self.evidence["final_receipt"] = self._lifecycle.final
            self.evidence["recovery_verified"] = False  # Exit alone is not stock camera functionality.
        error.first_validation_evidence = self.evidence

    def launch_temporary(self, maintenance_session, *, first_entry=None):
        if self.failed or self._placement is None or self._lifecycle is not None:
            raise ValueError("completed ready placement required; lifecycle is single-attempt")
        self._lifecycle_deadline = self._clock() + 150
        try:
            values = sc.decode_session(self.operation.preparation.raw_session)
            now = self._clock()
            if not self._launch.timestamp() + 90 <= now <= values["observed_epoch"] + 600:
                raise ValueError("original USB window not ended or ready observation expired")
            self.evidence["phase"] = "original-usb-preflight"
            boot = usb.preflight(maintenance_session)
            if boot != values["boot_id"] or self._clock() > values["observed_epoch"] + 600:
                raise ValueError("restored connection boot differs or original observation expired")
            if first_entry is not None:
                if type(first_entry) is not FirstValidationSession or first_entry._flow is not self:
                    raise ValueError("specific first entry differs from this temporary lifecycle")
                first_entry._validate()
            self.evidence["original_connection_preflight_passed"] = True
            self._lifecycle = TemporaryLifecycle(self.operation.manifest,
                self.operation.preparation.raw_session, maintenance_session)
            self.evidence["phase"] = "temporary-gui"
            if first_entry is not None:
                # Local evidence reads can outlive the time captured by the
                # full admission. Recheck time at the actual launch boundary.
                first_entry._require_current_time()
            self.evidence["lifecycle"].append(self._lifecycle.launch())
            # Leave the original 120-second window for actual UI observation.
            # Caller explicitly finishes it; running is never a menu PASS.
            return {**deepcopy(self.evidence), "status": "TEMPORARY_GUI_STARTED_AWAITING_REAL_UI_CHECK"}
        except Exception as error:
            self._failed_lifecycle(error)
            raise

    def read_temporary(self):
        if self.failed or self._lifecycle is None:
            raise ValueError("attempted healthy temporary lifecycle required")
        try:
            result = self._lifecycle.read()
            if self._lifecycle.final is not None:
                self.evidence["current_menu_observation"] = None
            self.evidence["lifecycle"].append(result)
            return result
        except Exception as error:
            self._failed_lifecycle(error)
            raise

    def read_temporary_menu(self):
        if self.failed or self._lifecycle is None or self._lifecycle.final is not None:
            raise ValueError("attempted healthy unfinished temporary lifecycle required")
        self.evidence["current_menu_observation"] = None
        try:
            result = self._lifecycle.read_menu()
            self.evidence.setdefault("menu_observations", []).append(result)
            self.evidence["current_menu_observation"] = result
            return result
        except Exception as error:
            self._failed_lifecycle(error)
            raise

    def finish_and_restore(self):
        """Explicitly end the observation, then obtain the true exit receipt.

        Calling this does not attest that any menu/capture checks passed. It
        only makes the fixed stop request required by the original worker.
        """
        if self.failed or self._lifecycle is None or self._stop_attempted:
            raise ValueError("unfinished healthy temporary lifecycle required")
        try:
            if self._lifecycle.final is None:
                # The worker may have completed while the host checked the UI.
                # Read its actual result (including timeout 78) before stop,
                # including one read when the original polling budget ended.
                self.evidence["lifecycle"].append(self._lifecycle.read())
            if self._lifecycle.final is None:
                try:
                    self._request_stop()
                except Exception as stop_error:
                    # The fixed stopper refuses with 33 when a worker exits
                    # between the preceding read and this request. Only an
                    # observed response from that exact stop command plus its
                    # bound successful final receipt resolves that race.
                    from .menu_lifecycle_transport import command as lifecycle_command
                    report = getattr(self._lifecycle.maintenance, "report", {})
                    rows = report.get("commands", []) if type(report) is dict else []
                    row = rows[-1] if type(rows) is list and rows else {}
                    known_stop_refusal = (type(stop_error) is ValueError and
                        str(stop_error) == "camera command returned 33" and type(row) is dict and
                        row.get("label") == "lifecycle-stop" and row.get("exit") == 33 and
                        row.get("command") == lifecycle_command(self.operation.manifest,
                            self.operation.preparation.raw_session, action="stop"))
                    if not known_stop_refusal:
                        raise
                    stop_evidence = {"error": str(stop_error), "resolution": "UNRESOLVED"}
                    self.evidence.setdefault("stop_errors", []).append(stop_evidence)
                    try:
                        self.evidence["lifecycle"].append(self._lifecycle.read())
                    except Exception as read_error:
                        self.evidence["recovery_errors"].append({"action": "stop-race-read", "error": str(read_error)})
                        raise stop_error
                    if self._lifecycle.final is None:
                        raise stop_error
                    stop_evidence["resolution"] = "MATCHING_FINAL_RECEIPT"
            final = self._lifecycle.final or self._poll_final(self._lifecycle_deadline, recovering=False)
            if final["exit_code"] != 0:
                raise ValueError("temporary GUI lifecycle exited " + str(final["exit_code"]))
            self.evidence["phase"] = "ended-not-feature-validated"
            self.evidence["current_menu_observation"] = None
            return {**deepcopy(self.evidence), "status": "TEMPORARY_GUI_EXITED_NOT_FUNCTION_QUALIFIED"}
        except Exception as error:
            self._failed_lifecycle(error)
            raise


def prepare_first_validation(manifest, parent_plan, *, saved_observation, saved_observation_sha256,
                             prerequisites, approval, observation_sources):
    """Create one explicitly approved temporary-validation session; no I/O to camera."""
    return FirstValidationSession(manifest, parent_plan, saved_observation=saved_observation,
        saved_observation_sha256=saved_observation_sha256, prerequisites=prerequisites,
        approval=approval, observation_sources=observation_sources)


class FirstValidationSession:
    """The three fixed windows then temporary GUI, not a generic action broker.

    Human approval is supplied/reviewed externally. It covers this candidate,
    build, boot and operation once; refreshed observations never renew a USB
    timer. There are deliberately no boot-activation or install methods.
    """
    def __init__(self, manifest, parent_plan, *, saved_observation, saved_observation_sha256,
                 prerequisites, approval, observation_sources):
        self.manifest, self.parent_plan = deepcopy(manifest), deepcopy(parent_plan)
        self.approval = deepcopy(approval)
        self.phase, self.failed = "content", False
        self._completed = {}
        self._prepared_at = self._maintenance = self._launch_raw = self._flow = None
        self._starts = []
        self._set_observation(saved_observation, saved_observation_sha256, prerequisites, observation_sources)
        self._validate()
        self._make_stage()

    def _set_observation(self, raw, digest, prerequisites, sources):
        self._observation = raw
        self._observation_sha256 = digest
        self._prerequisites, self._sources = deepcopy(prerequisites), deepcopy(sources)

    def _validate(self):
        if self.failed:
            raise ValueError("first validation failed; no further new actions")
        saved, q, expires = _validate_first_entry(self.manifest, self._observation, self._observation_sha256,
            self._prerequisites, self.approval, self._sources, now=datetime.now(timezone.utc))
        code = content.plan_temporary_preparation(self.parent_plan, self.manifest, saved.raw_session)
        prepared._check_current_install_parent(code)
        self._saved, self._q, self._approval_expires = saved, q, expires

    def _make_stage(self):
        if self.phase == "content":
            session = content.stage.plan_raw_session_staging(self.parent_plan, self.manifest, self._saved.raw_session)
            self._stage = content.ContentStageCoordinator(self.parent_plan, session, clock=self._clock)
        elif self.phase == "code":
            self._code = content.plan_temporary_preparation(self.parent_plan, self.manifest, self._saved.raw_session)
            self._stage = content.SecondWindowPreparationCoordinator(self._code, clock=self._clock)
        else:
            ready = content.plan_temporary_ready(self._code, self._saved.raw_session)
            previous = self._completed["code"]
            self._flow = _FirstValidationFlow(ready, previous_code_result=previous["result"],
                previous_launch_report=previous["report"], clock=self._clock)
            self._stage = self._flow.operation.coordinator

    def _require_current_time(self):
        now = datetime.now(timezone.utc)
        if not datetime.fromisoformat(self.approval["approved_utc"]) <= now < self._approval_expires:
            raise ValueError("first-menu human approval is stale or future")
        observed = datetime.fromisoformat(self._q["observed_utc"])
        if not 0 <= (now - observed).total_seconds() <= 600:
            raise ValueError("complete observation is stale or future")

    @staticmethod
    def _clock():
        return datetime.now(timezone.utc).timestamp()

    def prepare_window(self, maintenance_session):
        """Admit before the first maintenance write; don't open/extend USB."""
        self._validate()
        if self._prepared_at is not None or self.phase in self._completed:
            raise ValueError("this fixed window was already prepared or completed")
        self._maintenance = maintenance_session
        try:
            if usb.preflight(maintenance_session) != self._q["boot_id"]:
                raise ValueError("original maintenance connection boot differs")
            self._validate()  # Reads can expire consent/observation before writing.
            # Preparation contains multiple writes and may outlive its initial
            # admission. Guard each new write without gating later recovery.
            from types import SimpleNamespace
            def guarded_command(label, command):
                self._require_current_time()
                return maintenance_session.command(label, command)
            guarded_preparation = SimpleNamespace(command=guarded_command)
            if self.phase == "ready":
                self._flow.prepare_observer(guarded_preparation)
                self._prepared_at = self._flow.operation._observer_completed_at
            else:
                self._prepared_at = _prepare_content_stage(self._stage, guarded_preparation, clock=self._clock)
        except Exception:
            self.failed = True
            raise

    def next_window(self, *, saved_observation, saved_observation_sha256, prerequisites, observation_sources):
        """Use an actually completed predecessor and a later complete observation."""
        if self.failed or self.phase not in self._completed or self.phase == "ready":
            raise ValueError("completed content/code predecessor required")
        previous = self._completed[self.phase]
        old = sc.decode_session(self._saved.raw_session)
        self._set_observation(saved_observation, saved_observation_sha256, prerequisites, observation_sources)
        try:
            self._validate()
            new = sc.decode_session(self._saved.raw_session)
            if (new["session_nonce"] == old["session_nonce"] or
                new["observed_epoch"] < previous["launch"].timestamp() + 90 or
                any(new[key] != old[key] for key in ("boot_id", "mount_namespace", "init_mount_namespace"))):
                raise ValueError("next window needs new nonce/observation after original restoration")
            self.phase = "code" if self.phase == "content" else "ready"
            self._prepared_at = self._maintenance = self._launch_raw = None
            self._starts = []
            self._make_stage()
        except Exception:
            self.failed = True
            raise

    def _bind_window(self, raw):
        if type(raw) is not bytes or not 0 < len(raw) <= 1024 * 1024:
            raise ValueError("exact bounded saved launch bytes required")
        report = strict_json(raw)
        launch = prepared._recorded_launch(report)
        if (report.get("status") != "LAUNCH_REQUESTED_AWAITING_REAL_USB_EVIDENCE" or
            "error" in report or report.get("bootId") != self._q["boot_id"] or
            self._prepared_at is None or launch.timestamp() < self._prepared_at):
            raise ValueError("successful original launch after preparation required")
        if self.phase != "content":
            # Reuse the exact prior-restoration/preflight checks, including its
            # commands, original timestamps and fresh remote worker identity.
            from types import SimpleNamespace
            previous = self._completed["content" if self.phase == "code" else "code"]
            binding = SimpleNamespace(preparation=self._code if self.phase == "code" else self._flow.operation.preparation,
                _previous_launch=previous["launch"], _previous_launch_report=previous["report"])
            prepared.PreparedMenuPlacementOperation._bind_launch(binding, report, launch)
        return report, launch

    def _native_source(self, phase, supplied_source):
        """Only the fixed host calls this immediately before its child boundary."""
        self._validate()
        report, launch = self._bind_window(self._launch_raw)
        sequence = ("stable-content",) if self.phase == "content" else (
            ("preparation", "menu-preplacement") if self.phase == "ready" else ("preparation",))
        if len(self._starts) >= len(sequence) or phase != sequence[len(self._starts)]:
            raise ValueError("first-validation native phase repeated or out of order")
        stage = self._stage
        if phase == "menu-preplacement":
            expected = self._flow.operation._worker_source(launch)
            prefix, entry, flag = "X2d2MenuPreplace_", "RunFourFiles", "SupervisionQualified"
            deadline_name = "OriginalWindowDeadline"
        else:
            expected = (content.review_content_host_source(stage._plan, stage._session, launch)
                if self.phase == "content" else content.review_preparation_host_source(stage.preparation, launch))
            prefix, entry, flag = "X2d2ContentStage_", "RunContentStage", "ContentQualified"
            deadline_name = "ContentDeadlineEpoch"
        if type(supplied_source) is not str or supplied_source != expected:
            raise ValueError("first-validation child differs from exact current renderer")
        original = int(content.original_window_deadline(stage._session.observed_epoch, launch))
        deadline = datetime.fromtimestamp(min(original, int(self._approval_expires.timestamp())), timezone.utc)
        from .menu_maintenance_boundary import STAGES
        from .temporary_menu_files import FILE_LAYOUT
        remaining = len(FILE_LAYOUT) * len(STAGES) if self.phase == "ready" else 0
        if phase != "menu-preplacement":
            remaining += len(content.stage.execution_steps(stage._plan, dict(stage._session.context), session=stage._session))
        # Includes remaining preparation + all 28 later file observations before
        # starting ready's first child. Uses pinned N-1 cadence and integer time.
        content.stage._require_maintenance_budget(deadline, now=datetime.now(timezone.utc), remaining_commands=remaining)
        source = content.usb.replace_once(expected, f"private const long {deadline_name} = {original};",
            f"private const long {deadline_name} = {int(deadline.timestamp())};")
        source = content.usb.replace_once(source, f"private static readonly bool {flag} = false;",
            f"private static readonly bool {flag} = true;")
        self._starts.append(phase)  # Lost spawn is never retried.
        return source, prefix, entry, f"private static readonly bool {flag} = true;"

    def run_window(self, saved_launch_report, maintenance_session):
        self._validate()
        if maintenance_session is not self._maintenance or self._prepared_at is None or self.phase in self._completed:
            raise ValueError("same prepared maintenance session and unfinished window required")
        try:
            report, launch = self._bind_window(saved_launch_report)
            self._launch_raw = saved_launch_report
            from .menu_host_process import FirstValidationHost
            host = FirstValidationHost(self)
            if self.phase == "ready":
                result = self._flow.place(report, maintenance_session, start_process=host.start)
            else:
                result = _run_content_stage(self._stage, report, maintenance_session,
                    observer_completed_at=self._prepared_at, start_process=host.start)
            self._completed[self.phase] = {"result": deepcopy(result), "report": deepcopy(report), "launch": launch,
                "launch_report_sha256": peer.sha(saved_launch_report), "observation_sha256": self._observation_sha256,
                "observation_sources": deepcopy(self._sources)}
            return deepcopy(result)
        except Exception:
            self.failed = True
            raise

    def launch_temporary(self, maintenance_session):
        self._validate()
        if self.phase != "ready" or "ready" not in self._completed or maintenance_session is not self._maintenance:
            raise ValueError("completed ready placement on same maintenance route required")
        return self._flow.launch_temporary(maintenance_session, first_entry=self)

    def read_temporary(self):
        # Do not make recovery conditional on later approval expiry/build drift.
        if self._flow is None:
            raise ValueError("no attempted temporary GUI")
        return self._flow.read_temporary()

    def read_temporary_menu(self):
        if self._flow is None:
            raise ValueError("no attempted temporary GUI")
        return self._flow.read_temporary_menu()

    def boot_validation_record(self):
        """Export already received placement/lifecycle bytes, never boot consent.

        This read-only export needs no still-current temporary launch approval.
        The separately reviewed real UI/capture/persistence results and the
        distinct human first-boot approval remain external admission inputs.
        """
        flow = self._flow
        if (self.phase != "ready" or "ready" not in self._completed or flow is None or
                flow.failed or flow._lifecycle is None or flow._lifecycle.final is None or
                flow._lifecycle.final["exit_code"] != 0 or
                flow.evidence.get("phase") != "ended-not-feature-validated"):
            raise ValueError("completed successful temporary lifecycle and ready placement required")
        import base64
        def saved(value):
            if type(value) is bytes:
                return {"encoding": "base64", "data": base64.b64encode(value).decode("ascii"), "sha256": peer.sha(value)}
            if isinstance(value, datetime):
                return value.isoformat()
            if type(value) is dict:
                return {key: saved(item) for key, item in value.items()}
            if type(value) in (tuple, list):
                return [saved(item) for item in value]
            return value
        ready = self._completed["ready"]
        raw = flow.operation.preparation.raw_session
        return {"schema": "x2dii-boot-validation-placement-v1", "candidate_sha256": self.manifest["candidate_sha256"],
            "session_data_sha256": peer.sha(raw), "placement_session_ascii": raw.decode("ascii"),
            "completed_identities": list(ready["result"]["worker_result"]["completed_identities"]),
            "placement_result": saved(ready["result"]), "ready_launch_report": saved(ready["report"]),
            "ready_launch_report_utf8": self._launch_raw.decode("utf-8"),
            "ready_launch_report_sha256": ready["launch_report_sha256"],
            "placement_observation_sha256": ready["observation_sha256"],
            "placement_observation_sources": saved(ready["observation_sources"]),
            "temporary_final_receipt": saved(flow._lifecycle.final),
            "temporary_lifecycle_evidence": saved(flow.evidence), "temporary_feature_validated": False}

    def finish_and_restore(self):
        if self._flow is None:
            raise ValueError("no attempted temporary GUI")
        return self._flow.finish_and_restore()
