"""Connect fixed ready/boot preparations to existing workers without a new lease.

Not a publisher, device finder or authorization path. Generated native sources
retain their closed qualification guards. Only the existing maintenance route
and an external process-start boundary are accepted; no shell command parameter
or automatic USB window/reboot/retry is added.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone, timedelta
import io
import json
from pathlib import Path
import re
import tarfile
import time

from . import menu_content_transport as content, menu_boot_transport as boot
from . import menu_preplacement_transport as placement, menu_cleanup_transport as cleanup
from . import session_context
from .stage_peer_usb_access import recorded_launch_start
from . import stage_peer_usb_access as usb_stage


def _recorded_launch(report):
    """Bind saved decoder attribution, not authenticity or present device state."""
    launch = recorded_launch_start(report)
    if (report.get("stagerSha256") != content._sha(Path(usb_stage.__file__).read_bytes()) or
        report.get("replySources") != usb_stage.live.source_hashes()):
        raise ValueError("saved launch source attribution missing or changed")
    return launch


def _check_current_install_parent(preparation):
    """Reproduce install content, not just a caller-supplied plan digest.

    Only new file placement uses current candidate inputs. Boot restoration and
    owned cleanup deliberately do not depend on mutable local payload sources.
    The bounded archive is generated here in memory, never extracted to disk.
    """
    from . import delivery_files, prepare_peer_install as peer
    manifest = json.loads(preparation.manifest_bytes)
    programs = peer.render_role_programs(manifest)
    assembled = delivery_files.assemble_role_delivery(manifest["candidate"], manifest["candidate_sha256"], programs)
    with tarfile.open(fileobj=io.BytesIO(assembled["archive_bytes"]), mode="r:") as archive:
        members = {item.name: archive.extractfile(item).read() for item in archive.getmembers()
                   if item.name != "members.json"}
    renderer = Path(peer.__file__).read_bytes()
    expected = content.stage.plan_compressed_role_staging(members=members, candidate=manifest["candidate"],
        candidate_sha256=manifest["candidate_sha256"],
        script_hashes={name: content._sha(source.encode("ascii")) for name, source in programs.items()},
        renderer_source=renderer, renderer_source_sha256=content._sha(renderer),
        delivery_identity=assembled["delivery_identity"])
    if preparation.parent_plan != expected:
        raise ValueError("stable content parent differs from current complete fixed plan")


class _PreparedOperation:
    """Shared pipe lifecycle for fixed operations below, not an executor."""

    def _initialize(self, preparation, clock):
        self.preparation = deepcopy(preparation)
        self.manifest = json.loads(preparation.manifest_bytes)
        self.coordinator = content.SecondWindowPreparationCoordinator(self.preparation, clock=clock)
        self._clock = clock
        self._observer_prepared = False
        self._observer_attempted = False
        self._observer_completed_at = None
        self._run_attempted = False
        self.failed = False

    def prepare_observer(self, maintenance_session):
        """Use the existing fixed pre-window table preparation, once only."""
        if self.failed or self._observer_attempted or self._run_attempted:
            raise ValueError("observer preparation already attempted or failed")
        self._observer_attempted = True
        try:
            while (operation := self.coordinator.next_preparation) is not None:
                output = maintenance_session.command("prepare-observer-" + str(operation.index), operation.command)
                self.coordinator.accept_preparation(exit_code=0, stdout=output, completion_validated=True)
            self._observer_completed_at = self._clock()
            self._observer_prepared = True
        except Exception:
            self.failed = True
            raise

    def _bind_launch(self, report, launch):
        """Only ready operations need evidence of a preceding code window."""

    def run_qualified(self, saved_launch_report, maintenance_session, start_process, *, qualification,
                      window_authorization, saved_manifest=None, saved_manifest_sha256=None):
        """Existing final/recovery admission around this object's fixed run path.

        No arbitrary source or permission switch is accepted. Temporary first
        menu validation cannot use this method. Each child is still produced by
        run(); only its exact generated source receives a qualified guard after
        rechecking all original evidence, scope, raw context and launch bytes.
        """
        from . import prepare_peer_install as install, prepare_peer_recovery as recovery
        from .regression_manifest import strict_json
        from . import peer_usb_access as usb
        formal = type(self) is PreparedFormalPlacementOperation or (
            type(self) is PreparedBootOperation and self.action == "activate")
        recovering = type(self) is PreparedCleanupOperation or (
            type(self) is PreparedBootOperation and self.action == "restore")
        if not (formal or recovering):
            raise ValueError("only formal install or independent recovery can use qualified execution; not temporary validation")
        q, window = deepcopy(qualification), deepcopy(window_authorization)
        report = launch = deadline = None
        starts = []

        def validate_budget():
            # Count the exact fixed worker branch, not a caller's claimed budget.
            # The first child's reservation includes the worker it must leave
            # room for. Once preparation has completed, do not count it again.
            if type(self) is PreparedFormalPlacementOperation:
                from .menu_maintenance_boundary import STAGES
                from .temporary_menu_files import FILE_LAYOUT
                remaining = len(FILE_LAYOUT) * len(STAGES)
            elif type(self) is PreparedBootOperation:
                worker = boot.BootCoordinator(self.manifest, self.preparation.raw_session, **self.options)
                remaining = len(worker.sequence) - worker.first_boundary
            else:
                remaining = len(cleanup.cleanup.FILE_LAYOUT) * len(cleanup.cleanup.STAGES)
            if not starts:
                remaining += len(content.stage.execution_steps(self.preparation.plan,
                    dict(self.preparation.session.context), session=self.preparation.session))
            content.stage._require_maintenance_budget(deadline, now=datetime.now(timezone.utc),
                remaining_commands=remaining)

        def validate():
            nonlocal deadline
            content._validate_preparation(self.preparation)
            if json.loads(self.preparation.manifest_bytes) != self.manifest:
                raise ValueError("prepared candidate changed after construction")
            if formal:
                if saved_manifest is not None or saved_manifest_sha256 is not None:
                    raise ValueError("formal installation does not consume a recovery authorization")
                install.validate_qualification(self.manifest, q, for_publication=True)
                expected_raw = install.session_data(self.manifest, q)
            else:
                if saved_manifest is None or saved_manifest_sha256 is None:
                    raise ValueError("independent recovery requires the existing saved manifest and its hash")
                recovery.validate_qualification(saved_manifest, saved_manifest_sha256, q, for_publication=True)
                saved = recovery.load_saved_candidate(saved_manifest, saved_manifest_sha256)
                if not recovery.role_delivery(saved) or saved != self.manifest:
                    raise ValueError("prepared recovery does not match the saved role delivery")
                expected_raw = recovery.session_data(saved, q)
                backup = (self.options[2]["backup_identity"] if type(self) is PreparedCleanupOperation
                          else self.options["backup_identity"])
                if q.get("backup_identity") != backup:
                    raise ValueError("prepared recovery backup identity differs from qualification")
            if expected_raw != self.preparation.raw_session:
                raise ValueError("qualified raw session differs from fixed preparation")
            if report is not None:
                if (_recorded_launch(report) != launch or report.get("bootId") != q["boot_id"] or
                    window.get("launch_started_utc") != launch.isoformat()):
                    raise ValueError("qualified preparation and original launch boot/time differ")
                deadline = content.stage.validate_staging_window(window, self.preparation.plan, q,
                    now=datetime.now(timezone.utc), session=self.preparation.session)
                validate_budget()

        try:
            validate()  # Complete original admission before decoding a launch or exposing any source.
            if (type(saved_launch_report) is not bytes or not 0 < len(saved_launch_report) <= 1024 * 1024 or
                type(window) is not dict or window.get("launch_session_sha256") != content._sha(saved_launch_report)):
                raise ValueError("exact qualified launch report bytes and original hash required")
            report = strict_json(saved_launch_report)
            if (type(report) is not dict or report.get("status") != "LAUNCH_REQUESTED_AWAITING_REAL_USB_EVIDENCE"
                or "error" in report):
                raise ValueError("successful original launch report required")
            launch = _recorded_launch(report)
            # Bind the initial window without repeating expensive full gates;
            # they are rechecked again immediately before EACH child boundary.
            if report.get("bootId") != q["boot_id"] or window.get("launch_started_utc") != launch.isoformat():
                raise ValueError("qualified preparation and original launch boot/time differ")
            deadline = content.stage.validate_staging_window(window, self.preparation.plan, q,
                now=datetime.now(timezone.utc), session=self.preparation.session)
            validate_budget()

            def qualified_start(phase, source):
                sequence = ("preparation", self._worker_phase)
                if len(starts) >= len(sequence) or phase != sequence[len(starts)]:
                    raise ValueError("qualified child phase differs or was repeated")
                validate()
                first = phase == "preparation"
                expected = (content.review_preparation_host_source(self.preparation, launch) if first
                            else self._worker_source(launch))
                if type(source) is not str or source != expected:
                    raise ValueError("qualified child is not this operation's fixed generated source")
                original_deadline = int(content.original_window_deadline(self.preparation.session.observed_epoch, launch))
                deadline_epoch = min(original_deadline, int(deadline.timestamp()))
                if datetime.now(timezone.utc) + timedelta(seconds=2) >= deadline:
                    raise ValueError("qualified child original window expired")
                validate_budget()
                flag = "ContentQualified" if first else "SupervisionQualified"
                deadline_name = "ContentDeadlineEpoch" if first else "OriginalWindowDeadline"
                admitted = usb.replace_once(source,
                    f"private const long {deadline_name} = {original_deadline};",
                    f"private const long {deadline_name} = {deadline_epoch};")
                admitted = usb.replace_once(admitted, f"private static readonly bool {flag} = false;",
                    f"private static readonly bool {flag} = true;")
                starts.append(phase)
                return start_process(phase, admitted)

            result = self.run(report, maintenance_session, qualified_start)
            return {**result, "qualification_route": "final_installation" if formal else "independent_recovery",
                    "qualification_sha256": content._sha(json.dumps(q, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()),
                    "launch_report_sha256": content._sha(saved_launch_report)}
        except Exception:
            self.failed = True
            raise

    @staticmethod
    def _close_child(process):
        errors = []
        if process is None:
            return errors
        for name, operation in (
                ("terminate-host-child", lambda: process.terminate() if process.poll() is None else None),
                ("wait-host-child", lambda: process.wait(timeout=5)),
                *(("close-host-" + name, lambda name=name: getattr(process, name).close())
                  for name in ("stdin", "stdout", "stderr"))):
            try:
                operation()
            except Exception as error:
                errors.append({"step": name, "error": str(error)})
        return errors

    def run(self, saved_launch_report, maintenance_session, start_process):
        """Start only generated fixed sources, with the original recorded window.

        `start_process(phase, source)` is the process boundary, not an approval
        callback. Sources still refuse native access until the complete delivery
        is separately qualified. Their local tests disable native imports first.
        """
        if self.failed or self._run_attempted or not self._observer_prepared:
            raise ValueError("operation already attempted, failed, or observer not prepared")
        self._run_attempted = True
        evidence = {"phase": "launch-binding", "candidate_sha256": self.manifest["candidate_sha256"],
            "session_data_sha256": self.preparation.session.data_sha256,
            "preparation_plan_sha256": self.preparation.plan.plan_sha256,
            "launch_started_utc": None, "preparation_result": None, "worker_result": None,
            "installable": False, "usb_restore_verified": False}
        process = None
        active_error = None
        try:
            launch = _recorded_launch(saved_launch_report)
            if saved_launch_report.get("status") != "LAUNCH_REQUESTED_AWAITING_REAL_USB_EVIDENCE" or "error" in saved_launch_report:
                raise ValueError("failed or uncertain USB launch cannot start a prepared operation")
            values = session_context.decode_session(self.preparation.raw_session)
            if saved_launch_report.get("bootId") != values["boot_id"]:
                raise ValueError("USB launch and fixed preparation boot differ")
            if launch.timestamp() < self._observer_completed_at:
                raise ValueError("observer preparation finished after the original USB launch")
            self._bind_launch(saved_launch_report, launch)
            evidence["launch_started_utc"] = launch.isoformat()
            self.coordinator.start_window(launch)
            # Render both now with precisely the same raw data and launch. The
            # second child's startup must not grant it another 90-second window.
            preparation_source = content.review_preparation_host_source(self.preparation, launch)
            worker_source = self._worker_source(launch)
            evidence["phase"] = "preparation"
            self.coordinator.remaining_window_seconds()
            process = start_process("preparation", preparation_source)
            evidence["preparation_result"] = content.drive_preparation_process(process, self.coordinator, maintenance_session)
            cleanup = self._close_child(process)
            process = None
            if cleanup:
                evidence["cleanup_errors"] = cleanup
                raise ValueError("preparation host cleanup failed; worker not started")
            evidence["phase"] = "before-worker"
            self.coordinator.remaining_window_seconds()
            process = start_process(self._worker_phase, worker_source)
            evidence["phase"] = self._worker_phase
            evidence["worker_result"] = self._drive_worker(process, maintenance_session)
            return {**evidence, "status": self._result_status}
        except Exception as error:
            self.failed = True
            active_error = error
            # Preserve any worker's original partial evidence; add this phase's
            # context separately rather than replace its first failure.
            error.prepared_operation_evidence = evidence
            raise
        finally:
            cleanup = self._close_child(process)
            if cleanup:
                self.failed = True
                evidence.setdefault("cleanup_errors", []).extend(cleanup)
                if active_error is None:
                    error = ValueError("prepared operation host cleanup failed")
                    error.prepared_operation_evidence = evidence
                    raise error


class PreparedBootOperation(_PreparedOperation):
    """One preparation plus one activate/restore transaction, never lifecycle PASS."""
    _result_status = "PREPARED_BOOT_FILE_TRANSACTION_NOT_LIFECYCLE_VALIDATED"

    def __init__(self, preparation, *, backup_identity=None, clock=time.time):
        content._validate_preparation(preparation)
        purposes = {"boot_activation_preparation": "activate", "boot_recovery_preparation": "restore"}
        if preparation.purpose not in purposes:
            raise ValueError("only a fixed boot preparation can enter this operation")
        self.action = purposes[preparation.purpose]
        self._worker_phase = "boot-" + self.action
        self.options = dict(action=self.action, payload_identities=preparation.payload_identities,
                            backup_identity=backup_identity)
        # Reject invalid/mixed ownership inputs before any preparation write.
        boot.BootCoordinator(json.loads(preparation.manifest_bytes), preparation.raw_session, **self.options)
        self._initialize(preparation, clock)

    def _worker_source(self, launch):
        return boot.review_boot_host_source(self.manifest, self.preparation.raw_session,
            launch_started_utc=launch, **self.options)

    def _drive_worker(self, process, maintenance_session):
        return boot.drive_boot_process(process, self.manifest, self.preparation.raw_session,
            maintenance_session, clock=self._clock, **self.options)


class PreparedMenuPlacementOperation(_PreparedOperation):
    """Only a later ready window may place files; it never starts the GUI."""
    _worker_phase = "menu-preplacement"
    _result_status = "PREPARED_MENU_FILES_NOT_LOADED_NOT_FEATURE_VALIDATED"

    def __init__(self, preparation, *, previous_code_result=None, previous_launch_report=None, clock=time.time):
        content._validate_preparation(preparation)
        if preparation.purpose != "temporary_menu_ready":
            raise ValueError("menu placement requires a later fresh ready window, not code preparation")
        _check_current_install_parent(preparation)
        self._previous_launch = self._bind_completed_code(preparation, previous_code_result, previous_launch_report)
        self._previous_launch_report = deepcopy(previous_launch_report)
        placement.PreplacementCoordinator(json.loads(preparation.manifest_bytes), preparation.raw_session)
        self._initialize(preparation, clock)

    @staticmethod
    def _bind_completed_code(preparation, result, report):
        code = preparation.code_preparation
        if (type(result) is not dict or result.get("status") != content._preparation_scope(code) or
            result.get("purpose") != code.purpose or result.get("worker_followup_allowed") is not False or
            result.get("installable") is not False or
            result.get("preparation_plan_sha256") != code.plan.plan_sha256 or
            result.get("session_data_sha256") != code.session.data_sha256):
            raise ValueError("completed original code preparation evidence required")
        steps = content.stage.execution_steps(code.plan, dict(code.session.context), session=code.session)
        retained = result.get("retained_adb_payloads")
        if type(retained) not in (list, tuple) or len(retained) != len(steps):
            raise ValueError("complete original code payload records required")
        for index, (item, step) in enumerate(zip(retained, steps)):
            expected = (step.expected_stdout + f"\nX2DII_CONTENT_{code.session.binding_sha256[:24]}_{index}_RC=0\n").encode("ascii")
            if (type(item) is not dict or item.get("index") != index or type(item.get("raw")) is not bytes or
                item.get("sha256") != content._sha(item["raw"]) or item["raw"].replace(b"\r\n", b"\n") != expected):
                raise ValueError("original code payload identity or completion differs")
        previous = _recorded_launch(report)
        if result.get("launch_started_utc") != previous.isoformat():
            raise ValueError("completed code result and original launch differ")
        prior_context = session_context.decode_session(code.raw_session)
        if (report.get("status") != "LAUNCH_REQUESTED_AWAITING_REAL_USB_EVIDENCE" or "error" in report or
            report.get("bootId") != prior_context["boot_id"]):
            raise ValueError("successful original code launch on the same boot required")
        content.original_window_deadline(prior_context["observed_epoch"], previous)
        return previous

    def _bind_launch(self, report, launch):
        """Reuse the saved launch CLI's actual preflight, not a new collector.

        Stage and launch legitimately have duplicate preflight labels. Only
        the complete fixed sequence immediately before this unique launch is
        used; an older matching label cannot stand in for a new observation.
        Properties plus accepted maintenance replies are not proof that every
        physical USB interface has recovered or that menu functions work.
        """
        lower = self._previous_launch.timestamp() + 90
        if (report["remote"] == self._previous_launch_report["remote"] or
            self.preparation.session.observed_epoch < lower):
            raise ValueError("ready must follow the original code window with a new observed launch")
        history = report["commands"]
        index = next(i for i, item in enumerate(history) if item.get("label") == "launch")
        selected = history[max(0, index - 7):index + 1]
        labels = ("transport-hash", "boot-id", "usb-state", "uid", "lock-absent", "recheck-script", "check-syntax", "launch")
        if tuple(item.get("label") for item in selected) != labels:
            raise ValueError("ready requires the complete immediately preceding launch preflight")
        root = report["remote"]
        exact = {
            "boot-id": ("cat /proc/sys/kernel/random/boot_id", report["bootId"] + "\n"),
            "usb-state": ("getprop sys.usb.config;getprop sys.usb.state;getprop init.svc.adbd",
                          usb_stage.BASE + "\n" + usb_stage.BASE + "\nstopped\n"),
            "uid": ("id -u", "0\n"),
            "lock-absent": ("[ ! -e /tmp/x2dii-peer-adb.lock ] && [ ! -L /tmp/x2dii-peer-adb.lock ]", ""),
            "recheck-script": (f"sha256sum {root}/s", usb_stage.SCRIPT_SHA + "  " + root + "/s\n"),
            "check-syntax": (f"sh -n {root}/s", ""),
        }
        last = lower
        for row in selected:
            if type(row.get("exit")) is not int or row["exit"] != 0 or "error" in row or type(row.get("utc")) is not str:
                raise ValueError("failed or incomplete ready launch preflight")
            try:
                observed = datetime.fromisoformat(row["utc"])
            except ValueError as error:
                raise ValueError("invalid ready preflight time") from error
            if observed.tzinfo is None or not last <= observed.timestamp() <= launch.timestamp():
                raise ValueError("ready preflight did not follow the previous window in order")
            last = observed.timestamp()
            if row["label"] in exact and (row.get("command"), row.get("text")) != exact[row["label"]]:
                raise ValueError("ready launch preflight command or result differs: " + row["label"])
        transport_row = selected[0]
        text = transport_row.get("text")
        if transport_row.get("command") != usb_stage.live.QUERIES["transport_hash"] or type(text) is not str:
            raise ValueError("ready transport producer query differs")
        lines = text.splitlines()
        if len(lines) != len(usb_stage.TRANSPORT_PRODUCERS):
            raise ValueError("ready transport producer result is incomplete")
        pids = []
        for line, (_, digest) in zip(lines, usb_stage.TRANSPORT_PRODUCERS):
            match = re.fullmatch(digest + r"  /proc/([1-9][0-9]*)/exe", line)
            if match is None:
                raise ValueError("ready transport producer identity differs")
            pids.append(match[1])
        if len(set(pids)) != len(pids):
            raise ValueError("ready transport producer identities alias")

    def _worker_source(self, launch):
        return placement.review_host_source(self.manifest, self.preparation.raw_session,
            launch_started_utc=launch)

    def _drive_worker(self, process, maintenance_session):
        return placement.drive_preplacement_process(process, self.manifest, self.preparation.raw_session,
            maintenance_session, clock=self._clock)


class PreparedFormalPlacementOperation(PreparedMenuPlacementOperation):
    """Later install/v2 placement, using the same bounded four-file worker path.

    The first content window and this fresh context must be independently
    recorded. This reuses the ready path's later-window checks and pipe lifecycle;
    neither successful content staging nor file placement is menu qualification.
    """

    def __init__(self, preparation, *, previous_content_result=None, previous_content_session=None,
                 previous_launch_report=None, clock=time.time):
        content._validate_preparation(preparation)
        if preparation.purpose != "install_preparation":
            raise ValueError("formal placement requires a fixed install preparation")
        _check_current_install_parent(preparation)
        manifest = json.loads(preparation.manifest_bytes)
        session = previous_content_session
        if (type(session) is not content.stage.SessionStaging or
            content.stage.plan_raw_session_staging(preparation.parent_plan, manifest, session.data) != session):
            raise ValueError("original content session binding required")
        old = session_context.decode_session(session.data)
        current = session_context.decode_session(preparation.raw_session)
        if (old["kind"] != "install" or session.context != preparation.session.context or
            old["session_nonce"] == current["session_nonce"] or
            old["observed_epoch"] >= current["observed_epoch"]):
            raise ValueError("formal placement requires a fresh session on the same boot and namespace")
        result = previous_content_result
        if (type(result) is not dict or result.get("status") != content.ContentStageCoordinator.final_scope or
            result.get("installable") is not False or result.get("candidate_sha256") != manifest["candidate_sha256"] or
            result.get("plan_sha256") != preparation.parent_plan.plan_sha256 or
            result.get("session_data_sha256") != session.data_sha256 or
            result.get("session_binding_sha256") != session.binding_sha256):
            raise ValueError("completed original stable content evidence required")
        steps = content.stage.execution_steps(preparation.parent_plan, dict(session.context), session=session)
        retained = result.get("retained_adb_payloads")
        if type(retained) not in (list, tuple) or len(retained) != len(steps):
            raise ValueError("complete original stable content payload records required")
        for index, (item, step) in enumerate(zip(retained, steps)):
            expected = (step.expected_stdout + f"\nX2DII_CONTENT_{session.binding_sha256[:24]}_{index}_RC=0\n").encode("ascii")
            if (type(item) is not dict or item.get("index") != index or type(item.get("raw")) is not bytes or
                item.get("sha256") != content._sha(item["raw"]) or item["raw"].replace(b"\r\n", b"\n") != expected):
                raise ValueError("original stable content payload identity or completion differs")
        previous = _recorded_launch(previous_launch_report)
        if (result.get("launch_started_utc") != previous.isoformat() or
            previous_launch_report.get("status") != "LAUNCH_REQUESTED_AWAITING_REAL_USB_EVIDENCE" or
            "error" in previous_launch_report or previous_launch_report.get("bootId") != old["boot_id"]):
            raise ValueError("completed stable content result and original launch differ")
        content.original_window_deadline(old["observed_epoch"], previous)
        self._previous_launch = previous
        self._previous_launch_report = deepcopy(previous_launch_report)
        placement.PreplacementCoordinator(manifest, preparation.raw_session)
        self._initialize(preparation, clock)


class PreparedCleanupOperation(_PreparedOperation):
    """Stage only the fixed cleanup programs, then remove four exact-owned files.

    Requires the saved original identities, restore receipt and fresh stock-GUI
    observation already bound by the cleanup preparation producer. This does
    not restore boot configuration, reboot, or infer camera functionality.
    """
    _worker_phase = "owned-cleanup"
    _result_status = "PREPARED_FOUR_OWNED_FILES_REMOVED_NOT_FUNCTION_VALIDATED"

    def __init__(self, preparation, *, clock=time.time):
        content._validate_preparation(preparation)
        if preparation.purpose != "owned_cleanup_preparation":
            raise ValueError("only a fixed cleanup preparation can enter this operation")
        saved = json.loads(preparation.cleanup_evidence)
        self.options = (preparation.payload_identities, saved["stock_readback"], saved["restore_receipt"])
        cleanup.cleanup.CleanupCoordinator(json.loads(preparation.manifest_bytes), preparation.raw_session, *self.options)
        self._initialize(preparation, clock)

    def _worker_source(self, launch):
        return cleanup.review_cleanup_host_source(self.manifest, self.preparation.raw_session,
            *self.options, launch_started_utc=launch)

    def _drive_worker(self, process, maintenance_session):
        return cleanup.drive_cleanup_process(process, self.manifest, self.preparation.raw_session,
            *self.options, maintenance_session, clock=self._clock)
