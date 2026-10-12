"""Fixed first-window v2 content sender adaptation; no admitted native entry.

Observer preparation finishes before launching the unchanged original USB
worker. Its device-local 90-second restore timer is neither extended nor killed.
The content-only window cannot launch menu workers or upload their session file.
Successful staging is not installation, runtime qualification or reconnection.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import math
import queue
import re
import threading
import time

from . import stage_menu_delivery as stage
from . import peer_usb_access as usb
from . import session_context


RESTORE_RESERVE_SECONDS = 10


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class SecondWindowPreparation:
    """New execution identity; never mutate or relabel the stable parent plan."""
    purpose: str
    parent_plan: stage.StagingPlan
    manifest_bytes: bytes
    raw_session: bytes
    payload_identities: tuple[str, ...] | None
    plan: stage.StagingPlan
    session: stage.SessionStaging
    code_preparation: SecondWindowPreparation | None = None
    cleanup_evidence: bytes | None = None
    installable: bool = field(default=False, init=False)


def _program_readbacks(plan, session, files):
    """Read-only checks of specific producer-selected sources, grouped by parent."""
    steps = []
    for index, root in enumerate(dict.fromkeys(path.rsplit("/", 1)[0] for path, _ in files)):
        subset = tuple((path, data) for path, data in files if path.rsplit("/", 1)[0] == root)
        paths = " ".join(path for path, _ in subset)
        guard = stage._directory(root)
        if root.startswith("/tmp/"):
            guard = "[ -d /tmp ] && [ ! -L /tmp ] && " + guard
        body = guard + " && for x2dii_file in " + paths + "; do " + stage._regular('"$x2dii_file"') + (
            " || exit 31; done && sha256sum " + paths + " && stat -c %s " + paths)
        expected = "".join(f"{_sha(data)}  {path}\n" for path, data in subset)
        expected += "".join(f"{len(data)}\n" for _, data in subset)
        steps.append(stage._preparation_step(plan, session, f"verify-existing-source-group-{index}", body, expected))
    return tuple(steps)


def _second_preparation(parent_plan, manifest, raw_session, purpose, payload_identities, code_preparation=None, cleanup_evidence=None):
    # Both inputs are regenerated through the specific reviewed producers, not
    # accepted as caller-supplied commands or an altered parent's step list.
    if type(parent_plan) is not stage.StagingPlan or parent_plan.phase != "stable-content":
        raise ValueError("second-window preparation requires original stable parent")
    original = stage.plan_raw_session_staging(parent_plan, manifest, raw_session)
    values = session_context.decode_session(raw_session)
    if purpose != "owned_cleanup_preparation" and cleanup_evidence is not None:
        raise ValueError("cleanup evidence belongs only to fixed cleanup preparation")
    auxiliary = None
    support = None
    readback = ()
    if purpose == "temporary_menu_preparation" and values["kind"] == "menu_validation" and payload_identities is None:
        if code_preparation is not None:
            raise ValueError("code preparation cannot replace a previous source set")
        auxiliary = stage.plan_menu_validation_worker_staging(parent_plan, manifest, raw_session)
        support = stage.plan_menu_support_staging(parent_plan, manifest, raw_session)
    elif purpose == "temporary_menu_ready" and values["kind"] == "menu_validation" and payload_identities is None:
        _validate_preparation(code_preparation)
        if code_preparation.purpose != "temporary_menu_preparation" or code_preparation.parent_plan != parent_plan:
            raise ValueError("ready window requires its exact prior code preparation")
        prior = session_context.decode_session(code_preparation.raw_session)
        if (values["session_nonce"] == prior["session_nonce"] or values["observed_epoch"] < prior["observed_epoch"] or
            any(values[key] != prior[key] for key in ("boot_id", "mount_namespace", "init_mount_namespace"))):
            raise ValueError("fresh ready context must have a new nonce/current observation and same boot/namespace")
        from . import temporary_menu_files as workers
        files = tuple((workers.worker_path(manifest, i, session_kind="menu_validation"),
            workers.render_supervised_preplacement(manifest, file_index=i, session_kind="menu_validation").encode("ascii"))
            for i in range(4)) + stage.menu_support_files(manifest)
        readback = _program_readbacks(parent_plan, original, files)
    elif purpose == "install_preparation" and values["kind"] == "install" and payload_identities is None:
        if code_preparation is not None:
            raise ValueError("formal install preparation does not reuse temporary menu code")
        from . import prepare_peer_install as peer
        support = stage.plan_install_observer_staging(parent_plan, manifest, raw_session)
        programs = peer.render_role_programs(manifest)
        files = tuple((parent_plan.stage_root + f"/preplace-{index}.sh",
                       programs[f"preplace-{index}.sh"].encode("ascii")) for index in range(4))
        readback = _program_readbacks(parent_plan, original, files)
    elif purpose == "owned_cleanup_preparation" and values["kind"] == "recovery":
        if code_preparation is not None or type(cleanup_evidence) is not bytes:
            raise ValueError("cleanup requires exact saved recovery evidence, not menu code basis")
        evidence = json.loads(cleanup_evidence)
        if (type(evidence) is not dict or set(evidence) != {"stock_readback", "restore_receipt"} or
            json.dumps(evidence, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii") != cleanup_evidence):
            raise ValueError("exact canonical cleanup evidence required")
        auxiliary = stage.plan_owned_cleanup_staging(parent_plan, manifest, raw_session, payload_identities,
            evidence["stock_readback"], evidence["restore_receipt"])
    elif purpose == "boot_activation_preparation" and values["kind"] == "install":
        auxiliary = stage.plan_boot_payload_identity_staging(parent_plan, manifest, raw_session, payload_identities)
    elif not (purpose == "boot_recovery_preparation" and values["kind"] == "recovery" and payload_identities is None):
        raise ValueError("fixed second-window purpose/session/dependencies differ")
    if purpose in ("boot_activation_preparation", "boot_recovery_preparation"):
        if code_preparation is not None:
            raise ValueError("boot preparation cannot install previous temporary code")
        from . import menu_boot_boundary as boot_boundary, prepare_peer_install as peer
        action = "activate" if purpose == "boot_activation_preparation" else "restore"
        support = stage.plan_boot_observer_staging(parent_plan, manifest, raw_session, action=action)
        program_name = action + "-boot.sh"
        observer_path = boot_boundary.paths(manifest, action, 0, session_nonce=values["session_nonce"],
                                           session_data_sha256=_sha(raw_session))["program"]
        files = ((parent_plan.stage_root + "/" + program_name, peer.render_role_programs(manifest)[program_name].encode("ascii")),
                 (observer_path, boot_boundary.render_observer(manifest, action=action).encode("ascii")))
        readback = _program_readbacks(parent_plan, original, files)
    steps = original.steps + (() if auxiliary is None else auxiliary.steps) + (() if support is None else support.steps) + readback
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    identity = {"schema": "x2dii-second-window-preparation-v1", "purpose": purpose,
        "parent_plan_sha256": parent_plan.plan_sha256, "candidate_sha256": parent_plan.candidate_sha256,
        "manifest_sha256": _sha(manifest_bytes), "raw_session_sha256": _sha(raw_session),
        "original_session_binding_sha256": original.binding_sha256,
        "auxiliary_binding_sha256": None if auxiliary is None else auxiliary.binding_sha256,
        "support_binding_sha256": None if support is None else support.binding_sha256,
        "code_preparation_sha256": None if code_preparation is None else code_preparation.plan.plan_sha256,
        "steps": [step.__dict__ for step in steps]}
    if cleanup_evidence is not None:
        identity["cleanup_evidence_sha256"] = _sha(cleanup_evidence)
    digest = _sha(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("ascii"))
    plan = stage.StagingPlan(parent_plan.candidate_sha256, parent_plan.renderer_source_sha256,
        parent_plan.stage_root, parent_plan.member_names, steps, digest, include_session_file=False,
        phase="second-window-preparation")
    # Only the plan/execution binding changes. The camera observation bytes,
    # nonce, boot identity, namespace and original expiry remain exactly intact.
    session = stage.plan_raw_session_staging(plan, manifest, raw_session)
    return SecondWindowPreparation(purpose, parent_plan, manifest_bytes, raw_session,
        None if payload_identities is None else tuple(payload_identities), plan, session, code_preparation, cleanup_evidence)


def plan_temporary_preparation(parent_plan, manifest, raw_menu_session):
    """Code staging ONLY; let the original USB window restore before ready.

    This stages fresh data, four workers and six fixed temporary support programs.
    Never chain it straight into preplacement: transfer + file boundaries cannot
    fit the original 80-second usable budget at the recorded transport cadence.
    """
    return _second_preparation(parent_plan, manifest, raw_menu_session, "temporary_menu_preparation", None)


def plan_temporary_ready(code_preparation, fresh_raw_session):
    """A later fresh window uploads data and only reads the prior source set."""
    _validate_preparation(code_preparation)
    return _second_preparation(code_preparation.parent_plan, json.loads(code_preparation.manifest_bytes),
        fresh_raw_session, "temporary_menu_ready", None, code_preparation)


def plan_boot_preparation(parent_plan, manifest, raw_session, *, action, payload_identities=None):
    """Activation adds four prior inode identities; recovery uploads only data."""
    if action not in ("activate", "restore"):
        raise ValueError("fixed activate/restore preparation required")
    purpose = "boot_activation_preparation" if action == "activate" else "boot_recovery_preparation"
    return _second_preparation(parent_plan, manifest, raw_session, purpose, payload_identities)


def plan_install_preparation(parent_plan, manifest, raw_install_session):
    """Fresh install/v2 data, actual /o source, and four stable-worker readbacks.

    No content-window replay, file placement, GUI launch or authority is added.
    The executing caller must bind completed prior stable content and its USB
    restoration to the new window; source equality alone is not that evidence.
    """
    return _second_preparation(parent_plan, manifest, raw_install_session, "install_preparation", None)


def plan_cleanup_preparation(parent_plan, manifest, raw_recovery, original_identities, stock_readback, restore_receipt):
    """Exact raw recovery data plus the five fixed cleanup sources; no removal."""
    evidence = json.dumps({"stock_readback": stock_readback, "restore_receipt": restore_receipt},
        sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    return _second_preparation(parent_plan, manifest, raw_recovery, "owned_cleanup_preparation",
        original_identities, cleanup_evidence=evidence)


def _validate_preparation(preparation):
    if type(preparation) is not SecondWindowPreparation:
        raise ValueError("fixed second-window preparation required")
    expected = _second_preparation(preparation.parent_plan, json.loads(preparation.manifest_bytes),
        preparation.raw_session, preparation.purpose, preparation.payload_identities, preparation.code_preparation, preparation.cleanup_evidence)
    if expected != preparation:
        raise ValueError("second-window preparation identity or fixed commands differ")


def original_window_deadline(observed_epoch, launched):
    """Shared two-window bound; explicit launch never renews the observation.

    `launched` is the host timestamp before sending the launch request, not
    the later PID reply/ADB enumeration timestamp (which could extend time).
    The caller must bind that provenance to the existing recorded command.
    """
    if type(observed_epoch) is not int or not 0 <= observed_epoch < 10**10:
        raise ValueError("original integer observation epoch required")
    if type(launched) is not datetime or launched.tzinfo is None:
        raise ValueError("timezone-aware original launch time required")
    stamp = launched.timestamp()
    if not math.isfinite(stamp) or not observed_epoch <= stamp < observed_epoch + 600:
        raise ValueError("launch is outside the original observation lease")
    deadline = min(stamp + 90, observed_epoch + 600) - RESTORE_RESERVE_SECONDS
    if deadline <= stamp:
        raise ValueError("original window has no budget after restore reserve")
    return deadline


class ContentStageCoordinator:
    """Fixed host dialogue, not an arbitrary command or qualification interface.

    Maintenance completion must come from the existing recorded Session.command
    decoder, not an unvalidated return string. The booleans here are boundary
    assertions; the real integration must retain and validate native records.
    """
    installable = False
    final_scope = "STABLE_CONTENT_STAGED_NOT_INSTALLED_USB_RESTORE_UNVERIFIED"

    def __init__(self, plan, session, *, clock=time.time):
        if type(plan) is not stage.StagingPlan or plan.include_session_file is not False or plan.phase != "stable-content":
            raise ValueError("first window requires compressed stable-content-only plan")
        self._initialize(plan, session, clock)

    def _initialize(self, plan, session, clock):
        self.exchange = stage.FixedStagingExchange(plan, dict(session.context), session=session, clock=clock)
        self.observer = self.exchange.observer
        self._plan = plan
        self._session, self._clock = session, clock
        self._su = stage.execution_steps(plan, dict(session.context), session=session)
        self._preparation = 0
        self._released_preparation = None
        self._deadline = self._launched = None
        self._pending = None
        self._write = None
        self._index = 0
        self.failed = False

    def _need(self, ok, message):
        if self.failed or not ok:
            self.failed = True
            raise ValueError("content stage coordinator: " + message)

    def _window(self):
        now = self._clock()
        self._need(type(now) in (int, float) and self._deadline is not None and
                   self._launched <= now < self._deadline, "original USB window expired or not started")
        return int(now)

    @property
    def next_preparation(self):
        self._need(self._deadline is None, "observer preparation must precede USB window")
        if self._preparation == len(self.observer.preparation):
            return None
        self._released_preparation = self.exchange.next_step
        return self._released_preparation

    def accept_preparation(self, *, exit_code, stdout, completion_validated):
        self._need(self._deadline is None and self._released_preparation is not None,
                   "no fixed pre-window preparation released")
        operation = self._released_preparation
        try:
            self.exchange.accept(role="maintenance", index=operation.index, command=operation.command,
                                 exit_code=exit_code, stdout=stdout, completion_validated=completion_validated)
        except Exception:
            self.failed = True
            raise
        self._preparation += 1
        self._released_preparation = None

    def start_window(self, launch_started_utc):
        self._need(self._deadline is None and self._preparation == len(self.observer.preparation),
                   "window cannot precede completed preparation or restart its timer")
        try:
            self._deadline = original_window_deadline(self._session.observed_epoch, launch_started_utc)
            self._launched = launch_started_utc.timestamp()
            self._launch_started_utc = launch_started_utc.isoformat()
            self._window()
        except Exception:
            self.failed = True
            raise

    def begin_command(self, line):
        self._window()
        self._need(self._pending is None and self._write is None and self._index < len(self._su),
                   "content command requested out of order")
        digest = _sha(self._su[self._index].command.encode("ascii"))
        self._need(line == f"X2DII_CONTENT_NEED:{self._index}:{self._session.binding_sha256}:{digest}",
                   "content request identity differs")
        self._pending = self.exchange.next_step
        self._need(self._pending.role == "maintenance" and self._pending.index == self._index,
                   "fixed maintenance observation was not next")
        return self._pending

    def accept_maintenance(self, *, exit_code, stdout, completion_validated):
        self._window()
        self._need(self._pending is not None and self._write is None, "no pending fixed observation")
        operation = self._pending
        try:
            self.exchange.accept(role="maintenance", index=operation.index, command=operation.command,
                                 exit_code=exit_code, stdout=stdout, completion_validated=completion_validated)
            self._write = self.exchange.next_step
        except Exception:
            self.failed = True
            raise
        self._pending = None
        checked = int(stdout.replace("\r\n", "\n").rstrip("\n").rsplit(":", 1)[1])
        digest = _sha(self._write.command.encode("ascii"))
        self._window()
        return f"X2DII_CONTENT_GO:{self._index}:{self._session.binding_sha256}:{digest}:{checked}\n"

    def accept_su_reply(self, line):
        self._window()
        self._need(self._write is not None and type(line) is str and len(line) <= 12000,
                   "no bounded completed su response expected")
        prefix = f"X2DII_CONTENT_REPLY:{self._index}:"
        self._need(line.startswith(prefix), "su response index differs")
        try:
            raw = base64.b64decode(line[len(prefix):], validate=True)
            output = raw.decode("ascii").replace("\r\n", "\n")
            marker = f"\nX2DII_CONTENT_{self._session.binding_sha256[:24]}_{self._index}_RC=0\n"
            self._need(output == self._write.expected_stdout + marker, "su exact completion differs")
            self.exchange.accept(role="su", index=self._index, command=self._write.command,
                                 exit_code=0, stdout=output[:-len(marker)], completion_validated=True)
        except Exception:
            self.failed = True
            raise
        reply = f"X2DII_CONTENT_ACCEPTED:{self._index}:{_sha(raw)}\n"
        self._write = None
        self._index += 1
        return reply

    @property
    def all_results_validated(self):
        return not self.failed and self.exchange.all_results_validated

    def remaining_window_seconds(self):
        self._window()
        return self._deadline - self._clock()


class SecondWindowPreparationCoordinator(ContentStageCoordinator):
    """Same fixed role dialogue, bound to a distinct second-window step list."""
    final_scope = "SECOND_WINDOW_PREPARATION_STAGED_NOT_LOADED_NOT_INSTALLED_USB_RESTORE_UNVERIFIED"

    def __init__(self, preparation, *, clock=time.time):
        _validate_preparation(preparation)
        self.preparation = preparation
        self.final_scope = _preparation_scope(preparation)
        self._initialize(preparation.plan, preparation.session, clock)


def drive_content_process(process, coordinator, maintenance_session):
    """Drive the fixed C# process using the existing recorded maintenance route.

    `process` must be the separately generated fixed sender, with binary pipes.
    It is not launched here. Session.command retains native maintenance records
    and checks framing/status before this driver issues a GO on the same stdin.
    The original device USB restore worker is not touched, extended or stopped.
    Returned byte records are host evidence, not camera integration qualification.
    """
    if type(coordinator) is not ContentStageCoordinator:
        raise ValueError("fixed content coordinator required")
    return _drive_stage_process(process, coordinator, maintenance_session)


def drive_preparation_process(process, coordinator, maintenance_session):
    """Fixed second preparation only; same original launch deadline is retained."""
    if type(coordinator) is not SecondWindowPreparationCoordinator:
        raise ValueError("fixed second-window coordinator required")
    return _drive_stage_process(process, coordinator, maintenance_session)


def _preparation_scope(preparation):
    if preparation.purpose == "temporary_menu_preparation":
        return "MENU_CODE_STAGED_NEW_READY_WINDOW_REQUIRED_NOT_LOADED_NOT_INSTALLED_USB_RESTORE_UNVERIFIED"
    if preparation.purpose == "temporary_menu_ready":
        return "FRESH_MENU_CONTEXT_AND_SOURCES_VERIFIED_NOT_LOADED_NOT_INSTALLED_USB_RESTORE_UNVERIFIED"
    if preparation.purpose == "owned_cleanup_preparation":
        return "OWNED_CLEANUP_SOURCES_STAGED_NOT_EXECUTED_USB_RESTORE_UNVERIFIED"
    if preparation.purpose == "install_preparation":
        return "FORMAL_CONTEXT_AND_OBSERVER_READY_NOT_FILES_PLACED_USB_RESTORE_UNVERIFIED"
    return SecondWindowPreparationCoordinator.final_scope


def _drive_stage_process(process, coordinator, maintenance_session):
    messages = queue.Queue(maxsize=16)
    sender_errors = bytearray()
    error_output = {"bytes": 0, "read_error": None}

    def read_errors():
        # Drain even beyond the retained limit: otherwise a full stderr pipe
        # can block the child before stdout EOF and disguise its real failure.
        try:
            while True:
                raw = process.stderr.read(4096)
                if not raw:
                    break
                error_output["bytes"] += len(raw)
                sender_errors.extend(raw[:max(0, 65536 - len(sender_errors))])
        except Exception as error:
            error_output["read_error"] = str(error)

    def stderr_evidence():
        return {"stderr": bytes(sender_errors), "stderr_bytes": error_output["bytes"],
                "stderr_truncated": error_output["bytes"] > len(sender_errors),
                "stderr_read_error": error_output["read_error"]}

    def read_lines():
        try:
            while True:
                raw = process.stdout.readline(12001)
                if raw == b"":
                    messages.put(None)
                    return
                if type(raw) is not bytes or len(raw) > 12000 or not raw.endswith(b"\n"):
                    raise ValueError("content process line limit/framing")
                line = raw[:-1]
                if line.endswith(b"\r"):
                    line = line[:-1]
                if any(value < 32 or value > 126 for value in line):
                    raise ValueError("content process non-ASCII/control output")
                messages.put(line.decode("ascii"))
        except Exception as error:
            messages.put(error)

    reader = threading.Thread(target=read_lines, daemon=True)
    error_reader = threading.Thread(target=read_errors, daemon=True)
    reader.start()
    error_reader.start()
    index, seen_final = 0, False
    chunks = bytearray()
    retained = []
    phase = "await-native-event"

    def reply(value):
        coordinator.remaining_window_seconds()
        process.stdin.write(value.encode("ascii"))
        process.stdin.flush()

    try:
        while True:
            phase = "await-native-event"
            timeout = min(8, coordinator.remaining_window_seconds())
            if timeout <= 0:
                raise ValueError("original content window exhausted")
            try:
                line = messages.get(timeout=timeout)
            except queue.Empty as error:
                raise ValueError("content process output deadline expired") from error
            if isinstance(line, Exception):
                raise line
            if line is None:
                phase = "validate-final-process"
                if not seen_final or not coordinator.all_results_validated:
                    raise ValueError("content process ended before exact final receipt")
                if process.wait(timeout=min(2, coordinator.remaining_window_seconds())) != 0:
                    raise ValueError("content sender process failed")
                error_reader.join(timeout=1)
                if error_reader.is_alive() or error_output["read_error"] is not None:
                    raise ValueError("content sender error output did not close cleanly")
                result = {"status": coordinator.final_scope,
                        "candidate_sha256": coordinator._plan.candidate_sha256,
                        "plan_sha256": coordinator._plan.plan_sha256,
                        "session_data_sha256": coordinator._session.data_sha256,
                        "session_binding_sha256": coordinator._session.binding_sha256,
                        "launch_started_utc": coordinator._launch_started_utc,
                        **stderr_evidence(), "sender_exit_code": 0,
                        "retained_adb_payloads": retained, "usb_restore_verified": False,
                        "installable": False}
                if type(coordinator) is SecondWindowPreparationCoordinator:
                    result.update(purpose=coordinator.preparation.purpose,
                        preparation_plan_sha256=coordinator.preparation.plan.plan_sha256,
                        session_data_sha256=coordinator._session.data_sha256,
                        worker_followup_allowed=coordinator.preparation.purpose != "temporary_menu_preparation")
                return result
            if seen_final:
                raise ValueError("unexpected output after final content receipt")
            if line.startswith("X2DII_CONTENT_NEED:"):
                phase = "validate-native-request"
                if chunks:
                    raise ValueError("prior native payload was not completed")
                operation = coordinator.begin_command(line)
                # Existing Session.command verifies native packets, unique
                # completion, status, and retains the raw transport bytes.
                phase = "maintenance-observation"
                output = maintenance_session.command(f"content-observe-{index}", operation.command)
                phase = "validate-maintenance-and-send-permit"
                reply(coordinator.accept_maintenance(exit_code=0, stdout=output, completion_validated=True))
            elif line.startswith(f"X2DII_CONTENT_BYTES:{index}:"):
                phase = "retain-native-bytes"
                raw = base64.b64decode(line.split(":", 2)[2], validate=True)
                if len(chunks) + len(raw) > 8192:
                    raise ValueError("content native payload limit")
                chunks.extend(raw)
            elif line.startswith(f"X2DII_CONTENT_REPLY:{index}:"):
                phase = "validate-native-completion"
                raw = base64.b64decode(line.split(":", 2)[2], validate=True)
                if bytes(chunks).replace(b"\r\n", b"\n") != raw:
                    raise ValueError("content completed payload differs from retained native bytes")
                acknowledgement = coordinator.accept_su_reply(line)
                retained.append({"index": index, "raw": bytes(chunks), "sha256": _sha(bytes(chunks))})
                phase = "acknowledge-native-completion"
                reply(acknowledgement)
                chunks.clear()
                index += 1
            elif line == "X2DII_" + coordinator.final_scope:
                phase = "validate-final-receipt"
                if not coordinator.all_results_validated or chunks:
                    raise ValueError("premature final content receipt")
                seen_final = True
            else:
                raise ValueError("unexpected fixed content process event")
    except Exception as error:
        coordinator.failed = True
        evidence = {"status": "FAILED_OR_INCOMPLETE_NOT_INSTALLATION_SUCCESS",
            "phase": phase, "command_index": index,
            "candidate_sha256": coordinator._plan.candidate_sha256,
            "plan_sha256": coordinator._plan.plan_sha256,
            "session_data_sha256": coordinator._session.data_sha256,
            "session_binding_sha256": coordinator._session.binding_sha256,
            "launch_started_utc": getattr(coordinator, "_launch_started_utc", None),
            "retained_adb_payloads": tuple(dict(item) for item in retained),
            "current_adb_payload": bytes(chunks), "current_adb_payload_sha256": _sha(bytes(chunks)),
            "final_receipt_seen": seen_final, "installable": False, "usb_restore_verified": False,
            "cleanup_errors": []}
        error.partial_evidence = evidence
        # Only this host child is stopped; not the camera's independent USB
        # restoration worker. No automatic retry or cleanup of uncertain files.
        try:
            if process.poll() is None:
                process.terminate()
        except Exception as cleanup_error:
            evidence["cleanup_errors"].append({"step": "terminate-host-child", "error": str(cleanup_error)})
        for label, operation in (
                ("wait-host-child", lambda: process.wait(timeout=5)),
                ("join-error-output", lambda: error_reader.join(timeout=1))):
            try:
                operation()
            except Exception as cleanup_error:
                evidence["cleanup_errors"].append({"step": label, "error": str(cleanup_error)})
        if error_reader.is_alive():
            evidence["cleanup_errors"].append({"step": "join-error-output", "error": "reader still running"})
        evidence.update(stderr_evidence())
        try:
            evidence["sender_exit_code"] = process.poll()
        except Exception as cleanup_error:
            evidence["cleanup_errors"].append({"step": "poll-host-child", "error": str(cleanup_error)})
        raise


def review_content_host_source(plan, session, launch_started_utc):
    """Compile the actual fixed native path, with qualification guard CLOSED.

    No caller flag opens it. Tests replace only native/time edges in their own
    copies, never execute the original native path or create a released source.
    """
    if type(plan) is not stage.StagingPlan or plan.include_session_file is not False or plan.phase != "stable-content":
        raise ValueError("compressed stable-content-only plan required")
    return _review_stage_host_source(plan, session, launch_started_utc, ContentStageCoordinator.final_scope)


def review_preparation_host_source(preparation, launch_started_utc):
    """Closed native entry for only these bound second-window preparation steps.

    Pass the original pre-send USB launch timestamp to this and every following
    file/boot sender in that window. Starting another host child does not restart
    the device's timer; no new device USB worker is created here.
    """
    _validate_preparation(preparation)
    return _review_stage_host_source(preparation.plan, preparation.session, launch_started_utc,
                                    _preparation_scope(preparation))


def _review_stage_host_source(plan, session, launch_started_utc, final_scope):
    deadline = original_window_deadline(session.observed_epoch, launch_started_utc)
    steps = stage.execution_steps(plan, dict(session.context), session=session)
    commands, outputs, hashes = [], [], []
    for index, operation in enumerate(steps):
        marker = f"X2DII_CONTENT_{session.binding_sha256[:24]}_{index}_RC="
        command = "(" + operation.command + ");r=$?;printf '\\n" + marker + "%s\\n' \"$r\""
        if len(("shell:" + command + "\0").encode("ascii")) > 4096:
            raise ValueError("fixed content command exceeds native ADB OPEN budget")
        commands.append(command)
        outputs.append(operation.expected_stdout + "\n" + marker + "0\n")
        hashes.append(_sha(operation.command.encode("ascii")))
    source = usb.host_source(usb.REFERENCE.read_bytes())
    namespace = "X2d2ContentStage_" + _sha((session.binding_sha256 + launch_started_utc.isoformat()).encode())[:16]
    source = usb.replace_once(source, "namespace X2d2PeerAdb", "namespace " + namespace)
    source = usb.replace_once(source,
        "        public static ProbeResult Probe() { return new ProbeResult { MatchingInterfaces = Enumerate().Count }; }",
        "        // No separate native enumeration or arbitrary-shell entry.")
    source = usb.replace_once(source, "        public static string Query() { return RunShell(); }\n", "")
    # The existing core checks before EACH native write/read. An OPEN's header
    # and payload both recheck its permit, including a delay inside Send().
    source = usb.replace_once(source,
        '            if (deadline.ElapsedMilliseconds > 15000) throw new UsbFailure("ADB_DEADLINE");',
        '            ContentTime(2000);\n            if(requirePermit) ContentPermit(permitEpoch);')
    helpers = r'''
        private static readonly bool ContentQualified = false;
        private static readonly string[] ContentCommands = new string[] { @COMMANDS@ };
        private static readonly string[] ContentOutputs = new string[] { @OUTPUTS@ };
        private static readonly string[] ContentHashes = new string[] { @HASHES@ };
        private static readonly string[] ReplyHashes = new string[] { @REPLY_HASHES@ };
        private const string ContentExecution = @EXECUTION@;
        private const long ContentLaunchEpoch = @LAUNCH@;
        private const long ContentDeadlineEpoch = @DEADLINE@;
        private static Stopwatch contentClock;
        private static long remainingMilliseconds;
        private static int contentAttempted;
        private bool requirePermit;
        private long permitEpoch;
        private static long ContentNow() {
            return (long)(DateTime.UtcNow-new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc)).TotalSeconds;
        }
        private static void ContentTime(int reserveMilliseconds) {
            long now=ContentNow();
            if(contentClock==null || now<ContentLaunchEpoch ||
               now*1000+reserveMilliseconds>=ContentDeadlineEpoch*1000 ||
               contentClock.ElapsedMilliseconds+reserveMilliseconds>=remainingMilliseconds)
                throw new UsbFailure("CONTENT_ORIGINAL_WINDOW_DEADLINE");
        }
        private static void ContentPermit(long checkedAt) {
            long now=ContentNow();
            if(checkedAt<ContentLaunchEpoch || checkedAt>now || now-checkedAt>8)
                throw new UsbFailure("CONTENT_MAINTENANCE_PERMIT_EXPIRED");
        }
        private static string ContentReadLine() {
            var pending=System.Threading.Tasks.Task<string>.Factory.StartNew(delegate {
                var text=new StringBuilder();
                for(int i=0;i<256;i++) {
                    int value=Console.In.Read();
                    if(value<0) throw new UsbFailure("CONTENT_HOST_EOF");
                    if(value==10) return text.ToString();
                    if(value<32 || value>126) throw new UsbFailure("CONTENT_HOST_CHARACTER");
                    text.Append((char)value);
                }
                throw new UsbFailure("CONTENT_HOST_LINE_LIMIT");
            });
            if(!pending.Wait(7500)) throw new UsbFailure("CONTENT_HOST_TIMEOUT");
            return pending.Result;
        }
        private static long ContentAcceptPermit(int index,string line) {
            string prefix="X2DII_CONTENT_GO:"+index+":"+ContentExecution+":"+ContentHashes[index]+":";
            if(line==null || !line.StartsWith(prefix,StringComparison.Ordinal))
                throw new UsbFailure("CONTENT_PERMIT_IDENTITY");
            string value=line.Substring(prefix.Length);
            if(!Regex.IsMatch(value,"\\A[1-9][0-9]{0,9}\\z")) throw new UsbFailure("CONTENT_PERMIT_TIME");
            long checkedAt=long.Parse(value,CultureInfo.InvariantCulture);
            ContentPermit(checkedAt);
            return checkedAt;
        }
        private static string RunContentCommand(AdbUsbCheck stream,int index,long checkedAt) {
            uint local=(uint)index+1,remote=0;
            ContentTime(2000); ContentPermit(checkedAt);
            stream.permitEpoch=checkedAt; stream.requirePermit=true;
            try { stream.Send("OPEN",local,0,Encoding.ASCII.GetBytes("shell:"+ContentCommands[index]+"\0")); }
            finally { stream.requirePermit=false; }
            var payload=new List<byte>();
            for(int packets=0;packets<128;packets++) {
                ContentTime(2000);
                Packet p=stream.Receive();
                if(p.B!=local) throw new UsbFailure("CONTENT_STREAM_ID");
                if(p.Command==Cmd("OKAY")) {
                    if(remote!=0 || p.A==0 || p.Data.Length!=0) throw new UsbFailure("CONTENT_UNEXPECTED_OKAY");
                    remote=p.A; continue;
                }
                if(remote==0 || p.A!=remote) throw new UsbFailure("CONTENT_REMOTE_ID");
                if(p.Command==Cmd("WRTE")) {
                    Console.WriteLine("X2DII_CONTENT_BYTES:"+index+":"+Convert.ToBase64String(p.Data));
                    Console.Out.Flush();
                    if(payload.Count+p.Data.Length>8192) throw new UsbFailure("CONTENT_OUTPUT_LIMIT");
                    foreach(byte value in p.Data) {
                        if(value!=10 && value!=13 && (value<32 || value>126)) throw new UsbFailure("CONTENT_OUTPUT_CHARACTER");
                        payload.Add(value);
                    }
                    stream.Send("OKAY",local,remote,new byte[0]); continue;
                }
                if(p.Command==Cmd("CLSE")) {
                    if(p.Data.Length!=0) throw new UsbFailure("CONTENT_CLOSE_PAYLOAD");
                    stream.Send("CLSE",local,remote,new byte[0]);
                    string output=Encoding.ASCII.GetString(payload.ToArray()).Replace("\r\n","\n");
                    if(output!=ContentOutputs[index]) throw new UsbFailure("CONTENT_EXACT_REPLY");
                    ContentTime(0); ContentPermit(checkedAt);
                    // Canonical ASCII is emitted only after complete native CLSE.
                    return output;
                }
                throw new UsbFailure("CONTENT_UNEXPECTED_PACKET");
            }
            throw new UsbFailure("CONTENT_PACKET_LIMIT");
        }
        public static string RunContentStage() {
            if(!ContentQualified) throw new UsbFailure("CONTENT_SOURCE_NOT_QUALIFIED");
            if(System.Threading.Interlocked.Exchange(ref contentAttempted,1)!=0)
                throw new UsbFailure("CONTENT_ALREADY_ATTEMPTED");
            long now=ContentNow();
            remainingMilliseconds=Math.Min(80000,(ContentDeadlineEpoch-now)*1000);
            contentClock=Stopwatch.StartNew();
            ContentTime(2000);
            using(AdbUsbCheck stream=new AdbUsbCheck()) {
                stream.Open(new ReadResult());
                stream.Send("CNXN",0x01000000,4096,Encoding.ASCII.GetBytes("host::\0"));
                Packet hello=stream.Receive();
                ValidateHandshakePacket(hello.Command,hello.A,hello.B,hello.Data.Length);
                for(int index=0;index<ContentCommands.Length;index++) {
                    ContentTime(2000);
                    Console.WriteLine("X2DII_CONTENT_NEED:"+index+":"+ContentExecution+":"+ContentHashes[index]);
                    Console.Out.Flush();
                    long permit=ContentAcceptPermit(index,ContentReadLine());
                    string output=RunContentCommand(stream,index,permit);
                    Console.WriteLine("X2DII_CONTENT_REPLY:"+index+":"+Convert.ToBase64String(Encoding.ASCII.GetBytes(output)));
                    Console.Out.Flush();
                    string acknowledgement=ContentReadLine();
                    ContentTime(0);
                    if(acknowledgement!="X2DII_CONTENT_ACCEPTED:"+index+":"+ReplyHashes[index])
                        throw new UsbFailure("CONTENT_HOST_REJECTED_REPLY");
                }
            }
            return @FINAL_SCOPE@;
        }
'''
    values = {"@COMMANDS@": ",\n".join(map(json.dumps, commands)),
              "@OUTPUTS@": ",\n".join(map(json.dumps, outputs)),
              "@HASHES@": ",\n".join(map(json.dumps, hashes)),
              "@REPLY_HASHES@": ",\n".join(json.dumps(_sha(value.encode("ascii"))) for value in outputs),
              "@EXECUTION@": json.dumps(session.binding_sha256),
              "@FINAL_SCOPE@": json.dumps("X2DII_" + final_scope),
              "@LAUNCH@": str(int(launch_started_utc.timestamp())), "@DEADLINE@": str(int(deadline))}
    for key, value in values.items():
        helpers = helpers.replace(key, value)
    return usb.replace_once(source, "        private static uint Cmd(string name)",
                            helpers + "\n        private static uint Cmd(string name)")
