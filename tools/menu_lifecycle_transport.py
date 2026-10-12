"""Fixed temporary GUI lifecycle bridge for the eight-second maintenance route.

Launch only starts an independently bounded worker. Its actual exit receipt is
not menu/capture qualification. No device discovery, installation or publication.
"""
from __future__ import annotations

from copy import deepcopy
import re

from . import menu_maintenance_boundary as boundary, session_context as sc


def paths(manifest, raw_session):
    boundary.session_kind_for_context(manifest, raw_session)
    values = sc.decode_session(raw_session)
    if values["kind"] != "menu_validation":
        raise ValueError("temporary lifecycle requires menu_validation")
    root = "/tmp/x2mb-" + manifest["candidate_sha256"][:12]
    return {**{name: root + "/" + name for name in "lwtqs"},
            "root": root,
            "session": boundary.session_path(manifest, boundary._sha(raw_session)),
            "run": "/tmp/x2ml-" + manifest["candidate_sha256"][:12] + "-" + values["session_nonce"],
            "transaction": "/tmp/x2dii-menu-validation-" + values["session_nonce"]}


def command(manifest, raw_session, *, action):
    if action not in ("launch", "read", "stop", "menu"):
        raise ValueError("fixed lifecycle action required")
    fixed = paths(manifest, raw_session)
    entry = {"launch": "l", "read": "q", "stop": "s", "menu": "q"}[action]
    result = "sh " + fixed[entry] + " " + boundary._sha(raw_session)
    if action == "menu":
        result += " menu"
    from .stage_peer_usb_access import envelope
    envelope(result, "123456abcdef")
    return result


class TemporaryLifecycle:
    """Fixed lifecycle and read-only menu queries on the held maintenance route.

    The supplied route is the already held maintenance connection; this class
    cannot discover devices, reopen USB, stage programs, or approve installation.
    """
    def __init__(self, manifest, raw_session, maintenance_session):
        paths(manifest, raw_session)
        self.manifest = deepcopy(manifest)
        self.raw_session = bytes(raw_session)
        self.sha256 = boundary._sha(raw_session)
        self.maintenance = maintenance_session
        self.launch_attempted = False
        self.final = None
        self._menu_cursor = None
        self._menu_exhausted = False

    def _send(self, action):
        result = self.maintenance.command("lifecycle-" + action,
            command(self.manifest, self.raw_session, action=action))
        if type(result) is not str or not 0 < len(result.encode("utf-8")) <= 256:
            raise ValueError("bounded lifecycle response required")
        return result

    def launch(self):
        if self.launch_attempted:
            raise ValueError("this lifecycle launch was already attempted")
        self.launch_attempted = True  # A lost reply cannot authorize a retry.
        reply = self._send("launch")
        if reply != "X2DII_LIFECYCLE_STARTED_NOT_VALIDATED:" + self.sha256 + "\n":
            raise ValueError("lifecycle launch reply differs")
        return {"status": "STARTED_NOT_VALIDATED", "feature_validated": False}

    def read(self):
        reply = self._send("read")
        pending = re.fullmatch(r"X2DII_LIFECYCLE_PENDING:([0-9a-f]{64}):(AWAITING_WORKER|WORKER_OBSERVED)\n", reply)
        uncertain = reply == "X2DII_LIFECYCLE_UNCERTAIN:" + self.sha256 + ":NO_FINAL_RECEIPT\n"
        if pending and pending[1] == self.sha256:
            if self.final is not None:
                raise ValueError("completed lifecycle lost its final receipt")
            return {"status": "PENDING", "phase": pending[2], "feature_validated": False}
        if uncertain:
            if self.final is not None:
                raise ValueError("completed lifecycle lost its final receipt")
            return {"status": "UNCERTAIN_NO_FINAL_RECEIPT", "feature_validated": False}
        match = re.fullmatch(r"X2DII_LIFECYCLE_FINAL:([0-9a-f]{64}):([0-9a-f]{64}):(0|[1-9][0-9]{0,2}):NOT_FEATURE_VALIDATED\n", reply)
        if not match or match[1] != self.sha256 or int(match[3]) > 255:
            raise ValueError("invalid lifecycle final reply")
        raw = (self.sha256 + ":" + match[3] + "\n").encode("ascii")
        if boundary._sha(raw) != match[2]:
            raise ValueError("lifecycle final hash differs")
        final = {"status": "EXITED_NOT_FEATURE_VALIDATED", "session_sha256": self.sha256,
                 "receipt_sha256": match[2], "exit_code": int(match[3]), "feature_validated": False}
        if self.final is not None and self.final != final:
            raise ValueError("lifecycle final receipt changed")
        self.final = final
        return dict(final)

    def read_menu(self):
        """A bound log snapshot, never a feature/capture/installation PASS."""
        if not self.launch_attempted or self.final is not None:
            raise ValueError("attempted unfinished lifecycle required for menu observation")
        reply = self._send("menu")
        unknown = re.fullmatch(r"X2DII_MENU_UNKNOWN:([0-9a-f]{64}):(INACTIVE|NOT_READY|INVALID_LOG|OVERFLOW|IDENTITY_CHANGED|SNAPSHOT_CHANGED)\n", reply)
        values = sc.decode_session(self.raw_session)
        common = {"candidate_sha256": self.manifest["candidate_sha256"],
                  "session_sha256": self.sha256, "boot_id": values["boot_id"],
                  "feature_validated": False, "raw_reply": reply}
        if unknown and unknown[1] == self.sha256:
            if unknown[2] == "OVERFLOW":
                self._menu_exhausted = True
            return {**common, "status": "MENU_UNKNOWN", "reason": unknown[2], "ready": False}
        match = re.fullmatch(r"X2DII_MENU_SNAPSHOT:([0-9a-f]{64}):([1-9][0-9]{0,6}):([1-9][0-9]{0,18}):([0-9a-f]{64}):([1-9][0-9]{0,2}):([1-9][0-9]{0,2}):([01]):([01]):([01]):([01]):([01]):(-1|0|[1-9]|1[0-2]):(-1|0|[1-9]|1[01])\n", reply)
        if not match or match[1] != self.sha256:
            raise ValueError("invalid bound menu snapshot reply")
        generation, sequence = int(match[5]), int(match[6])
        ready, model, button, visible, eligible = map(int, match.groups()[6:11])
        count, index = int(match[12]), int(match[13])
        if (not 1 <= generation <= 256 or not 1 <= sequence <= 256 or
            (ready and (not model or not button or not 0 <= index < count)) or
            (visible and not ready) or (eligible and not visible) or (button and index < 0)):
            raise ValueError("inconsistent menu snapshot reply")
        identity = (match[2], match[3])
        state = match.groups()[6:]
        if self._menu_exhausted:
            raise ValueError("menu overflow cannot recover within this lifecycle")
        if self._menu_cursor is not None:
            prior_identity, prior_generation, prior_sequence, prior_state = self._menu_cursor
            if identity != prior_identity:
                raise ValueError("menu GUI lifetime changed")
            if generation < prior_generation or (generation == prior_generation and sequence < prior_sequence):
                raise ValueError("menu snapshot sequence regressed")
            if generation == prior_generation and sequence == prior_sequence and state != prior_state:
                raise ValueError("menu snapshot changed without a new sequence")
        self._menu_cursor = (identity, generation, sequence, state)
        return {**common, "status": "MENU_SNAPSHOT_NOT_FEATURE_VALIDATED",
                "pid": int(match[2]), "start_ticks": match[3], "log_sha256": match[4],
                "generation": generation, "sequence": sequence, "ready": bool(ready),
                "model_matched": bool(model), "button_instantiated": bool(button),
                "visible": bool(visible), "eligible": bool(eligible),
                "grid_count": count, "extension_index": index}

    def stop(self):
        if not self.launch_attempted or self.final is not None:
            raise ValueError("stop requires this attempted, unfinished lifecycle")
        reply = self._send("stop")
        if reply != "X2DII_LIFECYCLE_STOP_REQUESTED_NOT_COMPLETED:" + self.sha256 + "\n":
            raise ValueError("lifecycle stop reply differs")
        return {"status": "STOP_REQUESTED_NOT_COMPLETED", "feature_validated": False}


def _guarded_sources(temporary, common, manifest):
    """Compose the existing recovery body with the fixed w/t ownership handoff.

    No new transport role or host-supplied command is introduced. The direct
    two-argument temporary-session renderer remains unchanged.
    """
    from . import prepare_peer_install as peer

    def anchor_once(source, anchor):
        if source.count(anchor) != 1:
            raise ValueError("temporary lifecycle anchor changed: " + repr(anchor))
        return source.index(anchor)

    def replace_once(source, anchor, replacement):
        anchor_once(source, anchor)
        return source.replace(anchor, replacement, 1)

    split = "trap temporary_finish EXIT\n"
    anchor_once(temporary, split)
    prelude, controller = temporary.split(split, 1)
    recovery = prelude[anchor_once(prelude, "core_equals() {"):]
    # w receives the same functions and original admission checks as t, before
    # either can stop the official service. It does not race a live t's trap.
    bridge = common[anchor_once(common, 'ml_run="'):]
    shell = r'''
mg_shell_exe=$(readlink "/proc/$$/exe") || exit 33
mg_shell_hash_line=$(sha256sum "/proc/$$/exe") || exit 33
mg_shell_hash=${mg_shell_hash_line%% *}
x2dii_sc_scalar hex64 "$mg_shell_hash" || exit 33
mg_controller_pid=''
mg_controller_ticks=''
mg_worker_identity=''
mg_lock_identity=''
mg_child_offered=0
mg_official() {
 hashok /system/etc/init/camera-gui.rc OFFICIAL_RC_HASH && meta /system/etc/init/camera-gui.rc "$X2DII_SESSION_RC_LABEL"
}
mg_role_process() {
 mg_role_pid=$1; mg_role_ticks=$2; mg_role=$3
 core_process "$mg_role_pid" "$mg_role_ticks" "$mg_shell_exe" "$mg_shell_hash" u:r:hbl_camera_service:s0 "$X2DII_SESSION_MOUNT_NAMESPACE" || return 1
 mg_command_hash=$(printf '%s\000' /system/bin/sh "$ml_root/$mg_role" "$ml_sha" | sha256sum) || return 1
 hashok "/proc/$mg_role_pid/cmdline" "${mg_command_hash%% *}" || return 1
 core_equals "$mg_role_ticks" start_ticks "/proc/$mg_role_pid/stat"
}
mg_worker() {
 ml_claim && ml_owner || return 1
 mg_role_process "$ml_pid" "$ml_ticks" w || return 1
 if [ -n "$mg_worker_identity" ]; then
  [ "$mg_worker_identity" = "$ml_pid:$ml_ticks" ] || return 1
 else mg_worker_identity="$ml_pid:$ml_ticks"; fi
}
mg_controller() {
 ml_claim || return 1
 mg_identity=$(ml_line "$ml_run/controller.identity") || return 1
 if [ -n "$mg_controller_pid" ]; then
  [ "$mg_identity" = "$mg_controller_pid:$mg_controller_ticks" ] || return 1
 else
  mg_controller_pid=${mg_identity%%:*}; mg_controller_ticks=${mg_identity#*:}
 fi
 x2dii_sc_scalar pid "$mg_controller_pid" && x2dii_sc_scalar ticks "$mg_controller_ticks" || return 1
 mg_role_process "$mg_controller_pid" "$mg_controller_ticks" t
}
mg_dead() {
 # Absence, a reaped/zombie lifetime, or a different start time cannot be the
 # admitted controller. A read failure on a present stat is not absence.
 [ ! -e "/proc/$1/stat" ] && [ ! -L "/proc/$1/stat" ] && return 0
 mg_death_stat=$(cat "/proc/$1/stat") || return 1
 mg_death_tail=${mg_death_stat##*) }
 [ "$mg_death_tail" != "$mg_death_stat" ] || return 1
 set -- "$2" $mg_death_tail
 mg_expected_ticks=$1; mg_state=$2
 [ "$#" -ge 21 ] || return 1
 shift 20
 x2dii_sc_scalar ticks "$1" || return 1
 [ "$1" != "$mg_expected_ticks" ] && return 0
 case "$mg_state" in Z|X) return 0;; esac
 return 1
}
mg_transaction() {
 ml_claim && ml_private "$transaction" || return 1
 mg_transaction_identity=$(ml_line "$transaction/directory.identity") || return 1
 ml_equals "$mg_transaction_identity" stat -c '%d:%i' "$transaction" || return 1
 mg_attempt_hash=$(printf 'candidate=%s\nnonce=%s\npurpose=temporary_menu_validation\naction=run_and_restore\n' "$X2DII_SESSION_CANDIDATE_SHA256" "$X2DII_SESSION_SESSION_NONCE" | sha256sum) || return 1
 ml_regular "$transaction/attempt" && ml_hash "$transaction/attempt" "${mg_attempt_hash%% *}"
}
mg_put() (
 # Readers see no logical record until its complete, identity-bound bytes
 # are promoted. Retain any failed pending record for diagnosis, never reuse.
 mg_put_target="$ml_run/$1"; mg_put_pending="$ml_run/$1.pending"
 mg_put_value=$2
 ml_claim && ml_absent "$mg_put_target" && ml_absent "$mg_put_pending" || return 1
 set -C
 exec 4>"$mg_put_pending" || return 1
 set +C
 mg_put_identity=$(stat -Lc '%d:%i' /proc/self/fd/4) || return 1
 printf '%s\n' "$mg_put_value" >&4 || return 1
 exec 4>&-
 mg_put_owned() {
  ml_regular "$mg_put_pending" &&
  ml_equals "$mg_put_identity" stat -c '%d:%i' "$mg_put_pending" &&
  ml_equals "$mg_put_value" ml_line "$mg_put_pending"
 }
 mg_put_owned && ml_claim && ml_absent "$mg_put_target" && mg_put_owned || return 1
 mv -n "$mg_put_pending" "$mg_put_target" || return 1
 ml_absent "$mg_put_pending" && ml_regular "$mg_put_target" &&
 ml_equals "$mg_put_identity" stat -c '%d:%i' "$mg_put_target" &&
 ml_equals "$mg_put_value" ml_line "$mg_put_target"
)
mg_ready_value() { printf '%s:%s:%s' "$ml_sha" "$mg_controller_pid" "$mg_controller_ticks"; }
mg_wait_worker_line() {
 mg_wait_name=$1; mg_wait_value=$2; mg_wait_count=0
 while [ "$mg_wait_count" -lt 50 ]; do
  mg_worker && fresh || return 1
  if ! ml_absent "$ml_run/$mg_wait_name"; then
   ml_equals "$mg_wait_value" ml_line "$ml_run/$mg_wait_name" || return 1
   mg_worker
   return $?
  fi
  sleep .1 || return 1
  mg_wait_count=$((mg_wait_count+1))
 done
 return 1
}
mg_admit_controller() {
 mg_controller_pid=$$; mg_controller_ticks=$(start_ticks "/proc/$$/stat") || return 1
 mg_ready=$(mg_ready_value) || return 1
 mg_wait_worker_line guardian.ready "$mg_ready" || return 1
 mg_controller && [ "$mg_controller_pid" = "$$" ] || return 1
 mg_parent=$(process_birth "$$") || return 1
 mg_worker && [ "${mg_parent#*:}" = "$ml_pid" ]
}
mg_arm() {
 mg_worker && mg_transaction && readonly_system && mg_official || return 1
 mg_lock_identity=$(stat -c '%d:%i' /tmp/x2dii-menu-install.lock) || return 1
 ml_private /tmp/x2dii-menu-install.lock || return 1
 mg_put stop.intent "$mg_lock_identity" || return 1
 mg_wait_worker_line stop.armed "$mg_lock_identity" || return 1
 mg_worker && mg_transaction && mg_official && ml_equals "$mg_lock_identity" stat -c '%d:%i' /tmp/x2dii-menu-install.lock
}
mg_unlock() {
 [ -n "$mg_lock_identity" ] && ml_private /tmp/x2dii-menu-install.lock &&
 ml_equals "$mg_lock_identity" stat -c '%d:%i' /tmp/x2dii-menu-install.lock || return 1
 rmdir /tmp/x2dii-menu-install.lock
}
mg_child_shell() {
 core_process "$child_pid" "$child_ticks" "$mg_shell_exe" "$mg_shell_hash" u:r:hbl_camera_service:s0 "$X2DII_SESSION_MOUNT_NAMESPACE" || return 1
 mg_gate_hash=$(printf '%s\000' /system/bin/sh "$ml_root/t" "$ml_sha" gate | sha256sum) || return 1
 hashok "/proc/$child_pid/cmdline" "${mg_gate_hash%% *}"
}
child_owned() {
 [ "$child_recorded" = 1 ] && mount_identity || return 1
 # Parent is bound at transfer, but may become init after either owner dies.
 # Start time and the permitted shell-to-GUI image transition stay mandatory.
 core_equals "$child_ticks" start_ticks "/proc/$child_pid/stat" || return 1
 if ! mg_child_shell; then
  core_process "$child_pid" "$child_ticks" "$X2DII_SESSION_CORE_GUI_EXE_TARGET" "$X2DII_SESSION_CORE_GUI_EXE_SHA256" "$X2DII_SESSION_CORE_GUI_DOMAIN" "$X2DII_SESSION_CORE_GUI_MOUNT_NAMESPACE" || return 1
 fi
 core_equals "$child_ticks" start_ticks "/proc/$child_pid/stat"
}
child_exited() {
 mount_identity || return 1
 if ! absent "/proc/$child_pid/stat"; then
  mg_exit_stat=$(cat "/proc/$child_pid/stat") || return 1
  mg_exit_tail=${mg_exit_stat##*) }
  [ "$mg_exit_tail" != "$mg_exit_stat" ] || return 1
  set -- $mg_exit_tail
  [ "$#" -ge 20 ] || return 1
  case "$1" in Z|X) :;; *) return 1;; esac
  shift 19
  [ "$1" = "$child_ticks" ] || return 1
 fi
 # Reused/live PIDs never satisfy this proof and are never signalled.
 wait "$child_pid" 2>/dev/null || :
 child_pid=''
}
stop_owned_child() {
 if [ "${mg_mode:-worker}" = controller ] && [ "$child_recorded" != 1 ] && ! ml_absent "$ml_run/gui.request"; then
  # No admission was issued by this controller. Permanently close the gate
  # instead of guessing ownership of an offer interrupted by guardian loss.
  ml_absent "$ml_run/child.admit" || return 1
  if ml_absent "$ml_run/child.cancel"; then mg_put child.cancel "$ml_sha" || return 1
  else ml_equals "$ml_sha" ml_line "$ml_run/child.cancel" || return 1; fi
  child_pid=''
  return 0
 fi
 [ -n "$child_pid" ] || return 0
 if child_exited; then return 0; fi
 # The known child can end between the live check and identity observation.
 # Recheck only exact disappearance/death; a reused live PID remains refused.
 if ! child_owned; then child_exited; return $?; fi
 if ! kill -TERM "$child_pid"; then child_exited; return $?; fi
 stop_wait=0
 while [ "$stop_wait" -lt 30 ]; do
  if child_exited; then return 0; fi
  if ! child_owned; then child_exited; return $?; fi
  sleep .1 || return 1
  stop_wait=$((stop_wait+1))
 done
 if ! child_owned; then child_exited; return $?; fi
 if ! kill -KILL "$child_pid"; then child_exited; return $?; fi
 stop_wait=0
 while [ "$stop_wait" -lt 20 ]; do
  if child_exited; then return 0; fi
  if ! child_owned; then child_exited; return $?; fi
  sleep .1 || return 1
  stop_wait=$((stop_wait+1))
 done
 child_exited
}
record_child() {
 [ "$child_recorded" = 1 ] && child_owned || return 1
 child_exe=$(readlink "/proc/$child_pid/exe") || return 1
 [ "$child_exe" = "$X2DII_SESSION_CORE_GUI_EXE_TARGET" ] || return 1
 child_hash=$X2DII_SESSION_CORE_GUI_EXE_SHA256
 child_domain=$X2DII_SESSION_CORE_GUI_DOMAIN
 child_namespace=$X2DII_SESSION_CORE_GUI_MOUNT_NAMESPACE
 core_process "$child_pid" "$child_ticks" "$child_exe" "$child_hash" "$child_domain" "$child_namespace" || return 1
 (set -C; printf 'pid=%s\nstart_ticks=%s\nexe=%s\nsha256=%s\ndomain=%s\nnamespace=%s\n' "$child_pid" "$child_ticks" "$child_exe" "$child_hash" "$child_domain" "$child_namespace" > "$transaction/child.identity") || return 1
}
mg_request_child() {
 mg_worker && mg_transaction || return 1
 mg_put gui.request "$ml_sha" || return 1
 mg_offer_wait=0
 while ml_absent "$ml_run/child.offer" && [ "$mg_offer_wait" -lt 50 ]; do
  mg_worker && fresh || return 1
  sleep .1 || return 1
  mg_offer_wait=$((mg_offer_wait+1))
 done
 mg_offer=$(ml_line "$ml_run/child.offer") || return 1
 child_pid=${mg_offer%%:*}; child_ticks=${mg_offer#*:}
 x2dii_sc_scalar pid "$child_pid" && x2dii_sc_scalar ticks "$child_ticks" || return 1
 mg_worker && mg_child_shell || return 1
 child_birth=$(process_birth "$child_pid") || return 1
 [ "$child_birth" = "$child_ticks:$ml_pid" ] || return 1
 # Install deterministic cleanup BEFORE the only permission to exec GUI.
 child_recorded=1
 mg_put child.admit "$mg_offer" || return 1
}
mg_gate() {
 mg_transaction && mg_worker && mg_controller && readonly_system && mg_official && unchanged_core && preplaced_files || exit 75
 mg_gate_birth=$(process_birth "$$") || exit 75
 mg_worker && [ "${mg_gate_birth#*:}" = "$ml_pid" ] || exit 75
 mg_gate_identity="$$:${mg_gate_birth%%:*}"
 mg_gate_wait=0
 while [ "$mg_gate_wait" -lt 50 ]; do
  ml_absent "$ml_run/child.cancel" && mg_worker && mg_controller && fresh || exit 75
  if ! ml_absent "$ml_run/child.admit"; then
   ml_equals "$mg_gate_identity" ml_line "$ml_run/child.offer" &&
   ml_equals "$mg_gate_identity" ml_line "$ml_run/child.admit" || exit 75
   mg_transaction && readonly_system && mg_official && unchanged_core && preplaced_files && quiescent || exit 75
   return 0
  fi
  sleep .1 || exit 75
  mg_gate_wait=$((mg_gate_wait+1))
 done
 exit 75
}
'''
    shell = replace_once(shell, 'OFFICIAL_RC_HASH', manifest['candidate']['rc']['before'])
    prelude = replace_once(prelude, '[ "$#" = 1 ] || exit 32\n',
        '[ "$#" = 1 ] || { [ "$#" = 2 ] && [ "$2" = gate ]; } || exit 32\nmg_mode=${2-controller}\n')
    prelude = replace_once(prelude, 'runtime_identity || exit 32\n', '[ "$mg_mode" = gate ] || runtime_identity || exit 32\n')
    prelude = replace_once(prelude, 'absent "$transaction" || exit 33\n', '[ "$mg_mode" = gate ] || absent "$transaction" || exit 33\n')
    prelude = replace_once(prelude, ' recover_needed=1\n stop camera-gui\n', ' mg_arm || exit 74\n recover_needed=1\n stop camera-gui\n')
    prelude = replace_once(prelude, 'rmdir /tmp/x2dii-menu-install.lock || recovered=0', 'mg_unlock || recovered=0')
    root_start = anchor_once(common, 'ml_root=') + len('ml_root=')
    bridge = 'ml_sha=$1\nml_root=' + peer.shlex.quote(common[root_start:].splitlines()[0]) + '\n' + bridge
    launch_start = anchor_once(controller, '# A direct child, never an init restart')
    launch_end = anchor_once(controller, 'launch_wait=0\nwhile [ "$launch_wait" -lt 50 ]; do')
    command_start = anchor_once(controller, 'env X2DII_MENU_EXTENSION=1 ')
    command_end = anchor_once(controller, '\nchild_pid=$!')
    if not launch_start < command_start < command_end < launch_end:
        raise ValueError("temporary lifecycle launch anchors reordered")
    launch_command = controller[command_start:command_end]
    # Assignment-prefix exec has exactly the admitted shell -> GUI image
    # transition. An intermediate env/toybox image is not an owned GUI image.
    gui_separator = ' /system/bin/camera-gui '
    if not launch_command.startswith('env ') or launch_command.count(gui_separator) != 1 or not launch_command.endswith(' &'):
        raise ValueError("temporary fixed GUI launch changed")
    assignments, gui_arguments = launch_command[4:-2].split(gui_separator, 1)
    gate_launch = 'set -C\n ' + assignments + ' exec /system/bin/camera-gui ' + gui_arguments + '\n'
    controller = controller[:launch_start] + 'mg_request_child || exit 75\n' + controller[launch_end:]
    temporary = prelude + bridge + shell + '\nif [ "$mg_mode" = gate ]; then\n mg_gate\n ' + gate_launch + 'fi\nmg_admit_controller || exit 74\n' + split + controller
    worker = common + replace_once(recovery, 'rmdir /tmp/x2dii-menu-install.lock || recovered=0', 'mg_unlock || recovered=0') + shell
    worker += r'''
ml_claim && ml_fresh && original_gui_running || exit 32
stock_environment_verified=1
ml_regular "$ml_root/t" && ml_hash "$ml_root/t" TEMPORARY_CONTROLLER_HASH || exit 33
ml_ticks=$(ml_birth "$$") || exit 33
mg_put worker.identity "$$:$ml_ticks" || exit 33
trap '' HUP
(set -C; exec /system/bin/sh "$ml_root/t" "$ml_sha" > "$ml_run/lifecycle.log" 2>&1) &
mg_controller_pid=$!
mg_birth_wait=0
while [ "$mg_birth_wait" -lt 50 ]; do
 mg_controller_birth=$(process_birth "$mg_controller_pid") && [ "${mg_controller_birth#*:}" = "$$" ] && break
 sleep .1
 mg_birth_wait=$((mg_birth_wait+1))
done
[ -n "${mg_controller_birth:-}" ] && [ "${mg_controller_birth#*:}" = "$$" ] || exit 33
mg_controller_ticks=${mg_controller_birth%%:*}
mg_role_process "$mg_controller_pid" "$mg_controller_ticks" t || exit 33
mg_put controller.identity "$mg_controller_pid:$mg_controller_ticks" || exit 33
mg_put guardian.ready "$(mg_ready_value)" || exit 33
mg_supervise=0
mg_protocol_failed=0
mg_supervision_started=$(date -u +%s) || exit 33
x2dii_sc_scalar epoch "$mg_supervision_started" || exit 33
while ! mg_dead "$mg_controller_pid" "$mg_controller_ticks" && [ "$mg_supervise" -lt 1700 ]; do
 mg_supervision_now=$(date -u +%s) || { mg_protocol_failed=1; break; }
 if ! x2dii_sc_scalar epoch "$mg_supervision_now" ||
    [ "$mg_supervision_now" -lt "$mg_supervision_started" ] ||
    [ "$mg_supervision_now" -ge "$((mg_supervision_started+170))" ] ||
    [ "$mg_supervision_now" -gt "$((X2DII_SESSION_OBSERVED_EPOCH+600))" ]; then
  mg_protocol_failed=1
  break
 fi
 if [ "$recover_needed" = 0 ] && ! ml_absent "$ml_run/stop.intent"; then
  if mg_controller && mg_transaction && original_gui_running && readonly_system && mg_official && preplaced_files; then
   mg_lock_identity=$(ml_line "$ml_run/stop.intent") || break
   ml_private /tmp/x2dii-menu-install.lock && ml_equals "$mg_lock_identity" stat -c '%d:%i' /tmp/x2dii-menu-install.lock || break
   locked=1
   recover_needed=1
   mg_put stop.armed "$mg_lock_identity" || break
  else mg_protocol_failed=1; break; fi
 fi
 if [ "$recover_needed" = 1 ] && [ "$mg_child_offered" = 0 ] && ! ml_absent "$ml_run/gui.request"; then
  mg_controller && mg_transaction && ml_equals "$ml_sha" ml_line "$ml_run/gui.request" && quiescent &&
  ml_regular "$ml_root/t" && ml_hash "$ml_root/t" TEMPORARY_GATE_HASH || { mg_protocol_failed=1; break; }
  mg_child_offered=1
  (set -C; exec /system/bin/sh "$ml_root/t" "$ml_sha" gate > "$transaction/gate.log" 2>&1 < /dev/null) &
  child_pid=$!
  mg_child_wait=0
  while [ "$mg_child_wait" -lt 50 ]; do
   child_birth=$(process_birth "$child_pid") && [ "${child_birth#*:}" = "$$" ] && break
   sleep .1
   mg_child_wait=$((mg_child_wait+1))
  done
  if [ -n "${child_birth:-}" ] && [ "${child_birth#*:}" = "$$" ]; then
   child_ticks=${child_birth%%:*}
   if mg_child_shell; then
    child_recorded=1
    mg_put child.offer "$child_pid:$child_ticks" || { mg_protocol_failed=1; break; }
   else mg_protocol_failed=1; break; fi
  else mg_protocol_failed=1; break; fi
 fi
 sleep .1
 mg_supervise=$((mg_supervise+1))
done
# Never race the cleanup trap of a surviving controller. The separate owner
# can request bounded termination only after proving the exact t lifetime.
if ! mg_dead "$mg_controller_pid" "$mg_controller_ticks"; then
 if mg_role_process "$mg_controller_pid" "$mg_controller_ticks" t; then
  kill -TERM "$mg_controller_pid" || :
 else
  # A role read may race this exact controller's death. Never signal an
  # unverified lifetime, but do not abandon recovery after proven death.
  mg_dead "$mg_controller_pid" "$mg_controller_ticks" || exit 79
 fi
 mg_end_wait=0
 while ! mg_dead "$mg_controller_pid" "$mg_controller_ticks" && [ "$mg_end_wait" -lt 50 ]; do sleep .1; mg_end_wait=$((mg_end_wait+1)); done
 if ! mg_dead "$mg_controller_pid" "$mg_controller_ticks"; then
  if mg_role_process "$mg_controller_pid" "$mg_controller_ticks" t; then
   kill -KILL "$mg_controller_pid" || :
  else mg_dead "$mg_controller_pid" "$mg_controller_ticks" || exit 79; fi
 fi
 mg_end_wait=0
 while ! mg_dead "$mg_controller_pid" "$mg_controller_ticks" && [ "$mg_end_wait" -lt 20 ]; do sleep .1; mg_end_wait=$((mg_end_wait+1)); done
 mg_dead "$mg_controller_pid" "$mg_controller_ticks" || exit 79
fi
ml_status=0
wait "$mg_controller_pid" || ml_status=$?
if [ "$mg_protocol_failed" = 1 ] && [ "$ml_status" = 0 ]; then ml_status=79; fi
if [ "$recover_needed" = 1 ]; then
 # A pending cancel writer may outlive its controller. Its bytes grant no
 # authority and remain untouched. Recovery instead needs exact recorded
 # child termination, or no admission plus proof no gate lifetime remains.
 if [ "$child_recorded" != 1 ]; then
  mg_transaction &&
  ml_absent "$ml_run/child.offer" && ml_absent "$ml_run/child.offer.pending" &&
  ml_absent "$ml_run/child.admit" && ml_absent "$ml_run/child.admit.pending" || exit 79
  if [ "$mg_child_offered" = 0 ]; then
   [ -z "$child_pid" ] || exit 79
  else
   [ "$mg_child_offered" = 1 ] && x2dii_sc_scalar pid "$child_pid" &&
   x2dii_sc_scalar ticks "$child_ticks" && child_exited || exit 79
  fi
  child_pid=''
 fi
 if ! stop_owned_child; then
  printf '%s\n' X2DII_TEMPORARY_RECOVERY_FAILED_RETAIN_ATTEMPT_AND_FILES >> "$ml_run/lifecycle.log"
  ml_status=79
 elif ml_absent /tmp/x2dii-menu-install.lock; then
  if ! original_gui_running || ! unchanged_core || ! readonly_system; then ml_status=79; fi
 else
  if ! mg_transaction || ! ml_equals "$mg_lock_identity" stat -c '%d:%i' /tmp/x2dii-menu-install.lock; then
   ml_status=79
  else
   mg_recovered_status=0
   (trap temporary_finish EXIT; exit "$ml_status") >> "$ml_run/lifecycle.log" 2>&1 || mg_recovered_status=$?
   ml_status=$mg_recovered_status
  fi
 fi
fi
'''
    temporary_sha256 = peer.sha(temporary.encode('ascii'))
    worker = replace_once(worker, 'TEMPORARY_CONTROLLER_HASH', temporary_sha256)
    worker = replace_once(worker, 'TEMPORARY_GATE_HASH', temporary_sha256)
    return temporary, worker


def _menu_query_source():
    """Read the existing transaction log, with no collector or device writes."""
    return r'''
ml_menu_unknown() { printf 'X2DII_MENU_UNKNOWN:%s:%s\n' "$ml_sha" "$1"; }
ml_menu_bounded_hash() {
 # The completion suffix is present only if the native bounded reader succeeds.
 # Pipeline status alone cannot turn a failed/partial read into success.
 { head -c 65537 "$ml_menu_log" && printf X2DII_MENU_BOUNDED_READ_OK; } | sha256sum
}
ml_menu_writer() {
 for ml_menu_fd in 1 2; do
  ml_equals "$ml_menu_log" readlink "/proc/$ml_menu_pid/fd/$ml_menu_fd" &&
  ml_equals "$ml_menu_log_identity" stat -Lc '%d:%i' "/proc/$ml_menu_pid/fd/$ml_menu_fd" || return 1
 done
}
ml_menu_identity() {
 ml_boundary && ml_fresh && ml_claim && ml_owner && ml_absent "$ml_run/final" || return 1
 ml_private "$ml_transaction" &&
 ml_equals "$ml_menu_directory_identity" stat -c '%d:%i' "$ml_transaction" || return 1
 ml_regular "$ml_transaction/attempt" && ml_hash "$ml_transaction/attempt" "$ml_menu_attempt_hash" || return 1
 ml_equals "$ml_menu_admit" ml_line "$ml_run/child.admit" &&
 ml_equals "$ml_menu_admit" ml_line "$ml_run/child.offer" || return 1
 ml_regular "$ml_transaction/child.identity" &&
 ml_hash "$ml_transaction/child.identity" "$ml_menu_child_hash" || return 1
 ml_equals "$ml_menu_ticks" ml_birth "$ml_menu_pid" &&
 ml_equals "$X2DII_SESSION_CORE_GUI_EXE_TARGET" readlink "/proc/$ml_menu_pid/exe" &&
 ml_hash "/proc/$ml_menu_pid/exe" "$X2DII_SESSION_CORE_GUI_EXE_SHA256" &&
 ml_equals "$X2DII_SESSION_CORE_GUI_DOMAIN" cat "/proc/$ml_menu_pid/attr/current" &&
 ml_equals "$X2DII_SESSION_CORE_GUI_MOUNT_NAMESPACE" readlink "/proc/$ml_menu_pid/ns/mnt" &&
 ml_equals "$ml_menu_ticks" ml_birth "$ml_menu_pid"
}
ml_menu_parse() (
 set -f
 mm_sequence=0; mm_generation=0; mm_previous=''; mm_last=''
 while IFS= read -r mm_line; do
  case "$mm_line" in
   'qml: X2DII_MENU_STATE_V1:'*) mm_record=${mm_line#'qml: X2DII_MENU_STATE_V1:'};;
   'X2DII_MENU_STATE_V1:'*) mm_record=${mm_line#'X2DII_MENU_STATE_V1:'};;
   *X2DII_MENU_STATE_V1*) return 1;;
   *) continue;;
  esac
  if [ "$mm_record" = OVERFLOW ]; then printf OVERFLOW; return 0; fi
  IFS=:; set -- $mm_record; IFS=' '
  [ "$#" = 8 ] && [ "$mm_record" = "$1:$2:$3:$4:$5:$6:$7:$8" ] || return 1
  case "$1" in ''|0*|*[!0-9]*) return 1;; esac
  [ "${#1}" -le 3 ] && [ "$1" -le 256 ] || return 1
  for mm_bit in "$2" "$3" "$4" "$5" "$6"; do
   case "$mm_bit" in 0|1) :;; *) return 1;; esac
  done
  case "$7" in -1|0|[1-9]|1[0-2]) :;; *) return 1;; esac
  case "$8" in -1|0|[1-9]|1[01]) :;; *) return 1;; esac
  if [ "$2" = 1 ]; then [ "$3" = 1 ] && [ "$4" = 1 ] && [ "$8" -ge 0 ] && [ "$8" -lt "$7" ] || return 1; fi
  [ "$5" = 0 ] || [ "$2" = 1 ] || return 1
  [ "$6" = 0 ] || [ "$5" = 1 ] || return 1
  [ "$4" = 0 ] || [ "$8" -ge 0 ] || return 1
  if [ "$1" = 1 ]; then
   # A new Loader starts unavailable. Only an observed detached/unavailable
   # predecessor may precede its reset; old ready cannot cross generations.
   [ "$mm_record" = '1:0:0:0:0:0:-1:-1' ] || return 1
   [ "$mm_sequence" = 0 ] || [ "$mm_previous" = '0:0:0:0:0:-1:-1' ] || return 1
   mm_generation=$((mm_generation+1))
   [ "$mm_generation" -le 256 ] || return 1
  else [ "$mm_sequence" -gt 0 ] && [ "$1" = "$((mm_sequence+1))" ] || return 1; fi
  mm_sequence=$1; mm_previous=${mm_record#*:}; mm_last=$mm_record
 done <<X2DII_MENU_SNAPSHOT_DATA_END
$ml_menu_snapshot
X2DII_MENU_SNAPSHOT_DATA_END
 if [ -n "$mm_last" ]; then printf '%s:%s' "$mm_generation" "$mm_last"; else printf NOT_READY; fi
)
ml_menu_query() {
 export LC_ALL=C
 if ! ml_absent "$ml_run/final"; then ml_menu_unknown INACTIVE; return; fi
 if ml_absent "$ml_transaction/child.identity" || ml_absent "$ml_transaction/gui.log"; then
  ml_menu_unknown NOT_READY; return
 fi
 ml_menu_admit=$(ml_line "$ml_run/child.admit") || { ml_menu_unknown IDENTITY_CHANGED; return; }
 ml_menu_pid=${ml_menu_admit%%:*}; ml_menu_ticks=${ml_menu_admit#*:}
 x2dii_sc_scalar pid "$ml_menu_pid" && x2dii_sc_scalar ticks "$ml_menu_ticks" || { ml_menu_unknown IDENTITY_CHANGED; return; }
 ml_menu_directory_identity=$(ml_line "$ml_transaction/directory.identity") || { ml_menu_unknown IDENTITY_CHANGED; return; }
 ml_menu_attempt=$(printf 'candidate=%s\nnonce=%s\npurpose=temporary_menu_validation\naction=run_and_restore\n' "$X2DII_SESSION_CANDIDATE_SHA256" "$X2DII_SESSION_SESSION_NONCE" | sha256sum) || return 1
 ml_menu_attempt_hash=${ml_menu_attempt%% *}
 ml_menu_child=$(printf 'pid=%s\nstart_ticks=%s\nexe=%s\nsha256=%s\ndomain=%s\nnamespace=%s\n' "$ml_menu_pid" "$ml_menu_ticks" "$X2DII_SESSION_CORE_GUI_EXE_TARGET" "$X2DII_SESSION_CORE_GUI_EXE_SHA256" "$X2DII_SESSION_CORE_GUI_DOMAIN" "$X2DII_SESSION_CORE_GUI_MOUNT_NAMESPACE" | sha256sum) || return 1
 ml_menu_child_hash=${ml_menu_child%% *}
 ml_menu_identity || { ml_menu_unknown IDENTITY_CHANGED; return; }
 ml_menu_log="$ml_transaction/gui.log"
 ml_regular "$ml_menu_log" || { ml_menu_unknown INVALID_LOG; return; }
 ml_menu_log_identity=$(stat -c '%d:%i' "$ml_menu_log") || return 1
 ml_menu_writer || { ml_menu_unknown IDENTITY_CHANGED; return; }
 ml_menu_bytes=$(stat -c %s "$ml_menu_log") || return 1
 case "$ml_menu_bytes" in ''|*[!0-9]*) return 1;; esac
 [ "$ml_menu_bytes" -le 65536 ] || { ml_menu_unknown INVALID_LOG; return; }
 # Read at most cap+1 bytes even if the GUI appends after stat. No whole-file
 # hash/cat can silently consume an unbounded growing log here.
 ml_menu_snapshot=$(head -c 65537 "$ml_menu_log" && printf X) || return 1
 ml_menu_snapshot=${ml_menu_snapshot%X}
 [ "${#ml_menu_snapshot}" -le 65536 ] && [ "${#ml_menu_snapshot}" = "$ml_menu_bytes" ] || { ml_menu_unknown INVALID_LOG; return; }
 ml_menu_native=$(ml_menu_bounded_hash) || return 1
 ml_menu_marked=$(printf '%sX2DII_MENU_BOUNDED_READ_OK' "$ml_menu_snapshot" | sha256sum) || return 1
 [ "${ml_menu_native%% *}" = "${ml_menu_marked%% *}" ] || { ml_menu_unknown INVALID_LOG; return; }
 ml_menu_reconstructed=$(printf '%s' "$ml_menu_snapshot" | sha256sum) || return 1
 ml_menu_log_hash=${ml_menu_reconstructed%% *}
 case "$ml_menu_snapshot" in ''|*'
') :;; *) ml_menu_unknown INVALID_LOG; return;; esac
 ml_menu_state=$(ml_menu_parse) || { ml_menu_unknown INVALID_LOG; return; }
 # Recheck the path inode/size after the final native read. Checking them
 # before hashing misses same-byte replacement during that last read.
 ml_regular "$ml_menu_log" && ml_equals "$ml_menu_native" ml_menu_bounded_hash &&
 ml_equals "$ml_menu_log_identity" stat -c '%d:%i' "$ml_menu_log" &&
 ml_equals "$ml_menu_bytes" stat -c %s "$ml_menu_log" || { ml_menu_unknown SNAPSHOT_CHANGED; return; }
 ml_menu_writer && ml_menu_identity || { ml_menu_unknown IDENTITY_CHANGED; return; }
 case "$ml_menu_state" in OVERFLOW|NOT_READY) ml_menu_unknown "$ml_menu_state";;
  *) printf 'X2DII_MENU_SNAPSHOT:%s:%s:%s:%s:%s\n' "$ml_sha" "$ml_menu_pid" "$ml_menu_ticks" "$ml_menu_log_hash" "$ml_menu_state";;
 esac
}
'''


def render_programs(manifest):
    """Pure fixed sources with two identity-bound local recovery owners.

    There is no shell text, PID, path or arbitrary action supplied by the host.
    `l` detaches `w`; `w` admits `t` before its first GUI stop and guards the
    fixed child launch. `t` retains its own cleanup if `w` disappears. `w` can
    recover only after proving `t` has ended, then retains its actual receipt.
    """
    from . import prepare_peer_install as peer
    digest = boundary._candidate(manifest)
    root = "/tmp/x2mb-" + digest[:12]
    stage = "/blackbox/x2dii-menu-stage/" + digest[:24]
    legacy = peer.render_temporary_menu_session(manifest)
    admission = '[ "$#" = 2 ] || exit 32\nx2dii_load_session "$1" "$2" || exit 32\n'
    if legacy.count(admission) != 1:
        raise ValueError("temporary lifecycle admission changed")
    temporary = legacy.replace(admission, f'''[ "$#" = 1 ] || exit 32
x2dii_sc_scalar hex64 "$1" || exit 32
x2dii_load_session "{stage}/session-context-$1.data" "$1" || exit 32
''', 1)
    transaction_created = 'private_directory "$transaction" || exit 33\n'
    if temporary.count(transaction_created) != 1:
        raise ValueError("temporary transaction ownership changed")
    temporary = temporary.replace(transaction_created, transaction_created + '''temporary_directory_identity=$(stat -c '%d:%i' "$transaction") || exit 33
(set -C; printf '%s\\n' "$temporary_directory_identity" > "$transaction/directory.identity") || exit 33
''', 1)
    common = f'''#!/system/bin/sh
# Fixed temporary lifecycle bridge; not an installation or qualification.
set -eu
export PATH=/system/bin:/system/xbin:/sbin
# SESSION_DATA_PARSER_BEGIN
{sc.shell_parser()}
# SESSION_DATA_PARSER_END
[ "$#" = 1 ] && x2dii_sc_scalar hex64 "$1" || exit 32
ml_sha=$1
ml_root={root}
x2dii_load_session "{stage}/session-context-$ml_sha.data" "$ml_sha" || exit 32
[ "$X2DII_SESSION_KIND" = menu_validation ] &&
[ "$X2DII_SESSION_SCHEMA" = x2dii-session-context-v3 ] &&
[ "$X2DII_SESSION_PURPOSE" = temporary_menu_validation ] &&
[ "$X2DII_SESSION_ACTION" = run_and_restore ] &&
[ "$X2DII_SESSION_CANDIDATE_SHA256" = {digest} ] || exit 32
ml_run="/tmp/x2ml-{digest[:12]}-$X2DII_SESSION_SESSION_NONCE"
ml_transaction="/tmp/x2dii-menu-validation-$X2DII_SESSION_SESSION_NONCE"
ml_equals() {{ ml_expected=$1; shift; ml_actual=$("$@") || return 1; [ "$ml_actual" = "$ml_expected" ]; }}
ml_absent() {{ [ ! -e "$1" ] && [ ! -L "$1" ]; }}
ml_private() {{ [ -d "$1" ] && [ ! -L "$1" ] && ml_equals 0:0:700 stat -c '%u:%g:%a' "$1"; }}
ml_regular() {{ [ -f "$1" ] && [ ! -L "$1" ] && ml_equals 1 stat -c %h "$1" && ml_equals 0:0:600 stat -c '%u:%g:%a' "$1"; }}
ml_hash() {{ ml_hash_actual=$(sha256sum "$1") || return 1; [ "${{ml_hash_actual%% *}}" = "$2" ]; }}
ml_boundary() {{
 ml_equals 0 id -u && ml_equals u:r:hbl_camera_service:s0 cat /proc/self/attr/current &&
 ml_equals "$X2DII_SESSION_BOOT_ID" cat /proc/sys/kernel/random/boot_id &&
 ml_equals "$X2DII_SESSION_MOUNT_NAMESPACE" readlink /proc/self/ns/mnt &&
 ml_equals "$X2DII_SESSION_INIT_MOUNT_NAMESPACE" readlink /proc/1/ns/mnt
}}
ml_fresh() {{
 ml_now=$(date -u +%s) || return 1
 x2dii_sc_scalar epoch "$ml_now" && [ "$ml_now" -ge "$X2DII_SESSION_OBSERVED_EPOCH" ] &&
 [ "$ml_now" -le "$((X2DII_SESSION_OBSERVED_EPOCH+600))" ]
}}
ml_line() {{
 ml_regular "$1" || return 1
 ml_count=$(stat -c %s "$1") || return 1
 case "$ml_count" in ''|*[!0-9]*) return 1;; esac
 [ "$ml_count" -gt 0 ] && [ "$ml_count" -le 200 ] || return 1
 ml_text=$(cat "$1") || return 1
 # Exact reconstruction rejects embedded NUL, extra newline and non-EOF bytes.
 ml_equals "$(( ${{#ml_text}} + 1 ))" stat -c %s "$1" || return 1
 ml_reconstructed=$(printf '%s\\n' "$ml_text" | sha256sum) || return 1
 ml_hash "$1" "${{ml_reconstructed%% *}}" || return 1
 printf '%s' "$ml_text"
}}
ml_claim() {{
 ml_private "$ml_run" && ml_equals "$ml_sha" ml_line "$ml_run/attempt" || return 1
 ml_directory_identity=$(ml_line "$ml_run/directory.identity") || return 1
 ml_equals "$ml_directory_identity" stat -c '%d:%i' "$ml_run"
}}
ml_birth() {{
 ml_stat=$(cat "/proc/$1/stat") || return 1
 ml_tail=${{ml_stat##*) }}
 [ "$ml_stat" != "$ml_tail" ] || return 1
 set -f
 set -- $ml_tail
 [ "$#" -ge 20 ] || return 1
 shift 19
 x2dii_sc_scalar ticks "$1" || return 1
 printf '%s\\n' "$1"
}}
ml_owner() {{
 ml_identity=$(ml_line "$ml_run/worker.identity") || return 1
 ml_pid=${{ml_identity%%:*}}
 ml_ticks=${{ml_identity#*:}}
 x2dii_sc_scalar pid "$ml_pid" && x2dii_sc_scalar ticks "$ml_ticks" &&
 ml_equals "$ml_ticks" ml_birth "$ml_pid" &&
 ml_equals u:r:hbl_camera_service:s0 cat "/proc/$ml_pid/attr/current" &&
 ml_equals "$X2DII_SESSION_MOUNT_NAMESPACE" readlink "/proc/$ml_pid/ns/mnt" &&
 ml_equals "$ml_ticks" ml_birth "$ml_pid"
}}
ml_boundary && ml_private "$ml_root" || exit 31
umask 077
'''
    temporary, worker = _guarded_sources(temporary, common, manifest)
    worker += f'''
ml_boundary && ml_claim && ml_owner || exit 33
set -C
exec 3>"$ml_run/final.pending"
set +C
ml_final_identity=$(stat -Lc '%d:%i' /proc/self/fd/3) || exit 33
printf '%s:%s\\n' "$ml_sha" "$ml_status" >&3 || exit 33
exec 3>&-
ml_final_hash=$(printf '%s:%s\\n' "$ml_sha" "$ml_status" | sha256sum) || exit 33
ml_pending_owned() {{
 ml_regular "$ml_run/final.pending" &&
 ml_equals "$ml_final_identity" stat -c '%d:%i' "$ml_run/final.pending" &&
 ml_hash "$ml_run/final.pending" "${{ml_final_hash%% *}}"
}}
ml_pending_owned || exit 33
ml_boundary && ml_claim && ml_owner && ml_absent "$ml_run/final" || exit 33
ml_pending_owned || exit 33
mv -n "$ml_run/final.pending" "$ml_run/final" || exit 33
ml_absent "$ml_run/final.pending" && ml_regular "$ml_run/final" || exit 33
ml_equals "$ml_final_identity" stat -c '%d:%i' "$ml_run/final" &&
ml_hash "$ml_run/final" "${{ml_final_hash%% *}}" || exit 33
'''
    launcher = common + f'''
ml_fresh || exit 32
ml_regular "$ml_root/w" && ml_hash "$ml_root/w" {peer.sha(worker.encode('ascii'))} &&
ml_regular "$ml_root/t" && ml_hash "$ml_root/t" {peer.sha(temporary.encode('ascii'))} || exit 33
ml_absent "$ml_run" && ml_absent "$ml_transaction" || exit 33
mkdir "$ml_run" && ml_private "$ml_run" || exit 33
(set -C; printf '%s\\n' "$ml_sha" > "$ml_run/attempt") || exit 33
ml_directory_identity=$(stat -c '%d:%i' "$ml_run") || exit 33
(set -C; printf '%s\\n' "$ml_directory_identity" > "$ml_run/directory.identity") || exit 33
# All descriptors are detached. Returning a PID is deliberately not success.
(set -C; nohup /system/bin/sh "$ml_root/w" "$ml_sha" > "$ml_run/worker.log" 2>&1 < /dev/null &)
printf 'X2DII_LIFECYCLE_STARTED_NOT_VALIDATED:%s\\n' "$ml_sha"
'''
    reader_common = common.replace('[ "$#" = 1 ] && x2dii_sc_scalar hex64 "$1" || exit 32\n',
        '[ "$#" = 1 ] || { [ "$#" = 2 ] && [ "$2" = menu ]; } || exit 32\nx2dii_sc_scalar hex64 "$1" || exit 32\n', 1)
    if reader_common == common:
        raise ValueError("fixed menu query admission anchor changed")
    reader = reader_common + _menu_query_source() + '''
ml_claim || exit 33
if [ "${2-}" = menu ]; then ml_menu_query || exit 33; exit 0; fi
if ! ml_absent "$ml_run/final"; then
 ml_final=$(ml_line "$ml_run/final") || exit 33
 [ "${ml_final%%:*}" = "$ml_sha" ] || exit 33
 ml_exit=${ml_final#*:}
 case "$ml_exit" in 0|[1-9]|[1-9][0-9]|[1-9][0-9][0-9]) :;; *) exit 33;; esac
 [ "$ml_exit" -le 255 ] || exit 33
 ml_final_sha=$(sha256sum "$ml_run/final") || exit 33
 printf 'X2DII_LIFECYCLE_FINAL:%s:%s:%s:NOT_FEATURE_VALIDATED\\n' "$ml_sha" "${ml_final_sha%% *}" "$ml_exit"
elif ml_absent "$ml_run/worker.identity"; then
 printf 'X2DII_LIFECYCLE_PENDING:%s:AWAITING_WORKER\\n' "$ml_sha"
elif ml_owner; then
 printf 'X2DII_LIFECYCLE_PENDING:%s:WORKER_OBSERVED\\n' "$ml_sha"
else
 printf 'X2DII_LIFECYCLE_UNCERTAIN:%s:NO_FINAL_RECEIPT\\n' "$ml_sha"
fi
'''
    stopper = common + f'''
ml_claim && ml_owner && ml_absent "$ml_run/final" && ml_private "$ml_transaction" || exit 33
ml_regular "$ml_transaction/attempt" || exit 33
ml_expected_attempt=$(printf 'candidate=%s\\nnonce=%s\\npurpose=temporary_menu_validation\\naction=run_and_restore\\n' {digest} "$X2DII_SESSION_SESSION_NONCE" | sha256sum) || exit 33
ml_hash "$ml_transaction/attempt" "${{ml_expected_attempt%% *}}" || exit 33
ml_transaction_identity=$(ml_line "$ml_transaction/directory.identity") || exit 33
ml_equals "$ml_transaction_identity" stat -c '%d:%i' "$ml_transaction" || exit 33
ml_boundary && ml_owner && ml_absent "$ml_run/final" && ml_absent "$ml_transaction/stop" || exit 33
ml_equals "$ml_transaction_identity" stat -c '%d:%i' "$ml_transaction" || exit 33
(set -C; printf '%s\\n' stop > "$ml_transaction/stop") || exit 33
printf 'X2DII_LIFECYCLE_STOP_REQUESTED_NOT_COMPLETED:%s\\n' "$ml_sha"
'''
    return {"l": launcher, "w": worker, "t": temporary, "q": reader, "s": stopper}
