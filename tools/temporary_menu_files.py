"""Pure single-file su renderer, NOT an independently deployable operation.

No publisher, transport, executor, recovery/removal operation or qualification
entry exists here. Maintenance-side fresh core/GUI/slot/namespace checks at
EVERY former write_ready boundary remain required and are NOT connected.
These self/file guards cannot replace that missing supervision. The source
must remain local until a separately reviewed fixed orchestration supplies it.

Only one of four developer-fixed paths can be selected at rendering time.
The open creation descriptor binds the first inode; failures retain both
partial and unexpected files. Cleanup only attempts its owned mount's return
to read-only. No maps scan or deletion is implemented.
"""
from __future__ import annotations

import hashlib
import json
import re

from .session_context import shell_parser


FILE_LAYOUT = (
    ("build/native/libx2dii_menu.so", "/system/lib64/libx2dii_menu.so", "LIBRARY_LABEL"),
    ("qml/X2d2MenuBootstrap.qml", "/system/etc/X2d2MenuBootstrap.qml", "BOOTSTRAP_LABEL"),
    ("qml/X2d2MenuModel.qml", "/system/etc/X2d2MenuModel.qml", "MODEL_LABEL"),
    ("qml/X2d2MenuPage.qml", "/system/etc/X2d2MenuPage.qml", "PAGE_LABEL"),
)
MAX_PAYLOAD_BYTES = 8 * 1024 * 1024 - 1  # Same strict member bound as delivery_files.
STATUS = "LOCAL_SOURCE_MAINTENANCE_BOUNDARIES_UNCONNECTED"


def render_preplacement(manifest, *, file_index):
    """Return fixed single-file prepare/commit source, without any I/O.

    Runtime inputs are only the fixed staged v3 data path and its expected
    hash. Data describes the operation but grants no authority. Caller-supplied
    file paths, runtime index selectors and arbitrary commands are unsupported.
    This is one process: ownership is never reconstructed from a saved receipt.
    Target stat -L, descriptor inheritance, no-clobber rename, actual labels and
    exclusive maintenance remain unverified target requirements.
    """
    if type(file_index) is not int or not 0 <= file_index < len(FILE_LAYOUT):
        raise ValueError("compile-time file_index must be one of 0, 1, 2, 3")
    if type(manifest) is not dict or type(manifest.get("candidate")) is not dict:
        raise ValueError("fixed candidate manifest required")
    candidate = manifest["candidate"]
    digest = hashlib.sha256(json.dumps(candidate, sort_keys=True, ensure_ascii=False,
                                      separators=(",", ":")).encode()).hexdigest()
    if manifest.get("candidate_sha256") != digest:
        raise ValueError("exact candidate hash differs")
    entries = candidate.get("files")
    if type(entries) is not list or len(entries) != len(FILE_LAYOUT):
        raise ValueError("exact four-file candidate required")
    for entry, (source, target, _) in zip(entries, FILE_LAYOUT):
        if (type(entry) is not dict or set(entry) != {"source", "target", "sha256", "bytes"}
                or entry["source"] != source or entry["target"] != target
                or type(entry["sha256"]) is not str
                or re.fullmatch("[0-9a-f]{64}", entry["sha256"]) is None
                or type(entry["bytes"]) is not int or not 0 < entry["bytes"] <= MAX_PAYLOAD_BYTES):
            raise ValueError("developer-fixed payload layout or identity differs")
    entry = entries[file_index]
    source_name, target, label = FILE_LAYOUT[file_index]
    parent = target.rsplit("/", 1)[0]
    stage = "/blackbox/x2dii-menu-stage/" + digest[:24]
    head = """#!/system/bin/sh
# LOCAL SOURCE ONLY. Fresh maintenance checks at write boundaries ARE NOT CONNECTED.
# No publication, camera execution, authority, feature validation or removal.
set -eu
export PATH=/system/bin:/system/xbin:/sbin
# SESSION_DATA_PARSER_BEGIN
""" + shell_parser() + """# SESSION_DATA_PARSER_END
"""
    body = r'''[ "$#" = 2 ] || exit 32
[ "$(id -u)" = 0 ] && [ "$(cat /proc/self/attr/current)" = u:r:su:s0 ] || exit 31
[ "$1" = '@STAGE@/session-context.data' ] || exit 32
x2dii_load_session "$1" "$2" || exit 32
[ "$X2DII_SESSION_SCHEMA" = x2dii-session-context-v3 ] &&
[ "$X2DII_SESSION_KIND" = menu_validation ] &&
[ "$X2DII_SESSION_PURPOSE" = temporary_menu_validation ] &&
[ "$X2DII_SESSION_ACTION" = run_and_restore ] &&
[ "$X2DII_SESSION_CANDIDATE_SHA256" = '@DIGEST@' ] || exit 32
source='@STAGE@/@SOURCE@'
target='@TARGET@'
temporary="@PARENT@/.x2dii-preplace-@SHORT@-$X2DII_SESSION_SESSION_NONCE-@INDEX@"
expected_label="$X2DII_SESSION_@LABEL@"
baseline="$X2DII_SESSION_MOUNT_DEVICE $X2DII_SESSION_MOUNT_FILESYSTEM $X2DII_SESSION_MOUNT_OPTIONS"
rw="$X2DII_SESSION_MOUNT_DEVICE $X2DII_SESSION_MOUNT_FILESYSTEM rw,${X2DII_SESSION_MOUNT_OPTIONS#ro,}"
mount_owned=0
created=0
committed=0
owned_inode=''
equals() {
 expected=$1
 shift
 observed=$("$@") || return 1
 [ "$observed" = "$expected" ]
}
hashok() {
 actual=$(sha256sum "$1") || return 1
 [ "${actual%% *}" = "$2" ]
}
absent() { [ ! -e "$1" ] && [ ! -L "$1" ]; }
regular() { [ -f "$1" ] && [ ! -L "$1" ] && equals 1 stat -c %h "$1"; }
identityok() (
 [ "${#1}" -le 160 ] || return 1
 case "$1" in ''|*[!0-9a-f:]*|*::*|:*|*:) return 1;; esac
 IFS=:
 set -- $1
 [ "$#" = 7 ] && [ "$4" = 1 ]
)
labelok() {
 label_path=$1
 observed_label=$(ls -Zd "$1") || return 1
 set -- $observed_label
 [ "$#" = 2 ] && [ "$1" = "$expected_label" ] && [ "$2" = "$label_path" ] || return 1
 actual_label=$1
}
state() (
 set -f
 while :; do
  mount_line=''
  if IFS= read -r mount_line; then
   set -- $mount_line
   [ "$#" = 6 ] || return 1
   if [ "$2" = /system ]; then printf '%s %s %s\n' "$1" "$3" "$4" || return 1; fi
  else
   read_status=$?
   [ "$read_status" = 1 ] && [ -z "$mount_line" ] || return 1
   break
  fi
 done < /proc/mounts
)
self_identity() {
 equals 0 id -u && equals u:r:su:s0 cat /proc/self/attr/current || return 1
 equals "$X2DII_SESSION_BOOT_ID" cat /proc/sys/kernel/random/boot_id || return 1
 equals "$X2DII_SESSION_MOUNT_NAMESPACE" readlink /proc/self/ns/mnt
}
fresh() {
 now=$(date -u +%s) || return 1
 x2dii_sc_scalar epoch "$now" || return 1
 [ "$now" -ge "$X2DII_SESSION_OBSERVED_EPOCH" ] &&
 [ "$now" -le "$((X2DII_SESSION_OBSERVED_EPOCH + 600))" ]
}
ready() {
 self_identity && equals "$1" state && fresh
}
path_owned() {
 [ "$created" = 1 ] && regular "$temporary" || return 1
 equals "$owned_inode" stat -c '%d:%i' "$temporary"
}
payload() {
 regular "$1" && equals '@BYTES@' stat -c %s "$1" && hashok "$1" '@HASH@'
}
restore_ro() {
 [ "$mount_owned" = 1 ] || return 0
 self_identity || return 1
 current=$(state) || return 1
 if [ "$current" = "$rw" ]; then mount -o remount,ro /system || return 1
 else [ "$current" = "$baseline" ] || return 1; fi
 equals "$baseline" state
}
finish() {
 result=$?
 trap - EXIT HUP INT TERM
 exec 3>&-
 restore_ro || result=72
 if [ "$result" != 0 ]; then
  printf 'X2DII_PREPLACEMENT_FAILED:%s; retained-created=%s; committed=%s; no file removed\n' "$result" "$created" "$committed" >&2
  exit "$result"
 fi
 [ "$committed" = 1 ] || exit 73
 # This bounded readback binds the final owned object, not merely equal bytes.
 # It is not authorization or proof of the still-missing maintenance boundary.
 ready "$baseline" && payload "$target" &&
 equals '0 0 644' stat -c '%u %g %a' "$target" && labelok "$target" || exit 73
 final_identity=$(stat -c '%d:%i:%f:%h:%s:%u:%g' "$target") || exit 73
 identityok "$final_identity" && [ "$final_identity" = "$prepared_identity" ] || exit 73
 final_hash_line=$(sha256sum "$target") || exit 73
 final_hash=${final_hash_line%% *}
 [ "$final_hash" = '@HASH@' ] && ready "$baseline" && labelok "$target" &&
 equals "$prepared_identity" stat -c '%d:%i:%f:%h:%s:%u:%g' "$target" || exit 73
 printf 'schema=x2dii-one-file-preplacement-v1\ncandidate_sha256=@DIGEST@\nsession_nonce=%s\nfile_index=@INDEX@\nidentity=%s\nlabel=%s\nsha256=%s\nmaintenance_boundaries=UNCONNECTED\n' \
  "$X2DII_SESSION_SESSION_NONCE" "$final_identity" "$actual_label" "$final_hash" || exit 73
 printf '%s\n' X2DII_ONE_FILE_PREPLACED_NOT_RUNTIME_VALIDATED
}
trap finish EXIT
trap 'exit 74' HUP INT TERM
# Source and ancestors are also covered by the fixed session parser's path checks.
[ -d '@PARENT@' ] && [ ! -L '@PARENT@' ] &&
[ -d /system ] && [ ! -L /system ] || exit 33
equals '0 0 700' stat -c '%u %g %a' '@STAGE@' || exit 33
payload "$source" && absent "$temporary" && absent "$target" || exit 33
ready "$baseline" || exit 32
mount_owned=1
mount -o remount,rw /system
ready "$rw" || exit 32
umask 077
set -C
exec 3>"$temporary"
set +C
created=1
# The inherited open descriptor, not a later pathname, freezes the first inode.
owned_inode=$(stat -Lc '%d:%i' /proc/self/fd/3)
created_identity=$(stat -Lc '%d:%i:%f:%h:%s:%u:%g' /proc/self/fd/3)
identityok "$created_identity" || exit 33
printf 'X2DII_CREATED_FILE:@INDEX@:%s\n' "$created_identity"
path_owned && equals '0 0 600' stat -c '%u %g %a' "$temporary" && labelok "$temporary" || exit 33
payload "$source" || exit 33
ready "$rw" || exit 32
cat "$source" >&3
path_owned && payload "$temporary" && labelok "$temporary" || exit 33
ready "$rw" || exit 32
chmod 0644 "$temporary"
path_owned && payload "$temporary" &&
equals '0 0 644' stat -c '%u %g %a' "$temporary" && labelok "$temporary" || exit 33
prepared_identity=$(stat -c '%d:%i:%f:%h:%s:%u:%g' "$temporary")
identityok "$prepared_identity" || exit 33
sync
path_owned && equals "$prepared_identity" stat -c '%d:%i:%f:%h:%s:%u:%g' "$temporary" &&
payload "$temporary" && labelok "$temporary" && absent "$target" || exit 33
ready "$rw" || exit 32
mv -n "$temporary" "$target"
absent "$temporary" && payload "$target" &&
equals "$prepared_identity" stat -c '%d:%i:%f:%h:%s:%u:%g' "$target" &&
equals '0 0 644' stat -c '%u %g %a' "$target" && labelok "$target" || exit 33
committed=1
exec 3>&-
sync
restore_ro || exit 72
'''
    replacements = {"@STAGE@": stage, "@DIGEST@": digest, "@SHORT@": digest[:24],
                    "@SOURCE@": source_name.rsplit("/", 1)[-1], "@TARGET@": target,
                    "@PARENT@": parent, "@INDEX@": str(file_index), "@LABEL@": label,
                    "@BYTES@": str(entry["bytes"]), "@HASH@": entry["sha256"]}
    for token, value in replacements.items():
        body = body.replace(token, value)
    return head + body


def worker_path(manifest, file_index, *, session_kind):
    """Fixed per-role source names; temporary bytes cannot shadow final bytes."""
    if type(session_kind) is not str or session_kind not in ("menu_validation", "install"):
        raise ValueError("unsupported fixed preplacement session kind")
    render_preplacement(manifest, file_index=file_index)
    prefix = "menu-validation-preplace" if session_kind == "menu_validation" else "preplace"
    return "/blackbox/x2dii-menu-stage/" + manifest["candidate_sha256"][:24] + f"/{prefix}-{file_index}.sh"


def render_supervised_preplacement(manifest, *, file_index, session_kind="menu_validation"):
    """Same open-file transaction, pausing at each of its seven readies.

    The host must validate the actual fixed maintenance reply before writing
    an ACK to this same process. This renderer does not provide that transport
    or installation approval. Losing stdin, a deadline or a sequence stops
    mutation and leaves the original owned-mount recovery trap intact.
    """
    from . import menu_maintenance_boundary as boundary

    fixed_worker_path = worker_path(manifest, file_index, session_kind=session_kind)
    source = render_preplacement(manifest, file_index=file_index)
    digest = manifest["candidate_sha256"]
    stage = "/blackbox/x2dii-menu-stage/" + digest[:24]
    old_session = f'''[ "$1" = '{stage}/session-context.data' ] || exit 32
x2dii_load_session "$1" "$2" || exit 32'''
    new_session = f'''x2dii_sc_scalar hex64 "$2" || exit 32
[ "$1" = "{stage}/session-context-$2.data" ] || exit 32
x2dii_load_session "$1" "$2" || exit 32'''
    if source.count(old_session) != 1:
        raise ValueError("fixed preplacement session path admission changed")
    source = source.replace(old_session, new_session, 1)
    if session_kind == "install":
        temporary_admission = f'''[ "$X2DII_SESSION_SCHEMA" = x2dii-session-context-v3 ] &&
[ "$X2DII_SESSION_KIND" = menu_validation ] &&
[ "$X2DII_SESSION_PURPOSE" = temporary_menu_validation ] &&
[ "$X2DII_SESSION_ACTION" = run_and_restore ] &&
[ "$X2DII_SESSION_CANDIDATE_SHA256" = '{digest}' ] || exit 32'''
        if source.count(temporary_admission) != 1:
            raise ValueError("fixed preplacement session admission changed")
        source = source.replace(temporary_admission, '''[ "$X2DII_SESSION_SCHEMA" = x2dii-session-context-v2 ] &&
[ "$X2DII_SESSION_KIND" = install ] &&
[ "$X2DII_SESSION_OBSERVER_DOMAIN" = u:r:hbl_camera_service:s0 ] || exit 32''', 1)
    observer_hash = hashlib.sha256(boundary.render_observer(manifest, session_kind=session_kind).encode("ascii")).hexdigest()
    expected_stages = ((0, "remount_rw", "ro"), (1, "create_temp", "rw"),
                       (2, "write_payload", "rw"), (3, "chmod", "rw"),
                       (4, "commit_rename", "rw"), (5, "final_identity", "ro"),
                       (6, "final_receipt", "ro"))
    if boundary.STAGES != expected_stages:
        raise ValueError("maintenance observer and worker boundary sequence differ")
    guard = r'''
# Only the already-staged program may consume the stdin response channel.
worker_program='@WORKER_PATH@'
[ "$0" = "$worker_program" ] && regular "$worker_program" || exit 81
worker_program_identity=$(stat -c '%d:%i:%f:%h:%s:%u:%g' "$worker_program") || exit 81
worker_program_hash_line=$(sha256sum "$worker_program") || exit 81
worker_program_hash=${worker_program_hash_line%% *}
x2dii_sc_scalar hex64 "$worker_program_hash" || exit 81
worker_session_hash=$2
boundary_index=0
supervised_objects() {
 case "$boundary_index" in
  0|1)
   payload "$source" && absent "$temporary" && absent "$target";;
  2)
   path_owned && equals "$created_identity" stat -c '%d:%i:%f:%h:%s:%u:%g' "$temporary" &&
   equals '0 0 600' stat -c '%u %g %a' "$temporary" && labelok "$temporary" && payload "$source";;
  3)
   path_owned && payload "$temporary" && equals '0 0 600' stat -c '%u %g %a' "$temporary" &&
   labelok "$temporary" && path_owned;;
  4)
   path_owned && payload "$temporary" && equals '0 0 644' stat -c '%u %g %a' "$temporary" &&
   labelok "$temporary" && absent "$target" &&
   equals "$prepared_identity" stat -c '%d:%i:%f:%h:%s:%u:%g' "$temporary";;
  5|6)
   [ "$committed" = 1 ] && absent "$temporary" && payload "$target" &&
   equals '0 0 644' stat -c '%u %g %a' "$target" && labelok "$target" &&
   equals "$prepared_identity" stat -c '%d:%i:%f:%h:%s:%u:%g' "$target";;
  *) return 1;;
 esac
}
supervised_ready() {
 self_identity && equals "$1" state && fresh || return 1
 equals "$worker_program_identity" stat -c '%d:%i:%f:%h:%s:%u:%g' "$worker_program" &&
 hashok "$worker_program" "$worker_program_hash" || exit 81
 case "$boundary_index:$1" in
  "0:$baseline") boundary_name=remount_rw; mount_access=ro;;
  "1:$rw") boundary_name=create_temp; mount_access=rw;;
  "2:$rw") boundary_name=write_payload; mount_access=rw;;
  "3:$rw") boundary_name=chmod; mount_access=rw;;
  "4:$rw") boundary_name=commit_rename; mount_access=rw;;
  "5:$baseline") boundary_name=final_identity; mount_access=ro;;
  "6:$baseline") boundary_name=final_receipt; mount_access=ro;;
  *) exit 81;;
 esac
 issued_epoch=$(date -u +%s) || exit 81
 x2dii_sc_scalar epoch "$issued_epoch" && fresh || exit 81
 # A fresh nonce and no-clobber request path make this a single session use.
 # The challenge correlates a response; it is not cryptographic authority.
 challenge_line=$(printf '%s\n' "$X2DII_SESSION_BOOT_ID:$X2DII_SESSION_SESSION_NONCE:@INDEX@:$boundary_index:$worker_program_hash" | sha256sum) || exit 81
 challenge=${challenge_line%% *}
 x2dii_sc_scalar hex64 "$challenge" || exit 81
 request='@STAGE@/.boundary-@INDEX@-'"$boundary_index"'.data'
 absent "$request" || exit 81
 (set -C; umask 077; printf '%s\n' \
  'schema=x2dii-menu-maintenance-request-v1' \
  'candidate_sha256=@DIGEST@' \
  "boot_id=$X2DII_SESSION_BOOT_ID" \
  "session_nonce=$X2DII_SESSION_SESSION_NONCE" \
  'file_index=@INDEX@' \
  "boundary_index=$boundary_index" \
  "boundary_name=$boundary_name" \
  "mount_access=$mount_access" \
  "worker_program_sha256=$worker_program_hash" \
  "worker_session_sha256=$worker_session_hash" \
  'maintenance_program_sha256=@OBSERVER_HASH@' \
  "maintenance_session_sha256=$worker_session_hash" \
  "challenge=$challenge" \
  "observed_epoch=$X2DII_SESSION_OBSERVED_EPOCH" \
  "issued_epoch=$issued_epoch" \
  "deadline_epoch=$((X2DII_SESSION_OBSERVED_EPOCH+600))" > "$request") || exit 81
 regular "$request" && equals '0 0 600' stat -c '%u %g %a' "$request" || exit 81
 request_identity=$(stat -c '%d:%i:%f:%h:%s:%u:%g' "$request") || exit 81
 request_hash_line=$(sha256sum "$request") || exit 81
 request_hash=${request_hash_line%% *}
 x2dii_sc_scalar hex64 "$request_hash" || exit 81
 printf 'X2DII_BOUNDARY_REQUEST:@INDEX@:%s:%s\n' "$boundary_index" "$request_hash" || exit 81
 # Android shell timeout semantics still need a target read-only tool check.
 # EOF, failed/timed-out reads and malformed replies never release a write.
 IFS= read -r -t 8 acknowledgement || exit 81
 [ "${#acknowledgement}" -le 128 ] || exit 81
 case "$acknowledgement" in "X2DII_BOUNDARY_ACK:$request_hash:"*) ;; *) exit 81;; esac
 ack_times=${acknowledgement#"X2DII_BOUNDARY_ACK:$request_hash:"}
 ack_started=${ack_times%%:*}
 ack_checked=${ack_times#*:}
 x2dii_sc_scalar epoch "$ack_started" && x2dii_sc_scalar epoch "$ack_checked" || exit 81
 received_epoch=$(date -u +%s) || exit 81
 x2dii_sc_scalar epoch "$received_epoch" || exit 81
 [ "$ack_started" -ge "$issued_epoch" ] && [ "$ack_checked" -ge "$ack_started" ] &&
 [ "$received_epoch" -ge "$ack_checked" ] && [ "$((received_epoch-issued_epoch))" -le 8 ] || exit 81
 regular "$request" && hashok "$request" "$request_hash" &&
 equals "$request_identity" stat -c '%d:%i:%f:%h:%s:%u:%g' "$request" &&
 equals "$worker_program_identity" stat -c '%d:%i:%f:%h:%s:%u:%g' "$worker_program" &&
 hashok "$worker_program" "$worker_program_hash" &&
 supervised_objects &&
 self_identity && equals "$1" state && fresh || exit 81
 boundary_index=$((boundary_index+1))
}
ready() { supervised_ready "$1"; }
'''
    for key, value in {"@STAGE@": stage, "@INDEX@": str(file_index), "@DIGEST@": digest,
                       "@OBSERVER_HASH@": observer_hash, "@WORKER_PATH@": fixed_worker_path}.items():
        guard = guard.replace(key, value)
    anchor = "trap finish EXIT\n"
    if source.count(anchor) != 1:
        raise ValueError("one-file recovery boundary changed")
    # Guards run after helper definitions, before installing the recovery trap
    # or mutating mounts. At all later exits the same mount-owned trap applies.
    source = source.replace(anchor, guard + anchor, 1)
    source = source.replace("maintenance_boundaries=UNCONNECTED", "maintenance_boundaries=HOST_MEDIATED_SEVEN_MATCHED")
    source = source.replace("# LOCAL SOURCE ONLY. Fresh maintenance checks at write boundaries ARE NOT CONNECTED.",
                            "# LOCAL SOURCE ONLY. Seven fixed host-mediated maintenance boundaries; transport qualification pending.")
    return source
