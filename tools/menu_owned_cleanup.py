"""Fixed exact-owned file cleanup, separate from official boot restoration.

Pure renderers/coordinator: no device connection, publisher, launch or approval.
Every deletion still requires a current, complete maintenance observation. The
pathname check/unlink gap is not atomic; exclusive maintenance remains required.
Unreadable/incomplete process coverage fails and retains the remaining files.
"""
from copy import deepcopy
import hashlib
import json
import re

from . import boot_config, menu_boot_boundary, menu_boot_transport, session_context as sc
from . import menu_maintenance_boundary as base
from .temporary_menu_files import FILE_LAYOUT, render_preplacement

REQUEST_SCHEMA = "x2dii-owned-cleanup-request-v1"
RESPONSE_SCHEMA = "x2dii-owned-cleanup-response-v1"
STAGES = ((0, "remount_rw", "ro"), (1, "unlink_owned", "rw"),
          (2, "confirm_absent", "ro"), (3, "receipt", "ro"))
SCOPE = base.SCOPE

_METADATA = r'''
mc_meta() {
 mc_meta_path=$1; mc_meta_label=$2
 [ -f "$mc_meta_path" ] && [ ! -L "$mc_meta_path" ] || return 1
 mc_meta_stat=$(stat -c '%u %g %a %h' "$mc_meta_path") || return 1
 [ "$mc_meta_stat" = '0 0 644 1' ] || return 1
 mc_meta_observed=$(ls -Zd "$mc_meta_path") || return 1
 [ "$mc_meta_observed" = "$mc_meta_label $mc_meta_path" ] || return 1
 mc_meta_names=$(/system/bin/toybox getfattr "$mc_meta_path") || return 1
 mc_meta_expected=$(printf '# file: %s\nsecurity.selinux\n' "$mc_meta_path") || return 1
 [ "$mc_meta_names" = "$mc_meta_expected" ] || return 1
 mc_meta_attrs=$(/system/bin/toybox getfattr -d "$mc_meta_path") || return 1
 mc_meta_expected=$(printf '# file: %s\nsecurity.selinux="%s"\n' "$mc_meta_path" "$mc_meta_label") || return 1
 [ "$mc_meta_attrs" = "$mc_meta_expected" ]
}
'''


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _need(ok, message):
    if not ok:
        raise ValueError("owned cleanup: " + message)


def _context(manifest, raw):
    render_preplacement(manifest, file_index=0)  # exact fixed four-file layout
    c = menu_boot_boundary.context_for_action(manifest, raw, "restore")
    _need(c["gui_state"] == "present" and c["gui_service_state"] == "running" and
          c["gui_exe_sha256"] == manifest["candidate"]["gui_sha256"] and
          c["gui_domain"] == "u:r:hbl_camera_service:s0" and
          c["rc_sha256"] == manifest["candidate"]["rc"]["before"], "stock GUI/rc recovery context required")
    return c


def worker_path(manifest, raw_session, file_index):
    _context(manifest, raw_session)
    _need(type(file_index) is int and 0 <= file_index < 4, "fixed file index required")
    return ("/blackbox/x2dii-menu-stage/" + manifest["candidate_sha256"][:24] +
            "/cleanup-" + _sha(raw_session)[:12] + f"-{file_index}.sh")


def observer_path(manifest, raw_session):
    _context(manifest, raw_session)
    # Full candidate/session identities are checked inside the program. A short
    # unique session path keeps the real framed maintenance command below 232.
    return "/tmp/xc-" + _sha(raw_session)[:16] + "/o"


def request_path(manifest, raw_session, file_index, boundary_index):
    c = _context(manifest, raw_session)
    _need(type(file_index) is int and 0 <= file_index < 4 and type(boundary_index) is int and
          0 <= boundary_index < 4, "fixed cleanup boundary required")
    return (worker_path(manifest, raw_session, file_index).rsplit("/", 1)[0] +
            f"/.cleanup-{c['session_nonce']}-{file_index}-{boundary_index}.data")


def _inputs(manifest, raw, identities, stock, receipt):
    c = _context(manifest, raw)
    _need(type(identities) in (tuple, list) and len(identities) == 4 and
          all(menu_boot_transport._identity(identity, item["bytes"])
              for identity, item in zip(identities, manifest["candidate"]["files"])),
          "four exact original placement identities required")
    _need(len({value.split(":", 2)[:2][0] + ":" + value.split(":", 2)[:2][1]
               for value in identities}) == 4, "placement identities cannot alias")
    keys = {"candidate_sha256", "session_data_sha256", "action", "backup_identity",
            "identity", "sha256", "output_sha256"}
    _need(type(receipt) is dict and set(receipt) == keys and receipt["action"] == "restore" and
          receipt["candidate_sha256"] == manifest["candidate_sha256"] and
          receipt["sha256"] == c["rc_sha256"] and
          menu_boot_transport._identity(receipt["identity"], len(boot_config.STOCK.read_bytes())) and
          menu_boot_transport._identity(receipt["backup_identity"], len(boot_config.STOCK.read_bytes())) and
          all(type(receipt[k]) is str and re.fullmatch(r"[0-9a-f]{64}", receipt[k])
              for k in ("session_data_sha256", "output_sha256")), "exact completed restore receipt required")
    receipt_hash = _sha(json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode())
    _need(type(stock) is dict and stock.get("status") == "OBSERVED_STOCK_GUI_NOT_FUNCTION_VERIFIED" and
          stock.get("candidate_sha256") == manifest["candidate_sha256"] and
          stock.get("session_data_sha256") == _sha(raw) and stock.get("boot_id") == c["boot_id"] and
          type(stock.get("previous_boot_id")) is str and
          re.fullmatch(sc.PATTERNS["uuid"][1], stock["previous_boot_id"]) and
          stock["previous_boot_id"] != c["boot_id"] and
          stock.get("restore_receipt_sha256") == receipt_hash and stock.get("removal_authorized") is False and
          stock.get("all_process_mappings_verified") is False, "bound new-boot stock readback required")
    return c


def decode_request(raw):
    values = base._decode(raw, base.REQUEST_FIELDS)
    _need(values["schema"] == REQUEST_SCHEMA, "cleanup request schema differs")
    index = values["boundary_index"]
    _need(type(index) is int and 0 <= index < 4 and
          (values["boundary_name"], values["mount_access"]) == STAGES[index][1:], "cleanup stage differs")
    scalar = dict(values, schema=base.REQUEST_SCHEMA, boundary_index=0,
                  boundary_name="remount_rw", mount_access="ro")
    base._validate_request(scalar)
    return values


def encode_response(values):
    _need(type(values) is dict and set(values) == set(base.RESPONSE_FIELDS), "response fields differ")
    return base._encode(values, base.RESPONSE_FIELDS)


def _observer(manifest, raw, identities, stock, receipt):
    c = _inputs(manifest, raw, identities, stock, receipt)
    source = base.render_observer(manifest, session_kind="install")

    def once(before, after):
        nonlocal source
        _need(source.count(before) == 1, "fixed observer source anchor changed")
        source = source.replace(before, after, 1)

    old = base.paths(manifest, 0, 0, session_data_sha256=_sha(raw), session_kind="install")
    source = source.replace(old["program"], observer_path(manifest, raw))
    source = source.replace(base.REQUEST_SCHEMA, REQUEST_SCHEMA).replace(base.RESPONSE_SCHEMA, RESPONSE_SCHEMA)
    once('case "$3" in 0|1|2|3|4|5|6) ;; *) exit 32;; esac',
         'case "$3" in 0|1|2|3) ;; *) exit 32;; esac')
    once('mb_session_sha=$1\n', f'[ "$1" = {_sha(raw)} ] || exit 32\nmb_session_sha=$1\n')
    once('/.boundary-$mb_file_index_arg-$mb_boundary_index_arg.data"',
         f'/.cleanup-{c["session_nonce"]}-$mb_file_index_arg-$mb_boundary_index_arg.data"')
    once('[ "$X2DII_SESSION_SCHEMA" = x2dii-session-context-v2 ] &&\n[ "$X2DII_SESSION_KIND" = install ]',
         '[ "$X2DII_SESSION_SCHEMA" = x2dii-session-context-v1 ] &&\n[ "$X2DII_SESSION_KIND" = recovery ]')
    old_case = "case \"$mb_boundary_index\" in\n" + "".join(
        f' {i}) [ "$mb_boundary_name" = {name} ] && [ "$mb_mount_access" = {access} ] || exit 33;;\n'
        for i, name, access in base.STAGES) + 'esac\n'
    new_case = 'case "$mb_boundary_index" in\n' + "".join(
        f' {i}) [ "$mb_boundary_name" = {name} ] && [ "$mb_mount_access" = {access} ] || exit 33;;\n'
        for i, name, access in STAGES) + 'esac\n'
    once(old_case, new_case)
    start = source.index(' mb_process "$X2DII_SESSION_CORE_GUI_PID"')
    end = source.index('\nx2dii_sc_private "$mb_program"', start)
    rc_identity = receipt["identity"]
    # Keep observer self identity from the original runtime function, replace
    # capture-health dependencies with current stock identity and complete scan.
    suffixes = ("PID", "START_TICKS", "EXE_TARGET", "EXE_SHA256", "DOMAIN", "MOUNT_NAMESPACE")
    gui_args = " ".join(f'"$X2DII_SESSION_GUI_{key}"' for key in suffixes)
    checks = f''' mb_process {gui_args} &&
 mb_equals running getprop init.svc.camera-gui &&
 mb_equals "$X2DII_SESSION_GUI_PID" pidof camera-gui &&
 mb_equals '{rc_identity}' stat -c '%d:%i:%f:%h:%s:%u:%g' /system/etc/init/camera-gui.rc &&
 x2dii_sc_hash /system/etc/init/camera-gui.rc '{c["rc_sha256"]}' || return 1
 mc_meta /system/etc/init/camera-gui.rc u:object_r:system_file:s0
}}
'''
    inodes = [value.split(":")[1] for value in identities]
    maps = _METADATA + r'''
# UNKNOWN_RETAIN_FILES on any unreadable or changing enumeration. This bounded
# namespace observation does not remove the exclusive-maintenance prerequisite.
mc_proc_mount() (
 set -f
 mc_found=0
 while :; do
  mc_line=
  if IFS= read -r mc_line; then
   set -- $mc_line
   [ "$#" = 6 ] || return 1
   if [ "$2" = /proc ]; then
    [ "$3" = proc ] && [ "$mc_found" = 0 ] || return 1
    case ",$4," in *,hidepid=*|*,subset=*) return 1;; esac
    mc_found=1
   fi
  else mc_status=$?; [ "$mc_status" = 1 ] && [ -z "$mc_line" ] || return 1; break; fi
 done < /proc/mounts
 [ "$mc_found" = 1 ]
)
mc_list() {
 mc_pids=''
 [ -r /proc ] && [ -x /proc ] || return 1
 # Built-in globbing/list construction does not introduce a transient ls PID.
 for mc_dir in /proc/[0-9]*; do
  [ -d "$mc_dir" ] && [ ! -L "$mc_dir" ] || return 1
  mc_pid=${mc_dir##*/}
  case "$mc_pid" in ''|0*|*[!0-9]*) return 1;; esac
  mc_pids="$mc_pids $mc_pid"
 done
 case " $mc_pids " in *' 1 '*) ;; *) return 1;; esac
 case " $mc_pids " in *" $X2DII_SESSION_OBSERVER_PID "*) ;; *) return 1;; esac
 case " $mc_pids " in *" $X2DII_SESSION_GUI_PID "*) ;; *) return 1;; esac
 [ "${#mc_pids}" -le 32768 ]
}
mc_validate_maps() (
 set -f
 while :; do
  mc_line=''
  if IFS= read -r mc_line; then
   set -- $mc_line
   [ "$#" -ge 5 ] || return 1
   mc_start=${1%%-*}; mc_end=${1#*-}
   [ "$mc_start" != "$1" ] && [ -n "$mc_start" ] && [ -n "$mc_end" ] || return 1
   case "$mc_start$mc_end" in *[!0-9a-f]*) return 1;; esac
   case "$2" in [r-][w-][x-][ps]) ;; *) return 1;; esac
   case "$3" in ''|*[!0-9a-f]*) return 1;; esac
   mc_major=${4%%:*}; mc_minor=${4#*:}
   [ "$mc_major" != "$4" ] && [ -n "$mc_major" ] && [ -n "$mc_minor" ] || return 1
   case "$mc_major$mc_minor" in *[!0-9a-f]*) return 1;; esac
   case "$5" in ''|*[!0-9]*) return 1;; esac
   # An inode-only collision on another device is conservatively UNKNOWN,
   # not evidence that the process necessarily loaded our extension.
   case "$5" in @I0@|@I1@|@I2@|@I3@) return 1;; esac
   case "$mc_line" in *libx2dii_menu.so*|*X2d2MenuBootstrap.qml*|*X2d2MenuModel.qml*|*X2d2MenuPage.qml*) return 1;; esac
  else mc_status=$?; [ "$mc_status" = 1 ] && [ -z "$mc_line" ] || return 1; break; fi
 done
)
mc_all_maps() {
 mc_proc_mount || return 1
 mc_ns=$(readlink /proc/self/ns/pid) || return 1
 case "$mc_ns" in pid:\[*\]) ;; *) return 1;; esac
 mb_equals "$mc_ns" readlink /proc/1/ns/pid || return 1
 mc_list || return 1
 mc_first_pids=$mc_pids
 mc_first_lifetimes=''
 for mc_pid in $mc_first_pids; do
  mc_tick=$(mb_ticks "/proc/$mc_pid/stat") || return 1
  case "$mc_tick" in ''|0*|*[!0-9]*) return 1;; esac
  # A second completed byte count detects bytes (especially NUL) that this
  # shell cannot retain. A changing count fails, never becomes clean absence.
  mc_size=$(/system/bin/toybox wc -c < "/proc/$mc_pid/maps") || return 1
  set -- $mc_size
  [ "$#" = 1 ] || return 1
  mc_size=$1
  case "$mc_size" in ''|*[!0-9]*) return 1;; esac
  [ "${#mc_size}" -le 7 ] && [ "$mc_size" -le 2097152 ] || return 1
  # A sentinel retains the final newline; cat failure cannot look like EOF.
  mc_raw=$(cat "/proc/$mc_pid/maps" && printf '|X2DII_MAPS_EOF|') || return 1
  case "$mc_raw" in *'|X2DII_MAPS_EOF|') ;; *) return 1;; esac
  mc_raw=${mc_raw%'|X2DII_MAPS_EOF|'}
  [ "${#mc_raw}" -eq "$mc_size" ] || return 1
  case "$mc_raw" in ''|*'
') ;; *) return 1;; esac
  printf '%s' "$mc_raw" | mc_validate_maps || return 1
  mb_equals "$mc_tick" mb_ticks "/proc/$mc_pid/stat" || return 1
  mc_first_lifetimes="$mc_first_lifetimes $mc_pid:$mc_tick"
 done
 mc_list && [ "$mc_first_pids" = "$mc_pids" ] || return 1
 mc_second_lifetimes=''
 for mc_pid in $mc_pids; do
  mc_tick=$(mb_ticks "/proc/$mc_pid/stat") || return 1
  mc_second_lifetimes="$mc_second_lifetimes $mc_pid:$mc_tick"
 done
 [ "$mc_first_lifetimes" = "$mc_second_lifetimes" ] && mc_proc_mount
}
mc_environment() (
 set -f
 mc_env_size=$(/system/bin/toybox wc -c < "/proc/$X2DII_SESSION_GUI_PID/environ") || return 1
 set -- $mc_env_size
 [ "$#" = 1 ] || return 1
 mc_env_size=$1
 case "$mc_env_size" in ''|*[!0-9]*) return 1;; esac
 [ "${#mc_env_size}" -le 5 ] && [ "$mc_env_size" -gt 0 ] && [ "$mc_env_size" -le 65536 ] || return 1
 mc_env_hex=$(/system/bin/toybox od -An -v -tx1 "/proc/$X2DII_SESSION_GUI_PID/environ") || return 1
 [ "${#mc_env_hex}" -le 262160 ] || return 1
 mc_n=0; mc_value=0; mc_complete=0; mc_key=''
 for mc_b in $mc_env_hex; do
  mc_n=$((mc_n+1))
  case "$mc_b" in [0-9a-f][0-9a-f]) ;; *) return 1;; esac
  if [ "$mc_b" = 00 ]; then
   [ "$mc_value" = 1 ] || return 1
   case "$mc_key" in 4c445f5052454c4f4144|58324449495f4d454e555f455854454e53494f4e) return 1;; esac
   mc_key=''; mc_value=0; mc_complete=1
  else
   mc_complete=0
   if [ "$mc_value" = 0 ]; then
    if [ "$mc_b" = 3d ]; then [ -n "$mc_key" ] || return 1; mc_value=1
    else
     case "$mc_b" in
      4[1-9a-f]|5[0-9a]|6[1-9a-f]|7[0-9a]|5f) ;;
      3[0-9]) [ -n "$mc_key" ] || return 1;;
      *) return 1;;
     esac
     mc_key=$mc_key$mc_b
     [ "${#mc_key}" -le 512 ] || return 1
    fi
   fi
  fi
 done
 [ "$mc_complete" = 1 ] && [ "$mc_n" -eq "$mc_env_size" ]
)
mb_runtime && mc_environment && mb_runtime && mc_all_maps && mc_environment && mb_runtime || exit 35
'''
    for index, inode in enumerate(inodes):
        maps = maps.replace(f"@I{index}@", inode)
    source = source[:start] + checks + maps + source[end:]
    # Final runtime observation immediately precedes the timestamp/response;
    # do not turn a failed or incomplete scan into an absent mapping claim.
    return source


def _worker(manifest, raw, identities, stock, receipt, file_index, observer_sha):
    c = _inputs(manifest, raw, identities, stock, receipt)
    entry = manifest["candidate"]["files"][file_index]
    label = c[("library_label", "bootstrap_label", "model_label", "page_label")[file_index]]
    stage = worker_path(manifest, raw, file_index).rsplit("/", 1)[0]
    source = '''#!/system/bin/sh
# LOCAL SOURCE ONLY: exact-owned cleanup; exclusive maintenance required.
# The final pathname check/unlink race is NOT atomically eliminated.
set -eu
export PATH=/system/bin:/system/xbin:/sbin
export LC_ALL=C
# SESSION_DATA_PARSER_BEGIN
''' + sc.shell_parser() + '''# SESSION_DATA_PARSER_END
'''
    body = r'''[ "$#" = 2 ] && [ "$1" = '@STAGE@/session-context-@SESSION@.data' ] &&
[ "$2" = '@SESSION@' ] && [ "$0" = '@WORKER@' ] || exit 32
x2dii_load_session "$1" "$2" || exit 32
[ "$X2DII_SESSION_SCHEMA" = x2dii-session-context-v1 ] &&
[ "$X2DII_SESSION_KIND" = recovery ] || exit 32
target='@TARGET@'
program='@WORKER@'
session_file=$1
expected_identity='@IDENTITY@'
baseline="$X2DII_SESSION_MOUNT_DEVICE $X2DII_SESSION_MOUNT_FILESYSTEM $X2DII_SESSION_MOUNT_OPTIONS"
rw="$X2DII_SESSION_MOUNT_DEVICE $X2DII_SESSION_MOUNT_FILESYSTEM rw,${X2DII_SESSION_MOUNT_OPTIONS#ro,}"
mount_owned=0
removed=0
boundary_index=0
equals() { expected=$1; shift; actual=$("$@") || return 1; [ "$actual" = "$expected" ]; }
hashok() { observed_hash=$(sha256sum "$1") || return 1; [ "${observed_hash%% *}" = "$2" ]; }
absent() { [ ! -e "$1" ] && [ ! -L "$1" ]; }
regular() { [ -f "$1" ] && [ ! -L "$1" ] && equals 1 stat -c %h "$1"; }
owned() {
 [ -d /system ] && [ ! -L /system ] && [ -d "${target%/*}" ] && [ ! -L "${target%/*}" ] || return 1
 regular "$target" && equals "$expected_identity" stat -c '%d:%i:%f:%h:%s:%u:%g' "$target" &&
 mc_meta "$target" '@LABEL@' && hashok "$target" '@PAYLOAD_SHA@' &&
 mc_meta "$target" '@LABEL@' &&
 equals "$expected_identity" stat -c '%d:%i:%f:%h:%s:%u:%g' "$target"
}
state() (
 set -f
 while :; do
  line=
  if IFS= read -r line; then
   set -- $line; [ "$#" = 6 ] || return 1
   if [ "$2" = /system ]; then printf '%s %s %s\n' "$1" "$3" "$4" || return 1; fi
  else status=$?; [ "$status" = 1 ] && [ -z "$line" ] || return 1; break; fi
 done < /proc/mounts
)
self_identity() {
 equals 0 id -u && equals u:r:su:s0 cat /proc/self/attr/current &&
 equals "$X2DII_SESSION_BOOT_ID" cat /proc/sys/kernel/random/boot_id &&
 equals "$X2DII_SESSION_MOUNT_NAMESPACE" readlink /proc/self/ns/mnt
}
fresh() {
 now=$(date -u +%s) || return 1
 x2dii_sc_scalar epoch "$now" && [ "$now" -ge "$X2DII_SESSION_OBSERVED_EPOCH" ] &&
 [ "$now" -le "$((X2DII_SESSION_OBSERVED_EPOCH+600))" ]
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
 restore_ro || result=72
 if [ "$result" != 0 ]; then
  printf 'X2DII_CLEANUP_FAILED:%s; removed=@INDEX@:%s; other files retained\n' "$result" "$removed" >&2
 fi
 exit "$result"
}
regular "$program" && x2dii_sc_private "$program" || exit 81
program_identity=$(stat -c '%d:%i:%f:%h:%s:%u:%g' "$program") || exit 81
program_hash_line=$(sha256sum "$program") || exit 81
program_hash=${program_hash_line%% *}
x2dii_sc_scalar hex64 "$program_hash" || exit 81
trap finish EXIT
trap 'exit 74' HUP INT TERM
objects() {
 regular "$program" && equals "$program_identity" stat -c '%d:%i:%f:%h:%s:%u:%g' "$program" &&
 hashok "$program" "$program_hash" && hashok "$session_file" '@SESSION@' || return 1
 case "$boundary_index" in 0|1) owned;; 2|3) [ "$removed" = 1 ] && absent "$target";; *) return 1;; esac
}
ready() {
 self_identity && fresh && equals "$1" state && objects || return 1
 case "$boundary_index:$1" in
  "0:$baseline") boundary_name=remount_rw; access=ro;;
  "1:$rw") boundary_name=unlink_owned; access=rw;;
  "2:$baseline") boundary_name=confirm_absent; access=ro;;
  "3:$baseline") boundary_name=receipt; access=ro;;
  *) return 1;;
 esac
 issued=$(date -u +%s) || return 1
 x2dii_sc_scalar epoch "$issued" || return 1
 challenge_line=$(printf '%s\n' "$X2DII_SESSION_BOOT_ID:$X2DII_SESSION_SESSION_NONCE:cleanup:@INDEX@:$boundary_index:$program_hash" | sha256sum) || return 1
 challenge=${challenge_line%% *}
 request='@STAGE@/.cleanup-@NONCE@-@INDEX@-'"$boundary_index"'.data'
 absent "$request" || return 1
 (set -C; umask 077; printf '%s\n' \
  'schema=x2dii-owned-cleanup-request-v1' 'candidate_sha256=@CANDIDATE@' \
  "boot_id=$X2DII_SESSION_BOOT_ID" "session_nonce=$X2DII_SESSION_SESSION_NONCE" 'file_index=@INDEX@' \
  "boundary_index=$boundary_index" "boundary_name=$boundary_name" "mount_access=$access" \
  "worker_program_sha256=$program_hash" 'worker_session_sha256=@SESSION@' \
  'maintenance_program_sha256=@OBSERVER_SHA@' 'maintenance_session_sha256=@SESSION@' \
  "challenge=$challenge" "observed_epoch=$X2DII_SESSION_OBSERVED_EPOCH" "issued_epoch=$issued" \
  "deadline_epoch=$((X2DII_SESSION_OBSERVED_EPOCH+600))" > "$request") || return 1
 x2dii_sc_private "$request" || return 1
 request_identity=$(stat -c '%d:%i:%f:%h:%s:%u:%g' "$request") || return 1
 request_hash_line=$(sha256sum "$request") || return 1
 request_hash=${request_hash_line%% *}
 x2dii_sc_scalar hex64 "$request_hash" || return 1
 printf 'X2DII_CLEANUP_BOUNDARY_REQUEST:@INDEX@:%s:%s\n' "$boundary_index" "$request_hash" || return 1
 IFS= read -r -t 8 ack || return 1
 [ "${#ack}" -le 128 ] || return 1
 case "$ack" in "X2DII_CLEANUP_BOUNDARY_ACK:$request_hash:"*) ;; *) return 1;; esac
 times=${ack#"X2DII_CLEANUP_BOUNDARY_ACK:$request_hash:"}
 started=${times%%:*}; checked=${times#*:}
 x2dii_sc_scalar epoch "$started" && x2dii_sc_scalar epoch "$checked" || return 1
 received=$(date -u +%s) || return 1
 x2dii_sc_scalar epoch "$received" && [ "$started" -ge "$issued" ] &&
 [ "$checked" -ge "$started" ] && [ "$received" -ge "$checked" ] &&
 [ "$((received-issued))" -le 8 ] || return 1
 regular "$request" && equals "$request_identity" stat -c '%d:%i:%f:%h:%s:%u:%g' "$request" &&
 hashok "$request" "$request_hash" && objects && self_identity && fresh && equals "$1" state || return 1
 boundary_index=$((boundary_index+1))
}
ready "$baseline" || exit 81
mount_owned=1
mount -o remount,rw /system || exit 72
ready "$rw" || exit 81
# Only this immutable compile-time target, with original placement identity.
# There is a residual final check -> unlink gap; no atomic guarantee is made.
owned || exit 82
rm -- "$target" || exit 82
removed=1
absent "$target" || exit 82
sync
restore_ro || exit 72
ready "$baseline" && ready "$baseline" || exit 81
absent "$target" && self_identity && fresh && equals "$baseline" state || exit 82
printf 'schema=x2dii-one-file-cleanup-v1\ncandidate_sha256=@CANDIDATE@\nsession_data_sha256=@SESSION@\nsession_nonce=@NONCE@\nfile_index=@INDEX@\noriginal_identity=@IDENTITY@\nsha256=@PAYLOAD_SHA@\nmaintenance_boundaries=HOST_MEDIATED_FOUR_CLEANUP_MATCHED\nX2DII_ONE_OWNED_FILE_REMOVED_NOT_FUNCTION_VALIDATED\n'
'''
    for key, value in {"STAGE": stage, "SESSION": _sha(raw), "WORKER": worker_path(manifest, raw, file_index),
        "TARGET": entry["target"], "IDENTITY": identities[file_index], "LABEL": label,
        "PAYLOAD_SHA": entry["sha256"], "INDEX": str(file_index), "NONCE": c["session_nonce"],
        "CANDIDATE": manifest["candidate_sha256"], "OBSERVER_SHA": observer_sha}.items():
        body = body.replace("@" + key + "@", value)
    return source + body.replace("owned() {\n", _METADATA + "owned() {\n", 1)


def render_programs(manifest, raw_session, original_identities, stock_readback, restore_receipt):
    _inputs(manifest, raw_session, original_identities, stock_readback, restore_receipt)
    observer = _observer(manifest, raw_session, original_identities, stock_readback, restore_receipt).encode("ascii")
    result = {observer_path(manifest, raw_session): observer}
    for index in range(4):
        result[worker_path(manifest, raw_session, index)] = _worker(manifest, raw_session,
            original_identities, stock_readback, restore_receipt, index, _sha(observer)).encode("ascii")
    return result


class CleanupCoordinator:
    """Fresh fixed cleanup dialogue, never a grant to run it on the camera."""
    def __init__(self, manifest, raw_session, original_identities, stock_readback, restore_receipt):
        self.manifest = deepcopy(manifest)
        self.raw_session = raw_session
        self.identities = tuple(original_identities)
        self.context = _inputs(self.manifest, raw_session, original_identities, stock_readback, restore_receipt)
        self.programs = render_programs(self.manifest, raw_session, self.identities, stock_readback, restore_receipt)
        self.worker_hashes = tuple(_sha(self.programs[worker_path(self.manifest, raw_session, index)]) for index in range(4))
        self._file = self._boundary = 0
        self._waiting = None
        self._receipts = []
        self.failed = False

    def _need(self, condition, message):
        if self.failed or not condition:
            self.failed = True
            _need(False, message)

    @property
    def completed_receipts(self):
        return tuple(deepcopy(self._receipts))

    @property
    def next_boundary(self):
        return ((self._file, self._boundary) if not self.failed and self._waiting is None and
                self._file < 4 and self._boundary < 4 else None)

    def expected_request(self, *, issued_epoch):
        self._need(not self.failed and self._file < 4 and self._boundary < 4, "no next cleanup request")
        c = self.context
        challenge = _sha((f"{c['boot_id']}:{c['session_nonce']}:cleanup:{self._file}:"
                          f"{self._boundary}:{self.worker_hashes[self._file]}\n").encode())
        values = dict(schema=REQUEST_SCHEMA, candidate_sha256=self.manifest["candidate_sha256"],
            boot_id=c["boot_id"], session_nonce=c["session_nonce"], file_index=self._file,
            boundary_index=self._boundary, boundary_name=STAGES[self._boundary][1],
            mount_access=STAGES[self._boundary][2], worker_program_sha256=self.worker_hashes[self._file],
            worker_session_sha256=_sha(self.raw_session), maintenance_program_sha256=_sha(
                self.programs[observer_path(self.manifest, self.raw_session)]),
            maintenance_session_sha256=_sha(self.raw_session), challenge=challenge,
            observed_epoch=c["observed_epoch"], issued_epoch=issued_epoch, deadline_epoch=c["observed_epoch"]+600)
        raw = base._encode(values, base.REQUEST_FIELDS)
        decode_request(raw)
        return raw

    def begin_boundary(self, line):
        self._need(self.next_boundary is not None, "no next cleanup boundary")
        match = re.fullmatch(r"X2DII_HOST_CLEANUP_BOUNDARY:([0-3]):([0-3]):([0-9a-f]{64})", line) if type(line) is str else None
        self._need(match is not None and (int(match[1]), int(match[2])) == self.next_boundary, "wrong or repeated cleanup boundary")
        self._waiting = match[3]
        command = (f"sh {observer_path(self.manifest, self.raw_session)} {_sha(self.raw_session)} "
                   f"{self._file} {self._boundary} {self._waiting}")
        from .stage_peer_usb_access import envelope
        envelope(command, "123456abcdef")
        return command

    def accept_reply(self, raw_response, *, received_epoch):
        self._need(self._waiting is not None, "no outstanding cleanup boundary")
        try:
            response = base._decode(raw_response, base.RESPONSE_FIELDS)
            self._need(response["schema"] == RESPONSE_SCHEMA and type(received_epoch) is int and
                       0 <= received_epoch-response["issued_epoch"] <= 8, "stale or wrong cleanup response")
            expected = self.expected_request(issued_epoch=response["issued_epoch"])
            request = decode_request(expected)
            self._need(_sha(expected) == self._waiting and response["request_sha256"] == self._waiting and
                all(response[k] == request[k] for k in base.REQUEST_FIELDS[1:]) and
                response["result"] == "OBSERVED_MATCH" and response["scope"] == SCOPE and
                request["issued_epoch"] <= response["started_epoch"] <= response["checked_epoch"] <= received_epoch <=
                request["deadline_epoch"], "cleanup observation binding differs")
            ack = (f"X2DII_CLEANUP_BOUNDARY_ACK:{self._waiting}:{response['started_epoch']}:"
                   f"{response['checked_epoch']}\n").encode()
            self._waiting = None
            self._boundary += 1
            return ack
        except Exception:
            self.failed = True
            raise

    def finish_file(self, *, file_index, decoded_output, stream_completed):
        self._need(self._waiting is None and self._boundary == 4 and file_index == self._file and
                   type(file_index) is int and stream_completed is True and type(decoded_output) is bytes and
                   len(decoded_output) <= 32768, "cleanup stream incomplete")
        marker = f"X2DII_CLEANUP_WORKER_{_sha(self.raw_session)[:24]}_{file_index}_RC="
        exact = ("schema=x2dii-one-file-cleanup-v1\n" +
            f"candidate_sha256={self.manifest['candidate_sha256']}\nsession_data_sha256={_sha(self.raw_session)}\n" +
            f"session_nonce={self.context['session_nonce']}\nfile_index={file_index}\n" +
            f"original_identity={self.identities[file_index]}\nsha256={self.manifest['candidate']['files'][file_index]['sha256']}\n" +
            "maintenance_boundaries=HOST_MEDIATED_FOUR_CLEANUP_MATCHED\n" +
            "X2DII_ONE_OWNED_FILE_REMOVED_NOT_FUNCTION_VALIDATED\n\n" + marker + "0\n").encode()
        text = decoded_output.replace(b"\r\n", b"\n")
        self._need(text.endswith(exact) and text.count(b"schema=x2dii-one-file-cleanup-v1\n") == 1 and
                   text.count(marker.encode()) == 1, "cleanup receipt differs")
        self._receipts.append(dict(candidate_sha256=self.manifest["candidate_sha256"],
            session_data_sha256=_sha(self.raw_session), file_index=file_index,
            original_identity=self.identities[file_index], output_sha256=_sha(decoded_output)))
        self._file += 1
        self._boundary = 0
        return f"X2DII_HOST_CLEANUP_ACK:{file_index}:{_sha(decoded_output)}\n".encode()
