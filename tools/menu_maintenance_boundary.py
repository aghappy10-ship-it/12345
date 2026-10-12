"""Fixed, read-only maintenance observations for one waiting file boundary.

No transport, installer, executor, release approval or file-removal authority.
The caller must connect each request to the same live su worker, consume replies
in order once, and refuse stale/replayed data. Observed identity is not an atomic
lock across the two domains, nor proof that a worker executed a stated program.
"""
from __future__ import annotations

import hashlib
import json
import re

from . import session_context
from .qt_unit import GUI_SHA256


STAGES = (
    (0, "remount_rw", "ro"),
    (1, "create_temp", "rw"),
    (2, "write_payload", "rw"),
    (3, "chmod", "rw"),
    (4, "commit_rename", "rw"),
    (5, "final_identity", "ro"),
    (6, "final_receipt", "ro"),
)
REQUEST_SCHEMA = "x2dii-menu-maintenance-request-v1"
RESPONSE_SCHEMA = "x2dii-menu-maintenance-response-v1"
SCOPE = "ONE_BOUNDARY_ONLY_NOT_AUTHORIZATION"
REQUEST_FIELDS = (
    "schema", "candidate_sha256", "boot_id", "session_nonce", "file_index", "boundary_index",
    "boundary_name", "mount_access", "worker_program_sha256", "worker_session_sha256",
    "maintenance_program_sha256", "maintenance_session_sha256", "challenge", "observed_epoch",
    "issued_epoch", "deadline_epoch",
)
RESPONSE_FIELDS = REQUEST_FIELDS + ("request_sha256", "started_epoch", "checked_epoch", "result", "scope")
INTEGER_FIELDS = {"file_index", "boundary_index", "observed_epoch", "issued_epoch", "deadline_epoch",
                  "started_epoch", "checked_epoch"}
HEX_FIELDS = ("candidate_sha256", "worker_program_sha256", "worker_session_sha256",
              "maintenance_program_sha256", "maintenance_session_sha256", "challenge")
MAX_DATA_BYTES = 4096


def _need(ok, reason):
    if not ok:
        raise ValueError("maintenance boundary: " + reason)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _index(file_index, boundary_index):
    _need(type(file_index) is int and 0 <= file_index < 4, "file index must be 0..3")
    _need(type(boundary_index) is int and 0 <= boundary_index < len(STAGES), "boundary index must be 0..6")


def _candidate(manifest):
    _need(type(manifest) is dict and type(manifest.get("candidate")) is dict, "candidate manifest required")
    digest = _sha(json.dumps(manifest["candidate"], sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False).encode())
    _need(manifest.get("candidate_sha256") == digest, "candidate hash differs")
    _need(manifest["candidate"].get("gui_sha256") == GUI_SHA256, "original GUI differs")
    return digest


def session_path(manifest, session_data_sha256):
    """Immutable current data; historical sessions never need replacement."""
    digest = _candidate(manifest)
    _need(type(session_data_sha256) is str and re.fullmatch("[0-9a-f]{64}", session_data_sha256) is not None,
          "exact session data SHA required")
    return "/blackbox/x2dii-menu-stage/" + digest[:24] + "/session-context-" + session_data_sha256 + ".data"


def paths(manifest, file_index, boundary_index, *, session_data_sha256, session_kind):
    """Only developer-fixed paths, selected by bounded numeric stage indexes."""
    _index(file_index, boundary_index)
    digest = _candidate(manifest)
    _need(type(session_kind) is str and session_kind in ("menu_validation", "install"), "fixed observer kind required")
    stage = "/blackbox/x2dii-menu-stage/" + digest[:24]
    return {"program": "/tmp/x2mb-" + digest[:12] + ("/v" if session_kind == "menu_validation" else "/o"),
            "session": session_path(manifest, session_data_sha256),
            "request": stage + f"/.boundary-{file_index}-{boundary_index}.data"}


def _integer(value, *, low=0, high=2147483047):
    return type(value) is int and low <= value <= high


def _validate_request(values):
    _need(type(values) is dict and set(values) == set(REQUEST_FIELDS), "request fields differ")
    _need(values["schema"] == REQUEST_SCHEMA, "request schema differs")
    _index(values["file_index"], values["boundary_index"])
    _, name, access = STAGES[values["boundary_index"]]
    _need(values["boundary_name"] == name and values["mount_access"] == access, "stage name/access differs")
    for key in HEX_FIELDS:
        _need(type(values[key]) is str and re.fullmatch("[0-9a-f]{64}", values[key]) is not None,
              "invalid hex field: " + key)
    _need(type(values["boot_id"]) is str and re.fullmatch(session_context.PATTERNS["uuid"][1], values["boot_id"]) is not None,
          "invalid boot id")
    _need(type(values["session_nonce"]) is str and re.fullmatch("[0-9a-f]{32}", values["session_nonce"]) is not None,
          "invalid session nonce")
    for key in ("observed_epoch", "issued_epoch", "deadline_epoch"):
        # The calculated deadline may include the reserved 600 seconds, but
        # actual timestamps must have the same range as the shell scalar.
        high = 2147483647 if key == "deadline_epoch" else 2147483047
        _need(_integer(values[key], low=1, high=high), "invalid epoch: " + key)
    _need(values["observed_epoch"] <= 2147483047 and
          values["deadline_epoch"] == values["observed_epoch"] + 600 and
          values["observed_epoch"] <= values["issued_epoch"] <= values["deadline_epoch"],
          "original session deadline differs or expired")
    _need(values["maintenance_session_sha256"] == values["worker_session_sha256"],
          "this fixed path requires the same session data in both roles")


def _encode(values, fields):
    return "".join(key + "=" + str(values[key]) + "\n" for key in fields).encode("ascii")


def _decode(raw, fields):
    _need(type(raw) is bytes and 0 < len(raw) <= MAX_DATA_BYTES, "bounded bytes required")
    _need(raw.endswith(b"\n") and all(c == 10 or 32 <= c <= 126 for c in raw), "canonical ASCII lines required")
    lines = raw.decode("ascii").split("\n")[:-1]
    _need(len(lines) == len(fields), "wrong line count")
    values = {}
    for key, line in zip(fields, lines):
        _need(line.startswith(key + "="), "missing/duplicate/out-of-order field: " + key)
        value = line[len(key) + 1:]
        if key in INTEGER_FIELDS:
            _need(re.fullmatch("0|[1-9][0-9]{0,9}", value) is not None, "noncanonical integer")
            value = int(value)
        values[key] = value
    _need(_encode(values, fields) == raw, "noncanonical bytes")
    return values


def decode_request(raw):
    values = _decode(raw, REQUEST_FIELDS)
    _validate_request(values)
    return values


def session_kind_for_context(manifest, raw_session):
    """Choose a fixed protocol variant, not permission for temporary or final writes."""
    data = session_context.decode_session(raw_session)
    digest = _candidate(manifest)
    kind = data["kind"]
    _need(kind in ("menu_validation", "install"), "unsupported maintenance session kind")
    schema = (session_context.MENU_VALIDATION_SCHEMA if kind == "menu_validation"
              else session_context.INSTALL_SCHEMA)
    _need(raw_session.startswith(("schema=" + schema + "\n").encode("ascii")),
          "maintenance session schema differs")
    _need(data["observer_domain"] == "u:r:hbl_camera_service:s0", "maintenance context differs")
    if kind == "menu_validation":
        _need(data["purpose"] == "temporary_menu_validation" and data["action"] == "run_and_restore" and
              data["candidate_sha256"] == digest, "maintenance context differs")
    return kind


def make_request(manifest, maintenance_session_data, *, worker_session_sha256,
                 worker_program_sha256, file_index, boundary_index, challenge, issued_epoch):
    """One request only; a caller must issue a new challenge at each live boundary."""
    _index(file_index, boundary_index)
    data = session_context.decode_session(maintenance_session_data)
    digest = _candidate(manifest)
    session_kind = session_kind_for_context(manifest, maintenance_session_data)
    _, name, access = STAGES[boundary_index]
    values = dict(schema=REQUEST_SCHEMA, candidate_sha256=digest, boot_id=data["boot_id"],
        session_nonce=data["session_nonce"], file_index=file_index, boundary_index=boundary_index,
        boundary_name=name, mount_access=access, worker_program_sha256=worker_program_sha256,
        worker_session_sha256=worker_session_sha256,
        maintenance_program_sha256=_sha(render_observer(manifest, session_kind=session_kind).encode("ascii")),
        maintenance_session_sha256=_sha(maintenance_session_data), challenge=challenge,
        observed_epoch=data["observed_epoch"], issued_epoch=issued_epoch,
        deadline_epoch=data["observed_epoch"] + 600)
    _validate_request(values)
    return _encode(values, REQUEST_FIELDS)


def decode_response(raw, expected_request, *, received_epoch):
    """Validate one exact reply, not ordering, live transport or write authority."""
    request = decode_request(expected_request)
    response = _decode(raw, RESPONSE_FIELDS)
    _need(response["schema"] == RESPONSE_SCHEMA, "response schema differs")
    _need(all(response[key] == request[key] for key in REQUEST_FIELDS[1:]), "response binding differs")
    _need(response["request_sha256"] == _sha(expected_request), "request digest differs")
    _need(response["result"] == "OBSERVED_MATCH" and response["scope"] == SCOPE, "observation result/scope differs")
    _need(_integer(response["started_epoch"], low=1) and _integer(response["checked_epoch"], low=1) and
          _integer(received_epoch, low=1), "invalid response time")
    _need(request["issued_epoch"] <= response["started_epoch"] <= response["checked_epoch"] <=
          received_epoch <= request["deadline_epoch"], "response predates request or original lease expired")
    return response


def render_observer(manifest, *, session_kind="menu_validation"):
    """Fixed hbl program; argv: SESSION_SHA FILE_INDEX BOUNDARY_INDEX REQUEST_SHA.

    No path or command arguments. Program/request files are read back and bound
    to fixed paths. No observation output authorizes a later operation: the host
    must still return this single reply to the same blocked worker immediately.
    """
    _need(type(session_kind) is str and session_kind in ("menu_validation", "install"),
          "unsupported fixed maintenance session kind")
    digest = _candidate(manifest)
    fixed = paths(manifest, 0, 0, session_data_sha256="0" * 64, session_kind=session_kind)
    stage = fixed["session"].rsplit("/", 1)[0]
    source = '''#!/system/bin/sh
# LOCAL SOURCE ONLY: one read-only maintenance boundary, no camera executor.
set -eu
export PATH=/system/bin:/system/xbin:/sbin
export LC_ALL=C
# SESSION_DATA_PARSER_BEGIN
''' + session_context.shell_parser() + '''# SESSION_DATA_PARSER_END
[ "$#" = 4 ] || exit 32
[ "$(id -u)" = 0 ] && [ "$(cat /proc/self/attr/current)" = u:r:hbl_camera_service:s0 ] || exit 31
x2dii_sc_scalar hex64 "$1" && x2dii_sc_scalar hex64 "$4" || exit 32
case "$2" in 0|1|2|3) ;; *) exit 32;; esac
case "$3" in 0|1|2|3|4|5|6) ;; *) exit 32;; esac
mb_session_sha=$1
mb_file_index_arg=$2
mb_boundary_index_arg=$3
mb_request_sha=$4
'''
    source += f'''[ "$0" = {fixed['program']} ] || exit 32
mb_program={fixed['program']}
mb_session="{stage}/session-context-$mb_session_sha.data"
mb_request="{stage}/.boundary-$mb_file_index_arg-$mb_boundary_index_arg.data"
x2dii_load_session "$mb_session" "$mb_session_sha" || exit 32
'''
    if session_kind == "menu_validation":
        source += f'''[ "$X2DII_SESSION_SCHEMA" = x2dii-session-context-v3 ] &&
[ "$X2DII_SESSION_KIND" = menu_validation ] &&
[ "$X2DII_SESSION_PURPOSE" = temporary_menu_validation ] &&
[ "$X2DII_SESSION_ACTION" = run_and_restore ] &&
[ "$X2DII_SESSION_CANDIDATE_SHA256" = {digest} ] &&
[ "$X2DII_SESSION_OBSERVER_DOMAIN" = u:r:hbl_camera_service:s0 ] || exit 32
'''
    else:
        source += '''[ "$X2DII_SESSION_SCHEMA" = x2dii-session-context-v2 ] &&
[ "$X2DII_SESSION_KIND" = install ] &&
[ "$X2DII_SESSION_OBSERVER_DOMAIN" = u:r:hbl_camera_service:s0 ] || exit 32
'''
    source += r'''mb_read() {
 IFS= read -r mb_line || return 1
 [ "${#mb_line}" -le 512 ] && [ "${mb_line%%=*}" = "$1" ] || return 1
 mb_value=${mb_line#*=}
 [ "$mb_value" != "$mb_line" ]
}
mb_parse() {
'''
    for key in REQUEST_FIELDS:
        source += f' mb_read {key} || return 1\n mb_{key}=$mb_value\n'
    source += r''' mb_extra=
 if IFS= read -r mb_extra; then return 1
 else mb_read_status=$?; fi
 [ "$mb_read_status" = 1 ] && [ -z "$mb_extra" ]
}
mb_canonical_request() {
'''
    for key in REQUEST_FIELDS:
        source += f' printf \'{key}=%s\\n\' "$mb_{key}"\n'
    source += '''}
x2dii_sc_private "$mb_program" && x2dii_sc_private "$mb_request" || exit 33
mb_request_size=$(stat -c %s "$mb_request") || exit 33
case "$mb_request_size" in ''|*[!0-9]*) exit 33;; esac
[ "${#mb_request_size}" -le 4 ] && [ "$mb_request_size" -gt 0 ] && [ "$mb_request_size" -le 4096 ] || exit 33
mb_request_identity=$(stat -c '%d:%i:%f:%h:%s:%u:%g' "$mb_request") || exit 33
x2dii_sc_hash "$mb_request" "$mb_request_sha" && mb_parse < "$mb_request" || exit 33
'''
    source += f'''[ "$mb_schema" = {REQUEST_SCHEMA} ] && [ "$mb_candidate_sha256" = {digest} ] || exit 33
[ "$mb_file_index" = "$mb_file_index_arg" ] && [ "$mb_boundary_index" = "$mb_boundary_index_arg" ] || exit 33
case "$mb_boundary_index" in
'''
    for index, name, access in STAGES:
        source += f' {index}) [ "$mb_boundary_name" = {name} ] && [ "$mb_mount_access" = {access} ] || exit 33;;\n'
    source += 'esac\n'
    for key in HEX_FIELDS:
        source += f'x2dii_sc_scalar hex64 "$mb_{key}" || exit 33\n'
    source += '''[ "$mb_boot_id" = "$X2DII_SESSION_BOOT_ID" ] &&
[ "$mb_session_nonce" = "$X2DII_SESSION_SESSION_NONCE" ] &&
[ "$mb_observed_epoch" = "$X2DII_SESSION_OBSERVED_EPOCH" ] &&
[ "$mb_maintenance_session_sha256" = "$mb_session_sha" ] &&
[ "$mb_worker_session_sha256" = "$mb_session_sha" ] &&
[ "$mb_deadline_epoch" = "$((X2DII_SESSION_OBSERVED_EPOCH+600))" ] || exit 33
x2dii_sc_scalar epoch "$mb_issued_epoch" || exit 33
[ "$mb_issued_epoch" -ge "$mb_observed_epoch" ] && [ "$mb_issued_epoch" -le "$mb_deadline_epoch" ] || exit 33
mb_canonical_sha=$(mb_canonical_request | sha256sum) || exit 33
[ "${mb_canonical_sha%% *}" = "$mb_request_sha" ] || exit 33
x2dii_sc_hash "$mb_program" "$mb_maintenance_program_sha256" || exit 33
mb_program_identity=$(stat -c '%d:%i:%f:%h:%s:%u:%g' "$mb_program") || exit 33
mb_equals() {
 mb_expected=$1
 shift
 mb_actual=$("$@") || return 1
 [ "$mb_actual" = "$mb_expected" ]
}
mb_time() {
 mb_now=$(date -u +%s) || return 1
 x2dii_sc_scalar epoch "$mb_now" || return 1
 [ "$mb_now" -ge "$mb_issued_epoch" ] && [ "$mb_now" -le "$mb_deadline_epoch" ]
}
mb_time || exit 34
mb_started=$mb_now
mb_ticks() {
 mb_stat=$(cat "$1") || return 1
 mb_tail=${mb_stat##*) }
 [ "$mb_tail" != "$mb_stat" ] || return 1
 set -- $mb_tail
 [ "$#" -ge 20 ] || return 1
 shift 19
 printf '%s\\n' "$1"
}
mb_process() {
 mb_proc="/proc/$1"
 mb_equals "$2" mb_ticks "$mb_proc/stat" &&
 mb_equals "$3" readlink "$mb_proc/exe" &&
 x2dii_sc_hash "$mb_proc/exe" "$4" &&
 mb_equals "$5" cat "$mb_proc/attr/current" &&
 mb_equals "$6" readlink "$mb_proc/ns/mnt" &&
 mb_equals "$2" mb_ticks "$mb_proc/stat"
}
mb_file() {
 x2dii_sc_regular "$1" && mb_equals "$3" stat -c %s "$1" && x2dii_sc_hash "$1" "$2"
}
mb_mount() (
 set -f
 while :; do
  mb_line=
  if IFS= read -r mb_line; then
   set -- $mb_line
   [ "$#" = 6 ] || return 1
   if [ "$2" = /system ]; then printf '%s %s %s\\n' "$1" "$3" "$4" || return 1; fi
  else
   mb_status=$?
   [ "$mb_status" = 1 ] && [ -z "$mb_line" ] || return 1
   break
  fi
 done < /proc/mounts
)
mb_expected_mount="$X2DII_SESSION_MOUNT_DEVICE $X2DII_SESSION_MOUNT_FILESYSTEM $X2DII_SESSION_MOUNT_OPTIONS"
if [ "$mb_mount_access" = rw ]; then
 mb_expected_mount="$X2DII_SESSION_MOUNT_DEVICE $X2DII_SESSION_MOUNT_FILESYSTEM rw,${X2DII_SESSION_MOUNT_OPTIONS#ro,}"
fi
mb_runtime() {
 mb_equals 0 id -u && mb_equals u:r:hbl_camera_service:s0 cat /proc/self/attr/current &&
 mb_equals "$X2DII_SESSION_BOOT_ID" cat /proc/sys/kernel/random/boot_id &&
 mb_equals "$X2DII_SESSION_MOUNT_NAMESPACE" readlink /proc/self/ns/mnt &&
 mb_equals "$X2DII_SESSION_INIT_MOUNT_NAMESPACE" readlink /proc/1/ns/mnt &&
 mb_equals "$mb_expected_mount" mb_mount || return 1
'''
    for slot in (1, 2):
        for flag in ("active", "bootable", "successful"):
            source += f' mb_equals "$X2DII_SESSION_SLOT{slot}_{flag.upper()}" unrd slot_{slot}.status_{flag} || return 1\n'
    suffixes = ("PID", "START_TICKS", "EXE_TARGET", "EXE_SHA256", "DOMAIN", "MOUNT_NAMESPACE")
    for prefix in ("OBSERVER", "CORE_GUI", "CORE_SERVICE", "CORE_CAPTURE"):
        args = " ".join(f'"$X2DII_SESSION_{prefix}_{suffix}"' for suffix in suffixes)
        source += f' mb_process {args} || return 1\n'
    for prefix, path in (("GUI", "/system/bin/camera-gui"), ("SERVICE", "/system/bin/camera-service")):
        source += f' mb_file {path} "$X2DII_SESSION_CORE_{prefix}_EXE_SHA256" "$X2DII_SESSION_CORE_{prefix}_BYTES" || return 1\n'
    source += ''' mb_file "$X2DII_SESSION_CORE_CAPTURE_EXE_TARGET" "$X2DII_SESSION_CORE_CAPTURE_EXE_SHA256" "$X2DII_SESSION_CORE_CAPTURE_BYTES" || return 1
 mb_file /system/etc/imx861bqr_hb722.conf "$X2DII_SESSION_CORE_SENSOR_SHA256" "$X2DII_SESSION_CORE_SENSOR_BYTES" || return 1
 [ "$X2DII_SESSION_CORE_GUI_SERVICE_STATE" = running ] &&
 mb_equals running getprop init.svc.camera-gui &&
 mb_equals "$X2DII_SESSION_CORE_GUI_PID" pidof camera-gui &&
 mb_equals "$X2DII_SESSION_CORE_SERVICE_SERVICE_STATE" getprop init.svc.camera-service &&
 mb_equals "$X2DII_SESSION_CORE_SERVICE_PID" pidof camera-service
}
mb_runtime || exit 35
# No all-process maps scan: these are new inert-file boundaries, not deletion.
mb_environment=$(tr '\\000' '\\n' < "/proc/$X2DII_SESSION_CORE_GUI_PID/environ") || exit 35
case "
$mb_environment
" in *'
LD_PRELOAD='*|*'
X2DII_MENU_EXTENSION='*) exit 35;; esac
if grep -F /system/lib64/libx2dii_menu.so "/proc/$X2DII_SESSION_CORE_GUI_PID/maps" >/dev/null; then exit 35
else [ "$?" = 1 ] || exit 35; fi
x2dii_sc_private "$mb_program" && x2dii_sc_private "$mb_request" &&
x2dii_sc_hash "$mb_program" "$mb_maintenance_program_sha256" &&
x2dii_sc_hash "$mb_session" "$mb_session_sha" &&
x2dii_sc_hash "$mb_request" "$mb_request_sha" &&
mb_equals "$mb_program_identity" stat -c '%d:%i:%f:%h:%s:%u:%g' "$mb_program" &&
mb_equals "$mb_request_identity" stat -c '%d:%i:%f:%h:%s:%u:%g' "$mb_request" || exit 33
mb_runtime || exit 35
mb_time && [ "$mb_now" -ge "$mb_started" ] || exit 34
mb_checked=$mb_now
'''
    source += f"printf 'schema={RESPONSE_SCHEMA}\\n'\n"
    for key in REQUEST_FIELDS[1:]:
        source += f'printf \'{key}=%s\\n\' "$mb_{key}"\n'
    source += f'''printf 'request_sha256=%s\\nstarted_epoch=%s\\nchecked_epoch=%s\\nresult=OBSERVED_MATCH\\nscope={SCOPE}\\n' "$mb_request_sha" "$mb_started" "$mb_checked"
'''
    return source
