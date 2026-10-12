"""Small, non-executable data for the menu install/recovery renderers.

This module only encodes and parses data. It grants no authority, proves no
device fact, and performs no device access. Callers retain kind, freshness,
candidate/program identity, qualification and user-approval checks.
"""
from __future__ import annotations
from collections.abc import Mapping
import re

SCHEMA = "x2dii-session-context-v1"
INSTALL_SCHEMA = "x2dii-session-context-v2"
MENU_VALIDATION_SCHEMA = "x2dii-session-context-v3"
MENU_VALIDATION_FIELDS = ("purpose", "action", "candidate_sha256")
MAX_BYTES = 16384
COMMON_FIELDS = (
    "kind", "observed_epoch", "boot_id", "session_nonce", "mount_device",
    "mount_filesystem", "mount_options", "mount_namespace", "init_mount_namespace",
    "observer_pid", "observer_start_ticks", "observer_exe_target", "observer_exe_sha256",
    "observer_domain", "observer_mount_namespace", "active_slot", "official_slot",
    "slot1_active", "slot1_bootable", "slot1_successful", "slot2_active", "slot2_bootable",
    "slot2_successful", "rc_label", "library_label", "bootstrap_label", "model_label", "page_label",
)
RECOVERY_FIELDS = (
    "recovery_nonce", "gui_state", "gui_service_state", "gui_pid", "gui_start_ticks",
    "gui_exe_target", "gui_exe_sha256", "gui_domain", "gui_mount_namespace",
    "backup_owner_label", "present_library", "present_bootstrap", "present_model",
    "present_page", "rc_sha256",
)
GUI_PROCESS_FIELDS = RECOVERY_FIELDS[3:9]
CORE_PREFIXES = ("core_gui", "core_service", "core_capture")
PROCESS_SUFFIXES = ("pid", "start_ticks", "exe_target", "exe_sha256", "domain", "mount_namespace", "bytes")
INSTALL_RUNTIME_FIELDS = (
    *(prefix + "_" + suffix for prefix in CORE_PREFIXES for suffix in PROCESS_SUFFIXES),
    "core_gui_service_state", "core_service_service_state", "core_sensor_sha256", "core_sensor_bytes",
)
INTEGER_FIELDS = frozenset(("observed_epoch", "observer_pid", "gui_pid", *(
    key for key in INSTALL_RUNTIME_FIELDS if key.endswith(("_pid", "_bytes")))))
FIELD_KINDS = {
    "purpose": "menu_purpose", "action": "menu_action", "candidate_sha256": "hex64",
    "kind": "kind", "observed_epoch": "epoch", "boot_id": "uuid", "session_nonce": "hex32",
    "mount_device": "device", "mount_filesystem": "filesystem", "mount_options": "options",
    "mount_namespace": "namespace", "init_mount_namespace": "namespace",
    "observer_pid": "pid", "observer_start_ticks": "ticks", "observer_exe_target": "executable",
    "observer_exe_sha256": "hex64", "observer_domain": "domain", "observer_mount_namespace": "namespace",
    "active_slot": "slot", "official_slot": "slot",
    **{k: "bit" for k in COMMON_FIELDS if k.startswith(("slot1_", "slot2_"))},
    **{k: "label" for k in COMMON_FIELDS if k.endswith("_label")},
    "recovery_nonce": "hex32", "gui_state": "gui_state", "gui_service_state": "service_state",
    "gui_pid": "pid", "gui_start_ticks": "ticks", "gui_exe_target": "executable",
    "gui_exe_sha256": "hex64", "gui_domain": "domain", "gui_mount_namespace": "namespace",
    "backup_owner_label": "label", "present_library": "bit", "present_bootstrap": "bit",
    "present_model": "bit", "present_page": "bit", "rc_sha256": "hex64",
    **{prefix + "_" + suffix: kind for prefix in CORE_PREFIXES for suffix, kind in zip(
        PROCESS_SUFFIXES, ("pid", "ticks", "executable", "hex64", "domain", "namespace", "bytes"))},
    "core_gui_service_state": "service_state", "core_service_service_state": "service_state",
    "core_sensor_sha256": "hex64", "core_sensor_bytes": "bytes",
}
PATTERNS = {
    "uuid": (36, r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}"),
    "hex32": (32, r"[0-9a-f]{32}"), "hex64": (64, r"[0-9a-f]{64}"),
    "device": (200, r"/dev/block/[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*"),
    "options": (256, r"ro,[A-Za-z0-9_][A-Za-z0-9_=.-]*(,[A-Za-z0-9_][A-Za-z0-9_=.-]*)*"),
    "namespace": (26, r"mnt:\[[1-9][0-9]{0,19}\]"),
    "ticks": (20, r"[1-9][0-9]{0,19}"),
    "executable": (128, r"/system/(bin|xbin)/[A-Za-z0-9_-]{1,100}"),
    "domain": (128, r"u:r:[a-z0-9_]{1,96}:s0"),
    "label": (128, r"u:object_r:[a-z0-9_]{1,96}:s0"),
}
CHOICES = {
    "kind": ("install", "recovery", "menu_validation"),
    "menu_purpose": ("temporary_menu_validation",), "menu_action": ("run_and_restore",),
    "filesystem": ("ext4",), "slot": ("slot_1", "slot_2"),
    "bit": ("0", "1"), "gui_state": ("absent", "present"),
    "service_state": ("stopped", "running", "restarting"),
}


class SessionContextError(ValueError):
    """Invalid data, never an installation or device verdict."""


def _need(ok, message):
    if not ok:
        raise SessionContextError(message)


def _fields(kind, schema):
    _need(type(schema) is str and schema in (SCHEMA, INSTALL_SCHEMA, MENU_VALIDATION_SCHEMA), "unsupported session schema")
    _need(type(kind) is str and kind in CHOICES["kind"], "invalid session kind")
    if schema == INSTALL_SCHEMA:
        _need(kind == "install", "v2 is install-only")
        return COMMON_FIELDS + INSTALL_RUNTIME_FIELDS
    if schema == MENU_VALIDATION_SCHEMA:
        _need(kind == "menu_validation", "v3 is temporary menu-validation-only")
        return COMMON_FIELDS + INSTALL_RUNTIME_FIELDS + MENU_VALIDATION_FIELDS
    _need(kind != "menu_validation", "temporary menu validation requires v3")
    return COMMON_FIELDS + (RECOVERY_FIELDS if kind == "recovery" else ())


def _validate_scalar(key, value):
    kind = FIELD_KINDS[key]
    if kind in ("epoch", "pid", "bytes"):
        low, high = (1, 2147483047) if kind == "epoch" else (2 if kind == "pid" else 1, 2147483647)
        _need(type(value) is int and low <= value <= high, "bounded integer required: " + key)
        return
    _need(type(value) is str, "string required: " + key)
    if kind in CHOICES:
        _need(value in CHOICES[kind], "unsupported value: " + key)
    else:
        limit, pattern = PATTERNS[kind]
        _need(0 < len(value) <= limit and re.fullmatch(pattern, value) is not None,
              "invalid scalar: " + key)
    if kind == "options":
        _need(not any(token in ("ro", "rw") for token in value.split(",")[1:]),
              "contradictory mount access option")


def _validate_values(values, schema):
    fields = _fields(values.get("kind"), schema)
    _need(set(values) == set(fields), "missing or extra session field")
    absent = values["kind"] == "recovery" and values["gui_state"] == "absent"
    for key in fields:
        if absent and key in GUI_PROCESS_FIELDS:
            _need(type(values[key]) is str and values[key] == "-", "absent GUI identity must be '-'")
        elif (values["kind"] == "recovery" and key in ("library_label", "bootstrap_label", "model_label", "page_label")
              and values[key] == "-" and values["present_" + key.removesuffix("_label")] == "0"):
            # This denotes no observed inode/label, not a default label.
            pass
        else:
            _validate_scalar(key, values[key])
    _need(values["mount_namespace"] == values["init_mount_namespace"] == values["observer_mount_namespace"],
          "namespace observations differ")
    _need(values["active_slot"] != values["official_slot"], "active and official slots must differ")
    for slot in (1, 2):
        expected = "1" if values["active_slot"] == "slot_" + str(slot) else "0"
        _need(values[f"slot{slot}_active"] == expected and
              values[f"slot{slot}_bootable"] == values[f"slot{slot}_successful"] == "1",
              "contradictory slot observation")
    if values["kind"] == "recovery":
        _need(values["recovery_nonce"] == values["session_nonce"], "recovery nonce differs from session")
        if not absent:
            _need(values["gui_exe_target"] == "/system/bin/camera-gui" and
                  values["gui_mount_namespace"] == values["mount_namespace"], "GUI identity differs")
    if schema in (INSTALL_SCHEMA, MENU_VALIDATION_SCHEMA):
        _need(values["core_gui_exe_target"] == "/system/bin/camera-gui" and
              values["core_service_exe_target"] == "/system/bin/camera-service", "core executable differs")
        for index, prefix in enumerate(CORE_PREFIXES):
            _need(values[prefix + "_mount_namespace"] == values["mount_namespace"], "core namespace differs")
            for other in ("observer", *CORE_PREFIXES[:index]):
                if values[prefix + "_pid"] == values[other + "_pid"]:
                    suffixes = PROCESS_SUFFIXES[:-1] if other == "observer" else PROCESS_SUFFIXES
                    _need(all(values[prefix + "_" + suffix] == values[other + "_" + suffix]
                              for suffix in suffixes), "same PID has conflicting identity")
                if other != "observer" and values[prefix + "_exe_target"] == values[other + "_exe_target"]:
                    _need(all(values[prefix + "_" + suffix] == values[other + "_" + suffix]
                              for suffix in ("exe_sha256", "bytes")), "same executable has conflicting bytes")
    return fields


def encode_session(values: Mapping[str, str | int], *, schema=SCHEMA) -> bytes:
    _need(isinstance(values, Mapping), "session mapping required")
    values = dict(values)
    fields = _validate_values(values, schema)
    raw = ("schema=" + schema + "\n" + "".join(
        key + "=" + str(values[key]) + "\n" for key in fields)).encode("ascii")
    _need(len(raw) <= MAX_BYTES, "session data too large")
    return raw


def decode_session(raw: bytes) -> dict[str, str | int]:
    _need(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, "bounded bytes required")
    _need(raw.endswith(b"\n") and all(c == 10 or 32 <= c <= 126 for c in raw),
          "ASCII lines with final newline required")
    lines = raw.decode("ascii").split("\n")[:-1]
    _need(lines[0] in tuple("schema=" + s for s in (SCHEMA, INSTALL_SCHEMA, MENU_VALIDATION_SCHEMA)), "unsupported session schema")
    schema = lines[0][7:]
    _need(len(lines) > 1 and lines[1].startswith("kind="), "session kind must be first")
    fields = _fields(lines[1][5:], schema)
    _need(len(lines) == len(fields) + 1, "wrong session field count")
    values = {}
    for key, line in zip(fields, lines[1:]):
        _need(line.startswith(key + "="), "missing, duplicate or out-of-order field: " + key)
        values[key] = line[len(key) + 1:]
    for key in INTEGER_FIELDS.intersection(values):
        if key == "gui_pid" and values[key] == "-":
            continue
        try:
            values[key] = int(values[key])
        except ValueError as error:
            raise SessionContextError("integer required: " + key) from error
    _need(encode_session(values, schema=schema) == raw, "noncanonical session bytes")
    return values


def _shell_validation() -> str:
    choices = "".join(
        f'  {kind}) case "$x2dii_sc_v" in ' + "|".join(values) + ') return 0;; *) return 1;; esac;;\n'
        for kind, values in CHOICES.items())
    common = ""
    for key in COMMON_FIELDS:
        line = f' x2dii_sc_scalar {FIELD_KINDS[key]} "$x2dii_sc_{key}" || return 1\n'
        if key in ("library_label", "bootstrap_label", "model_label", "page_label"):
            present = "present_" + key.removesuffix("_label")
            line = (f' if [ "$x2dii_sc_kind" = recovery ] && [ "$x2dii_sc_{present}" = 0 ] && '
                    f'[ "$x2dii_sc_{key}" = - ]; then :\n else\n' + line + ' fi\n')
        common += line
    install_runtime = "".join(f'  x2dii_sc_scalar {FIELD_KINDS[k]} "$x2dii_sc_{k}" || return 1\n'
                              for k in INSTALL_RUNTIME_FIELDS)
    install_runtime += ('  [ "$x2dii_sc_core_gui_exe_target" = /system/bin/camera-gui ] || return 1\n'
                        '  [ "$x2dii_sc_core_service_exe_target" = /system/bin/camera-service ] || return 1\n')
    for index, prefix in enumerate(CORE_PREFIXES):
        install_runtime += f'  [ "$x2dii_sc_{prefix}_mount_namespace" = "$x2dii_sc_mount_namespace" ] || return 1\n'
        for other in ("observer", *CORE_PREFIXES[:index]):
            install_runtime += f'  if [ "$x2dii_sc_{prefix}_pid" = "$x2dii_sc_{other}_pid" ]; then\n'
            suffixes = PROCESS_SUFFIXES[:-1] if other == "observer" else PROCESS_SUFFIXES
            install_runtime += "".join(
                f'   [ "$x2dii_sc_{prefix}_{suffix}" = "$x2dii_sc_{other}_{suffix}" ] || return 1\n'
                for suffix in suffixes) + '  fi\n'
            if other != "observer":
                install_runtime += f'  if [ "$x2dii_sc_{prefix}_exe_target" = "$x2dii_sc_{other}_exe_target" ]; then\n'
                install_runtime += "".join(
                    f'   [ "$x2dii_sc_{prefix}_{suffix}" = "$x2dii_sc_{other}_{suffix}" ] || return 1\n'
                    for suffix in ("exe_sha256", "bytes")) + '  fi\n'
    recovery = ""
    for key in RECOVERY_FIELDS:
        line = f'  x2dii_sc_scalar {FIELD_KINDS[key]} "$x2dii_sc_{key}" || return 1\n'
        if key in GUI_PROCESS_FIELDS:
            line = (f'  if [ "$x2dii_sc_gui_state" = absent ]; then\n'
                    f'   [ "$x2dii_sc_{key}" = - ] || return 1\n  else\n' + line + '  fi\n')
        recovery += line
    menu_validation = "".join(f'  x2dii_sc_scalar {FIELD_KINDS[k]} "$x2dii_sc_{k}" || return 1\n'
                              for k in MENU_VALIDATION_FIELDS)
    return r'''x2dii_sc_hex() {
 [ "${#1}" = "$2" ] || return 1
 case "$1" in *[!0-9a-f]*|'') return 1;; esac
}
x2dii_sc_digits() {
 [ "${#1}" -le "$2" ] || return 1
 case "$1" in ''|0*|*[!0-9]*) return 1;; esac
}
x2dii_sc_scalar() {
 x2dii_sc_v=$2
 case "$1" in
''' + choices + r'''  epoch|pid|bytes)
   x2dii_sc_digits "$x2dii_sc_v" 10 || return 1
   if [ "${#x2dii_sc_v}" = 10 ]; then
    # Compare only the final nine digits numerically: safe on 32-bit shells.
    case "$x2dii_sc_v" in
     1*) ;;
     2*)
      x2dii_sc_last=${x2dii_sc_v#?}
      if [ "$1" = epoch ]; then [ "$x2dii_sc_last" -le 147483047 ] || return 1
      else [ "$x2dii_sc_last" -le 147483647 ] || return 1; fi;;
     *) return 1;;
    esac
   fi
   [ "$1" != pid ] || [ "$x2dii_sc_v" != 1 ];;
  hex32) x2dii_sc_hex "$x2dii_sc_v" 32;;
  hex64) x2dii_sc_hex "$x2dii_sc_v" 64;;
  uuid)
   [ "${#x2dii_sc_v}" = 36 ] || return 1
   x2dii_sc_uuid=$x2dii_sc_v
   for x2dii_sc_width in 8 4 4 4; do
    x2dii_sc_hex "${x2dii_sc_uuid%%-*}" "$x2dii_sc_width" || return 1
    x2dii_sc_uuid=${x2dii_sc_uuid#*-}
   done
   x2dii_sc_hex "$x2dii_sc_uuid" 12;;
  ticks) x2dii_sc_digits "$x2dii_sc_v" 20;;
  namespace)
   case "$x2dii_sc_v" in 'mnt:['*']') ;; *) return 1;; esac
   x2dii_sc_inner=${x2dii_sc_v#'mnt:['}
   x2dii_sc_inner=${x2dii_sc_inner%']'}
   x2dii_sc_digits "$x2dii_sc_inner" 20;;
  executable)
   [ "${#x2dii_sc_v}" -le 128 ] || return 1
   case "$x2dii_sc_v" in
    /system/bin/*) x2dii_sc_inner=${x2dii_sc_v#/system/bin/};;
    /system/xbin/*) x2dii_sc_inner=${x2dii_sc_v#/system/xbin/};;
    *) return 1;;
   esac
   [ "${#x2dii_sc_inner}" -le 100 ] || return 1
   case "$x2dii_sc_inner" in ''|*[!A-Za-z0-9_-]*) return 1;; esac;;
  domain|label)
   [ "${#x2dii_sc_v}" -le 128 ] || return 1
   if [ "$1" = domain ]; then
    case "$x2dii_sc_v" in u:r:*:s0) x2dii_sc_inner=${x2dii_sc_v#u:r:};; *) return 1;; esac
   else
    case "$x2dii_sc_v" in u:object_r:*:s0) x2dii_sc_inner=${x2dii_sc_v#u:object_r:};; *) return 1;; esac
   fi
   x2dii_sc_inner=${x2dii_sc_inner%:s0}
   [ "${#x2dii_sc_inner}" -le 96 ] || return 1
   case "$x2dii_sc_inner" in ''|*[!a-z0-9_]*) return 1;; esac;;
  device)
   [ "${#x2dii_sc_v}" -le 200 ] || return 1
   case "$x2dii_sc_v" in /dev/block/*) x2dii_sc_inner=${x2dii_sc_v#/dev/block/};; *) return 1;; esac
   case "$x2dii_sc_inner" in ''|/*|*/|*//*|*[!A-Za-z0-9_/-]*) return 1;; esac;;
  options)
   [ "${#x2dii_sc_v}" -le 256 ] || return 1
   case "$x2dii_sc_v" in ro,*) x2dii_sc_opts=${x2dii_sc_v#ro,};; *) return 1;; esac
   case "$x2dii_sc_opts" in ''|,*|*,|*,,*|*[!A-Za-z0-9_=.,-]*) return 1;; esac
   while :; do
    x2dii_sc_token=${x2dii_sc_opts%%,*}
    case "$x2dii_sc_token" in ro|rw) return 1;; esac
    case "$x2dii_sc_token" in [A-Za-z0-9_]*) ;; *) return 1;; esac
    [ "$x2dii_sc_token" != "$x2dii_sc_opts" ] || break
    x2dii_sc_opts=${x2dii_sc_opts#*,}
   done;;
  *) return 1;;
 esac
}
x2dii_sc_validate() (
 LC_ALL=C
 export LC_ALL
''' + common + r''' [ "$x2dii_sc_mount_namespace" = "$x2dii_sc_init_mount_namespace" ] || return 1
 [ "$x2dii_sc_mount_namespace" = "$x2dii_sc_observer_mount_namespace" ] || return 1
 [ "$x2dii_sc_active_slot" != "$x2dii_sc_official_slot" ] || return 1
 [ "$x2dii_sc_slot1_bootable" = 1 ] && [ "$x2dii_sc_slot1_successful" = 1 ] || return 1
 [ "$x2dii_sc_slot2_bootable" = 1 ] && [ "$x2dii_sc_slot2_successful" = 1 ] || return 1
 if [ "$x2dii_sc_active_slot" = slot_1 ]; then
  [ "$x2dii_sc_slot1_active" = 1 ] && [ "$x2dii_sc_slot2_active" = 0 ] || return 1
 else
  [ "$x2dii_sc_slot1_active" = 0 ] && [ "$x2dii_sc_slot2_active" = 1 ] || return 1
 fi
 if [ "$x2dii_sc_schema" != x2dii-session-context-v1 ]; then
''' + install_runtime + r''' fi
 if [ "$x2dii_sc_kind" = menu_validation ]; then
''' + menu_validation + r''' fi
 if [ "$x2dii_sc_kind" = recovery ]; then
''' + recovery + r'''  [ "$x2dii_sc_recovery_nonce" = "$x2dii_sc_session_nonce" ] || return 1
  if [ "$x2dii_sc_gui_state" = present ]; then
   [ "$x2dii_sc_gui_exe_target" = /system/bin/camera-gui ] || return 1
   [ "$x2dii_sc_gui_mount_namespace" = "$x2dii_sc_mount_namespace" ] || return 1
  fi
 fi
 return 0
)
'''


def shell_parser() -> str:
    """Return fixed POSIX-style shell functions; no session value is rendered.

    x2dii_load_session PATH EXPECTED_SHA256 only parses a local data file.
    It requires root:root mode 0600 data in a root:root mode 0700 direct parent,
    and rejects linked ancestors. Its caller must establish trusted shell/PATH/
    tools and a separately bound expected digest. Shell cannot request
    atomic O_NOFOLLOW/nonblocking open; before/after observations do not defeat
    malicious privileged concurrent pathname replacement. Native tools, actual
    ownership/SELinux and observed directory safety remain target gates.

    Success sets X2DII_SESSION_VALID=1, X2DII_SESSION_SCHEMA and
    X2DII_SESSION_<UPPERCASE_FIELD>. v1 install parsing is compatibility only;
    installation consumers must explicitly require INSTALL_SCHEMA (v2).
    Failure clears every public field and leaves VALID=0. Consumers must check
    the return value AND the intended kind, then their normal identity,
    freshness, candidate, qualification and approval requirements. There are
    no locks, service actions, mounts, temporary files, writes or authorization.
    """
    all_fields = COMMON_FIELDS + RECOVERY_FIELDS + INSTALL_RUNTIME_FIELDS + MENU_VALIDATION_FIELDS
    clear = "unset X2DII_SESSION_SCHEMA " + " ".join("X2DII_SESSION_" + k.upper() for k in all_fields) + "\n"
    read_common = "".join(
        f" x2dii_sc_read {key} || return 1\n x2dii_sc_{key}=$x2dii_sc_value\n"
        for key in COMMON_FIELDS)
    read_recovery = "".join(
        f"  x2dii_sc_read {key} || return 1\n  x2dii_sc_{key}=$x2dii_sc_value\n"
        for key in RECOVERY_FIELDS)
    read_install_runtime = "".join(
        f"  x2dii_sc_read {key} || return 1\n  x2dii_sc_{key}=$x2dii_sc_value\n"
        for key in INSTALL_RUNTIME_FIELDS)
    emit_common = "".join(f" printf '{key}=%s\\n' \"$x2dii_sc_{key}\"\n" for key in COMMON_FIELDS)
    emit_recovery = "".join(f"  printf '{key}=%s\\n' \"$x2dii_sc_{key}\"\n" for key in RECOVERY_FIELDS)
    emit_install_runtime = "".join(f"  printf '{key}=%s\\n' \"$x2dii_sc_{key}\"\n" for key in INSTALL_RUNTIME_FIELDS)
    commit_common = "".join(f' X2DII_SESSION_{key.upper()}="$x2dii_sc_{key}"\n' for key in COMMON_FIELDS)
    commit_recovery = "".join(f'  X2DII_SESSION_{key.upper()}="$x2dii_sc_{key}"\n' for key in RECOVERY_FIELDS)
    commit_install_runtime = "".join(f'  X2DII_SESSION_{key.upper()}="$x2dii_sc_{key}"\n' for key in INSTALL_RUNTIME_FIELDS)
    read_menu = "".join(f"  x2dii_sc_read {key} || return 1\n  x2dii_sc_{key}=$x2dii_sc_value\n"
                        for key in MENU_VALIDATION_FIELDS)
    emit_menu = "".join(f"  printf '{key}=%s\\n' \"$x2dii_sc_{key}\"\n" for key in MENU_VALIDATION_FIELDS)
    commit_menu = "".join(f'  X2DII_SESSION_{key.upper()}="$x2dii_sc_{key}"\n' for key in MENU_VALIDATION_FIELDS)
    return _shell_validation() + r'''# Fixed data parser only. Data and direct parent must be root-owned and private.
# No atomic O_NOFOLLOW open is available here; this is not adversarial-root safety.
x2dii_sc_regular() {
 [ -f "$1" ] && [ ! -L "$1" ] || return 1
 x2dii_sc_links=$(stat -c %h "$1") || return 1
 [ "$x2dii_sc_links" = 1 ]
}
x2dii_sc_private() {
 x2dii_sc_regular "$1" || return 1
 x2dii_sc_owner_mode=$(stat -c '%u:%g:%a' "$1") || return 1
 [ "$x2dii_sc_owner_mode" = 0:0:600 ] || return 1
 x2dii_sc_parent_path=${1%/*}
 [ -n "$x2dii_sc_parent_path" ] || x2dii_sc_parent_path=/
 x2dii_sc_owner_mode=$(stat -c '%u:%g:%a' "$x2dii_sc_parent_path") || return 1
 [ "$x2dii_sc_owner_mode" = 0:0:700 ] || return 1
 x2dii_sc_parent=$x2dii_sc_parent_path
 while [ -n "$x2dii_sc_parent" ]; do
  [ -d "$x2dii_sc_parent" ] && [ ! -L "$x2dii_sc_parent" ] || return 1
  x2dii_sc_parent=${x2dii_sc_parent%/*}
 done
}
x2dii_sc_hash() {
 x2dii_sc_hash_output=$(sha256sum "$1") || return 1
 [ "${x2dii_sc_hash_output%% *}" = "$2" ]
}
x2dii_sc_read() {
 IFS= read -r x2dii_sc_line || return 1
 [ "${#x2dii_sc_line}" -le 512 ] || return 1
 [ "${x2dii_sc_line%%=*}" = "$1" ] || return 1
 x2dii_sc_value=${x2dii_sc_line#*=}
 [ "$x2dii_sc_value" != "$x2dii_sc_line" ]
}
x2dii_sc_parse() {
 x2dii_sc_read schema || return 1
 case "$x2dii_sc_value" in x2dii-session-context-v1|x2dii-session-context-v2|x2dii-session-context-v3) ;; *) return 1;; esac
 x2dii_sc_schema=$x2dii_sc_value
''' + read_common + r'''
 case "$x2dii_sc_schema:$x2dii_sc_kind" in
  x2dii-session-context-v1:install|x2dii-session-context-v1:recovery|x2dii-session-context-v2:install|x2dii-session-context-v3:menu_validation) ;;
  *) return 1;;
 esac
 if [ "$x2dii_sc_schema" != x2dii-session-context-v1 ]; then
''' + read_install_runtime + r''' elif [ "$x2dii_sc_kind" = recovery ]; then
''' + read_recovery + r''' fi
 if [ "$x2dii_sc_kind" = menu_validation ]; then
''' + read_menu + r''' fi
 x2dii_sc_extra=
 if IFS= read -r x2dii_sc_extra; then return 1; fi
 [ -z "$x2dii_sc_extra" ]
}
x2dii_sc_canonical() {
 printf 'schema=%s\n' "$x2dii_sc_schema"
''' + emit_common + r''' if [ "$x2dii_sc_schema" != x2dii-session-context-v1 ]; then
''' + emit_install_runtime + r''' elif [ "$x2dii_sc_kind" = recovery ]; then
''' + emit_recovery + r''' fi
 if [ "$x2dii_sc_kind" = menu_validation ]; then
''' + emit_menu + r''' fi
}
x2dii_load_session() {
 X2DII_SESSION_VALID=0
''' + clear + r''' [ "$#" = 2 ] || return 1
 x2dii_sc_path=$1
 x2dii_sc_expected=$2
 case "$x2dii_sc_expected" in *[!0-9a-f]*|'') return 1;; esac
 [ "${#x2dii_sc_expected}" = 64 ] || return 1
 case "$x2dii_sc_path" in /*) ;; *) return 1;; esac
 case "$x2dii_sc_path" in *[!A-Za-z0-9_./-]*|*//*|*/../*|*/./*|*/..|*/.|*/) return 1;; esac
 [ "${#x2dii_sc_path}" -le 512 ] || return 1
 x2dii_sc_private "$x2dii_sc_path" || return 1
 x2dii_sc_size=$(stat -c %s "$x2dii_sc_path") || return 1
 case "$x2dii_sc_size" in *[!0-9]*|'') return 1;; esac
 [ "${#x2dii_sc_size}" -le 5 ] && [ "$x2dii_sc_size" -gt 0 ] && [ "$x2dii_sc_size" -le 16384 ] || return 1
 x2dii_sc_before=$(stat -c '%d:%i:%f:%h:%s:%u:%g' "$x2dii_sc_path") || return 1
 x2dii_sc_hash "$x2dii_sc_path" "$x2dii_sc_expected" || return 1
 x2dii_sc_private "$x2dii_sc_path" || return 1
 x2dii_sc_parse < "$x2dii_sc_path" || return 1
 x2dii_sc_validate || return 1
 x2dii_sc_encoded=$(x2dii_sc_canonical | sha256sum) || return 1
 [ "${x2dii_sc_encoded%% *}" = "$x2dii_sc_expected" ] || return 1
 x2dii_sc_private "$x2dii_sc_path" || return 1
 x2dii_sc_after=$(stat -c '%d:%i:%f:%h:%s:%u:%g' "$x2dii_sc_path") || return 1
 [ "$x2dii_sc_after" = "$x2dii_sc_before" ] || return 1
 x2dii_sc_hash "$x2dii_sc_path" "$x2dii_sc_expected" || return 1
 x2dii_sc_private "$x2dii_sc_path" || return 1
 x2dii_sc_after=$(stat -c '%d:%i:%f:%h:%s:%u:%g' "$x2dii_sc_path") || return 1
 [ "$x2dii_sc_after" = "$x2dii_sc_before" ] || return 1
 X2DII_SESSION_SCHEMA=$x2dii_sc_schema
''' + commit_common + r''' if [ "$x2dii_sc_schema" != x2dii-session-context-v1 ]; then
''' + commit_install_runtime + r''' elif [ "$x2dii_sc_kind" = recovery ]; then
''' + commit_recovery + r''' fi
 if [ "$x2dii_sc_kind" = menu_validation ]; then
''' + commit_menu + r''' fi
 X2DII_SESSION_VALID=1
 return 0
}
'''
