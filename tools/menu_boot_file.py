"""Local fixed su rc transactions; no publisher, transport or authorization.

The supervised variant waits for fixed maintenance boundaries; the historical
and stable-only renderers remain explicitly UNCONNECTED and non-publishable.
Neither an rc receipt nor local file tests qualify startup, reboot, removal,
a package or camera installation. No GUI control, mkdir, hardlink, relabel or
deletion is implemented here.

The source keeps the original rc present until one final same-filesystem rename.
A verified separate backup is retained, since the pinned su system_file grants
do not include link. Only root:root 0644 and security.selinux are supported;
additional xattrs require a separate verified preservation method, not omission.
The original toybox b62d2767deab3f0645a36ebfca566561eece56bb41d4739bab17609cb48292cd
contains a getfattr applet (name 0x4302b, table 0x805e0, function 0x2542c,
options dhn:), even though historical command -v getfattr failed. Its names/-d
format matches AOSP android-9.0.0_r1/toys/pending/getfattr.c. Explicit applet
invocation, live permissions/labels, target timestamp/rename/sync behavior and
complete init scan roots still need target qualification. No GNU hex options
or unverified relabel operation are assumed.
"""
from __future__ import annotations

import re

from . import boot_config as boot
from .session_context import shell_parser
from .temporary_menu_files import render_preplacement


STATUS = "LOCAL_SUPERVISED_SOURCE_TRANSPORT_UNQUALIFIED"


def encode_payload_identities(manifest, identities):
    """Four already validated placement identities, not paths or permissions."""
    render_preplacement(manifest, file_index=0)
    if type(identities) not in (tuple, list) or len(identities) != 4:
        raise ValueError("exactly four payload identities required")
    for identity, entry in zip(identities, manifest["candidate"]["files"]):
        pattern = rf"(?:0|[1-9][0-9]{{0,19}}):[1-9][0-9]{{0,19}}:81a4:1:{entry['bytes']}:0:0"
        if type(identity) is not str or re.fullmatch(pattern, identity) is None:
            raise ValueError("payload identity does not match candidate size/root/0644/single link")
    if len({item.split(":")[0] + ":" + item.split(":")[1] for item in identities}) != 4:
        raise ValueError("payload identities must have four distinct inodes")
    return "".join(f"identity_{i}={value}\n" for i, value in enumerate(identities)).encode("ascii")


def decode_payload_identities(manifest, raw):
    if type(raw) is not bytes or len(raw) > 1024:
        raise ValueError("bounded payload identity data required")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError("ASCII payload identity data required") from error
    if len(lines) != 4 or any(not line.startswith(f"identity_{i}=") for i, line in enumerate(lines)):
        raise ValueError("four ordered identity fields required")
    identities = tuple(line.split("=", 1)[1] for line in lines)
    if encode_payload_identities(manifest, identities) != raw:
        raise ValueError("noncanonical payload identity data")
    return identities


def render_supervised_boot_transaction(manifest, *, action, original_rc, metadata, init_scan_roots):
    """Fixed boot transaction with live host-mediated maintenance boundaries.

    Activation argv3 hashes four final-placement identities; recovery argv3 is
    the saved official backup identity. Neither function launches a transport.
    Recovery never needs the four extension files to be healthy or even exist.
    """
    from . import menu_boot_boundary as boundary
    import hashlib

    source = render_stable_boot_transaction(manifest, action=action, original_rc=original_rc,
        metadata=metadata, init_scan_roots=init_scan_roots)
    digest = manifest["candidate_sha256"]
    stage = "/blackbox/x2dii-menu-stage/" + digest[:24]
    observer_hash = hashlib.sha256(boundary.render_observer(manifest, action=action).encode("ascii")).hexdigest()

    def replace_once(old, new):
        nonlocal source
        if source.count(old) != 1:
            raise ValueError("fixed supervised boot boundary changed")
        source = source.replace(old, new, 1)

    replace_once(f'[ "$1" = \'{stage}/session-context.data\' ] || exit 32\nx2dii_sc_scalar hex64 "$2" || exit 32',
        f'x2dii_sc_scalar hex64 "$2" || exit 32\n[ "$1" = "{stage}/session-context-$2.data" ] || exit 32')
    dependencies = 'boot_dependencies() { :; }\n'
    if action == "activate":
        replace_once('[ "$#" = 2 ] || exit 32', '[ "$#" = 3 ] || exit 32')
        dependencies = r'''
x2dii_sc_scalar hex64 "$3" || exit 32
boot_dependencies_sha=$3
boot_dependencies_path="@STAGE@/.payload-identities-$X2DII_SESSION_SESSION_NONCE.data"
x2dii_sc_private "$boot_dependencies_path" && hashok "$boot_dependencies_path" "$boot_dependencies_sha" || exit 81
boot_dependencies_size=$(stat -c %s "$boot_dependencies_path") || exit 81
case "$boot_dependencies_size" in ''|*[!0-9]*) exit 81;; esac
[ "${#boot_dependencies_size}" -le 4 ] && [ "$boot_dependencies_size" -gt 0 ] && [ "$boot_dependencies_size" -le 1024 ] || exit 81
boot_dependencies_identity=$(stat -c '%d:%i:%f:%h:%s:%u:%g' "$boot_dependencies_path") || exit 81
boot_load_dependencies() {
'''
        for i in range(4):
            dependencies += f''' IFS= read -r boot_line || return 1
 case "$boot_line" in identity_{i}=*) ;; *) return 1;; esac
 boot_payload_{i}=${{boot_line#identity_{i}=}}
'''
        dependencies += r''' boot_extra=
 if IFS= read -r boot_extra; then return 1; else boot_read_status=$?; fi
 [ "$boot_read_status" = 1 ] && [ -z "$boot_extra" ]
}
boot_load_dependencies < "$boot_dependencies_path" || exit 81
boot_canonical_dependencies() {
 printf 'identity_0=%s\nidentity_1=%s\nidentity_2=%s\nidentity_3=%s\n' "$boot_payload_0" "$boot_payload_1" "$boot_payload_2" "$boot_payload_3"
}
boot_canonical_sha=$(boot_canonical_dependencies | sha256sum) || exit 81
[ "${boot_canonical_sha%% *}" = "$boot_dependencies_sha" ] || exit 81
boot_dependency() (
 set -f
 boot_dep_path=$1; boot_dep_hash=$2; boot_dep_size=$3; boot_dep_label=$4; boot_dep_identity=$5
 [ "${#boot_dep_identity}" -le 160 ] || return 1
 case "$boot_dep_identity" in ''|*[!0-9a-f:]*|*::*|:*|*:) return 1;; esac
 boot_dep_ifs=$IFS; IFS=:; set -- $boot_dep_identity; IFS=$boot_dep_ifs
 [ "$#" = 7 ] && [ "$3" = 81a4 ] && [ "$4" = 1 ] && [ "$5" = "$boot_dep_size" ] &&
 [ "$6" = 0 ] && [ "$7" = 0 ] || return 1
 for boot_number in "$1" "$2"; do
  [ "${#boot_number}" -le 20 ] || return 1
  case "$boot_number" in ''|*[!0-9]*|0[0-9]*) return 1;; esac
 done
 [ "$2" != 0 ] || return 1
 payload "$boot_dep_path" "$boot_dep_hash" "$boot_dep_size" && meta "$boot_dep_path" 644 "$boot_dep_label" &&
 equals "$boot_dep_identity" stat -c '%d:%i:%f:%h:%s:%u:%g' "$boot_dep_path"
)
boot_dependencies() {
 x2dii_sc_private "$boot_dependencies_path" && hashok "$boot_dependencies_path" "$boot_dependencies_sha" &&
 equals "$boot_dependencies_identity" stat -c '%d:%i:%f:%h:%s:%u:%g' "$boot_dependencies_path" || return 1
'''
        for i, entry in enumerate(manifest["candidate"]["files"]):
            label = ("LIBRARY", "BOOTSTRAP", "MODEL", "PAGE")[i]
            dependencies += (f' boot_dependency {entry["target"]} {entry["sha256"]} {entry["bytes"]} '
                             f'"$X2DII_SESSION_{label}_LABEL" "$boot_payload_{i}" || return 1\n')
        for i in range(4):
            for j in range(i):
                dependencies += f' [ "${{boot_payload_{i}%%:81a4:*}}" != "${{boot_payload_{j}%%:81a4:*}}" ] || return 1\n'
        dependencies += '}\nboot_dependencies || exit 81\n'
    guard = dependencies + r'''
boot_program='@STAGE@/@ACTION@-boot.sh'
[ "$0" = "$boot_program" ] && x2dii_sc_private "$boot_program" || exit 81
boot_program_identity=$(stat -c '%d:%i:%f:%h:%s:%u:%g' "$boot_program") || exit 81
boot_program_hash_line=$(sha256sum "$boot_program") || exit 81
boot_program_sha=${boot_program_hash_line%% *}
x2dii_sc_scalar hex64 "$boot_program_sha" || exit 81
boot_boundary_index=0
boot_objects() {
 case "$boot_boundary_name" in
  remount_rw)
   target_original && absent "$temporary" && payload "$source" '@OUTPUT_HASH@' '@OUTPUT_SIZE@' && @INITIAL_BACKUP@;;
  backup_create|temporary_create)
   target_original && absent "$new_path";;
  backup_write|temporary_write)
   target_original && new_owned && meta "$new_path" 600 '@LABEL@' && equals 0 stat -c %s "$new_path";;
  backup_chmod|temporary_chmod)
   target_original && new_owned && payload "$new_path" "$new_hash" "$new_size" && meta "$new_path" 600 '@LABEL@';;
  backup_timestamp|temporary_timestamp)
   target_original && new_owned && payload "$new_path" "$new_hash" "$new_size" && meta "$new_path" 644 '@LABEL@';;
  commit_rename)
   verified_backup && target_original && payload "$temporary" '@OUTPUT_HASH@' '@OUTPUT_SIZE@' &&
   meta "$temporary" 644 '@LABEL@' && equals "$original_mtime" stat -c %y "$temporary" &&
   equals "$prepared_identity" stat -c '%d:%i:%f:%h:%s:%u:%g' "$temporary";;
  final_identity|final_receipt)
   [ "$committed" = 1 ] && verified_backup && absent "$temporary" &&
   payload "$target" '@OUTPUT_HASH@' '@OUTPUT_SIZE@' && meta "$target" 644 '@LABEL@' &&
   equals "$original_mtime" stat -c %y "$target" &&
   equals "$prepared_identity" stat -c '%d:%i:%f:%h:%s:%u:%g' "$target";;
  *) return 1;;
 esac
}
boot_wait() {
 boot_boundary_name=$1
 boot_expected_mount=$2
 case "$boot_boundary_index:$boot_boundary_name:$boot_expected_mount" in
@STAGE_CASES@
  *) exit 81;;
 esac
 ready "$boot_expected_mount" && boot_dependencies && boot_objects &&
 equals "$boot_program_identity" stat -c '%d:%i:%f:%h:%s:%u:%g' "$boot_program" &&
 hashok "$boot_program" "$boot_program_sha" || exit 81
 boot_issued_epoch=$(date -u +%s) || exit 81
 x2dii_sc_scalar epoch "$boot_issued_epoch" && fresh || exit 81
 boot_challenge_line=$(printf '%s\n' "$X2DII_SESSION_BOOT_ID:$X2DII_SESSION_SESSION_NONCE:@ACTION@:$boot_boundary_index:$boot_program_sha" | sha256sum) || exit 81
 boot_challenge=${boot_challenge_line%% *}
 x2dii_sc_scalar hex64 "$boot_challenge" || exit 81
 boot_request='@STAGE@/.boot-@ACTION@-'"$X2DII_SESSION_SESSION_NONCE-$boot_boundary_index"'.data'
 absent "$boot_request" || exit 81
 (set -C; umask 077; printf '%s\n' \
  'schema=x2dii-boot-maintenance-request-v1' 'candidate_sha256=@DIGEST@' \
  "boot_id=$X2DII_SESSION_BOOT_ID" "session_nonce=$X2DII_SESSION_SESSION_NONCE" \
  'action=@ACTION@' "boundary_index=$boot_boundary_index" "boundary_name=$boot_boundary_name" \
  "mount_access=$boot_mount_access" "worker_program_sha256=$boot_program_sha" \
  "worker_session_sha256=$boot_session_sha" 'maintenance_program_sha256=@OBSERVER_HASH@' \
  "maintenance_session_sha256=$boot_session_sha" "challenge=$boot_challenge" \
  "observed_epoch=$X2DII_SESSION_OBSERVED_EPOCH" "issued_epoch=$boot_issued_epoch" \
  "deadline_epoch=$((X2DII_SESSION_OBSERVED_EPOCH+600))" > "$boot_request") || exit 81
 x2dii_sc_private "$boot_request" || exit 81
 boot_request_identity=$(stat -c '%d:%i:%f:%h:%s:%u:%g' "$boot_request") || exit 81
 boot_request_hash_line=$(sha256sum "$boot_request") || exit 81
 boot_request_sha=${boot_request_hash_line%% *}
 x2dii_sc_scalar hex64 "$boot_request_sha" || exit 81
 printf 'X2DII_BOOT_BOUNDARY_REQUEST:@ACTION@:%s:%s\n' "$boot_boundary_index" "$boot_request_sha" || exit 81
 IFS= read -r -t 8 boot_ack || exit 81
 [ "${#boot_ack}" -le 128 ] || exit 81
 case "$boot_ack" in "X2DII_BOOT_BOUNDARY_ACK:$boot_request_sha:"*) ;; *) exit 81;; esac
 boot_ack_times=${boot_ack#"X2DII_BOOT_BOUNDARY_ACK:$boot_request_sha:"}
 boot_ack_started=${boot_ack_times%%:*}; boot_ack_checked=${boot_ack_times#*:}
 x2dii_sc_scalar epoch "$boot_ack_started" && x2dii_sc_scalar epoch "$boot_ack_checked" || exit 81
 boot_received=$(date -u +%s) || exit 81
 x2dii_sc_scalar epoch "$boot_received" && [ "$boot_ack_started" -ge "$boot_issued_epoch" ] &&
 [ "$boot_ack_checked" -ge "$boot_ack_started" ] && [ "$boot_received" -ge "$boot_ack_checked" ] &&
 [ "$((boot_received-boot_issued_epoch))" -le 8 ] || exit 81
 x2dii_sc_private "$boot_request" && hashok "$boot_request" "$boot_request_sha" &&
 equals "$boot_request_identity" stat -c '%d:%i:%f:%h:%s:%u:%g' "$boot_request" &&
 x2dii_sc_hash "$X2DII_SESSION_DATA_PATH" "$boot_session_sha" &&
 equals "$boot_program_identity" stat -c '%d:%i:%f:%h:%s:%u:%g' "$boot_program" &&
 hashok "$boot_program" "$boot_program_sha" &&
 boot_dependencies && boot_objects && ready "$boot_expected_mount" || exit 81
 boot_boundary_index=$((boot_boundary_index+1))
}
'''
    # The session parser deliberately has no mutable public path variable.
    guard = guard.replace('"$X2DII_SESSION_DATA_PATH"', '"' + stage + '/session-context-$boot_session_sha.data"')
    proposed = boot.activate(original_rc)
    replacements = {"@STAGE@": stage, "@ACTION@": action, "@DIGEST@": digest,
        "@OBSERVER_HASH@": observer_hash, "@LABEL@": metadata["label"],
        "@OUTPUT_HASH@": manifest["candidate"]["rc"]["after" if action == "activate" else "before"],
        "@OUTPUT_SIZE@": str(len(proposed if action == "activate" else original_rc)),
        "@INITIAL_BACKUP@": 'absent "$backup"' if action == "activate" else 'verified_backup',
        "@STAGE_CASES@": "\n".join(f'  "{i}:{name}:${"baseline" if access == "ro" else "rw"}") boot_mount_access={access};;'
            for i, name, access in boundary.stages(action))}
    for key, value in replacements.items():
        guard = guard.replace(key, value)
    replace_once('trap finish EXIT\n', guard + 'trap finish EXIT\n')
    replace_once('mount_owned=1\nmount -o remount,rw /system',
                 'boot_wait remount_rw "$baseline"\nmount_owned=1\nmount -o remount,rw /system')
    replace_once(' new_path=$1; input_path=$2; new_hash=$3; new_size=$4',
                 ' new_path=$1; input_path=$2; new_hash=$3; new_size=$4\n'
                 ' if [ "$new_path" = "$backup" ]; then copy_phase=backup; else copy_phase=temporary; fi')
    replace_once(' umask 077\n set -C', ' boot_wait "${copy_phase}_create" "$rw"\n umask 077\n set -C')
    replace_once(' cat "$input_path" >&3 || return',
                 ' boot_wait "${copy_phase}_write" "$rw"\n cat "$input_path" >&3 || return')
    replace_once(' chmod 0644 "$new_path" || return',
                 ' boot_wait "${copy_phase}_chmod" "$rw"\n chmod 0644 "$new_path" || return')
    replace_once(' touch -r /proc/self/fd/4 "$new_path" || return',
                 ' boot_wait "${copy_phase}_timestamp" "$rw"\n touch -r /proc/self/fd/4 "$new_path" || return')
    replace_once('mv -f "$temporary" "$target"', 'boot_wait commit_rename "$rw"\nmv -f "$temporary" "$target"')
    replace_once(' [ "$committed" = 1 ] && ready "$baseline" && verified_backup &&',
                 ' boot_wait final_identity "$baseline"\n [ "$committed" = 1 ] && ready "$baseline" && verified_backup &&')
    replace_once(' exec 4<&-\n exec 5<&-', ' boot_wait final_receipt "$baseline"\n exec 4<&-\n exec 5<&-')
    source = source.replace('maintenance_boundaries=UNCONNECTED', 'maintenance_boundaries=HOST_MEDIATED_FIXED_BOOT_MATCHED')
    source = source.replace('# LOCAL ONLY: maintenance write-boundary supervision IS NOT CONNECTED.',
                            '# LOCAL SOURCE: fixed host-mediated boot boundaries; transport qualification pending.')
    if action == "restore":
        before = manifest["candidate"]["rc"]["before"]
        after = manifest["candidate"]["rc"]["after"]
        replace_once(f'[ "$X2DII_SESSION_RC_SHA256" = \'{after}\' ] || exit 32',
            f'case "$X2DII_SESSION_RC_SHA256" in {before}|{after}) ;; *) exit 32;; esac')
        branch = r'''
if [ "$X2DII_SESSION_RC_SHA256" = '@BEFORE@' ]; then
 # Retried restoration: verify the original rc and retained backup without
 # remounting, copying, relabeling, deleting or depending on extension health.
 backup_identity=$boot_saved_backup_identity
 ready "$baseline" && payload "$target" '@BEFORE@' '@SIZE@' && meta "$target" 644 '@LABEL@' &&
 payload "$backup" '@BEFORE@' '@SIZE@' && meta "$backup" 644 '@LABEL@' && absent "$temporary" &&
 equals "$backup_identity" stat -c '%d:%i:%f:%h:%s:%u:%g' "$backup" || exit 33
 exec 4<"$backup"
 equals "$backup_identity" stat -Lc '%d:%i:%f:%h:%s:%u:%g' /proc/self/fd/4 || exit 33
 original_mtime=$(stat -Lc %y /proc/self/fd/4) || exit 33
 exec 5<"$target"
 prepared_identity=$(stat -Lc '%d:%i:%f:%h:%s:%u:%g' /proc/self/fd/5) || exit 33
 identityok "$prepared_identity" && verified_backup &&
 equals "$original_mtime" stat -c %y "$target" &&
 equals "$prepared_identity" stat -c '%d:%i:%f:%h:%s:%u:%g' "$target" || exit 33
 boot_boundary_index=6
 committed=1
 exit 0
fi
'''.replace("@BEFORE@", before).replace("@SIZE@", str(len(original_rc))).replace("@LABEL@", metadata["label"])
        replace_once('done\nready "$baseline" && payload "$target"',
                     'done\n' + branch + 'ready "$baseline" && payload "$target"')
    return source


def render_stable_boot_transaction(manifest, *, action, original_rc, metadata, init_scan_roots):
    """Stable fixed-action source; current session identity is runtime data.

    No sender or authority is added. Arguments are the developer-fixed session
    path and its exact SHA256; restore additionally requires the exact saved
    backup identity. Transaction operations, open descriptors, inode checks
    and rollback handling stay unchanged. No argument is shell source.
    """
    compiled_hash = "0" * 64
    compiled_identity = "0:0:81a4:1:0:0:0"
    source = render_boot_transaction(manifest, action=action,
        session_data_sha256=compiled_hash, original_rc=original_rc,
        metadata=metadata, init_scan_roots=init_scan_roots,
        backup_identity=compiled_identity if action == "restore" else None)
    stage = "/blackbox/x2dii-menu-stage/" + manifest["candidate_sha256"][:24]

    def replace_once(old, new):
        nonlocal source
        if source.count(old) != 1:
            raise ValueError("stable rc parameter boundary changed")
        source = source.replace(old, new, 1)

    replace_once(f'''[ "$#" = 2 ] || exit 32
[ "$1" = '{stage}/session-context.data' ] && [ "$2" = '{compiled_hash}' ] || exit 32
x2dii_load_session "$1" '{compiled_hash}' || exit 32''', f'''[ "$#" = {3 if action == 'restore' else 2} ] || exit 32
[ "$1" = '{stage}/session-context.data' ] || exit 32
x2dii_sc_scalar hex64 "$2" || exit 32
boot_session_sha=$2
x2dii_load_session "$1" "$boot_session_sha" || exit 32''')
    if action == "restore":
        identity_guard = r'''
boot_saved_backup_identity=$3
boot_identity_valid() (
 [ "${#1}" -le 160 ] || return 1
 case "$1" in ''|*[!0-9a-f:]*|*::*|:*|*:) return 1;; esac
 IFS=:
 set -- $1
 [ "$#" = 7 ] && [ "$3" = 81a4 ] && [ "$4" = 1 ] &&
 [ "$5" = '@ORIGINAL_BYTES@' ] && [ "$6" = 0 ] && [ "$7" = 0 ] || return 1
 for boot_number in "$1" "$2" "$5"; do
  [ "${#boot_number}" -le 20 ] || return 1
  case "$boot_number" in ''|*[!0-9]*|0[0-9]*) return 1;; esac
 done
)
boot_identity_valid "$boot_saved_backup_identity" || exit 32
'''.replace("@ORIGINAL_BYTES@", str(len(original_rc)))
        replace_once('x2dii_load_session "$1" "$boot_session_sha" || exit 32',
                     'x2dii_load_session "$1" "$boot_session_sha" || exit 32' + identity_guard)
        replace_once("backup_identity='" + compiled_identity + "'",
                     'backup_identity=$boot_saved_backup_identity')
    replace_once("\\nsession_data_sha256=" + compiled_hash + "\\nsession_nonce=%s",
                 "\\nsession_data_sha256=%s\\nsession_nonce=%s")
    replace_once('  "$X2DII_SESSION_SESSION_NONCE" "$backup_identity" "$prepared_identity" || exit 73',
                 '  "$boot_session_sha" "$X2DII_SESSION_SESSION_NONCE" "$backup_identity" "$prepared_identity" || exit 73')
    return source


def render_boot_transaction(manifest, *, action, session_data_sha256, original_rc,
                            metadata, init_scan_roots, backup_identity=None):
    """Pure fixed-action rendering. Inputs are observations, never authority.

    The exact session hash is compiled into this candidate/action source;
    callers must also bind the resulting program hash in future orchestration.
    No runtime path/action selector or saved shell receipt is interpreted.
    """
    render_preplacement(manifest, file_index=0)  # Same strict four-member input.
    if action not in ("activate", "restore"):
        raise ValueError("unsupported fixed rc action")
    if action == "activate" and backup_identity is not None:
        raise ValueError("activation cannot adopt an existing backup")
    if action == "restore" and (not isinstance(backup_identity, str) or len(backup_identity) > 160
                                or re.fullmatch(r"[0-9]+:[0-9]+:81a4:1:[0-9]+:0:0", backup_identity) is None):
        raise ValueError("exact previously recorded backup identity required")
    if not isinstance(session_data_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", session_data_sha256) is None:
        raise ValueError("exact session data hash required")
    if type(original_rc) is not bytes:
        raise ValueError("exact original rc bytes required")
    proposed = boot.activate(original_rc)
    rc = manifest["candidate"].get("rc")
    if rc != {"target": boot.TARGET, "before": boot.STOCK_SHA256,
              "after": boot.sha256(proposed), "source": "build/boot-config/camera-gui.rc.proposed"}:
        raise ValueError("fixed original and two-line rc pair required")
    if (type(metadata) is not dict or set(metadata) != {"uid", "gid", "mode", "label", "xattr_names"}
            or type(metadata["uid"]) is not int or type(metadata["gid"]) is not int
            or metadata["uid"] != 0 or metadata["gid"] != 0 or metadata["mode"] != "644"
            or not isinstance(metadata["label"], str)
            or re.fullmatch(r"u:object_r:[a-z0-9_]{1,96}:s0", metadata["label"]) is None
            or metadata["xattr_names"] != ["security.selinux"]):
        raise ValueError("verified supported metadata and all xattr names required")
    digest = manifest["candidate_sha256"]
    backup = "/system/etc/.x2dii-boot-" + digest[:24] + ".original"
    if (type(init_scan_roots) not in (list, tuple) or not init_scan_roots
            or "/system/etc/init" not in init_scan_roots):
        raise ValueError("complete qualified init scan roots required")
    for root in init_scan_roots:
        if (not isinstance(root, str) or re.fullmatch(r"/[A-Za-z0-9_/-]+", root) is None
                or root.endswith("/") or "//" in root
                or backup == root or backup.startswith(root + "/")):
            raise ValueError("backup/staging must remain outside all init scan roots")
    stage = "/blackbox/x2dii-menu-stage/" + digest[:24]
    head = """#!/system/bin/sh
# LOCAL ONLY: maintenance write-boundary supervision IS NOT CONNECTED.
set -eu
export PATH=/system/bin:/system/xbin:/sbin
# SESSION_DATA_PARSER_BEGIN
""" + shell_parser() + "# SESSION_DATA_PARSER_END\n"
    body = r'''[ "$#" = 2 ] || exit 32
[ "$1" = '@STAGE@/session-context.data' ] && [ "$2" = '@SESSION@' ] || exit 32
x2dii_load_session "$1" '@SESSION@' || exit 32
[ "$X2DII_SESSION_SCHEMA" = '@SCHEMA@' ] &&
[ "$X2DII_SESSION_KIND" = '@KIND@' ] && [ "$X2DII_SESSION_RC_LABEL" = '@LABEL@' ] || exit 32
@EXTRA_SESSION@
target=/system/etc/init/camera-gui.rc
backup='@BACKUP@'
temporary="/system/etc/.x2dii-boot-@SHORT@-$X2DII_SESSION_SESSION_NONCE-@ACTION@.stage"
source='@SOURCE@'
baseline="$X2DII_SESSION_MOUNT_DEVICE $X2DII_SESSION_MOUNT_FILESYSTEM $X2DII_SESSION_MOUNT_OPTIONS"
rw="$X2DII_SESSION_MOUNT_DEVICE $X2DII_SESSION_MOUNT_FILESYSTEM rw,${X2DII_SESSION_MOUNT_OPTIONS#ro,}"
mount_owned=0
committed=0
equals() { expected=$1; shift; observed=$("$@") || return 1; [ "$observed" = "$expected" ]; }
hashok() { observed_hash=$(sha256sum "$1") || return 1; [ "${observed_hash%% *}" = "$2" ]; }
absent() { [ ! -e "$1" ] && [ ! -L "$1" ]; }
regular() { [ -f "$1" ] && [ ! -L "$1" ] && equals 1 stat -c %h "$1"; }
identityok() (
 [ "${#1}" -le 160 ] || return 1
 case "$1" in ''|*[!0-9a-f:]*|*::*|:*|*:) return 1;; esac
 IFS=:; set -- $1
 [ "$#" = 7 ] && [ "$4" = 1 ]
)
labelok() {
 label_path=$1; label_expected=$2
 label_line=$(ls -Zd "$label_path") || return 1
 set -- $label_line
 [ "$#" = 2 ] && [ "$1" = "$label_expected" ] && [ "$2" = "$label_path" ]
}
meta() {
 meta_path=$1; meta_mode=$2; meta_label=$3
 regular "$meta_path" && equals "0 0 $meta_mode" stat -c '%u %g %a' "$meta_path" &&
 labelok "$meta_path" "$meta_label" || return 1
 # List ALL names, without -n filtering; command status and returned path count.
 names=$(/system/bin/toybox getfattr "$meta_path") || return 1
 expected_names=$(printf '# file: %s\nsecurity.selinux\n' "$meta_path") || return 1
 [ "$names" = "$expected_names" ] || return 1
 attrs=$(/system/bin/toybox getfattr -d "$meta_path") || return 1
 expected_attrs=$(printf '# file: %s\nsecurity.selinux="%s"\n' "$meta_path" "$meta_label") || return 1
 [ "$attrs" = "$expected_attrs" ]
}
payload() { regular "$1" && equals "$3" stat -c %s "$1" && hashok "$1" "$2"; }
state() (
 set -f
 while :; do
  line=''
  if IFS= read -r line; then
   set -- $line; [ "$#" = 6 ] || return 1
   [ "$2" != /system ] || printf '%s %s %s\n' "$1" "$3" "$4" || return 1
  else code=$?; [ "$code" = 1 ] && [ -z "$line" ] || return 1; break; fi
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
 [ "$now" -le "$((X2DII_SESSION_OBSERVED_EPOCH + 600))" ]
}
ready() { self_identity && equals "$1" state && fresh; }
restore_ro() {
 [ "$mount_owned" = 1 ] || return 0
 self_identity || return 1
 current=$(state) || return 1
 if [ "$current" = "$rw" ]; then mount -o remount,ro /system || return 1
 else [ "$current" = "$baseline" ] || return 1; fi
 equals "$baseline" state
}
target_original() {
 payload "$target" '@INPUT_HASH@' '@INPUT_SIZE@' && meta "$target" 644 '@LABEL@' &&
 equals "$target_identity" stat -c '%d:%i:%f:%h:%s:%u:%g' "$target"
}
verified_backup() {
 payload "$backup" '@BEFORE@' '@ORIGINAL_SIZE@' && meta "$backup" 644 '@LABEL@' &&
 equals "$original_mtime" stat -c %y "$backup" &&
 equals "$backup_identity" stat -c '%d:%i:%f:%h:%s:%u:%g' "$backup"
}
new_owned() {
 regular "$new_path" && equals "$new_inode" stat -c '%d:%i' "$new_path"
}
copy_owned() {
 # $1 is an already developer-fixed local path, not a caller path selector.
 new_path=$1; input_path=$2; new_hash=$3; new_size=$4
 absent "$new_path" && target_original && ready "$rw" || return 33
 umask 077
 set -C
 exec 3>"$new_path"
 set +C
 new_inode=$(stat -Lc '%d:%i' /proc/self/fd/3) || return 33
 birth=$(stat -Lc '%d:%i:%f:%h:%s:%u:%g' /proc/self/fd/3) || return 33
 identityok "$birth" && new_owned && meta "$new_path" 600 '@LABEL@' || return 33
 printf 'X2DII_RC_CREATED:%s\n' "$birth"
 target_original && ready "$rw" || return 33
 cat "$input_path" >&3 || return
 new_owned && payload "$new_path" "$new_hash" "$new_size" && meta "$new_path" 600 '@LABEL@' || return 33
 target_original && ready "$rw" || return 33
 chmod 0644 "$new_path" || return
 new_owned && meta "$new_path" 644 '@LABEL@' && target_original && ready "$rw" || return 33
 touch -r /proc/self/fd/4 "$new_path" || return
 new_owned && payload "$new_path" "$new_hash" "$new_size" && meta "$new_path" 644 '@LABEL@' &&
 equals "$original_mtime" stat -c %y "$new_path" || return 33
 copied_identity=$(stat -c '%d:%i:%f:%h:%s:%u:%g' "$new_path") || return 33
 identityok "$copied_identity" || return 33
 sync || return
 new_owned && equals "$copied_identity" stat -c '%d:%i:%f:%h:%s:%u:%g' "$new_path" || return 33
 exec 3>&-
}
finish() {
 result=$?
 trap - EXIT HUP INT TERM
 exec 3>&-
 restore_ro || result=72
 if [ "$result" != 0 ]; then
  printf 'X2DII_RC_FILE_FAILED:%s; committed=%s; backup/partial/unknown files retained\n' "$result" "$committed" >&2
  exit "$result"
 fi
 [ "$committed" = 1 ] && ready "$baseline" && verified_backup &&
 payload "$target" '@OUTPUT_HASH@' '@OUTPUT_SIZE@' && meta "$target" 644 '@LABEL@' &&
 equals "$original_mtime" stat -c %y "$target" &&
 equals "$prepared_identity" stat -c '%d:%i:%f:%h:%s:%u:%g' "$target" || exit 73
 # The final hash must not allow a same-content replacement inode to be adopted.
 hashok "$target" '@OUTPUT_HASH@' && verified_backup && meta "$target" 644 '@LABEL@' &&
 equals "$original_mtime" stat -c %y "$target" && ready "$baseline" &&
 equals "$prepared_identity" stat -c '%d:%i:%f:%h:%s:%u:%g' "$target" || exit 73
 exec 4<&-
 exec 5<&-
 printf 'schema=x2dii-rc-file-transaction-v1\naction=@ACTION@\ncandidate_sha256=@CANDIDATE@\nsession_data_sha256=@SESSION@\nsession_nonce=%s\nbackup_identity=%s\nidentity=%s\nsha256=@OUTPUT_HASH@\nmaintenance_boundaries=UNCONNECTED\n' \
  "$X2DII_SESSION_SESSION_NONCE" "$backup_identity" "$prepared_identity" || exit 73
 printf '%s\n' X2DII_RC_FILE_COMMITTED_NOT_LIFECYCLE_VALIDATED
}
trap finish EXIT
trap 'exit 74' HUP INT TERM
self_identity || exit 31
for directory in /system /system/etc /system/etc/init; do
 [ -d "$directory" ] && [ ! -L "$directory" ] && equals '0 0' stat -c '%u %g' "$directory" || exit 33
done
ready "$baseline" && payload "$target" '@INPUT_HASH@' '@INPUT_SIZE@' && meta "$target" 644 '@LABEL@' || exit 33
@BACKUP_ADMISSION@
absent "$temporary" && payload "$source" '@OUTPUT_HASH@' '@OUTPUT_SIZE@' || exit 33
exec 5<"$target"
target_identity=$(stat -Lc '%d:%i:%f:%h:%s:%u:%g' /proc/self/fd/5)
identityok "$target_identity" && target_original || exit 33
@SOURCE_OPEN@
original_mtime=$(stat -Lc %y /proc/self/fd/4)
target_device=$(stat -Lc %d /proc/self/fd/5)
equals "$target_device" stat -c %d /system/etc || exit 33
mount_owned=1
mount -o remount,rw /system
target_original && ready "$rw" || exit 33
@BACKUP_COPY@
verified_backup && target_original && ready "$rw" || exit 33
payload "$source" '@OUTPUT_HASH@' '@OUTPUT_SIZE@' || exit 33
copy_owned "$temporary" @COPY_INPUT@ '@OUTPUT_HASH@' '@OUTPUT_SIZE@'
prepared_identity=$copied_identity
verified_backup && target_original && payload "$temporary" '@OUTPUT_HASH@' '@OUTPUT_SIZE@' &&
meta "$temporary" 644 '@LABEL@' && equals "$prepared_identity" stat -c '%d:%i:%f:%h:%s:%u:%g' "$temporary" &&
ready "$rw" || exit 33
mv -f "$temporary" "$target"
absent "$temporary" && payload "$target" '@OUTPUT_HASH@' '@OUTPUT_SIZE@' &&
meta "$target" 644 '@LABEL@' && equals "$prepared_identity" stat -c '%d:%i:%f:%h:%s:%u:%g' "$target" || exit 33
committed=1
sync
restore_ro || exit 72
'''
    activating = action == "activate"
    replacements = {
        "@BACKUP_ADMISSION@": ('absent "$backup" || exit 33' if activating else
                                "backup_identity='" + backup_identity + "'\n" +
                                'meta "$backup" 644 \'@LABEL@\' && payload "$backup" \'@BEFORE@\' \'@ORIGINAL_SIZE@\' &&\n'
                                'equals "$backup_identity" stat -c \'%d:%i:%f:%h:%s:%u:%g\' "$backup" || exit 33'),
        "@SOURCE_OPEN@": ('exec 4<"$target"\nequals "$target_identity"' if activating else
                           'exec 4<"$backup"\nequals "$backup_identity"') +
                          " stat -Lc '%d:%i:%f:%h:%s:%u:%g' /proc/self/fd/4 || exit 33",
        "@BACKUP_COPY@": ('copy_owned "$backup" /proc/self/fd/4 \'@BEFORE@\' \'@ORIGINAL_SIZE@\'\nbackup_identity=$copied_identity'
                           if activating else ':'),
        "@EXTRA_SESSION@": (':' if activating else '[ "$X2DII_SESSION_RC_SHA256" = \'@INPUT_HASH@\' ] || exit 32'),
        "@SOURCE@": stage + "/camera-gui.rc.proposed" if activating else backup,
        "@COPY_INPUT@": '"$source"' if activating else '/proc/self/fd/4',
        "@SCHEMA@": "x2dii-session-context-v2" if activating else "x2dii-session-context-v1",
        "@KIND@": "install" if activating else "recovery", "@ACTION@": action,
        "@INPUT_HASH@": rc["before"] if activating else rc["after"],
        "@OUTPUT_HASH@": rc["after"] if activating else rc["before"],
        "@INPUT_SIZE@": str(len(original_rc) if activating else len(proposed)),
        "@OUTPUT_SIZE@": str(len(proposed) if activating else len(original_rc)),
        "@STAGE@": stage, "@SESSION@": session_data_sha256, "@LABEL@": metadata["label"],
                    "@BACKUP@": backup, "@SHORT@": digest[:24], "@CANDIDATE@": digest,
                    "@BEFORE@": rc["before"], "@AFTER@": rc["after"],
                    "@ORIGINAL_SIZE@": str(len(original_rc)), "@PROPOSED_SIZE@": str(len(proposed))}
    for token, value in replacements.items():
        body = body.replace(token, value)
    return head + body
