"""Recovery-only source from an externally hash-bound saved candidate.

No inventory, payload-source reads, camera access, transfer or execution. Pure
rendering is available for review/harnesses; publishing a script additionally
requires separately reviewed, current recovery evidence and authorization.
An arbitrary author's JSON is not proof of real device observations or consent.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess

from .output_guard import guard_output, publish_output_set
from .prepare_peer_install import LABEL_FIELDS, session_values, session_variable
from . import release_identity
from .runtime_observation import normalize_observation

ROOT = Path(__file__).resolve().parents[1]
RC = "/system/etc/init/camera-gui.rc"
LIBRARY = "/system/lib64/libx2dii_menu.so"
TARGETS = (LIBRARY, *("/system/etc/" + name for name in
                     ("X2d2MenuBootstrap.qml", "X2d2MenuModel.qml", "X2d2MenuPage.qml")))
GATES = ("recovery_offline_audit", "recovery_historical_regressions", "saved_installed_candidate",
         "current_recovery_domain_session", "current_process_lifetimes", "current_slot_mount_namespace",
         "original_backup_metadata_ownership", "complete_metadata_xattrs", "init_stop_inhibits_restart",
         "target_shell_tools_sync_rename", "independent_recovery_official_slot")
CONTEXT = ("candidate_sha256", "saved_manifest_sha256", "observed_utc", "boot_id", "uid", "domain",
           "system_mount", "mount_namespace", "init_mount_namespace", "observer", "gui", "active_slot",
           "official_slot", "slot_readback", "metadata", "backup_metadata", "payload_presence", "rc_sha256",
           "recovery_nonce", "init_scan_roots", "init_scan_roots_complete", "session_nonce")
SCRIPT = "recover-boot.sh"
RUNTIME_FIELDS = ("candidate_sha256", "saved_manifest_sha256", "boot_id", "uid", "domain",
                  "system_mount", "mount_namespace", "init_mount_namespace", "observer", "gui",
                  "active_slot", "official_slot", "slot_readback", "metadata", "backup_metadata",
                  "payload_presence", "rc_sha256", "init_scan_roots", "init_scan_roots_complete")
GATE_PHASES = {gate: (("build",) if gate == "recovery_offline_audit" else
                     ("build", "runtime") if gate == "recovery_historical_regressions" else ("runtime",))
               for gate in GATES}
FAILURE_ARTIFACT_FORMATS = {
    "identity": "json", "recent_logcat": "text", "capture_filtered_logcat": "text",
    "kernel_log": "text", "runtime_configuration": "json", "storage_file_index": "text",
    "log_index": "text", "tombstone_index": "text",
}
MAX_FAILURE_JSON_BYTES = 256 * 1024
MAX_FAILURE_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_FAILURE_BUNDLE_BYTES = 128 * 1024 * 1024


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _failure_original(reference, *, limit, budget, seen):
    """Read bounded externally bound original bytes, never a claimed PASS list."""
    prefix = "pre-rollback failure bundle: "
    need(type(reference) is dict and set(reference) == {"evidence_file", "evidence_sha256"},
         prefix + "exact original reference required")
    name = reference["evidence_file"]
    need(type(name) is str and len(name) <= 512 and
         re.fullmatch(r"build/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", name) is not None and
         not any(part in (".", "..") for part in name.split("/")) and
         digest(reference["evidence_sha256"]), prefix + "invalid original path or hash")
    path = guard_output(ROOT / name)
    fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    try:
        before = path.lstat()
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
             prefix + "unshared regular original required")
        identity = (before.st_dev, before.st_ino)
        need(identity not in seen, prefix + "duplicate original object")
        bound = min(limit, budget[0])
        need(0 < before.st_size <= bound, prefix + "empty or oversized original")
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            need(all(getattr(opened, field) == getattr(before, field) for field in fields),
                 prefix + "original changed while opening")
            raw = stream.read(bound + 1)
            held = os.fstat(stream.fileno())
        guard_output(path)
        after = path.lstat()
        need(all(getattr(before, field) == getattr(after, field) == getattr(held, field) for field in fields)
             and len(raw) == before.st_size, prefix + "original changed while reading")
    except OSError as error:
        raise ValueError(prefix + "missing or unreadable original: " + name) from error
    need(raw.strip() and sha(raw) == reference["evidence_sha256"], prefix + "original hash or content differs")
    budget[0] -= len(raw)
    seen.add(identity)
    return raw


def _failure_timestamp(value):
    need(type(value) is str and len(value) <= 64, "pre-rollback failure bundle: invalid time")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError("pre-rollback failure bundle: invalid time") from error
    need(parsed.tzinfo is not None, "pre-rollback failure bundle: timezone-aware time required")
    return parsed


def _validate_failure_bundle(q, observation, *, saved_sha, build, runtime, subject):
    """Formal publication admission only; no collection, consent or truth claim.

    The existing historical runtime gate retains the independently reviewed
    bundle reference. Its original identity/configuration records must exactly
    describe this context, including unhealthy/absent components. Log coverage
    is declared and hash-bound; authenticity still requires external review.
    Pure rendering and automatic urgent guardian restoration never call this.
    """
    from .regression_manifest import strict_json
    prefix = "pre-rollback failure bundle: "
    budget, seen = [MAX_FAILURE_BUNDLE_BYTES], set()
    bindings = release_identity.gate_bindings("runtime", candidate_sha256=q["candidate_sha256"],
        build_subject_sha256=build, runtime_subject_sha256=runtime, boot_id=q["boot_id"],
        retained={"saved_manifest_sha256": saved_sha})
    need(type(q.get("gates")) is dict, prefix + "recovery gates required")
    historical = q["gates"].get("recovery_historical_regressions")
    need(type(historical) is dict and set(historical) == set(GATE_PHASES["recovery_historical_regressions"]),
         prefix + "complete historical gate phases required")
    gate = historical["runtime"]
    need(type(gate) is dict and gate.get("status") == "PASS" and
         all(gate.get(key) == value for key, value in bindings.items()), prefix + "runtime proof binding differs")
    reference = {key: gate.get(key) for key in ("evidence_file", "evidence_sha256")}
    evidence = strict_json(_failure_original(reference, limit=MAX_FAILURE_JSON_BYTES, budget=budget, seen=seen))
    need(type(evidence) is dict and evidence.get("gate") == "recovery_historical_regressions" and
         evidence.get("result") == "PASS" and evidence.get("synthetic") is False and
         evidence.get("test_fixture_only") is False and
         all(evidence.get(key) == value for key, value in bindings.items()), prefix + "runtime gate differs")
    bundle = strict_json(_failure_original(evidence.get("pre_rollback_failure_bundle"),
        limit=MAX_FAILURE_JSON_BYTES, budget=budget, seen=seen))
    need(type(bundle) is dict and set(bundle) == {"schema", "synthetic", "test_fixture_only", "bindings",
         "observed_utc", "failure_window", "artifacts"} and
         bundle["schema"] == "x2dii-pre-rollback-failure-bundle-v1" and bundle["synthetic"] is False and
         bundle["test_fixture_only"] is False, prefix + "complete non-fixture bundle required")
    need(canonical(bundle["bindings"]) == canonical(dict(bindings, execution_subject_sha256=subject)) and
         bundle["observed_utc"] == q["observed_utc"], prefix + "current identity binding differs")
    window = bundle["failure_window"]
    need(type(window) is dict and set(window) == {"start_utc", "end_utc"}, prefix + "failure window required")
    start, end = (_failure_timestamp(window[key]) for key in ("start_utc", "end_utc"))
    observed = _failure_timestamp(q["observed_utc"])
    need(start <= end <= observed, prefix + "failure window is reversed or after observation")
    artifacts = bundle["artifacts"]
    need(type(artifacts) is dict and set(artifacts) == set(FAILURE_ARTIFACT_FORMATS),
         prefix + "complete original artifact set required")
    originals = {}
    for name, expected_format in FAILURE_ARTIFACT_FORMATS.items():
        record = artifacts[name]
        is_logcat = name in ("recent_logcat", "capture_filtered_logcat")
        fields = {"format", "evidence_file", "evidence_sha256", "bytes"} | ({"coverage"} if is_logcat else set())
        need(type(record) is dict and set(record) == fields and record["format"] == expected_format and
             type(record["bytes"]) is int and record["bytes"] > 0, prefix + "typed original required: " + name)
        raw = _failure_original({key: record[key] for key in ("evidence_file", "evidence_sha256")},
            limit=MAX_FAILURE_JSON_BYTES if expected_format == "json" else MAX_FAILURE_ARTIFACT_BYTES,
            budget=budget, seen=seen)
        need(len(raw) == record["bytes"], prefix + "original byte length differs: " + name)
        originals[name] = raw
        if is_logcat:
            coverage = record["coverage"]
            need(type(coverage) is dict and set(coverage) == {"start_utc", "end_utc", "events"} and
                 coverage["events"] in ("PRESENT", "NONE_MATCHING"), prefix + "explicit log coverage required")
            lower, upper = (_failure_timestamp(coverage[key]) for key in ("start_utc", "end_utc"))
            need(lower <= start <= end <= upper <= observed, prefix + "logs omit the failure window")
            no_events = re.search(rb"(?m)^X2DII_NO_MATCHING_EVENTS\r?$", raw) is not None
            need(no_events == (coverage["events"] == "NONE_MATCHING"),
                 prefix + "no-matching-events must be explicit in the original")
    identity = {key: q[key] for key in ("candidate_sha256", "saved_manifest_sha256", "boot_id",
                "active_slot", "official_slot", "slot_readback", "observed_utc")}
    identity["runtime_observation"] = observation
    context = {key: q[key] for key in RUNTIME_FIELDS + (("backup_identity",) if "backup_identity" in q else ())}
    configuration = {"context": context, "runtime_observation": observation}
    need(canonical(strict_json(originals["identity"])) == canonical(identity),
         prefix + "original component/slot identity differs")
    need(canonical(strict_json(originals["runtime_configuration"])) == canonical(configuration),
         prefix + "original runtime/configuration state differs")


def role_delivery(manifest):
    from .delivery_content import ROLE_FORMAT_VERSION
    return manifest.get("delivery_identity", {}).get("format_version") == ROLE_FORMAT_VERSION


def _saved_role_content(manifest):
    """Validate the retained description, never read mutable payload sources.

    This binds saved hashes/lengths, not archive availability or installation.
    Current installed-file ownership must come from the actual saved receipts.
    """
    from .delivery_content import _validate_manifest, ROLE_FORMAT_VERSION
    from .delivery_plan import ROLE_PROGRAMS, PAYLOADS
    from . import boot_config
    description = manifest.get("delivery_members")
    raw, package_bytes = _validate_manifest(description)
    identity = manifest["delivery_identity"]
    candidate = manifest["candidate"]
    need(description["format_version"] == ROLE_FORMAT_VERSION and
         description["candidate_sha256"] == manifest["candidate_sha256"] and
         identity["member_manifest_sha256"] == sha(raw) and identity["package_bytes"] == package_bytes,
         "saved role content description differs from delivery identity")
    entries = {entry["name"]: entry for entry in description["members"]}
    for file, (source, target) in zip(candidate["files"], PAYLOADS):
        need(file["source"] == source and file["target"] == target and
             entries[source.rsplit("/", 1)[-1]]["sha256"] == file["sha256"] and
             entries[source.rsplit("/", 1)[-1]]["bytes"] == file["bytes"],
             "saved role payload member differs from candidate")
    need(candidate["rc"]["before"] == boot_config.STOCK_SHA256 and
         entries["camera-gui.rc.proposed"]["sha256"] == candidate["rc"]["after"],
         "saved role boot member differs from candidate")
    need(set(manifest["script_hashes"]) == set(ROLE_PROGRAMS) and
         all(entries[name]["sha256"] == manifest["script_hashes"][name] for name in ROLE_PROGRAMS),
         "saved role program member differs from script identity")


def load_saved_candidate(path, expected_sha256):
    """Read only saved manifest bytes, never the source paths named within it."""
    path = guard_output(Path(path))
    need(path.is_file() and digest(expected_sha256), "saved candidate and retained manifest hash required")
    raw = path.read_bytes()
    need(sha(raw) == expected_sha256, "saved candidate manifest hash mismatch")
    m = json.loads(raw)
    need(m["schema"] == "x2dii-peer-script-source-v2", "unsupported saved candidate schema")
    c = m["candidate"]
    need(m["candidate_sha256"] == sha(canonical(c)), "saved candidate digest mismatch")
    need(m.get("status") in ("QUALIFIED_SCRIPT_SOURCE_NOT_EXECUTED", "QUALIFIED_DELIVERY_NOT_EXECUTED")
         and m.get("scripts_emitted") is True,
         "saved qualified installation manifest required; installation still needs current evidence")
    if m["status"] == "QUALIFIED_DELIVERY_NOT_EXECUTED":
        need(m.get("package_created") is True, "saved delivery package identity missing")
        release_identity.validate_delivery_identity(m.get("delivery_identity"))
    need(all(digest(m.get(key)) for key in
             ("renderer_source_sha256", "qualification_sha256", "execution_subject_sha256")),
         "saved installation binding missing")
    from .delivery_plan import ROLE_PROGRAMS
    expected_programs = set(ROLE_PROGRAMS) if role_delivery(m) else {"install-files.sh", "activate-boot.sh", "restore-boot.sh"}
    need(set(m.get("script_hashes", {})) == expected_programs
         and all(digest(v) for v in m["script_hashes"].values()), "saved installation script hashes required")
    need(len(c["files"]) == 4 and {f["target"] for f in c["files"]} == set(TARGETS), "exact four owned targets required")
    need(all(digest(f["sha256"]) and type(f["bytes"]) is int and f["bytes"] > 0 for f in c["files"]),
         "saved payload hashes/lengths required")
    need(c["rc"]["target"] == RC and all(digest(c["rc"][k]) for k in ("before", "after"))
         and c["rc"]["before"] != c["rc"]["after"] and digest(c["gui_sha256"]), "saved official/candidate rc identity required")
    if role_delivery(m):
        need(m["status"] == "QUALIFIED_DELIVERY_NOT_EXECUTED", "saved role delivery identity required")
        _saved_role_content(m)
    return m


def _metadata(meta, mode):
    need(meta["uid"] == meta["gid"] == 0 and meta["mode"] == mode, "unsupported owner or metadata mode")
    need(re.fullmatch(r"u:object_r:[a-z0-9_]+:s0", meta["label"]), "invalid metadata label")
    need(meta["xattr_names"] == ["security.selinux"], "unknown xattrs require a verified preservation method")


def _process(p):
    need(type(p["pid"]) is int and 1 < p["pid"] < 2**31 and re.fullmatch(r"[1-9][0-9]*", p["start_ticks"]),
         "process lifetime identity required")
    need(re.fullmatch(r"/system/(bin|xbin)/[a-zA-Z0-9_-]+", p["exe_target"]) and digest(p["exe_sha256"]),
         "process executable identity required")
    need(re.fullmatch(r"u:r:[a-z0-9_]+:s0", p["domain"]) and re.fullmatch(r"mnt:\[[0-9]+\]", p["mount_namespace"]),
         "process domain and namespace required")


def _execution_gui(m, q):
    """Existing executor supports known present/absent GUI, not unknown state.

    This is execution admission, not an observation-format rule. A changed or
    unknown GUI must still be representable in the read-only runtime identity.
    """
    gui = q["gui"]
    need(gui["state"] in ("absent", "present") and gui["service_state"] in ("stopped", "running", "restarting"),
         "explicit observed GUI state required")
    if gui["state"] == "present":
        _process(gui["process"])
        need(gui["process"]["exe_target"] == "/system/bin/camera-gui" and
             gui["process"]["exe_sha256"] == m["candidate"]["gui_sha256"] and
             gui["process"]["mount_namespace"] == q["mount_namespace"], "GUI executable/namespace differs")
    else:
        need(set(gui) == {"state", "service_state"}, "absent GUI must not contain guessed process identity")


def _context(m, saved_sha, q):
    is_role = role_delivery(m)
    need(q["candidate_sha256"] == m["candidate_sha256"] and q["saved_manifest_sha256"] == saved_sha,
         "recovery saved candidate binding mismatch")
    need(re.fullmatch(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}", q["boot_id"]), "invalid recovery boot identity")
    observed = datetime.fromisoformat(q["observed_utc"])
    need(observed.tzinfo is not None, "timezone-aware recovery observation required")
    need(q["uid"] == 0 and q["domain"] == "u:r:su:s0", "current actual su domain required")
    mount = q["system_mount"]
    need(re.fullmatch(r"/dev/block/[A-Za-z0-9_/-]+", mount["device"]) and ".." not in mount["device"].split("/"),
         "invalid recovery mount device")
    need(mount["filesystem"] == "ext4" and re.fullmatch(r"ro,[A-Za-z0-9_=,.-]+", mount["options"]),
         "read-only ext4 recovery mount required")
    need(all(re.fullmatch(r"mnt:\[[0-9]+\]", q[k]) for k in ("mount_namespace", "init_mount_namespace")),
         "current namespace evidence required")
    need(q["mount_namespace"] == q["init_mount_namespace"], "recovery namespace differs from init")
    _process(q["observer"])
    need(q["observer"]["mount_namespace"] == q["mount_namespace"], "observer namespace differs")
    need(q["active_slot"] in ("slot_1", "slot_2") and q["official_slot"] in ("slot_1", "slot_2")
         and q["active_slot"] != q["official_slot"], "distinct active and official slots required")
    expected = {slot + ".status_" + field: ("0" if slot == q["official_slot"] and field == "active" else "1")
                for slot in ("slot_1", "slot_2") for field in ("active", "bootable", "successful")}
    need(q["slot_readback"] == expected, "complete consistent slot flags required")
    need(set(q["payload_presence"]) == set(TARGETS) and all(type(x) is bool for x in q["payload_presence"].values()),
         "explicit owned payload presence required")
    need(set(q["metadata"]) == {RC, *TARGETS}, "complete target metadata required")
    for target, value in q["metadata"].items():
        if is_role and target != RC:
            # These fields are retained as actual observations for later
            # cleanup; corrupt ownership/mode must not block restoring rc.
            # An actually absent inode has no label. The wire '-' sentinel
            # is allowed only with an explicit false presence observation.
            absent = q["payload_presence"][target] is False and value == {"state": "absent", "label": None}
            need(absent or (type(value) is dict and type(value.get("label")) is str and
                 re.fullmatch(r"u:object_r:[a-z0-9_]+:s0", value["label"])),
                 "role recovery payload label is unobserved or invalid")
        else:
            _metadata(value, "644")
    need(set(q["backup_metadata"]) == ({"official"} if is_role else {"official", "owner"}),
         "original backup metadata required")
    _metadata(q["backup_metadata"]["official"], "644")
    if not is_role:
        _metadata(q["backup_metadata"]["owner"], "600")
    else:
        from . import boot_config
        from .menu_boot_transport import _identity
        need(q["observer"]["domain"] == "u:r:hbl_camera_service:s0", "role recovery needs maintenance observer")
        need(q["metadata"][RC]["label"] == "u:object_r:system_file:s0", "fixed role recovery metadata differs")
        need(_identity(q.get("backup_identity"), len(boot_config.STOCK.read_bytes())),
             "role recovery needs exact saved backup identity")
    need(q["backup_metadata"]["official"] == q["metadata"][RC], "official backup/rc metadata differ")
    need(q["rc_sha256"] in (m["candidate"]["rc"]["before"], m["candidate"]["rc"]["after"]),
         "unknown rc requires independent recovery")
    need(re.fullmatch(r"[0-9a-f]{32}", q["recovery_nonce"]), "fresh recovery workspace nonce required")
    locations = ("/system/.x2dii-menu-recovery-" + q["recovery_nonce"],
                 "/system/etc/x2dii-menu-backup/" + m["candidate_sha256"][:24])
    if is_role:
        boot_prefix = "/system/etc/.x2dii-boot-" + m["candidate_sha256"][:24]
        locations = ("/blackbox/x2dii-menu-stage/" + m["candidate_sha256"][:24],
                     boot_prefix + ".original", boot_prefix + "-" + q["session_nonce"] + "-restore.stage")
    roots = q["init_scan_roots"]
    need(q["init_scan_roots_complete"] is True and roots and len(roots) == len(set(roots))
         and "/system/etc/init" in roots, "complete actual init scan roots required")
    for root in roots:
        need(re.fullmatch(r"/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+", root) and not any(p in (".", "..") for p in root.split("/")),
             "invalid init scan root")
        need(all(not (p == root.rstrip("/") or p.startswith(root.rstrip("/") + "/")) for p in locations),
             "recovery workspace or backup lies inside init scan root")


def session_data(m, q):
    from .session_context import encode_session
    values = session_values(q)
    values.update(kind="recovery", recovery_nonce=q["recovery_nonce"], gui_state=q["gui"]["state"],
                  gui_service_state=q["gui"]["service_state"],
                  # V1's wire field remains canonical but role restore has no
                  # separate owner file; it uses the exact recorded inode.
                  backup_owner_label=q["backup_metadata"]["official" if role_delivery(m) else "owner"]["label"],
                  rc_sha256=q["rc_sha256"])
    process = q["gui"].get("process", {})
    for key in ("pid", "start_ticks", "exe_target", "exe_sha256", "domain", "mount_namespace"):
        values["gui_" + key] = process.get(key, "-")
    for target, name in LABEL_FIELDS.items():
        if target != RC:
            values["present_" + name.removesuffix("_label")] = "1" if q["payload_presence"][target] else "0"
            if role_delivery(m) and q["payload_presence"][target] is False and q["metadata"][target] == {"state": "absent", "label": None}:
                values[name] = "-"
    return encode_session(values)


def _render(m, q=None):
    need(not role_delivery(m), "role-aware recovery cannot use legacy combined-su renderer")
    from .session_context import shell_parser
    quote = shlex.quote
    candidate = m["candidate"]
    backup = "/system/etc/x2dii-menu-backup/" + m["candidate_sha256"][:24]

    def meta(path, field=None, mode="644"):
        return f'meta {quote(path)} {mode} {session_variable(field or LABEL_FIELDS[path])}\n'

    def process(name):
        prefix = '"/proc/${X2DII_SESSION_' + name.upper() + '_PID}'
        return (f'checked_equals {session_variable(name + "_start_ticks")} start_ticks {prefix}/stat" || return 1\n'
                f'checked_equals {session_variable(name + "_exe_target")} readlink {prefix}/exe" || return 1\n'
                f'hashok {prefix}/exe" {session_variable(name + "_exe_sha256")} || return 1\n'
                f'checked_equals {session_variable(name + "_domain")} cat {prefix}/attr/current" || return 1\n'
                f'checked_equals {session_variable(name + "_mount_namespace")} readlink {prefix}/ns/mnt" || return 1\n'
                f'checked_equals {session_variable(name + "_start_ticks")} start_ticks {prefix}/stat" || return 1\n')

    source = f'''#!/system/bin/sh
# Recovery ONLY. Saved candidate {m['candidate_sha256']}.
# Pure source is not qualification; no service start or reboot.
set -eu
export PATH=/system/bin:/system/xbin:/sbin
# SESSION_DATA_PARSER_BEGIN
{shell_parser()}
# SESSION_DATA_PARSER_END
[ "$#" = 2 ] || exit 32
x2dii_load_session "$1" "$2" || exit 32
[ "$X2DII_SESSION_KIND" = recovery ] || exit 32
umask 077
baseline="$X2DII_SESSION_MOUNT_DEVICE $X2DII_SESSION_MOUNT_FILESYSTEM $X2DII_SESSION_MOUNT_OPTIONS"
rw="$X2DII_SESSION_MOUNT_DEVICE $X2DII_SESSION_MOUNT_FILESYSTEM rw,${{X2DII_SESSION_MOUNT_OPTIONS#ro,}}"
backup={quote(backup)}
work="/system/.x2dii-menu-recovery-$X2DII_SESSION_RECOVERY_NONCE"
locked=0
work_owned=0
completed=0
# Only fixed renderer-authored commands reach this helper; no eval or source.
checked_equals() {{
 recovery_query_expected=$1
 shift
 recovery_query_actual=$("$@") || return 1
 [ "$recovery_query_actual" = "$recovery_query_expected" ]
}}
hashok() {{ actual=$(sha256sum "$1") || return 1; [ "${{actual%% *}}" = "$2" ]; }}
regular() {{ [ -f "$1" ] && [ ! -L "$1" ] && checked_equals 1 stat -c %h "$1"; }}
absent() {{ [ ! -e "$1" ] && [ ! -L "$1" ]; }}
meta() {{
 regular "$1" || return 1
 checked_equals "0 0 $2" stat -c '%u %g %a' "$1" || return 1
 label=$(ls -Zd "$1") || return 1
 [ "${{label%% *}}" = "$3" ]
}}
private_directory() {{ [ -d "$1" ] && [ ! -L "$1" ] && checked_equals '0 0 700' stat -c '%u %g %a' "$1"; }}
state() (
 set -f
 while :; do
  state_line=
  if IFS= read -r state_line; then
   set -- $state_line
   [ "$#" = 6 ] || return 1
   [ "$2" != /system ] || printf '%s %s %s\\n' "$1" "$3" "$4" || return 1
  else
   recovery_read_status=$?
   # Only empty status-1 reads retain EOF behavior; I/O errors may share that result.
   [ "$recovery_read_status" = 1 ] || return 1
   [ -z "$state_line" ] || return 1
   break
  fi
 done < /proc/mounts
)
rw_state() {{ checked_equals "$rw" state; }}
start_ticks() {{
 line=$(cat "$1") || return 1
 tail=${{line##*) }}
 [ "$tail" != "$line" ] || return 1
 set -- $tail
 [ "$#" -ge 20 ] || return 1
 shift 19
 printf '%s\\n' "$1"
}}
fresh() {{
 now=$(date -u +%s) || return 1
 case "$now" in ''|*[!0-9]*) return 1;; esac
 [ "$now" -ge "$X2DII_SESSION_OBSERVED_EPOCH" ] && [ "$now" -le "$((X2DII_SESSION_OBSERVED_EPOCH + 600))" ]
}}
mount_identity() {{
 checked_equals "$X2DII_SESSION_BOOT_ID" cat /proc/sys/kernel/random/boot_id || return 1
 checked_equals "$X2DII_SESSION_MOUNT_NAMESPACE" readlink /proc/self/ns/mnt || return 1
 checked_equals "$X2DII_SESSION_INIT_MOUNT_NAMESPACE" readlink /proc/1/ns/mnt
}}
identity() {{
 fresh || return 1
 checked_equals 0 id -u && checked_equals u:r:su:s0 cat /proc/self/attr/current || return 1
 mount_identity || return 1
'''
    source += process("observer")
    for slot in (1, 2):
        for flag in ("active", "bootable", "successful"):
            source += f'checked_equals {session_variable(f"slot{slot}_{flag}")} unrd slot_{slot}.status_{flag} || return 1\n'
    source += f'hashok /system/bin/camera-gui {candidate["gui_sha256"]} || return 1\nfresh\n}}\n'
    source += 'observed_gui() {\n'
    source += 'checked_equals "$X2DII_SESSION_GUI_SERVICE_STATE" getprop init.svc.camera-gui || return 1\n'
    source += 'if [ "$X2DII_SESSION_GUI_STATE" = present ]; then\n'
    source += 'pids=$(pidof camera-gui) || return 1\n[ "$pids" = "$X2DII_SESSION_GUI_PID" ] || return 1\n'
    source += process("gui")
    source += 'else\nif pidof camera-gui >/dev/null 2>&1; then return 1; else [ "$?" = 1 ] || return 1; fi\nfi\n'
    source += '''}
quiescent() {
 checked_equals stopped getprop init.svc.camera-gui || return 1
 if pidof camera-gui >/dev/null 2>&1; then return 1; else [ "$?" = 1 ] || return 1; fi
 for maps in /proc/[0-9]*/maps; do
  [ -e "$maps" ] || continue
  [ -r "$maps" ] || return 1
'''
    source += f'  if grep -F {quote(LIBRARY)} "$maps" >/dev/null; then return 1; else [ "$?" = 1 ] || return 1; fi\n'
    source += ''' done
}
paths() {
 for directory in /system /system/etc /system/lib64 /system/bin /system/etc/init /tmp; do
  [ -d "$directory" ] && [ ! -L "$directory" ] || return 1
 done
 private_directory /system/etc/x2dii-menu-backup || return 1
 private_directory "$backup" || return 1
 device=$(stat -c %d /system) || return 1
 for directory in /system/etc /system/lib64 /system/etc/init "$backup"; do
  checked_equals "$device" stat -c %d "$directory" || return 1
 done
}
backup_ok() {
'''
    source += meta(backup + "/owner", "backup_owner_label", "600").rstrip() + ' || return 1\n'
    source += f'hashok "$backup/owner" {sha((m["candidate_sha256"] + chr(10)).encode())} || return 1\n'
    source += meta(backup + "/camera-gui.rc.original", "rc_label").rstrip() + ' || return 1\n'
    source += f'hashok "$backup/camera-gui.rc.original" {candidate["rc"]["before"]} || return 1\n}}\n'
    source += 'payloads_ok() {\n'
    for entry in candidate["files"]:
        target = entry["target"]
        field = "present_" + LABEL_FIELDS[target].removesuffix("_label")
        source += f'if [ {session_variable(field)} = 1 ]; then\n'
        source += meta(target).rstrip() + ' || return 1\n'
        source += f'hashok {quote(target)} {entry["sha256"]} || return 1\n'
        source += f'checked_equals {entry["bytes"]} stat -c %s {quote(target)} || return 1\n'
        source += f'else\nabsent {quote(target)} || return 1\nfi\n'
    source += ' }\npreflight() {\nidentity || return 1\npaths || return 1\nbackup_ok || return 1\npayloads_ok || return 1\n'
    source += meta(RC).rstrip() + ' || return 1\n'
    source += f'hashok {RC} "$X2DII_SESSION_RC_SHA256" || return 1\n}}\n'
    source += f'''restore_ro() {{
 mount_identity || return 1
 current=$(state) || return 1
 if [ "$current" = "$rw" ]; then mount -o remount,ro /system || return 1; fi
 checked_equals "$baseline" state
}}
finish() {{
 code=$?
 trap - EXIT HUP INT TERM
 if [ "$locked" = 1 ]; then
  # Cleanup only our exclusive workspace, and only in the original identity.
  if mount_identity; then
   if [ "$work_owned" = 1 ] && identity && rw_state; then
    if [ -e "$work/camera-gui.rc.restore" ] || [ -L "$work/camera-gui.rc.restore" ]; then
     if regular "$work/camera-gui.rc.restore" && hashok "$work/camera-gui.rc.restore" {candidate['rc']['before']} && identity; then
      rm "$work/camera-gui.rc.restore" || code=71
     else code=71; fi
    fi
    if identity; then rmdir "$work" || code=71; else code=71; fi
   fi
   restore_ro || code=72
   if mount_identity; then rmdir /tmp/x2dii-menu-install.lock || code=73; else code=72; fi
  else code=72; fi
 fi
 [ "$code" = 0 ] || echo "X2DII_RECOVERY_FAILED:$code; GUI state unverified; this script does not restart GUI; preserve official backup" >&2
 if [ "$code" = 0 ] && [ "$completed" = 1 ]; then
  echo X2DII_OFFICIAL_RC_RESTORED_OWNED_FILES_REMOVED
 fi
 exit "$code"
}}
trap finish EXIT
trap 'exit 74' HUP INT TERM
checked_equals "$baseline" state || exit 32
preflight
observed_gui
absent "$work"
identity
mkdir /tmp/x2dii-menu-install.lock
locked=1
preflight
observed_gui
identity
stop camera-gui
i=0
while ! quiescent && [ "$i" -lt 50 ]; do sleep .1; i=$((i+1)); done
quiescent || exit 34
preflight
checked_equals "$baseline" state
identity
mount -o remount,rw /system
rw_state
preflight
quiescent
rw_state
identity
mkdir "$work"
work_owned=1
private_directory "$work"
work_device=$(stat -c %d "$work") || exit 1
checked_equals "$work_device" stat -c %d /system/etc/init
identity
cp -p "$backup/camera-gui.rc.original" "$work/camera-gui.rc.restore"
identity
chcon "$X2DII_SESSION_RC_LABEL" "$work/camera-gui.rc.restore"
hashok "$work/camera-gui.rc.restore" {candidate['rc']['before']}
meta "$work/camera-gui.rc.restore" 644 "$X2DII_SESSION_RC_LABEL"
sync
preflight
quiescent
rw_state
identity
mv -f "$work/camera-gui.rc.restore" {RC}
sync
hashok {RC} {candidate['rc']['before']}
'''
    source += meta(RC)
    # All present files were verified before the first write. Recheck each file
    # just before removing it; never clean up an unknown/changed extension.
    for entry in candidate["files"]:
        target = entry["target"]
        field = "present_" + LABEL_FIELDS[target].removesuffix("_label")
        source += f'if [ {session_variable(field)} = 1 ]; then\n'
        source += 'identity\npaths\nbackup_ok\nquiescent\nrw_state\n'
        source += f'hashok {RC} {candidate["rc"]["before"]}\n' + meta(RC)
        source += f'hashok {quote(target)} {entry["sha256"]}\n' + meta(target)
        source += f'identity\nrm {quote(target)}\nabsent {quote(target)}\nsync\nfi\n'
    source += f'hashok {RC} {candidate["rc"]["before"]}\n'
    for target in TARGETS:
        source += f'absent {quote(target)}\n'
    source += 'backup_ok\nidentity\nrmdir "$work"\nwork_owned=0\nrestore_ro\ncompleted=1\n'
    return source


def _render_role(m):
    """Official-rc first, using saved candidate identity, not current payloads."""
    from . import boot_config, menu_boot_file
    return menu_boot_file.render_supervised_boot_transaction(m, action="restore",
        original_rc=boot_config.STOCK.read_bytes(), metadata={"uid": 0, "gid": 0, "mode": "644",
            "label": "u:object_r:system_file:s0", "xattr_names": ["security.selinux"]},
        init_scan_roots=["/system/etc/init"])


def render_recovery(saved_manifest, saved_manifest_sha256, context):
    """Pure review/harness source; this does not authorize or publish execution."""
    m = load_saved_candidate(saved_manifest, saved_manifest_sha256)
    _context(m, saved_manifest_sha256, context)
    if role_delivery(m):
        # No process restart/unmapping/deletion in this phase. Validate the
        # supported recovery wire context without requiring healthy capture.
        from .menu_boot_boundary import context_for_action
        context_for_action(m, session_data(m, context), "restore")
        return _render_role(m)
    _execution_gui(m, context)
    return _render(m, context)


def build_subject_sha256(saved_manifest, saved_manifest_sha256, *, rendered_script=None):
    m = load_saved_candidate(saved_manifest, saved_manifest_sha256)
    # Recovery never reads mutable candidate payloads or Qt/native build output.
    # The independently audited recovery sources and tests are its own inputs.
    paths = ("tools/prepare_peer_recovery.py", "tools/prepare_peer_install.py", "tools/session_context.py",
             "tools/release_identity.py", "tools/output_guard.py", "tools/regression_manifest.py",
             "tools/boot_config.py", "tools/qt_unit.py", "tests/test_peer_install.py",
             "tools/reviewed_applicability.py", "tests/test_reviewed_applicability.py",
             "tests/test_registry_review_integration.py", "tests/test_regression_manifest.py",
             "tests/test_peer_recovery.py", "tests/test_session_context.py", "tests/test_session_context_v2.py",
             "tests/test_release_lifecycle.py",
             "tests/test_recovery_boundaries.py", "tests/test_recovery_query_status.py", "tests/test_full_audit_inventory.py",
             "tools/runtime_observation.py", "tests/test_runtime_observation.py", "tests/test_runtime_binding.py",
             "tools/delivery_content.py", "tools/delivery_plan.py", "tests/test_delivery_binding.py", "tests/test_recovery_delivery.py",
             "tests/test_recovery_role_v2.py", "tests/test_recovery_role_publication.py",
             "tests/test_output_set.py", "tests/test_output_withdrawal.py",
             "work/reverse/X2DII_REGRESSION_GATES.json", "AGENTS.md", "pytest.ini") + release_identity.REVIEW_INPUTS + release_identity.AUDIT_INPUTS
    if role_delivery(m):
        paths += ("tools/menu_boot_file.py", "tools/menu_boot_boundary.py", "tools/menu_boot_transport.py",
                  "tools/menu_preplacement_transport.py", "tools/menu_content_transport.py",
                  "tools/menu_maintenance_boundary.py", "tools/temporary_menu_files.py",
                  "tools/menu_prepared_transport.py", "tools/stage_menu_delivery.py",
                  "tools/menu_owned_cleanup.py", "tools/menu_cleanup_transport.py", "tools/menu_stock_boot.py",
                  "tools/stage_peer_usb_access.py", "tools/peer_usb_access.py", "tools/live_readout.py",
                  "tools/factory_reply.py", "tools/delivery_files.py", "tools/menu_lifecycle_transport.py",
                  "tests/test_menu_boot_file.py", "tests/test_menu_boot_boundary.py",
                  "tests/test_menu_boot_transport.py", "tests/test_boot_host_transport.py",
                  "tests/test_prepared_qualified_transport.py", "tests/test_prepared_boot_transport.py",
                  "tests/test_prepared_cleanup_transport.py", "tests/test_menu_owned_cleanup.py",
                  "tests/test_menu_preplacement_transport.py", "tests/test_role_end_to_end.py",
                  "tests/test_menu_cleanup_transport.py", "tests/test_menu_stock_boot.py",
                  "tests/test_cleanup_source_staging.py", "tests/test_boot_observer_staging.py",
                  "tests/test_menu_preparation_transport.py", "tests/test_menu_content_transport.py",
                  "tests/test_stage_menu_delivery.py", "tests/test_raw_session_staging.py",
                  "tests/test_exclusive_archive_staging.py", "tests/test_stage_peer_usb_access.py",
                  "tests/test_preplacement_host_dialogue.py", "tests/menu_transport_wire_fixture.py",
                  "tests/test_qualified_role_content.py", "tests/test_formal_install_preparation.py")
    inputs = {path: sha((ROOT / path).read_bytes()) for path in paths}
    source = (_render_role(m) if role_delivery(m) else _render(m)) if rendered_script is None else rendered_script
    need(type(source) is str and source and source.isascii(), "recovery program must be nonempty ASCII source")
    scripts = {SCRIPT: source}
    if role_delivery(m):
        from .menu_boot_boundary import render_observer
        scripts = {"restore-boot.sh": source, "maintenance-restore": render_observer(m, action="restore")}
    return release_identity.build_subject(m["candidate"], scripts,
                                          source_hash=sha(Path(__file__).read_bytes()), inputs=inputs,
                                          retained={"saved_manifest_sha256": saved_manifest_sha256})


def runtime_subject_sha256(saved_manifest, saved_manifest_sha256, context):
    m = load_saved_candidate(saved_manifest, saved_manifest_sha256)
    _context(m, saved_manifest_sha256, context)
    observation = normalize_observation(context, m["candidate"]["gui_sha256"], recovery=True)
    return sha(canonical({"schema": "x2dii-recovery-runtime-subject-v2",
                          "build_subject_sha256": build_subject_sha256(saved_manifest, saved_manifest_sha256),
                          "context": {key: context[key] for key in
                                      RUNTIME_FIELDS + (("backup_identity",) if role_delivery(m) else ())},
                          "runtime_observation": observation}))


def execution_subject_sha256(saved_manifest, saved_manifest_sha256, context):
    m = load_saved_candidate(saved_manifest, saved_manifest_sha256)
    if not role_delivery(m):
        _execution_gui(m, context)
    return sha(canonical({"schema": "x2dii-recovery-execution-lease-v2",
                          "runtime_subject_sha256": runtime_subject_sha256(saved_manifest, saved_manifest_sha256, context),
                          "observed_utc": context["observed_utc"], "session_nonce": context["session_nonce"],
                          "session_data_sha256": sha(session_data(m, context))}))


def validate_qualification(saved_manifest, saved_manifest_sha256, qualification, now=None, *, for_publication=False):
    q = qualification
    need(q.get("synthetic") is False, "synthetic recovery cannot authorize publication")
    m = load_saved_candidate(saved_manifest, saved_manifest_sha256)
    observation = normalize_observation(q, m["candidate"]["gui_sha256"], recovery=True)
    need(not for_publication or observation["test_fixture_only"] is False,
         "runtime observation test fixture cannot authorize publication")
    if for_publication:
        release_identity.validate_runtime_references(observation)
    subject = execution_subject_sha256(saved_manifest, saved_manifest_sha256, q)
    fixed_now = now
    now = now or datetime.now(timezone.utc)
    observed = datetime.fromisoformat(q["observed_utc"])
    need(observed.tzinfo is not None and 0 <= (now - observed).total_seconds() <= 600, "recovery qualification is not fresh")
    need(q.get("execution_subject_sha256") == subject, "recovery execution subject mismatch")
    build = build_subject_sha256(saved_manifest, saved_manifest_sha256)
    runtime = runtime_subject_sha256(saved_manifest, saved_manifest_sha256, q)
    need(q.get("build_subject_sha256") == build, "recovery build subject mismatch")
    need(q.get("runtime_subject_sha256") == runtime, "recovery runtime subject mismatch")
    gate_values, gate_phases = q["gates"], GATE_PHASES
    if for_publication:
        _validate_failure_bundle(q, observation, saved_sha=saved_manifest_sha256,
                                 build=build, runtime=runtime, subject=subject)
        # This one runtime phase is fully checked above using bounded original
        # reads and the same bindings. Do not reread it with the generic reader.
        # Keep every other gate/phase, including this gate's build half, intact.
        gate_values = dict(q["gates"], recovery_historical_regressions={
            "build": q["gates"]["recovery_historical_regressions"]["build"]})
        gate_phases = dict(GATE_PHASES, recovery_historical_regressions=("build",))
    release_identity.validate_gates(gate_values, gate_phases, candidate_sha256=q["candidate_sha256"],
                                   build_subject_sha256=build, runtime_subject_sha256=runtime, boot_id=q["boot_id"],
                                   retained={"saved_manifest_sha256": saved_manifest_sha256},
                                   for_publication=for_publication)
    bindings = {"candidate_sha256": q["candidate_sha256"], "saved_manifest_sha256": saved_manifest_sha256,
                "boot_id": q["boot_id"], "execution_subject_sha256": subject}
    approval = q["recovery_authorization"]
    need(approval.get("approved") is True and approval.get("purpose") == "restore_official_boot_remove_owned_extension"
         and all(approval.get(k) == v for k, v in bindings.items())
         and approval.get("session_nonce") == q["recovery_nonce"], "separate current recovery-only authorization required")
    completed_at = fixed_now if fixed_now is not None else datetime.now(timezone.utc)
    need(0 <= (completed_at - observed).total_seconds() <= 600,
         "lease expired during recovery qualification evidence checks")
    return subject


def prepare(destination, saved_manifest, saved_manifest_sha256, qualification=None):
    m = load_saved_candidate(saved_manifest, saved_manifest_sha256)
    is_role = role_delivery(m)
    report = {"schema": "x2dii-peer-recovery-source-v1", "status": "LOCAL_RECOVERY_UNQUALIFIED",
              "candidate_sha256": m["candidate_sha256"], "saved_manifest_sha256": saved_manifest_sha256,
              "installable": False, "camera_accesses": 0, "package_created": False, "scripts_emitted": False,
              "required_gates": {gate: "PENDING" for gate in GATES}, "recovery_authorization": "PENDING_SEPARATE",
              "script_hashes": {}, "execution_subject_sha256": None,
              "independent_recovery_gaps": ["missing/corrupt verified official backup", "loss of accepted su domain",
                                            "unknown/corrupt rc or changed/unowned payload", "power loss during writes"]}
    if is_role:
        # Restore the official boot configuration first. Later owned cleanup
        # requires its own different-boot observation and exact inode receipts;
        # nothing published here removes files or claims that restart succeeded.
        report.update(recovery_scope="OFFICIAL_RC_ONLY_OWNED_FILES_RETAINED",
                      owned_cleanup_status="REQUIRES_NEW_BOOT_STOCK_READBACK_AND_EXACT_OWNERSHIP",
                      independent_recovery_gaps=["missing/corrupt verified official backup",
                          "loss of accepted su domain", "unknown/corrupt rc", "power loss during writes"])
    outputs = {}
    if qualification is not None:
        qualification = deepcopy(qualification)
        subject = validate_qualification(saved_manifest, saved_manifest_sha256, qualification, for_publication=True)
        source = render_recovery(saved_manifest, saved_manifest_sha256, qualification)
        need(build_subject_sha256(saved_manifest, saved_manifest_sha256, rendered_script=source)
             == qualification["build_subject_sha256"], "rendered recovery differs from the approved build")
        programs = {SCRIPT: source}
        if is_role:
            from .menu_boot_boundary import render_observer
            programs = {"restore-boot.sh": source,
                        "maintenance-restore": render_observer(m, action="restore")}
        shell = shutil.which("sh") or "C:/Program Files/Git/bin/sh.exe"
        for name, program in programs.items():
            raw = program.encode("ascii")
            checked = subprocess.run([shell, "-n"], input=raw, capture_output=True, timeout=10)
            need(checked.returncode == 0, "recovery shell syntax failure: " + name)
            outputs[name] = raw
        outputs["session-context.data"] = session_data(m, qualification)
        report.update(status="QUALIFIED_RECOVERY_SOURCE_NOT_EXECUTED", scripts_emitted=True,
                      required_gates={gate: "PASS" for gate in GATES}, execution_subject_sha256=subject,
                      recovery_authorization="SUPPLIED_CURRENT_RECOVERY_ONLY_NOT_EXECUTED",
                      qualification_sha256=sha(canonical(qualification)),
                      script_hashes={name: sha(outputs[name]) for name in programs})
        report.update(build_subject_sha256=qualification["build_subject_sha256"],
                      runtime_subject_sha256=qualification["runtime_subject_sha256"],
                      session_data_sha256=sha(outputs["session-context.data"]))
    destination = guard_output(Path(destination))
    # This publication directory is exclusively recovery-only, including when
    # the caller tries to reuse a directory from the installation publisher.
    forbidden = ("install-files.sh", "activate-boot.sh", "restore-boot.sh", SCRIPT, "maintenance-restore",
                 "session-context.data", "x2dii-menu-content.tar", "members.json",
                 *(f"preplace-{index}.sh" for index in range(4)))
    for name in forbidden:
        if name not in outputs:
            need(not guard_output(destination / name).exists(), "recovery output contains forbidden executable: " + name)
    outputs["peer-recovery-source.json"] = (json.dumps(report, indent=2) + "\n").encode()
    recheck = (lambda: validate_qualification(saved_manifest, saved_manifest_sha256, qualification,
                                             for_publication=True)) if qualification is not None else None
    publish_output_set(destination, outputs, commit_name="peer-recovery-source.json", before_commit=recheck)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--saved-manifest", required=True, type=Path)
    parser.add_argument("--saved-manifest-sha256", required=True)
    parser.add_argument("--qualification", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "build/peer-recovery-source")
    args = parser.parse_args()
    report = prepare(args.output, args.saved_manifest, args.saved_manifest_sha256,
                     json.loads(args.qualification.read_text()) if args.qualification else None)
    print(json.dumps({k: report[k] for k in ("status", "scripts_emitted", "installable")}))
