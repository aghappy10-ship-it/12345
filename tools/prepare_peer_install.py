"""二代参考安装适配：默认只生成未决清单；完整资格后才发布固定内容。

不连接相机、不执行设备命令或传输。获准交付绑定精确归档、检查和短时批准。
无资格时不装配归档或输出脚本。脚本继承参考项目
的文件安装、启动启用和启动恢复三个阶段；只有 camera-gui 的两行环境改动。
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess

from . import boot_config as boot
from .output_guard import guard_output
from .qt_unit import GUI_SHA256
from . import release_identity
from .runtime_observation import normalize_observation

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "reference/x2d/CodeTests/temporary_af_speed_probe/original-menu-candidate"
REFERENCE_COMMIT = "9f6c9baffeaf30ac805905f8052973f60b11acf6"
REFERENCE_HASHES = {
    "native-package/install-files.sh": "7f085414fe3efaf732fa3739ea7ccbc7d6b064023c48da7b3d3b133773b25730",
    "native-package/activate-boot.sh": "9c69fcc351bef0aa0596021cd7959e1d710887e9c827b7d152b217b5747d398b",
    "native-package/restore-boot.sh": "22fbe7a8d7436696f455f686a7882247d8050cdfcb1988f2e96b201a0d258338",
    "prepare_device_files.py": "c8da5bc66acd46f6ae9a55adbd8db6b5fe7e2815b537c3a66e0f5ee1c4ea9f4c",
    "prepare_persistent_config.py": "c9957bc957b6fa1721befcc3ecdfb97b296961d35c580717179ae9e369638ae0",
}
FILES = (("build/native/libx2dii_menu.so", boot.LIBRARY),
         *(("qml/" + name, "/system/etc/" + name) for name in
           ("X2d2MenuBootstrap.qml", "X2d2MenuModel.qml", "X2d2MenuPage.qml")))
GATES = ("complete_offline_audit", "all_applicable_historical_regressions", "actual_menu_keys_capture",
         "package_integrity_and_roundtrip", "actual_su_domain_access", "independent_recovery_official_slot",
         "target_shell_tools_and_sync_rename", "complete_metadata_xattrs", "init_stop_inhibits_restart",
         "current_slot_mount_namespace", "exclusive_maintenance_session")
EXECUTION_CONTEXT_FIELDS = ("observed_utc", "boot_id", "uid", "domain", "system_mount", "slot_readback",
                            "active_slot", "official_slot", "metadata", "init_scan_roots",
                            "init_scan_roots_complete", "mount_namespace", "init_mount_namespace", "observer", "session_nonce")
RUNTIME_FIELDS = ("boot_id", "uid", "domain", "system_mount", "slot_readback", "active_slot",
                  "official_slot", "metadata", "init_scan_roots", "init_scan_roots_complete",
                  "mount_namespace", "init_mount_namespace", "observer")
GATE_PHASES = {gate: (("build",) if gate == "complete_offline_audit" else
                     ("build", "runtime") if gate in ("all_applicable_historical_regressions",
                                                        "package_integrity_and_roundtrip") else ("runtime",))
               for gate in GATES}
LABEL_FIELDS = dict(zip((boot.TARGET, *(target for _, target in FILES)),
                       ("rc_label", "library_label", "bootstrap_label", "model_label", "page_label")))
DELIVERY_NAME = "x2dii-menu-content.tar"


def session_variable(name):
    """Only fixed developer-authored field names are used in program source."""
    return '"${X2DII_SESSION_' + name.upper() + '}"'


def session_values(q):
    """Flatten the existing observation fields; no claims are inferred here."""
    values = {"kind": "install", "observed_epoch": int(datetime.fromisoformat(q["observed_utc"]).timestamp()),
              "boot_id": q["boot_id"], "session_nonce": q["session_nonce"],
              "mount_namespace": q["mount_namespace"], "init_mount_namespace": q["init_mount_namespace"],
              "active_slot": q["active_slot"], "official_slot": q["official_slot"]}
    values.update({"mount_" + key: value for key, value in q["system_mount"].items()})
    values.update({"observer_" + key: value for key, value in q["observer"].items()})
    for slot in (1, 2):
        for flag in ("active", "bootable", "successful"):
            values[f"slot{slot}_{flag}"] = q["slot_readback"][f"slot_{slot}.status_{flag}"]
    values.update({name: q["metadata"][target]["label"] for target, name in LABEL_FIELDS.items()})
    return values


def session_data(manifest, q):
    """Canonical data only, never executable shell or installation authority."""
    from .session_context import encode_session, INSTALL_SCHEMA
    observation = normalize_observation(q, manifest["candidate"]["gui_sha256"])
    values = session_values(q)
    for component, prefix in (("gui", "core_gui"), ("service", "core_service"),
                              ("capture_owner", "core_capture")):
        values.update({prefix + "_" + key: value for key, value in observation[component]["process"].items()})
        values[prefix + "_bytes"] = observation[component]["artifact"]["bytes"]
    values.update(core_gui_service_state=observation["gui"]["service_state"],
                  core_service_service_state=observation["service"]["service_state"],
                  core_sensor_sha256=observation["sensor"]["sha256"],
                  core_sensor_bytes=observation["sensor"]["bytes"])
    return encode_session(values, schema=INSTALL_SCHEMA)


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def renderer_source_sha256():
    return sha(Path(__file__).read_bytes())


def validate_session_context(q):
    """The same current namespace/lifetime contract used by recovery-only."""
    need(all(re.fullmatch(r"mnt:\[[0-9]+\]", q[key]) for key in
             ("mount_namespace", "init_mount_namespace")), "current namespace evidence required")
    need(q["mount_namespace"] == q["init_mount_namespace"], "execution namespace differs from init")
    observer = q["observer"]
    need(type(observer["pid"]) is int and 1 < observer["pid"] < 2**31
         and re.fullmatch(r"[1-9][0-9]*", observer["start_ticks"]), "observer process lifetime required")
    need(re.fullmatch(r"/system/(bin|xbin)/[a-zA-Z0-9_-]+", observer["exe_target"])
         and re.fullmatch(r"[0-9a-f]{64}", observer["exe_sha256"]), "observer executable identity required")
    need(re.fullmatch(r"u:r:[a-z0-9_]+:s0", observer["domain"])
         and observer["mount_namespace"] == q["mount_namespace"], "observer domain/namespace differs")


def build_subject_sha256(manifest):
    return release_identity.build_subject(manifest["candidate"], render_role_programs(manifest),
                                          source_hash=renderer_source_sha256())


def render_role_programs(manifest):
    """Stable six-program formal replacement for the legacy combined-su route.

    Pure source rendering is not publication or permission to run. Maintenance
    programs stay on their own route and are bound as reviewed build inputs.
    Runtime data never changes these payload/rc program bytes.
    """
    from .temporary_menu_files import render_supervised_preplacement
    from .menu_boot_file import render_supervised_boot_transaction
    scripts = {f"preplace-{index}.sh": render_supervised_preplacement(
        manifest, file_index=index, session_kind="install") for index in range(4)}
    metadata = {"uid": 0, "gid": 0, "mode": "644", "label": "u:object_r:system_file:s0",
                "xattr_names": ["security.selinux"]}
    for action in ("activate", "restore"):
        scripts[action + "-boot.sh"] = render_supervised_boot_transaction(
            manifest, action=action, original_rc=boot.STOCK.read_bytes(),
            metadata=metadata, init_scan_roots=["/system/etc/init"])
    return scripts


def runtime_subject_sha256(manifest, qualification):
    observation = normalize_observation(qualification, manifest["candidate"]["gui_sha256"])
    return sha(canonical({"schema": "x2dii-install-runtime-subject-v2",
                          "build_subject_sha256": build_subject_sha256(manifest),
                          "context": {key: qualification[key] for key in RUNTIME_FIELDS},
                          "runtime_observation": observation}))


def execution_subject_sha256(manifest, qualification):
    """Short lease identity; reports/approval excluded, nonce explicitly bound."""
    return sha(canonical({
        "schema": "x2dii-peer-execution-lease-v3",
        "delivery_identity": release_identity.validate_delivery_identity(qualification.get("delivery_identity")),
        "runtime_subject_sha256": runtime_subject_sha256(manifest, qualification),
        "observed_utc": qualification["observed_utc"], "session_nonce": qualification["session_nonce"],
        "session_data_sha256": sha(session_data(manifest, qualification)),
    }))


def inventory():
    for name, digest in REFERENCE_HASHES.items():
        need(sha((REFERENCE / name).read_bytes()) == digest, "参考来源变化: " + name)
    native = json.loads((ROOT / "build/native/native-build.json").read_text())
    files = [{"source": source, "target": target, "sha256": sha((ROOT / source).read_bytes()),
              "bytes": (ROOT / source).stat().st_size} for source, target in FILES]
    need(files[0]["sha256"] == native["library"]["sha256"], "当前原生库与构建证据不一致")
    need(sha((ROOT / "src/menu_preload.c").read_bytes()) == native["sourceSha256"], "原生源码变化")
    need(native["reproducibility"]["exactLibraryBytesEqual"] is True, "缺少双重原生构建")
    original = boot.STOCK.read_bytes()
    proposed = boot.activate(original)
    candidate = {"gui_sha256": GUI_SHA256, "files": files,
                 "rc": {"target": boot.TARGET, "before": sha(original), "after": sha(proposed),
                        "source": "build/boot-config/camera-gui.rc.proposed"}}
    need(sha((ROOT / candidate["rc"]["source"]).read_bytes()) == candidate["rc"]["after"], "启动配置提案变化")
    from .delivery_content import ROLE_FORMAT_VERSION
    return {"schema": "x2dii-peer-script-source-v2", "status": "LOCAL_SOURCE_UNQUALIFIED",
            "installable": False, "camera_accesses": 0, "package_created": False,
            "renderer_source_sha256": renderer_source_sha256(), "execution_subject_sha256": None,
            "candidate": candidate, "candidate_sha256": sha(canonical(candidate)),
            "reference": {"commit": REFERENCE_COMMIT, "files": REFERENCE_HASHES,
                          "executed": False, "adaptation": "二代四文件、动态槽位、rc最后启用及先恢复；不移植preview-loader或AF修改",
                          "historical_mismatch": "参考install-files与activate-boot内的库及Bootstrap哈希不同，不能拼接为同一候选"},
            "required_gates": {gate: "PENDING" for gate in GATES},
            "required_domain": "u:r:su:s0", "maintenance_domain_is_not_su": True,
            "recovery_limitations": {"supported": "仅恢复已知原厂/候选rc及哈希、元数据、归属匹配的扩展文件",
                                     "independent": "PENDING：未知或损坏rc、元数据变化、断电及失去su访问仍需独立恢复路径；本脚本拒绝覆盖未知文件"},
            "final_installation_approval": "PENDING_SEPARATE", "scripts_emitted": False,
            "role_deployment": {"format_version": ROLE_FORMAT_VERSION, "status": "SOURCE_CONNECTED_UNQUALIFIED",
                "legacy_combined_su_route_replaced": True,
                "remaining": ["current_target_qualification"]}}


def validate_qualification(manifest, qualification, now=None, *, for_publication=False):
    """Validate exact bindings and supplied evidence; never infer a live PASS.

    Evidence must already be reviewed externally. Hash verification establishes
    identity, not truth of an arbitrary JSON author's device claims.
    Default use also admits marked format fixtures for structural tests only;
    the publication boundary always rejects them explicitly.
    """
    fixed_now = now  # Explicit deterministic clock only for structural callers.
    now = now or datetime.now(timezone.utc)
    q, digest = qualification, manifest["candidate_sha256"]
    from .delivery_content import ROLE_FORMAT_VERSION
    role_delivery = q.get("delivery_identity", {}).get("format_version") == ROLE_FORMAT_VERSION
    need(q.get("candidate_sha256") == digest, "qualification candidate mismatch")
    need(q.get("synthetic") is False, "synthetic qualification cannot authorize scripts")
    observation = normalize_observation(q, manifest["candidate"]["gui_sha256"])
    need(not for_publication or observation["test_fixture_only"] is False,
         "runtime observation test fixture cannot authorize publication")
    if for_publication:
        release_identity.validate_runtime_references(observation)
    observed = datetime.fromisoformat(q["observed_utc"])
    need(observed.tzinfo is not None and 0 <= (now - observed).total_seconds() <= 600, "qualification is not fresh")
    need(re.fullmatch(r"[0-9a-f-]{36}", q["boot_id"]), "invalid current boot identity")
    need(q.get("uid") == 0 and q.get("domain") == "u:r:su:s0", "actual su domain is required; maintenance is not equivalent")
    validate_session_context(q)
    if role_delivery:
        need(q["observer"]["domain"] == "u:r:hbl_camera_service:s0",
             "formal role route needs maintenance observer")
    need(not for_publication or role_delivery, "formal publication requires role-aware v2 delivery")
    mount = q["system_mount"]
    need(re.fullmatch(r"/dev/block/[A-Za-z0-9_/-]+", mount["device"]) and ".." not in mount["device"].split("/"), "invalid attested mount device")
    need(mount["filesystem"] == "ext4" and re.fullmatch(r"ro,[A-Za-z0-9_=,.-]+", mount["options"]), "exact read-only ext4 mount required")
    need(q["active_slot"] in ("slot_1", "slot_2") and q["official_slot"] in ("slot_1", "slot_2")
         and q["active_slot"] != q["official_slot"], "distinct active and official slots required")
    slots = {slot + ".status_" + field for slot in ("slot_1", "slot_2") for field in ("active", "bootable", "successful")}
    need(set(q["slot_readback"]) == slots, "complete fresh slot readback required")
    # Observed unrd format: run-s04ccwd7/slot{1,2}.txt contains one bare
    # 0/1 per command. Qualification stores each command substitution's
    # value without its final newline; reject every unobserved representation.
    need(all(isinstance(v, str) and v in ("0", "1") for v in q["slot_readback"].values()),
         "unknown slot response format")
    slot_flags = {key: int(value) for key, value in q["slot_readback"].items()}
    need(slot_flags[q["active_slot"] + ".status_active"] == 1 and
         slot_flags[q["official_slot"] + ".status_active"] == 0, "slot active flags contradict declared slots")
    need(all(slot_flags[slot + ".status_" + flag] == 1 for slot in ("slot_1", "slot_2")
             for flag in ("bootable", "successful")), "both slots must report bootable and successful")
    # Flags never establish official-slot file integrity or a recovery route;
    # independent_recovery_official_slot still requires separate evidence below.
    need(set(q["metadata"]) == {f["target"] for f in manifest["candidate"]["files"]} | {boot.TARGET}, "complete target metadata required")
    for metadata in q["metadata"].values():
        need(metadata["uid"] == metadata["gid"] == 0 and metadata["mode"] == "644", "unsupported verified owner/mode")
        need(re.fullmatch(r"u:object_r:[a-z0-9_]+:s0", metadata["label"]), "invalid SELinux label")
        need(metadata["xattr_names"] == ["security.selinux"], "additional or unknown xattrs require a verified preservation method")
    if role_delivery:
        need(q["metadata"][boot.TARGET]["label"] == "u:object_r:system_file:s0",
             "fixed role boot metadata requires system_file label")
    roots = q["init_scan_roots"]
    need(q.get("init_scan_roots_complete") is True and roots and len(roots) == len(set(roots))
         and "/system/etc/init" in roots, "complete actual init scan roots required")
    if role_delivery:
        boot_prefix = "/system/etc/.x2dii-boot-" + digest[:24]
        locations = ("/blackbox/x2dii-menu-stage/" + digest[:24], boot_prefix + ".original",
                     *(boot_prefix + "-" + q["session_nonce"] + "-" + action + ".stage"
                       for action in ("activate", "restore")))
    else:
        # Retain historical v1 structural checks, never publish that route.
        locations = ("/system/.x2dii-menu-stage/" + digest[:24], "/system/etc/x2dii-menu-backup/" + digest[:24])
    for root in roots:
        need(re.fullmatch(r"/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+", root) and all(p not in (".", "..") for p in root.split("/")), "invalid init scan root")
        need(all(not (p == root.rstrip("/") or p.startswith(root.rstrip("/") + "/")) for p in locations),
             "work or backup path lies inside an init scan root")
    subject = execution_subject_sha256(manifest, q)
    need(q.get("execution_subject_sha256") == subject, "qualification execution subject mismatch")
    build = build_subject_sha256(manifest)
    runtime = runtime_subject_sha256(manifest, q)
    need(q.get("build_subject_sha256") == build, "qualification build subject mismatch")
    need(q.get("runtime_subject_sha256") == runtime, "qualification runtime subject mismatch")
    release_identity.validate_gates(q["gates"], GATE_PHASES, candidate_sha256=digest,
                                   build_subject_sha256=build, runtime_subject_sha256=runtime, boot_id=q["boot_id"],
                                   delivery_identity=q["delivery_identity"],
                                   for_publication=for_publication)
    approval = q["final_installation_approval"]
    need(approval["approved"] is True and approval["purpose"] == "final_camera_installation"
         and approval["candidate_sha256"] == digest and approval["boot_id"] == q["boot_id"], "separate final installation approval missing")
    need(approval.get("session_nonce") == q["session_nonce"], "approval session nonce mismatch")
    need(approval.get("execution_subject_sha256") == subject, "approval execution subject mismatch")
    completed_at = fixed_now if fixed_now is not None else datetime.now(timezone.utc)
    need(0 <= (completed_at - observed).total_seconds() <= 600,
         "lease expired during qualification evidence checks")


def _render_head(manifest, *, menu_validation=False):
    """Common exact-candidate, runtime, mount and metadata guards; not authority."""
    from .session_context import shell_parser
    quote = shlex.quote
    digest = manifest["candidate_sha256"]
    base = digest[:24]
    source = "/blackbox/x2dii-menu-stage/" + base
    work = "/system/.x2dii-menu-stage/" + base
    backup = "/system/etc/x2dii-menu-backup/" + base
    rc = manifest["candidate"]["rc"]
    entries = manifest["candidate"]["files"]
    session_kind = "menu_validation" if menu_validation else "install"
    session_schema = "x2dii-session-context-v3" if menu_validation else "x2dii-session-context-v2"
    session_action = (f'[ "$X2DII_SESSION_PURPOSE" = temporary_menu_validation ] || exit 32\n'
                      f'[ "$X2DII_SESSION_ACTION" = run_and_restore ] || exit 32\n'
                      f'[ "$X2DII_SESSION_CANDIDATE_SHA256" = {digest} ] || exit 32\n') if menu_validation else ""
    head = f'''#!/system/bin/sh
# Adapted from pinned peer source {REFERENCE_COMMIT}; exact X2D II candidate {digest}.
# Does not transfer files, start a service or reboot. Independent recovery remains required.
set -eu
export PATH=/system/bin:/system/xbin:/sbin
# SESSION_DATA_PARSER_BEGIN
{shell_parser()}
# SESSION_DATA_PARSER_END
[ "$#" = 2 ] || exit 32
x2dii_load_session "$1" "$2" || exit 32
[ "$X2DII_SESSION_KIND" = {session_kind} ] || exit 32
[ "$X2DII_SESSION_SCHEMA" = {session_schema} ] || exit 32
{session_action}x2dii_gui_stopped=X2DII_INITIAL_GUI_STOPPED
observer_proc="/proc/$X2DII_SESSION_OBSERVER_PID"
core_equals() {{
 core_expected=$1
 shift
 core_actual=$("$@") || return 1
 [ "$core_actual" = "$core_expected" ]
}}
fresh() {{
 now=$(date -u +%s) || return 1
 case "$now" in ''|*[!0-9]*) return 1;; esac
 [ "$now" -ge "$X2DII_SESSION_OBSERVED_EPOCH" ] && [ "$now" -le "$((X2DII_SESSION_OBSERVED_EPOCH + 600))" ]
}}
fresh || exit 32
core_equals 0 id -u && core_equals u:r:su:s0 cat /proc/self/attr/current || exit 31
core_equals "$X2DII_SESSION_BOOT_ID" cat /proc/sys/kernel/random/boot_id || exit 32
state() (
 set -f
 while :; do
  state_line=
  if IFS= read -r state_line; then
   set -- $state_line
   [ "$#" = 6 ] || return 1
   if [ "$2" = /system ]; then printf '%s %s %s\\n' "$1" "$3" "$4" || return 1; fi
  else
   state_read_status=$?
   # Preserve distinguishable read errors. Status 1 remains the shell's EOF
   # boundary only for empty data. Reject unterminated records, including
   # whitespace; this does not identify IO errors also reported as empty 1.
   [ "$state_read_status" = 1 ] || return 1
   [ -z "$state_line" ] || return 1
   break
  fi
 done < /proc/mounts
)
baseline="$X2DII_SESSION_MOUNT_DEVICE $X2DII_SESSION_MOUNT_FILESYSTEM $X2DII_SESSION_MOUNT_OPTIONS"
rw="$X2DII_SESSION_MOUNT_DEVICE $X2DII_SESSION_MOUNT_FILESYSTEM rw,${{X2DII_SESSION_MOUNT_OPTIONS#ro,}}"
core_equals "$baseline" state || exit 32
source={quote(source)}
work={quote(work)}
backup={quote(backup)}
hashok() {{ actual=$(sha256sum "$1") || return 1; [ "${{actual%% *}}" = "$2" ]; }}
regular() {{ [ -f "$1" ] && [ ! -L "$1" ] && core_equals 1 stat -c %h "$1"; }}
absent() {{ [ ! -e "$1" ] && [ ! -L "$1" ]; }}
meta() (
 set -f
 regular "$1" || return 1
 core_equals '0 0 644' stat -c '%u %g %a' "$1" || return 1
 meta_path=$1
 meta_expected=$2
 meta_label=$(ls -Zd "$1") || return 1
 set -- $meta_label
 [ "$#" = 2 ] && [ "$1" = "$meta_expected" ] && [ "$2" = "$meta_path" ]
)
quiescent() {{
 core_equals stopped getprop init.svc.camera-gui || return 1
 if pidof camera-gui >/dev/null 2>&1; then return 1; else [ "$?" = 1 ] || return 1; fi
 for maps in /proc/[0-9]*/maps; do
  [ -e "$maps" ] || continue
  [ -r "$maps" ] || return 1
  if grep -F {quote(boot.LIBRARY)} "$maps" >/dev/null; then return 1; else [ "$?" = 1 ] || return 1; fi
 done
}}
private_directory() {{ [ -d "$1" ] && [ ! -L "$1" ] && core_equals '0 0 700' stat -c '%u %g %a' "$1"; }}
optional_private_directory() {{ absent "$1" || private_directory "$1"; }}
rw_state() {{ core_equals "$rw" state; }}
start_ticks() {{
 line=$(cat "$1") || return 1
 tail=${{line##*) }}
 [ "$tail" != "$line" ] || return 1
 set -- $tail
 [ "$#" -ge 20 ] || return 1
 shift 19
 printf '%s\\n' "$1"
}}
mount_identity() {{
 core_equals "$X2DII_SESSION_BOOT_ID" cat /proc/sys/kernel/random/boot_id || return 1
 core_equals "$X2DII_SESSION_MOUNT_NAMESPACE" readlink /proc/self/ns/mnt || return 1
 core_equals "$X2DII_SESSION_INIT_MOUNT_NAMESPACE" readlink /proc/1/ns/mnt
}}
core_process() {{
 core_proc="/proc/$1"
 core_equals "$2" start_ticks "$core_proc/stat" || return 1
 core_equals "$3" readlink "$core_proc/exe" || return 1
 hashok "$core_proc/exe" "$4" || return 1
 core_equals "$5" cat "$core_proc/attr/current" || return 1
 core_equals "$6" readlink "$core_proc/ns/mnt" || return 1
 core_equals "$2" start_ticks "$core_proc/stat"
}}
core_artifact() {{
 regular "$1" || return 1
 core_equals "$3" stat -c %s "$1" || return 1
 hashok "$1" "$2"
}}
unchanged_core() {{
 # These recheck observed disk/process identity, not applied sensor state or
 # the internal capture route. Those still require independent live evidence.
 core_artifact /system/bin/camera-gui "$X2DII_SESSION_CORE_GUI_EXE_SHA256" "$X2DII_SESSION_CORE_GUI_BYTES" || return 1
 core_artifact /system/bin/camera-service "$X2DII_SESSION_CORE_SERVICE_EXE_SHA256" "$X2DII_SESSION_CORE_SERVICE_BYTES" || return 1
 core_artifact /system/etc/imx861bqr_hb722.conf "$X2DII_SESSION_CORE_SENSOR_SHA256" "$X2DII_SESSION_CORE_SENSOR_BYTES" || return 1
 core_equals "$X2DII_SESSION_CORE_SERVICE_SERVICE_STATE" getprop init.svc.camera-service || return 1
 core_equals "$X2DII_SESSION_CORE_SERVICE_PID" pidof camera-service || return 1
 core_process "$X2DII_SESSION_CORE_SERVICE_PID" "$X2DII_SESSION_CORE_SERVICE_START_TICKS" "$X2DII_SESSION_CORE_SERVICE_EXE_TARGET" "$X2DII_SESSION_CORE_SERVICE_EXE_SHA256" "$X2DII_SESSION_CORE_SERVICE_DOMAIN" "$X2DII_SESSION_CORE_SERVICE_MOUNT_NAMESPACE" || return 1
 # Session v2 rejects contradictory same-PID/path aliases. The GUI's deliberate
 # transition to stopped also stops a capture owner observed to be that GUI.
 if [ "$X2DII_SESSION_CORE_CAPTURE_PID" != "$X2DII_SESSION_CORE_GUI_PID" ] && [ "$X2DII_SESSION_CORE_CAPTURE_PID" != "$X2DII_SESSION_CORE_SERVICE_PID" ]; then
  core_artifact "$X2DII_SESSION_CORE_CAPTURE_EXE_TARGET" "$X2DII_SESSION_CORE_CAPTURE_EXE_SHA256" "$X2DII_SESSION_CORE_CAPTURE_BYTES" || return 1
  core_process "$X2DII_SESSION_CORE_CAPTURE_PID" "$X2DII_SESSION_CORE_CAPTURE_START_TICKS" "$X2DII_SESSION_CORE_CAPTURE_EXE_TARGET" "$X2DII_SESSION_CORE_CAPTURE_EXE_SHA256" "$X2DII_SESSION_CORE_CAPTURE_DOMAIN" "$X2DII_SESSION_CORE_CAPTURE_MOUNT_NAMESPACE" || return 1
 fi
}}
core_identity() {{
 unchanged_core || return 1
 if [ "$x2dii_gui_stopped" = 0 ]; then
  core_equals "$X2DII_SESSION_CORE_GUI_SERVICE_STATE" getprop init.svc.camera-gui || return 1
  core_equals "$X2DII_SESSION_CORE_GUI_PID" pidof camera-gui || return 1
  core_process "$X2DII_SESSION_CORE_GUI_PID" "$X2DII_SESSION_CORE_GUI_START_TICKS" "$X2DII_SESSION_CORE_GUI_EXE_TARGET" "$X2DII_SESSION_CORE_GUI_EXE_SHA256" "$X2DII_SESSION_CORE_GUI_DOMAIN" "$X2DII_SESSION_CORE_GUI_MOUNT_NAMESPACE" || return 1
 else
  quiescent || return 1
 fi
}}
runtime_identity() {{
 fresh || return 1
 core_equals 0 id -u && core_equals u:r:su:s0 cat /proc/self/attr/current || return 1
 mount_identity || return 1
 core_equals "$X2DII_SESSION_OBSERVER_START_TICKS" start_ticks "$observer_proc/stat" || return 1
 core_equals "$X2DII_SESSION_OBSERVER_EXE_TARGET" readlink "$observer_proc/exe" || return 1
 hashok "$observer_proc/exe" "$X2DII_SESSION_OBSERVER_EXE_SHA256" || return 1
 core_equals "$X2DII_SESSION_OBSERVER_DOMAIN" cat "$observer_proc/attr/current" || return 1
 core_equals "$X2DII_SESSION_OBSERVER_MOUNT_NAMESPACE" readlink "$observer_proc/ns/mnt" || return 1
 core_equals "$X2DII_SESSION_OBSERVER_START_TICKS" start_ticks "$observer_proc/stat" || return 1
 core_identity || return 1
 fresh
}}
write_ready() {{
 quiescent || exit 34
 rw_state || exit 32
 # Read-only service/maps queries may take time: identity/freshness comes last.
 runtime_identity || exit 32
}}
remount_ready() {{
 core_equals "$baseline" state || exit 32
 quiescent || exit 34
 runtime_identity || exit 32
}}
restore_ro() {{
 mount_identity || return 1
 current=$(state) || return 1
 if [ "$current" = "$rw" ]; then mount -o remount,ro /system || return 1; fi
 core_equals "$baseline" state
}}
locked=0
success_marker=''
finish() {{
 code=$?
 trap - EXIT HUP INT TERM
 if [ "$locked" = 1 ]; then
  # An expired observation may still restore its exact owned mount read-only.
  # A changed boot/namespace must not clean up another runtime's mount or lock.
  if mount_identity; then
   restore_ro || code=72
   if mount_identity; then rmdir /tmp/x2dii-menu-install.lock || code=73; else code=72; fi
  else code=72; fi
 fi
 [ "$code" = 0 ] || echo "X2DII_SCRIPT_FAILED:$code; GUI is not restarted; retain stage and official backup" >&2
 if [ "$code" = 0 ] && [ -n "$success_marker" ]; then
  printf '%s\\n' "$success_marker"
 fi
 exit "$code"
}}
trap finish EXIT
trap 'exit 74' HUP INT TERM
runtime_identity || exit 32
'''
    for slot in (1, 2):
        for flag in ("active", "bootable", "successful"):
            head += f'core_equals {session_variable(f"slot{slot}_{flag}")} unrd slot_{slot}.status_{flag} || exit 32\n'
    head += f'hashok /system/bin/camera-gui {GUI_SHA256}\n'
    head += '''for directory in /system /system/etc /system/lib64 /system/etc/init /tmp; do
 [ -d "$directory" ] && [ ! -L "$directory" ] || exit 33
done
umask 077
optional_private_directory /system/.x2dii-menu-stage
optional_private_directory /system/etc/x2dii-menu-backup
lock_and_stop() {
 core_equals "$baseline" state || exit 32
 runtime_identity || exit 32
 mkdir /tmp/x2dii-menu-install.lock
 locked=1
 core_equals "$baseline" state || exit 32
 runtime_identity || exit 32
 stop camera-gui
 x2dii_gui_stopped=1
 i=0
 while ! quiescent && [ "$i" -lt 50 ]; do sleep .1; i=$((i+1)); done
 quiescent || exit 34
}
'''
    return head


def _render(manifest, q=None):
    """Formal install sources only; q never contributes executable code bytes.

    Only prepare() publishes these sources, with unchanged complete release
    qualification and final-installation approval requirements.
    """
    quote = shlex.quote
    digest = manifest["candidate_sha256"]
    rc = manifest["candidate"]["rc"]
    entries = manifest["candidate"]["files"]
    head = _render_head(manifest)
    owner = f'private_directory "$work"\nprivate_directory "$backup"\nregular "$backup/owner"\ncore_equals {quote(digest)} cat "$backup/owner"\n'
    official = f'regular "$backup/camera-gui.rc.original"\nhashok "$backup/camera-gui.rc.original" {rc["before"]}\n'
    rc_label = session_variable("rc_label")
    install = head + f'regular {boot.TARGET}\nhashok {boot.TARGET} {rc["before"]}\nmeta {boot.TARGET} {rc_label}\n'
    for entry in entries:
        target, name = entry["target"], Path(entry["source"]).name
        install += f'absent {quote(target)}\nregular "$source/{name}"\nhashok "$source/{name}" {entry["sha256"]}\n'
    install += f'regular "$source/camera-gui.rc.proposed"\nhashok "$source/camera-gui.rc.proposed" {rc["after"]}\n'
    install += '''private_directory "$source"
absent "$work"
absent "$backup"
lock_and_stop
remount_ready
mount -o remount,rw /system
rw_state
write_ready
mkdir -p /system/.x2dii-menu-stage /system/etc/x2dii-menu-backup
for directory in /system/.x2dii-menu-stage /system/etc/x2dii-menu-backup; do
 private_directory "$directory"
done
write_ready
mkdir "$work" "$backup"
'''
    install += f'write_ready\ncp -p {boot.TARGET} "$backup/camera-gui.rc.original"\nwrite_ready\nchcon {rc_label} "$backup/camera-gui.rc.original"\n'
    install += official + f'meta "$backup/camera-gui.rc.original" {rc_label}\nwrite_ready\nprintf \'%s\\n\' {quote(digest)} > "$backup/owner"\nsync\n'
    for entry in entries:
        name, target = Path(entry["source"]).name, entry["target"]
        label = session_variable(LABEL_FIELDS[target])
        install += f'write_ready\ncp "$source/{name}" "$work/{name}"\nwrite_ready\nchown 0:0 "$work/{name}"\nwrite_ready\nchmod 0644 "$work/{name}"\nwrite_ready\nchcon {label} "$work/{name}"\nhashok "$work/{name}" {entry["sha256"]}\nmeta "$work/{name}" {label}\n'
    install += f'write_ready\ncp -p "$backup/camera-gui.rc.original" "$work/camera-gui.rc.proposed"\nwrite_ready\ncat "$source/camera-gui.rc.proposed" > "$work/camera-gui.rc.proposed"\nwrite_ready\ntouch -r "$backup/camera-gui.rc.original" "$work/camera-gui.rc.proposed"\nwrite_ready\nchcon {rc_label} "$work/camera-gui.rc.proposed"\nhashok "$work/camera-gui.rc.proposed" {rc["after"]}\nmeta "$work/camera-gui.rc.proposed" {rc_label}\nsync\n'
    for entry in entries:
        name, target = Path(entry["source"]).name, entry["target"]
        install += f'absent {quote(target)}\nwrite_ready\nmv -n "$work/{name}" {quote(target)}\nabsent "$work/{name}"\nhashok {quote(target)} {entry["sha256"]}\nmeta {quote(target)} {session_variable(LABEL_FIELDS[target])}\nsync\n'
    install += "restore_ro\nsuccess_marker='X2DII_FILES_INSTALLED_NOT_ACTIVATED'\n"
    activate = head + owner + official
    for entry in entries:
        activate += f'hashok {quote(entry["target"])} {entry["sha256"]}\nmeta {quote(entry["target"])} {session_variable(LABEL_FIELDS[entry["target"]])}\n'
    activate += f'hashok {boot.TARGET} {rc["before"]}\nmeta {boot.TARGET} {rc_label}\nhashok "$work/camera-gui.rc.proposed" {rc["after"]}\nmeta "$work/camera-gui.rc.proposed" {rc_label}\nlock_and_stop\nremount_ready\nmount -o remount,rw /system\nrw_state\nhashok {boot.TARGET} {rc["before"]}\nwrite_ready\nmv -f "$work/camera-gui.rc.proposed" {boot.TARGET}\nsync\nhashok {boot.TARGET} {rc["after"]}\nmeta {boot.TARGET} {rc_label}\nrestore_ro\nsuccess_marker=X2DII_BOOT_CONFIG_ACTIVATED_GUI_LEFT_STOPPED\n'
    restore = head + owner + official
    restore += f'meta {boot.TARGET} {rc_label}\nhashok {boot.TARGET} {rc["after"]} || hashok {boot.TARGET} {rc["before"]}\nrestore_file="$work/camera-gui.rc.restore.$$"\nabsent "$restore_file"\nlock_and_stop\nremount_ready\nmount -o remount,rw /system\nrw_state\nwrite_ready\ncp -p "$backup/camera-gui.rc.original" "$restore_file"\nwrite_ready\nchcon {rc_label} "$restore_file"\nhashok "$restore_file" {rc["before"]}\nmeta "$restore_file" {rc_label}\nsync\nwrite_ready\nmv -f "$restore_file" {boot.TARGET}\nsync\nhashok {boot.TARGET} {rc["before"]}\nmeta {boot.TARGET} {rc_label}\n'
    for entry in entries:
        target = quote(entry["target"])
        restore += f'if ! absent {target}; then\n hashok {target} {entry["sha256"]}\n meta {target} {session_variable(LABEL_FIELDS[entry["target"]])}\n write_ready\n rm {target}\n sync\nfi\n'
    restore += "restore_ro\nsuccess_marker='X2DII_OFFICIAL_RC_RESTORED_OWNED_FILES_REMOVED'\n"
    return {name: source.replace("X2DII_INITIAL_GUI_STOPPED", "0" if name == "install-files.sh" else "1")
            for name, source in {"install-files.sh": install, "activate-boot.sh": activate,
                                 "restore-boot.sh": restore}.items()}


def _render_maintenance_head(manifest):
    """Read-only system guards for the hbl supervisor, never a su installer.

    Keep this role separate from the formal legacy file scripts. The exhaustive
    maps observation remains an unresolved removal gate, separate from restoring
    the stock GUI. Inaccessible processes are not treated as absent processes.
    """
    from .session_context import shell_parser
    digest = manifest["candidate_sha256"]
    head = f'''#!/system/bin/sh
# LOCAL SOURCE ONLY: maintenance-domain lifecycle for exact candidate {digest}.
# Reads preplaced extension files; never installs, removes, relabels or remounts.
set -eu
export PATH=/system/bin:/system/xbin:/sbin
# SESSION_DATA_PARSER_BEGIN
{shell_parser()}
# SESSION_DATA_PARSER_END
[ "$#" = 2 ] || exit 32
x2dii_load_session "$1" "$2" || exit 32
[ "$X2DII_SESSION_KIND" = menu_validation ] || exit 32
[ "$X2DII_SESSION_SCHEMA" = x2dii-session-context-v3 ] || exit 32
[ "$X2DII_SESSION_PURPOSE" = temporary_menu_validation ] || exit 32
[ "$X2DII_SESSION_ACTION" = run_and_restore ] || exit 32
[ "$X2DII_SESSION_CANDIDATE_SHA256" = {digest} ] || exit 32
core_equals() {{
 core_expected=$1
 shift
 core_actual=$("$@") || return 1
 [ "$core_actual" = "$core_expected" ]
}}
core_equals 0 id -u && core_equals u:r:hbl_camera_service:s0 cat /proc/self/attr/current || exit 31
[ "$X2DII_SESSION_OBSERVER_DOMAIN" = u:r:hbl_camera_service:s0 ] || exit 31
observer_proc="/proc/$X2DII_SESSION_OBSERVER_PID"
x2dii_gui_stopped=0
locked=0
fresh() {{
 now=$(date -u +%s) || return 1
 case "$now" in ''|*[!0-9]*) return 1;; esac
 [ "$now" -ge "$X2DII_SESSION_OBSERVED_EPOCH" ] && [ "$now" -le "$((X2DII_SESSION_OBSERVED_EPOCH + 600))" ]
}}
state() (
 set -f
 while :; do
  state_line=
  if IFS= read -r state_line; then
   set -- $state_line
   [ "$#" = 6 ] || return 1
   if [ "$2" = /system ]; then printf '%s %s %s\\n' "$1" "$3" "$4" || return 1; fi
  else
   state_read_status=$?
   [ "$state_read_status" = 1 ] && [ -z "$state_line" ] || return 1
   break
  fi
 done < /proc/mounts
)
baseline="$X2DII_SESSION_MOUNT_DEVICE $X2DII_SESSION_MOUNT_FILESYSTEM $X2DII_SESSION_MOUNT_OPTIONS"
hashok() {{ actual=$(sha256sum "$1") || return 1; [ "${{actual%% *}}" = "$2" ]; }}
regular() {{ [ -f "$1" ] && [ ! -L "$1" ] && core_equals 1 stat -c %h "$1"; }}
absent() {{ [ ! -e "$1" ] && [ ! -L "$1" ]; }}
meta() (
 set -f
 regular "$1" || return 1
 core_equals '0 0 644' stat -c '%u %g %a' "$1" || return 1
 meta_path=$1
 meta_expected=$2
 meta_label=$(ls -Zd "$1") || return 1
 set -- $meta_label
 [ "$#" = 2 ] && [ "$1" = "$meta_expected" ] && [ "$2" = "$meta_path" ]
)
private_directory() {{ [ -d "$1" ] && [ ! -L "$1" ] && core_equals '0 0 700' stat -c '%u %g %a' "$1"; }}
start_ticks() {{
 line=$(cat "$1") || return 1
 tail=${{line##*) }}
 [ "$tail" != "$line" ] || return 1
 set -- $tail
 [ "$#" -ge 20 ] || return 1
 shift 19
 printf '%s\\n' "$1"
}}
mount_identity() {{
 core_equals "$X2DII_SESSION_BOOT_ID" cat /proc/sys/kernel/random/boot_id || return 1
 core_equals "$X2DII_SESSION_MOUNT_NAMESPACE" readlink /proc/self/ns/mnt || return 1
 core_equals "$X2DII_SESSION_INIT_MOUNT_NAMESPACE" readlink /proc/1/ns/mnt
}}
readonly_system() {{ mount_identity && core_equals "$baseline" state; }}
core_process() {{
 core_proc="/proc/$1"
 core_equals "$2" start_ticks "$core_proc/stat" || return 1
 core_equals "$3" readlink "$core_proc/exe" || return 1
 hashok "$core_proc/exe" "$4" || return 1
 core_equals "$5" cat "$core_proc/attr/current" || return 1
 core_equals "$6" readlink "$core_proc/ns/mnt" || return 1
 core_equals "$2" start_ticks "$core_proc/stat"
}}
core_artifact() {{
 regular "$1" || return 1
 core_equals "$3" stat -c %s "$1" || return 1
 hashok "$1" "$2"
}}
unchanged_core() {{
 core_artifact /system/bin/camera-gui "$X2DII_SESSION_CORE_GUI_EXE_SHA256" "$X2DII_SESSION_CORE_GUI_BYTES" || return 1
 core_artifact /system/bin/camera-service "$X2DII_SESSION_CORE_SERVICE_EXE_SHA256" "$X2DII_SESSION_CORE_SERVICE_BYTES" || return 1
 core_artifact /system/etc/imx861bqr_hb722.conf "$X2DII_SESSION_CORE_SENSOR_SHA256" "$X2DII_SESSION_CORE_SENSOR_BYTES" || return 1
 core_equals "$X2DII_SESSION_CORE_SERVICE_SERVICE_STATE" getprop init.svc.camera-service || return 1
 core_equals "$X2DII_SESSION_CORE_SERVICE_PID" pidof camera-service || return 1
 core_process "$X2DII_SESSION_CORE_SERVICE_PID" "$X2DII_SESSION_CORE_SERVICE_START_TICKS" "$X2DII_SESSION_CORE_SERVICE_EXE_TARGET" "$X2DII_SESSION_CORE_SERVICE_EXE_SHA256" "$X2DII_SESSION_CORE_SERVICE_DOMAIN" "$X2DII_SESSION_CORE_SERVICE_MOUNT_NAMESPACE" || return 1
 if [ "$X2DII_SESSION_CORE_CAPTURE_PID" != "$X2DII_SESSION_CORE_GUI_PID" ] && [ "$X2DII_SESSION_CORE_CAPTURE_PID" != "$X2DII_SESSION_CORE_SERVICE_PID" ]; then
  core_artifact "$X2DII_SESSION_CORE_CAPTURE_EXE_TARGET" "$X2DII_SESSION_CORE_CAPTURE_EXE_SHA256" "$X2DII_SESSION_CORE_CAPTURE_BYTES" || return 1
  core_process "$X2DII_SESSION_CORE_CAPTURE_PID" "$X2DII_SESSION_CORE_CAPTURE_START_TICKS" "$X2DII_SESSION_CORE_CAPTURE_EXE_TARGET" "$X2DII_SESSION_CORE_CAPTURE_EXE_SHA256" "$X2DII_SESSION_CORE_CAPTURE_DOMAIN" "$X2DII_SESSION_CORE_CAPTURE_MOUNT_NAMESPACE" || return 1
 fi
}}
no_extension_mappings() {{
 # Enumerate PID directories, not */maps. Direct query failure (including a
 # disappearance race) is incomplete observation, never proof of absence.
 for maps_proc in /proc/[0-9]*; do
  maps="$maps_proc/maps"
  if grep -F {shlex.quote(boot.LIBRARY)} "$maps" >/dev/null; then return 1
  else
   maps_result=$?
   if [ "$maps_result" != 1 ]; then
    printf 'X2DII_MAPS_OBSERVATION_INCOMPLETE:%s\\n' "$maps" >&2
    return 2
   fi
  fi
 done
}}
quiescent() {{
 core_equals stopped getprop init.svc.camera-gui || return 1
 if pidof camera-gui >/dev/null 2>&1; then return 1; else [ "$?" = 1 ] || return 1; fi
 # This only proves GUI quiescence. Global mapping evidence is separate and
 # cannot be used to deny stock recovery or infer permission to remove files.
 return 0
}}
core_identity() {{
 unchanged_core || return 1
 if [ "$x2dii_gui_stopped" = 0 ]; then
  core_equals "$X2DII_SESSION_CORE_GUI_SERVICE_STATE" getprop init.svc.camera-gui || return 1
  core_equals "$X2DII_SESSION_CORE_GUI_PID" pidof camera-gui || return 1
  core_process "$X2DII_SESSION_CORE_GUI_PID" "$X2DII_SESSION_CORE_GUI_START_TICKS" "$X2DII_SESSION_CORE_GUI_EXE_TARGET" "$X2DII_SESSION_CORE_GUI_EXE_SHA256" "$X2DII_SESSION_CORE_GUI_DOMAIN" "$X2DII_SESSION_CORE_GUI_MOUNT_NAMESPACE" || return 1
 else quiescent || return 1; fi
}}
runtime_identity() {{
 fresh || return 1
 core_equals 0 id -u && core_equals u:r:hbl_camera_service:s0 cat /proc/self/attr/current || return 1
 readonly_system || return 1
 core_process "$X2DII_SESSION_OBSERVER_PID" "$X2DII_SESSION_OBSERVER_START_TICKS" "$X2DII_SESSION_OBSERVER_EXE_TARGET" "$X2DII_SESSION_OBSERVER_EXE_SHA256" "$X2DII_SESSION_OBSERVER_DOMAIN" "$X2DII_SESSION_OBSERVER_MOUNT_NAMESPACE" || return 1
 core_identity || return 1
 fresh
}}
runtime_identity || exit 32
'''
    for slot in (1, 2):
        for flag in ("active", "bootable", "successful"):
            head += f'core_equals {session_variable(f"slot{slot}_{flag}")} unrd slot_{slot}.status_{flag} || exit 32\n'
    head += f'hashok /system/bin/camera-gui {GUI_SHA256} || exit 33\n'
    head += '''for directory in /system /system/etc /system/lib64 /system/etc/init /tmp; do
 [ -d "$directory" ] && [ ! -L "$directory" ] || exit 33
done
umask 077
lock_and_stop() {
 runtime_identity && preplaced_files || exit 32
 mkdir /tmp/x2dii-menu-install.lock
 locked=1
 runtime_identity && preplaced_files || exit 32
 recover_needed=1
 stop camera-gui
 x2dii_gui_stopped=1
 i=0
 while ! quiescent && [ "$i" -lt 50 ]; do sleep .1; i=$((i+1)); done
 quiescent || exit 34
}
'''
    return head


def render_temporary_menu_session(manifest):
    """Pure local source, not a publisher, executor or installation approval.

    The separate v3 menu_validation purpose/action cannot activate boot config.
    This branch is deliberately not included in prepare() or delivery members.
    """
    quote = shlex.quote
    entries = manifest["candidate"]["files"]
    digest = manifest["candidate_sha256"]
    rc = manifest["candidate"]["rc"]
    source = _render_maintenance_head(manifest)
    source += f'''# A v3 data file describes a separately approved action; it grants no authority.
# No publication or camera executor currently accepts this local-only source.
hashok {boot.TARGET} {rc['before']} || exit 33
meta {boot.TARGET} "$X2DII_SESSION_RC_LABEL" || exit 33
transaction="/tmp/x2dii-menu-validation-$X2DII_SESSION_SESSION_NONCE"
absent "$transaction" || exit 33
absent /tmp/x2dii-menu.attempt || exit 33
absent /blackbox/x2dii-menu.disable || exit 33
preplaced_files() {{
'''
    for entry in entries:
        target = quote(entry["target"])
        source += f' meta {target} {session_variable(LABEL_FIELDS[entry["target"]])} && hashok {target} {entry["sha256"]} || return 1\n'
    source += '''}
preplaced_files || exit 33
'''
    source += '''child_pid=''
child_recorded=0
child_birth=''
child_ticks=''
recover_needed=0
stock_environment_verified=0
process_birth() {
 birth_line=$(cat "/proc/$1/stat") || return 1
 birth_tail=${birth_line##*) }
 [ "$birth_tail" != "$birth_line" ] || return 1
 set -- $birth_tail
 [ "$#" -ge 20 ] || return 1
 birth_parent=$2
 shift 19
 x2dii_sc_scalar ticks "$1" && x2dii_sc_scalar pid "$birth_parent" || return 1
 printf '%s:%s\\n' "$1" "$birth_parent"
}
freeze_child_birth() {
 observed_birth=$(process_birth "$child_pid") || return 1
 [ "${observed_birth#*:}" = "$$" ] || return 1
 if [ -n "$child_birth" ]; then [ "$observed_birth" = "$child_birth" ]; return; fi
 child_birth=$observed_birth
 child_ticks=${child_birth%%:*}
}
child_owned() {
 [ "$child_recorded" = 1 ] || return 1
 mount_identity || return 1
 core_equals "$child_birth" process_birth "$child_pid" || return 1
 core_process "$child_pid" "$child_ticks" "$child_exe" "$child_hash" "$child_domain" "$child_namespace"
}
record_child() {
 [ -n "$child_birth" ] || return 1
 core_equals "$child_birth" process_birth "$child_pid" || return 1
 child_exe=$(readlink "/proc/$child_pid/exe") || return 1
 child_hash_line=$(sha256sum "/proc/$child_pid/exe") || return 1
 child_hash=${child_hash_line%% *}
 child_domain=$(cat "/proc/$child_pid/attr/current") || return 1
 child_namespace=$(readlink "/proc/$child_pid/ns/mnt") || return 1
 x2dii_sc_scalar ticks "$child_ticks" && x2dii_sc_scalar executable "$child_exe" &&
 x2dii_sc_scalar hex64 "$child_hash" && x2dii_sc_scalar domain "$child_domain" &&
 x2dii_sc_scalar namespace "$child_namespace" || return 1
 # Record the observed domain; even a maintenance launch must prove its child.
 core_process "$child_pid" "$child_ticks" "$child_exe" "$child_hash" "$child_domain" "$child_namespace" || return 1
 core_equals "$child_birth" process_birth "$child_pid" || return 1
 child_recorded=1
 printf 'pid=%s\nstart_ticks=%s\nexe=%s\nsha256=%s\ndomain=%s\nnamespace=%s\n' \\
  "$child_pid" "$child_ticks" "$child_exe" "$child_hash" "$child_domain" "$child_namespace" > "$transaction/child.identity"
}
child_exited() {
 mount_identity && absent "/proc/$child_pid" || return 1
 wait "$child_pid" 2>/dev/null || :
 child_pid=''
}
stop_owned_child() {
 [ -n "$child_pid" ] || return 0
 if child_exited; then return 0; fi
 # Exit can race the final identity read or signal syscall. Only verified
 # absence resolves that race; a still-live unknown/reused PID stays refused.
 if ! child_owned; then child_exited || return 1; return 0; fi
 if ! kill -TERM "$child_pid"; then child_exited || return 1; return 0; fi
 stop_wait=0
 while ! absent "/proc/$child_pid" && [ "$stop_wait" -lt 30 ]; do
  if ! child_owned; then absent "/proc/$child_pid" || return 1; break; fi
  sleep .1 || return 1
  stop_wait=$((stop_wait+1))
 done
 if ! absent "/proc/$child_pid"; then
  if ! child_owned; then child_exited || return 1; return 0; fi
  if ! kill -KILL "$child_pid"; then child_exited || return 1; return 0; fi
  stop_wait=0
  while ! absent "/proc/$child_pid" && [ "$stop_wait" -lt 20 ]; do
   if ! child_owned; then absent "/proc/$child_pid" || return 1; break; fi
   sleep .1 || return 1
   stop_wait=$((stop_wait+1))
  done
 fi
 child_exited
}
no_extension_environment() {
 stock_environment=$(tr '\\000' '\\n' < "/proc/$1/environ") || return 1
 case "
$stock_environment
" in *'
LD_PRELOAD='*|*'
X2DII_MENU_EXTENSION='*) return 1;; esac
}
original_gui_running() {
 core_equals running getprop init.svc.camera-gui || return 1
 original_pid=$(pidof camera-gui) || return 1
 x2dii_sc_scalar pid "$original_pid" || return 1
 original_ticks=$(start_ticks "/proc/$original_pid/stat") || return 1
 core_process "$original_pid" "$original_ticks" "$X2DII_SESSION_CORE_GUI_EXE_TARGET" "$X2DII_SESSION_CORE_GUI_EXE_SHA256" "$X2DII_SESSION_CORE_GUI_DOMAIN" "$X2DII_SESSION_CORE_GUI_MOUNT_NAMESPACE" || return 1
 no_extension_environment "$original_pid" || return 1
 if grep -F /system/lib64/libx2dii_menu.so "/proc/$original_pid/maps" >/dev/null; then return 1
 else [ "$?" = 1 ] || return 1; fi
}
'''
    source += '''temporary_finish() {
 result=$?
 trap - EXIT HUP INT TERM
 # Refuse to kill a reused/unknown PID, unlink mapped files or claim recovery.
 recovered=1
 if [ "$locked" = 1 ]; then
  if mount_identity && stop_owned_child; then
   if [ "$recover_needed" = 1 ]; then
    # Files belong to a separate su transaction. Never unlink or relabel them.
'''
    source += f'''     if [ "$stock_environment_verified" = 1 ] && hashok {boot.TARGET} {rc['before']} && meta {boot.TARGET} "$X2DII_SESSION_RC_LABEL" && readonly_system; then
      if ! original_gui_running; then
       if quiescent; then
        if start camera-gui; then :; else recovered=0; fi
       else recovered=0; fi
      fi
      restore_wait=0
      while ! original_gui_running && [ "$restore_wait" -lt 50 ]; do sleep .1; restore_wait=$((restore_wait+1)); done
      original_gui_running || recovered=0
      unchanged_core || recovered=0
     else recovered=0; fi
   fi
  else recovered=0; fi
  # This domain never changes mount state, including during error recovery.
  readonly_system || recovered=0
  if [ "$recovered" = 1 ]; then rmdir /tmp/x2dii-menu-install.lock || recovered=0; fi
 fi
 if [ "$recovered" != 1 ]; then
  printf '%s\\n' X2DII_TEMPORARY_RECOVERY_FAILED_RETAIN_ATTEMPT_AND_FILES >&2
  exit 79
 fi
 if [ "$recover_needed" = 1 ]; then
  printf '%s\\n' X2DII_ORIGINAL_GUI_RESTORED_EXTENSION_FILES_RETAINED_PENDING_SU_REMOVAL
  # Restoring the stock GUI is not proof that no other process maps a file.
  # This source cannot authorize su removal, even when the scan was readable.
  if no_extension_mappings; then
   printf '%s\\n' X2DII_VISIBLE_PROCESS_MAPPINGS_OBSERVED_CLEAR_COVERAGE_UNVERIFIED_NOT_REMOVAL_AUTHORITY
  else
   mapping_result=$?
   if [ "$mapping_result" = 1 ]; then
    printf '%s\\n' X2DII_OTHER_PROCESS_MAPPING_PRESENT_FILES_RETAINED_NO_REMOVAL_AUTHORITY >&2
   else
    printf '%s\\n' X2DII_ALL_PROCESS_MAPPINGS_UNVERIFIED_FILES_RETAINED_NO_REMOVAL_AUTHORITY >&2
   fi
   [ "$result" != 0 ] || result=80
  fi
 fi
 if [ "$result" != 0 ]; then
  printf 'X2DII_TEMPORARY_FAILED:%s; original GUI recovery verified if stopped; extension files retained pending su removal\\n' "$result" >&2
  exit "$result"
 fi
 exit 0
}}
trap temporary_finish EXIT
trap 'exit 74' HUP INT TERM
original_gui_running || exit 34
stock_environment_verified=1
runtime_identity || exit 32
mkdir "$transaction"
private_directory "$transaction" || exit 33
# The attempt survives success and failure: never auto-retry the same session.
printf 'candidate=%s\\nnonce=%s\\npurpose=temporary_menu_validation\\naction=run_and_restore\\n' {digest} "$X2DII_SESSION_SESSION_NONCE" > "$transaction/attempt"
lock_and_stop
'''
    source += f'''preplaced_files || exit 33
runtime_identity || exit 32
hashok {boot.TARGET} {rc['before']} || exit 33
absent /tmp/x2dii-menu.attempt || exit 33
absent /blackbox/x2dii-menu.disable || exit 33
# A direct child, never an init restart that might reuse already-parsed rc.
env X2DII_MENU_EXTENSION=1 LD_PRELOAD={boot.LIBRARY} XDG_RUNTIME_DIR=/tmp XDG_CACHE_HOME=/data QT_QPA_FONTDIR=/system/lib64/qt/lib/fonts /system/bin/camera-gui -platform wayland-egl --fullscreen > "$transaction/gui.log" 2>&1 < /dev/null &
child_pid=$!
launch_wait=0
while ! freeze_child_birth && [ "$launch_wait" -lt 50 ]; do sleep .1; launch_wait=$((launch_wait+1)); done
[ -n "$child_birth" ] || exit 75
launch_wait=0
while [ "$launch_wait" -lt 50 ]; do
 if record_child && [ "$child_exe" = "$X2DII_SESSION_CORE_GUI_EXE_TARGET" ]; then break; fi
 sleep .1
 launch_wait=$((launch_wait+1))
done
[ "$child_recorded" = 1 ] || exit 75
[ "$child_exe" = "$X2DII_SESSION_CORE_GUI_EXE_TARGET" ] && [ "$child_hash" = "$X2DII_SESSION_CORE_GUI_EXE_SHA256" ] || exit 75
[ "$child_domain" = "$X2DII_SESSION_CORE_GUI_DOMAIN" ] && [ "$child_namespace" = "$X2DII_SESSION_CORE_GUI_MOUNT_NAMESPACE" ] || exit 76
child_owned || exit 75
core_equals stopped getprop init.svc.camera-gui || exit 75
core_equals "$child_pid" pidof camera-gui || exit 75
grep -F {boot.LIBRARY} "/proc/$child_pid/maps" >/dev/null || exit 75
fresh || exit 78
printf '%s\\n' X2DII_TEMPORARY_CHILD_LOADED_NOT_FEATURE_VERIFIED
# At most 120 polling iterations; no automatic relaunch or persistent boot edit.
validation_started=$(date -u +%s) || exit 78
x2dii_sc_scalar epoch "$validation_started" || exit 78
[ "$validation_started" -ge "$X2DII_SESSION_OBSERVED_EPOCH" ] && [ "$validation_started" -le "$((X2DII_SESSION_OBSERVED_EPOCH+600))" ] || exit 78
validation_poll=0
while [ "$validation_poll" -lt 120 ]; do
 validation_now=$(date -u +%s) || exit 78
 x2dii_sc_scalar epoch "$validation_now" || exit 78
 [ "$validation_now" -ge "$validation_started" ] && [ "$validation_now" -lt "$((validation_started+120))" ] || exit 78
 [ "$validation_now" -ge "$X2DII_SESSION_OBSERVED_EPOCH" ] && [ "$validation_now" -le "$((X2DII_SESSION_OBSERVED_EPOCH+600))" ] || exit 78
 child_owned || exit 75
 core_equals stopped getprop init.svc.camera-gui || exit 75
 core_equals "$child_pid" pidof camera-gui || exit 75
 mount_identity && core_equals "$baseline" state || exit 32
 if ! absent "$transaction/stop"; then
  regular "$transaction/stop" && core_equals stop cat "$transaction/stop" || exit 77
  break
 fi
 sleep 1
 validation_poll=$((validation_poll+1))
done
# Timeout is a failed observation, even if return to stock succeeds.
[ "$validation_poll" -lt 120 ] || exit 78
'''
    return source


def prepare(destination, qualification=None):
    manifest = inventory()
    scripts = {}
    assembled = None
    if qualification is not None:
        # Freeze the caller's object, not its authority: external evidence and
        # approval still need independent review and all existing admission checks.
        qualification = deepcopy(qualification)
        validate_qualification(manifest, qualification, for_publication=True)
        # The source path is connected; only the complete current qualification
        # above can authorize publication. Local source/tests are not that proof.
        scripts = render_role_programs(manifest)
        need(release_identity.build_subject(manifest["candidate"], scripts,
                 source_hash=manifest["renderer_source_sha256"]) == qualification["build_subject_sha256"],
             "rendered delivery programs differ from the approved build")
        shell = shutil.which("sh") or "C:/Program Files/Git/bin/sh.exe"
        need(Path(shell).is_file(), "local shell syntax checker unavailable")
        for name, source in scripts.items():
            checked = subprocess.run([shell, "-n"], input=source.encode("ascii"), capture_output=True, timeout=10)
            need(checked.returncode == 0, "shell syntax failure: " + name)
        from .delivery_files import assemble_role_delivery
        assembled = assemble_role_delivery(manifest["candidate"], manifest["candidate_sha256"], scripts)
        need(assembled["delivery_identity"] == qualification["delivery_identity"],
             "assembled delivery differs from the approved package identity")
        manifest["scripts_emitted"] = True
        manifest["status"] = "QUALIFIED_DELIVERY_NOT_EXECUTED"
        manifest["package_created"] = True
        manifest["installable"] = True
        manifest["delivery_identity"] = assembled["delivery_identity"]
        manifest["delivery_members"] = assembled["content_manifest"]
        manifest["qualification_sha256"] = sha(canonical(qualification))
        manifest["execution_subject_sha256"] = qualification["execution_subject_sha256"]
        manifest["build_subject_sha256"] = qualification["build_subject_sha256"]
        manifest["runtime_subject_sha256"] = qualification["runtime_subject_sha256"]
        manifest["session_data_sha256"] = sha(session_data(manifest, qualification))
        manifest["required_gates"] = {gate: "PASS" for gate in GATES}
        manifest["final_installation_approval"] = "SUPPLIED_CURRENT_BOUND_EVIDENCE_NOT_EXECUTED"
        manifest["role_deployment"].update(status="QUALIFIED_DELIVERY_NOT_EXECUTED", remaining=[])
    outputs = {name: text.encode("ascii") for name, text in scripts.items()}
    manifest["script_hashes"] = {name: sha(raw) for name, raw in outputs.items()}
    if qualification is not None:
        outputs["session-context.data"] = session_data(manifest, qualification)
        outputs[DELIVERY_NAME] = assembled["archive_bytes"]
    outputs["peer-install-source.json"] = (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode()
    destination = guard_output(destination)
    if not scripts:
        from .delivery_content import MEMBER_NAMES, ROLE_MEMBER_NAMES
        for name in (*dict.fromkeys((*MEMBER_NAMES, *ROLE_MEMBER_NAMES)), DELIVERY_NAME, "members.json", "session-context.data"):
            need(not guard_output(destination / name).exists(), "unqualified output already contains delivery content or runnable script: " + name)
    else:
        # Assembly/syntax checks can consume time; recheck current build inputs,
        # unchanged evidence and the original (not renewed) lease before output.
        validate_qualification(manifest, qualification, for_publication=True)
    from .output_guard import publish_output_set
    recheck = (lambda: validate_qualification(manifest, qualification, for_publication=True)) if scripts else None
    publish_output_set(destination, outputs, commit_name="peer-install-source.json", before_commit=recheck)
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/peer-install-source")
    parser.add_argument("--qualification", type=Path)
    args = parser.parse_args()
    result = prepare(args.output, json.loads(args.qualification.read_text()) if args.qualification else None)
    print(json.dumps({key: result[key] for key in ("status", "candidate_sha256", "scripts_emitted", "installable")}))
