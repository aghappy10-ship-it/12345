"""Read-only recovery observations through an already-held Session.

No connection, USB window, file change, capture, service action or authorization.
Retained Session raw-byte references are copied, not reopened/authenticated.
"""
from copy import deepcopy
from datetime import datetime, timezone
import re
import secrets
import time

from . import boot_config, menu_boot_boundary, prepare_peer_recovery as recovery
from .menu_boot_transport import _identity
from .menu_maintenance_boundary import _candidate
from .menu_observation_readout import _Readout, _domain, _epoch, _external, _json, _line, _sha
from .regression_manifest import strict_json
from .runtime_observation import COMPONENT_PATHS, ENVIRONMENT_FIELDS, normalize_observation
from .temporary_menu_files import render_preplacement

SCOPE = "menu-recovery-readonly"
SYNTHETIC_SCOPE = "synthetic-menu-recovery-readonly"
EXTERNAL_KINDS = ("su_identity", "official_recovery", "init_scan_roots")


def _need(ok, reason):
    if not ok:
        raise ValueError("recovery readout: " + reason)


def _read(reads, name, command, maximum=4096):
    text, _ = reads.read(name, command, maximum=maximum)
    return _line(text)


def _hash(reads, name, path):
    value = _read(reads, name, "sha256sum " + path)
    match = re.fullmatch(r"([0-9a-f]{64})  " + re.escape(path), value)
    _need(match is not None, "hash output is not bound to requested path")
    return match[1]


def _listing(reads, name, command):
    text, _ = reads.read(name, command, maximum=262144)
    _need(text.endswith("\n") and "\0" not in text, "complete newline-terminated enumeration required")
    return text.splitlines()


def _process(reads, phase, role):
    reads.process(phase, role)
    value = reads.processes[(phase, role)]
    command = "sha256sum /proc/" + str(value["pid"]) + "/exe"
    row = next(row for row in reversed(reads.queries) if row["command"] == command)
    _need(_line(row["stdout"]) == value["exe_sha256"] + "  " + command[10:],
          "process hash is not bound to requested executable")
    recovery._process(value)
    return deepcopy(value)


def _snapshot(reads, phase, manifest, external, backup_identity):
    def read(name, command, maximum=4096):
        return _read(reads, phase + "-" + name, command, maximum)

    timestamp = read("time", "date -u +%s")
    _need(re.fullmatch(r"[1-9][0-9]{0,9}", timestamp) and
          abs(int(timestamp) - _epoch(reads.clock)) <= 8, "camera and collection clocks differ")
    uid = read("uid", "id -u")
    # Decode the original reply exactly once. Generic line stripping first
    # would silently accept mixed/repeated kernel terminators such as NUL+LF.
    domain, _ = reads.read(phase + "-domain", "cat /proc/self/attr/current")
    _need(uid == "0" and _domain(domain) == "u:r:hbl_camera_service:s0",
          "current maintenance identity differs")
    context = {"boot_id": read("boot", "cat /proc/sys/kernel/random/boot_id"),
        "mount_namespace": read("namespace", "readlink /proc/self/ns/mnt"),
        "init_mount_namespace": read("init-namespace", "readlink /proc/1/ns/mnt")}
    _need(all(item["boot_id"] == context["boot_id"] for item in external.values()), "external boot differs")
    if "su_identity" in external:
        _need(external["su_identity"]["mount_namespace"] == context["mount_namespace"], "su namespace differs")
    flags = {f"slot_{slot}.status_{flag}": read(f"slot-{slot}-{flag}", f"unrd slot_{slot}.status_{flag}")
             for slot in (1, 2) for flag in ("active", "bootable", "successful")}
    _need(all(value in ("0", "1") for value in flags.values()), "individual slot flag is not a bare bit")
    active = [slot for slot in ("slot_1", "slot_2") if flags[slot + ".status_active"] == "1"]
    _need(len(active) == 1, "one active slot required")
    context.update(slot_readback=flags, active_slot=active[0])
    mounts = read("mounts", "cat /proc/mounts", 65536).splitlines()
    rows = [line.split() for line in mounts]
    _need(rows and all(len(row) == 6 for row in rows), "complete mount rows required")
    system = [row for row in rows if row[1] == "/system"]
    _need(len(system) == 1, "one system mount required")
    context["system_mount"] = dict(zip(("device", "filesystem", "options"),
                                       (system[0][0], system[0][2], system[0][3])))
    context["observer"] = _process(reads, phase, "observer")
    _need(context["observer"]["exe_target"] == "/system/bin/camera-test", "maintenance observer differs")

    # Complete successful directory enumerations establish presence/absence;
    # a failed stat/test or failed listing is never projected as absent.
    directory_names = {}
    for parent in ("/system", "/system/etc", "/system/etc/init", "/system/lib64"):
        _need(read("plain-parent", f"[ -d {parent} ] && [ ! -L {parent} ]") == "", "parent is not plain")
    for parent in ("/system/etc", "/system/lib64"):
        names = _listing(reads, phase + "-directory", "ls -a " + parent)
        _need(names and "." in names and ".." in names and len(names) == len(set(names)) and
              all(name and "/" not in name and all(32 <= ord(c) < 127 for c in name) for name in names),
              "complete unambiguous directory enumeration required")
        directory_names[parent] = names

    backup = "/system/etc/.x2dii-boot-" + manifest["candidate_sha256"][:24] + ".original"
    metadata = {}
    for role, path in (("rc", recovery.RC), ("backup", backup)):
        _need(read(role + "-plain", f"[ -f {path} ] && [ ! -L {path} ]") == "", "plain rc/backup required")
        identity = read(role + "-identity", "stat -c '%d:%i:%f:%h:%s:%u:%g' " + path)
        size = len(boot_config.STOCK.read_bytes()) if role == "backup" else None
        if role == "backup":
            _need(_identity(identity, size) and identity == backup_identity, "current backup ownership differs")
        else:
            _need(re.fullmatch(r"(?:0|[1-9][0-9]{0,19}):[1-9][0-9]{0,19}:81a4:1:[1-9][0-9]{0,19}:0:0", identity),
                  "current rc inode identity differs")
        digest = _hash(reads, phase + "-" + role + "-hash", path)
        meta = reads.file_metadata(phase, role, path)
        if role == "backup":
            _need(digest == manifest["candidate"]["rc"]["before"], "current backup hash differs")
            context.update(backup_identity=identity, backup_sha256=digest, backup_metadata={"official": meta})
        else:
            original = boot_config.STOCK.read_bytes()
            known_sizes = {manifest["candidate"]["rc"]["before"]: len(original),
                           manifest["candidate"]["rc"]["after"]: len(boot_config.activate(original))}
            _need(digest in known_sizes and _identity(identity, known_sizes[digest]),
                  "current rc hash and inode length differ from a known rc")
            context.update(rc_identity=identity, rc_sha256=digest)
            metadata[path] = meta
    presence = {}
    for index, target in enumerate(recovery.TARGETS):
        parent, name = target.rsplit("/", 1)
        presence[target] = name in directory_names[parent]
        if presence[target]:
            label = read("payload-label-" + str(index), "ls -Zd " + target).split()
            _need(len(label) == 2 and label[1] == target and
                  re.fullmatch(r"u:object_r:[a-z0-9_]{1,96}:s0", label[0]), "payload label is unobserved")
            metadata[target] = {"label": label[0]}
        else:
            metadata[target] = {"state": "absent", "label": None}
    context.update(metadata=metadata, payload_presence=presence)

    table = _listing(reads, phase + "-process-table", "ps -A -o PID,NAME")
    _need(table and table[0].split() == ["PID", "NAME"], "complete process table header required")
    rows = [row.split() for row in table[1:]]
    _need(rows and all(len(row) == 2 and re.fullmatch(r"[1-9][0-9]{0,9}", row[0]) and
                      re.fullmatch(r"[^\s\x00-\x1f]+", row[1]) for row in rows) and
          len({row[0] for row in rows}) == len(rows), "complete unambiguous process table required")
    pids = [int(row[0]) for row in rows if row[1] == "camera-gui"]
    _need(len(pids) <= 1, "multiple GUI processes observed")
    state = read("gui-service", "getprop init.svc.camera-gui")
    _need(state in ("running", "stopped", "restarting"), "GUI service state unknown")
    gui = {"state": "present" if pids else "absent", "service_state": state}
    if pids:
        gui["process"] = _process(reads, phase, "gui")
        _need(gui["process"]["pid"] == pids[0], "GUI process table and live identity differ")
    else:
        _need(state != "running", "running GUI service has no observed process")
    context["gui"] = gui
    if "init_scan_roots" in external:
        data = external["init_scan_roots"]
        _need(read("init-exe", "readlink /proc/1/exe") == data["init_exe_path"], "init executable differs")
        for index, (path, digest) in enumerate({"/init": data["init_exe_sha256"], **data["configuration_sha256"]}.items()):
            _need(_hash(reads, phase + "-init-input-" + str(index), path) == digest, "current init input differs")
    return context


def _runtime(q, fixture):
    def unknown(path):
        return {"state": "unknown", "path": path, "sha256": None, "bytes": None}
    observed = {"schema": "x2dii-runtime-observation-v1", "test_fixture_only": fixture,
                **{key: q[key] for key in ENVIRONMENT_FIELDS}}
    observed["gui"] = {**deepcopy(q["gui"]), "artifact": unknown(COMPONENT_PATHS["gui"]),
                       "process": deepcopy(q["gui"].get("process"))}
    observed["service"] = {"state": "unknown", "service_state": "unknown", "process": None,
                           "artifact": unknown(COMPONENT_PATHS["service"])}
    observed["sensor"] = unknown(COMPONENT_PATHS["sensor"])
    observed["capture_owner"] = {"state": "unknown", "process": None, "route": None,
                                 "artifact": unknown(COMPONENT_PATHS["service"])}
    return observed


def collect_menu_recovery_observation(saved_manifest_raw, saved_manifest_sha256,
                                      maintenance_session, *, backup_identity,
                                      external_evidence, collection_scope, clock=time.time):
    """Collect current recovery data; never authorize or execute recovery."""
    _need(collection_scope in (SCOPE, SYNTHETIC_SCOPE), "fixed recovery collection scope required")
    _need(type(saved_manifest_raw) is bytes and 0 < len(saved_manifest_raw) <= 1024 * 1024 and
          _sha(saved_manifest_raw) == saved_manifest_sha256, "saved manifest bytes/hash differ")
    manifest = strict_json(saved_manifest_raw)
    candidate = _candidate(manifest)
    render_preplacement(manifest, file_index=0)
    _need(type(manifest.get("delivery_identity")) is dict and recovery.role_delivery(manifest),
          "fixed role delivery candidate required")
    _need(manifest["candidate"]["rc"]["before"] == boot_config.STOCK_SHA256, "original rc baseline differs")
    _need(manifest["candidate"]["rc"]["after"] == _sha(boot_config.activate(boot_config.STOCK.read_bytes())),
          "fixed activated rc differs")
    _need(_identity(backup_identity, len(boot_config.STOCK.read_bytes())), "exact saved backup identity required")
    fixture, started = collection_scope == SYNTHETIC_SCOPE, _epoch(clock)
    _need(type(external_evidence) is dict and not (set(external_evidence) - set(EXTERNAL_KINDS)),
          "fixed independent recovery source names required")
    external, sources, times = _external(external_evidence, manifest, started, fixture)
    reads = _Readout(maintenance_session, clock, started, fixture)
    output = {"schema": "x2dii-menu-recovery-readout-v1", "candidate_sha256": candidate,
        "saved_manifest_sha256": saved_manifest_sha256, "collection_scope": collection_scope,
        "status": "PARTIAL_RECOVERY_CONTEXT_NOT_QUALIFICATION", "installable": False, "feature_validated": False,
        "raw_observation": None, "raw_observation_sha256": None, "raw_session": None, "raw_session_sha256": None,
        "queries": reads.queries, "external_sources": sources, "snapshots": {},
        "missing": [kind for kind in EXTERNAL_KINDS if kind not in external], "errors": [],
        "limits": ["External sources are supplied claims, not authenticated observations or consent.",
                   "Retained Session raw-byte references are not reopened or authenticated.",
                   "Two sampled states do not exclude transient changes between observations.",
                   "GUI artifact, service, sensor and capture state remain explicitly unknown; no healthy capture is inferred.",
                   "No recovery, menu, boot, cleanup or installation success is inferred."]}
    try:
        for phase in ("before", "after"):
            output["snapshots"][phase] = _snapshot(reads, phase, manifest, external, backup_identity)
        _need(output["snapshots"]["before"] == output["snapshots"]["after"], "current recovery state changed during collection")
        _need(all(row.get("session_record_status") == "RETAINED_SESSION_REFERENCE_NOT_REOPENED_OR_AUTHENTICATED"
                  for row in reads.queries), "actual retained Session command records required")
        _need(0 <= _epoch(clock) - min([started, *times]) <= 600, "original evidence interval expired")
        if output["missing"]:
            return output
        q = deepcopy(output["snapshots"]["before"])
        nonce = secrets.token_hex(16)
        q.update(candidate_sha256=candidate, saved_manifest_sha256=saved_manifest_sha256,
            observed_utc=datetime.fromtimestamp(min([started, *times]), timezone.utc).isoformat(),
            uid=external["su_identity"]["uid"], domain=external["su_identity"]["domain"],
            official_slot=external["official_recovery"]["official_slot"],
            init_scan_roots=external["init_scan_roots"]["roots"], init_scan_roots_complete=True,
            session_nonce=nonce, recovery_nonce=nonce, synthetic=fixture)
        q["runtime_observation"] = _runtime(q, fixture)
        normalize_observation(q, manifest["candidate"]["gui_sha256"], recovery=True)
        recovery._context(manifest, saved_manifest_sha256, q)
        recovery._execution_gui(manifest, q)
        raw_session = recovery.session_data(manifest, q)
        menu_boot_boundary.context_for_action(manifest, raw_session, "restore")
        output.update(raw_observation=_json(q), raw_observation_sha256=_sha(_json(q)),
                      status="OBSERVED_RECOVERY_CONTEXT_NOT_QUALIFICATION")
        if fixture:
            output["conversion_refusal"] = "Synthetic observations cannot produce a usable recovery session."
        else:
            output.update(raw_session=raw_session, raw_session_sha256=_sha(raw_session))
    except Exception as error:
        output["errors"].append(str(error))
        output["missing"].append("complete_successful_collection")
    return output
