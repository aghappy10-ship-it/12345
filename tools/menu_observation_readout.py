"""Fixed menu observation using an already-held maintenance Session.

No connection, USB window, capture, upload or installation is created here.
Collection scope describes reads, never a new permission or an authorization.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import secrets
import time

from . import observation_producer as producer
from . import prepare_peer_install as peer
from .menu_maintenance_boundary import _candidate
from .stage_peer_usb_access import envelope
from .temporary_menu_files import FILE_LAYOUT, render_preplacement
from .regression_manifest import strict_json

EXTERNAL_KINDS = ("su_identity", "official_recovery", "capture_route", "init_scan_roots")
SCOPE = "menu-first-validation-readonly"
SYNTHETIC_SCOPE = "synthetic-menu-first-validation-readonly"
BOOT_SCOPE = "menu-boot-activation-readonly"
SYNTHETIC_BOOT_SCOPE = "synthetic-menu-boot-activation-readonly"
RC = "/system/etc/init/camera-gui.rc"
PATHS = {"gui": "/system/bin/camera-gui", "service": "/system/bin/camera-service",
         "sensor": "/system/etc/imx861bqr_hb722.conf"}


def _need(ok, reason):
    if not ok:
        raise ValueError("menu observation: " + reason)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _epoch(clock):
    value = clock()
    _need(type(value) in (int, float) and math.isfinite(value) and 1 <= value <= 2147483047, "finite bounded sampling time required")
    return value


def _line(text):
    _need(type(text) is str, "text reply required")
    return text[:-2] if text.endswith("\r\n") else text[:-1] if text.endswith("\n") else text


def _domain(text):
    # Exactly one legal kernel terminator, never general strip/replace.
    raw = text.encode("utf-8")
    if raw.endswith((b"\0", b"\n")):
        raw = raw[:-1]
    _need(re.fullmatch(rb"u:r:[a-z0-9_]{1,96}:s0", raw) is not None, "invalid exact process domain bytes")
    return raw.decode("ascii")


def _external(evidence, manifest, now, fixture):
    """Validate supplied records, not their truth, provenance or approval.

    raw bytes/hash and complete wrapper hash have separate meanings: the
    latter also binds supplied time/reference. Neither authenticates a camera.
    """
    _need(type(evidence) is dict and not (set(evidence) - set(EXTERNAL_KINDS)), "fixed external evidence names required")
    values, sources, times = {}, {}, []
    fields = {
        "su_identity": {"uid", "domain", "mount_namespace"},
        "official_recovery": {"official_slot", "gui_sha256", "rc_sha256", "recovery_route"},
        "capture_route": {"owner", "identity"},
        "init_scan_roots": {"roots", "complete", "init_exe_path", "init_exe_sha256", "configuration_sha256"},
    }
    schemas = {"su_identity": "x2dii-supplied-su-identity-v1", "official_recovery": "x2dii-supplied-official-recovery-v1",
               "capture_route": "x2dii-supplied-capture-route-v1", "init_scan_roots": "x2dii-supplied-init-roots-v1"}
    for kind, record in evidence.items():
        _need(type(record) is dict and set(record) == {"evidence_file", "evidence_sha256", "raw_utf8", "observed_utc"}, "external source fields differ")
        reference = record["evidence_file"]
        _need(type(reference) is str and len(reference) <= 512 and
              re.fullmatch(r"build/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", reference) is not None and
              not any(part in (".", "..") for part in reference.split("/")), "bounded build evidence reference required")
        _need(type(record["raw_utf8"]) is str and 0 < len(record["raw_utf8"].encode("utf-8")) <= 32768, "bounded external raw bytes required")
        raw = record["raw_utf8"].encode("utf-8")
        _need(_sha(raw) == record["evidence_sha256"], "external raw evidence hash differs")
        try:
            stamp = datetime.fromisoformat(record["observed_utc"])
            _need(stamp.tzinfo is not None and 0 <= now - stamp.timestamp() <= 600, "external observation time is stale or future")
        except (TypeError, OverflowError) as error:
            raise ValueError("external observation time is invalid") from error
        data = strict_json(raw)
        _need(type(data) is dict and set(data) == {"schema", "boot_id", "test_fixture_only", *fields[kind]}, "external payload fields differ")
        _need(data["schema"] == schemas[kind] and type(data["test_fixture_only"]) is bool and
              data["test_fixture_only"] is fixture, "external schema/fixture scope differs")
        _need(type(data["boot_id"]) is str and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", data["boot_id"]), "external boot identity required")
        if kind == "su_identity":
            _need(type(data["uid"]) is int and data["uid"] == 0 and data["domain"] == "u:r:su:s0" and
                  type(data["mount_namespace"]) is str and re.fullmatch(r"mnt:\[[1-9][0-9]{0,19}\]", data["mount_namespace"]), "independently observed su identity required")
        elif kind == "official_recovery":
            _need(data["official_slot"] in ("slot_1", "slot_2") and
                  data["gui_sha256"] == manifest["candidate"]["gui_sha256"] and
                  data["rc_sha256"] == manifest["candidate"]["rc"]["before"] and
                  type(data["recovery_route"]) is str and 0 < len(data["recovery_route"]) <= 2048 and
                  data["recovery_route"].strip() and data["recovery_route"].isprintable(), "independent official recovery binding required")
        elif kind == "capture_route":
            # The original assembler owns this exact route/owner contract.
            route = {"reference": reference, "raw_utf8": record["raw_utf8"], "sha256": record["evidence_sha256"]}
            producer.assemble_supplied_observation(_json({"schema": "x2dii-supplied-query-observations-v1",
                "test_fixture_only": fixture, "before": [], "observations": [], "after": [], "capture_route": route}),
                manifest["candidate"]["gui_sha256"])
        else:
            roots = data["roots"]
            _need(type(roots) is list and 0 < len(roots) <= 32 and
                  all(type(root) is str and len(root) <= 201 and
                      re.fullmatch(r"/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*", root) and
                      not any(part in (".", "..") for part in root.split("/")) for root in roots) and
                  len(roots) == len(set(roots)) and
                  "/system/etc/init" in roots and data["complete"] is True, "explicit complete init roots required")
            _need(data["init_exe_path"] == "/init" and type(data["init_exe_sha256"]) is str and
                  re.fullmatch(r"[0-9a-f]{64}", data["init_exe_sha256"]), "fixed init executable binding required")
            configs = data["configuration_sha256"]
            _need(type(configs) is dict and 0 < len(configs) <= 64 and "/init.rc" in configs,
                  "complete independently reviewed init inputs required")
            for path, digest in configs.items():
                _need(type(path) is str and len(path) <= 128 and
                      (path == "/init.rc" or re.fullmatch(r"/(?:system|vendor|odm)/etc/init/[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.rc", path)) and
                      type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest), "fixed init input path/hash required")
        values[kind] = data
        sources[kind] = {**deepcopy(record), "source_record_sha256": _sha(_json(record))}
        times.append(stamp.timestamp())
    _need(len({data["boot_id"] for data in values.values()}) <= 1, "external sources disagree on boot")
    return values, sources, times


class _Readout:
    def __init__(self, session, clock, started, fixture):
        self.session, self.clock, self.started = session, clock, started
        self.queries = []
        self.supplied = {"schema": "x2dii-supplied-query-observations-v1", "test_fixture_only": fixture,
                         "before": [], "observations": [], "after": [], "capture_route": None}
        self.context, self.processes, self.derived_sources = {}, {}, {}

    def read(self, name, command, *, maximum=4096):
        _need(0 <= _epoch(self.clock) - self.started <= 600, "original observation interval expired")
        envelope(command, "123456abcdef")
        row = {"source_id": f"menu-{len(self.queries)+1:03d}-{name}", "command": command,
               "observed_utc": datetime.fromtimestamp(_epoch(self.clock), timezone.utc).isoformat()}
        self.queries.append(row)
        report = getattr(self.session, "report", None)
        history = report.get("commands") if type(report) is dict else None
        index = len(history) if type(history) is list else None
        try:
            text = self.session.command(row["source_id"], command)
            _need(type(text) is str and len(text.encode("utf-8")) <= maximum, "bounded full query reply required")
            row.update(stdout=text, stdout_sha256=_sha(text.encode("utf-8")), exit_code=0)
            _need(0 <= _epoch(self.clock) - self.started <= 600, "original observation interval expired during query")
            return text, row
        except Exception as error:
            row["error"] = str(error)
            raise
        finally:
            if index is None:
                row["session_record_status"] = "EXTERNAL_IO_WITHOUT_RETAINED_SESSION_RECORD"
            else:
                try:
                    _need(len(history) == index + 1, "Session command record count changed")
                    native = deepcopy(history[index])
                    row["session_record"] = native
                    row["session_record_sha256"] = _sha(_json(native))
                    _need(type(native) is dict and native.get("label") == row["source_id"] and
                          native.get("command") == command, "Session command record identity differs")
                    if "error" not in row:
                        _need(type(native.get("exit")) is int and native["exit"] == 0 and
                              native.get("text") == row["stdout"] and "error" not in native,
                              "Session command record result differs")
                    digest = native.get("rawSha256")
                    _need(type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest),
                          "Session received bytes hash missing")
                    folder = Path(self.session.folder).resolve()
                    relative = folder.relative_to(peer.ROOT.resolve()).as_posix()
                    _need(relative.startswith("build/") and
                          re.fullmatch(r"build/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", relative),
                          "Session received bytes source must be inside project build")
                    row["received_bytes_source"] = {
                        "evidence_file": f"{relative}/{index+1:03d}-{row['source_id']}.received.bin",
                        "evidence_sha256": digest,
                    }
                    row["session_record_status"] = "RETAINED_SESSION_REFERENCE_NOT_REOPENED_OR_AUTHENTICATED"
                except Exception as error:
                    row["session_record_error"] = str(error)
                    if "error" not in row:
                        row["error"] = str(error)
                        raise

    def scalar(self, phase, field, command, *, decode=_line, maximum=4096):
        text, source = self.read(phase + "-" + field.replace(".", "-"), command, maximum=maximum)
        value = decode(text)
        source.setdefault("projections", []).append({"phase": phase, "field": field, "value": value})
        self.supplied[phase].append({"source_id": source["source_id"], "field": field,
            "stdout": value + "\n", "exit_code": 0})
        return value

    def supplied_external(self, phase, field, value, source_name, record):
        source_id = "external-" + phase + "-" + source_name
        self.supplied[phase].append({"source_id": source_id,
            "field": field, "stdout": value + "\n", "exit_code": 0})
        self.derived_sources[source_id] = {"kind": "external_fact_projection", "field": field,
            "evidence_file": record["evidence_file"], "evidence_sha256": record["evidence_sha256"],
            "observed_utc": record["observed_utc"], "source_record_sha256": record["source_record_sha256"],
            "remote_query_executed": False, "exit_code_meaning": "LOCAL_FORMAT_PROJECTION_SUCCEEDED_NOT_REMOTE_SHELL_STATUS"}

    def process(self, phase, role, *, explicit=None):
        if explicit is None:
            name = {"observer": "camera-test", "gui": "camera-gui", "service": "camera-service"}[role]
            pid_text = self.scalar(phase, role + ".process.pid", "pidof " + name)
        else:
            pid_text = str(explicit["pid"])
            # Bind the supplied owner to an actual live process, not its name.
            text, source = self.read(phase + "-capture-pid", "cat /proc/" + pid_text + "/stat")
            _need(text.startswith(pid_text + " ("), "capture PID/stat differs")
            self.supplied[phase].append({"source_id": source["source_id"], "field": role + ".process.pid",
                "stdout": pid_text + "\n", "exit_code": 0})
            source["projections"] = [{"phase": phase, "field": role + ".process.pid", "value": pid_text}]
        _need(re.fullmatch(r"[1-9][0-9]{0,9}", pid_text) is not None and 1 < int(pid_text) < 2**31, "one bounded process PID required")
        proc = "/proc/" + pid_text

        def ticks(text):
            head, separator, tail = text.rpartition(") ")
            fields = tail.split()
            _need(separator and head.startswith(pid_text + " (") and "\0" not in text and
                  len(fields) >= 20 and fields[0] not in ("Z", "X", "x") and
                  re.fullmatch(r"[1-9][0-9]{0,19}", fields[19]) is not None, "complete live process stat required")
            return fields[19]

        prefix = role + ".process."
        values = {"pid": int(pid_text)}
        values["start_ticks"] = self.scalar(phase, prefix + "start_ticks", "cat " + proc + "/stat", decode=ticks)
        values["exe_target"] = self.scalar(phase, prefix + "exe_target", "readlink " + proc + "/exe")
        digest = self.scalar(phase, prefix + "exe_sha256", "sha256sum " + proc + "/exe")
        values["exe_sha256"] = digest.split("  ", 1)[0]
        values["domain"] = self.scalar(phase, prefix + "domain", "cat " + proc + "/attr/current", decode=_domain)
        values["mount_namespace"] = self.scalar(phase, prefix + "mount_namespace", "readlink " + proc + "/ns/mnt")
        _need(explicit is None or values == explicit, "independent capture owner differs from live identity")
        self.processes[(phase, role)] = values

    def snapshot(self, phase, external, sources):
        boot = self.scalar(phase, "boot_id", "cat /proc/sys/kernel/random/boot_id")
        namespace = self.scalar(phase, "mount_namespace", "readlink /proc/self/ns/mnt")
        self.scalar(phase, "init_mount_namespace", "readlink /proc/1/ns/mnt")
        flags, active_queries = {}, []
        for slot in (1, 2):
            for flag in ("active", "bootable", "successful"):
                key = f"slot_{slot}.status_{flag}"
                text, source = self.read(phase + "-" + key.replace(".", "-"), "unrd " + key)
                value = _line(text)
                _need(value in ("0", "1"), "slot flag must be its own bare 0/1 result")
                flags[key] = value
                if flag == "active":
                    active_queries.append(source["source_id"])
        active = [slot for slot in ("slot_1", "slot_2") if flags[slot + ".status_active"] == "1"]
        _need(len(active) == 1, "one active slot required")
        # This is an explicit projection of two individually successful reads,
        # not a statement that the inactive slot is an official recovery image.
        active_source = phase + "-active-slot-from-flags"
        self.supplied[phase].append({"source_id": active_source, "field": "active_slot",
            "stdout": active[0] + "\n", "exit_code": 0})
        self.derived_sources[active_source] = {"kind": "two_observed_active_flags_projection", "field": "active_slot",
            "query_ids": active_queries, "exit_code_meaning": "BOTH_INDIVIDUAL_QUERIES_SUCCEEDED_NO_ADDITIONAL_REMOTE_QUERY"}
        if "official_recovery" in external:
            self.supplied_external(phase, "official_slot", external["official_recovery"]["official_slot"],
                                   "official-slot", sources["official_recovery"])
        mounts, _ = self.read(phase + "-system-mount", "cat /proc/mounts", maximum=65536)
        lines = [line.split() for line in mounts.splitlines()]
        _need(all(len(line) == 6 for line in lines), "complete mount rows required")
        system = [line for line in lines if line[1] == "/system"]
        _need(len(system) == 1, "one actual system mount required")
        mount = {"device": system[0][0], "filesystem": system[0][2], "options": system[0][3]}
        self.context[phase] = {"boot_id": boot, "mount_namespace": namespace, "active_slot": active[0],
                               "slot_readback": flags, "system_mount": mount}
        _need(all(data["boot_id"] == boot for data in external.values()), "supplied evidence is for another boot")
        _need("su_identity" not in external or external["su_identity"]["mount_namespace"] == namespace,
              "independent su namespace differs")
        for role in ("observer", "gui", "service"):
            self.process(phase, role)
        if "capture_route" in external:
            self.process(phase, "capture_owner", explicit=external["capture_route"]["owner"])
        for role, path in PATHS.items():
            prefix = "sensor." if role == "sensor" else role + ".artifact."
            self.scalar(phase, prefix + "sha256", "sha256sum " + path)
            self.scalar(phase, prefix + "bytes", "stat -c %s " + path)
        if "capture_route" in external:
            path = external["capture_route"]["owner"]["exe_target"]
            self.scalar(phase, "capture_owner.artifact.sha256", "sha256sum " + path)
            self.scalar(phase, "capture_owner.artifact.bytes", "stat -c %s " + path)

    def observations(self, external):
        roles = ["gui", "service"] + (["capture_owner"] if "capture_route" in external else [])
        for role in roles:
            process = self.processes[("before", role)]
            self.scalar("observations", role + ".state", f"[ -d /proc/{process['pid']} ] && printf 'present\\n'")
            if role != "capture_owner":
                self.scalar("observations", role + ".service_state", "getprop init.svc." + ("camera-gui" if role == "gui" else "camera-service"))
        paths = {**PATHS}
        if "capture_route" in external:
            paths["capture_owner"] = external["capture_route"]["owner"]["exe_target"]
        for role, path in paths.items():
            prefix = "sensor." if role == "sensor" else role + ".artifact."
            def regular(text):
                value = _line(text)
                _need(re.fullmatch(r"[0-9a-f]{4,8}", value) is not None and int(value, 16) & 0o170000 == 0o100000,
                      "regular artifact inode required")
                return "present"
            self.scalar("observations", prefix + "state", "stat -c %f " + path, decode=regular)
            for key, command in (("path", "stat -c %n "), ("sha256", "sha256sum "), ("bytes", "stat -c %s ")):
                self.scalar("observations", prefix + key, command + path)

    def file_metadata(self, phase, name, path):
        """Read fixed caller-selected rc/payload paths, not expected metadata."""
        prefix = phase + "-" + name
        metadata_text, _ = self.read(prefix + "-stat", "stat -c '%u %g %a' " + path)
        _need(_line(metadata_text) == "0 0 644", "original rc metadata differs")
        label_text, _ = self.read(prefix + "-label", "ls -Zd " + path)
        label = _line(label_text).split()
        _need(len(label) == 2 and label[1] == path and re.fullmatch(r"u:object_r:[a-z0-9_]{1,96}:s0", label[0]),
              "rc label is not bound to the requested path")
        names, _ = self.read(prefix + "-xattr-names", "/system/bin/toybox getfattr " + path)
        attrs, _ = self.read(prefix + "-xattr-values", "/system/bin/toybox getfattr -d " + path)
        _need(names in (f"# file: {path}\nsecurity.selinux\n", f"# file: {path}\nsecurity.selinux\n\n") and
              attrs in (f'# file: {path}\nsecurity.selinux="{label[0]}"\n', f'# file: {path}\nsecurity.selinux="{label[0]}"\n\n'),
              "complete original rc xattrs differ or remain unreadable")
        return {"uid": 0, "gid": 0, "mode": "644", "label": label[0], "xattr_names": ["security.selinux"]}

    def supporting_context(self, phase, external, manifest, payload_identities=None):
        timestamp, _ = self.read(phase + "-device-time", "date -u +%s")
        _need(re.fullmatch(r"[1-9][0-9]{0,9}\n", timestamp) and abs(int(timestamp) - _epoch(self.clock)) <= 8,
              "camera and observation clock are not coherently sampled")
        uid, _ = self.read(phase + "-maintenance-uid", "id -u")
        domain, _ = self.read(phase + "-maintenance-domain", "cat /proc/self/attr/current")
        _need(_line(uid) == "0" and _domain(domain) == "u:r:hbl_camera_service:s0", "maintenance role changed")
        rc_hash, _ = self.read(phase + "-rc-hash", "sha256sum " + RC)
        _need(_line(rc_hash) == manifest["candidate"]["rc"]["before"] + "  " + RC, "original rc differs")
        meta = self.file_metadata(phase, "rc", RC)
        parents = {}
        for path in ("/system", "/system/etc", "/system/lib64", "/system/etc/init"):
            plain, _ = self.read(phase + "-parent-plain-" + path.replace("/", "-"), f"[ -d {path} ] && [ ! -L {path} ]")
            _need(plain == "", "plain parent check returned unexpected bytes")
            stat, _ = self.read(phase + "-parent-meta-" + path.replace("/", "-"), "stat -c '%u %g %a' " + path)
            _need(re.fullmatch(r"(?:0|[1-9][0-9]{0,9}) (?:0|[1-9][0-9]{0,9}) [0-7]{3,4}", _line(stat)), "parent stat is malformed")
            label, _ = self.read(phase + "-parent-label-" + path.replace("/", "-"), "ls -Zd " + path)
            parts = _line(label).split()
            _need(len(parts) == 2 and parts[1] == path and re.fullmatch(r"u:object_r:[a-z0-9_]{1,96}:s0", parts[0]),
                  "parent label is not bound to requested path")
            parents[path] = {"stat": _line(stat), "label": parts[0]}
        payload_metadata = {}
        for index, (_, target, _) in enumerate(FILE_LAYOUT):
            if payload_identities is None:
                text, _ = self.read(phase + "-target-absence-" + str(index), f"[ ! -e {target} ] && [ ! -L {target} ]")
                _need(text == "", "absence check returned unexpected data")
            else:
                name = "placed-" + str(index)
                text, _ = self.read(phase + "-" + name + "-plain", f"[ -f {target} ] && [ ! -L {target} ]")
                _need(text == "", "placed payload plain-file check differs")
                identity, _ = self.read(phase + "-" + name + "-identity", "stat -c '%d:%i:%f:%h:%s:%u:%g' " + target)
                _need(_line(identity) == payload_identities[index], "placed payload ownership differs")
                digest, _ = self.read(phase + "-" + name + "-hash", "sha256sum " + target)
                _need(_line(digest) == manifest["candidate"]["files"][index]["sha256"] + "  " + target,
                      "placed payload content differs")
                payload_metadata[target] = self.file_metadata(phase, name, target)
                _need(payload_metadata[target]["label"] == "u:object_r:system_file:s0", "placed payload label differs")
        if "init_scan_roots" in external:
            data = external["init_scan_roots"]
            actual, _ = self.read(phase + "-init-executable", "readlink /proc/1/exe")
            _need(_line(actual) == data["init_exe_path"], "current init executable differs")
            for index, (path, digest) in enumerate({"/init": data["init_exe_sha256"], **data["configuration_sha256"]}.items()):
                actual, _ = self.read(phase + "-init-source-" + str(index), "sha256sum " + path)
                _need(_line(actual) == digest + "  " + path, "independent init source differs from current bytes")
        return {"rc_metadata": meta, "parents": parents, "payload_metadata": payload_metadata}


def collect_menu_observation(manifest, maintenance_session, *, external_evidence,
                             collection_scope, clock=time.time):
    if collection_scope not in (SCOPE, SYNTHETIC_SCOPE):
        raise ValueError("fixed menu observation collection scope required")
    return _collect_menu_observation(manifest, maintenance_session, external_evidence=external_evidence,
        collection_scope=collection_scope, clock=clock, payload_identities=None)


def collect_boot_activation_observation(manifest, maintenance_session, *, payload_identities,
                                        external_evidence, collection_scope, clock=time.time):
    """Read the four previously placed files and a fresh stock runtime context.

    The supplied inode identities are expected ownership, not proof of earlier
    placement or authority. Both current snapshots must actually match them.
    No temporary-menu context is relabelled and no boot action is performed.
    """
    if collection_scope not in (BOOT_SCOPE, SYNTHETIC_BOOT_SCOPE):
        raise ValueError("fixed boot activation observation collection scope required")
    from .menu_boot_file import encode_payload_identities
    encode_payload_identities(manifest, payload_identities)
    return _collect_menu_observation(manifest, maintenance_session, external_evidence=external_evidence,
        collection_scope=collection_scope, clock=clock, payload_identities=tuple(payload_identities))


def _collect_menu_observation(manifest, maintenance_session, *, external_evidence,
                              collection_scope, clock, payload_identities):
    manifest = deepcopy(manifest)
    candidate = _candidate(manifest)
    render_preplacement(manifest, file_index=0)  # Existing fixed four-path contract.
    started = _epoch(clock)
    fixture = collection_scope in (SYNTHETIC_SCOPE, SYNTHETIC_BOOT_SCOPE)
    external, sources, external_times = _external(external_evidence, manifest, started, fixture)
    reads = _Readout(maintenance_session, clock, started, fixture)
    errors = []
    metadata = None
    try:
        reads.snapshot("before", external, sources)
        metadata = reads.supporting_context("before", external, manifest, payload_identities)
        reads.observations(external)
        after_metadata = reads.supporting_context("after", external, manifest, payload_identities)
        reads.snapshot("after", external, sources)
        _need(reads.context["before"] == reads.context["after"], "context changed during collection")
        _need(metadata == after_metadata, "rc or parent metadata changed during collection")
    except Exception as error:
        errors.append(str(error))
    if "capture_route" in external:
        source = sources["capture_route"]
        reads.supplied["capture_route"] = {"reference": source["evidence_file"], "raw_utf8": source["raw_utf8"],
                                            "sha256": source["evidence_sha256"]}
    try:
        result = producer.assemble_supplied_observation(_json(reads.supplied), manifest["candidate"]["gui_sha256"])
    except ValueError as error:
        errors.append(str(error))
        result = {"runtime_observation": None, "missing": ["coherent_current_runtime_observation"],
                  "supplied_raw": _json(reads.supplied), "installable": False}
    expected = {target: {"uid": 0, "gid": 0, "mode": "644", "label": "u:object_r:system_file:s0",
                         "xattr_names": ["security.selinux"]} for _, target, _ in FILE_LAYOUT}
    output = {"schema": "x2dii-menu-observation-readout-v1", "candidate_sha256": candidate,
        "collection_scope": collection_scope,
        "status": "PARTIAL_MENU_CONTEXT_NOT_QUALIFICATION", "installable": False, "feature_validated": False,
        "raw_observation": None, "raw_observation_sha256": None, "raw_session": None, "raw_session_sha256": None,
        "queries": reads.queries, "derived_sources": reads.derived_sources,
        "external_sources": sources, "supplied_observation": result,
        "deployment_constraints": {"kind": "EXPECTED_NEW_FILE_METADATA_NOT_EXISTING_TARGET_OBSERVATION",
                                   "metadata": expected, "source": "tools/menu_observation_readout.py",
                                   "source_sha256": _sha(Path(__file__).read_bytes()),
                                   "actual_creation_permissions_verified": False},
        "limits": ["supplied-producer queries include explicitly named local projections; only queries holds Session.command calls",
                   "external fact projection exit zero means local format success, not remote shell execution",
                   "hashes and fixture markers do not authenticate independent evidence or continuous identity",
                   "parent metadata and absence checks do not prove write permission or future inherited labels",
                   "no actual capture, menu, recovery, startup or withdrawal result is inferred"],
        "missing": [*[kind for kind in EXTERNAL_KINDS if kind not in external], *result["missing"]], "errors": errors}
    if errors:
        output["missing"].append("complete_successful_collection")
    if output["missing"]:
        return output
    if payload_identities is not None:
        expected = metadata["payload_metadata"]
        output["deployment_constraints"].update(
            kind="OBSERVED_PLACED_FILE_METADATA_NOT_WRITE_AUTHORITY", metadata=deepcopy(expected))
    observed_epoch = min([started, *external_times])
    if not 0 <= _epoch(clock) - observed_epoch <= 600:
        output["missing"].append("unexpired_original_observation")
        return output
    context = reads.context["before"]
    observed = result["runtime_observation"]
    q = {**context, "synthetic": fixture,
         "observed_utc": datetime.fromtimestamp(observed_epoch, timezone.utc).isoformat(),
         "uid": external["su_identity"]["uid"], "domain": external["su_identity"]["domain"],
         "official_slot": external["official_recovery"]["official_slot"],
         "metadata": {RC: metadata["rc_metadata"], **expected},
         "init_scan_roots": external["init_scan_roots"]["roots"],
         "init_scan_roots_complete": external["init_scan_roots"]["complete"],
         "init_mount_namespace": observed["init_mount_namespace"],
         "observer": reads.processes[("before", "observer")], "runtime_observation": observed,
         "session_nonce": secrets.token_hex(16)}
    raw = _json(q)
    output.update(raw_observation=raw, raw_observation_sha256=_sha(raw),
                  session_nonce_origin="HOST_GENERATED_CORRELATION_NOT_CAMERA_FACT")
    from .menu_first_validation import saved_menu_session
    try:
        if payload_identities is None:
            session = saved_menu_session(manifest, raw, expected_sha256=_sha(raw))
            raw_session = session.raw_session
        else:
            _need(not fixture, "synthetic saved observation cannot supply a camera session")
            peer.validate_session_context(q)
            raw_session = peer.session_data(manifest, q)
            from .menu_boot_boundary import context_for_action
            context_for_action(manifest, raw_session, "activate")
    except ValueError as error:
        output["conversion_refusal"] = str(error)
        if fixture:
            output["status"] = "COMPLETE_SYNTHETIC_SHAPE_NOT_SESSION_OR_QUALIFICATION"
        else:
            output["errors"].append(str(error))
            output["missing"].append("valid_saved_menu_session")
        return output
    output.update(status="COMPLETE_CONTEXT_DATA_NOT_QUALIFICATION", raw_session=raw_session,
                  raw_session_sha256=_sha(raw_session))
    return output
