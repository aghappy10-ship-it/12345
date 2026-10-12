"""Assemble supplied scalar query results with no I/O.

No collector, shell generation, device authority or authenticated observation.
The single-query scope is a caller collection contract, not something JSON or
matching sampled identities can prove. Start ticks are supplied scalar text;
this module does not parse a complete /proc/PID/stat record.
"""
import hashlib
import json
import re

from tools.runtime_observation import ENVIRONMENT_FIELDS, PROCESS_FIELDS, COMPONENT_PATHS, normalize_observation


ROLES = ("observer", "gui", "service", "capture_owner")
ARTIFACT_IDENTITIES = tuple(prefix + field for prefix in (
    "gui.artifact.", "service.artifact.", "capture_owner.artifact.", "sensor.")
    for field in ("sha256", "bytes"))
IDENTITY_FIELDS = (*ENVIRONMENT_FIELDS, *(role + ".process." + field
                   for role in ROLES for field in PROCESS_FIELDS), *ARTIFACT_IDENTITIES)
OBSERVED_FIELDS = tuple(
    field for role in ("gui", "service", "capture_owner")
    for field in (role + ".state", *(role + ".artifact." + key
                                    for key in ("state", "path", "sha256", "bytes")),
                  *((role + ".service_state",) if role != "capture_owner" else ()))
) + tuple("sensor." + key for key in ("state", "path", "sha256", "bytes"))
UNVERIFIED = ["input_authenticity_and_single_query_execution", "sampling_time_and_freshness",
              "continuous_identity_between_samples", "observer_collection_authority",
              "official_slot_physical_integrity", "sensor_configuration_applied_state",
              "physical_capture_route_and_behavior", "camera_menu_and_qualification_authority"]


def _need(condition, reason):
    if not condition:
        raise ValueError("supplied observation: " + reason)


def _keys(value, fields, name):
    _need(type(value) is dict and set(value) == set(fields), name + " fields differ")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        _need(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def _nonfinite(_value):
    raise ValueError("supplied observation: nonfinite JSON number")


def _json(raw):
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_nonfinite)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ValueError("supplied observation: invalid JSON, encoding or duplicate field") from error


def _text(value, limit):
    if type(value) is not str:
        return False
    try:
        return len(value.encode("utf-8")) <= limit
    except UnicodeError:
        return False


def _match(value, pattern):
    return type(value) is str and re.fullmatch(pattern, value) is not None


def _scalar(field, value):
    """Validate one decoded scalar, not its collection method or truth."""
    if field == "boot_id":
        pattern = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
    elif field in ("active_slot", "official_slot"):
        pattern = r"slot_[12]"
    elif field.endswith("mount_namespace"):
        pattern = r"mnt:\[[1-9][0-9]{0,19}\]"
    elif field.endswith(".pid"):
        _need(_match(value, r"[1-9][0-9]{0,9}") and 1 < int(value) < 2**31, "invalid pid scalar")
        return int(value)
    elif field.endswith(".bytes"):
        _need(_match(value, r"[1-9][0-9]{0,18}") and int(value) < 2**63, "invalid size scalar")
        return int(value)
    elif field.endswith(".start_ticks"):
        pattern = r"[1-9][0-9]{0,19}"
    elif field.endswith("sha256"):
        pattern = r"[0-9a-f]{64}"
    elif field.endswith(".exe_target"):
        pattern = r"/system/(bin|xbin)/[A-Za-z0-9_-]{1,100}"
    elif field.endswith(".domain"):
        pattern = r"u:r:[a-z0-9_]{1,96}:s0"
    elif field.endswith(".path"):
        _need(len(value) <= 512 and not any(part in (".", "..") for part in value.split("/")), "artifact path")
        pattern = r"/system/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_.-]+)*"
    elif field.endswith(".service_state"):
        pattern = r"running|stopped|restarting|unknown"
    else:
        pattern = r"present|absent|unknown"
    _need(_match(value, pattern), "invalid scalar: " + field)
    return value


def _check_partial_relationships(values):
    recorded = values["observations"]
    process_samples = []
    for identity in (values["before"], values["after"]):
        for field in ARTIFACT_IDENTITIES:
            if field in identity and field in recorded:
                _need(identity[field] == recorded[field], "conflicting sampled disk identity")
        if "active_slot" in identity and "official_slot" in identity:
            _need(identity["active_slot"] != identity["official_slot"], "conflicting active/official slots")
        namespaces = [value for key, value in identity.items() if key.endswith("mount_namespace")]
        _need(len(set(namespaces)) <= 1, "conflicting mount namespaces")
        seen = {}
        for role in ROLES:
            process = {key: identity[role + ".process." + key] for key in PROCESS_FIELDS
                       if role + ".process." + key in identity}
            pid = process.get("pid")
            if pid is not None:
                prior = seen.setdefault(pid, {})
                _need(all(prior[key] == process[key] for key in set(prior) & set(process)), "conflicting same-PID identities")
                prior.update(process)
            if role != "observer":
                for process_key, artifact_key in (("exe_target", "path"), ("exe_sha256", "sha256")):
                    disk_key = role + ".artifact." + artifact_key
                    if process_key in process and disk_key in recorded:
                        _need(process[process_key] == recorded[disk_key], "conflicting process/disk identity")
                    if process_key == "exe_sha256" and process_key in process and disk_key in identity:
                        _need(process[process_key] == identity[disk_key], "conflicting sampled process/disk hash")
        process_samples.append(seen)
    before, after = process_samples
    for pid in set(before) & set(after):
        _need(all(before[pid][key] == after[pid][key] for key in set(before[pid]) & set(after[pid])),
              "conflicting same-PID identity across samples")
    for sample in (recorded, values["before"], values["after"]):
        artifacts = {}
        for role in ("gui", "service", "capture_owner", "sensor"):
            prefix = "sensor." if role == "sensor" else role + ".artifact."
            artifact = {key: sample.get(prefix + key, recorded.get(prefix + key))
                        for key in ("state", "path", "sha256", "bytes")
                        if prefix + key in sample or prefix + key in recorded}
            path = artifact.get("path")
            if path is not None:
                _need(role not in COMPONENT_PATHS or path == COMPONENT_PATHS[role], "conflicting fixed artifact path")
                prior = artifacts.setdefault(path, {})
                _need(all(prior[key] == artifact[key] for key in set(prior) & set(artifact)), "conflicting same-path artifacts")
                prior.update(artifact)


def assemble_supplied_observation(raw: bytes, expected_gui_sha256: str) -> dict:
    """Assemble supplied facts only; never fill gaps from an expected baseline."""
    _need(type(raw) is bytes and 0 < len(raw) <= 1024 * 1024, "bounded immutable bytes required")
    _need(_match(expected_gui_sha256, r"[0-9a-f]{64}"), "expected GUI hash is invalid")
    document = _json(raw)
    _keys(document, ("schema", "test_fixture_only", "before", "observations", "after", "capture_route"), "document")
    _need(document["schema"] == "x2dii-supplied-query-observations-v1", "unsupported schema")
    _need(type(document["test_fixture_only"]) is bool, "explicit fixture marker required")
    _need(all(type(document[key]) is list for key in ("before", "observations", "after")), "query lists required")
    _need(sum(len(document[key]) for key in ("before", "observations", "after")) <= 128, "too many queries")
    values, queries = {}, {}
    for phase in ("before", "observations", "after"):
        values[phase] = {}
        for record in document[phase]:
            _keys(record, ("source_id", "field", "stdout", "exit_code"), "query")
            _need(_match(record["source_id"], r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}"), "invalid query source")
            field, text = record["field"], record["stdout"]
            _need(type(record["exit_code"]) is int and record["exit_code"] == 0,
                  "nonzero or invalid individual query status: " + record["source_id"])
            _need(type(field) is str and field in (OBSERVED_FIELDS if phase == "observations" else IDENTITY_FIELDS),
                  "unknown query field")
            _need(record["source_id"] not in queries, "duplicate query source")
            _need(_text(text, 4096), "bounded UTF-8 stdout required")
            value = text[:-2] if text.endswith("\r\n") else text[:-1] if text.endswith("\n") else text
            reported_path = None
            if field.endswith("sha256"):
                match = re.fullmatch(r"([0-9a-f]{64})  (/[A-Za-z0-9_./-]+)", value)
                _need(match is not None, "exact single sha256sum output required")
                value, reported_path = match.groups()
            value = _scalar(field, value)
            _need(field not in values[phase] or values[phase][field] == value,
                  "contradictory repeated field: " + phase + "." + field)
            values[phase][field] = value
            queries[record["source_id"]] = {
                "phase": phase, "record": record, "value": value, "reported_hash_path": reported_path,
                "stdout_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                "record_canonical_sha256": hashlib.sha256(json.dumps(
                    record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()}
    for query in queries.values():
        field, phase = query["record"]["field"], query["phase"]
        reported_path = query["reported_hash_path"]
        if reported_path is None:
            continue
        if field.endswith(".process.exe_sha256"):
            _need(_match(reported_path, r"/proc/[1-9][0-9]{0,9}/exe"), "process hash output path")
            pid = values[phase].get(field.removesuffix("exe_sha256") + "pid")
            expected_path = None if pid is None else "/proc/" + str(pid) + "/exe"
        else:
            expected_path = COMPONENT_PATHS.get(field.split(".")[0]) or (
                values["observations"].get("capture_owner.artifact.path") if phase == "observations"
                else values[phase].get("capture_owner.process.exe_target"))
            if field == "capture_owner.artifact.sha256":
                observed_path = values["observations"].get("capture_owner.artifact.path")
                _need(observed_path is None or reported_path == observed_path, "capture hash output path differs from explicit artifact")
        _need(expected_path is None or reported_path == expected_path, "hash output path differs from explicit identity")
    for field in set(values["before"]) & set(values["after"]):
        _need(values["before"][field] == values["after"][field], "identity changed between samples: " + field)
    _check_partial_relationships(values)
    missing = [phase + "." + field for phase, fields in (("before", IDENTITY_FIELDS),
               ("observations", OBSERVED_FIELDS), ("after", IDENTITY_FIELDS))
               for field in fields if field not in values[phase] or
               (field.endswith(".state") and values[phase][field] != "present") or
               (field.endswith(".service_state") and values[phase][field] == "unknown")]
    if document["capture_route"] is None:
        missing.append("capture_route")
    route_record = None
    route_data = None
    if document["capture_route"] is not None:
        route = document["capture_route"]
        _keys(route, ("reference", "raw_utf8", "sha256"), "capture route record")
        _need(_text(route["raw_utf8"], 32 * 1024), "capture route byte bound")
        reference = route["reference"]
        _need(_match(reference, r"build/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*") and len(reference) <= 512
              and not any(part in (".", "..") for part in reference.split("/")), "capture route reference")
        route_raw = route["raw_utf8"].encode("utf-8")
        route_hash = hashlib.sha256(route_raw).hexdigest()
        _need(route_hash == route["sha256"], "capture route raw hash differs")
        route_data = _json(route_raw)
        _need(type(route_data) is dict and set(route_data) == {
            "schema", "test_fixture_only", "boot_id", "owner", "identity"}, "capture route fields differ")
        _need(route_data["schema"] == "x2dii-supplied-capture-route-v1", "capture route schema")
        _need(type(route_data["test_fixture_only"]) is bool and
              route_data["test_fixture_only"] == document["test_fixture_only"], "capture route fixture marker differs")
        _need(type(route_data["owner"]) is dict and set(route_data["owner"]) == set(PROCESS_FIELDS),
              "complete explicit capture route owner required")
        _scalar("boot_id", route_data["boot_id"])
        for key in PROCESS_FIELDS:
            item = route_data["owner"][key]
            _need(type(item) is (int if key == "pid" else str), "capture route owner field type")
            _scalar("capture_owner.process." + key, str(item))
        route_identity = route_data["identity"]
        _need(type(route_identity) is str and 0 < len(route_identity) <= 2048 and route_identity.strip()
              and all(character.isprintable() for character in route_identity), "capture route identity")
        for phase in ("before", "after"):
            if "boot_id" in values[phase]:
                _need(values[phase]["boot_id"] == route_data["boot_id"], "capture route boot differs")
            for key in PROCESS_FIELDS:
                field = "capture_owner.process." + key
                if field in values[phase]:
                    _need(values[phase][field] == route_data["owner"][key], "capture route owner differs: " + key)
        route_record = {"record": route, "raw_sha256": route_hash,
                        "record_canonical_sha256": hashlib.sha256(json.dumps(
                            route, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()}
    observed = None
    if not missing:
        identity, recorded = values["before"], values["observations"]
        observed = {"schema": "x2dii-runtime-observation-v1", "test_fixture_only": document["test_fixture_only"],
                    **{key: identity[key] for key in ENVIRONMENT_FIELDS}}
        for role in ("gui", "service", "capture_owner"):
            observed[role] = {"state": recorded[role + ".state"],
                              "artifact": {key: recorded[role + ".artifact." + key]
                                           for key in ("state", "path", "sha256", "bytes")},
                              "process": {key: identity[role + ".process." + key] for key in PROCESS_FIELDS}}
            if role != "capture_owner":
                observed[role]["service_state"] = recorded[role + ".service_state"]
        observed["sensor"] = {key: recorded["sensor." + key] for key in ("state", "path", "sha256", "bytes")}
        route = document["capture_route"]
        observed["capture_owner"]["route"] = {"identity": route_data["identity"],
                                              "evidence_file": route["reference"], "evidence_sha256": route["sha256"]}
        context = {key: identity[key] for key in ENVIRONMENT_FIELDS}
        context["observer"] = {key: identity["observer.process." + key] for key in PROCESS_FIELDS}
        observed = normalize_observation({**context, "runtime_observation": observed}, expected_gui_sha256)
    return {"schema": "x2dii-supplied-observation-result-v1",
            "status": "STRUCTURALLY_NORMALIZED_SUPPLIED_DATA_ONLY" if observed else "LOCAL_PARTIAL_SUPPLIED_OBSERVATION",
            "installable": False,
            "source": {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
                       "test_fixture_only": document["test_fixture_only"]},
            "queries": queries, "capture_route": route_record,
            "runtime_observation": observed, "missing": missing,
            "unverified": list(UNVERIFIED)}
