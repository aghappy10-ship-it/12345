"""Interpret supplied saved-readout bytes, never acquire or qualify a device.

The result is an offline partial inventory. Recorded text and matching hashes
are not authenticated observations, current state, execution authority, a lease,
or proof that a sensor configuration was applied. No path or command in an input
is opened or executed. The historical transport and its parser are not imported.
"""
import hashlib
import json
import re
from datetime import datetime

from .runtime_observation import ENVIRONMENT_FIELDS, PROCESS_FIELDS

MAX_BYTES = 1024 * 1024
MAX_RECORD_BYTES = 96 * 1024
MAX_TEXT_BYTES = 64 * 1024
MAX_RECORDS = 128
_TOP = {"schema", "startedUtc", "transportSha256", "collectorSha256", "endpoint",
        "cameraWritten", "captureTriggered", "installable", "status", "queries", "output"}
_QUERY = {"name", "command", "shellLastExitCode", "text", "receive", "validatedReceivedPacketCount",
          "relayTailsFullyExplained", "retainedPacketsSha256", "rawReceivedSha256", "rawReceivedBytes"}
# Exact existing single-command records only. Do not split/execute arbitrary
# shell text or import the network collector to discover more commands.
_HASH_QUERIES = {
    "gui_hash": (("/system/bin/camera-gui", "gui.artifact"),
                 ("/system/etc/init/camera-gui.rc", None)),
    "service_hash": (("/system/bin/camera-service", "service.artifact"),
                     ("/system/etc/imx861bqr_hb722.conf", "sensor")),
}


def _need(condition, reason):
    if not condition:
        raise ValueError("saved readout: " + reason)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        _need(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def _nonfinite(value):
    raise ValueError("saved readout: nonfinite JSON number")


def _text(value, limit):
    return type(value) is str and len(value.encode("utf-8")) <= limit


def _hash(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _load(raw):
    _need(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, "bounded immutable bytes required")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_nonfinite)
        _need(type(document) is dict and _TOP <= set(document)
              and set(document) <= _TOP | {"finishedUtc", "replyDecoderSha256"}, "report fields differ")
        _need(document["schema"] == "x2dii-menu-readonly-readout-v1", "unsupported schema")
        _need(document["status"] in ("INCOMPLETE", "TRANSPORT_OR_VALIDATION_FAILURE",
                                      "FIXED_READOUT_COMPLETE_NOT_QUALIFICATION"), "unknown report status")
        _need(all(document[key] is False for key in ("cameraWritten", "captureTriggered", "installable")),
              "read-only non-installable report flags required")
        _need(document["endpoint"] == "192.168.42.2:30303" and _text(document["output"], 4096),
              "unsupported endpoint or output label")
        for key in ("transportSha256", "collectorSha256", "replyDecoderSha256"):
            _need(key not in document or _hash(document[key]), "invalid producer hash")
        times = []
        for key in ("startedUtc", "finishedUtc"):
            if key in document:
                _need(_text(document[key], 64), "invalid timestamp type")
                stamp = datetime.fromisoformat(document[key])
                _need(stamp.tzinfo is not None, "timestamp needs timezone")
                times.append(stamp)
        _need(len(times) < 2 or times[0] <= times[1], "conflicting acquisition times")
        queries = document["queries"]
        _need(type(queries) is dict and len(queries) <= MAX_RECORDS, "bounded query dictionary required")
        for index, (source, record) in enumerate(queries.items(), 1):
            match = re.fullmatch(r"([0-9]{3})-([a-z][a-z0-9_]{0,63})", source)
            _need(match is not None and int(match[1]) == index, "ambiguous query sequence/source")
            _need(type(record) is dict, "query record must be an object")
            encoded = json.dumps(record, ensure_ascii=False, allow_nan=False).encode("utf-8")
            _need(len(encoded) <= MAX_RECORD_BYTES, "query record exceeds bound")
            if "error" in record:
                _need(set(record) <= {"error", "receive"} and _text(record["error"], MAX_TEXT_BYTES),
                      "ambiguous error record")
                _need("receive" not in record or type(record["receive"]) is dict, "invalid receive metadata")
                continue
            _need(set(record) == _QUERY, "query fields differ")
            _need(record["name"] == match[2], "query name/source conflict")
            _need(_text(record["command"], 4096) and _text(record["text"], MAX_TEXT_BYTES),
                  "query command/text type or bound")
            code = record["shellLastExitCode"]
            _need(type(code) is int and 0 <= code <= 255, "invalid query exit status")
            _need(type(record["receive"]) is dict and type(record["relayTailsFullyExplained"]) is bool,
                  "invalid query receive metadata")
            _need(all(type(record[key]) is int and 0 <= record[key] < 2**63
                      for key in ("validatedReceivedPacketCount", "rawReceivedBytes")), "invalid byte/packet count")
            _need(all(_hash(record[key]) for key in ("retainedPacketsSha256", "rawReceivedSha256")),
                  "invalid retained-byte hash")
        return document
    except (ValueError, UnicodeError, RecursionError) as error:
        if isinstance(error, ValueError) and str(error).startswith("saved readout:"):
            raise
        raise ValueError("saved readout: invalid JSON, encoding, or record value") from error


def _fields():
    names = ["schema", "test_fixture_only", *ENVIRONMENT_FIELDS]
    for component in ("gui", "service", "capture_owner"):
        names.append(component + ".state")
        names.extend(component + ".artifact." + key for key in ("state", "path", "sha256", "bytes"))
        names.extend(component + ".process." + key for key in PROCESS_FIELDS)
        if component == "capture_owner":
            names.extend(component + ".route." + key for key in ("identity", "evidence_file", "evidence_sha256"))
        else:
            names.append(component + ".service_state")
    names.extend("sensor." + key for key in ("state", "path", "sha256", "bytes"))
    return {name: {"status": "UNKNOWN", "value": None, "sources": []} for name in names}


def _record_value(field, value, source):
    if field["status"] == "UNKNOWN":
        field.update(status="RECORDED", value=value, sources=[source])
        return
    if field["status"] == "RECORDED" and field["value"] != value:
        field["candidates"] = [{"value": field["value"], "sources": field["sources"].copy()}]
        field.update(status="CONFLICT", value=None)
    field["sources"].append(source)
    if field["status"] == "CONFLICT":
        for candidate in field["candidates"]:
            if candidate["value"] == value:
                candidate["sources"].append(source)
                break
        else:
            field["candidates"].append({"value": value, "sources": [source]})


def summarize_readout(raw):
    """Summarize one existing v1 READOUT.json supplied as bytes, without I/O.

    Input limits: 1 MiB total, 128 sequential query records, 96 KiB per normalized
    JSON record and 64 KiB decoded UTF-8 text. Metadata and times are only recorded
    claims; this function does not check freshness or authenticate producers.
    Malformed/ambiguous input raises ValueError, never produces a qualification.
    """
    document = _load(raw)
    fields, queries = _fields(), {}
    for source, record in document["queries"].items():
        row = {"status": "RECORDED_UNINTERPRETED", "exit_scope": "LAST_SHELL_COMMAND_ONLY",
               "record": record,
               "record_canonical_sha256": hashlib.sha256(json.dumps(
                   record, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                   allow_nan=False).encode("utf-8")).hexdigest()}
        queries[source] = row
        if "error" in record:
            row.update(status="RECORDED_QUERY_ERROR", exit_scope="NOT_RECORDED")
            continue
        if record["shellLastExitCode"] != 0:
            row["status"] = "RECORDED_QUERY_FAILURE"
            continue
        paths = _HASH_QUERIES.get(record["name"])
        if paths is None or record["command"] != "sha256sum " + " ".join(path for path, _ in paths):
            continue
        row["exit_scope"] = "ONE_FIXED_SHA256SUM_COMMAND"
        pattern = "".join(r"([0-9a-f]{64})  " + re.escape(path) + r"\r?\n" for path, _ in paths)
        parsed = re.fullmatch(pattern, record["text"])
        if parsed is None:
            row["status"] = "MALFORMED_HASH_OUTPUT"
            continue
        row["status"] = "RECORDED_DISK_HASHES"
        for index, (path, prefix) in enumerate(paths, 1):
            if prefix is not None:
                _record_value(fields[prefix + ".path"], path, source)
                _record_value(fields[prefix + ".sha256"], parsed[index], source)
    return {"schema": "x2dii-offline-observation-summary-v1",
            "status": "LOCAL_PARTIAL_OBSERVATION_NOT_QUALIFICATION", "installable": False,
            "source": {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
                       "recorded_metadata": {key: value for key, value in document.items() if key != "queries"}},
            "queries": queries, "fields": fields,
            "missing": [name for name, field in fields.items() if field["status"] != "RECORDED"],
            "unverified": ["input_authenticity", "current_runtime_identity", "applied_sensor_state",
                           "actual_capture_route", "qualification_and_authority"]}
