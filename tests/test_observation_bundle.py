"""Offline saved-readout interpretation, never device or qualification evidence."""
import hashlib
import json

import pytest


def saved_readout(queries):
    return json.dumps({
        "schema": "x2dii-menu-readonly-readout-v1",
        "startedUtc": "2026-10-03T14:37:02+00:00",
        "finishedUtc": "2026-10-03T14:37:08+00:00",
        "transportSha256": "1" * 64,
        "collectorSha256": "2" * 64,
        "endpoint": "192.168.42.2:30303",
        "cameraWritten": False,
        "captureTriggered": False,
        "installable": False,
        "status": "FIXED_READOUT_COMPLETE_NOT_QUALIFICATION",
        "queries": queries,
        "output": "C:/untrusted/saved/path/not/to/be/opened",
    }).encode("utf-8")


def record(name, command, text, exit_code=0):
    return {"name": name, "command": command, "shellLastExitCode": exit_code,
            "text": text, "receive": {}, "validatedReceivedPacketCount": 1,
            "relayTailsFullyExplained": False, "retainedPacketsSha256": "3" * 64,
            "rawReceivedSha256": "4" * 64, "rawReceivedBytes": 1024}


def test_saved_identity_last_exit_does_not_qualify_earlier_commands_or_applied_sensor():
    from tools.observation_bundle import summarize_readout

    raw = saved_readout({
        "001-identity": record("identity", "id;cat /proc/self/attr/current;getprop ro.product.model;"
                               "getprop ro.dji.build.version;cat /proc/sys/kernel/random/boot_id",
                               "uid=0(root)\nu:r:su:s0\nmodel\nversion\n"
                               "c182e5d2-2e15-4c57-aa15-31d0dc7d9413\n"),
        "002-service_hash": record("service_hash", "sha256sum /system/bin/camera-service "
                                   "/system/etc/imx861bqr_hb722.conf",
                                   "a" * 64 + "  /system/bin/camera-service\n" +
                                   "b" * 64 + "  /system/etc/imx861bqr_hb722.conf\n"),
    })
    result = summarize_readout(raw)

    assert result["status"] == "LOCAL_PARTIAL_OBSERVATION_NOT_QUALIFICATION"
    assert result["installable"] is False
    assert result["source"]["sha256"] == hashlib.sha256(raw).hexdigest()
    assert result["queries"]["001-identity"]["status"] == "RECORDED_UNINTERPRETED"
    assert result["queries"]["001-identity"]["exit_scope"] == "LAST_SHELL_COMMAND_ONLY"
    assert result["fields"]["boot_id"]["value"] is None
    assert result["fields"]["service.artifact.sha256"] == {
        "status": "RECORDED", "value": "a" * 64, "sources": ["002-service_hash"]}
    assert result["fields"]["sensor.sha256"]["value"] == "b" * 64
    assert "sensor.bytes" in result["missing"]
    assert "capture_owner.process.pid" in result["missing"]
    assert "applied_sensor_state" in result["unverified"]
    assert "runtime_observation" not in result
    assert "gates" not in result and "lease" not in result and "approval" not in result


@pytest.mark.parametrize("fault", ["text-input", "mutable-input", "oversized-input", "bad-json",
    "duplicate-key", "wrong-schema", "wrong-query-type", "boolean-exit", "wrong-record-name",
    "nontext-output", "oversized-text", "oversized-record", "too-many-records", "false-provenance-flag",
    "bad-producer-hash", "nonfinite-number", "deep-json"])
def test_saved_readout_rejects_ambiguous_types_duplicates_and_unbounded_records(fault):
    from tools.observation_bundle import summarize_readout

    raw = saved_readout({"001-identity": record("identity", "id;cat /proc/self/attr/current", "untrusted\n")})
    document = json.loads(raw)
    row = document["queries"]["001-identity"]
    if fault == "text-input":
        raw = raw.decode()
    elif fault == "mutable-input":
        raw = bytearray(raw)
    elif fault == "oversized-input":
        raw = b" " * (1024 * 1024 + 1)
    elif fault == "bad-json":
        raw = b"["
    elif fault == "duplicate-key":
        raw = raw[:-1] + b', "queries": {}}'
    elif fault == "wrong-schema":
        document["schema"] = "qualified-observation"
    elif fault == "wrong-query-type":
        document["queries"] = []
    elif fault == "boolean-exit":
        row["shellLastExitCode"] = False
    elif fault == "wrong-record-name":
        row["name"] = "service_hash"
    elif fault == "nontext-output":
        row["text"] = 42
    elif fault == "oversized-text":
        row["text"] = "x" * (64 * 1024 + 1)
    elif fault == "oversized-record":
        row["receive"] = {"unparsed": "x" * (96 * 1024)}
    elif fault == "too-many-records":
        document["queries"] = {f"{i:03d}-identity": row for i in range(1, 130)}
    elif fault == "false-provenance-flag":
        document["installable"] = 0
    elif fault == "bad-producer-hash":
        document["collectorSha256"] = "not a hash"
    elif fault == "nonfinite-number":
        row["receive"] = {"elapsed_seconds": float("nan")}
    elif fault == "deep-json":
        raw = b"[" * 2000 + b"0" + b"]" * 2000
    if fault not in {"text-input", "mutable-input", "oversized-input", "bad-json", "duplicate-key", "deep-json"}:
        raw = json.dumps(document).encode()
    with pytest.raises(ValueError, match="saved readout"):
        summarize_readout(raw)


@pytest.mark.parametrize("changed", [False, True])
def test_repeated_queries_preserve_sources_and_conflicting_disk_hashes_never_pick_a_winner(changed):
    from tools.observation_bundle import summarize_readout

    command = "sha256sum /system/bin/camera-service /system/etc/imx861bqr_hb722.conf"
    first = record("service_hash", command, "a" * 64 + "  /system/bin/camera-service\n" +
                   "b" * 64 + "  /system/etc/imx861bqr_hb722.conf\n")
    second = record("service_hash", command, ("c" if changed else "a") * 64 +
                    "  /system/bin/camera-service\n" + "b" * 64 + "  /system/etc/imx861bqr_hb722.conf\n")
    result = summarize_readout(saved_readout({"001-service_hash": first, "002-service_hash": second,
                                              "003-service_hash": first}))
    service = result["fields"]["service.artifact.sha256"]
    assert service["sources"] == ["001-service_hash", "002-service_hash", "003-service_hash"]
    assert result["fields"]["sensor.sha256"]["sources"] == service["sources"]
    if changed:
        assert service["status"] == "CONFLICT" and service["value"] is None
        assert service["candidates"] == [
            {"value": "a" * 64, "sources": ["001-service_hash", "003-service_hash"]},
            {"value": "c" * 64, "sources": ["002-service_hash"]}]
        assert "service.artifact.sha256" in result["missing"]
    else:
        assert service["status"] == "RECORDED" and service["value"] == "a" * 64
        assert "service.artifact.sha256" not in result["missing"]
    assert result["source"]["recorded_metadata"]["collectorSha256"] == "2" * 64
    assert "replyDecoderSha256" not in result["source"]["recorded_metadata"]
    assert result["queries"]["001-service_hash"]["record"] == first


@pytest.mark.parametrize("case,expected_status", [
    ("gui", "RECORDED_DISK_HASHES"), ("nonzero", "RECORDED_QUERY_FAILURE"),
    ("error", "RECORDED_QUERY_ERROR"), ("malformed", "MALFORMED_HASH_OUTPUT"),
    ("changed-command", "RECORDED_UNINTERPRETED"),
])
def test_each_record_keeps_its_own_result_and_only_fixed_successful_hash_text_yields_fields(case, expected_status):
    from tools.observation_bundle import summarize_readout

    row = record("gui_hash", "sha256sum /system/bin/camera-gui /system/etc/init/camera-gui.rc",
                 "c" * 64 + "  /system/bin/camera-gui\n" + "d" * 64 +
                 "  /system/etc/init/camera-gui.rc\n")
    if case == "nonzero":
        row["shellLastExitCode"] = 2
    elif case == "error":
        row = {"error": "QueryFailure: retained old partial response", "receive": {"packet_count": 1}}
    elif case == "malformed":
        row["text"] += "unrelated trailing content\n"
    elif case == "changed-command":
        row["command"] += ";true"
    result = summarize_readout(saved_readout({"001-gui_hash": row}))
    interpreted = result["queries"]["001-gui_hash"]
    assert interpreted["status"] == expected_status
    assert interpreted["record"] == row
    assert len(interpreted["record_canonical_sha256"]) == 64
    if case == "gui":
        assert result["fields"]["gui.artifact.sha256"]["value"] == "c" * 64
        assert result["fields"]["gui.artifact.path"]["value"] == "/system/bin/camera-gui"
    else:
        assert result["fields"]["gui.artifact.sha256"]["status"] == "UNKNOWN"
    assert result["fields"]["gui.process.exe_sha256"]["status"] == "UNKNOWN"
    assert result["fields"]["gui.artifact.bytes"]["status"] == "UNKNOWN"


def test_summary_does_not_open_declared_paths_connect_run_commands_or_change_saved_bytes(monkeypatch):
    import builtins
    from pathlib import Path
    import socket
    import subprocess
    from tools.observation_bundle import summarize_readout

    # Literal legacy layout seen in run-dlje9f9h: attr/current has no LF,
    # so domain and model join. Preserve it; never guess field boundaries.
    row = record("identity", "id;cat /proc/self/attr/current;getprop ro.product.model;"
                 "getprop ro.dji.build.version;cat /proc/sys/kernel/random/boot_id",
                 "uid=0(root) gid=0(root) groups=0(root) context=u:r:hbl_camera_service:s0\n"
                 "u:r:hbl_camera_service:s0Android HB722 on Eagle2 HB722\n10.00.09.77\n"
                 "c182e5d2-2e15-4c57-aa15-31d0dc7d9413\n")
    row["receive"] = {"stop_reason": "completion_marker", "remote_termination_proven": False,
                      "resync_discarded_bytes": 3820}
    raw = saved_readout({"001-identity": row})
    original = bytes(raw)

    def forbidden(*args, **kwargs):
        pytest.fail("pure summarizer attempted filesystem, process or network I/O")

    for target, name in ((builtins, "open"), (Path, "open"), (socket, "create_connection"),
                         (socket, "socket"), (subprocess, "run"), (subprocess, "Popen")):
        monkeypatch.setattr(target, name, forbidden)
    result = summarize_readout(raw)
    assert raw == original
    assert result["queries"]["001-identity"]["record"]["receive"] == row["receive"]
    assert result["source"]["recorded_metadata"]["status"] == "FIXED_READOUT_COMPLETE_NOT_QUALIFICATION"
    assert all(field["status"] == "UNKNOWN" for field in result["fields"].values())
    assert result["unverified"][0] == "input_authenticity"


def test_exact_total_and_text_limits_are_accepted_without_interpreting_content():
    from tools.observation_bundle import summarize_readout

    raw = saved_readout({"001-identity": record("identity", "id;cat /proc/self/attr/current", "x" * 65536)})
    raw += b" " * (1048576 - len(raw))
    result = summarize_readout(raw)
    assert result["source"]["bytes"] == 1048576
    assert len(result["queries"]["001-identity"]["record"]["text"]) == 65536
    assert all(field["value"] is None for field in result["fields"].values())


@pytest.mark.parametrize("fault", ["duplicate-query-key", "duplicate-sequence", "unknown-root-field",
                                    "failure-success-mixed"])
def test_duplicate_or_mixed_source_identity_is_rejected_instead_of_silently_merged(fault):
    from tools.observation_bundle import summarize_readout

    row = record("identity", "id;cat /proc/self/attr/current", "recorded only\n")
    document = json.loads(saved_readout({"001-identity": row}))
    if fault == "duplicate-sequence":
        document["queries"]["001-other"] = {**row, "name": "other"}
    elif fault == "unknown-root-field":
        document["final_installation_approval"] = True
    elif fault == "failure-success-mixed":
        document["queries"]["001-identity"]["error"] = "partial receive"
    raw = json.dumps(document).encode()
    if fault == "duplicate-query-key":
        raw = raw.replace(b'"queries": {', b'"queries": {"001-identity": {}, ', 1)
    with pytest.raises(ValueError, match="saved readout"):
        summarize_readout(raw)


def test_empty_saved_acquisition_retains_all_required_fields_as_unknown():
    from tools.observation_bundle import summarize_readout

    document = json.loads(saved_readout({}))
    document["status"] = "INCOMPLETE"
    del document["finishedUtc"]
    result = summarize_readout(json.dumps(document).encode())
    assert result["queries"] == {}
    assert set(result["missing"]) == set(result["fields"])
    assert all(field == {"status": "UNKNOWN", "value": None, "sources": []}
               for field in result["fields"].values())


def test_crlf_hash_records_keep_original_text_and_only_record_disk_fields():
    from tools.observation_bundle import summarize_readout

    text = "a" * 64 + "  /system/bin/camera-service\r\n" + "b" * 64 + "  /system/etc/imx861bqr_hb722.conf\r\n"
    row = record("service_hash", "sha256sum /system/bin/camera-service /system/etc/imx861bqr_hb722.conf", text)
    result = summarize_readout(saved_readout({"001-service_hash": row}))
    assert result["queries"]["001-service_hash"]["record"]["text"] == text
    assert result["fields"]["service.artifact.sha256"]["value"] == "a" * 64
    assert result["fields"]["sensor.sha256"]["value"] == "b" * 64
    assert result["fields"]["service.process.exe_sha256"]["status"] == "UNKNOWN"
