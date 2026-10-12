"""Saved scalar-query data only; no collector, wire fixture or camera access."""
from copy import deepcopy
import hashlib
import json

import pytest


SIX = (
    ("single_boot_id", "cat /proc/sys/kernel/random/boot_id", "11111111-2222-4333-8444-555555555555"),
    ("single_gui_pid", "pidof camera-gui", "234"),
    ("single_service_pid", "pidof camera-service", "345"),
    ("single_gui_hash", "sha256sum /system/bin/camera-gui", "a" * 64 + "  /system/bin/camera-gui"),
    ("single_service_hash", "sha256sum /system/bin/camera-service", "b" * 64 + "  /system/bin/camera-service"),
    ("single_sensor_hash", "sha256sum /system/etc/imx861bqr_hb722.conf", "c" * 64 + "  /system/etc/imx861bqr_hb722.conf"),
)


def saved_document():
    queries = {}
    for index, (name, command, text) in enumerate((*SIX, *SIX[3:], *SIX), 1):
        queries[f"{index:03d}-{name}"] = {
            "name": name, "command": command, "shellLastExitCode": 0,
            "text": text + ("\r\n" if index % 3 == 0 else "\n" if index % 3 == 1 else ""),
            "receive": {"recorded_only": "external acquisition claim"},
            "validatedReceivedPacketCount": 1, "relayTailsFullyExplained": False,
            "retainedPacketsSha256": "1" * 64, "rawReceivedSha256": "2" * 64, "rawReceivedBytes": 1024}
    return {"schema": "x2dii-menu-readonly-readout-v1", "startedUtc": "2026-10-04T00:00:00+00:00",
            "finishedUtc": "2026-10-04T00:00:15+00:00", "transportSha256": "3" * 64,
            "collectorSha256": "4" * 64, "endpoint": "192.168.42.2:30303", "cameraWritten": False,
            "captureTriggered": False, "installable": False, "status": "FIXED_READOUT_COMPLETE_NOT_QUALIFICATION",
            "queries": queries, "output": "recorded-label-not-opened"}


def encoded(value):
    return json.dumps(value, ensure_ascii=False).encode("utf-8")


def test_exact_fixed_saved_sequence_preserves_raw_records_and_only_fifteen_partial_fields():
    from tools.observation_query_bridge import assemble_single_query_readout

    document = saved_document()
    original = deepcopy(document)
    raw = encoded(document)
    result = assemble_single_query_readout(raw, "a" * 64, test_fixture_only=True)
    assert result["runtime_observation"] is None and result["installable"] is False
    assert result["status"] == "LOCAL_PARTIAL_READOUT_BRIDGE_NOT_QUALIFICATION"
    assert result["source"]["sha256"] == hashlib.sha256(raw).hexdigest()
    assert result["source"]["bytes"] == len(raw)
    assert result["source"]["recorded_metadata"]["transportSha256"] == "3" * 64
    converted = result["supplied_observation"]
    assert len(converted["queries"]) == 15 and len(converted["missing"]) == 81
    assert converted["runtime_observation"] is None and converted["installable"] is False
    assert converted["source"]["test_fixture_only"] is True
    assert "before.official_slot" in converted["missing"]
    assert "capture_route" in converted["missing"]
    assert converted["queries"]["002-single_gui_pid"]["value"] == 234
    assert converted["queries"]["007-single_gui_hash"]["phase"] == "observations"
    assert converted["queries"]["010-single_boot_id"]["phase"] == "after"
    for source, record in document["queries"].items():
        assert result["readout"]["queries"][source]["record"] == record
        assert result["readout"]["queries"][source]["record_canonical_sha256"] == hashlib.sha256(
            json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()
        assert converted["queries"][source]["record"]["source_id"] == source
        assert converted["queries"][source]["record"]["stdout"] == record["text"]
        assert converted["queries"][source]["record"]["exit_code"] == record["shellLastExitCode"]
    assert "input_authenticity" in result["unverified"]
    assert "sampling_time_and_freshness" in result["unverified"]
    assert "saved_status_and_completion_marker_claims_not_authenticated" in result["unverified"]
    assert document == original


@pytest.mark.parametrize("damage", ["missing", "extra", "renamed", "reordered", "command", "old_composite", "error"])
def test_bridge_rejects_nonexact_saved_sequence_without_selecting_successful_records(damage):
    from tools.observation_query_bridge import assemble_single_query_readout

    document = saved_document()
    pairs = list(document["queries"].items())
    if damage == "missing":
        pairs.pop()
    elif damage == "extra":
        pairs.append(("016-single_boot_id", deepcopy(pairs[0][1])))
    elif damage == "renamed":
        pairs[0] = ("001-renamed_boot_id", {**pairs[0][1], "name": "renamed_boot_id"})
    elif damage == "reordered":
        pairs[0], pairs[1] = pairs[1], pairs[0]
        pairs = [(f"{index:03d}-" + record["name"], record) for index, (_, record) in enumerate(pairs, 1)]
    elif damage == "command":
        pairs[0][1]["command"] += ";true"
    elif damage == "old_composite":
        pairs[0] = ("001-identity", {**pairs[0][1], "name": "identity",
                    "command": "id;cat /proc/self/attr/current;getprop ro.product.model;getprop ro.dji.build.version;cat /proc/sys/kernel/random/boot_id"})
    else:
        pairs[0] = (pairs[0][0], {"error": "recorded acquisition failure"})
    document["queries"] = dict(pairs)
    with pytest.raises(ValueError, match="single-query bridge"):
        assemble_single_query_readout(encoded(document), "a" * 64, test_fixture_only=True)


@pytest.mark.parametrize("index", range(15))
def test_every_individual_nonzero_status_is_rejected_even_with_later_success(index):
    from tools.observation_query_bridge import assemble_single_query_readout

    document = saved_document()
    record = list(document["queries"].values())[index]
    record["shellLastExitCode"] = 7
    with pytest.raises(ValueError, match="single-query bridge.*individual query status"):
        assemble_single_query_readout(encoded(document), "a" * 64, test_fixture_only=True)


@pytest.mark.parametrize("damage", ["incomplete", "failed", "unfinished"])
def test_complete_individual_rows_do_not_override_failed_or_unfinished_report(damage):
    from tools.observation_query_bridge import assemble_single_query_readout

    document = saved_document()
    if damage == "unfinished":
        del document["finishedUtc"]
    else:
        document["status"] = "INCOMPLETE" if damage == "incomplete" else "TRANSPORT_OR_VALIDATION_FAILURE"
    with pytest.raises(ValueError, match="single-query bridge.*completed saved report"):
        assemble_single_query_readout(encoded(document), "a" * 64, test_fixture_only=True)


@pytest.mark.parametrize("index", [3, 4, 5, 6, 7, 8, 12, 13, 14])
def test_each_original_hash_record_requires_its_exact_named_disk_path(index):
    from tools.observation_query_bridge import assemble_single_query_readout

    document = saved_document()
    record = list(document["queries"].values())[index]
    record["text"] = record["text"][:64] + "  /system/bin/other\n"
    with pytest.raises(ValueError, match="hash output path differs"):
        assemble_single_query_readout(encoded(document), "a" * 64, test_fixture_only=True)


@pytest.mark.parametrize("index", range(6, 15))
def test_middle_hash_and_every_after_sample_must_not_drift_from_before(index):
    from tools.observation_query_bridge import assemble_single_query_readout

    document = saved_document()
    record = list(document["queries"].values())[index]
    if index == 9:
        record["text"] = "22222222-2222-4333-8444-555555555555\n"
    elif index in (10, 11):
        record["text"] = "456\n"
    else:
        record["text"] = "d" * 64 + record["text"][64:]
    with pytest.raises(ValueError, match="identity changed between samples|conflicting sampled disk identity"):
        assemble_single_query_readout(encoded(document), "a" * 64, test_fixture_only=True)


@pytest.mark.parametrize("damage", ["duplicate", "boolean_status", "write_claim", "oversized", "schema"])
def test_saved_v1_validation_still_precedes_conversion(damage):
    from tools.observation_query_bridge import assemble_single_query_readout

    document = saved_document()
    if damage == "boolean_status":
        document["queries"]["001-single_boot_id"]["shellLastExitCode"] = False
    elif damage == "write_claim":
        document["cameraWritten"] = True
    elif damage == "schema":
        document["schema"] = "unrecognized"
    raw = encoded(document)
    if damage == "duplicate":
        raw = raw.replace(b'{"schema":', b'{"schema":"duplicate","schema":', 1)
    elif damage == "oversized":
        raw += b" " * (1024 * 1024)
    with pytest.raises(ValueError, match="saved readout:"):
        assemble_single_query_readout(raw, "a" * 64, test_fixture_only=True)


@pytest.mark.parametrize("marker", [True, False])
def test_explicit_fixture_claim_never_qualifies_the_partial_saved_data(marker):
    from tools.observation_query_bridge import assemble_single_query_readout

    result = assemble_single_query_readout(encoded(saved_document()), "a" * 64, test_fixture_only=marker)
    assert result["runtime_observation"] is None and result["installable"] is False
    supplied = result["supplied_observation"]
    assert supplied["runtime_observation"] is None and supplied["installable"] is False
    assert supplied["source"]["test_fixture_only"] is marker
    assert len(result["missing"]) == 81 and "capture_route" in result["missing"]


@pytest.mark.parametrize("marker", [0, "false", None])
def test_fixture_marker_must_be_explicit_boolean(marker):
    from tools.observation_query_bridge import assemble_single_query_readout

    with pytest.raises(ValueError, match="explicit fixture marker required"):
        assemble_single_query_readout(encoded(saved_document()), "a" * 64, test_fixture_only=marker)


def test_supplied_bytes_are_interpreted_without_files_network_or_process_execution(monkeypatch):
    import builtins
    import io
    import os
    from pathlib import Path
    import socket
    import subprocess
    # Load normal pure dependencies before denying external system boundaries.
    from tools.observation_bundle import summarize_readout
    from tools.observation_producer import assemble_supplied_observation
    from tools.observation_query_bridge import assemble_single_query_readout

    raw = encoded(saved_document())

    def forbidden(*args, **kwargs):
        raise AssertionError("pure supplied-data bridge attempted external I/O")

    with monkeypatch.context() as isolated:
        for owner, names in ((builtins, ("open",)), (io, ("open",)), (os, ("open", "system")),
                             (Path, ("open", "read_bytes", "write_bytes", "read_text", "write_text")),
                             (socket, ("socket", "create_connection")), (subprocess, ("Popen",))):
            for name in names:
                isolated.setattr(owner, name, forbidden)
        result = assemble_single_query_readout(raw, "a" * 64, test_fixture_only=True)
    assert result["runtime_observation"] is None and len(result["missing"]) == 81


def test_existing_collector_table_exposes_only_the_fixed_scalar_command_contract():
    # Import and inspect the explicit table only; never query/collect/load transport.
    from tools.live_readout import QUERIES
    from tools.observation_query_bridge import SINGLE_QUERY_COMMANDS, SINGLE_QUERY_SEQUENCE

    expected = {name: command for name, command, _ in SIX}
    assert dict(SINGLE_QUERY_COMMANDS) == expected
    assert {name: QUERIES[name] for name in expected} == expected
    assert SINGLE_QUERY_SEQUENCE == (
        "single_boot_id", "single_gui_pid", "single_service_pid", "single_gui_hash", "single_service_hash", "single_sensor_hash",
        "single_gui_hash", "single_service_hash", "single_sensor_hash",
        "single_boot_id", "single_gui_pid", "single_service_pid", "single_gui_hash", "single_service_hash", "single_sensor_hash")
