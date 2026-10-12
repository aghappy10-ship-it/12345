"""Synthetic text-result fixtures for the no-I/O supplied-observation producer."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest


GUI_HASH = "a" * 64
SERVICE_HASH = "51b9e02f8bfebf388be8dfa163c8e512bee19aeb8ae37a6712727ccc6f26a52d"
SENSOR_HASH = "4d1db41c60d3eac1f989110de15335c91798bcca972e475558365d1989e49f6e"


@pytest.fixture
def producer():
    from tools.observation_producer import assemble_supplied_observation

    return assemble_supplied_observation


def document():
    return {"schema": "x2dii-supplied-query-observations-v1", "test_fixture_only": True,
            "before": [], "observations": [], "after": [], "capture_route": None}


def encoded(value):
    return json.dumps(value, ensure_ascii=False).encode("utf-8")


def row(source, field, text, code=0):
    return {"source_id": source, "field": field, "stdout": text, "exit_code": code}


def complete_document():
    value = document()
    identity = {"boot_id": "11111111-2222-4333-8444-555555555555", "active_slot": "slot_2",
                "official_slot": "slot_1", "mount_namespace": "mnt:[123]", "init_mount_namespace": "mnt:[123]"}
    processes = {}
    for role, pid, target, digest in (
        ("observer", 100, "/system/bin/adbd", "1" * 64),
        ("gui", 234, "/system/bin/camera-gui", GUI_HASH),
        ("service", 345, "/system/bin/camera-service", SERVICE_HASH),
        ("capture_owner", 456, "/system/bin/capture-owner", "e" * 64),
    ):
        process = {"pid": pid, "start_ticks": str(pid * 100), "exe_target": target,
                   "exe_sha256": digest, "domain": "u:r:hbl_camera_service:s0", "mount_namespace": "mnt:[123]"}
        processes[role] = process
        identity.update({role + ".process." + key: str(item) for key, item in process.items()})
        identity[role + ".process.exe_sha256"] = digest + "  /proc/" + str(pid) + "/exe"
    value["before"] = [row("before-" + field, field, str(item)) for field, item in identity.items()]
    value["after"] = [row("after-" + field, field, str(item) + "\r\n") for field, item in identity.items()]
    observations = {}
    for role in ("gui", "service", "capture_owner"):
        observations.update({role + ".state": "present", role + ".artifact.state": "present",
                             role + ".artifact.path": processes[role]["exe_target"],
                             role + ".artifact.sha256": processes[role]["exe_sha256"] + "  " + processes[role]["exe_target"],
                             role + ".artifact.bytes": "1234"})
        if role != "capture_owner":
            observations[role + ".service_state"] = "running"
    observations.update({"sensor.state": "present", "sensor.path": "/system/etc/imx861bqr_hb722.conf",
                         "sensor.sha256": SENSOR_HASH + "  /system/etc/imx861bqr_hb722.conf", "sensor.bytes": "4321"})
    value["observations"] = [row("observed-" + field, field, item + "\n") for field, item in observations.items()]
    for phase in ("before", "after"):
        value[phase].extend(row(phase + "-" + field, field, item + "\n") for field, item in observations.items()
                            if field.endswith((".sha256", ".bytes")))
    route = encoded({"schema": "x2dii-supplied-capture-route-v1", "test_fixture_only": True,
                     "boot_id": identity["boot_id"], "owner": processes["capture_owner"],
                     "identity": "SYNTHETIC independent capture-owner route; not actual capture"})
    value["capture_route"] = {"reference": "build/synthetic-route/route.json",
                              "raw_utf8": route.decode(), "sha256": hashlib.sha256(route).hexdigest()}
    return value


def test_missing_queries_remain_unknown_without_inventing_runtime(producer):
    raw = encoded(document())
    result = producer(raw, GUI_HASH)
    assert result["runtime_observation"] is None
    assert result["status"] == "LOCAL_PARTIAL_SUPPLIED_OBSERVATION"
    assert result["installable"] is False
    assert result["source"]["sha256"] == hashlib.sha256(raw).hexdigest()
    assert "before.official_slot" in result["missing"]
    assert "observations.sensor.sha256" in result["missing"]
    assert "capture_route" in result["missing"]
    assert result["queries"] == {}
    assert "input_authenticity_and_single_query_execution" in result["unverified"]


def test_complete_individually_statused_text_yields_only_a_structurally_normalized_observation(producer):
    from tools.runtime_observation import normalize_observation

    supplied = complete_document()
    before = deepcopy(supplied)
    raw = encoded(supplied)
    result = producer(raw, GUI_HASH)
    observation = result["runtime_observation"]
    assert result["status"] == "STRUCTURALLY_NORMALIZED_SUPPLIED_DATA_ONLY"
    assert result["missing"] == [] and result["installable"] is False
    assert observation["test_fixture_only"] is True
    assert observation["capture_owner"]["process"]["pid"] == 456
    assert observation["service"]["process"]["pid"] == 345
    assert observation["official_slot"] == "slot_1"
    context = {key: observation[key] for key in ("boot_id", "active_slot", "official_slot",
                                                "mount_namespace", "init_mount_namespace")}
    assert normalize_observation({**context, "runtime_observation": observation}, GUI_HASH) == observation
    source = result["queries"]["before-gui.process.domain"]
    assert source["record"]["stdout"] == "u:r:hbl_camera_service:s0"
    assert source["stdout_sha256"] == hashlib.sha256(b"u:r:hbl_camera_service:s0").hexdigest()
    assert source["value"] == "u:r:hbl_camera_service:s0"
    assert supplied == before
    assert not any(key in result for key in ("approval", "lease", "gates", "synthetic", "q"))


@pytest.mark.parametrize("fault", ["individual_failure", "boolean_exit", "boot_drift", "pid_reuse",
                                  "source_reused", "field_conflict", "extra_field", "missing_owner",
                                  "missing_official_slot", "unknown_artifact"])
def test_individual_status_and_identity_are_not_replaced_by_later_success(producer, fault):
    supplied = complete_document()
    if fault in ("individual_failure", "boolean_exit"):
        supplied["before"][0]["exit_code"] = 7 if fault == "individual_failure" else False
    elif fault in ("boot_drift", "pid_reuse"):
        key = "boot_id" if fault == "boot_drift" else "gui.process.start_ticks"
        next(r for r in supplied["after"] if r["field"] == key)["stdout"] = (
            "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee\n" if fault == "boot_drift" else "99999\n")
    elif fault == "source_reused":
        supplied["after"][0]["source_id"] = supplied["before"][0]["source_id"]
    elif fault == "field_conflict":
        supplied["before"].append(row("other-boot", "boot_id", "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"))
    elif fault == "extra_field":
        supplied["observations"].append(row("unknown-query", "applied_sensor_state", "verified"))
    elif fault in ("missing_owner", "missing_official_slot"):
        key = "capture_owner.process." if fault == "missing_owner" else "official_slot"
        for phase in ("before", "after"):
            supplied[phase] = [r for r in supplied[phase] if not r["field"].startswith(key)]
        result = producer(encoded(supplied), GUI_HASH)
        assert result["runtime_observation"] is None
        assert any(key in missing for missing in result["missing"])
        return
    else:
        next(r for r in supplied["observations"] if r["field"] == "sensor.state")["stdout"] = "unknown\n"
        result = producer(encoded(supplied), GUI_HASH)
        assert result["runtime_observation"] is None
        assert "observations.sensor.state" in result["missing"]
        return
    with pytest.raises(ValueError, match="supplied observation"):
        producer(encoded(supplied), GUI_HASH)


@pytest.mark.parametrize("fault", ["hash", "boot", "owner_lifetime", "fixture_marker", "extra_field"])
def test_capture_route_bytes_must_bind_the_supplied_boot_and_full_independent_owner(producer, fault):
    supplied = complete_document()
    route = supplied["capture_route"]
    body = json.loads(route["raw_utf8"])
    if fault == "hash":
        route["sha256"] = "f" * 64
    else:
        if fault == "boot":
            body["boot_id"] = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        elif fault == "owner_lifetime":
            body["owner"]["start_ticks"] = "99999"
        elif fault == "fixture_marker":
            body["test_fixture_only"] = False
        else:
            body["capture_proven"] = True
        content = encoded(body)
        route.update(raw_utf8=content.decode(), sha256=hashlib.sha256(content).hexdigest())
    with pytest.raises(ValueError, match="supplied observation"):
        producer(encoded(supplied), GUI_HASH)


def test_matching_repeated_facts_retain_all_sources_and_exact_route_bytes(producer):
    supplied = complete_document()
    repeated = deepcopy(supplied["before"][0])
    repeated["source_id"] = "independent-repeat"
    repeated["stdout"] += "\n"
    supplied["before"].append(repeated)
    result = producer(encoded(supplied), GUI_HASH)
    assert result["queries"]["independent-repeat"]["value"] == result["queries"]["before-boot_id"]["value"]
    assert result["queries"]["independent-repeat"]["stdout_sha256"] != result["queries"]["before-boot_id"]["stdout_sha256"]
    assert result["capture_route"]["record"] == supplied["capture_route"]
    assert result["capture_route"]["raw_sha256"] == supplied["capture_route"]["sha256"]


@pytest.mark.parametrize("fault", ["mutable", "oversize", "deep", "duplicate_json", "top_extra",
                                  "wrong_schema", "marker_integer", "row_extra", "too_many",
                                  "stdout_bound", "multiline", "empty", "bad_scalar", "leading_space",
                                  "route_bound", "route_traversal"])
def test_ambiguous_or_unbounded_supplied_text_is_rejected_even_when_partial(producer, fault):
    supplied = document()
    supplied["before"] = [row("one-boot", "boot_id", "11111111-2222-4333-8444-555555555555")]
    raw = None
    if fault == "mutable":
        raw = bytearray(encoded(supplied))
    elif fault == "oversize":
        raw = b" " * (1024 * 1024 + 1)
    elif fault == "deep":
        raw = b"[" * 2000 + b"0" + b"]" * 2000
    elif fault == "duplicate_json":
        raw = encoded(supplied).replace(b'"schema":', b'"schema":"duplicate","schema":', 1)
    elif fault == "top_extra":
        supplied["commands"] = []
    elif fault == "wrong_schema":
        supplied["schema"] = "x2dii-menu-readonly-readout-v1"
    elif fault == "marker_integer":
        supplied["test_fixture_only"] = 1
    elif fault == "row_extra":
        supplied["before"][0]["value"] = "already-decoded"
    elif fault == "too_many":
        supplied["before"] = [row(f"boot-{index}", "boot_id", supplied["before"][0]["stdout"]) for index in range(129)]
    elif fault == "stdout_bound":
        supplied["before"][0]["stdout"] = "x" * 4097
    elif fault == "multiline":
        supplied["before"][0]["stdout"] += "\n\n"
    elif fault == "empty":
        supplied["before"][0]["stdout"] = ""
    elif fault == "bad_scalar":
        supplied["before"][0]["stdout"] = "not-a-boot-id"
    elif fault == "leading_space":
        supplied["before"][0]["stdout"] = " " + supplied["before"][0]["stdout"]
    else:
        supplied["capture_route"] = complete_document()["capture_route"]
        if fault == "route_bound":
            supplied["capture_route"]["raw_utf8"] += " " * (32 * 1024)
            supplied["capture_route"]["sha256"] = hashlib.sha256(supplied["capture_route"]["raw_utf8"].encode()).hexdigest()
        else:
            supplied["capture_route"]["reference"] = "build/../outside.json"
    with pytest.raises(ValueError, match="supplied observation"):
        producer(encoded(supplied) if raw is None else raw, GUI_HASH)


@pytest.mark.parametrize("field,bad_path", [("gui.process.exe_sha256", "/proc/235/exe"),
                                         ("gui.artifact.sha256", "/system/bin/unrelated")])
def test_hash_command_output_must_name_the_explicit_process_or_artifact(producer, field, bad_path):
    supplied = complete_document()
    phase = "before" if ".process." in field else "observations"
    record = next(r for r in supplied[phase] if r["field"] == field)
    record["stdout"] = GUI_HASH + "  " + bad_path + "\n"
    with pytest.raises(ValueError, match="supplied observation.*hash output path"):
        producer(encoded(supplied), GUI_HASH)


@pytest.mark.parametrize("fault", ["same_pid", "namespace", "same_slots", "same_artifact", "process_disk_hash"])
def test_partial_input_cannot_hide_already_observed_contradictions(producer, fault):
    supplied = document()
    if fault == "same_pid":
        supplied["before"] = [row("g-pid", "gui.process.pid", "234"),
                              row("s-pid", "service.process.pid", "234"),
                              row("g-life", "gui.process.start_ticks", "23400"),
                              row("s-life", "service.process.start_ticks", "23401")]
    elif fault == "namespace":
        supplied["before"] = [row("ns", "mount_namespace", "mnt:[123]"),
                              row("init-ns", "init_mount_namespace", "mnt:[124]")]
    elif fault == "same_slots":
        supplied["before"] = [row("active", "active_slot", "slot_2"),
                              row("official", "official_slot", "slot_2")]
    elif fault == "same_artifact":
        supplied["observations"] = [row("s-path", "service.artifact.path", "/system/bin/camera-service"),
                                    row("c-path", "capture_owner.artifact.path", "/system/bin/camera-service"),
                                    row("s-size", "service.artifact.bytes", "1234"),
                                    row("c-size", "capture_owner.artifact.bytes", "1235")]
    else:
        supplied["before"] = [row("g-pid", "gui.process.pid", "234"),
                              row("g-hash", "gui.process.exe_sha256", GUI_HASH + "  /proc/234/exe")]
        supplied["observations"] = [row("g-disk", "gui.artifact.sha256", "b" * 64 + "  /system/bin/camera-gui")]
    with pytest.raises(ValueError, match="supplied observation.*conflict"):
        producer(encoded(supplied), GUI_HASH)


def test_producer_uses_only_supplied_bytes_and_never_promotes_fixture_false(producer, monkeypatch):
    import builtins
    import socket
    import subprocess

    supplied = complete_document()
    supplied["test_fixture_only"] = False
    route = json.loads(supplied["capture_route"]["raw_utf8"])
    route["test_fixture_only"] = False
    content = encoded(route)
    supplied["capture_route"].update(raw_utf8=content.decode(), sha256=hashlib.sha256(content).hexdigest())
    raw = encoded(supplied)

    def forbidden(*args, **kwargs):
        pytest.fail("producer attempted external I/O")

    for target, name in ((builtins, "open"), (Path, "open"), (socket, "socket"),
                         (socket, "create_connection"), (subprocess, "run"), (subprocess, "Popen")):
        monkeypatch.setattr(target, name, forbidden)
    result = producer(raw, GUI_HASH)
    assert result["runtime_observation"]["test_fixture_only"] is False
    assert result["status"] == "STRUCTURALLY_NORMALIZED_SUPPLIED_DATA_ONLY"
    assert result["installable"] is False
    assert "sampling_time_and_freshness" in result["unverified"]
    assert "official_slot_physical_integrity" in result["unverified"]
    assert raw == encoded(supplied)


@pytest.mark.parametrize("field", ["gui.artifact.sha256", "service.artifact.bytes", "sensor.sha256",
                                 "capture_owner.artifact.bytes"])
def test_independently_supplied_artifact_identity_drift_is_rejected(producer, field):
    supplied = complete_document()
    record = next(r for r in supplied["after"] if r["field"] == field)
    record["stdout"] = "9999\n" if field.endswith(".bytes") else "f" * 64 + record["stdout"][64:]
    with pytest.raises(ValueError, match="supplied observation.*identity changed between samples"):
        producer(encoded(supplied), GUI_HASH)


def test_sampled_capture_hash_cannot_name_a_different_file_with_identical_bytes(producer):
    supplied = complete_document()
    for phase in ("before", "after"):
        record = next(r for r in supplied[phase] if r["field"] == "capture_owner.artifact.sha256")
        record["stdout"] = "e" * 64 + "  /system/bin/not-capture-owner\n"
    with pytest.raises(ValueError, match="supplied observation.*hash output path"):
        producer(encoded(supplied), GUI_HASH)


def test_exact_total_and_query_limits_preserve_missing_data_without_promotion(producer):
    supplied = document()
    supplied["before"] = [row(f"boot-{index}", "boot_id", "11111111-2222-4333-8444-555555555555")
                          for index in range(128)]
    raw = encoded(supplied)
    raw += b" " * (1024 * 1024 - len(raw))
    result = producer(raw, GUI_HASH)
    assert result["source"]["bytes"] == 1024 * 1024
    assert len(result["queries"]) == 128
    assert result["runtime_observation"] is None
    assert "before.official_slot" in result["missing"]


@pytest.mark.parametrize("changed", [False, True])
def test_partial_same_pid_identity_is_checked_across_roles_and_samples_without_filling_gaps(producer, changed):
    supplied = document()
    for phase in ("before", "after"):
        supplied[phase] = [row(phase + "-boot", "boot_id", "11111111-2222-4333-8444-555555555555"),
                           row(phase + "-observer", "observer.process.pid", "234"),
                           row(phase + "-gui", "gui.process.pid", "234")]
    supplied["before"].append(row("before-lifetime", "observer.process.start_ticks", "100"))
    supplied["after"].append(row("after-lifetime", "gui.process.start_ticks", "101" if changed else "100"))
    if changed:
        with pytest.raises(ValueError, match="supplied observation.*conflicting.*PID.*samples"):
            producer(encoded(supplied), GUI_HASH)
    else:
        result = producer(encoded(supplied), GUI_HASH)
        assert result["runtime_observation"] is None
        assert "before.gui.process.start_ticks" in result["missing"]
        assert "after.observer.process.start_ticks" in result["missing"]
