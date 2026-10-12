"""Bridge supplied saved scalar-query records, never collect or qualify.

Six literal commands address only existing read-only objects. The sequence is
data for an explicit caller, not an automatic collection or command generator.
Matching command text and saved exit status do not authenticate execution,
completion framing, current identity, atomicity, or an actual capture route.
"""
import json
from types import MappingProxyType


SINGLE_QUERY_SPECS = (
    ("single_boot_id", "cat /proc/sys/kernel/random/boot_id", "boot_id"),
    ("single_gui_pid", "pidof camera-gui", "gui.process.pid"),
    ("single_service_pid", "pidof camera-service", "service.process.pid"),
    ("single_gui_hash", "sha256sum /system/bin/camera-gui", "gui.artifact.sha256"),
    ("single_service_hash", "sha256sum /system/bin/camera-service", "service.artifact.sha256"),
    ("single_sensor_hash", "sha256sum /system/etc/imx861bqr_hb722.conf", "sensor.sha256"),
)
SINGLE_QUERY_COMMANDS = MappingProxyType({name: command for name, command, _ in SINGLE_QUERY_SPECS})
SINGLE_QUERY_SEQUENCE = tuple(name for name, _, _ in (*SINGLE_QUERY_SPECS, *SINGLE_QUERY_SPECS[3:], *SINGLE_QUERY_SPECS))
_STEPS = tuple((phase, name, command, field) for phase, specs in (
    ("before", SINGLE_QUERY_SPECS), ("observations", SINGLE_QUERY_SPECS[3:]), ("after", SINGLE_QUERY_SPECS))
    for name, command, field in specs)


def _need(condition, reason):
    if not condition:
        raise ValueError("single-query bridge: " + reason)


def assemble_single_query_readout(raw: bytes, expected_gui_sha256, *, test_fixture_only: bool):
    """Convert only the explicit fixed sequence; keep all remaining gaps.

    Importing the command constants does not load any observation dependency,
    collector or transport, including the existing standalone collector path.
    The explicit fixture marker is a caller claim, never authentication.
    """
    from .observation_bundle import summarize_readout
    from .observation_producer import assemble_supplied_observation

    readout = summarize_readout(raw)
    metadata = readout["source"]["recorded_metadata"]
    _need(metadata["status"] == "FIXED_READOUT_COMPLETE_NOT_QUALIFICATION" and "finishedUtc" in metadata,
          "completed saved report with finish timestamp required")
    _need(list(readout["queries"]) == [f"{index:03d}-{name}" for index, name in enumerate(SINGLE_QUERY_SEQUENCE, 1)],
          "exact fixed fifteen-record sequence required")
    supplied = {"schema": "x2dii-supplied-query-observations-v1", "test_fixture_only": test_fixture_only,
                "before": [], "observations": [], "after": [], "capture_route": None}
    for (source, row), (phase, name, command, field) in zip(readout["queries"].items(), _STEPS):
        record = row["record"]
        _need("error" not in record, "saved query failure: " + source)
        _need(record["name"] == name and record["command"] == command, "fixed query name/command differs: " + source)
        _need(record["shellLastExitCode"] == 0, "nonzero individual query status: " + source)
        supplied[phase].append({"source_id": source, "field": field,
                                "stdout": record["text"], "exit_code": record["shellLastExitCode"]})
    result = assemble_supplied_observation(json.dumps(supplied, ensure_ascii=False).encode("utf-8"), expected_gui_sha256)
    return {"schema": "x2dii-single-query-readout-bridge-v1",
            "status": "LOCAL_PARTIAL_READOUT_BRIDGE_NOT_QUALIFICATION", "installable": False,
            "runtime_observation": None, "source": readout["source"], "readout": readout,
            "supplied_observation": result, "missing": result["missing"],
            "unverified": list(dict.fromkeys([*readout["unverified"], *result["unverified"],
                "saved_status_and_completion_marker_claims_not_authenticated"]))}
