"""Pure observation shape checks, not evidence truth or device authority.

No device, network, filesystem, process or historical-log access occurs here.
The historical live_readout text fields alone are not this complete current
observation. Callers must obtain and independently review genuine observations.
"""
from copy import deepcopy
import re


ENVIRONMENT_FIELDS = ("boot_id", "active_slot", "official_slot", "mount_namespace", "init_mount_namespace")
OBSERVATION_FIELDS = {"schema", "test_fixture_only", *ENVIRONMENT_FIELDS,
                      "gui", "service", "sensor", "capture_owner"}
# Expected official 1.3.16.2 local baseline, never current observations.
# Provenance: rg390 inputs-before.json, externally retained SHA256
# 981d162ea2b424d7227c0d59e6ab4ee485c225b7d34a9e6c8c9aac75809c4d53.
OFFICIAL_SERVICE_SHA256 = "51b9e02f8bfebf388be8dfa163c8e512bee19aeb8ae37a6712727ccc6f26a52d"
OFFICIAL_SENSOR_SHA256 = "4d1db41c60d3eac1f989110de15335c91798bcca972e475558365d1989e49f6e"
COMPONENT_PATHS = {"gui": "/system/bin/camera-gui", "service": "/system/bin/camera-service",
                   "sensor": "/system/etc/imx861bqr_hb722.conf"}
PROCESS_FIELDS = ("pid", "start_ticks", "exe_target", "exe_sha256", "domain", "mount_namespace")


def _need(condition, message):
    if not condition:
        raise ValueError("runtime observation: " + message)


def _keys(value, fields, name):
    _need(type(value) is dict and set(value) == set(fields), name + " fields differ")


def _matches(value, pattern):
    return type(value) is str and re.fullmatch(pattern, value) is not None


def _artifact(value, name, recovery, fixed_path=None):
    _keys(value, ("state", "path", "sha256", "bytes"), name + " artifact")
    _need(_matches(value["path"], r"/system/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_.-]+)*")
          and len(value["path"]) <= 512
          and not any(part in (".", "..") for part in value["path"].split("/")), name + " artifact path")
    _need(fixed_path is None or value["path"] == fixed_path, name + " artifact path differs")
    _need(value["state"] in ("present", "absent", "unknown"), name + " artifact state")
    _need(recovery or value["state"] == "present", name + " artifact is not observed present")
    if value["state"] == "present":
        _need(_matches(value["sha256"], r"[0-9a-f]{64}"), name + " artifact hash")
        _need(type(value["bytes"]) is int and 0 < value["bytes"] < 2**63, name + " artifact size")
    else:
        _need(value["sha256"] is None and value["bytes"] is None,
              name + " unobserved artifact cannot contain invented hash/size")


def _process(value, name, namespace):
    _keys(value, PROCESS_FIELDS, name + " process")
    _need(type(value["pid"]) is int and 1 < value["pid"] < 2**31, name + " process pid")
    _need(_matches(value["start_ticks"], r"[1-9][0-9]{0,19}"), name + " process lifetime")
    _need(_matches(value["exe_target"], r"/system/(bin|xbin)/[A-Za-z0-9_-]{1,100}"), name + " process executable")
    _need(_matches(value["exe_sha256"], r"[0-9a-f]{64}"), name + " process executable hash")
    _need(_matches(value["domain"], r"u:r:[a-z0-9_]{1,96}:s0"), name + " process domain")
    _need(value["mount_namespace"] == namespace, name + " process namespace differs")


def _route(value):
    _keys(value, ("identity", "evidence_file", "evidence_sha256"), "capture route")
    _need(type(value["identity"]) is str and 0 < len(value["identity"]) <= 2048 and value["identity"].strip()
          and all(character.isprintable() for character in value["identity"]), "capture route identity")
    path = value["evidence_file"]
    _need(_matches(path, r"build/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*") and len(path) <= 512
          and not any(part in (".", "..") for part in path.split("/")), "capture route evidence path")
    _need(_matches(value["evidence_sha256"], r"[0-9a-f]{64}"), "capture route evidence hash")


def normalize_observation(q, expected_gui_sha256, recovery=False):
    """Validate supplied data and return a deep copy, never infer observations.

    The caller hashes this complete result into its runtime subject and rejects
    test_fixture_only at publication. Evidence references are format-checked,
    not opened or accepted as true. Recovery may record explicit absent/unknown
    states and changed official bytes; this does not authorize any recovery
    action, waive its independent gates, or require a successful capture.
    """
    _need(type(q) is dict and "runtime_observation" in q, "complete current data required")
    _need(type(recovery) is bool, "recovery mode must be boolean")
    observed = deepcopy(q["runtime_observation"])
    _keys(observed, OBSERVATION_FIELDS, "top-level")
    _need(observed["schema"] == "x2dii-runtime-observation-v1", "unsupported schema")
    _need(type(observed["test_fixture_only"]) is bool, "explicit fixture marker required")
    for key in ENVIRONMENT_FIELDS:
        _need(key in q and observed[key] == q[key], key + " differs from current context")
    _need(_matches(observed["boot_id"], r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"), "boot identity")
    _need(observed["active_slot"] in ("slot_1", "slot_2")
          and observed["official_slot"] in ("slot_1", "slot_2")
          and observed["active_slot"] != observed["official_slot"], "distinct known slots required")
    _need(_matches(observed["mount_namespace"], r"mnt:\[[1-9][0-9]{0,19}\]")
          and observed["mount_namespace"] == observed["init_mount_namespace"], "current/init namespace differs")
    processes = {}
    if "observer" in q:
        _process(q["observer"], "existing observer", observed["mount_namespace"])
        processes[q["observer"]["pid"]] = q["observer"]
    for name in ("gui", "service", "capture_owner"):
        fields = ("state", "artifact", "process", "route" if name == "capture_owner" else "service_state")
        record = observed[name]
        _keys(record, fields, name)
        _artifact(record["artifact"], name, recovery, COMPONENT_PATHS.get(name))
        _need(record["state"] in ("present", "absent", "unknown"), name + " process state")
        _need(recovery or record["state"] == "present", name + " process is not observed present")
        if record["state"] == "present":
            process = record["process"]
            _process(process, name, observed["mount_namespace"])
            prior = processes.setdefault(process["pid"], process)
            _need(prior == process, "same process pid has conflicting observations")
            if record["artifact"]["state"] == "present":
                _need(process["exe_target"] == record["artifact"]["path"]
                      and process["exe_sha256"] == record["artifact"]["sha256"],
                      name + " running executable differs from observed artifact")
        else:
            _need(record["process"] is None, name + " unobserved process must be null")
        if name == "capture_owner":
            if record["state"] == "present":
                _route(record["route"])
            else:
                _need(record["route"] is None, "unobserved capture route must be null")
        else:
            _need(record["service_state"] in ("running", "stopped", "restarting", "unknown"),
                  name + " service state")
            _need(recovery or record["service_state"] != "unknown", name + " service state is unknown")
    if "gui" in q:
        gui = observed["gui"]
        projection = {key: gui[key] for key in ("state", "service_state")}
        if gui["state"] == "present":
            projection["process"] = gui["process"]
        _need(q["gui"] == projection, "GUI differs from existing context observation")
    _artifact(observed["sensor"], "sensor", recovery, COMPONENT_PATHS["sensor"])
    artifacts = {}
    for artifact in (observed["gui"]["artifact"], observed["service"]["artifact"],
                     observed["capture_owner"]["artifact"], observed["sensor"]):
        prior = artifacts.setdefault(artifact["path"], artifact)
        _need(prior == artifact, "same artifact path has conflicting observations")
    _need(_matches(expected_gui_sha256, r"[0-9a-f]{64}"), "expected GUI hash is invalid")
    gui_artifact = observed["gui"]["artifact"]
    if not recovery:
        _need(gui_artifact["sha256"] == expected_gui_sha256, "observed GUI differs from expected baseline")
        _need(observed["service"]["artifact"]["sha256"] == OFFICIAL_SERVICE_SHA256,
              "observed service differs from fixed official baseline")
        _need(observed["sensor"]["sha256"] == OFFICIAL_SENSOR_SHA256,
              "observed sensor differs from fixed official baseline")
    return observed
