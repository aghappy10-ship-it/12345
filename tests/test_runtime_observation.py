"""Pure synthetic shape fixtures, never camera observations or authority."""
from copy import deepcopy

import pytest


GUI_HASH = "a" * 64
SERVICE_HASH = "51b9e02f8bfebf388be8dfa163c8e512bee19aeb8ae37a6712727ccc6f26a52d"
SENSOR_HASH = "4d1db41c60d3eac1f989110de15335c91798bcca972e475558365d1989e49f6e"


def synthetic_observation(q, expected_gui_sha256, recovery=False):
    """Return labelled invented data for host tests only; do not mutate q."""
    def process(pid, target, digest):
        return {"pid": pid, "start_ticks": str(pid * 100), "exe_target": target,
                "exe_sha256": digest, "domain": "u:r:hbl_camera_service:s0",
                "mount_namespace": q["mount_namespace"]}

    def artifact(path, digest):
        return {"state": "present", "path": path, "sha256": digest, "bytes": 1234}

    gui = deepcopy(q.get("gui", {"state": "present", "service_state": "running",
                                "process": process(234, "/system/bin/camera-gui", expected_gui_sha256)}))
    gui["artifact"] = artifact("/system/bin/camera-gui", expected_gui_sha256)
    gui.setdefault("process", None)
    service = {"state": "present", "service_state": "running",
               "artifact": artifact("/system/bin/camera-service", SERVICE_HASH),
               "process": process(345, "/system/bin/camera-service", SERVICE_HASH)}
    return {"schema": "x2dii-runtime-observation-v1", "test_fixture_only": True,
            **{key: q[key] for key in ("boot_id", "active_slot", "official_slot",
                                      "mount_namespace", "init_mount_namespace")},
            "gui": gui, "service": service,
            "sensor": artifact("/system/etc/imx861bqr_hb722.conf", SENSOR_HASH),
            "capture_owner": {"state": "present", "artifact": deepcopy(service["artifact"]),
                              "process": deepcopy(service["process"]),
                              "route": {"identity": "SYNTHETIC original capture route; not observed",
                                        "evidence_file": "build/synthetic-runtime-fixture/route.json",
                                        "evidence_sha256": "d" * 64}}}


@pytest.fixture
def context():
    q = {"boot_id": "11111111-2222-4333-8444-555555555555", "active_slot": "slot_2",
         "official_slot": "slot_1", "mount_namespace": "mnt:[123]", "init_mount_namespace": "mnt:[123]"}
    q["runtime_observation"] = synthetic_observation(q, GUI_HASH)
    return q


def test_complete_observation_is_preserved_as_an_independent_deep_copy(context):
    from tools.runtime_observation import normalize_observation

    before = deepcopy(context)
    result = normalize_observation(context, GUI_HASH)
    assert result == before["runtime_observation"]
    result["service"]["process"]["start_ticks"] = "99999"
    result["capture_owner"]["route"]["identity"] = "changed output only"
    assert context == before
    assert result["test_fixture_only"] is True


@pytest.mark.parametrize("change", ("missing", "extra", "schema", "marker", "boot_id", "active_slot",
                                    "official_slot", "mount_namespace", "init_mount_namespace"))
def test_observation_requires_exact_schema_and_current_environment(context, change):
    from tools.runtime_observation import normalize_observation

    observed = context["runtime_observation"]
    if change == "missing":
        del context["runtime_observation"]
    elif change == "extra":
        observed["unbound_information"] = "must not be silently discarded"
    elif change == "schema":
        observed["schema"] = "older-shape"
    elif change == "marker":
        observed["test_fixture_only"] = "false"
    else:
        observed[change] = "different-current-environment"
    with pytest.raises(ValueError, match="observation"):
        normalize_observation(context, GUI_HASH)


@pytest.mark.parametrize("component", ("gui", "service", "sensor", "capture_owner"))
@pytest.mark.parametrize("change", ("absent", "unknown", "missing_hash", "bad_hash", "bad_size", "extra"))
def test_install_requires_explicit_complete_observed_artifacts(context, component, change):
    from tools.runtime_observation import normalize_observation

    record = context["runtime_observation"][component]
    artifact = record if component == "sensor" else record["artifact"]
    if change in ("absent", "unknown"):
        artifact.update(state=change, sha256=None, bytes=None)
    elif change == "missing_hash":
        del artifact["sha256"]
    elif change == "bad_hash":
        artifact["sha256"] = "not an observed hash"
    elif change == "bad_size":
        artifact["bytes"] = True
    else:
        artifact["expected_hash_is_not_an_observation"] = GUI_HASH
    with pytest.raises(ValueError, match="observation"):
        normalize_observation(context, GUI_HASH)


@pytest.mark.parametrize("component", ("gui", "service", "sensor"))
def test_fixed_component_paths_cannot_name_a_different_artifact(context, component):
    from tools.runtime_observation import normalize_observation

    record = context["runtime_observation"][component]
    artifact = record if component == "sensor" else record["artifact"]
    artifact["path"] = "/system/bin/unrelated"
    with pytest.raises(ValueError, match="observation"):
        normalize_observation(context, GUI_HASH)


def test_expected_gui_hash_never_fills_or_overrides_observed_gui_bytes(context):
    from tools.runtime_observation import normalize_observation

    observed = context["runtime_observation"]
    observed["gui"]["artifact"]["sha256"] = "f" * 64
    observed["gui"]["process"]["exe_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="observation.*GUI"):
        normalize_observation(context, GUI_HASH)
    assert observed["gui"]["artifact"]["sha256"] == "f" * 64


@pytest.mark.parametrize("component", ("service", "sensor"))
def test_install_compares_observed_components_to_fixed_official_baseline(context, component):
    from tools.runtime_observation import normalize_observation

    record = context["runtime_observation"][component]
    artifact = record if component == "sensor" else record["artifact"]
    artifact["sha256"] = "f" * 64
    with pytest.raises(ValueError, match="observation"):
        normalize_observation(context, GUI_HASH)


@pytest.mark.parametrize("component", ("gui", "service", "capture_owner"))
@pytest.mark.parametrize("field,bad", (("pid", True), ("pid", 1), ("start_ticks", "0"),
                                     ("exe_target", "/tmp/impostor"), ("exe_sha256", "bad"),
                                     ("domain", "unobserved"), ("mount_namespace", "mnt:[999]")))
def test_process_identity_must_be_complete_and_in_current_namespace(context, component, field, bad):
    from tools.runtime_observation import normalize_observation

    context["runtime_observation"][component]["process"][field] = bad
    with pytest.raises(ValueError, match="observation"):
        normalize_observation(context, GUI_HASH)


@pytest.mark.parametrize("component", ("gui", "service", "capture_owner"))
@pytest.mark.parametrize("state", ("absent", "unknown"))
def test_install_cannot_infer_a_running_owner_from_absent_or_unknown_state(context, component, state):
    from tools.runtime_observation import normalize_observation

    context["runtime_observation"][component].update(state=state, process=None)
    with pytest.raises(ValueError, match="observation"):
        normalize_observation(context, GUI_HASH)


@pytest.mark.parametrize("component", ("gui", "service"))
@pytest.mark.parametrize("field", ("exe_target", "exe_sha256"))
def test_gui_and_service_running_executable_must_match_observed_artifact(context, component, field):
    from tools.runtime_observation import normalize_observation

    context["runtime_observation"][component]["process"][field] = (
        "/system/bin/unrelated" if field == "exe_target" else "e" * 64
    )
    with pytest.raises(ValueError, match="observation"):
        normalize_observation(context, GUI_HASH)


def test_capture_owner_cannot_reuse_a_service_pid_with_different_lifetime(context):
    from tools.runtime_observation import normalize_observation

    context["runtime_observation"]["capture_owner"]["process"]["start_ticks"] = "99999"
    with pytest.raises(ValueError, match="observation"):
        normalize_observation(context, GUI_HASH)


@pytest.mark.parametrize("change", ("missing", "null", "empty_identity", "code_like_identity",
                                    "missing_evidence", "absolute_evidence", "traversal", "bad_hash", "extra"))
def test_original_capture_route_requires_an_explicit_bounded_evidence_reference(context, change):
    from tools.runtime_observation import normalize_observation

    owner = context["runtime_observation"]["capture_owner"]
    route = owner["route"]
    if change == "missing":
        del owner["route"]
    elif change == "null":
        owner["route"] = None
    elif change == "empty_identity":
        route["identity"] = ""
    elif change == "code_like_identity":
        route["identity"] = "route\nsecond line"
    elif change == "missing_evidence":
        del route["evidence_file"]
    elif change == "absolute_evidence":
        route["evidence_file"] = "/tmp/unreviewed.json"
    elif change == "traversal":
        route["evidence_file"] = "build/../unreviewed.json"
    elif change == "bad_hash":
        route["evidence_sha256"] = "unobserved"
    else:
        route["capture_success"] = True
    with pytest.raises(ValueError, match="observation"):
        normalize_observation(context, GUI_HASH)


@pytest.mark.parametrize("component", ("gui", "service"))
@pytest.mark.parametrize("state", ("unknown", "invented", None))
def test_install_requires_explicit_known_service_state(context, component, state):
    from tools.runtime_observation import normalize_observation

    context["runtime_observation"][component]["service_state"] = state
    with pytest.raises(ValueError, match="observation"):
        normalize_observation(context, GUI_HASH)


@pytest.mark.parametrize("field,value", (("boot_id", "same-but-invalid"), ("active_slot", "slot_1"),
                                       ("mount_namespace", "invalid"), ("init_mount_namespace", "mnt:[987]")))
def test_equal_but_invalid_environment_values_are_not_valid_observations(context, field, value):
    from tools.runtime_observation import normalize_observation

    context[field] = context["runtime_observation"][field] = value
    with pytest.raises(ValueError, match="observation"):
        normalize_observation(context, GUI_HASH)


@pytest.mark.parametrize("field", ("path", "sha256"))
def test_present_capture_owner_artifact_identifies_its_observed_executable(context, field):
    from tools.runtime_observation import normalize_observation

    context["runtime_observation"]["capture_owner"]["artifact"][field] = (
        "/system/bin/unrelated" if field == "path" else "f" * 64
    )
    with pytest.raises(ValueError, match="observation"):
        normalize_observation(context, GUI_HASH)


def test_recovery_records_absent_gui_and_unknown_capture_without_inventing_success(context):
    from tools.runtime_observation import normalize_observation

    context["gui"] = {"state": "absent", "service_state": "stopped"}
    observed = synthetic_observation(context, GUI_HASH, recovery=True)
    for component in ("service", "capture_owner"):
        record = observed[component]
        record.update(state="unknown", process=None)
        record["artifact"].update(state="unknown", sha256=None, bytes=None)
        record["route" if component == "capture_owner" else "service_state"] = (
            None if component == "capture_owner" else "unknown"
        )
    observed["sensor"].update(state="unknown", sha256=None, bytes=None)
    context["runtime_observation"] = observed
    result = normalize_observation(context, GUI_HASH, recovery=True)
    assert result == observed
    assert result["gui"]["process"] is None
    assert result["capture_owner"]["state"] == "unknown"
    assert result["capture_owner"]["route"] is None
    with pytest.raises(ValueError, match="observation"):
        normalize_observation(context, GUI_HASH)


def test_recovery_keeps_actual_changed_service_and_sensor_identity(context):
    from tools.runtime_observation import normalize_observation

    observed = context["runtime_observation"]
    for component in ("service", "capture_owner"):
        observed[component]["artifact"]["sha256"] = "e" * 64
        observed[component]["process"]["exe_sha256"] = "e" * 64
    observed["sensor"]["sha256"] = "f" * 64
    assert normalize_observation(context, GUI_HASH, recovery=True) == observed
    with pytest.raises(ValueError, match="observation"):
        normalize_observation(context, GUI_HASH)


@pytest.mark.parametrize("change", ("state", "service_state", "lifetime"))
def test_recovery_observation_must_agree_with_existing_gui_observation(context, change):
    from tools.runtime_observation import normalize_observation

    gui = context["runtime_observation"]["gui"]
    context["gui"] = {key: deepcopy(value) for key, value in gui.items() if key != "artifact"}
    if change == "state":
        context["gui"] = {"state": "absent", "service_state": "stopped"}
    elif change == "service_state":
        context["gui"]["service_state"] = "restarting"
    else:
        context["gui"]["process"]["start_ticks"] = "45678"
    with pytest.raises(ValueError, match="observation"):
        normalize_observation(context, GUI_HASH, recovery=True)


@pytest.mark.parametrize("state", ("absent", "unknown"))
def test_recovery_unobserved_process_state_cannot_carry_an_invented_process(context, state):
    from tools.runtime_observation import normalize_observation

    context["runtime_observation"]["capture_owner"]["state"] = state
    with pytest.raises(ValueError, match="observation"):
        normalize_observation(context, GUI_HASH, recovery=True)


def test_existing_observer_pid_cannot_identify_a_different_current_owner(context):
    from tools.runtime_observation import normalize_observation

    context["observer"] = deepcopy(context["runtime_observation"]["gui"]["process"])
    context["observer"]["start_ticks"] = "999999"
    with pytest.raises(ValueError, match="observation"):
        normalize_observation(context, GUI_HASH)


def test_recovery_retains_explicit_unknown_gui_without_guessing_identity(context):
    from tools.runtime_observation import normalize_observation

    context["gui"] = {"state": "unknown", "service_state": "unknown"}
    observed = synthetic_observation(context, GUI_HASH, recovery=True)
    observed["gui"]["artifact"].update(state="unknown", sha256=None, bytes=None)
    context["runtime_observation"] = observed
    result = normalize_observation(context, GUI_HASH, recovery=True)
    assert result == observed
    assert result["gui"]["process"] is None
    assert result["gui"]["artifact"]["sha256"] is None


def test_normalization_performs_no_external_reads_and_fixture_does_not_mutate_input(context, monkeypatch):
    import builtins
    from pathlib import Path
    import socket
    from tools.runtime_observation import normalize_observation

    before = deepcopy(context)

    def external_access_forbidden(*args, **kwargs):
        raise AssertionError("a pure observation normalizer must not access external state")

    with monkeypatch.context() as patch:
        patch.setattr(builtins, "open", external_access_forbidden)
        patch.setattr(Path, "open", external_access_forbidden)
        patch.setattr(socket, "socket", external_access_forbidden)
        generated = synthetic_observation(context, GUI_HASH)
        actual = normalize_observation(context, GUI_HASH)
    assert generated == actual
    assert context == before


def test_capture_route_identity_bounds_original_input_including_whitespace(context):
    from tools.runtime_observation import normalize_observation

    context["runtime_observation"]["capture_owner"]["route"]["identity"] = " " * 2049 + "route"
    with pytest.raises(ValueError, match="observation"):
        normalize_observation(context, GUI_HASH)


@pytest.mark.parametrize("recovery", (False, True), ids=("install", "recovery"))
@pytest.mark.parametrize("field", ("bytes", "sha256"))
def test_same_artifact_path_cannot_have_conflicting_current_identity(context, recovery, field):
    from tools.runtime_observation import normalize_observation

    owner = context["runtime_observation"]["capture_owner"]
    if field == "bytes":
        owner["artifact"]["bytes"] += 1
    else:
        # A different process may map the same named file; a distinct PID must
        # not conceal conflicting observations of that one artifact path.
        owner["artifact"]["sha256"] = "e" * 64
        owner["process"].update(pid=456, start_ticks="45600", exe_sha256="e" * 64)
    with pytest.raises(ValueError, match="observation.*artifact"):
        normalize_observation(context, GUI_HASH, recovery=recovery)


@pytest.mark.parametrize("state", ("absent", "unknown"))
def test_recovery_does_not_merge_conflicting_same_path_artifact_states(context, state):
    from tools.runtime_observation import normalize_observation

    owner = context["runtime_observation"]["capture_owner"]
    owner.update(state=state, process=None, route=None)
    owner["artifact"].update(state=state, sha256=None, bytes=None)
    before = deepcopy(context)
    with pytest.raises(ValueError, match="observation.*artifact"):
        normalize_observation(context, GUI_HASH, recovery=True)
    assert context == before


def test_distinct_capture_owner_artifact_is_not_merged_with_service(context):
    from tools.runtime_observation import normalize_observation

    owner = context["runtime_observation"]["capture_owner"]
    owner["artifact"].update(path="/system/bin/capture-owner", sha256="e" * 64, bytes=4321)
    owner["process"].update(pid=456, start_ticks="45600", exe_target="/system/bin/capture-owner",
                            exe_sha256="e" * 64)
    assert normalize_observation(context, GUI_HASH) == context["runtime_observation"]


@pytest.mark.parametrize("state", ("absent", "unknown"))
def test_recovery_preserves_explicit_different_path_artifact_state(context, state):
    from tools.runtime_observation import normalize_observation

    owner = context["runtime_observation"]["capture_owner"]
    owner.update(state=state, process=None, route=None)
    owner["artifact"].update(path="/system/bin/capture-owner", state=state, sha256=None, bytes=None)
    assert normalize_observation(context, GUI_HASH, recovery=True) == context["runtime_observation"]
