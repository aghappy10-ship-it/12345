"""Qualification must not ignore current core-runtime observations."""
from copy import deepcopy
import json
import re

import pytest


@pytest.fixture(params=("install", "recovery"))
def subject_fixture(request):
    if request.param == "install":
        from tests.test_peer_install import PeerInstallTests
        from tools import prepare_peer_install as peer
        PeerInstallTests.setUpClass()
        fixture = PeerInstallTests()
        fixture.setUp()
        subject = lambda q: peer.runtime_subject_sha256(fixture.manifest, q)
    else:
        from tests.test_peer_recovery import PeerRecoveryTests
        fixture = PeerRecoveryTests()
        fixture.setUp()
        module = fixture.recovery()
        subject = lambda q: module.runtime_subject_sha256(fixture.saved, fixture.saved_sha, q)
    try:
        yield fixture, subject
    finally:
        fixture.tearDown()


def test_runtime_subject_cannot_omit_current_core_observation(subject_fixture):
    fixture, subject = subject_fixture
    q = deepcopy(fixture.q)
    q.pop("runtime_observation", None)
    with pytest.raises(ValueError, match="observation"):
        subject(q)


def test_runtime_subject_must_reject_malformed_not_ignore_added_observation(subject_fixture):
    fixture, subject = subject_fixture
    q = deepcopy(fixture.q)
    q["runtime_observation"] = {"unexpected_or_unverified": True}
    with pytest.raises(ValueError, match="observation"):
        subject(q)


@pytest.mark.parametrize("component", ("service_process", "sensor_artifact", "capture_route", "gui_artifact"))
def test_each_current_observation_change_invalidates_the_previous_runtime_subject(subject_fixture, component):
    fixture, subject = subject_fixture
    q = deepcopy(fixture.q)
    original = subject(q)
    observation = q["runtime_observation"]
    if component == "service_process":
        observation["service"]["process"]["start_ticks"] = "999999"
        # This fixture names the same process as capture owner; a genuinely
        # new internally consistent observation must update both references.
        observation["capture_owner"]["process"]["start_ticks"] = "999999"
    elif component == "sensor_artifact":
        observation["sensor"]["bytes"] += 1
    elif component == "capture_route":
        observation["capture_owner"]["route"]["evidence_sha256"] = "f" * 64
    else:
        observation["gui"]["artifact"]["bytes"] += 1
    assert subject(q) != original


def test_referenced_runtime_evidence_must_exist_and_match_exact_bytes(subject_fixture):
    from tools import release_identity
    fixture, _ = subject_fixture
    observed = deepcopy(fixture.q["runtime_observation"])
    path = fixture.root / "current-capture-route.txt"
    route = observed["capture_owner"]["route"]
    route["evidence_file"] = path.relative_to(release_identity.ROOT).as_posix()
    with pytest.raises(ValueError, match="runtime evidence"):
        release_identity.validate_runtime_references(observed)
    raw = b"synthetic byte-identity fixture only; not proof of capture ownership"
    path.write_bytes(raw)
    route["evidence_sha256"] = release_identity.sha(raw)
    release_identity.validate_runtime_references(observed)
    path.write_bytes(raw + b" changed")
    with pytest.raises(ValueError, match="runtime evidence"):
        release_identity.validate_runtime_references(observed)


def test_changed_core_runtime_cannot_relabel_old_gate_proofs(subject_fixture):
    fixture, subject = subject_fixture
    is_recovery = hasattr(fixture, "saved")
    if is_recovery:
        module = fixture.recovery()
        q = fixture.structural_qualification()
        execute = lambda value: module.execution_subject_sha256(fixture.saved, fixture.saved_sha, value)
        validate = lambda value: module.validate_qualification(fixture.saved, fixture.saved_sha, value)
    else:
        from tools import prepare_peer_install as module
        q = fixture.validated_shape_fixture()
        execute = lambda value: module.execution_subject_sha256(fixture.manifest, value)
        validate = lambda value: module.validate_qualification(fixture.manifest, value)
    old = deepcopy(q)
    for name in ("service", "capture_owner"):
        q["runtime_observation"][name]["process"]["start_ticks"] = "999999"
    q["runtime_subject_sha256"] = subject(q)
    q["execution_subject_sha256"] = execute(q)
    with pytest.raises(ValueError, match="proof subject"):
        validate(q)
    assert q["gates"] == old["gates"]


def test_fixture_observation_blocks_each_publisher_before_any_output(subject_fixture):
    fixture, _ = subject_fixture
    destination = fixture.root / "runtime-fixture-must-not-publish"
    if hasattr(fixture, "saved"):
        q = fixture.structural_qualification()
        publish = lambda: fixture.recovery().prepare(destination, fixture.saved, fixture.saved_sha, q)
    else:
        from tools import prepare_peer_install as module
        q = fixture.validated_shape_fixture()
        publish = lambda: module.prepare(destination, q)
    with pytest.raises(ValueError, match="runtime observation test fixture"):
        publish()
    assert not destination.exists()


def test_gate_fixture_rejection_is_tested_independently_of_observation_marker(subject_fixture):
    from tools import release_identity
    fixture, _ = subject_fixture
    if hasattr(fixture, "saved"):
        module = fixture.recovery()
        q = fixture.structural_qualification()
        retained = {"saved_manifest_sha256": fixture.saved_sha}
    else:
        from tools import prepare_peer_install as module
        q = fixture.validated_shape_fixture()
        retained = None
    identity = {key: q[key] for key in
                ("candidate_sha256", "build_subject_sha256", "runtime_subject_sha256", "boot_id")}
    if not hasattr(fixture, "saved"):
        identity["delivery_identity"] = q["delivery_identity"]
    # Test the public evidence-validation seam directly. The synthetic
    # observation and reports retain their markers; no pretend live publication.
    release_identity.validate_gates(q["gates"], module.GATE_PHASES, retained=retained, **identity)
    with pytest.raises(ValueError, match="test fixture cannot authorize publication:"):
        release_identity.validate_gates(q["gates"], module.GATE_PHASES, for_publication=True,
                                        retained=retained, **identity)


def test_each_publisher_still_rejects_gate_fixtures_when_observation_marker_is_missing(subject_fixture):
    from tools import release_identity
    fixture, _ = subject_fixture
    # Deliberately counterfactual input: removing a marker cannot make an
    # invented observation real. Exercise the next independent refusal layer,
    # never publish these temporary fixtures or claim camera qualification.
    destination = fixture.root / "gate-fixture-must-not-publish"
    if hasattr(fixture, "saved"):
        from tests.test_recovery_role_publication import _original_bundle_format_case
        module = fixture.recovery()
        # The publisher now checks a bound failure bundle before generic gates.
        # Reuse its inert format fixture so this negative test reaches the
        # intended gate refusal, rather than failing at an unrelated new guard.
        saved_sha, q, _, _ = _original_bundle_format_case(fixture)
        refused_gate, refused_phase = "recovery_offline_audit", "build"
        proof = q["gates"][refused_gate][refused_phase]
        gate_path = module.ROOT / proof["evidence_file"]
        evidence = json.loads(gate_path.read_bytes())
        evidence["test_fixture_only"] = True
        raw = module.canonical(evidence)
        gate_path.write_bytes(raw)
        proof["evidence_sha256"] = module.sha(raw)
        publish = lambda: module.prepare(destination, fixture.saved, saved_sha, q)
    else:
        from tools import prepare_peer_install as module
        from tools.delivery_content import ROLE_FORMAT_VERSION
        observation = fixture.q["runtime_observation"]
        observation["test_fixture_only"] = False
        path = fixture.root / "synthetic-counterfactual-route.txt"
        raw = b"COUNTERFACTUAL TEST INPUT, NOT A CAMERA OBSERVATION"
        path.write_bytes(raw)
        observation["capture_owner"]["route"].update(
            evidence_file=path.relative_to(release_identity.ROOT).as_posix(),
            evidence_sha256=release_identity.sha(raw))
        # Formal publication uses the maintenance-observed role-aware route;
        # legacy delivery fixtures remain valid only for structural checks.
        fixture.q["delivery_identity"]["format_version"] = ROLE_FORMAT_VERSION
        fixture.q["observer"]["domain"] = "u:r:hbl_camera_service:s0"
        q = fixture.validated_shape_fixture()
        refused_gate = module.GATES[0]
        refused_phase = module.GATE_PHASES[refused_gate][0]
        publish = lambda: module.prepare(destination, q)
    expected = "test fixture cannot authorize publication: " + refused_gate + "/" + refused_phase
    with pytest.raises(ValueError, match="^" + re.escape(expected) + "$"):
        publish()
    assert not destination.exists()


@pytest.mark.parametrize("change", ("unknown_gui", "changed_gui"))
@pytest.mark.parametrize("subject_fixture", ["recovery"], indirect=True)
def test_recovery_can_record_unusable_gui_without_authorizing_execution(subject_fixture, change):
    fixture, subject = subject_fixture
    module = fixture.recovery()
    q = deepcopy(fixture.q)
    original = subject(q)
    gui = q["runtime_observation"]["gui"]
    if change == "unknown_gui":
        q["gui"] = {"state": "unknown", "service_state": "unknown"}
        gui.update(q["gui"], process=None)
        gui["artifact"].update(state="unknown", sha256=None, bytes=None)
    else:
        process = {"pid": 333, "start_ticks": "88888", "exe_target": "/system/bin/camera-gui",
                   "exe_sha256": "c" * 64, "domain": "u:r:hbl_camera_gui:s0",
                   "mount_namespace": q["mount_namespace"]}
        q["gui"] = {"state": "present", "service_state": "running", "process": process}
        gui.update(deepcopy(q["gui"]))
        gui["artifact"].update(state="present", sha256="c" * 64, bytes=4096)
    assert subject(q) != original
    with pytest.raises(ValueError, match="GUI"):
        module.execution_subject_sha256(fixture.saved, fixture.saved_sha, q)
    with pytest.raises(ValueError, match="GUI"):
        module.render_recovery(fixture.saved, fixture.saved_sha, q)


@pytest.mark.parametrize("subject_fixture", ["recovery"], indirect=True)
def test_recovery_does_not_require_healthy_capture_to_bind_its_own_evidence(subject_fixture):
    fixture, subject = subject_fixture
    module = fixture.recovery()
    observation = fixture.q["runtime_observation"]
    for name in ("service", "capture_owner"):
        record = observation[name]
        record.update(state="unknown", process=None)
        record["artifact"].update(state="unknown", sha256=None, bytes=None)
        record["route" if name == "capture_owner" else "service_state"] = (
            None if name == "capture_owner" else "unknown")
    observation["sensor"].update(state="unknown", sha256=None, bytes=None)
    q = fixture.structural_qualification()
    assert subject(q) == q["runtime_subject_sha256"]
    module.validate_qualification(fixture.saved, fixture.saved_sha, q)
    from tools import release_identity
    release_identity.validate_runtime_references(observation)
    # No camera claim: the fixture remains explicitly non-publishable.
    with pytest.raises(ValueError, match="runtime observation test fixture"):
        module.prepare(fixture.root / "capture-unknown-must-not-publish", fixture.saved, fixture.saved_sha, q)
