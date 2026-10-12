"""Stable reviewed programs, fresh data: no device access or qualification.

The seam is the existing renderer/qualification and host shell harness. These
fixtures express release ordering, not evidence that a camera passed a gate.
"""
from copy import deepcopy
from datetime import datetime, timedelta

import pytest


@pytest.fixture
def installer():
    from tests.test_peer_install import PeerInstallTests
    PeerInstallTests.setUpClass()
    fixture = PeerInstallTests()
    fixture.setUp()
    try:
        yield fixture
    finally:
        fixture.tearDown()


@pytest.fixture
def recovery_fixture():
    from tests.test_peer_recovery import PeerRecoveryTests
    fixture = PeerRecoveryTests()
    fixture.setUp()
    try:
        yield fixture
    finally:
        fixture.tearDown()


def refreshed(context):
    context = deepcopy(context)
    context["observed_utc"] = (
        datetime.fromisoformat(context["observed_utc"]) + timedelta(minutes=20)
    ).isoformat()
    context["boot_id"] = "33333333-4444-4555-8666-777777777777"
    context["observer"]["start_ticks"] = "23456"
    return context


def test_fresh_install_observation_does_not_change_reviewed_program_bytes(installer):
    from tools import prepare_peer_install as peer
    original = peer._render(installer.manifest, installer.q)
    later = peer._render(installer.manifest, refreshed(installer.q))
    assert original == later, "fresh session data must not invalidate the audited programs"


def test_fresh_recovery_observation_does_not_change_reviewed_program_bytes(recovery_fixture):
    fixture = recovery_fixture
    module = fixture.recovery()
    original = module.render_recovery(fixture.saved, fixture.saved_sha, fixture.q)
    later = module.render_recovery(fixture.saved, fixture.saved_sha, refreshed(fixture.q))
    assert original == later, "a reboot requires fresh data, not a rewritten recovery program"


def test_install_build_and_runtime_survive_lease_renewal_but_not_reboot(installer):
    from tools import prepare_peer_install as peer
    before = deepcopy(installer.q)
    later = deepcopy(before)
    later["observed_utc"] = (
        datetime.fromisoformat(before["observed_utc"]) + timedelta(minutes=20)
    ).isoformat()
    later["session_nonce"] = "c" * 32
    original_build = peer.build_subject_sha256(installer.manifest)
    original_runtime = peer.runtime_subject_sha256(installer.manifest, before)
    assert peer.build_subject_sha256(installer.manifest) == original_build
    assert peer.runtime_subject_sha256(installer.manifest, later) == original_runtime
    assert peer.execution_subject_sha256(installer.manifest, later) != peer.execution_subject_sha256(installer.manifest, before)
    later["boot_id"] = "33333333-4444-4555-8666-777777777777"
    later["runtime_observation"]["boot_id"] = later["boot_id"]
    assert peer.runtime_subject_sha256(installer.manifest, later) != original_runtime


def test_long_build_audit_then_fresh_lease_keeps_reports_immutable_and_needs_new_approval(installer):
    from datetime import timezone
    from tools import prepare_peer_install as peer
    now = datetime.now(timezone.utc)
    installer.q["observed_utc"] = (now - timedelta(minutes=20)).isoformat()
    earlier = deepcopy(installer.validated_shape_fixture())
    evidence_paths = [peer.ROOT / part["evidence_file"]
                      for gate in earlier["gates"].values() for part in gate.values()]
    preserved = {path: path.read_bytes() for path in evidence_paths}
    later = deepcopy(earlier)
    later["observed_utc"] = now.isoformat()
    later["session_nonce"] = "c" * 32
    later["execution_subject_sha256"] = peer.execution_subject_sha256(installer.manifest, later)
    # Merely replacing time cannot renew the previously supplied approval.
    with pytest.raises(ValueError, match="approval"):
        peer.validate_qualification(installer.manifest, later, now=now)
    later["final_installation_approval"]["session_nonce"] = later["session_nonce"]
    later["final_installation_approval"]["execution_subject_sha256"] = later["execution_subject_sha256"]
    peer.validate_qualification(installer.manifest, later, now=now)
    assert all(path.read_bytes() == raw for path, raw in preserved.items())
    with pytest.raises(ValueError, match="fresh"):
        peer.validate_qualification(installer.manifest, later, now=now + timedelta(seconds=601))


def test_recovery_build_and_runtime_survive_lease_renewal_but_not_reboot(recovery_fixture):
    fixture = recovery_fixture
    module = fixture.recovery()
    before = deepcopy(fixture.q)
    later = deepcopy(before)
    later["observed_utc"] = (datetime.fromisoformat(before["observed_utc"]) + timedelta(minutes=20)).isoformat()
    later["session_nonce"] = later["recovery_nonce"] = "a" * 32
    build = module.build_subject_sha256(fixture.saved, fixture.saved_sha)
    runtime = module.runtime_subject_sha256(fixture.saved, fixture.saved_sha, before)
    assert module.build_subject_sha256(fixture.saved, fixture.saved_sha) == build
    assert module.runtime_subject_sha256(fixture.saved, fixture.saved_sha, later) == runtime
    assert module.execution_subject_sha256(fixture.saved, fixture.saved_sha, later) != module.execution_subject_sha256(fixture.saved, fixture.saved_sha, before)
    later["boot_id"] = "33333333-4444-4555-8666-777777777777"
    later["runtime_observation"]["boot_id"] = later["boot_id"]
    assert module.runtime_subject_sha256(fixture.saved, fixture.saved_sha, later) != runtime


@pytest.mark.parametrize("gate", ("all_applicable_historical_regressions", "package_integrity_and_roundtrip"))
@pytest.mark.parametrize("phase", ("build", "runtime"))
def test_install_mixed_gate_needs_both_actual_evidence_halves(installer, gate, phase):
    from tools import prepare_peer_install as peer
    q = installer.validated_shape_fixture()
    assert set(q["gates"][gate]) == {"build", "runtime"}
    del q["gates"][gate][phase]
    with pytest.raises(ValueError, match="gate phase"):
        peer.validate_qualification(installer.manifest, q)


@pytest.mark.parametrize("change", ("boot", "pid_lifetime", "mount", "label", "namespace"))
def test_new_runtime_cannot_relabel_previous_live_proofs(installer, change):
    from tools import prepare_peer_install as peer
    q = deepcopy(installer.validated_shape_fixture())
    if change == "boot":
        q["boot_id"] = "33333333-4444-4555-8666-777777777777"
    elif change == "pid_lifetime":
        q["observer"]["start_ticks"] = "23456"
    elif change == "mount":
        q["system_mount"]["device"] = "/dev/block/different-slot"
    elif change == "label":
        q["metadata"][peer.boot.TARGET]["label"] = "u:object_r:changed_file:s0"
    else:
        q["mount_namespace"] = q["init_mount_namespace"] = q["observer"]["mount_namespace"] = "mnt:[19]"
    # This is a new synthetic observation of the simulated environment. The
    # previously created gate files remain untouched and must be rejected.
    from tests.test_runtime_observation import synthetic_observation
    q["runtime_observation"] = synthetic_observation(q, installer.manifest["candidate"]["gui_sha256"])
    q["runtime_subject_sha256"] = peer.runtime_subject_sha256(installer.manifest, q)
    q["execution_subject_sha256"] = peer.execution_subject_sha256(installer.manifest, q)
    with pytest.raises(ValueError, match="proof subject"):
        peer.validate_qualification(installer.manifest, q)


@pytest.mark.parametrize("phase", ("build", "runtime"))
def test_recovery_mixed_history_keeps_both_obligations(recovery_fixture, phase):
    fixture = recovery_fixture
    module = fixture.recovery()
    q = fixture.structural_qualification()
    assert set(q["gates"]["recovery_historical_regressions"]) == {"build", "runtime"}
    del q["gates"]["recovery_historical_regressions"][phase]
    with pytest.raises(ValueError, match="gate phase"):
        module.validate_qualification(fixture.saved, fixture.saved_sha, q)


def test_recovery_lease_renewal_never_copies_old_authorization(recovery_fixture):
    from datetime import timezone
    fixture = recovery_fixture
    module = fixture.recovery()
    now = datetime.now(timezone.utc)
    fixture.q["observed_utc"] = (now - timedelta(minutes=20)).isoformat()
    q = fixture.structural_qualification()
    paths = [module.ROOT / p["evidence_file"] for phases in q["gates"].values() for p in phases.values()]
    old_reports = {p: p.read_bytes() for p in paths}
    q["observed_utc"] = now.isoformat()
    q["session_nonce"] = q["recovery_nonce"] = "a" * 32
    q["execution_subject_sha256"] = module.execution_subject_sha256(fixture.saved, fixture.saved_sha, q)
    with pytest.raises(ValueError, match="authorization"):
        module.validate_qualification(fixture.saved, fixture.saved_sha, q, now=now)
    q["recovery_authorization"]["session_nonce"] = q["session_nonce"]
    q["recovery_authorization"]["execution_subject_sha256"] = q["execution_subject_sha256"]
    module.validate_qualification(fixture.saved, fixture.saved_sha, q, now=now)
    assert all(path.read_bytes() == raw for path, raw in old_reports.items())
    with pytest.raises(ValueError, match="fresh"):
        module.validate_qualification(fixture.saved, fixture.saved_sha, q, now=now + timedelta(seconds=601))


def test_saved_recovery_build_does_not_read_missing_installed_payload_sources(recovery_fixture):
    fixture = recovery_fixture
    module = fixture.recovery()
    before = module.build_subject_sha256(fixture.saved, fixture.saved_sha)
    # These explicitly named payload-source paths were never needed by recovery.
    for entry in fixture.manifest["candidate"]["files"]:
        path = module.ROOT / entry["source"]
        assert not path.exists()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"unrelated mutable development payload")
    assert module.build_subject_sha256(fixture.saved, fixture.saved_sha) == before


@pytest.mark.parametrize("drift", ("namespace", "boot"))
def test_recovery_must_not_clean_up_another_runtime_after_remount(recovery_fixture, drift):
    fixture = recovery_fixture
    module = fixture.recovery()
    action = "mode=wrong_namespace" if drift == "namespace" else (
        "printf '%s\\n' 99999999-9999-4999-8999-999999999999 > \"$fixture/proc/sys/kernel/random/boot_id\"")
    hook = "boundary() { [ \"$1\" != remount ] || { " + action + "; }; }\n"
    result = fixture.run_script(module.render_recovery(fixture.saved, fixture.saved_sha, fixture.q),
                                boundary_hook=hook)
    assert result.returncode != 0
    fixture.assert_intact()
    operations = (fixture.root / "operations").read_text().splitlines()
    assert not any(line.startswith("mount:") and "remount,ro" in line for line in operations)
    assert not any(line.startswith("rmdir:") for line in operations)
    assert (fixture.root / "tmp/x2dii-menu-install.lock").exists()


def test_recovery_expiration_during_final_gui_read_blocks_stop(recovery_fixture):
    fixture = recovery_fixture
    module = fixture.recovery()
    observed = int(datetime.fromisoformat(fixture.q["observed_utc"]).timestamp())
    hook = f'''
date() {{ if [ -e "$fixture/expired" ]; then echo {observed + 601}; else echo {observed}; fi; }}
getprop() {{
 n=0
 [ ! -e "$fixture/gui-read-count" ] || n=$(cat "$fixture/gui-read-count")
 n=$((n+1))
 printf '%s\\n' "$n" > "$fixture/gui-read-count"
 [ "$n" != 2 ] || printf expired > "$fixture/expired"
 printf 'stopped\\n'
}}
'''
    result = fixture.run_script(module.render_recovery(fixture.saved, fixture.saved_sha, fixture.q),
                                boundary_hook=hook)
    assert result.returncode != 0
    fixture.assert_intact()
    operations = fixture.root / "operations"
    assert not operations.exists() or "stop:" not in operations.read_text()


def test_recovery_expiration_during_precommit_read_blocks_atomic_commit(recovery_fixture):
    fixture = recovery_fixture
    module = fixture.recovery()
    observed = int(datetime.fromisoformat(fixture.q["observed_utc"]).timestamp())
    hook = f'''
date() {{ if [ -e "$fixture/expired" ]; then echo {observed + 601}; else echo {observed}; fi; }}
sync() {{ printf 'sync\\n' >> "$fixture/operations"; printf ready > "$fixture/staged"; }}
getprop() {{ [ ! -e "$fixture/staged" ] || printf expired > "$fixture/expired"; printf 'stopped\\n'; }}
'''
    result = fixture.run_script(module.render_recovery(fixture.saved, fixture.saved_sha, fixture.q),
                                boundary_hook=hook)
    assert result.returncode != 0
    fixture.assert_intact()
    assert "mv:" not in (fixture.root / "operations").read_text()


def test_install_publisher_refuses_explicit_structural_test_evidence(installer):
    from tools import prepare_peer_install as peer
    q = installer.validated_shape_fixture()
    destination = installer.root / "must-not-publish"
    with pytest.raises(ValueError, match="test fixture"):
        peer.prepare(destination, q)
    assert not destination.exists()


def test_recovery_publisher_refuses_explicit_structural_test_evidence(recovery_fixture):
    fixture = recovery_fixture
    q = fixture.structural_qualification()
    destination = fixture.root / "must-not-publish"
    with pytest.raises(ValueError, match="test fixture"):
        fixture.recovery().prepare(destination, fixture.saved, fixture.saved_sha, q)
    assert not destination.exists()


def test_gate_hash_and_result_must_use_the_same_read_bytes(installer, monkeypatch):
    import json
    from pathlib import Path
    from tools import prepare_peer_install as peer
    q = installer.validated_shape_fixture()
    proof = q["gates"]["complete_offline_audit"]["build"]
    path = peer.ROOT / proof["evidence_file"]
    accepted = path.read_bytes()
    failed = json.loads(accepted)
    failed["result"] = "FAIL"
    failed_raw = peer.canonical(failed)
    path.write_bytes(failed_raw)
    proof["evidence_sha256"] = peer.sha(failed_raw)
    original_read = Path.read_bytes
    changed = False

    def read_then_replace(target):
        nonlocal changed
        raw = original_read(target)
        if target == path and not changed:
            changed = True
            target.write_bytes(accepted)
        return raw

    monkeypatch.setattr(Path, "read_bytes", read_then_replace)
    with pytest.raises(ValueError, match="evidence.*result"):
        peer.validate_qualification(installer.manifest, q)
    assert changed


@pytest.mark.parametrize("relative", (
    "build/units/main-screen-bootstrap-host.bin", "build/units/main-screen-bootstrap-device.bin",
    "build/stock-qml/manifest.json", "build/stock-qml/qt/qml/app/qml/mainmenu/MainMenu.qml",
    "work/reverse/INHERITED_APPLICABILITY_REVIEW.json",
    "build/inherited-review-20261004/001-170.json",
    "build/inherited-review-20261004/171-260.json",
    "build/inherited-review-20261004/261-352.json",
    "build/peer-route-review-20261004-rg399/run_audit.py",
    "build/peer-route-review-20261006-menu-evidence/run_audit.py",
    "build/peer-route-review-20261006-dependency-closure/run_audit.py",
))
def test_build_identity_covers_real_compiled_and_stock_menu_inputs(installer, monkeypatch, relative):
    from pathlib import Path
    from tools import prepare_peer_install as peer
    target = peer.ROOT / relative
    original = peer.build_subject_sha256(installer.manifest)
    original_read = Path.read_bytes

    def changed_input(path):
        raw = original_read(path)
        return raw + b"changed-host-input" if path == target else raw

    # Read-only filesystem boundary fault; the real reviewed input is not edited.
    monkeypatch.setattr(Path, "read_bytes", changed_input)
    assert peer.build_subject_sha256(installer.manifest) != original


def test_source_identity_includes_actual_test_consumed_audit_runner():
    from tools import release_identity
    relative = "build/peer-route-review-20261006-menu-evidence/run_audit.py"
    inputs = release_identity.source_inputs()
    assert relative in inputs, "The audit tests' actual imported runner is missing from frozen inputs"
    assert inputs[relative] == {
        "sha256": "3cc21a9392f82b9f99dd162c142703458115c5abc207f92549814e02ea23766d",
        "bytes": 21331,
    }
