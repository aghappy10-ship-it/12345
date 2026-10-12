"""Saved v2 identity routing; inert fixtures are never installed candidates."""
from copy import deepcopy

import pytest

from tests.test_release_lifecycle import recovery_fixture
from tests.test_delivery_role_v2 import role_fixture
from tools import delivery_content as content, prepare_peer_recovery as recovery


def saved_role(fixture, change=None, *, fixed_boot=False):
    members, candidate, scripts = role_fixture()
    if fixed_boot:
        from tools import boot_config
        members["camera-gui.rc.proposed"] = boot_config.activate(boot_config.STOCK.read_bytes())
        candidate["rc"]["after"] = recovery.sha(members["camera-gui.rc.proposed"])
    candidate_sha = recovery.sha(recovery.canonical(candidate))
    description = content.plan_role_content(members, candidate_sha)
    identity = content.verify_content(content.encode_role_content(members, candidate_sha), description)
    manifest = deepcopy(fixture.manifest)
    manifest.update(candidate=candidate, candidate_sha256=candidate_sha,
        status="QUALIFIED_DELIVERY_NOT_EXECUTED", package_created=True, script_hashes=scripts,
        delivery_identity=identity, delivery_members=description, test_fixture_only=True)
    if change:
        change(manifest)
    raw = recovery.canonical(manifest)
    fixture.saved.write_bytes(raw)
    return manifest, recovery.sha(raw)


def test_saved_role_manifest_loads_without_reading_current_candidate_sources(recovery_fixture):
    fixture = recovery_fixture
    manifest, digest = saved_role(fixture)
    assert recovery.load_saved_candidate(fixture.saved, digest) == manifest


@pytest.mark.parametrize("fault", ("program", "payload", "rc", "length", "member-manifest",
                                    "layout", "old-programs"))
def test_saved_role_manifest_rejects_mixed_or_inconsistent_member_identities(recovery_fixture, fault):
    def change(manifest):
        if fault == "program":
            manifest["script_hashes"]["preplace-0.sh"] = "9" * 64
        elif fault == "member-manifest":
            manifest["delivery_identity"]["member_manifest_sha256"] = "9" * 64
        elif fault == "length":
            manifest["delivery_identity"]["package_bytes"] += 512
        elif fault == "layout":
            manifest["delivery_members"]["members"].reverse()
        elif fault == "old-programs":
            manifest["script_hashes"] = {name: "d" * 64 for name in
                                         ("install-files.sh", "activate-boot.sh", "restore-boot.sh")}
        else:
            target = manifest["candidate"]["files"][0] if fault == "payload" else manifest["candidate"]["rc"]
            target["sha256" if fault == "payload" else "after"] = "9" * 64
            manifest["candidate_sha256"] = recovery.sha(recovery.canonical(manifest["candidate"]))
    _, digest = saved_role(recovery_fixture, change)
    with pytest.raises(ValueError):
        recovery.load_saved_candidate(recovery_fixture.saved, digest)


def test_saved_role_manifest_never_falls_back_to_legacy_combined_su_renderer(recovery_fixture):
    manifest, digest = saved_role(recovery_fixture)
    with pytest.raises(ValueError, match="role-aware recovery"):
        recovery._render(manifest, recovery_fixture.q)


def role_recovery_context(fixture):
    from tools import boot_config
    manifest, digest = saved_role(fixture, fixed_boot=True)
    q = deepcopy(fixture.q)
    q.update(candidate_sha256=manifest["candidate_sha256"], saved_manifest_sha256=digest,
             rc_sha256=manifest["candidate"]["rc"]["after"],
             backup_identity=f"1:9:81a4:1:{len(boot_config.STOCK.read_bytes())}:0:0")
    q["observer"].update(domain="u:r:hbl_camera_service:s0", exe_target="/system/bin/camera-service")
    q["backup_metadata"].pop("owner")
    # An absent/unhealthy GUI cannot prevent official-rc restoration, and
    # grants no authority for unloading/deletion in this source.
    q["gui"] = {"state": "absent", "service_state": "stopped"}
    return manifest, digest, q


def test_saved_role_routes_to_supervised_official_rc_restore_without_payload_sources(recovery_fixture, monkeypatch):
    from tools import prepare_peer_install as peer
    manifest, digest, q = role_recovery_context(recovery_fixture)

    def forbidden_inventory():
        raise AssertionError("recovery read mutable installation inventory")

    monkeypatch.setattr(peer, "inventory", forbidden_inventory)
    source = recovery.render_recovery(recovery_fixture.saved, digest, q)
    assert "X2DII_BOOT_BOUNDARY_REQUEST:restore" in source
    assert "maintenance_boundaries=HOST_MEDIATED_FIXED_BOOT_MATCHED" in source
    assert "X2DII_SESSION_KIND\" = 'recovery'" in source
    assert "stop camera-gui" not in source and "rm " not in source
    assert "sha256sum /system/bin/camera-service" not in source
    assert ".x2dii-boot-" + manifest["candidate_sha256"][:24] + ".original" in source
    assert recovery.build_subject_sha256(recovery_fixture.saved, digest)


@pytest.mark.parametrize("fault", ("observer", "label", "backup", "init-root"))
def test_role_restore_admission_checks_its_actual_paths_and_backup(recovery_fixture, fault):
    manifest, digest, q = role_recovery_context(recovery_fixture)
    if fault == "observer":
        q["observer"]["domain"] = "u:r:su:s0"
    elif fault == "label":
        q["metadata"][recovery.RC]["label"] = "u:object_r:other_file:s0"
        q["backup_metadata"]["official"]["label"] = "u:object_r:other_file:s0"
    elif fault == "backup":
        q["backup_identity"] = "1:0:81a4:1:9:0:0"
    else:
        q["init_scan_roots"].append("/system/etc/.x2dii-boot-" + manifest["candidate_sha256"][:24] + ".original")
    with pytest.raises(ValueError):
        recovery.render_recovery(recovery_fixture.saved, digest, q)


@pytest.mark.parametrize("name", ("preplace-0.sh", "preplace-1.sh", "preplace-2.sh", "preplace-3.sh"))
def test_recovery_output_never_mixes_new_installation_workers(recovery_fixture, name):
    fixture = recovery_fixture
    output = fixture.root / "recovery-output"
    output.mkdir()
    raw = b"INERT STALE ROLE PROGRAM"
    (output / name).write_bytes(raw)
    with pytest.raises(ValueError, match="recovery output contains forbidden executable"):
        recovery.prepare(output, fixture.saved, fixture.saved_sha)
    assert (output / name).read_bytes() == raw
    assert not (output / "peer-recovery-source.json").exists()


@pytest.mark.parametrize("field,value", (("mode", "600"), ("uid", 99), ("gid", 99)))
def test_official_rc_restore_does_not_require_healthy_extension_metadata(recovery_fixture, field, value):
    _, digest, context = role_recovery_context(recovery_fixture)
    target = next(path for path in context["metadata"] if path != recovery.RC)
    context["metadata"][target][field] = value
    observed = deepcopy(context)
    source = recovery.render_recovery(recovery_fixture.saved, digest, context)
    assert "X2DII_BOOT_BOUNDARY_REQUEST:restore" in source
    assert "rm " not in source and "stop camera-gui" not in source
    assert context == observed, "Unhealthy observations must not be rewritten as healthy evidence"


def test_role_recovery_missing_extension_label_is_refused_not_invented(recovery_fixture):
    _, digest, context = role_recovery_context(recovery_fixture)
    target = next(path for path in context["metadata"] if path != recovery.RC)
    del context["metadata"][target]["label"]
    observed = deepcopy(context)
    with pytest.raises(ValueError):
        recovery.render_recovery(recovery_fixture.saved, digest, context)
    assert context == observed, "The current recovery schema cannot invent an unknown actual label"
