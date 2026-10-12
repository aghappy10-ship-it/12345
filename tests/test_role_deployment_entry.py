"""Formal content route, not a camera qualification or installation claim."""
from pathlib import Path
import tempfile
from unittest import mock

import pytest

from tools import prepare_peer_install as peer
from tools import release_identity
from tools.delivery_content import ROLE_FORMAT_VERSION
from tools.delivery_plan import ROLE_PROGRAMS


@pytest.fixture
def formal_context():
    from tests.test_peer_install import PeerInstallTests
    fixture = PeerInstallTests()
    fixture.manifest = peer.inventory()
    fixture.setUp()
    fixture.q["synthetic"] = False
    fixture.q["delivery_identity"]["format_version"] = ROLE_FORMAT_VERSION
    fixture.q["observer"]["domain"] = "u:r:hbl_camera_service:s0"
    try:
        yield fixture.manifest, fixture.q
    finally:
        fixture.tearDown()


def test_formal_admission_rejects_label_the_fixed_boot_program_cannot_preserve(formal_context):
    manifest, context = formal_context
    context["metadata"][peer.boot.TARGET]["label"] = "u:object_r:other_file:s0"
    with pytest.raises(ValueError, match="fixed role boot metadata"):
        peer.validate_qualification(manifest, context)


@pytest.mark.parametrize("suffix", [".original", "-" + "b" * 32 + "-activate.stage",
                                  "-" + "b" * 32 + "-restore.stage"])
def test_formal_admission_checks_actual_boot_backup_and_stage_locations(formal_context, suffix):
    manifest, context = formal_context
    context["init_scan_roots"].append("/system/etc/.x2dii-boot-" + manifest["candidate_sha256"][:24] + suffix)
    with pytest.raises(ValueError, match="work or backup path lies inside an init scan root"):
        peer.validate_qualification(manifest, context)


def test_formal_admission_does_not_reuse_su_as_maintenance_observer(formal_context):
    manifest, context = formal_context
    context["observer"]["domain"] = "u:r:su:s0"
    with pytest.raises(ValueError, match="formal role route needs maintenance observer"):
        peer.validate_qualification(manifest, context)


def test_formal_program_set_is_the_six_role_split_programs_and_not_old_installer():
    manifest = peer.inventory()
    programs = peer.render_role_programs(manifest)
    assert tuple(programs) == ROLE_PROGRAMS
    assert "install-files.sh" not in programs
    for index in range(4):
        worker = programs[f"preplace-{index}.sh"]
        assert "u:r:su:s0" in worker and "x2dii-session-context-v2" in worker
        assert "SESSION_KIND\" = install" in worker
        assert "X2DII_BOUNDARY_REQUEST:" in worker
        assert "chcon " not in worker and "mkdir " not in worker
        assert "readlink /proc/1" not in worker
        # Formal session data names the service, but su must not inspect it.
        assert "sha256sum /system/bin/camera-service" not in worker
        assert "readlink /proc/\"$X2DII_SESSION_CORE_SERVICE_PID" not in worker
    for action in ("activate", "restore"):
        assert "maintenance_boundaries=UNCONNECTED" not in programs[action + "-boot.sh"]
        assert "X2DII_BOOT_BOUNDARY_REQUEST:" + action in programs[action + "-boot.sh"]
        assert "HOST_MEDIATED_FIXED_BOOT_MATCHED" in programs[action + "-boot.sh"]
    assert ".payload-identities-" in programs["activate-boot.sh"]
    # Connected sources still do not establish camera qualification.
    assert manifest["role_deployment"]["status"] == "SOURCE_CONNECTED_UNQUALIFIED"
    assert manifest["role_deployment"]["remaining"] == ["current_target_qualification"]
    assert manifest["installable"] is False and manifest["scripts_emitted"] is False
    assert manifest["role_deployment"]["format_version"] == ROLE_FORMAT_VERSION


def test_build_subject_binds_new_role_programs_not_only_the_legacy_three():
    manifest = peer.inventory()
    inputs = {"tests/explicit-inert-build-boundary": {"sha256": "a" * 64, "bytes": 1}}
    with mock.patch.object(release_identity, "source_inputs", return_value=inputs):
        baseline = peer.build_subject_sha256(manifest)
        programs = peer.render_role_programs(manifest)
        programs["preplace-2.sh"] += "\n# changed fixed source\n"
        with mock.patch.object(peer, "render_role_programs", return_value=programs):
            assert peer.build_subject_sha256(manifest) != baseline


def test_role_delivery_identity_is_supported_but_never_creates_qualification():
    identity = {"package_sha256": "d" * 64, "package_bytes": 16384,
                "format_version": ROLE_FORMAT_VERSION, "member_manifest_sha256": "e" * 64}
    assert release_identity.validate_delivery_identity(identity) == identity
    assert "approved" not in identity and "installable" not in identity


def test_role_route_reaches_assembly_boundary_only_after_external_admission(tmp_path):
    # Explicit counterfactual boundary test: never build an archive, create a
    # qualified output or invoke native access. Real admission is tested below.
    manifest = peer.inventory()
    qualification = {"test_fixture_only": True,
                     "build_subject_sha256": peer.build_subject_sha256(manifest)}
    with mock.patch.object(peer, "validate_qualification") as check, \
         mock.patch("tools.delivery_files.assemble_role_delivery",
                    side_effect=RuntimeError("TEST_ONLY assembly boundary; no archive created")) as assembly, \
         mock.patch("tools.output_guard.publish_output_set") as publish:
        with pytest.raises(RuntimeError, match="TEST_ONLY assembly boundary"):
            peer.prepare(tmp_path, qualification=qualification)
    assert check.call_args.kwargs == {"for_publication": True}
    assembly.assert_called_once()
    publish.assert_not_called()


@pytest.mark.parametrize("qualification", ({}, {"synthetic": True}, {"test_fixture_only": True}))
def test_connected_role_route_keeps_real_unqualified_admission_closed(tmp_path, qualification):
    with mock.patch("tools.delivery_files.assemble_role_delivery") as assembly, \
         mock.patch("tools.output_guard.publish_output_set") as publish:
        with pytest.raises(ValueError):
            peer.prepare(tmp_path, qualification=qualification)
    assembly.assert_not_called()
    publish.assert_not_called()


def test_unqualified_output_refuses_stale_role_programs():
    with tempfile.TemporaryDirectory(prefix="role-source-refusal-", dir=peer.ROOT / "build") as folder:
        root = Path(folder)
        stale = root / "preplace-0.sh"
        stale.write_bytes(b"INERT STALE TEST DATA\n")
        with pytest.raises(ValueError, match="unqualified output already contains"):
            peer.prepare(root)
        assert stale.read_bytes() == b"INERT STALE TEST DATA\n"
        assert not (root / "peer-install-source.json").exists()
