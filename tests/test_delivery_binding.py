"""Delivery identity is a release input, never invented installation evidence."""
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from tests.test_release_lifecycle import installer
from tests.test_release_lifecycle import recovery_fixture
from tools import prepare_peer_install as peer
from tools import release_identity


def synthetic_identity():
    # Deliberately no real archive: a shape fixture cannot authorize publication.
    return {"package_sha256": "d" * 64, "package_bytes": 16384,
            "format_version": "x2dii-delivery-content-ustar-v1",
            "member_manifest_sha256": "e" * 64}


def test_changed_delivery_invalidates_lease_without_changing_runtime(installer):
    before = deepcopy(installer.q)
    before["delivery_identity"] = synthetic_identity()
    after = deepcopy(before)
    after["delivery_identity"]["package_sha256"] = "f" * 64
    assert peer.runtime_subject_sha256(installer.manifest, before) == peer.runtime_subject_sha256(installer.manifest, after)
    assert peer.execution_subject_sha256(installer.manifest, before) != peer.execution_subject_sha256(installer.manifest, after)


@pytest.mark.parametrize("phase", ("build", "runtime"))
def test_each_install_evidence_phase_binds_exact_delivery_identity(phase):
    identity = synthetic_identity()
    result = release_identity.gate_bindings(
        phase, candidate_sha256="a" * 64, build_subject_sha256="b" * 64,
        runtime_subject_sha256="c" * 64, boot_id="fixture",
        delivery_identity=identity)
    assert result["delivery_identity"] == identity
    identity["package_bytes"] += 512
    assert result["delivery_identity"]["package_bytes"] == 16384


def test_old_gate_reports_cannot_be_relabelled_for_another_delivery(installer):
    q = installer.validated_shape_fixture()
    old_gates = deepcopy(q["gates"])
    q["delivery_identity"]["package_sha256"] = "f" * 64
    q["execution_subject_sha256"] = peer.execution_subject_sha256(installer.manifest, q)
    q["final_installation_approval"]["execution_subject_sha256"] = q["execution_subject_sha256"]
    with pytest.raises(ValueError, match="proof subject binding mismatch"):
        peer.validate_qualification(installer.manifest, q)
    assert q["gates"] == old_gates


@pytest.mark.parametrize("bad", [None, {}, dict(synthetic_identity(), extra=True),
    dict(synthetic_identity(), package_bytes=True), dict(synthetic_identity(), package_bytes=513),
    dict(synthetic_identity(), package_bytes=0), dict(synthetic_identity(), package_bytes=2**28),
    dict(synthetic_identity(), package_sha256="D" * 64),
    dict(synthetic_identity(), member_manifest_sha256="no"),
    dict(synthetic_identity(), format_version="unknown")])
def test_lease_refuses_missing_or_malformed_delivery_identity(installer, bad):
    q = deepcopy(installer.q)
    q["delivery_identity"] = bad
    with pytest.raises(ValueError, match="delivery identity"):
        peer.execution_subject_sha256(installer.manifest, q)


@pytest.mark.parametrize("name", ["x2dii-menu-content.tar", "members.json", "session-context.data"])
def test_unqualified_source_output_cannot_disguise_stale_delivery_files(installer, name):
    output = installer.root / "source-only"
    output.mkdir()
    raw = b"INERT OLD OUTPUT: not a camera package"
    (output / name).write_bytes(raw)
    with pytest.raises(ValueError, match="unqualified output"):
        peer.prepare(output)
    assert (output / name).read_bytes() == raw
    assert not (output / "peer-install-source.json").exists()


def test_recovery_accepts_saved_delivery_without_current_payload_or_archive(recovery_fixture):
    fixture = recovery_fixture
    saved = deepcopy(fixture.manifest)
    saved.update(status="QUALIFIED_DELIVERY_NOT_EXECUTED", package_created=True,
                 delivery_identity=synthetic_identity())
    # A retained structural record, not a real qualified package. The recovery
    # loader consumes only these bytes and still grants no recovery execution.
    raw = peer.canonical(saved)
    fixture.saved.write_bytes(raw)
    result = fixture.recovery().load_saved_candidate(fixture.saved, peer.sha(raw))
    assert result == saved
    assert not (fixture.root / "x2dii-menu-content.tar").exists()


@pytest.mark.parametrize("change", ("missing_identity", "bad_identity", "not_created"))
def test_saved_new_delivery_requires_its_retained_package_identity(recovery_fixture, change):
    fixture = recovery_fixture
    saved = deepcopy(fixture.manifest)
    saved.update(status="QUALIFIED_DELIVERY_NOT_EXECUTED", package_created=True,
                 delivery_identity=synthetic_identity())
    if change == "missing_identity":
        del saved["delivery_identity"]
    elif change == "bad_identity":
        saved["delivery_identity"]["package_sha256"] = "not a digest"
    else:
        saved["package_created"] = False
    raw = peer.canonical(saved)
    fixture.saved.write_bytes(raw)
    with pytest.raises(ValueError, match="delivery"):
        fixture.recovery().load_saved_candidate(fixture.saved, peer.sha(raw))


def test_legacy_saved_script_manifest_keeps_its_existing_recovery_route(recovery_fixture):
    fixture = recovery_fixture
    result = fixture.recovery().load_saved_candidate(fixture.saved, fixture.saved_sha)
    assert result == fixture.manifest
    assert "delivery_identity" not in result


def test_fixture_with_claimed_archive_identity_cannot_publish_any_delivery(installer):
    q = installer.validated_shape_fixture()
    output = installer.root / "must-not-publish"
    with pytest.raises(ValueError, match="runtime observation test fixture"):
        peer.prepare(output, q)
    assert not output.exists()


@pytest.mark.parametrize("relative", ("tools/delivery_content.py", "tests/test_delivery_binding.py"))
def test_recovery_build_tracks_new_saved_delivery_admission_dependencies(recovery_fixture, monkeypatch, relative):
    fixture = recovery_fixture
    recovery = fixture.recovery()
    before = recovery.build_subject_sha256(fixture.saved, fixture.saved_sha)
    original_read = Path.read_bytes
    target = peer.ROOT / relative

    def changed_input(path):
        raw = original_read(path)
        return raw + b"\n# modeled filesystem drift\n" if path == target else raw

    monkeypatch.setattr(Path, "read_bytes", changed_input)
    assert recovery.build_subject_sha256(fixture.saved, fixture.saved_sha) != before


def test_lease_expiring_during_evidence_reads_cannot_pass_final_qualification(installer, monkeypatch):
    q = installer.validated_shape_fixture()
    observed = datetime.fromisoformat(q["observed_utc"])

    class SteppedClock(datetime):
        calls = 0

        @classmethod
        def now(cls, tz=None):
            cls.calls += 1
            return observed + timedelta(seconds=0 if cls.calls == 1 else 601)

    monkeypatch.setattr(peer, "datetime", SteppedClock)
    with pytest.raises(ValueError, match="expired during qualification"):
        peer.validate_qualification(installer.manifest, q)


def test_new_saved_delivery_recovery_never_reads_mutable_payloads_or_archive(recovery_fixture, monkeypatch):
    fixture = recovery_fixture
    recovery = fixture.recovery()
    saved = deepcopy(fixture.manifest)
    saved.update(status="QUALIFIED_DELIVERY_NOT_EXECUTED", package_created=True,
                 delivery_identity=synthetic_identity())
    raw = peer.canonical(saved)
    fixture.saved.write_bytes(raw)
    original_read = Path.read_bytes

    def block_payload_reads(path):
        relative = path.relative_to(peer.ROOT).as_posix() if path.is_relative_to(peer.ROOT) else ""
        if (relative.startswith(("qml/", "build/native/", "build/units/", "build/boot-config/"))
                or "mutable-source" in path.parts or path.suffix == ".tar"):
            raise AssertionError("recovery attempted mutable payload/archive read: " + str(path))
        return original_read(path)

    monkeypatch.setattr(Path, "read_bytes", block_payload_reads)
    assert recovery.load_saved_candidate(fixture.saved, peer.sha(raw)) == saved
    assert len(recovery.build_subject_sha256(fixture.saved, peer.sha(raw))) == 64
