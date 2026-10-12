"""Fixed role-aware replacement layout; synthetic bytes, no camera or publisher."""
import io
import json
import tarfile
from copy import deepcopy

import pytest

from tools import delivery_content as content
from tools import delivery_plan as delivery
from tests.test_delivery_plan import fixture, digest
from tests.test_delivery_files import synthetic_tree, candidate_hash
from tests.test_delivery_content import independent_archive, changed_header


ROLE_PROGRAMS = (*(f"preplace-{i}.sh" for i in range(4)), "activate-boot.sh", "restore-boot.sh")
NAMES = ("libx2dii_menu.so", "X2d2MenuBootstrap.qml", "X2d2MenuModel.qml",
         "X2d2MenuPage.qml", "camera-gui.rc.proposed", *ROLE_PROGRAMS)


def role_fixture():
    members, candidate, _ = fixture()
    members.pop("install-files.sh")
    for name in ROLE_PROGRAMS:
        members[name] = b"SYNTHETIC INERT ROLE PROGRAM: " + name.encode("ascii")
    members = {name: members[name] for name in NAMES}
    return members, candidate, {name: digest(members[name]) for name in ROLE_PROGRAMS}


def test_eleven_member_role_content_has_distinct_schema_and_independent_roundtrip():
    members, _, _ = role_fixture()
    plan = content.plan_role_content(members, "a" * 64)
    archive = content.encode_role_content(members, "a" * 64)
    assert plan["schema"] == "x2dii-delivery-members-v2"
    assert plan["format_version"] == "x2dii-delivery-content-ustar-v2"
    identity = content.verify_content(archive, plan)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as reader:
        assert reader.getnames() == [*NAMES, "members.json"]
        for name, raw in members.items():
            assert reader.extractfile(name).read() == raw
        assert json.loads(reader.extractfile("members.json").read()) == plan
    assert identity["format_version"] == plan["format_version"]
    assert identity["package_sha256"] == digest(archive)
    # V1's monolithic install entry cannot accidentally consume the new set.
    with pytest.raises(ValueError):
        content.plan_content(members, "a" * 64)


def test_role_programs_bind_to_same_candidate_without_monolithic_install_entry():
    members, candidate, scripts = role_fixture()
    digest_candidate = digest(json.dumps(candidate, sort_keys=True, separators=(",", ":")).encode())
    result = delivery.plan_role_delivery(members, candidate=candidate,
                                         candidate_sha256=digest_candidate, script_hashes=scripts)
    assert [row["name"] for row in result["members"]] == list(NAMES)
    assert result["candidate_sha256"] == digest_candidate
    assert "install-files.sh" not in scripts
    with pytest.raises(ValueError):
        delivery.plan_delivery(members, candidate=candidate,
                               candidate_sha256=digest_candidate, script_hashes=scripts)


def test_fixed_role_assembly_reads_payloads_but_does_not_write_package(synthetic_tree):
    from tools.delivery_files import assemble_role_delivery
    root, _, candidate, _ = synthetic_tree
    before = sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file())
    scripts = {name: "# SYNTHETIC INERT ROLE PROGRAM: " + name + "\n" for name in ROLE_PROGRAMS}
    result = assemble_role_delivery(candidate, candidate_hash(candidate), scripts, source_root=root)
    with tarfile.open(fileobj=io.BytesIO(result["archive_bytes"]), mode="r:") as reader:
        assert reader.getnames() == [*NAMES, "members.json"]
        for name, text in scripts.items():
            assert reader.extractfile(name).read() == text.encode("ascii")
    assert result["content_manifest"]["schema"] == "x2dii-delivery-members-v2"
    assert result["delivery_identity"]["format_version"] == "x2dii-delivery-content-ustar-v2"
    assert sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()) == before


@pytest.mark.parametrize("fault", ("monolithic", "missing-worker", "observer", "session", "extra-worker"))
def test_role_layout_refuses_legacy_entry_or_noncontent_programs(fault):
    members, _, _ = role_fixture()
    if fault == "monolithic":
        members.pop("preplace-0.sh")
        members["install-files.sh"] = b"SYNTHETIC WRONG ROLE"
    elif fault == "missing-worker":
        members.pop("preplace-3.sh")
    else:
        members[{"observer": "maintenance-observer.sh", "session": "session-context.data",
                 "extra-worker": "preplace-4.sh"}[fault]] = b"SYNTHETIC EXTRA"
    for entry in (content.plan_role_content, content.encode_role_content):
        with pytest.raises(ValueError):
            entry(members, "a" * 64)


@pytest.mark.parametrize("name", NAMES)
def test_changed_role_member_cannot_reuse_candidate_or_program_hash(name):
    members, candidate, scripts = role_fixture()
    members[name] += b" CHANGED"
    with pytest.raises(ValueError):
        delivery.plan_role_delivery(members, candidate=candidate,
                                     candidate_sha256=candidate_hash(candidate), script_hashes=scripts)


@pytest.mark.parametrize("fault", ("v1-schema", "v1-format", "worker-order", "worker-name", "worker-mode"))
def test_role_archive_verifier_refuses_self_consistent_wrong_layout(fault):
    members, _, _ = role_fixture()
    manifest = deepcopy(content.plan_role_content(members, "a" * 64))
    if fault == "v1-schema":
        manifest["schema"] = "x2dii-delivery-members-v1"
    elif fault == "v1-format":
        manifest["format_version"] = "x2dii-delivery-content-ustar-v1"
    elif fault == "worker-order":
        manifest["members"][5], manifest["members"][6] = manifest["members"][6], manifest["members"][5]
    elif fault == "worker-name":
        manifest["members"][5]["name"] = "install-files.sh"
    else:
        manifest["members"][5]["mode"] = 0o644
    with pytest.raises(ValueError):
        content.verify_content(independent_archive(members, manifest), manifest)


def test_independent_role_archive_matches_encoder_without_weakening_canonical_parser():
    members, _, _ = role_fixture()
    manifest = content.plan_role_content(members, "a" * 64)
    independent = independent_archive(members, manifest)
    assert independent == content.encode_role_content(dict(reversed(list(members.items()))), "a" * 64)
    assert content.verify_content(independent, manifest)["package_sha256"] == digest(independent)
    for changed in (independent + bytes(512), independent[:-1],
                    changed_header(independent, 5 * 1024, 156, b"2"),
                    changed_header(independent, 5 * 1024, 0, b"../preplace-0.sh".ljust(100, b"\0"))):
        with pytest.raises(ValueError):
            content.verify_content(changed, manifest)


@pytest.mark.parametrize("fault", ("missing", "legacy", "observer", "not-dict", "empty", "non-ascii"))
def test_role_assembler_refuses_wrong_scripts_before_reading_files(synthetic_tree, monkeypatch, fault):
    from tools import delivery_files
    root, _, candidate, _ = synthetic_tree
    scripts = {name: "# SYNTHETIC ONLY\n" for name in ROLE_PROGRAMS}
    if fault == "missing":
        scripts.pop("preplace-0.sh")
    elif fault in ("legacy", "observer"):
        scripts["install-files.sh" if fault == "legacy" else "maintenance-observer.sh"] = "# WRONG ROLE\n"
    elif fault == "not-dict":
        scripts = list(scripts)
    else:
        scripts["preplace-0.sh"] = "" if fault == "empty" else "# 非ASCII"

    def unexpected_read(*args, **kwargs):
        pytest.fail("malformed fixed role input must be rejected before filesystem access")

    monkeypatch.setattr(delivery_files, "_read_fixed", unexpected_read)
    with pytest.raises(ValueError):
        delivery_files.assemble_role_delivery(candidate, candidate_hash(candidate), scripts, source_root=root)
