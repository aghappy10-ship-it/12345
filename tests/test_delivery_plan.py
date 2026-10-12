"""Candidate/content integration uses inert synthetic data only, never camera bytes."""
from copy import deepcopy
import hashlib
import io
import json
import tarfile

import pytest

from tools import delivery_plan as delivery
from tools import delivery_content as content


PAYLOADS = (
    ("build/native/libx2dii_menu.so", "/system/lib64/libx2dii_menu.so"),
    ("qml/X2d2MenuBootstrap.qml", "/system/etc/X2d2MenuBootstrap.qml"),
    ("qml/X2d2MenuModel.qml", "/system/etc/X2d2MenuModel.qml"),
    ("qml/X2d2MenuPage.qml", "/system/etc/X2d2MenuPage.qml"),
)
PROGRAMS = ("install-files.sh", "activate-boot.sh", "restore-boot.sh")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fixture():
    names = [source.rsplit("/", 1)[-1] for source, _ in PAYLOADS]
    members = {name: b"SYNTHETIC INERT NOT FOR CAMERA: " + name.encode()
               for name in [*names, "camera-gui.rc.proposed", *PROGRAMS]}
    candidate = {
        "gui_sha256": "b1b643cb36176cd5a49129dd9bb2be480aa045a96ed1c35c30a779ab5af0801b",
        "files": [{"source": source, "target": target,
                   "sha256": digest(members[name]), "bytes": len(members[name])}
                  for (source, target), name in zip(PAYLOADS, names)],
        "rc": {"source": "build/boot-config/camera-gui.rc.proposed",
               "target": "/system/etc/init/camera-gui.rc",
               "before": "b237e080a60bda4765c1834592d410956931e7d453f33cfa55bc01c5f5d58f1d",
               "after": digest(members["camera-gui.rc.proposed"])},
    }
    return members, candidate, {name: digest(members[name]) for name in PROGRAMS}


def plan(members, candidate, scripts, candidate_hash=None):
    candidate_hash = candidate_hash or digest(
        json.dumps(candidate, sort_keys=True, separators=(",", ":")).encode())
    return delivery.plan_delivery(members, candidate=candidate,
                                  candidate_sha256=candidate_hash, script_hashes=scripts)


def test_exact_synthetic_candidate_and_programs_produce_content_plan_not_authority():
    members, candidate, scripts = fixture()
    originals = deepcopy((members, candidate, scripts))
    result = plan(members, candidate, scripts)
    assert result["schema"] == "x2dii-delivery-members-v1"
    assert [row["name"] for row in result["members"]] == list(members)
    assert result["members"][0]["bytes"] == len(members["libx2dii_menu.so"])
    assert "installable" not in result and "approval" not in result
    assert (members, candidate, scripts) == originals


@pytest.mark.parametrize("member", [source.rsplit("/", 1)[-1] for source, _ in PAYLOADS]
                         + ["camera-gui.rc.proposed", *PROGRAMS])
def test_changed_bytes_cannot_borrow_the_previous_candidate_or_program_hashes(member):
    members, candidate, scripts = fixture()
    members[member] += b" DIFFERENT VERSION"
    with pytest.raises(ValueError):
        plan(members, candidate, scripts)


def test_candidate_hash_must_describe_this_candidate_not_an_older_version():
    members, candidate, scripts = fixture()
    with pytest.raises(ValueError):
        plan(members, candidate, scripts, "f" * 64)


@pytest.mark.parametrize("damage", ["payload-target", "payload-source", "duplicate", "missing",
                                    "extra-row-field", "extra-candidate-field", "rc-source",
                                    "rc-target", "rc-baseline", "gui-baseline", "payload-bool-size",
                                    "program-missing", "program-extra"])
def test_self_consistent_hash_cannot_hide_a_different_layout_or_baseline(damage):
    members, candidate, scripts = fixture()
    if damage == "payload-target":
        candidate["files"][0]["target"] = "/system/bin/camera-service"
    elif damage == "payload-source":
        candidate["files"][0]["source"] = "old/libx2dii_menu.so"
    elif damage == "duplicate":
        candidate["files"][1] = deepcopy(candidate["files"][0])
    elif damage == "missing":
        candidate["files"].pop()
    elif damage == "extra-row-field":
        candidate["files"][0]["approved"] = True
    elif damage == "extra-candidate-field":
        candidate["authority"] = "not part of the content contract"
    elif damage.startswith("rc-"):
        candidate["rc"][{"rc-source": "source", "rc-target": "target", "rc-baseline": "before"}[damage]] = "changed"
    elif damage == "gui-baseline":
        candidate["gui_sha256"] = "0" * 64
    elif damage == "payload-bool-size":
        members["libx2dii_menu.so"] = b"S"
        candidate["files"][0].update(bytes=True, sha256=digest(b"S"))
    elif damage == "program-missing":
        scripts.pop(PROGRAMS[0])
    else:
        scripts["X2d2MenuPage.qml"] = digest(members["X2d2MenuPage.qml"])
    with pytest.raises(ValueError):
        plan(members, candidate, scripts)


@pytest.mark.parametrize("damage", ["candidate-null", "candidate-list", "files-null", "row-null",
                                    "rc-null", "rc-extra", "files-reordered", "programs-list",
                                    "payload-float-size", "hash-nonstring"])
def test_malformed_contract_is_rejected_with_no_partial_plan(damage):
    members, candidate, scripts = fixture()
    if damage == "candidate-null":
        candidate = None
    elif damage == "candidate-list":
        candidate = []
    elif damage == "files-null":
        candidate["files"] = None
    elif damage == "row-null":
        candidate["files"][0] = None
    elif damage == "rc-null":
        candidate["rc"] = None
    elif damage == "rc-extra":
        candidate["rc"]["bytes"] = len(members["camera-gui.rc.proposed"])
    elif damage == "files-reordered":
        candidate["files"].reverse()
    elif damage == "programs-list":
        scripts = list(scripts)
    elif damage == "payload-float-size":
        candidate["files"][0]["bytes"] = float(candidate["files"][0]["bytes"])
    else:
        candidate["files"][0]["sha256"] = None
    with pytest.raises(ValueError):
        plan(members, candidate, scripts)


def test_matching_new_synthetic_bytes_have_new_identity_but_no_trust_or_approval():
    members, candidate, scripts = fixture()
    previous = plan(members, candidate, scripts)
    members["libx2dii_menu.so"] += b" NEW SYNTHETIC VERSION"
    candidate["files"][0].update(bytes=len(members["libx2dii_menu.so"]),
                                  sha256=digest(members["libx2dii_menu.so"]))
    current = plan(members, candidate, scripts)
    assert current["candidate_sha256"] != previous["candidate_sha256"]
    assert current["members"][0]["sha256"] != previous["members"][0]["sha256"]
    assert set(current) == {"schema", "format_version", "candidate_sha256", "members"}


def test_synthetic_plan_encode_and_independent_readback_preserve_the_bound_eight_files():
    members, candidate, scripts = fixture()
    expected = plan(members, candidate, scripts)
    archive = content.encode_content(members, expected["candidate_sha256"])
    identity = content.verify_content(archive, expected)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as reader:
        assert reader.getnames() == [*members, "members.json"]
        for name, original in members.items():
            assert reader.extractfile(name).read() == original
        assert json.loads(reader.extractfile("members.json").read()) == expected
    assert identity["package_sha256"] == digest(archive)
    assert identity["package_bytes"] == len(archive)


def test_old_synthetic_archive_cannot_satisfy_a_new_candidate_plan():
    members, candidate, scripts = fixture()
    old_plan = plan(members, candidate, scripts)
    archive = content.encode_content(members, old_plan["candidate_sha256"])
    members["X2d2MenuPage.qml"] += b" NEW SYNTHETIC PAGE"
    candidate["files"][3].update(bytes=len(members["X2d2MenuPage.qml"]),
                                  sha256=digest(members["X2d2MenuPage.qml"]))
    new_plan = plan(members, candidate, scripts)
    with pytest.raises(ValueError):
        content.verify_content(archive, new_plan)


@pytest.mark.parametrize("index", range(4))
def test_candidate_payload_limit_matches_the_existing_stage_exclusive_eight_mib(index):
    members, candidate, scripts = fixture()
    name = PAYLOADS[index][0].rsplit("/", 1)[-1]
    for size in (8 * 1024 * 1024 - 1, 8 * 1024 * 1024):
        members[name] = b"S" * size  # Inert synthetic bytes, never a real payload.
        candidate["files"][index].update(bytes=size, sha256=digest(members[name]))
        if size < 8 * 1024 * 1024:
            assert plan(members, candidate, scripts)["members"][index]["bytes"] == size
        else:
            with pytest.raises(ValueError, match="payload"):
                plan(members, candidate, scripts)
