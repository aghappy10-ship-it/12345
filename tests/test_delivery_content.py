"""Pure-memory codec tests; every payload here is explicitly synthetic and inert."""
import hashlib
import copy
import io
import json
import tarfile

import pytest

from tools import delivery_content as content


NAMES = (
    "libx2dii_menu.so",
    "X2d2MenuBootstrap.qml",
    "X2d2MenuModel.qml",
    "X2d2MenuPage.qml",
    "camera-gui.rc.proposed",
    "install-files.sh",
    "activate-boot.sh",
    "restore-boot.sh",
)
CANDIDATE = "a" * 64


def synthetic_members():
    return {name: b"SYNTHETIC INERT CONTENT: " + name.encode("ascii") for name in NAMES}


def changed_header(archive, start, offset, raw, *, checksum=True):
    changed = bytearray(archive)
    changed[start + offset:start + offset + len(raw)] = raw
    if checksum:
        changed[start + 148:start + 156] = b"        "
        total = sum(changed[start:start + 512])
        changed[start + 148:start + 156] = f"{total:06o}".encode("ascii") + b"\0 "
    return bytes(changed)


def independent_archive(members, manifest, *, manifest_raw=None):
    """Independent stdlib writer of synthetic bytes, trimmed to two end blocks."""
    raw_manifest = (json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("ascii")
                    if manifest_raw is None else manifest_raw)
    buffer = io.BytesIO()
    end = 0
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as writer:
        for name, raw in [*members.items(), ("members.json", raw_manifest)]:
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            info.mode = 0o755 if name.endswith(".sh") else 0o644
            writer.addfile(info, io.BytesIO(raw))
            end += 512 + ((len(raw) + 511) // 512) * 512
    return buffer.getvalue()[:end + 1024]


def test_synthetic_content_roundtrips_as_nine_fixed_members_with_detached_identity():
    members = synthetic_members()
    manifest = content.plan_content(members, CANDIDATE)
    archive = content.encode_content(members, CANDIDATE)
    identity = content.verify_content(archive, manifest)

    # A separate standard-library reader must agree on actual archive membership.
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as reader:
        assert reader.getnames() == [*NAMES, "members.json"]
        for name, expected in members.items():
            assert reader.extractfile(name).read() == expected
        manifest_bytes = reader.extractfile("members.json").read()
        assert json.loads(manifest_bytes) == manifest

    assert manifest["candidate_sha256"] == CANDIDATE
    assert [entry["name"] for entry in manifest["members"]] == list(NAMES)
    assert identity == {
        "package_sha256": hashlib.sha256(archive).hexdigest(),
        "package_bytes": len(archive),
        "format_version": "x2dii-delivery-content-ustar-v1",
        "member_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
    }
    assert "package_sha256" not in manifest
    assert "session" not in manifest


@pytest.mark.parametrize("change", ["extra", "missing", "mutable", "empty", "bad-candidate"])
def test_plan_and_encoder_reject_noncanonical_input_contract(change):
    members = synthetic_members()
    candidate = CANDIDATE
    if change == "extra":
        members["session-context.data"] = b"SYNTHETIC SESSION MUST NOT BE PACKAGED"
    elif change == "missing":
        members.pop(NAMES[0])
    elif change == "mutable":
        members[NAMES[0]] = bytearray(b"SYNTHETIC MUTABLE")
    elif change == "empty":
        members[NAMES[0]] = b""
    else:
        candidate = "not-a-sha256"
    for interface in (content.plan_content, content.encode_content):
        with pytest.raises(ValueError):
            interface(members, candidate)


@pytest.mark.parametrize("offset,replacement", [
    (100, b"0000777\0"), (108, b"0000001\0"), (116, b"0000001\0"),
    (136, b"00000000001\0"), (156, b"2"), (157, b"SYNTHETIC_LINK"),
    (257, b"magic!"), (263, b"01"), (265, b"owner"), (297, b"group"),
    (329, b"0000001\0"), (337, b"0000001\0"), (345, b"prefix"),
    (500, b"x"), (99, b"x"), (124, b" "),
    (156, b"1"), (156, b"3"), (156, b"4"), (156, b"5"), (156, b"6"),
    (156, b"7"), (156, b"x"), (156, b"g"), (156, b"L"), (156, b"K"),
    (156, b"S"), (156, b"\0"), (124, b"\x80"), (124, b"-"),
])
def test_verifier_rejects_noncanonical_header_even_with_valid_checksum(offset, replacement):
    members = synthetic_members()
    archive = content.encode_content(members, CANDIDATE)
    changed = changed_header(archive, 0, offset, replacement)
    with pytest.raises(ValueError):
        content.verify_content(changed, content.plan_content(members, CANDIDATE))


@pytest.mark.parametrize("checksum", [b"000000\0 ", b"777777\0\0", b"00000000", b"        "])
def test_verifier_rejects_header_checksum_corruption(checksum):
    members = synthetic_members()
    archive = content.encode_content(members, CANDIDATE)
    changed = changed_header(archive, 0, 148, checksum, checksum=False)
    with pytest.raises(ValueError):
        content.verify_content(changed, content.plan_content(members, CANDIDATE))


def test_verifier_rejects_nonzero_member_alignment_padding():
    members = synthetic_members()
    archive = bytearray(content.encode_content(members, CANDIDATE))
    archive[512 + len(members[NAMES[0]])] = 1
    with pytest.raises(ValueError):
        content.verify_content(bytes(archive), content.plan_content(members, CANDIDATE))


def test_verifier_accepts_independent_canonical_archive_without_using_our_encoder():
    members = synthetic_members()
    manifest = content.plan_content(members, CANDIDATE)
    independent = independent_archive(members, manifest)
    assert content.verify_content(independent, manifest)["package_bytes"] == len(independent)


@pytest.mark.parametrize("change", ["schema", "format", "candidate", "extra-field", "mode", "entry-field"])
def test_verifier_rejects_malformed_expected_manifest_even_when_archive_agrees(change):
    members = synthetic_members()
    manifest = copy.deepcopy(content.plan_content(members, CANDIDATE))
    if change == "schema":
        manifest["schema"] = "invented"
    elif change == "format":
        manifest["format_version"] = "invented"
    elif change == "candidate":
        manifest["candidate_sha256"] = "not-a-digest"
    elif change == "extra-field":
        manifest["approved"] = True
    elif change == "mode":
        manifest["members"][0]["mode"] = 0o777
    else:
        manifest["members"][0]["target"] = "/invented"
    forged = independent_archive(members, manifest)
    with pytest.raises(ValueError):
        content.verify_content(forged, manifest)


def test_verifier_rejects_extra_member_even_if_forged_expected_manifest_agrees():
    members = synthetic_members()
    manifest = content.plan_content(members, CANDIDATE)
    members["session-context.data"] = b"SYNTHETIC MUST NOT BE PACKAGED"
    manifest["members"].append({"name": "session-context.data", "mode": 0o644,
                                "bytes": len(members["session-context.data"]),
                                "sha256": hashlib.sha256(members["session-context.data"]).hexdigest()})
    with pytest.raises(ValueError):
        content.verify_content(independent_archive(members, manifest), manifest)


@pytest.mark.parametrize("change", ["per-member", "total-archive"])
def test_planning_and_encoding_enforce_resource_limits_before_serialization(change):
    members = synthetic_members()
    if change == "per-member":
        members[NAMES[0]] = b"SYNTHETIC" * ((64 * 1024 * 1024) // 9 + 1)
    else:
        members = dict.fromkeys(NAMES, b"SYNTHETIC" * ((17 * 1024 * 1024) // 9 + 1))
    for interface in (content.plan_content, content.encode_content):
        with pytest.raises(ValueError, match="limit"):
            interface(members, CANDIDATE)


@pytest.mark.parametrize("change", ["per-member", "total-archive"])
def test_verifier_checks_declared_resource_limits_before_reading_archive(change):
    manifest = content.plan_content(synthetic_members(), CANDIDATE)
    if change == "per-member":
        manifest["members"][0]["bytes"] = 64 * 1024 * 1024 + 1
    else:
        for entry in manifest["members"]:
            entry["bytes"] = 17 * 1024 * 1024
    with pytest.raises(ValueError, match="limit"):
        content.verify_content(b"", manifest)


def test_verifier_requires_immutable_archive_bytes():
    members = synthetic_members()
    archive = bytearray(content.encode_content(members, CANDIDATE))
    with pytest.raises(ValueError):
        content.verify_content(archive, content.plan_content(members, CANDIDATE))


def test_encoder_is_deterministic_independent_of_mapping_insertion_order():
    members = synthetic_members()
    reverse = dict(reversed(list(members.items())))
    manifest = content.plan_content(members, CANDIDATE)
    archive = content.encode_content(members, CANDIDATE)
    assert content.plan_content(reverse, CANDIDATE) == manifest
    assert content.encode_content(reverse, CANDIDATE) == archive
    assert archive == independent_archive(members, manifest)
    assert members == synthetic_members()


@pytest.mark.parametrize("name", ["../libx2dii_menu.so", "/libx2dii_menu.so", "dir/libx2dii_menu.so",
                                  "..\\libx2dii_menu.so", "members.json", "X2d2MenuModel.qml"])
def test_verifier_rejects_alternate_member_paths_or_duplicate_names(name):
    members = synthetic_members()
    archive = content.encode_content(members, CANDIDATE)
    forged = changed_header(archive, 0, 0, name.encode("ascii").ljust(100, b"\0"))
    with pytest.raises(ValueError):
        content.verify_content(forged, content.plan_content(members, CANDIDATE))


@pytest.mark.parametrize("change", ["one-zero-block", "extra-zero-block", "extra-data", "concatenated",
                                   "missing-tail", "nonzero-tail", "duplicate-member", "reordered-members"])
def test_verifier_rejects_noncanonical_membership_and_archive_framing(change):
    members = synthetic_members()
    archive = content.encode_content(members, CANDIDATE)
    if change == "one-zero-block":
        forged = archive[:-512]
    elif change == "extra-zero-block":
        forged = archive + bytes(512)
    elif change == "extra-data":
        forged = archive + b"SYNTHETIC TRAILING DATA"
    elif change == "concatenated":
        forged = archive + archive
    elif change == "missing-tail":
        forged = archive[:-1024]
    elif change == "nonzero-tail":
        forged = archive[:-1] + b"X"
    elif change == "duplicate-member":
        forged = archive[:1024] + archive
    else:
        forged = archive[1024:2048] + archive[:1024] + archive[2048:]
    with pytest.raises(ValueError):
        content.verify_content(forged, content.plan_content(members, CANDIDATE))


@pytest.mark.parametrize("length", [0, 1, 511, 512, 513, 1023, 1024, 2047, 4095])
def test_verifier_rejects_truncated_archives(length):
    members = synthetic_members()
    archive = content.encode_content(members, CANDIDATE)
    with pytest.raises(ValueError):
        content.verify_content(archive[:length], content.plan_content(members, CANDIDATE))


@pytest.mark.parametrize("member_index", range(9))
def test_verifier_detects_content_tampering_in_every_member(member_index):
    members = synthetic_members()
    archive = bytearray(content.encode_content(members, CANDIDATE))
    # The eight explicitly tiny synthetic payloads each occupy one data block.
    archive[member_index * 1024 + 512] ^= 1
    with pytest.raises(ValueError):
        content.verify_content(bytes(archive), content.plan_content(members, CANDIDATE))


@pytest.mark.parametrize("change", ["different-candidate", "different-member", "pretty-json", "duplicate-key"])
def test_verifier_rejects_manifest_disagreement_or_noncanonical_json(change):
    members = synthetic_members()
    expected = content.plan_content(members, CANDIDATE)
    changed = copy.deepcopy(expected)
    raw = None
    if change == "different-candidate":
        changed["candidate_sha256"] = "b" * 64
    elif change == "different-member":
        changed["members"][0]["sha256"] = "b" * 64
    elif change == "pretty-json":
        raw = json.dumps(expected, indent=2).encode("ascii")
    else:
        raw = (b'{"candidate_sha256":"' + CANDIDATE.encode("ascii") + b'",' +
               json.dumps(expected, sort_keys=True, separators=(",", ":")).encode("ascii")[1:])
    with pytest.raises(ValueError):
        content.verify_content(independent_archive(members, changed, manifest_raw=raw), expected)


@pytest.mark.parametrize("size", [511, 512, 513, 1023, 1024, 1025])
def test_exact_block_boundaries_roundtrip_with_independent_reader(size):
    members = synthetic_members()
    members[NAMES[0]] = (b"SYNTHETIC INERT BLOCK BOUNDARY " * (size // 29 + 1))[:size]
    assert len(members[NAMES[0]]) == size
    manifest = content.plan_content(members, CANDIDATE)
    archive = content.encode_content(members, CANDIDATE)
    assert archive == independent_archive(members, manifest)
    assert content.verify_content(archive, manifest)["package_bytes"] == len(archive)


@pytest.mark.parametrize("field,value", [
    ("bytes", True), ("bytes", 0), ("bytes", -1), ("bytes", "42"),
    ("bytes", 1.5), ("mode", True), ("mode", "420"), ("sha256", "A" * 64),
    ("sha256", None), ("name", "../escape"), ("name", None),
])
def test_verifier_rejects_invalid_expected_member_field_types_and_values(field, value):
    members = synthetic_members()
    manifest = content.plan_content(members, CANDIDATE)
    archive = content.encode_content(members, CANDIDATE)
    manifest["members"][0][field] = value
    with pytest.raises(ValueError):
        content.verify_content(archive, manifest)


@pytest.mark.parametrize("bad_manifest", [None, [], b"SYNTHETIC", {}, {"members": []}])
def test_verifier_rejects_invalid_expected_manifest_shape(bad_manifest):
    with pytest.raises(ValueError):
        content.verify_content(b"SYNTHETIC INVALID ARCHIVE", bad_manifest)


@pytest.mark.parametrize("candidate", [None, True, b"a" * 64, "A" * 64, "a" * 63, "a" * 65, "a" * 64 + "\n"])
def test_candidate_identity_requires_exact_lowercase_hex(candidate):
    for interface in (content.plan_content, content.encode_content):
        with pytest.raises(ValueError):
            interface(synthetic_members(), candidate)


@pytest.mark.parametrize("members", [None, [], (), b"SYNTHETIC", {}])
def test_content_input_requires_an_exact_dictionary(members):
    for interface in (content.plan_content, content.encode_content):
        with pytest.raises(ValueError):
            interface(members, CANDIDATE)
