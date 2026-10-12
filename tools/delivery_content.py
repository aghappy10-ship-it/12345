"""Pure-memory delivery content codec, not packaging authority or a publisher.

The explicit v1 eight-member and v2 eleven-member layouts plus members.json use
the same deterministic uncompressed USTAR codec. Archive modes are not claims
about camera file metadata. The manifest's own hash and the archive hash are
detached. No session, qualification, approval, file IO or device IO belongs here.
"""
import hashlib
import json
import re


FORMAT_VERSION = "x2dii-delivery-content-ustar-v1"
ROLE_FORMAT_VERSION = "x2dii-delivery-content-ustar-v2"
MEMBER_NAMES = (
    "libx2dii_menu.so", "X2d2MenuBootstrap.qml", "X2d2MenuModel.qml",
    "X2d2MenuPage.qml", "camera-gui.rc.proposed", "install-files.sh",
    "activate-boot.sh", "restore-boot.sh",
)
ROLE_MEMBER_NAMES = (*MEMBER_NAMES[:5], *(f"preplace-{i}.sh" for i in range(4)),
                     "activate-boot.sh", "restore-boot.sh")
MANIFEST_NAME = "members.json"
BLOCK = 512
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_MANIFEST_BYTES = 8192


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _mode(name):
    return 0o755 if name.endswith(".sh") else 0o644


def _is_digest(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _check_limits(sizes, manifest_size=0):
    if any(size > MAX_MEMBER_BYTES for size in sizes) or manifest_size > MAX_MANIFEST_BYTES:
        raise ValueError("content member size limit exceeded")
    total = sum(BLOCK + size + (-size % BLOCK) for size in [*sizes, manifest_size]) + 2 * BLOCK
    if total > MAX_ARCHIVE_BYTES:
        raise ValueError("archive size limit exceeded")
    return total


def plan_content(members: dict[str, bytes], candidate_sha256: str) -> dict:
    """Return the canonical content description, without archive or self hash."""
    return _plan_content(members, candidate_sha256, role_aware=False)


def plan_role_content(members: dict[str, bytes], candidate_sha256: str) -> dict:
    """Fixed eleven-member replacement: four su workers, activation and restore.

    Maintenance observers and session data are deliberately not archive members.
    This pure content contract confers no installation or publication authority.
    """
    return _plan_content(members, candidate_sha256, role_aware=True)


def _plan_content(members, candidate_sha256, *, role_aware):
    names = ROLE_MEMBER_NAMES if role_aware else MEMBER_NAMES
    if type(members) is not dict or set(members) != set(names):
        raise ValueError(f"exactly the {len(names)} fixed content members are required")
    if not _is_digest(candidate_sha256):
        raise ValueError("candidate_sha256 must be a lowercase SHA256")
    if any(type(raw) is not bytes or not raw for raw in members.values()):
        raise ValueError("content members must be nonempty immutable bytes")
    _check_limits([len(members[name]) for name in names])
    manifest = {"schema": "x2dii-delivery-members-v2" if role_aware else "x2dii-delivery-members-v1",
                "format_version": ROLE_FORMAT_VERSION if role_aware else FORMAT_VERSION,
                "candidate_sha256": candidate_sha256,
                "members": [{"name": name, "bytes": len(members[name]),
                             "sha256": _sha(members[name]), "mode": _mode(name)}
                            for name in names]}
    _check_limits([entry["bytes"] for entry in manifest["members"]], len(_canonical(manifest)))
    return manifest


def _octal(value, width):
    return format(value, "0" + str(width - 1) + "o").encode("ascii") + b"\0"


def _header(name, size):
    header = bytearray(BLOCK)
    encoded = name.encode("ascii")
    header[:len(encoded)] = encoded
    header[100:108] = _octal(_mode(name), 8)
    header[108:116] = _octal(0, 8)
    header[116:124] = _octal(0, 8)
    header[124:136] = _octal(size, 12)
    header[136:148] = _octal(0, 12)
    header[148:156] = b"        "
    header[156:157] = b"0"
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    header[148:156] = format(sum(header), "06o").encode("ascii") + b"\0 "
    return bytes(header)


def encode_content(members: dict[str, bytes], candidate_sha256: str) -> bytes:
    """Serialize fixed content in memory; this confers no release qualification."""
    manifest = plan_content(members, candidate_sha256)
    return _encode_content(members, manifest)


def encode_role_content(members: dict[str, bytes], candidate_sha256: str) -> bytes:
    """Serialize the explicit fixed v2 role layout, never inferred from names."""
    return _encode_content(members, plan_role_content(members, candidate_sha256))


def _encode_content(members, manifest):
    parts = []
    for name in (*[row["name"] for row in manifest["members"]], MANIFEST_NAME):
        raw = _canonical(manifest) if name == MANIFEST_NAME else members[name]
        parts.extend((_header(name, len(raw)), raw, bytes(-len(raw) % BLOCK)))
    return b"".join((*parts, bytes(BLOCK * 2)))


def _read_octal(field):
    if not re.fullmatch(rb"[0-7]+\x00", field):
        raise ValueError("noncanonical archive number")
    return int(field[:-1], 8)


def _read_header(header, expected_name):
    """Parse and check fields independently; never call the encoder."""
    if len(header) != BLOCK:
        raise ValueError("truncated archive header")
    if header[:100] != expected_name.encode("ascii").ljust(100, b"\0"):
        raise ValueError("unexpected archive member name or order")
    if not re.fullmatch(rb"[0-7]{6}\x00 ", header[148:156]):
        raise ValueError("noncanonical archive checksum")
    if int(header[148:154], 8) != sum(header[:148]) + 8 * 32 + sum(header[156:]):
        raise ValueError("archive checksum mismatch")
    if (_read_octal(header[100:108]) != _mode(expected_name)
            or _read_octal(header[108:116]) != 0
            or _read_octal(header[116:124]) != 0
            or _read_octal(header[136:148]) != 0):
        raise ValueError("noncanonical archive metadata")
    if (header[156:157] != b"0" or header[157:257] != bytes(100)
            or header[257:265] != b"ustar\x0000"
            or header[265:512] != bytes(247)):
        raise ValueError("only canonical regular USTAR members are supported")
    return _read_octal(header[124:136])


def _validate_manifest(manifest):
    if type(manifest) is not dict or set(manifest) != {"schema", "format_version", "candidate_sha256", "members"}:
        raise ValueError("invalid manifest fields")
    layout = (manifest["schema"], manifest["format_version"])
    if layout == ("x2dii-delivery-members-v1", FORMAT_VERSION):
        names = MEMBER_NAMES
    elif layout == ("x2dii-delivery-members-v2", ROLE_FORMAT_VERSION):
        names = ROLE_MEMBER_NAMES
    else:
        raise ValueError("invalid manifest schema, format or candidate")
    if not _is_digest(manifest["candidate_sha256"]):
        raise ValueError("invalid manifest schema, format or candidate")
    entries = manifest["members"]
    if type(entries) is not list or len(entries) != len(names):
        raise ValueError(f"manifest must describe exactly {len(names)} input members")
    for name, entry in zip(names, entries):
        if type(entry) is not dict or set(entry) != {"name", "bytes", "sha256", "mode"}:
            raise ValueError("invalid manifest member fields")
        if (entry["name"] != name or type(entry["bytes"]) is not int or entry["bytes"] <= 0
                or not _is_digest(entry["sha256"]) or type(entry["mode"]) is not int
                or entry["mode"] != _mode(name)):
            raise ValueError("invalid manifest member identity")
    sizes = [entry["bytes"] for entry in entries]
    _check_limits(sizes)
    raw = _canonical(manifest)
    return raw, _check_limits(sizes, len(raw))


def verify_content(archive_bytes: bytes, expected_manifest: dict) -> dict:
    """Independently read the archive and return detached byte identity only."""
    if type(archive_bytes) is not bytes:
        raise ValueError("archive must be immutable bytes")
    if len(archive_bytes) > MAX_ARCHIVE_BYTES:
        raise ValueError("archive size limit exceeded")
    manifest_bytes, expected_bytes = _validate_manifest(expected_manifest)
    if len(archive_bytes) != expected_bytes:
        raise ValueError("archive length does not match exact content framing")
    position = 0
    for entry in [*expected_manifest["members"],
                  {"name": MANIFEST_NAME, "bytes": len(manifest_bytes), "sha256": _sha(manifest_bytes)}]:
        header = archive_bytes[position:position + BLOCK]
        size = _read_header(header, entry["name"])
        if size != entry["bytes"]:
            raise ValueError("archive member does not match manifest")
        position += BLOCK
        raw = archive_bytes[position:position + size]
        if _sha(raw) != entry["sha256"]:
            raise ValueError("archive member content mismatch")
        if archive_bytes[position + size:position + size + (-size % BLOCK)] != bytes(-size % BLOCK):
            raise ValueError("nonzero archive member padding")
        position += size + (-size % BLOCK)
    if archive_bytes[position:] != bytes(BLOCK * 2):
        raise ValueError("archive must end in exactly two zero blocks")
    return {"package_sha256": _sha(archive_bytes), "package_bytes": len(archive_bytes),
            "format_version": expected_manifest["format_version"], "member_manifest_sha256": _sha(manifest_bytes)}
