"""Read fixed content into an in-memory archive only after caller qualification.

This module grants no authority, publishes no files and never executes scripts.
The caller supplies either v1's three strings or v2's six role-program strings
from its same reviewed render. This returns content identity only; qualification
and publication remain external. Tests use only synthetic input trees under
this active project's build directory; no real candidate archive is published.
"""
import hashlib
import os
from pathlib import Path
import stat

from . import boot_config as boot
from .check_payload_stage import ROOT, RC_SOURCE, _source_path
from .delivery_content import encode_content, encode_role_content, verify_content
from .delivery_plan import PAYLOADS, PROGRAMS, ROLE_PROGRAMS, plan_delivery, plan_role_delivery


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read_fixed(root, relative, limit):
    """Reuse stage path checks and its single-handle freeze, with bounded reads.

    check_payload_stage._regular_bytes uses read() without a size; the same
    lstat/fstat/read/fstat/lstat identity mechanism is kept here with limit + 1.
    This detects observed changes, not adversarial atomic parent replacement.
    """
    path = _source_path(root, relative)
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or getattr(before, "st_file_attributes", 0) & 0x400
            or before.st_nlink != 1):
        raise ValueError("regular non-reparse, non-hard-linked input required")
    if not 0 < before.st_size <= limit:
        raise ValueError("fixed input size limit exceeded")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if _identity(opened) != _identity(before):
            raise ValueError("input identity changed during open")
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    final = _source_path(root, relative).lstat()
    if (_identity(after) != _identity(before) or _identity(final) != _identity(before)
            or len(raw) != before.st_size or not 0 < len(raw) <= limit):
        raise ValueError("input changed during bounded read")
    return raw, _identity(before)


def assemble_delivery(candidate, candidate_sha256, rendered_scripts, *, source_root=ROOT):
    """Freeze fixed inputs, bind candidate/program bytes, and independently verify."""
    return _assemble_delivery(candidate, candidate_sha256, rendered_scripts,
                              source_root=source_root, role_aware=False)


def assemble_role_delivery(candidate, candidate_sha256, rendered_scripts, *, source_root=ROOT):
    """In-memory v2 replacement assembly; never publish or execute a program."""
    return _assemble_delivery(candidate, candidate_sha256, rendered_scripts,
                              source_root=source_root, role_aware=True)


def _assemble_delivery(candidate, candidate_sha256, rendered_scripts, *, source_root, role_aware):
    names = ROLE_PROGRAMS if role_aware else PROGRAMS
    if type(rendered_scripts) is not dict or set(rendered_scripts) != set(names):
        raise ValueError(f"exactly {len(names)} fixed rendered script names are required")
    if any(type(text) is not str or not text or not text.isascii() for text in rendered_scripts.values()):
        raise ValueError("rendered scripts must be nonempty ASCII strings")
    programs = {name: rendered_scripts[name].encode("ascii") for name in names}
    root = Path(os.path.abspath(source_root))
    members = {}
    snapshots = {}
    for relative in (*[source for source, _ in PAYLOADS], RC_SOURCE):
        limit = boot.MAX_BYTES if relative == RC_SOURCE else 8 * 1024 * 1024 - 1
        raw, identity = _read_fixed(root, relative, limit)
        members[Path(relative).name] = raw
        snapshots[relative] = (raw, identity, limit)
    members.update(programs)
    hashes = {name: hashlib.sha256(members[name]).hexdigest() for name in names}
    manifest = (plan_role_delivery if role_aware else plan_delivery)(
        members, candidate=candidate, candidate_sha256=candidate_sha256, script_hashes=hashes)
    archive = (encode_role_content if role_aware else encode_content)(members, candidate_sha256)
    identity = verify_content(archive, manifest)
    for relative, (expected_raw, expected_identity, limit) in snapshots.items():
        raw, current_identity = _read_fixed(root, relative, limit)
        if raw != expected_raw or current_identity != expected_identity:
            raise ValueError("fixed input changed during assembly")
    return {"archive_bytes": archive, "content_manifest": manifest, "delivery_identity": identity}
