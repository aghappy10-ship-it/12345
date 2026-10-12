"""File assembly tests use only explicit synthetic inert files under active build.

No test reads the current candidate, renders real scripts, or writes an archive.
The unique fixture directories and XML reports remain available for inspection.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace

import pytest

from tools import boot_config as boot
from tools import delivery_files
from tools.qt_unit import GUI_SHA256


ROOT = Path(__file__).resolve().parents[1]
PAYLOADS = (
    ("build/native/libx2dii_menu.so", "/system/lib64/libx2dii_menu.so"),
    ("qml/X2d2MenuBootstrap.qml", "/system/etc/X2d2MenuBootstrap.qml"),
    ("qml/X2d2MenuModel.qml", "/system/etc/X2d2MenuModel.qml"),
    ("qml/X2d2MenuPage.qml", "/system/etc/X2d2MenuPage.qml"),
)
RC_SOURCE = "build/boot-config/camera-gui.rc.proposed"
SCRIPTS = ("install-files.sh", "activate-boot.sh", "restore-boot.sh")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def candidate_hash(candidate):
    return sha(json.dumps(candidate, sort_keys=True, separators=(",", ":")).encode())


@pytest.fixture
def synthetic_tree():
    root = Path(tempfile.mkdtemp(prefix="delivery-files-synthetic-", dir=ROOT / "build"))
    members = {}
    files = []
    for source, target in PAYLOADS:
        raw = b"SYNTHETIC INERT PAYLOAD: " + source.encode("ascii")
        path = root / source
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        members[path.name] = raw
        files.append({"source": source, "target": target, "sha256": sha(raw), "bytes": len(raw)})
    rc = b"# SYNTHETIC INERT RC ONLY; NOT A CAMERA CONFIGURATION\n"
    rc_path = root / RC_SOURCE
    rc_path.parent.mkdir(parents=True, exist_ok=True)
    rc_path.write_bytes(rc)
    members[rc_path.name] = rc
    scripts = {name: "# SYNTHETIC INERT SCRIPT: " + name + "\n" for name in SCRIPTS}
    members.update({name: text.encode("ascii") for name, text in scripts.items()})
    candidate = {"gui_sha256": GUI_SHA256, "files": files,
                 "rc": {"source": RC_SOURCE, "target": boot.TARGET,
                        "before": boot.STOCK_SHA256, "after": sha(rc)}}
    return root, members, candidate, scripts


def test_synthetic_fixed_files_assemble_to_exact_content_with_independent_tar_oracle(synthetic_tree):
    root, members, candidate, scripts = synthetic_tree
    result = delivery_files.assemble_delivery(candidate, candidate_hash(candidate), scripts, source_root=root)
    assert set(result) == {"archive_bytes", "content_manifest", "delivery_identity"}
    with tarfile.open(fileobj=io.BytesIO(result["archive_bytes"]), mode="r:") as reader:
        assert reader.getnames() == [*members, "members.json"]
        for name, raw in members.items():
            assert reader.extractfile(name).read() == raw
        raw_manifest = reader.extractfile("members.json").read()
        assert json.loads(raw_manifest) == result["content_manifest"]
    assert result["delivery_identity"] == {
        "package_sha256": sha(result["archive_bytes"]),
        "package_bytes": len(result["archive_bytes"]),
        "format_version": "x2dii-delivery-content-ustar-v1",
        "member_manifest_sha256": sha(raw_manifest),
    }


@pytest.mark.parametrize("change", ["missing", "extra", "overwrite-payload", "non-ascii", "bytes", "empty", "not-dict"])
def test_assembler_accepts_only_three_fixed_nonempty_ascii_script_strings(synthetic_tree, change):
    root, members, candidate, scripts = synthetic_tree
    if change == "missing":
        scripts.pop(SCRIPTS[0])
    elif change == "extra":
        scripts["other.sh"] = "# SYNTHETIC EXTRA\n"
    elif change == "overwrite-payload":
        scripts["libx2dii_menu.so"] = members["libx2dii_menu.so"].decode("ascii")
    elif change == "non-ascii":
        scripts[SCRIPTS[0]] = "# SYNTHETIC 非 ASCII\n"
    elif change == "bytes":
        scripts[SCRIPTS[0]] = b"# SYNTHETIC BYTES\n"
    elif change == "empty":
        scripts[SCRIPTS[0]] = ""
    else:
        scripts = None
    with pytest.raises(ValueError):
        delivery_files.assemble_delivery(candidate, candidate_hash(candidate), scripts, source_root=root)


def test_rc_size_limit_is_enforced_even_when_candidate_hash_agrees(synthetic_tree):
    root, _, candidate, scripts = synthetic_tree
    raw = (b"SYNTHETIC" * (boot.MAX_BYTES // 9 + 1))[:boot.MAX_BYTES + 1]
    (root / RC_SOURCE).write_bytes(raw)
    candidate["rc"]["after"] = sha(raw)
    with pytest.raises(ValueError, match="size"):
        delivery_files.assemble_delivery(candidate, candidate_hash(candidate), scripts, source_root=root)


def test_actual_file_reads_are_bounded_at_the_filesystem_boundary(synthetic_tree, monkeypatch):
    root, _, candidate, scripts = synthetic_tree
    original_open = Path.open
    read_sizes = []

    class BoundedReadProbe:
        def __init__(self, stream, limit):
            self.stream, self.limit = stream, limit

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def fileno(self):
            return self.stream.fileno()

        def read(self, size=-1):
            assert 0 < size <= self.limit + 1, "input read must have a hard byte limit"
            read_sizes.append(size)
            return self.stream.read(size)

    def guarded_open(path, *args, **kwargs):
        stream = original_open(path, *args, **kwargs)
        limit = boot.MAX_BYTES if path == root / RC_SOURCE else 8 * 1024 * 1024 - 1
        return BoundedReadProbe(stream, limit)

    monkeypatch.setattr(Path, "open", guarded_open)
    delivery_files.assemble_delivery(candidate, candidate_hash(candidate), scripts, source_root=root)
    assert read_sizes


@pytest.mark.parametrize("change", ["content", "same-bytes-replacement"])
def test_assembler_rejects_earlier_input_changes_later_in_the_same_assembly(synthetic_tree, monkeypatch, change):
    root, members, candidate, scripts = synthetic_tree
    victim = root / PAYLOADS[0][0]
    original_open = Path.open
    changed = False

    def mutate_on_last_input(path, *args, **kwargs):
        nonlocal changed
        if path == root / RC_SOURCE and not changed:
            changed = True
            raw = members[victim.name]
            if change == "content":
                with original_open(victim, "wb") as writer:
                    writer.write(b"X" + raw[1:])
            else:
                replacement = victim.with_suffix(".synthetic-replacement")
                with original_open(replacement, "wb") as writer:
                    writer.write(raw)
                replacement.replace(victim)
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", mutate_on_last_input)
    with pytest.raises(ValueError, match="changed"):
        delivery_files.assemble_delivery(candidate, candidate_hash(candidate), scripts, source_root=root)
    assert changed


@pytest.mark.parametrize("change", ["candidate-hash", "payload-hash", "payload-size", "payload-source", "payload-target",
                                   "rc-hash", "rc-source", "rc-target", "missing-payload", "extra-payload"])
def test_candidate_mismatch_is_rejected_without_following_its_paths(synthetic_tree, monkeypatch, change):
    root, _, candidate, scripts = synthetic_tree
    expected_hash = candidate_hash(candidate)
    if change == "candidate-hash":
        expected_hash = "f" * 64
    elif change.startswith("payload-"):
        field = {"hash": "sha256", "size": "bytes"}.get(change[8:], change[8:])
        candidate["files"][0][field] = 1 if field == "bytes" else "../../SYNTHETIC-FORBIDDEN-PATH"
    elif change.startswith("rc-"):
        field = "after" if change == "rc-hash" else change[3:]
        candidate["rc"][field] = "../../SYNTHETIC-FORBIDDEN-PATH"
    elif change == "missing-payload":
        candidate["files"].pop()
    else:
        candidate["files"].append(dict(candidate["files"][0]))
    if change != "candidate-hash":
        expected_hash = candidate_hash(candidate)
    fixed_paths = {root / source for source, _ in PAYLOADS} | {root / RC_SOURCE}
    original_open = Path.open
    opened = []

    def fixed_only_open(path, *args, **kwargs):
        assert path in fixed_paths, "caller-supplied candidate path must never be opened"
        opened.append(path)
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fixed_only_open)
    with pytest.raises(ValueError):
        delivery_files.assemble_delivery(candidate, expected_hash, scripts, source_root=root)
    assert set(opened) <= fixed_paths


def test_payload_exactly_eight_mib_is_rejected_before_open(synthetic_tree, monkeypatch):
    root, _, candidate, scripts = synthetic_tree
    target = root / PAYLOADS[0][0]
    raw = (b"SYNTHETIC" * ((8 * 1024 * 1024) // 9 + 1))[:8 * 1024 * 1024]
    target.write_bytes(raw)
    candidate["files"][0].update(bytes=len(raw), sha256=sha(raw))
    original_open = Path.open

    def not_oversized_open(path, *args, **kwargs):
        assert path != target, "oversized input must be rejected before opening"
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", not_oversized_open)
    with pytest.raises(ValueError, match="size"):
        delivery_files.assemble_delivery(candidate, candidate_hash(candidate), scripts, source_root=root)


@pytest.mark.parametrize("kind", ["payload", "rc"])
def test_largest_allowed_synthetic_input_roundtrips(kind, synthetic_tree):
    root, _, candidate, scripts = synthetic_tree
    size = 8 * 1024 * 1024 - 1 if kind == "payload" else boot.MAX_BYTES
    raw = (b"SYNTHETIC" * (size // 9 + 1))[:size]
    relative = PAYLOADS[0][0] if kind == "payload" else RC_SOURCE
    (root / relative).write_bytes(raw)
    if kind == "payload":
        candidate["files"][0].update(bytes=size, sha256=sha(raw))
    else:
        candidate["rc"]["after"] = sha(raw)
    result = delivery_files.assemble_delivery(candidate, candidate_hash(candidate), scripts, source_root=root)
    with tarfile.open(fileobj=io.BytesIO(result["archive_bytes"]), mode="r:") as reader:
        assert reader.extractfile(Path(relative).name).read() == raw


def test_source_root_outside_trusted_tree_is_rejected_before_any_open(synthetic_tree, monkeypatch):
    _, _, candidate, scripts = synthetic_tree

    def forbid_open(*args, **kwargs):
        pytest.fail("an untrusted source root must not open any file")

    monkeypatch.setattr(Path, "open", forbid_open)
    with pytest.raises(ValueError, match="source snapshots"):
        delivery_files.assemble_delivery(candidate, candidate_hash(candidate), scripts, source_root=ROOT.parent)


def test_hard_linked_payload_is_rejected(synthetic_tree):
    root, _, candidate, scripts = synthetic_tree
    target = root / PAYLOADS[0][0]
    os.link(target, root / "SYNTHETIC-hardlink")
    with pytest.raises(ValueError, match="hard-linked"):
        delivery_files.assemble_delivery(candidate, candidate_hash(candidate), scripts, source_root=root)


def test_real_symlinked_payload_is_rejected(synthetic_tree):
    root, _, candidate, scripts = synthetic_tree
    target = root / PAYLOADS[0][0]
    retained = root / "SYNTHETIC-retained-payload"
    target.replace(retained)
    try:
        target.symlink_to(retained)
    except OSError as error:
        if os.name == "nt" and getattr(error, "winerror", None) == 1314:
            pytest.skip("Windows denied actual native symlink creation (WinError 1314); link rejection remains unverified")
        raise
    with pytest.raises(ValueError, match="symlink"):
        delivery_files.assemble_delivery(candidate, candidate_hash(candidate), scripts, source_root=root)


def test_modeled_windows_reparse_ancestor_is_rejected_at_filesystem_boundary(synthetic_tree, monkeypatch):
    root, _, candidate, scripts = synthetic_tree
    original_lstat = Path.lstat

    def reparse_lstat(path, *args, **kwargs):
        info = original_lstat(path, *args, **kwargs)
        if path == root / "build":
            return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400)
        return info

    monkeypatch.setattr(Path, "lstat", reparse_lstat)
    with pytest.raises(ValueError, match="reparse"):
        delivery_files.assemble_delivery(candidate, candidate_hash(candidate), scripts, source_root=root)


def test_same_path_replacement_between_stat_and_open_is_rejected(synthetic_tree, monkeypatch):
    root, members, candidate, scripts = synthetic_tree
    target = root / PAYLOADS[0][0]
    original_open = Path.open
    changed = False

    def replace_before_open(path, *args, **kwargs):
        nonlocal changed
        if path == target and not changed:
            changed = True
            replacement = root / "SYNTHETIC-open-time-replacement"
            with original_open(replacement, "wb") as writer:
                writer.write(members[target.name])
            replacement.replace(target)
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", replace_before_open)
    with pytest.raises(ValueError, match="changed during open"):
        delivery_files.assemble_delivery(candidate, candidate_hash(candidate), scripts, source_root=root)
    assert changed


def test_mutation_during_single_handle_read_is_rejected(synthetic_tree, monkeypatch):
    root, members, candidate, scripts = synthetic_tree
    target = root / PAYLOADS[0][0]
    original_open = Path.open
    old_time = target.stat().st_mtime_ns
    changed = False

    class MutatingRead:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def fileno(self):
            return self.stream.fileno()

        def read(self, size=-1):
            nonlocal changed
            raw = self.stream.read(size)
            with original_open(target, "wb") as writer:
                writer.write(b"X" + members[target.name][1:])
            os.utime(target, ns=(old_time, old_time + 1_000_000))
            changed = True
            return raw

    def change_during_read(path, *args, **kwargs):
        stream = original_open(path, *args, **kwargs)
        return MutatingRead(stream) if path == target else stream

    monkeypatch.setattr(Path, "open", change_during_read)
    with pytest.raises(ValueError, match="changed during bounded read"):
        delivery_files.assemble_delivery(candidate, candidate_hash(candidate), scripts, source_root=root)
    assert changed


@pytest.mark.parametrize("change", ["missing", "empty", "directory"])
def test_missing_empty_or_nonregular_fixed_file_cannot_assemble(synthetic_tree, change):
    root, _, candidate, scripts = synthetic_tree
    target = root / PAYLOADS[0][0]
    if change == "empty":
        target.write_bytes(b"")
    else:
        target.replace(root / "SYNTHETIC-retained-original")
        if change == "directory":
            target.mkdir()
    with pytest.raises((OSError, ValueError)):
        delivery_files.assemble_delivery(candidate, candidate_hash(candidate), scripts, source_root=root)
