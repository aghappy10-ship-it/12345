"""Local filesystem publication tests with inert bytes and TEST_ONLY commits."""
import os
from pathlib import Path
import tempfile

import pytest

from tools import output_guard as guard


COMMIT = "TEST_ONLY.json"


@pytest.fixture
def workspace():
    guard.output_directory(guard.PROJECT / "build")
    with tempfile.TemporaryDirectory(prefix="output-set-test-", dir=guard.PROJECT / "build") as directory:
        yield Path(directory)


@pytest.fixture
def outputs():
    # Commit is deliberately first in insertion order, never real qualification.
    return {COMMIT: b'{"TEST_ONLY":"INERT SYNTHETIC COMMIT"}\n',
            "first.bin": b"SYNTHETIC INERT FIRST",
            "second.txt": b"SYNTHETIC INERT SECOND"}


def test_fresh_set_publishes_exact_bytes_and_commit_is_the_last_created_file(workspace, outputs, monkeypatch):
    destination = workspace / "new-set"
    original_open = Path.open
    original_rename = Path.rename
    created = []

    def observed_open(path, mode="r", *args, **kwargs):
        if path.parent == destination and path.name in outputs and "x" in mode:
            created.append(path.name)
        return original_open(path, mode, *args, **kwargs)

    def observed_rename(path, target):
        result = original_rename(path, target)
        if target == destination / COMMIT:
            created.append(COMMIT)
        return result

    monkeypatch.setattr(Path, "open", observed_open)
    monkeypatch.setattr(Path, "rename", observed_rename)
    result = guard.publish_output_set(destination, outputs, commit_name=COMMIT)
    assert result == destination
    assert created == ["first.bin", "second.txt", COMMIT]
    assert {path.name: path.read_bytes() for path in destination.iterdir()} == outputs


def test_complete_existing_set_is_verified_without_any_write_or_directory_creation(workspace, outputs, monkeypatch):
    destination = workspace / "already-complete"
    guard.publish_output_set(destination, outputs, commit_name=COMMIT)
    before = {path.name: path.stat() for path in destination.iterdir()}
    original_open = Path.open
    callbacks = []

    def read_only_open(path, mode="r", *args, **kwargs):
        if any(flag in mode for flag in "wax+"):
            raise AssertionError("idempotence cannot open for writing")
        return original_open(path, mode, *args, **kwargs)

    def no_mutation(*args, **kwargs):
        raise AssertionError("idempotence cannot mutate filesystem state")

    with monkeypatch.context() as patch:
        patch.setattr(Path, "open", read_only_open)
        patch.setattr(Path, "mkdir", no_mutation)
        patch.setattr(Path, "unlink", no_mutation)
        patch.setattr(os, "replace", no_mutation)
        assert guard.publish_output_set(destination, outputs, commit_name=COMMIT,
                                        before_commit=lambda: callbacks.append("checked")) == destination
    assert callbacks == ["checked"]
    assert {path.name: path.stat() for path in destination.iterdir()} == before


@pytest.mark.parametrize("damage", ["empty", "partial", "changed", "extra", "directory-member"])
def test_existing_incomplete_or_changed_set_is_never_repaired(workspace, outputs, damage):
    destination = workspace / "existing"
    destination.mkdir()
    for name, raw in outputs.items():
        if damage == "empty" or damage == "partial" and name == "second.txt":
            continue
        if damage == "directory-member" and name == "second.txt":
            (destination / name).mkdir()
        else:
            (destination / name).write_bytes(raw + (b" CHANGED" if damage == "changed" and name == COMMIT else b""))
    if damage == "extra":
        (destination / "unknown.txt").write_bytes(b"UNRELATED SYNTHETIC DATA")
    before = {path.name: (path.is_dir(), None if path.is_dir() else path.read_bytes())
              for path in destination.iterdir()}
    callbacks = []
    with pytest.raises(ValueError):
        guard.publish_output_set(destination, outputs, commit_name=COMMIT,
                                 before_commit=lambda: callbacks.append("must not run"))
    assert callbacks == []
    assert {path.name: (path.is_dir(), None if path.is_dir() else path.read_bytes())
            for path in destination.iterdir()} == before


class InjectedIO(OSError):
    pass


class BoundaryFile:
    """Fault injection at the real filesystem stream, not a product mock."""
    def __init__(self, stream, *, write_fault=None, read_fault=None, close_fault=None):
        self.stream = stream
        self.write_fault = write_fault
        self.read_fault = read_fault
        self.close_fault = close_fault

    def __enter__(self):
        self.stream.__enter__()
        return self

    def __exit__(self, *args):
        result = self.stream.__exit__(*args)
        if self.close_fault is not None:
            self.close_fault()
        return result

    def __getattr__(self, name):
        return getattr(self.stream, name)

    def write(self, raw):
        if self.write_fault is not None:
            return self.write_fault(self.stream, raw)
        return self.stream.write(raw)

    def read(self, size=-1):
        if self.read_fault is not None:
            return self.read_fault(self.stream, size)
        return self.stream.read(size)


@pytest.mark.parametrize("member", ["first.bin", "second.txt", COMMIT])
@pytest.mark.parametrize("boundary", ["write-before", "write-after", "readback", "final-read"])
def test_io_failure_never_leaves_this_attempts_complete_commit(workspace, outputs, monkeypatch, member, boundary):
    destination = workspace / "failed-set"
    original_open = Path.open
    state = {"reads": 0, "fired": False}

    def fail_write(stream, raw):
        state["fired"] = True
        if boundary == "write-after":
            stream.write(raw)
            stream.flush()
        raise InjectedIO(boundary)

    def fail_read(stream, size):
        state["fired"] = True
        raise InjectedIO(boundary)

    def failing_open(path, mode="r", *args, **kwargs):
        stream = original_open(path, mode, *args, **kwargs)
        logical_name = COMMIT if path.name == "." + COMMIT + ".pending" else path.name
        if path.parent != destination or logical_name != member or state["fired"]:
            return stream
        if "x" in mode and boundary.startswith("write"):
            return BoundaryFile(stream, write_fault=fail_write)
        if mode == "rb":
            state["reads"] += 1
            trigger = 1 if boundary == "readback" else 3
            if boundary in ("readback", "final-read") and state["reads"] == trigger:
                return BoundaryFile(stream, read_fault=fail_read)
        return stream

    with monkeypatch.context() as patch:
        patch.setattr(Path, "open", failing_open)
        with pytest.raises(InjectedIO):
            guard.publish_output_set(destination, outputs, commit_name=COMMIT)
    assert state["fired"]
    commit = destination / COMMIT
    assert not commit.exists() or commit.read_bytes() != outputs[COMMIT]
    assert destination.is_dir()  # Retain the attempt and partial data for diagnosis.


def test_exception_after_commit_publication_retracts_only_this_commit(workspace, outputs, monkeypatch):
    destination = workspace / "publication-failure"
    original_rename = Path.rename

    def failing_rename(path, target):
        original_rename(path, target)
        if target == destination / COMMIT:
            raise InjectedIO("after commit publication")

    with monkeypatch.context() as patch:
        patch.setattr(Path, "rename", failing_rename)
        with pytest.raises(InjectedIO):
            guard.publish_output_set(destination, outputs, commit_name=COMMIT)
    assert not (destination / COMMIT).exists()
    assert {path.name: path.read_bytes() for path in destination.iterdir()} == {
        name: raw for name, raw in outputs.items() if name != COMMIT}


@pytest.mark.parametrize("existing", [False, True])
def test_expired_final_admission_keeps_old_commit_but_never_creates_a_new_one(workspace, outputs, existing):
    destination = workspace / "expiry"
    if existing:
        guard.publish_output_set(destination, outputs, commit_name=COMMIT)
    calls = []

    def expired():
        assert (destination / "first.bin").read_bytes() == outputs["first.bin"]
        assert (destination / "second.txt").read_bytes() == outputs["second.txt"]
        assert (destination / COMMIT).exists() is existing
        calls.append("verified-before-callback")
        raise ValueError("expired")

    with pytest.raises(ValueError, match="expired"):
        guard.publish_output_set(destination, outputs, commit_name=COMMIT, before_commit=expired)
    assert calls == ["verified-before-callback"]
    assert (destination / COMMIT).exists() is existing
    expected = outputs if existing else {
        ("." + name + ".pending" if name == COMMIT else name): raw for name, raw in outputs.items()}
    assert {path.name: path.read_bytes() for path in destination.iterdir()} == expected


@pytest.mark.parametrize("replacement", ["different-bytes", "same-bytes-new-inode", "same-inode-changed-bytes"])
def test_failed_attempt_preserves_commit_it_no_longer_owns(workspace, outputs, monkeypatch, replacement):
    destination = workspace / "replaced"
    original_rename = Path.rename
    commit = destination / COMMIT
    replacement_bytes = outputs[COMMIT] if replacement == "same-bytes-new-inode" else b"UNRELATED SYNTHETIC OWNER"
    replacements = []

    def replace_after_publication():
        old_inode = commit.stat().st_ino
        if replacement == "same-inode-changed-bytes":
            commit.write_bytes(replacement_bytes)
        else:
            other = workspace / "replacement.bin"
            other.write_bytes(replacement_bytes)
            assert other.stat().st_ino != old_inode
            # Windows may refuse replacing a still-open destination even when
            # its metadata pin shares DELETE. Move it aside first, then place
            # the real rival at the now-vacant name; do not fake the new inode.
            os.rename(commit, workspace / "displaced-original.bin")
            os.replace(other, commit)
        replacements.append(commit.stat())
        raise InjectedIO("owner changed after commit publication")

    def failing_rename(path, target):
        result = original_rename(path, target)
        if target == commit:
            replace_after_publication()
        return result

    with monkeypatch.context() as patch:
        patch.setattr(Path, "rename", failing_rename)
        with pytest.raises(InjectedIO) as failure:
            guard.publish_output_set(destination, outputs, commit_name=COMMIT)
    assert replacements and commit.stat() == replacements[0]
    assert commit.read_bytes() == replacement_bytes
    assert any("withdrawal unverified" in note for note in failure.value.__notes__)


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("change", ["different-bytes", "same-bytes-new-inode"])
def test_later_read_cannot_conceal_change_to_an_already_verified_member(workspace, outputs, monkeypatch, existing, change):
    destination = workspace / "cross-read"
    if existing:
        guard.publish_output_set(destination, outputs, commit_name=COMMIT)
    original_open = Path.open
    state = {"reads": 0, "fired": False}
    callbacks = []

    def change_earlier_member(stream, size):
        raw = stream.read(size)
        first = destination / "first.bin"
        if change == "different-bytes":
            first.write_bytes(b"ALTERED SYNTHETIC FIRST")
        else:
            other = workspace / "replacement.bin"
            other.write_bytes(outputs["first.bin"])
            assert other.stat().st_ino != first.stat().st_ino
            os.replace(other, first)
        state["fired"] = True
        return raw

    def observed_open(path, mode="r", *args, **kwargs):
        stream = original_open(path, mode, *args, **kwargs)
        if path == destination / "second.txt" and mode == "rb":
            state["reads"] += 1
            if state["reads"] == (1 if existing else 2):
                return BoundaryFile(stream, read_fault=change_earlier_member)
        return stream

    with monkeypatch.context() as patch:
        patch.setattr(Path, "open", observed_open)
        with pytest.raises(ValueError):
            guard.publish_output_set(destination, outputs, commit_name=COMMIT,
                                     before_commit=lambda: callbacks.append("must not run"))
    assert state["fired"] and callbacks == []
    assert (destination / COMMIT).exists() is existing


@pytest.mark.parametrize("damage", ["empty-set", "list", "mutable", "empty-bytes", "text-bytes",
                                    "missing-commit", "bad-callback", "case-collision"])
def test_entire_contract_is_checked_before_creating_any_output_directory(workspace, outputs, damage):
    destination = workspace / "not-created" / "set"
    commit_name = COMMIT
    callback = None
    if damage == "empty-set":
        outputs = {}
    elif damage == "list":
        outputs = list(outputs.items())
    elif damage == "mutable":
        outputs["second.txt"] = bytearray(b"SYNTHETIC")
    elif damage == "empty-bytes":
        outputs["second.txt"] = b""
    elif damage == "text-bytes":
        outputs["second.txt"] = "SYNTHETIC"
    elif damage == "missing-commit":
        commit_name = "absent.json"
    elif damage == "bad-callback":
        callback = "not callable"
    else:
        outputs["FIRST.BIN"] = b"SYNTHETIC CASE COLLISION"
    with pytest.raises(ValueError):
        guard.publish_output_set(destination, outputs, commit_name=commit_name, before_commit=callback)
    assert not destination.parent.exists()


@pytest.mark.parametrize("name", ["../escape", "/absolute", "nested/file", "nested\\file", "C:drive",
                                  ".", "..", "trailing.", "trailing ", "CON", "NUL.txt", "LPT1",
                                  "unicode-\u03bb", "bad\0name", 1, "x" * 256])
def test_nonliteral_leaf_names_are_rejected_before_any_publication(workspace, outputs, name):
    destination = workspace / "not-created"
    outputs[name] = b"SYNTHETIC INVALID NAME"
    with pytest.raises(ValueError):
        guard.publish_output_set(destination, outputs, commit_name=COMMIT)
    assert not destination.exists()


def test_existing_hardlinked_member_is_rejected_without_modifying_either_link(workspace, outputs):
    destination = workspace / "linked"
    guard.publish_output_set(destination, outputs, commit_name=COMMIT)
    alias = workspace / "alias.bin"
    os.link(destination / "first.bin", alias)
    with pytest.raises(ValueError, match="hard-linked"):
        guard.publish_output_set(destination, outputs, commit_name=COMMIT)
    assert alias.read_bytes() == (destination / "first.bin").read_bytes() == outputs["first.bin"]


@pytest.mark.parametrize("member", ["first.bin", "second.txt", COMMIT])
def test_fsync_failure_is_not_a_successful_publication(workspace, outputs, monkeypatch, member):
    destination = workspace / "fsync-failed"
    original_fsync = os.fsync
    original_open = Path.open
    descriptors = {}
    failed = []

    def record_open(path, mode="r", *args, **kwargs):
        stream = original_open(path, mode, *args, **kwargs)
        if path.parent == destination and "x" in mode:
            descriptors[stream.fileno()] = COMMIT if path.name == "." + COMMIT + ".pending" else path.name
        return stream

    def fail_fsync(descriptor):
        if descriptors.get(descriptor) == member:
            failed.append(member)
            raise InjectedIO("fsync")
        return original_fsync(descriptor)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "open", record_open)
        patch.setattr(os, "fsync", fail_fsync)
        with pytest.raises(InjectedIO, match="fsync"):
            guard.publish_output_set(destination, outputs, commit_name=COMMIT)
    assert failed == [member]
    assert not (destination / COMMIT).exists()


def test_cleanup_io_failure_is_reported_as_unverified_not_success(workspace, outputs, monkeypatch):
    destination = workspace / "withdrawal-failed"
    original_rename = Path.rename
    reached = []

    def failing_rename(path, target):
        result = original_rename(path, target)
        if target == destination / COMMIT:
            raise InjectedIO("initial publication failed")
        return result

    def failing_disposition(*args):
        reached.append("native file disposition")
        raise OSError("withdrawal permission denied")

    with monkeypatch.context() as patch:
        patch.setattr(Path, "rename", failing_rename)
        patch.setattr(guard, "_win_set_file_information", failing_disposition)
        with pytest.raises(InjectedIO, match="initial publication failed") as failure:
            guard.publish_output_set(destination, outputs, commit_name=COMMIT)
    assert reached == ["native file disposition"]
    assert any("withdrawal unverified" in note and "permission denied" in note
               for note in failure.value.__notes__)
    assert (destination / COMMIT).read_bytes() == outputs[COMMIT]


def test_competing_directory_creator_is_not_adopted_or_modified(workspace, outputs, monkeypatch):
    destination = workspace / "race"
    original_mkdir = Path.mkdir

    def race_mkdir(path, *args, **kwargs):
        if path == destination:
            original_mkdir(path)
            (path / "unrelated.txt").write_bytes(b"SYNTHETIC OTHER OWNER")
            raise FileExistsError("another writer created this directory")
        return original_mkdir(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "mkdir", race_mkdir)
        with pytest.raises(FileExistsError):
            guard.publish_output_set(destination, outputs, commit_name=COMMIT)
    assert {path.name: path.read_bytes() for path in destination.iterdir()} == {
        "unrelated.txt": b"SYNTHETIC OTHER OWNER"}


def test_short_commit_write_cannot_leave_parseable_json_at_the_final_commit_name(workspace, outputs, monkeypatch):
    destination = workspace / "short-commit"
    original_open = Path.open
    fired = []

    def short_write(stream, raw):
        assert raw.endswith(b"\n")
        fired.append(True)
        return stream.write(raw[:-1])

    def failing_open(path, mode="r", *args, **kwargs):
        stream = original_open(path, mode, *args, **kwargs)
        if path.parent == destination and "TEST_ONLY" in path.name and "x" in mode:
            return BoundaryFile(stream, write_fault=short_write)
        return stream

    with monkeypatch.context() as patch:
        patch.setattr(Path, "open", failing_open)
        with pytest.raises(OSError, match="short output write"):
            guard.publish_output_set(destination, outputs, commit_name=COMMIT)
    assert fired == [True]
    assert not (destination / COMMIT).exists()


@pytest.mark.parametrize("existing", [False, True])
def test_final_callback_cannot_modify_verified_outputs_then_report_success(workspace, outputs, monkeypatch, existing):
    destination = workspace / "callback-change"
    if existing:
        guard.publish_output_set(destination, outputs, commit_name=COMMIT)
    original_open = Path.open
    original_rename = Path.rename
    published = []

    def record_open(path, mode="r", *args, **kwargs):
        if path == destination / COMMIT and "x" in mode:
            published.append(True)
        return original_open(path, mode, *args, **kwargs)

    def record_rename(path, target):
        if target == destination / COMMIT:
            published.append(True)
        return original_rename(path, target)

    def changed():
        (destination / "first.bin").write_bytes(b"SYNTHETIC CHANGE DURING CALLBACK")

    with monkeypatch.context() as patch:
        patch.setattr(Path, "open", record_open)
        patch.setattr(Path, "rename", record_rename)
        with pytest.raises(ValueError):
            guard.publish_output_set(destination, outputs, commit_name=COMMIT, before_commit=changed)
    assert published == []
    assert (destination / COMMIT).exists() is existing


def test_windows_commit_rename_does_not_overwrite_a_last_moment_competitor(workspace, outputs, monkeypatch):
    destination = workspace / "rename-race"
    original_rename = Path.rename
    other = b"UNRELATED SYNTHETIC LAST MOMENT OWNER"
    raced = []

    def racing_rename(path, target):
        if target == destination / COMMIT:
            target.write_bytes(other)
            raced.append(target.stat().st_ino)
        return original_rename(path, target)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "rename", racing_rename)
        with pytest.raises(FileExistsError):
            guard.publish_output_set(destination, outputs, commit_name=COMMIT)
    assert raced == [(destination / COMMIT).stat().st_ino]
    assert (destination / COMMIT).read_bytes() == other
    assert (destination / ("." + COMMIT + ".pending")).read_bytes() == outputs[COMMIT]


def test_pending_commit_close_failure_never_publishes_the_final_name(workspace, outputs, monkeypatch):
    destination = workspace / "pending-close"
    original_open = Path.open
    fired = []

    def after_close():
        fired.append(True)
        raise InjectedIO("pending commit close failed")

    def failing_open(path, mode="r", *args, **kwargs):
        stream = original_open(path, mode, *args, **kwargs)
        if path.parent == destination and path.name == "." + COMMIT + ".pending" and "x" in mode:
            return BoundaryFile(stream, close_fault=after_close)
        return stream

    with monkeypatch.context() as patch:
        patch.setattr(Path, "open", failing_open)
        with pytest.raises(InjectedIO, match="pending commit close"):
            guard.publish_output_set(destination, outputs, commit_name=COMMIT)
    assert fired == [True]
    assert not (destination / COMMIT).exists()
    assert (destination / ("." + COMMIT + ".pending")).read_bytes() == outputs[COMMIT]


def test_non_windows_platform_is_rejected_before_any_output_mutation(workspace, outputs, monkeypatch):
    destination = workspace / "unsupported-platform"
    with monkeypatch.context() as patch:
        patch.setattr(os, "name", "posix")
        with pytest.raises(NotImplementedError, match="Windows no-overwrite rename"):
            guard.publish_output_set(destination, outputs, commit_name=COMMIT)
    assert not destination.exists()
