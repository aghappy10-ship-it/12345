"""TEST_ONLY Windows filesystem cleanup races, never camera/package evidence."""
import os
import ctypes
from pathlib import Path

import pytest

from tests.test_output_set import workspace, outputs, COMMIT, InjectedIO, BoundaryFile
from tools import output_guard as guard


def test_last_boundary_leaf_replacement_cannot_be_deleted(workspace, outputs, monkeypatch):
    destination = workspace / "late-leaf-race"
    marker = destination / COMMIT
    rival = workspace / "rival.txt"
    unknown = b"TEST_ONLY UNRELATED REPLACEMENT MUST SURVIVE"
    rival.write_bytes(unknown)
    original_rename, original_unlink = Path.rename, Path.unlink
    events = []

    def failed_publication(path, target):
        result = original_rename(path, target)
        if target == marker:
            raise InjectedIO("TEST_ONLY after publication")
        return result

    def attempt_replacement():
        events.append("attempted real leaf replacement at delete boundary")
        try:
            os.rename(marker, workspace / "moved-original")
            os.replace(rival, marker)
        except PermissionError:
            events.append("kernel denied replacement of held file")

    # Both branches are filesystem boundaries: the historical pathname delete,
    # and the Windows deletion system call used by a handle-bound implementation.
    def at_path_delete(path, *args, **kwargs):
        if path == marker:
            attempt_replacement()
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "rename", failed_publication)
    monkeypatch.setattr(Path, "unlink", at_path_delete)
    if hasattr(guard, "_win_set_file_information"):
        original_disposition = guard._win_set_file_information

        def at_handle_delete(*args):
            attempt_replacement()
            return original_disposition(*args)

        monkeypatch.setattr(guard, "_win_set_file_information", at_handle_delete)
    with pytest.raises(InjectedIO, match="after publication"):
        guard.publish_output_set(destination, outputs, commit_name=COMMIT)
    assert events, "the intended final deletion boundary was not exercised"
    assert ((rival.exists() and rival.read_bytes() == unknown)
            or (marker.exists() and marker.read_bytes() == unknown)), "unrelated replacement was deleted"


def test_original_commit_object_is_pinned_through_withdrawal(workspace, outputs, monkeypatch):
    assert hasattr(guard, "_win_reopen_file"), "original file object has no lifetime pin against file-ID reuse"
    destination = workspace / "pinned-original"
    marker = destination / COMMIT
    original_rename = Path.rename
    reopen, close, dispose = guard._win_reopen_file, guard._win_close_handle, guard._win_set_file_information
    events, pins = [], []

    def file_id(handle):
        # FILE_ID_INFO: volume serial + 128-bit file ID, from the actual kernel.
        info = ctypes.create_string_buffer(24)
        assert guard._win_get_file_information(handle, 18, info, 24)
        return info.raw

    def record_pin(handle, access, sharing, flags):
        assert access == 0 and sharing == 7
        result = reopen(handle, access, sharing, flags)
        assert result != ctypes.c_void_p(-1).value
        assert file_id(result) == file_id(handle)
        pins.append((result, file_id(result)))
        events.append("pin opened from live original")
        return result

    def failing_rename(path, target):
        result = original_rename(path, target)
        if target == marker:
            assert pins and file_id(pins[0][0]) == pins[0][1]
            events.append("pin alive after publication")
            raise InjectedIO("TEST_ONLY pinned publication failure")
        return result

    def record_disposition(handle, *args):
        assert pins and file_id(pins[0][0]) == file_id(handle)
        events.append("same original pinned during delete")
        return dispose(handle, *args)

    def record_close(handle):
        result = close(handle)
        if pins and handle == pins[0][0]:
            assert result
            events.append("pin closed")
        return result

    monkeypatch.setattr(guard, "_win_reopen_file", record_pin)
    monkeypatch.setattr(guard, "_win_set_file_information", record_disposition)
    monkeypatch.setattr(guard, "_win_close_handle", record_close)
    monkeypatch.setattr(Path, "rename", failing_rename)
    with pytest.raises(InjectedIO, match="pinned publication failure"):
        guard.publish_output_set(destination, outputs, commit_name=COMMIT)
    assert events == ["pin opened from live original", "pin alive after publication",
                      "same original pinned during delete", "pin closed"]
    assert not marker.exists()


@pytest.mark.parametrize("outer_exception", (False, True))
def test_success_path_pin_close_failure_reports_residual_commit_without_retry(workspace, outputs, monkeypatch, outer_exception):
    destination = workspace / "success-close-failed"
    close = guard._win_close_handle
    failed_handles = []

    def failed_close(handle):
        failed_handles.append(handle)
        ctypes.set_last_error(6)
        return 0

    monkeypatch.setattr(guard, "_win_close_handle", failed_close)
    def publish():
        if outer_exception:
            try:
                raise ValueError("TEST_ONLY unrelated caller exception")
            except ValueError:
                return guard.publish_output_set(destination, outputs, commit_name=COMMIT)
        return guard.publish_output_set(destination, outputs, commit_name=COMMIT)
    try:
        with pytest.raises(OSError) as failure:
            publish()
        assert len(failed_handles) == 1, "an uncertain handle close must not be blindly retried"
        assert (destination / COMMIT).read_bytes() == outputs[COMMIT]
        assert any("withdrawal unverified" in note and "formal marker" in note
                   for note in getattr(failure.value, "__notes__", []))
    finally:
        # Injected API failure did not perform the real close. Release only the
        # exact handles recorded by this TEST_ONLY fault, not production retry.
        for handle in failed_handles:
            assert close(handle)


@pytest.mark.parametrize("boundary", ("pin-validation", "descriptor-transfer"))
def test_early_handle_close_failures_remain_visible_on_original_error(workspace, outputs, monkeypatch, boundary):
    destination = workspace / boundary
    marker = destination / COMMIT
    get_info, close, create = guard._win_get_file_information, guard._win_close_handle, guard._win_create_file
    rename = Path.rename
    failed_handles, cleanup_handles = [], []
    id_calls = []

    def failed_pin_validation(handle, kind, *args):
        if kind == 18:
            id_calls.append(handle)
            if len(id_calls) == 2:
                ctypes.set_last_error(5)
                return 0
        return get_info(handle, kind, *args)

    def failed_publication(path, target):
        result = rename(path, target)
        if target == marker:
            raise InjectedIO("TEST_ONLY transfer failure")
        return result

    def record_cleanup_handle(*args):
        handle = create(*args)
        cleanup_handles.append(handle)
        return handle

    def failed_transfer(handle, flags):
        assert handle in cleanup_handles
        raise OSError("TEST_ONLY descriptor transfer")

    def failed_close(handle):
        if boundary == "pin-validation" or handle in cleanup_handles:
            failed_handles.append(handle)
            ctypes.set_last_error(6)
            return 0
        return close(handle)

    monkeypatch.setattr(guard, "_win_close_handle", failed_close)
    if boundary == "pin-validation":
        monkeypatch.setattr(guard, "_win_get_file_information", failed_pin_validation)
    else:
        monkeypatch.setattr(Path, "rename", failed_publication)
        monkeypatch.setattr(guard, "_win_create_file", record_cleanup_handle)
        monkeypatch.setattr(guard.msvcrt, "open_osfhandle", failed_transfer)
    try:
        with pytest.raises(OSError) as failure:
            guard.publish_output_set(destination, outputs, commit_name=COMMIT)
        assert len(failed_handles) == 1
        diagnostic = "Original commit pin close unverified" if boundary == "pin-validation" else "Withdrawal native handle close unverified"
        assert any(diagnostic in note for note in getattr(failure.value, "__notes__", []))
        if boundary == "descriptor-transfer":
            assert isinstance(failure.value, InjectedIO)
        else:
            assert failure.value.winerror == 5
            assert not marker.exists()
    finally:
        for handle in failed_handles:
            assert close(handle)


@pytest.mark.parametrize("same_bytes", (False, True))
def test_replacement_just_before_open_is_not_the_pinned_original(workspace, outputs, monkeypatch, same_bytes):
    destination = workspace / "before-open"
    marker, displaced = destination / COMMIT, workspace / "displaced-original"
    rival = workspace / "unknown-rival"
    unknown = outputs[COMMIT] if same_bytes else b"TEST_ONLY DIFFERENT FILE"
    rival.write_bytes(unknown)
    original_rename, create = Path.rename, guard._win_create_file
    reached = []

    def failed_publication(path, target):
        result = original_rename(path, target)
        if target == marker:
            raise InjectedIO("TEST_ONLY before open")
        return result

    def replace_at_open(name, *args):
        assert Path(name) == marker
        reached.append("native open")
        os.rename(marker, displaced)
        os.replace(rival, marker)
        return create(name, *args)

    monkeypatch.setattr(Path, "rename", failed_publication)
    monkeypatch.setattr(guard, "_win_create_file", replace_at_open)
    with pytest.raises(InjectedIO, match="before open") as failure:
        guard.publish_output_set(destination, outputs, commit_name=COMMIT)
    assert reached == ["native open"]
    assert marker.read_bytes() == unknown
    assert displaced.read_bytes() == outputs[COMMIT]
    assert any("withdrawal unverified" in note for note in failure.value.__notes__)


@pytest.mark.parametrize("boundary", ("open", "attributes", "disposition", "read", "held-reader"))
def test_native_cleanup_failure_preserves_commit_and_has_no_path_delete_fallback(workspace, outputs, monkeypatch, boundary):
    destination = workspace / ("cleanup-" + boundary)
    marker = destination / COMMIT
    rename, unlink, fdopen = Path.rename, Path.unlink, os.fdopen
    get_info = guard._win_get_file_information
    reached, readers = [], []

    def failed_publication(path, target):
        result = rename(path, target)
        if target == marker:
            if boundary == "held-reader":
                readers.append(marker.open("rb"))
                reached.append(boundary)
            raise InjectedIO("TEST_ONLY cleanup failure")
        return result

    def fail_open(*args):
        reached.append(boundary)
        ctypes.set_last_error(5)
        return ctypes.c_void_p(-1).value

    def fail_attributes(handle, kind, *args):
        if kind == 9:
            reached.append(boundary)
            ctypes.set_last_error(5)
            return 0
        return get_info(handle, kind, *args)

    def fail_disposition(*args):
        reached.append(boundary)
        ctypes.set_last_error(5)
        return 0

    def failed_read(stream, size):
        reached.append(boundary)
        raise OSError("TEST_ONLY read failure")

    def no_path_delete(path, *args, **kwargs):
        assert path != marker, "cleanup must never fall back to pathname unlink"
        return unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "rename", failed_publication)
    monkeypatch.setattr(Path, "unlink", no_path_delete)
    if boundary == "open":
        monkeypatch.setattr(guard, "_win_create_file", fail_open)
    elif boundary == "attributes":
        monkeypatch.setattr(guard, "_win_get_file_information", fail_attributes)
    elif boundary == "disposition":
        monkeypatch.setattr(guard, "_win_set_file_information", fail_disposition)
    elif boundary == "read":
        monkeypatch.setattr(os, "fdopen", lambda *a, **k: BoundaryFile(fdopen(*a, **k), read_fault=failed_read))
    try:
        with pytest.raises(InjectedIO, match="cleanup failure") as failure:
            guard.publish_output_set(destination, outputs, commit_name=COMMIT)
        assert reached == [boundary]
        assert marker.read_bytes() == outputs[COMMIT]
        assert any("withdrawal unverified" in note for note in failure.value.__notes__)
    finally:
        for reader in readers:
            reader.close()


def test_held_withdrawal_handle_prevents_byte_changes(workspace, outputs, monkeypatch):
    destination = workspace / "during-write"
    marker = destination / COMMIT
    rename, disposition = Path.rename, guard._win_set_file_information
    reached = []

    def failed_publication(path, target):
        result = rename(path, target)
        if target == marker:
            raise InjectedIO("TEST_ONLY write race")
        return result

    def attempt_write(*args):
        reached.append("write while deletion handle is held")
        with pytest.raises(PermissionError):
            marker.write_bytes(b"TEST_ONLY UNRELATED WRITE")
        return disposition(*args)

    monkeypatch.setattr(Path, "rename", failed_publication)
    monkeypatch.setattr(guard, "_win_set_file_information", attempt_write)
    with pytest.raises(InjectedIO, match="write race"):
        guard.publish_output_set(destination, outputs, commit_name=COMMIT)
    assert len(reached) == 1
    assert not marker.exists()
