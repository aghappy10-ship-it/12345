"""Confine generated outputs to this new project; reject redirected/shared paths."""
from __future__ import annotations
import os
from pathlib import Path
import stat
import tempfile

if os.name == 'nt':
    import ctypes
    import msvcrt
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    _win_create_file = _kernel32.CreateFileW
    _win_create_file.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    _win_create_file.restype = wintypes.HANDLE
    _win_reopen_file = _kernel32.ReOpenFile
    _win_reopen_file.argtypes = (wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD)
    _win_reopen_file.restype = wintypes.HANDLE
    _win_close_handle = _kernel32.CloseHandle
    _win_close_handle.argtypes = (wintypes.HANDLE,)
    _win_close_handle.restype = wintypes.BOOL
    _win_get_file_information = _kernel32.GetFileInformationByHandleEx
    _win_get_file_information.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
    _win_get_file_information.restype = wintypes.BOOL
    _win_set_file_information = _kernel32.SetFileInformationByHandle
    _win_set_file_information.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
    _win_set_file_information.restype = wintypes.BOOL

    class _FileAttributeTagInfo(ctypes.Structure):
        _fields_ = [('FileAttributes', wintypes.DWORD), ('ReparseTag', wintypes.DWORD)]

    class _FileDispositionInfo(ctypes.Structure):
        _fields_ = [('DeleteFile', ctypes.c_ubyte)]

    class _FileIdInfo(ctypes.Structure):
        _fields_ = [('VolumeSerialNumber', ctypes.c_uint64), ('FileId', ctypes.c_ubyte * 16)]

PROJECT = Path(__file__).resolve().parents[1]


def guard_output(path: Path, root: Path = PROJECT / 'build', *, must_be_new=False) -> Path:
    path = Path(os.path.abspath(path))
    root = Path(os.path.abspath(root))
    if not root.is_relative_to(PROJECT / 'build'):
        raise ValueError('generated output root must remain under the literal project build directory')
    if not path.is_relative_to(root):
        raise ValueError('output is outside its declared project root')
    # Do not resolve the trust root before checking: doing that would bless a
    # build/ junction pointing into frozen assets or a completely different tree.
    current = PROJECT
    for part in path.relative_to(PROJECT).parts:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('symlink/junction/reparse output path forbidden: ' + str(current))
        if current != path and not stat.S_ISDIR(info.st_mode):
            raise ValueError('output ancestor is not a directory')
        if current == path and stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise ValueError('hard-linked output file forbidden')
        if current == path and must_be_new:
            raise ValueError('output already exists')
    if not path.resolve(strict=False).is_relative_to(root):
        raise ValueError('resolved output escaped the literal trusted root')
    return path


def output_directory(path: Path, root: Path = PROJECT / 'build') -> Path:
    path = guard_output(path, root)
    path.mkdir(parents=True, exist_ok=True)
    guard_output(path, root)
    if not path.is_dir(): raise ValueError('output directory required')
    return path


def write_output(path: Path, data: bytes, root: Path = PROJECT / 'build') -> Path:
    path = guard_output(path, root)
    output_directory(path.parent, root)
    descriptor, name = tempfile.mkstemp(prefix='.' + path.name + '.', suffix='.tmp', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        guard_output(path, root)
        os.replace(temporary, path)
        guard_output(path, root)
        if path.read_bytes() != data: raise ValueError('output readback mismatch')
    finally:
        # Only the exact file created above can be removed; never a directory.
        if temporary.exists():
            guard_output(temporary, root)
            temporary.unlink()
    return path


def _file_id(handle):
    info = _FileIdInfo()
    if not _win_get_file_information(handle, 18, ctypes.byref(info), ctypes.sizeof(info)):
        raise ctypes.WinError(ctypes.get_last_error())
    return info.VolumeSerialNumber, bytes(info.FileId)


def _pin_original_file(stream):
    """Retain the original object before closing its creating writer handle."""
    original = msvcrt.get_osfhandle(stream.fileno())
    original_id = _file_id(original)
    # Metadata-only pin: permits subsequent reads, writes and rename, but keeps
    # the original object alive so its file ID cannot be recycled for a rival.
    pin = _win_reopen_file(original, 0, 7, 0)
    if pin == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if _file_id(pin) != original_id:
            raise ValueError('original commit pin identity differs')
    except BaseException as error:
        try:
            if not _win_close_handle(pin):
                raise ctypes.WinError(ctypes.get_last_error())
        except OSError as close_error:
            error.add_note('Original commit pin close unverified: ' + str(close_error))
        raise
    return pin


def _withdraw_owned_commit(path, expected_inode, raw, pin):
    """Delete only the verified open Windows file, never resolve its name again.

    Share mode zero denies concurrent reads, writes, rename and deletion for the held
    leaf. An existing incompatible handle makes opening fail rather than weakening
    those flags. This does not make the containing output set an atomic group.
    """
    if os.name != 'nt':
        raise NotImplementedError('handle-bound withdrawal requires Windows')
    guard_output(path)
    # GENERIC_READ | DELETE; no sharing; OPEN_EXISTING; OPEN_REPARSE_POINT.
    handle = _win_create_file(str(path), 0x80010000, 0, None, 3, 0x00200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except BaseException as error:
        try:
            if not _win_close_handle(handle):
                raise ctypes.WinError(ctypes.get_last_error())
        except OSError as close_error:
            error.add_note('Withdrawal native handle close unverified: ' + str(close_error))
        raise
    # The CRT descriptor now owns the HANDLE; never close both independently.
    try:
        stream = os.fdopen(descriptor, 'rb')
    except BaseException:
        os.close(descriptor)
        raise
    with stream:
        if _file_id(handle) != _file_id(pin):
            raise ValueError('withdrawal is not the pinned original object')
        attributes = _FileAttributeTagInfo()
        if not _win_get_file_information(handle, 9, ctypes.byref(attributes), ctypes.sizeof(attributes)):
            raise ctypes.WinError(ctypes.get_last_error())
        if attributes.FileAttributes & 0x400:
            raise ValueError('withdrawal reparse file forbidden')
        before = os.fstat(descriptor)
        if ((before.st_dev, before.st_ino) != expected_inode
                or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size != len(raw)):
            raise ValueError('withdrawal file identity or length differs')
        if stream.read(len(raw) + 1) != raw:
            raise ValueError('withdrawal file bytes differ')
        after = os.fstat(descriptor)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if any(getattr(before, field) != getattr(after, field) for field in fields):
            raise ValueError('withdrawal file changed while reading')
        disposition = _FileDispositionInfo(1)
        if not _win_set_file_information(handle, 4, ctypes.byref(disposition), ctypes.sizeof(disposition)):
            raise ctypes.WinError(ctypes.get_last_error())


def publish_output_set(destination, outputs, *, commit_name, before_commit=None) -> Path:
    """Write a fixed byte set with its commit member last, not an atomic group.

    This local persistence helper grants no qualification or execution authority.
    The commit is staged/read back before Windows' no-overwrite rename. Other
    platforms are rejected, not silently given POSIX overwrite semantics.
    The destination must have no other writer throughout the call; exclusive
    creation alone does not enforce that continuing precondition. This is not
    power-loss recovery or atomic publication of an entire directory. The
    failed-attempt withdrawal is separately pinned to the original file object
    and verified through an exclusive deletion handle, not pathname unlink.
    This does not protect all publication/readback checks against concurrent
    parent replacement. Partial files are kept for diagnosis, never resumed.
    If safe commit withdrawal itself fails, the original exception includes an
    explicit unverified-withdrawal note; no success or atomicity is claimed.
    """
    import re

    if os.name != 'nt':
        raise NotImplementedError('output-set commit publication requires Windows no-overwrite rename')
    if type(outputs) is not dict or not outputs:
        raise ValueError('a nonempty fixed output dictionary is required')
    expected = outputs.copy()
    reserved = {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)),
                *(f'LPT{i}' for i in range(1, 10))}
    for name, raw in expected.items():
        if (type(name) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,254}', name) is None
                or name.endswith('.') or name.split('.', 1)[0].upper() in reserved):
            raise ValueError('output member must be a safe single filename')
        if type(raw) is not bytes or not raw:
            raise ValueError('output members must be nonempty immutable bytes')
    if len({name.casefold() for name in expected}) != len(expected):
        raise ValueError('case-colliding output names are forbidden')
    if type(commit_name) is not str or commit_name not in expected:
        raise ValueError('commit_name must identify one output member')
    pending_name = '.' + commit_name + '.pending'
    if len(pending_name) > 255:
        raise ValueError('commit name leaves no space for its staging suffix')
    if before_commit is not None and not callable(before_commit):
        raise ValueError('before_commit must be callable')
    destination = guard_output(destination)
    if destination == PROJECT / 'build':
        raise ValueError('a dedicated output directory is required')
    for name in [*expected, pending_name]:
        guard_output(destination / name)

    def inode(info):
        return info.st_dev, info.st_ino

    def regular(path):
        guard_output(path)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('regular unshared output member required')
        return info

    def read_exact(path, raw):
        before = regular(path)
        if before.st_size != len(raw):
            raise ValueError('output member byte length differs')
        with path.open('rb') as stream:
            if inode(os.fstat(stream.fileno())) != inode(before):
                raise ValueError('output member changed while opening')
            if stream.read(len(raw) + 1) != raw:
                raise ValueError('output member readback differs')
        after = regular(path)
        if (inode(after), after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
                inode(before), before.st_size, before.st_mtime_ns, before.st_ctime_ns):
            raise ValueError('output member changed while reading')
        return after

    try:
        directory_info = destination.lstat()
    except FileNotFoundError:
        existing = False
        output_directory(destination.parent)
        # A competitor winning creation is not permission to fill its directory.
        destination.mkdir(exist_ok=False)
        guard_output(destination)
        directory_info = destination.lstat()
    else:
        existing = True
    if not stat.S_ISDIR(directory_info.st_mode):
        raise ValueError('output directory required')
    directory_inode = inode(directory_info)

    def unchanged(checked, paths):
        guard_output(destination)
        current = destination.lstat()
        if not stat.S_ISDIR(current.st_mode) or inode(current) != directory_inode:
            raise ValueError('output directory changed')
        if {path.name for path in destination.iterdir()} != {path.name for path in paths.values()}:
            raise ValueError('output member set differs')
        for name, before in checked.items():
            after = regular(paths[name])
            if (inode(after), after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
                    inode(before), before.st_size, before.st_mtime_ns, before.st_ctime_ns):
                raise ValueError('output member changed during set verification')
        guard_output(destination)
        if (inode(destination.lstat()) != directory_inode
                or {path.name for path in destination.iterdir()} != {path.name for path in paths.values()}):
            raise ValueError('output directory changed during set verification')

    def verify(names, *, staged=False):
        paths = {name: destination / (pending_name if staged and name == commit_name else name)
                 for name in names}
        unchanged({}, paths)
        checked = {name: read_exact(paths[name], expected[name]) for name in names}
        # A later member read must not conceal an earlier member's replacement.
        unchanged(checked, paths)
        return checked, paths

    ordered = [name for name in expected if name != commit_name]
    if existing:
        checked, paths = verify(ordered + [commit_name])
        if before_commit is not None:
            before_commit()
        unchanged(checked, paths)
        return destination
    commit_inode = commit_pin = None
    publication_error = None
    try:
        for name in ordered + [commit_name]:
            guard_output(destination)
            if inode(destination.lstat()) != directory_inode:
                raise ValueError('output directory changed before writing')
            path = guard_output(destination / (pending_name if name == commit_name else name), must_be_new=True)
            with path.open('xb') as stream:
                if name == commit_name:
                    commit_inode = inode(os.fstat(stream.fileno()))
                    commit_pin = _pin_original_file(stream)
                if stream.write(expected[name]) != len(expected[name]):
                    raise OSError('short output write')
                stream.flush()
                os.fsync(stream.fileno())
            read_exact(path, expected[name])
        checked, paths = verify(ordered + [commit_name], staged=True)
        if before_commit is not None:
            before_commit()
        # Metadata and membership checks after admission avoid another slow full
        # byte read while still rejecting observable changes during the callback.
        unchanged(checked, paths)
        final = guard_output(destination / commit_name, must_be_new=True)
        (destination / pending_name).rename(final)
        verify(ordered + [commit_name])
    except BaseException as error:
        publication_error = error
        # Refuse an old idempotent result or a different inode, bytes or directory.
        # The final deletion is bound to the same verified file handle; never
        # issue a pathname unlink after checking its inode.
        if commit_inode is not None and commit_pin is not None:
            try:
                guard_output(destination)
                if inode(destination.lstat()) != directory_inode:
                    raise ValueError('output directory was replaced')
                path = destination / commit_name
                if inode(regular(path)) != commit_inode:
                    raise ValueError('commit was replaced')
                read_exact(path, expected[commit_name])
                if inode(regular(path)) != commit_inode:
                    raise ValueError('commit changed before withdrawal')
                _withdraw_owned_commit(path, commit_inode, expected[commit_name], commit_pin)
            except FileNotFoundError:
                pass
            except (ValueError, OSError) as cleanup_error:
                error.add_note('Commit withdrawal unverified; preserved unsafe or unreadable '
                               'content: ' + str(cleanup_error))
                for note in getattr(cleanup_error, '__notes__', ()):
                    error.add_note(note)
        raise
    finally:
        if commit_pin is not None:
            failure = publication_error
            try:
                if not _win_close_handle(commit_pin):
                    raise ctypes.WinError(ctypes.get_last_error())
            except OSError as close_error:
                if failure is None:
                    close_error.add_note('Commit withdrawal unverified after final pin close failure; '
                                         'formal marker may remain. Do not reuse this failed output set; '
                                         'no pathname deletion or uncertain-handle retry was attempted.')
                    raise
                failure.add_note('Commit pin close/withdrawal unverified: ' + str(close_error))
    return destination
