"""Exact Qt 6.8.2 Windows cached-QML registration, with a native callback.

One registration may be active per process. Close removes the callback, but
returned units/URLs/native libraries remain pinned only while Python retains
this module; Qt global type-cache destruction can happen later at process exit.
Successful isolated workers must destroy all engines, close their cache hooks,
then call qmlClearTypeRegistrations while these Python-owned bytes still live.
Do not put global type cleanup in close(): a live engine may still use a unit.
Run isolated child processes for independent host experiments.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import threading

try:
    from .build_host_bridge import BUILD, HOST, ROOT, CORE_HASHES, REFERENCE_HASHES, EXPORTS, pe_exports, runtime_snapshot, sha, require
    from .qt_unit import parse_unit
    from .output_guard import guard_output, output_directory
except ImportError:
    from build_host_bridge import BUILD, HOST, ROOT, CORE_HASHES, REFERENCE_HASHES, EXPORTS, pe_exports, runtime_snapshot, sha, require
    from qt_unit import parse_unit
    from output_guard import guard_output, output_directory

COMPILE_HASH = b"0a8139c574fe150aba92d5f2484a8f3fdb774977".ljust(48, b"\0")
REGISTER_SYMBOL = "?qmlregister@QQmlPrivate@@YAHW4RegistrationType@1@PEAX@Z"
UNREGISTER_SYMBOL = "?qmlunregister@QQmlPrivate@@YAXW4RegistrationType@1@_K@Z"
EQUALS_SYMBOL = "??8QUrl@@QEBA_NAEBV0@@Z"
_retained = []
_active = None
_registration_lock = threading.RLock()
_prepared = False
_runtime = None


class CachedUnit(ctypes.Structure):
    _fields_ = [("data", ctypes.c_void_p), ("aot", ctypes.c_void_p), ("unused2", ctypes.c_void_p)]


Lookup = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p)


class Registration(ctypes.Structure):
    _fields_ = [("version", ctypes.c_int), ("lookup", Lookup)]


def confined_workdir(path: Path) -> Path:
    # Preserve the literal path so the common guard can detect an ancestor
    # junction even when it points to another otherwise-permitted build path.
    return output_directory(path, ROOT / "build")


def fresh_cache_directory(workdir: Path) -> Path:
    directory = confined_workdir(workdir)
    # Qt writes its own cache files. Never hand it a reused directory whose
    # existing descendants could be reparse points or hard-linked outputs.
    return guard_output(Path(tempfile.mkdtemp(prefix="qml-cache-", dir=directory)), ROOT / "build")


def prepare_host(workdir: Path = BUILD / "runtime") -> dict:
    """Call before importing PySide6; reject foreign already-loaded bindings."""
    global _prepared, _runtime
    require(os.name == "nt" and struct.calcsize("P") == 8, "Windows x64 host required")
    directory = confined_workdir(workdir)
    sys.dont_write_bytecode = True
    for name in ("PySide6", "shiboken6"):
        loaded = sys.modules.get(name)
        if loaded is not None:
            require(Path(loaded.__file__).resolve().is_relative_to((HOST / name).resolve()), "foreign Qt binding already loaded")
    if not _prepared:
        _runtime = runtime_snapshot()
        sys.path.insert(0, str(HOST))
        os.environ["QML_DISK_CACHE_PATH"] = str(fresh_cache_directory(directory))
        os.environ["QT_QPA_PLATFORM"] = "offscreen"
        os.environ["QT_QUICK_BACKEND"] = "software"
        require(not os.environ.get("QML_DISABLE_DISK_CACHE"), "QML_DISABLE_DISK_CACHE would invalidate the compiled-unit experiment")
        import PySide6
        from PySide6.QtCore import qVersion
        require(PySide6.__version__ == "6.8.2" and qVersion() == "6.8.2", "exact Qt/PySide6 6.8.2 required")
        _prepared = True
    return {"runtime_root": str(HOST), "runtime_files": dict(_runtime), "qt_version": "6.8.2", "cache_path": os.environ["QML_DISK_CACHE_PATH"]}


def validate_cache(data: bytes) -> None:
    require(len(data) >= 248 and data[:8] == b"qv4cdata", "compiled QML unit header required")
    require(struct.unpack_from("<I", data, 8)[0] == 66, "compiled unit version must be 66")
    require(struct.unpack_from("<I", data, 12)[0] == 0x60802, "compiled unit Qt version must be 6.8.2")
    require(data[28:76] == COMPILE_HASH, "compiled unit library hash mismatch")
    require(struct.unpack_from("<I", data, 108)[0] & 2, "CachedQmlUnit requires immutable StaticData storage")
    parse_unit(data)


def as_static_cache(data: bytes) -> bytes:
    """Explicitly adapt qmlcachegen's bytecode cache ownership, not its code.

    Embedded camera units already have StaticData. For a host qmlc fixture,
    set only that ownership bit and regenerate its checksum. Callers record
    both hashes; no source fallback or bytecode substitution is performed.
    """
    require(len(data) >= 248, "short compiled unit")
    # Do not turn a damaged input into an apparently valid unit by rewriting
    # its checksum. Validate its original structure and checksum first.
    parse_unit(data)
    require(data[28:76] == COMPILE_HASH, "compiled unit library hash mismatch")
    changed = bytearray(data)
    struct.pack_into("<I", changed, 108, struct.unpack_from("<I", changed, 108)[0] | 2)
    changed[76:92] = hashlib.md5(changed[92:]).digest()
    validate_cache(bytes(changed))
    return bytes(changed)


class HostCache:
    def __init__(self, unit_path: Path, url: str, workdir: Path = BUILD / "runtime", *, expected_sha256: str | None = None):
        global _active
        self.closed = True
        self._final_hits = 0
        self.runtime_evidence = prepare_host(workdir)
        from PySide6.QtCore import QUrl
        from shiboken6 import getCppPointer
        raw = Path(unit_path).read_bytes()
        self.unit_sha256 = hashlib.sha256(raw).hexdigest()
        if expected_sha256 is not None:
            require(self.unit_sha256 == expected_sha256, "compiled unit SHA-256 mismatch")
        validate_cache(raw)
        report = json.loads((BUILD / "native/BUILD.json").read_text(encoding="utf-8"))
        require(report["reproduced"] is True and report["installable"] is False, "unverified bridge build")
        for relative, value in report["inputs"].items():
            require(sha(ROOT / relative) == value, "bridge source binding changed: " + relative)
        for name, expected in REFERENCE_HASHES.items():
            require(sha(BUILD / "qt-source" / name) == expected, "Qt reference changed")
        require(report["runtime_files"] == self.runtime_evidence["runtime_files"], "runtime differs from bridge build")
        bridge_path = BUILD / "native/host_cache_bridge.dll"
        require(sha(bridge_path) == report["dll_sha256"] and pe_exports(bridge_path) == EXPORTS, "bridge binary identity/exports mismatch")
        require(REGISTER_SYMBOL in pe_exports(HOST / "PySide6/Qt6Qml.dll"), "Qt qmlregister export missing")
        require(UNREGISTER_SYMBOL in pe_exports(HOST / "PySide6/Qt6Qml.dll"), "Qt qmlunregister export missing")
        require(EQUALS_SYMBOL in pe_exports(HOST / "PySide6/Qt6Core.dll"), "Qt QUrl equality export missing")
        self.core = ctypes.CDLL(str(HOST / "PySide6/Qt6Core.dll"))
        self.qml = ctypes.CDLL(str(HOST / "PySide6/Qt6Qml.dll"))
        self.bridge = ctypes.CDLL(str(bridge_path))
        self.storage = ctypes.create_string_buffer(raw)
        self.unit = CachedUnit(ctypes.addressof(self.storage), None, None)
        self.url = QUrl(url)
        require(self.url.isValid() and not self.url.isRelative() and self.url.scheme() in ("file", "qrc"), "absolute local file or qrc URL required")
        self.callback = Lookup(("bridge_lookup", self.bridge))
        self.registration = Registration(0, self.callback)
        self.bridge.bridge_configure.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        self.bridge.bridge_configure.restype = ctypes.c_int
        self.bridge.bridge_deactivate.argtypes = [ctypes.c_void_p]
        self.bridge.bridge_deactivate.restype = ctypes.c_int
        self.bridge.bridge_hits.restype = ctypes.c_uint64
        self.bridge.bridge_active.restype = ctypes.c_uint
        self.register = getattr(self.qml, REGISTER_SYMBOL)
        self.register.argtypes, self.register.restype = [ctypes.c_int, ctypes.c_void_p], ctypes.c_int
        self.unregister = getattr(self.qml, UNREGISTER_SYMBOL)
        self.unregister.argtypes, self.unregister.restype = [ctypes.c_int, ctypes.c_size_t], None
        require(ctypes.sizeof(CachedUnit) == self.bridge.bridge_unit_size() == 24 and ctypes.sizeof(Registration) == self.bridge.bridge_hook_size() == 16 and Registration.lookup.offset == self.bridge.bridge_hook_lookup_offset() == 8, "native/Python Qt layout disagreement")
        with _registration_lock:
            require(_active is None, "one active HostCache per process; close previous owner first")
            require(self.bridge.bridge_configure(getattr(self.core, EQUALS_SYMBOL), getCppPointer(self.url)[0], ctypes.byref(self.unit)) == 1, "native cache already active")
            _retained.append(self)
            try:
                require(self.register(6, ctypes.byref(self.registration)) == 0, "Qt rejected cache registration")
            except BaseException:
                self.bridge.bridge_deactivate(ctypes.byref(self.unit))
                raise
            self.closed = False
            _active = self

    @property
    def hits(self) -> int:
        return self._final_hits if self.closed else int(self.bridge.bridge_hits())

    def close(self) -> None:
        global _active
        with _registration_lock:
            if self.closed:
                return
            require(_active is self, "cache owner mismatch")
            # Removal uses Qt's metatype lock; native deactivation serializes
            # with any already-entered callback. Retained data outlives both;
            # final global type cleanup remains the isolated worker's duty.
            self.unregister(6, ctypes.cast(self.callback, ctypes.c_void_p).value)
            require(self.bridge.bridge_deactivate(ctypes.byref(self.unit)) == 1, "native cache deactivate failed")
            self._final_hits = int(self.bridge.bridge_hits())
            self.closed = True
            _active = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
