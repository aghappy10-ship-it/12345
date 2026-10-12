"""Build a reproducible desktop-only Qt cached-unit bridge; no device actions."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

try:
    from .output_guard import guard_output, output_directory, write_output
except ImportError:
    from output_guard import guard_output, output_directory, write_output

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build/host-bridge"
HOST = ROOT.parent / "x2d2/work/reverse/vendor/qt_host_6_8_2"
ZIG = ROOT.parent / "x2d2/work/reverse/vendor/tools/zig-x86_64-windows-0.15.2/zig.exe"
ZIG_SHA = "d408dd38eed3e5204af841bcebf70502a4dbbb8399a3a3262be55059370bc018"
SOURCE = ROOT / "src/host_cache_bridge.c"
REFERENCE_HASHES = {
    "qqmlprivate.h.txt": "495a251f7ecce28087d99bd2e47a182933c5ce619a064bfe73b175e3aba906a8",
    "qqml.cpp.txt": "f2f2618e32aebf43697ff6fd47fd17782659210496fcfe67a805f84b79e825aa",
    "qqmlmetatype.cpp.txt": "5c509fa1fbdf7c9c0768c731cd4250161a23d7640302067237029ff4336f29f3",
}
CORE_HASHES = {
    "PySide6/qmlcachegen.exe": "01f34cf585acc2d941b5f7897f5f9fa3403b68ad3489fb9606c9e30edba6b963",
    "PySide6/Qt6Core.dll": "0800ba66df27d1755e7e68c72d25503abdd3ae008e6da98f47c46117b2c41fd9",
    "PySide6/Qt6Qml.dll": "7f28a2d2a7db2310d43bca8084549e861b3a4beee52abd8d4b12517d526a1555",
}
EXPORTS = {"bridge_configure", "bridge_lookup", "bridge_deactivate", "bridge_hits",
           "bridge_active", "bridge_unit_size", "bridge_hook_size", "bridge_hook_lookup_offset"}


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def pe_exports(path: Path) -> set[str]:
    """Bounded PE32+ export reader, used before loading native code."""
    raw = path.read_bytes()
    def u32(offset):
        require(0 <= offset <= len(raw) - 4, "PE field outside image")
        return struct.unpack_from("<I", raw, offset)[0]
    require(raw[:2] == b"MZ", "PE DOS header")
    pe = u32(0x3C)
    require(raw[pe:pe+4] == b"PE\0\0", "PE signature")
    machine, count = struct.unpack_from("<HH", raw, pe+4)
    opt_size = struct.unpack_from("<H", raw, pe+20)[0]
    opt = pe + 24
    require(machine == 0x8664 and struct.unpack_from("<H", raw, opt)[0] == 0x20B, "Windows AMD64 PE32+ required")
    sections = []
    for index in range(count):
        at = opt + opt_size + index*40
        require(at + 40 <= len(raw), "PE section table truncated")
        virtual_size, va, size, offset = struct.unpack_from("<4I", raw, at+8)
        require(offset + size <= len(raw), "PE raw section outside file")
        sections.append((va, size, offset))
    def locate(va, size=1):
        found = [offset+va-base for base, length, offset in sections if base <= va and va+size <= base+length]
        require(len(found) == 1, "ambiguous/unmapped PE export address")
        return found[0]
    export_rva, export_size = struct.unpack_from("<II", raw, opt+112)
    table = locate(export_rva, 40)
    number = u32(table+24)
    require(number < 100000, "implausible export count")
    names = locate(u32(table+32), number*4)
    result = set()
    for index in range(number):
        start = locate(u32(names+index*4))
        end = raw.find(b"\0", start, min(len(raw), start+4096))
        require(end != -1, "unterminated PE export")
        value = raw[start:end].decode("ascii")
        require(value not in result, "duplicate PE export")
        result.add(value)
    return result


def runtime_snapshot() -> dict[str, str]:
    # Bind all shipped DLLs, native bindings, Python/QML source and import
    # descriptors. Never create bytecode or compiler caches in the frozen tree.
    result = {}
    for package in (HOST / "PySide6", HOST / "shiboken6"):
        for path in sorted(package.rglob("*")):
            if path.is_file() and (path.suffix.lower() in {".dll", ".pyd", ".py", ".qml", ".qmlc", ".js", ".mjs", ".jsc", ".rcc", ".exe"} or path.name == "qmldir"):
                result[str(path.relative_to(HOST)).replace("\\", "/")] = sha(path)
    require(result and all(result.get(name) == value for name, value in CORE_HASHES.items()), "Qt 6.8.2 core identity mismatch")
    return result


def build() -> dict:
    require(os.name == "nt" and struct.calcsize("P") == 8, "Windows x64 host required")
    directory = guard_output(BUILD / "native", ROOT / "build", must_be_new=True)
    require(sha(ZIG) == ZIG_SHA, "Zig identity mismatch")
    references = {}
    for name, expected in REFERENCE_HASHES.items():
        path = BUILD / "qt-source" / name
        require(sha(path) == expected, "Qt source reference mismatch: " + name)
        references[name] = {"sha256": expected, "url": "https://raw.githubusercontent.com/qt/qtdeclarative/v6.8.2/src/qml/qml/" + name[:-4]}
    output_directory(directory, ROOT / "build")
    environment = os.environ.copy()
    # Both caches start empty inside this newly created build, so compiler
    # writes cannot follow descendants left in a reused cache directory.
    environment.update(ZIG_GLOBAL_CACHE_DIR=str(output_directory(directory / "zig-global-cache")),
                       ZIG_LOCAL_CACHE_DIR=str(output_directory(directory / "zig-local-cache")))
    # Zig's cc translator rejects MSVC /noentry; its DLL COFF link still
    # requires the normal entry symbol even with -fno-entry. The source
    # provides a trivial successful entry without linking or initializing CRT.
    flags = ["build-lib", "-dynamic", "-target", "x86_64-windows-msvc", "-O", "ReleaseFast", "-fstrip", "-fno-stack-check", "-cflags", "-std=c11", "-fno-stack-protector", "-Wall", "-Wextra", "-Werror", "--"]
    inputs = {str(path.relative_to(ROOT)).replace("\\", "/"): sha(path) for path in (SOURCE, Path(__file__), ROOT / "tools/host_cache.py", ROOT / "tools/qt_unit.py", ROOT / "tools/output_guard.py")}
    before = runtime_snapshot()
    commands = []
    for name in ("host_cache_bridge.dll", "reproduction/host_cache_bridge.dll"):
        destination = guard_output(directory / name, must_be_new=True)
        output_directory(destination.parent)
        command = [str(ZIG), *flags, str(SOURCE), "-femit-bin=" + str(destination)]
        run = subprocess.run(command, capture_output=True, text=True, env=environment, timeout=180)
        commands.append({"argv": command, "exit_code": run.returncode, "stdout": run.stdout, "stderr": run.stderr})
        for generated in directory.rglob("*"):
            guard_output(generated)
        if run.returncode:
            write_output(directory / "FAILED.json", json.dumps(commands, indent=2).encode("utf-8"))
            raise ValueError("bridge compiler failed: " + run.stderr)
    primary, reproduced = (directory / name for name in ("host_cache_bridge.dll", "reproduction/host_cache_bridge.dll"))
    require(sha(primary) == sha(reproduced), "bridge reproduction differs")
    require(pe_exports(primary) == EXPORTS, "unexpected bridge exports")
    require(runtime_snapshot() == before, "frozen Qt runtime changed during build")
    require(all(sha(ROOT / name) == value for name, value in inputs.items()), "source changed during build")
    report = {"schema": "x2dii-desktop-qt682-cache-bridge-build-v1", "status": "LOCAL_ONLY_BUILT_NOT_CAMERA_QUALIFIED", "installable": False,
              "compiler": {"path": str(ZIG), "sha256": ZIG_SHA}, "inputs": inputs, "qt_source_references": references,
              "runtime_root": str(HOST), "runtime_files": before, "dll_sha256": sha(primary), "dll_bytes": primary.stat().st_size,
              "exports": sorted(EXPORTS), "commands": commands, "reproduced": True,
              "abi": {"CachedQmlUnit_size": 24, "RegisterQmlUnitCacheHook_size": 16, "lookup_offset": 8, "registration_type": 6, "struct_version": 0},
              "limits": ["desktop cache loader only", "no camera or target Android execution", "separate actual compiled-unit behavioral execution required"]}
    write_output(directory / "BUILD.json", json.dumps(report, indent=2).encode("utf-8"))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    result = build()
    print(json.dumps({key: result[key] for key in ("status", "dll_sha256", "dll_bytes", "reproduced", "installable")}, indent=2))
