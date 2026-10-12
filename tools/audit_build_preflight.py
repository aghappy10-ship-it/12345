"""Read-only bridge source/binary prerequisites; never camera qualification.

This early check avoids launching the audit with a stale local bridge build.
HostCache still owns its full runtime, Qt reference, export and loading checks.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

BRIDGE_INPUTS = ("src/host_cache_bridge.c", "tools/build_host_bridge.py",
                 "tools/host_cache.py", "tools/qt_unit.py", "tools/output_guard.py")


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate bridge BUILD.json field: " + key)
        value[key] = item
    return value


def _read(path):
    try:
        return path.read_bytes()
    except OSError as error:
        raise ValueError("bridge prerequisite unavailable: " + str(path)) from error


def check_bridge_build(project_root: Path) -> dict:
    """Reject missing/stale local bridge inputs before collection or execution."""
    root = Path(project_root)
    directory = root / "build/host-bridge/native"
    raw = _read(directory / "BUILD.json")
    try:
        report = json.loads(raw, object_pairs_hook=_unique_object)
    except (ValueError, UnicodeError) as error:
        raise ValueError("invalid bridge BUILD.json: " + str(error)) from error
    if (type(report) is not dict
            or report.get("schema") != "x2dii-desktop-qt682-cache-bridge-build-v1"
            or report.get("reproduced") is not True or report.get("installable") is not False):
        raise ValueError("unverified bridge build metadata")
    inputs = report.get("inputs")
    if type(inputs) is not dict or set(inputs) != set(BRIDGE_INPUTS):
        raise ValueError("bridge build requires the exact source input set")
    for relative in BRIDGE_INPUTS:
        expected = inputs[relative]
        actual = hashlib.sha256(_read(root / relative)).hexdigest()
        if actual != expected:
            raise ValueError("bridge source binding changed: " + relative)
    dll = _read(directory / "host_cache_bridge.dll")
    dll_sha256 = hashlib.sha256(dll).hexdigest()
    if (dll_sha256 != report.get("dll_sha256")
            or type(report.get("dll_bytes")) is not int
            or len(dll) != report["dll_bytes"]):
        raise ValueError("bridge binary identity/size mismatch")
    return {"status": "LOCAL_BRIDGE_SOURCE_AND_DLL_BINDINGS_VERIFIED_ONLY",
            "installable": False, "camera_accesses": 0,
            "build_report_sha256": hashlib.sha256(raw).hexdigest(),
            "inputs": dict(inputs), "dll_sha256": dll_sha256, "dll_bytes": len(dll)}
