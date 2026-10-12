"""Read-only desktop bridge prerequisite checks, independent of Qt loading."""
import hashlib
import json
from pathlib import Path

import pytest


INPUTS = ("src/host_cache_bridge.c", "tools/build_host_bridge.py",
          "tools/host_cache.py", "tools/qt_unit.py", "tools/output_guard.py")


@pytest.fixture
def bridge_tree(tmp_path):
    for name in INPUTS:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"abc")
    directory = tmp_path / "build/host-bridge/native"
    directory.mkdir(parents=True)
    (directory / "host_cache_bridge.dll").write_bytes(b"abc")
    report = {
        "schema": "x2dii-desktop-qt682-cache-bridge-build-v1",
        "installable": False, "reproduced": True,
        "inputs": {name: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                   for name in INPUTS},
        "dll_sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "dll_bytes": 3,
    }
    (directory / "BUILD.json").write_text(json.dumps(report), encoding="utf-8")
    return tmp_path


def test_stale_bridge_input_is_rejected_before_any_native_load(bridge_tree):
    from tools.audit_build_preflight import check_bridge_build

    (bridge_tree / "tools/output_guard.py").write_bytes(b"changed")
    with pytest.raises(ValueError, match="bridge source binding changed: tools/output_guard.py"):
        check_bridge_build(bridge_tree)


@pytest.mark.parametrize("damage", ["missing_report", "missing_source", "missing_binding",
                                  "extra_binding", "invalid_json", "duplicate_binding",
                                  "wrong_schema", "unreproduced", "installable"])
def test_incomplete_or_unverified_bridge_build_is_rejected(bridge_tree, damage):
    from tools.audit_build_preflight import check_bridge_build

    path = bridge_tree / "build/host-bridge/native/BUILD.json"
    report = json.loads(path.read_bytes())
    if damage == "missing_report":
        path.unlink()
    elif damage == "missing_source":
        (bridge_tree / "tools/output_guard.py").unlink()
    elif damage == "invalid_json":
        path.write_bytes(b"not json")
    elif damage == "duplicate_binding":
        raw = path.read_text(encoding="utf-8")
        path.write_text(raw.replace('"inputs": {', '"inputs": {"tools/output_guard.py": "wrong",'),
                        encoding="utf-8")
    else:
        if damage == "missing_binding":
            report["inputs"].pop("tools/output_guard.py")
        elif damage == "extra_binding":
            report["inputs"]["../outside.py"] = "a" * 64
        elif damage == "wrong_schema":
            report["schema"] = "different"
        elif damage == "unreproduced":
            report["reproduced"] = 1
        elif damage == "installable":
            report["installable"] = 0
        path.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(ValueError, match="bridge"):
        check_bridge_build(bridge_tree)


@pytest.mark.parametrize("damage", ["missing", "changed", "size", "boolean_size"])
def test_missing_or_changed_bridge_dll_is_rejected(bridge_tree, damage):
    from tools.audit_build_preflight import check_bridge_build

    dll = bridge_tree / "build/host-bridge/native/host_cache_bridge.dll"
    report_path = dll.with_name("BUILD.json")
    if damage == "missing":
        dll.unlink()
    elif damage == "changed":
        dll.write_bytes(b"abd")
    else:
        report = json.loads(report_path.read_bytes())
        report["dll_bytes"] = True if damage == "boolean_size" else 4
        report_path.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(ValueError, match="bridge"):
        check_bridge_build(bridge_tree)


def test_current_source_and_dll_bindings_return_exact_local_only_evidence(bridge_tree):
    from tools.audit_build_preflight import check_bridge_build

    raw = (bridge_tree / "build/host-bridge/native/BUILD.json").read_bytes()
    result = check_bridge_build(bridge_tree)
    assert result == {
        "status": "LOCAL_BRIDGE_SOURCE_AND_DLL_BINDINGS_VERIFIED_ONLY",
        "installable": False, "camera_accesses": 0,
        "build_report_sha256": hashlib.sha256(raw).hexdigest(),
        "inputs": {name: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                   for name in INPUTS},
        "dll_sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "dll_bytes": 3,
    }
