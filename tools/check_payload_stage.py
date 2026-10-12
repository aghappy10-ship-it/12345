"""Freeze and inspect five exact candidate files in an isolated host fixture.

This is not an archive, installer, device stage, package or release gate PASS.
The saved unqualified manifest and retained hash name the candidate; current
source bytes must match it, while an existing frozen fixture can be verified
without consulting mutable payload sources.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat

from elftools.elf.elffile import ELFFile

from . import boot_config as boot
from . import build_native as native
from . import build_unit
from . import menu_inputs
from . import qt_unit
from .output_guard import guard_output, output_directory, write_output

ROOT = Path(__file__).resolve().parents[1]
FILES = (("build/native/libx2dii_menu.so", "/system/lib64/libx2dii_menu.so"),
         *(("qml/" + name, "/system/etc/" + name) for name in
           ("X2d2MenuBootstrap.qml", "X2d2MenuModel.qml", "X2d2MenuPage.qml")))
RC_SOURCE = "build/boot-config/camera-gui.rc.proposed"
UNITS = ("build/units/main-screen-bootstrap-host.bin", "build/units/main-screen-bootstrap-device.bin")
TOOL_FILES = ("check_payload_stage.py", "build_native.py", "build_unit.py", "menu_inputs.py",
              "qt_unit.py", "boot_config.py", "output_guard.py")
REGISTRY = ROOT / "work/reverse/X2DII_REGRESSION_GATES.json"


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _regular_bytes(path):
    """No shared or redirected member; one handle supplies the frozen bytes."""
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and not getattr(before, "st_file_attributes", 0) & 0x400,
         "regular non-reparse input required: " + str(path))
    need(before.st_nlink == 1, "hard-linked input forbidden: " + str(path))
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        need((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino) and opened.st_nlink == 1,
             "input identity changed during open")
        raw = stream.read()
        after = os.fstat(stream.fileno())
    final = path.lstat()
    need((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) ==
         (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) and
         (final.st_dev, final.st_ino, final.st_nlink) == (before.st_dev, before.st_ino, 1)
         and len(raw) == before.st_size, "input changed while freezing: " + str(path))
    return raw


def _source_path(root, relative):
    path = root / relative
    need(root == ROOT or root.is_relative_to(ROOT / "build"), "source snapshots must remain in project or guarded build tree")
    current = ROOT
    for part in path.relative_to(ROOT).parts:
        current /= part
        info = current.lstat()
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
             "symlink/junction/reparse source forbidden")
    return path


def _manifest(path, retained_sha):
    path = guard_output(Path(path))
    raw = _regular_bytes(path)
    need(isinstance(retained_sha, str) and re.fullmatch(r"[0-9a-f]{64}", retained_sha)
         and sha(raw) == retained_sha, "saved manifest hash mismatch")
    manifest = json.loads(raw)
    need(manifest.get("schema") == "x2dii-peer-script-source-v2" and
         manifest.get("status") == "LOCAL_SOURCE_UNQUALIFIED" and manifest.get("installable") is False
         and manifest.get("package_created") is False and manifest.get("scripts_emitted") is False
         and manifest.get("script_hashes") == {}, "saved unqualified source-only manifest required")
    candidate = manifest["candidate"]
    need(manifest["candidate_sha256"] == sha(canonical(candidate)), "candidate digest mismatch")
    entries = candidate["files"]
    need(len(entries) == 4 and {(entry["source"], entry["target"]) for entry in entries} == set(FILES),
         "exact four source-target pairs required")
    for entry in entries:
        need(re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) and type(entry["bytes"]) is int
             and 0 < entry["bytes"] < 8 * 1024 * 1024, "invalid candidate payload hash/size")
    rc = candidate["rc"]
    need(candidate["gui_sha256"] == qt_unit.GUI_SHA256 and rc["target"] == boot.TARGET
         and rc["source"] == RC_SOURCE and rc["before"] == boot.STOCK_SHA256
         and re.fullmatch(r"[0-9a-f]{64}", rc["after"]), "pinned GUI/rc source-target identity required")
    need(manifest.get("required_gates", {}).get("package_integrity_and_roundtrip") == "PENDING",
         "saved package gate must remain pending")
    return manifest, raw


def extract_elf_units(raw):
    """Read symbol ranges from staged ELF itself; do not trust build reports."""
    elf = ELFFile(io.BytesIO(raw))
    need(elf.elfclass == 64 and elf.little_endian and elf["e_machine"] == "EM_AARCH64"
         and elf["e_type"] == "ET_DYN", "candidate must be ELF64 LE AArch64 shared object")
    symbols = elf.get_section_by_name(".symtab")
    need(symbols is not None, "candidate ELF symbols missing")
    found = {}
    for name in ("stock_unit", "extended_unit"):
        pair = []
        for symbol_name in (name, name + "_end"):
            matches = symbols.get_symbol_by_name(symbol_name) or []
            need(len(matches) == 1, "unique embedded unit symbol required: " + symbol_name)
            symbol = matches[0]
            need(type(symbol["st_shndx"]) is int, "embedded unit symbol must be defined")
            pair.append(symbol)
        start, end = pair
        address, size = int(start["st_value"]), int(end["st_value"] - start["st_value"])
        need(start["st_shndx"] == end["st_shndx"] and 0 < size < 1024 * 1024,
             "invalid embedded unit symbol range")
        offset = native.file_offset(elf, address, size)
        need(0 <= offset <= len(raw) - size, "embedded unit exceeds ELF file")
        segments = [s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"
                    and s["p_vaddr"] <= address and address + size <= s["p_vaddr"] + s["p_filesz"]]
        need(len(segments) == 1 and segments[0]["p_flags"] & 4 and not segments[0]["p_flags"] & 3,
             "embedded units must have one read-only non-executable file-backed mapping")
        found[name] = {"address": address, "offset": offset, "bytes": size,
                       "sha256": sha(raw[offset:offset + size]), "raw": raw[offset:offset + size]}
    left, right = found["stock_unit"], found["extended_unit"]
    need(left["offset"] + left["bytes"] <= right["offset"] or right["offset"] + right["bytes"] <= left["offset"],
         "embedded unit ranges overlap")
    return found


def _semantic_checks(payloads):
    original = qt_unit.read_main_screen(menu_inputs.GUI)
    embedded = extract_elf_units(payloads["libx2dii_menu.so"])
    need(embedded["stock_unit"]["raw"] == original, "embedded stock unit differs from pinned official bytes")
    host = build_unit.build(original, (ROOT / "qml/X2d2MenuBootstrap.qml").as_uri())
    menu_inputs.validate_pair(original, host, embedded["extended_unit"]["raw"])
    expected_device = build_unit.build(original, build_unit.DEVICE_URL)
    need(embedded["extended_unit"]["raw"] == expected_device, "embedded device unit differs from deterministic bytes")
    official = _regular_bytes(boot.STOCK)
    need(boot.deactivate(payloads["camera-gui.rc.proposed"], official) == official, "rc official roundtrip failed")
    result = {name: {key: value for key, value in data.items() if key != "raw"} for name, data in embedded.items()}
    result["stock_unit"]["matches_pinned_original"] = True
    result["extended_unit"]["matches_deterministic_device"] = True
    return {"elf_units": result, "rc_official_roundtrip": True,
            "official_gui_sha256": qt_unit.GUI_SHA256, "official_rc_sha256": sha(official)}


def _verify_members(manifest, payload_directory):
    directory = guard_output(Path(payload_directory))
    need(directory.is_dir(), "payload fixture directory missing")
    names = {Path(source).name for source, _ in FILES} | {"camera-gui.rc.proposed"}
    need({path.name for path in directory.iterdir()} == names, "extra or missing payload fixture member")
    payloads = {name: _regular_bytes(guard_output(directory / name)) for name in sorted(names)}
    for entry in manifest["candidate"]["files"]:
        raw = payloads[Path(entry["source"]).name]
        need(len(raw) == entry["bytes"] and sha(raw) == entry["sha256"], "staged payload hash/size mismatch")
    need(sha(payloads["camera-gui.rc.proposed"]) == manifest["candidate"]["rc"]["after"], "staged rc hash mismatch")
    return {"file_count": 5, "files": {name: {"sha256": sha(raw), "bytes": len(raw)} for name, raw in payloads.items()},
            **_semantic_checks(payloads)}


def verify_stage(saved_manifest, saved_manifest_sha256, payload_directory):
    """Read-only verification of the exact frozen member set and embedded units."""
    manifest, _ = _manifest(saved_manifest, saved_manifest_sha256)
    return _verify_members(manifest, payload_directory)


def _hash_after(inputs, source_root):
    hashes, errors = {}, {}
    source_names = {source for source, _ in FILES} | {RC_SOURCE, *UNITS}
    for name, (path, _) in inputs.items():
        try:
            if name in source_names:
                _source_path(source_root, name)
            hashes[name] = sha(_regular_bytes(path))
        except (OSError, ValueError) as error:
            hashes[name] = None
            errors[name] = type(error).__name__ + ": " + str(error)
    try:
        hashes["official_gui"] = qt_unit.sha256_file(menu_inputs.GUI)
    except OSError as error:
        hashes["official_gui"] = None
        errors["official_gui"] = type(error).__name__ + ": " + str(error)
    return hashes, errors


def prepare_stage(saved_manifest, saved_manifest_sha256, destination, *, source_root=ROOT):
    """Create a fresh local fixture, publish its non-installable report last."""
    destination = guard_output(Path(destination), must_be_new=True)
    source_root = Path(os.path.abspath(source_root))
    manifest, manifest_raw = _manifest(saved_manifest, saved_manifest_sha256)
    inputs = {"saved_manifest": (Path(saved_manifest), manifest_raw)}
    for relative in (*[source for source, _ in FILES], RC_SOURCE, *UNITS):
        path = _source_path(source_root, relative)
        inputs[relative] = (path, _regular_bytes(path))
    for name in TOOL_FILES:
        path = ROOT / "tools" / name
        inputs["tool/" + name] = (path, _regular_bytes(path))
    inputs["regression_registry"] = (REGISTRY, _regular_bytes(REGISTRY))
    inputs["official_rc"] = (boot.STOCK, _regular_bytes(boot.STOCK))
    before = {name: sha(raw) for name, (_, raw) in inputs.items()}
    before["official_gui"] = qt_unit.sha256_file(menu_inputs.GUI)
    need(before["official_gui"] == qt_unit.GUI_SHA256, "pinned official GUI mismatch")
    payloads = {Path(relative).name: inputs[relative][1] for relative in (*[source for source, _ in FILES], RC_SOURCE)}
    for entry in manifest["candidate"]["files"]:
        raw = inputs[entry["source"]][1]
        need(sha(raw) == entry["sha256"] and len(raw) == entry["bytes"], "source payload no longer matches saved candidate")
    need(sha(inputs[RC_SOURCE][1]) == manifest["candidate"]["rc"]["after"], "source rc no longer matches saved candidate")
    semantic = _semantic_checks(payloads)
    original = qt_unit.read_main_screen(menu_inputs.GUI)
    menu_inputs.validate_pair(original, inputs[UNITS[0]][1], inputs[UNITS[1]][1])
    need(semantic["elf_units"]["extended_unit"]["sha256"] == sha(inputs[UNITS[1]][1]), "staged ELF differs from exact device unit input")
    # Create the one final directory exclusively. Existing destinations are
    # never reused, including failed/partial runs, and no broad cleanup occurs.
    output_directory(destination.parent)
    destination.mkdir()
    after, after_errors = {}, {}
    success_raw = None
    try:
        payload_directory = destination / "payloads"
        payload_directory.mkdir()
        for name, raw in payloads.items():
            write_output(payload_directory / name, raw)
        readback = _verify_members(manifest, payload_directory)
        after, after_errors = _hash_after(inputs, source_root)
        need(not after_errors and before == after, "source/tool/registry input changed during payload roundtrip")
        report = {"schema": "x2dii-local-payload-stage-v1", "status": "LOCAL_PAYLOAD_ROUNDTRIP_PASS",
                  "candidate_sha256": manifest["candidate_sha256"], "saved_manifest_sha256": saved_manifest_sha256,
                  "installable": False, "package_created": False, "camera_accesses": 0, "camera_writes": 0,
                  "package_integrity_and_roundtrip": "PENDING", "source_hashes_before": before,
                  "source_hashes_after": after, "readback": readback, "payload_directory": str(payload_directory),
                  "scope": "five-file host fixture; no archive, deployment script, device metadata or live qualification",
                  "concurrent_parent_replacement_protected": False}
        success_raw = (json.dumps(report, indent=2) + "\n").encode()
        write_output(destination / "payload-stage.json", success_raw)
        return report
    except Exception as error:
        # Preserve the owned partial fixture. A failure report is never a gate
        # PASS and never replaces another run or its evidence.
        if not after:
            after, after_errors = _hash_after(inputs, source_root)
        # A writer may fail after replacing the success report (for example on
        # its final readback). Revoke only this run's exact regular owned bytes;
        # never leave that known PASS selectable beside the failure evidence.
        success_path = guard_output(destination / "payload-stage.json")
        if success_path.exists():
            need(success_raw is not None and _regular_bytes(success_path) == success_raw,
                 "refusing to remove an unknown success-report inode or content")
            success_path.unlink()
        failure = {"status": "LOCAL_PAYLOAD_ROUNDTRIP_FAIL", "installable": False, "package_created": False,
                   "camera_accesses": 0, "camera_writes": 0,
                   "package_integrity_and_roundtrip": "PENDING", "candidate_sha256": manifest["candidate_sha256"],
                   "saved_manifest_sha256": saved_manifest_sha256, "source_hashes_before": before,
                   "source_hashes_after": after, "source_readback_errors": after_errors,
                   "error": type(error).__name__ + ": " + str(error)}
        write_output(destination / "payload-stage-failure.json", (json.dumps(failure, indent=2) + "\n").encode())
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--saved-manifest", type=Path, required=True)
    parser.add_argument("--saved-manifest-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = prepare_stage(args.saved_manifest, args.saved_manifest_sha256, args.output)
    print(json.dumps({key: result[key] for key in ("status", "candidate_sha256", "installable", "package_created")}))
