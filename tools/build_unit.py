"""Build local-only X2D II MainScreen clones with one bootstrap Loader.

Adapted approach: MIT-licensed Hasselblad Feature Extensions, pinned reference
9f6c9baffeaf30ac805905f8052973f60b11acf6, build_bootstrap_unit.py.
Original data, original function indices and original non-root object addresses
are retained. This component output is not an installation package.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path
from urllib.parse import urlsplit

try:
    from .output_guard import guard_output, output_directory, write_output
    from .qt_unit import (BINDING_SIZE, GUI_SHA256, MAIN_SHA256, OBJECT_SIZE,
                          parse_unit, read_main_screen, require)
except ImportError:
    from output_guard import guard_output, output_directory, write_output
    from qt_unit import (BINDING_SIZE, GUI_SHA256, MAIN_SHA256, OBJECT_SIZE,
                         parse_unit, read_main_screen, require)

PROJECT = Path(__file__).resolve().parents[1]
DEVICE_URL = "file:///system/etc/X2d2MenuBootstrap.qml"
LOADER_NAME = "X2d2MenuBootstrapLoader"


def validate_url(source: str) -> None:
    url = urlsplit(source)
    require(url.scheme == "file" and source.startswith("file:///")
            and not url.netloc and url.path.endswith(".qml")
            and not url.query and not url.fragment
            and not any(ord(c) < 32 for c in source),
            "bootstrap URL must be an absolute local file:/// URL ending in .qml")


def build(original: bytes, source: str) -> bytes:
    validate_url(source)
    old = parse_unit(original)
    require(hashlib.sha256(original).hexdigest() == MAIN_SHA256,
            "builder accepts only the pinned original X2D II MainScreen unit")
    require(old.strings[0] == "" and old.strings[11] == "FocusScope", "MainScreen root contract")
    require(old.data[old.objects[0].offset:old.objects[0].offset + 4] == struct.pack("<I", 11),
            "MainScreen must have a FocusScope root")
    require(LOADER_NAME not in old.strings, "bootstrap already present")
    blob = bytearray(original)
    names = list(old.strings)
    string_offsets = list(old.string_offsets)

    def append(payload: bytes | bytearray) -> int:
        blob.extend(b"\0" * (-len(blob) % 8))
        offset = len(blob)
        blob.extend(payload)
        blob.extend(b"\0" * (-len(blob) % 8))
        require(len(blob) < 2**32, "unit exceeds 32-bit offset domain")
        return offset

    def name(text: str) -> int:
        if text not in names:
            raw = text.encode("utf-16le")
            string_offsets.append(append(struct.pack("<I", len(raw) // 2) + raw + b"\0\0"))
            names.append(text)
        return names.index(text)

    old_root = old.objects[0]
    root = bytearray(original[old_root.offset:old_root.end])
    require(old_root.binding_count < 65535, "root binding count overflow")
    binding_copy = original[old_root.bindings_offset:old_root.bindings_offset
                            + old_root.binding_count * BINDING_SIZE]
    new_binding_offset = len(root)
    root.extend(binding_copy)
    root.extend(struct.pack("<6I", name(""), 8 << 16, len(old.objects), 0, 0, 0))
    struct.pack_into("<H", root, 46, old_root.binding_count + 1)
    struct.pack_into("<I", root, 48, new_binding_offset)

    loader = bytearray(OBJECT_SIZE)
    struct.pack_into("<4I", loader, 0, name("Loader"), name(""), 0xFFFF0000, 0xFFFFFFFF)
    # Match Qt's serialized empty table convention: point to trailing data.
    for field in (20, 24, 28, 36, 40):
        struct.pack_into("<I", loader, field, OBJECT_SIZE)
    for field in (56, 68, 76):
        struct.pack_into("<I", loader, field, OBJECT_SIZE + 2 * BINDING_SIZE)
    struct.pack_into("<H", loader, 46, 2)
    struct.pack_into("<I", loader, 48, OBJECT_SIZE)
    loader.extend(struct.pack("<6I", name("objectName"), 3 << 16, 0, name(LOADER_NAME), 0, 0))
    loader.extend(struct.pack("<6I", name("source"), 3 << 16, 0, name(source), 0, 0))
    object_offsets = [offset - old.qml_offset for offset in old.object_offsets]
    object_offsets[0] = append(root) - old.qml_offset
    object_offsets.append(append(loader) - old.qml_offset)
    object_table = append(struct.pack("<" + "I" * len(object_offsets), *object_offsets))
    struct.pack_into("<II", blob, old.qml_offset + 8, len(object_offsets), object_table - old.qml_offset)
    string_table = append(struct.pack("<" + "I" * len(string_offsets), *string_offsets))
    struct.pack_into("<II", blob, 112, len(string_offsets), string_table)
    struct.pack_into("<I", blob, 24, len(blob))
    blob[76:92] = hashlib.md5(blob[92:]).digest()
    result = bytes(blob)
    validate_preservation(original, result, source)
    return result


def validate_preservation(original: bytes, candidate: bytes, source: str) -> dict:
    old, new = parse_unit(original), parse_unit(candidate)
    allowed = ((24, 28), (76, 92), (112, 120), (old.qml_offset + 8, old.qml_offset + 16))
    require(len(candidate) > len(original), "candidate must append data")
    require(all(a == b or any(start <= i < end for start, end in allowed)
                for i, (a, b) in enumerate(zip(original, candidate))),
            "original bytes changed outside allowed header/table pointers")
    require(new.strings[:len(old.strings)] == old.strings, "original string indices changed")
    require(new.string_offsets[:len(old.strings)] == old.string_offsets, "original strings moved")
    require(candidate[120:248] == original[120:248], "function/AOT index or header contract changed")
    require(len(new.objects) == len(old.objects) + 1, "expected exactly one added object")
    require(new.object_offsets[1:-1] == old.object_offsets[1:], "original object indices moved")
    for record in old.objects[1:]:
        require(candidate[record.offset:record.end] == original[record.offset:record.end],
                "original non-root object data changed")
    old_root, new_root = old.objects[0], new.objects[0]
    for relative in range(old_root.end - old_root.offset):
        if not 46 <= relative < 52:
            require(original[old_root.offset + relative] == candidate[new_root.offset + relative],
                    "relocated root data changed")
    require(new_root.bindings[:-1] == old_root.bindings, "original root bindings changed")
    require(new_root.bindings[-1] == (0, 8 << 16, len(old.objects), 0, 0, 0), "root Loader link")
    loader = new.objects[-1]
    require(new.strings[struct.unpack_from("<I", candidate, loader.offset)[0]] == "Loader", "Loader type")
    expected = (("objectName", LOADER_NAME), ("source", source))
    require(loader.binding_count == 2, "Loader binding count")
    for binding, (prop, value) in zip(loader.bindings, expected):
        require(new.strings[binding[0]] == prop and binding[1] == 3 << 16
                and binding[2] == 0 and new.strings[binding[3]] == value, "Loader string binding")
    return {"originalBytesPreservedExceptDeclaredPointers": True,
            "originalFunctionIndicesPreserved": True, "originalObjectIndicesPreserved": True,
            "originalRootBindingsPreserved": True, "addedObjects": 1,
            "originalUnitSha256": hashlib.sha256(original).hexdigest(),
            "candidateUnitSha256": hashlib.sha256(candidate).hexdigest(),
            "originalChecksumMode": old.checksum_mode, "candidateChecksumMode": new.checksum_mode,
            "originalObjectCount": len(old.objects), "candidateObjectCount": len(new.objects),
            "functionCount": old.tables["function"][0], "source": source}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gui", required=True, type=Path)
    parser.add_argument("--host-url", required=True, help="Explicit file:/// bootstrap URL for host tests")
    parser.add_argument("--output-dir", type=Path, default=PROJECT / "build" / "units")
    args = parser.parse_args()
    output = args.output_dir.absolute()
    build_root = PROJECT / "build"
    require(build_root.resolve() == build_root, "project build/ must not redirect through a link")
    require(output.is_relative_to(build_root), "outputs must remain under project build/")
    guard_output(output)
    validate_url(args.host_url)
    original = read_main_screen(args.gui)
    outputs = {}
    # Build and validate both in memory before creating output files.
    clones = {"device": build(original, DEVICE_URL), "host": build(original, args.host_url)}
    output_directory(output)
    for kind, data in clones.items():
        path = output / ("main-screen-bootstrap-" + kind + ".bin")
        require(not path.is_symlink() and (not path.exists() or path.stat().st_nlink == 1),
                "output file must not be a symlink or hard link")
        write_output(path, data)
        reread = path.read_bytes()
        require(reread == data, "unit output round-trip mismatch")
        outputs[kind] = validate_preservation(original, reread, DEVICE_URL if kind == "device" else args.host_url)
        outputs[kind].update(bytes=len(data), path=str(path))
    report = {"status": "LOCAL_COMPONENT_ONLY", "installable": False, "cameraValidated": False,
              "guiSha256": GUI_SHA256, "qtVersion": "6.8.2", "qv4DataVersion": 66,
              "outputs": outputs,
              "unverified": ["Qt vendor private ABI and type compilation acceptance",
                             "cache replacement preserves original AOT function pointer association",
                             "live Loader creation, menu integration and camera capture regression"]}
    report_path = output / "unit-validation.json"
    require(not report_path.is_symlink() and (not report_path.exists() or report_path.stat().st_nlink == 1),
            "report file must not be a symlink or hard link")
    write_output(report_path, (json.dumps(report, indent=2) + "\n").encode('utf-8'))
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
