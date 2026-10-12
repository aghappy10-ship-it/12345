"""Extract bounded, original QML/JS and small UI images from the pinned GUI.

No firmware execution, device access, old-project imports, or installation.
Qt RCC v2/v3 tree records are 22-byte big-endian records. ELF is LE64.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import zlib
from pathlib import Path, PurePosixPath

if __package__:
    from .output_guard import guard_output, output_directory, write_output
else:
    from output_guard import guard_output, output_directory, write_output

GUI_SHA256 = "b1b643cb36176cd5a49129dd9bb2be480aa045a96ed1c35c30a779ab5af0801b"
PROJECT = Path(__file__).resolve().parents[1]
STOCK = Path(os.environ.get("X2D2_STOCK_GUI", r"F:\Codex\2026-08-19\x2d2\work\reverse\vendor\x2dii_1_3_16_2_system_root\bin\camera-gui"))
MAX_TEXT = 1024 * 1024
MAX_IMAGE = 512 * 1024
MAX_TOTAL = 32 * 1024 * 1024
RCC_SYMBOLS = {"_ZL16qt_resource_name": "names", "_ZL16qt_resource_data": "data", "_ZL18qt_resource_struct": "tree"}
TEXT_SUFFIXES = {".qml", ".js", ".mjs"}
IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".svg", ".webp", ".gif"}
REQUIRED = {
    "qt/qml/app/qml/mainmenu/MainScreen.qml": "333060ab5ecdc8c6f66cb4dc97e5f447e401cfd498ed0e1eba104dde5a32dbd6",
    "qt/qml/app/qml/controlscreen/ControlDrawer.qml": "e9e7fcfd6744729422b4e4647c5f2be232363f5c97ae545166d55d39e4f67086",
    "qt/qml/app/qml/mainmenu/MainMenu.qml": "c4987f3e688dc926c9468981b97bc9173944929581641f4276c31fb7932d7058",
    "qt/qml/app/qml/mainmenu/MainMenuViewModel.qml": "e8e371091815ce3e1e22941d170b52b85a3e398a8f81a3e56c47b2110b11651c",
    "qt/qml/app/qml/mainmenu/MenuData.qml": "59c8712c36b2a129437d0416ca8195c66983d47e8f7f7004e995c163dd23598a",
    "qt/qml/app/qml/scripts/Keys.js": "b2e1e58bbd83c55133316c1849286b491d54ec5b0d395985849277171a02393e",
}


class ResourceError(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise ResourceError(message)


def checked(data, offset, size, label):
    require(0 <= offset <= len(data) and 0 <= size <= len(data) - offset, label + " out of bounds")
    return data[offset:offset + size]


def unpack(fmt, data, offset=0):
    return struct.unpack(fmt, checked(data, offset, struct.calcsize(fmt), fmt))


def cstring(data, offset):
    require(0 <= offset < len(data), "ELF string offset")
    end = data.find(b"\0", offset)
    require(end >= 0, "ELF string terminator")
    return data[offset:end].decode("utf-8", errors="strict")


def rcc_groups(blob):
    """Recover RCC arrays by their local STT_FILE scope, without symbol-name loss."""
    checked(blob, 0, 64, "ELF header")
    require(blob[:7] == b"\x7fELF\x02\x01\x01", "requires ELF64 little endian")
    require(unpack("<H", blob, 18)[0] == 183, "requires AArch64")
    phoff, shoff = unpack("<QQ", blob, 32)
    phwidth, phcount, shwidth, shcount = unpack("<HHHH", blob, 54)
    require(phwidth == 56 and shwidth == 64 and phcount > 0 and shcount > 0, "ELF table format")
    checked(blob, phoff, phwidth * phcount, "ELF program table")
    checked(blob, shoff, shwidth * shcount, "ELF section table")
    segments = [unpack("<IIQQQQQQ", blob, phoff + i * phwidth) for i in range(phcount)]
    sections = [unpack("<IIQQQQIIQQ", blob, shoff + i * shwidth) for i in range(shcount)]

    def virtual(address, size):
        matches = []
        for p in segments:
            if p[0] == 1 and p[3] <= address and size <= p[5] - (address - p[3]):
                matches.append(checked(blob, p[2] + address - p[3], size, "RCC symbol"))
        require(len(matches) == 1, "RCC symbol must have one complete PT_LOAD mapping")
        return matches[0]

    groups = {}
    for sec in sections:
        if sec[1] != 2:  # SHT_SYMTAB preserves duplicate local RCC symbol names.
            continue
        require(sec[9] == 24 and sec[5] % 24 == 0 and sec[6] < len(sections), "ELF symbol table")
        strings_sec = sections[sec[6]]
        strings = checked(blob, strings_sec[4], strings_sec[5], "ELF symbol strings")
        syms = checked(blob, sec[4], sec[5], "ELF symbols")
        scope = ""
        for pos in range(0, len(syms), 24):
            name_ix, info, _, _, address, size = unpack("<IBBHQQ", syms, pos)
            name = cstring(strings, name_ix)
            if info & 15 == 4:
                scope = name
            if name not in RCC_SYMBOLS:
                continue
            require(scope.startswith("qrc_") and info & 15 == 1, "RCC object scope/type")
            key = RCC_SYMBOLS[name]
            group = groups.setdefault(scope, {})
            require(key not in group, "duplicate RCC symbol in a file scope")
            require(0 < size <= MAX_TOTAL, "RCC array size limit")
            group[key] = virtual(address, size)
            group[key + "_address"] = address
    require(groups, "no RCC arrays found")
    require(all(all(k in g for k in ("tree", "names", "data")) for g in groups.values()), "incomplete RCC group")
    return groups


def safe_component(name):
    require(name not in ("", ".", "..") and not any(c in name for c in '/\\:<>"|?*')
            and not any(ord(c) < 32 for c in name), "unsafe RCC path component")
    require(not name.endswith((" ", ".")), "Windows-ambiguous RCC component")
    require(name.split(".")[0].upper() not in {"CON", "PRN", "AUX", "NUL", *("COM" + str(i) for i in range(1, 10)), *("LPT" + str(i) for i in range(1, 10))}, "Windows reserved RCC component")


def parse_rcc(tree, names, data):
    """Validate an RCC tree fully, returning file paths and bounded packed payloads."""
    require(len(tree) >= 22 and len(tree) % 22 == 0, "RCC record size")
    count = len(tree) // 22
    require(count <= 100000, "RCC node limit")
    seen = set()
    result = []
    paths = set()
    node_paths = set()

    def visit(ix, path, depth):
        require(depth <= 64 and 0 <= ix < count, "RCC child/depth bounds")
        require(ix not in seen, "RCC cycle or multiply owned node")
        seen.add(ix)
        pos = ix * 22
        no, flags = unpack(">IH", tree, pos)
        require(flags & ~7 == 0, "unknown RCC flags")
        length = unpack(">H", names, no)[0]
        checked(names, no, 6 + length * 2, "RCC name")
        name = checked(names, no + 6, length * 2, "RCC name text").decode("utf-16be", errors="strict")
        if ix:
            safe_component(name)
            path = path + (name,)
            folded = "/".join(path).casefold()
            require(folded not in node_paths, "duplicate or colliding RCC node path")
            node_paths.add(folded)
        else:
            require(flags == 2, "RCC root must be a directory")
        if flags & 2:
            require(flags == 2, "compressed RCC directory")
            children, start = unpack(">II", tree, pos + 6)
            require(start <= count and children <= count - start, "RCC child range")
            for child in range(start, start + children):
                visit(child, path, depth + 1)
        else:
            require(flags in (0, 1, 4), "invalid RCC compression flags")
            relative = "/".join(path)
            require(relative and relative.casefold() not in paths, "duplicate or empty RCC file path")
            paths.add(relative.casefold())
            offset = unpack(">I", tree, pos + 10)[0]
            size = unpack(">I", data, offset)[0]
            packed = checked(data, offset + 4, size, "RCC payload")
            result.append((relative, flags, packed))
    visit(0, (), 0)
    require(len(seen) == count, "unreachable RCC nodes")
    return result


def decode_payload(packed, flags, limit):
    require(limit > 0, "positive decompression limit required")
    if flags == 0:
        require(len(packed) <= limit, "resource exceeds size limit")
        return packed
    require(flags == 1, "unsupported compression (only raw or Qt zlib accepted)")
    expected = unpack(">I", packed)[0]
    require(0 < expected <= limit, "declared decompression size limit")
    decoder = zlib.decompressobj()
    try:
        decoded = decoder.decompress(packed[4:], expected + 1)
    except zlib.error as error:
        raise ResourceError("invalid zlib payload") from error
    require(len(decoded) == expected and decoder.eof and not decoder.unconsumed_tail and not decoder.unused_data,
            "zlib length, truncation, trailing-data, or size-limit mismatch")
    return decoded


def select_limit(path):
    p = PurePosixPath(path)
    app = path.startswith(("qt/qml/app/", "qt/qml/com/hasselblad/"))
    if app and (p.suffix.lower() in TEXT_SUFFIXES or p.name == "qmldir"):
        return MAX_TEXT
    if p.suffix.lower() in IMAGE_SUFFIXES:
        return MAX_IMAGE
    return None


def collect(blob):
    require(hashlib.sha256(blob).hexdigest() == GUI_SHA256, "GUI SHA256 mismatch")
    groups = rcc_groups(blob)
    files, entries, skipped = {}, {}, []
    folded = set()
    total = 0
    for scope, group in sorted(groups.items()):
        for path, flags, packed in parse_rcc(group["tree"], group["names"], group["data"]):
            limit = select_limit(path)
            if limit is None:
                skipped.append({"path": path, "scope": scope, "reason": "out-of-scope-type-or-module"})
                continue
            require(flags in (0, 1), "unsupported compression in selected resource: " + path)
            declared = len(packed) if flags == 0 else unpack(">I", packed)[0]
            if declared > limit and PurePosixPath(path).suffix.lower() in IMAGE_SUFFIXES:
                skipped.append({"path": path, "scope": scope, "reason": "image-size-limit", "size": declared})
                continue
            content = decode_payload(packed, flags, limit)
            require(path.casefold() not in folded, "resource shadowing/case collision: " + path)
            folded.add(path.casefold())
            if limit == MAX_TEXT:
                content.decode("utf-8", errors="strict")
            total += len(content)
            require(total <= MAX_TOTAL, "aggregate extraction size limit")
            files[path] = content
            entries[path] = {"sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content),
                             "rcc_scope": scope, "compression": "zlib" if flags else "none"}
    for path, digest in REQUIRED.items():
        require(path in entries and entries[path]["sha256"] == digest, "required original mismatch: " + path)
    manifest = {"schema": 1, "gui_sha256": GUI_SHA256, "qt_version": "6.8.2", "device_validated": False,
                "extracted_count": len(files), "extracted_bytes": total, "files": entries, "skipped": skipped,
                "rcc_groups": {name: {k: hex(g[k + "_address"]) for k in ("tree", "names", "data")} for name, g in groups.items()}}
    return files, manifest


def contract(manifest):
    return {
        "schema": 1, "gui_sha256": GUI_SHA256, "qt_version": "6.8.2", "device_validated": False,
        "source_hashes": {p: manifest["files"][p]["sha256"] for p in REQUIRED},
        "qml_prefix": "qrc:/qt/qml/app/qml/", "keys_url": "qrc:/qt/qml/app/qml/scripts/Keys.js",
        "model": {"property": "MainMenuViewModel.favoriteModel", "type": "var", "writable": True,
                  "roles": {"257": "menuName", "258": "label", "259": "labelContext", "260": "itemEnabled", "261": "iconSrc"},
                  "delegate_required": ["index", "menuName", "labelContext", "label", "iconSrc", "itemEnabled"],
                  "index_is_role": False, "methods": ["count()", "itemEnabled(int)", "rowCount()", "index(int,int)", "data(QModelIndex,int)"],
                  "absent_model_methods": ["get", "modelData", "itemsEnabled", "addItem"],
                  "source_signals": ["dataChanged", "modelAboutToBeReset", "modelReset", "rowsInserted", "rowsRemoved", "rowsMoved", "layoutChanged"],
                  "native_dynamic_update": "reloadModel and E_MenuRW/E_MenuAvail callbacks reset the entire model; image-format changes emit dataChanged",
                  "count": "runtime-dependent: Menu::topMenus filtered by conditionValid(E_MenuAvail)",
                  "static_top_menu_candidates": [
                      {"menuName": "exposureMenu", "rw": 0, "avail": 0},
                      {"menuName": "focusMenu", "rw": 0, "avail": 0},
                      {"menuName": "qualityMenu", "rw": 0, "avail": 0},
                      {"menuName": "cropModesMenu", "rw": 0, "avail": 0},
                      {"menuName": "flashMenu", "rw": 0, "avail": 0},
                      {"menuName": "displayMenu", "rw": 0, "avail": 0},
                      {"menuName": "powerMenu", "rw": 32, "avail": 0},
                      {"menuName": "storageMenu", "rw": 32, "avail": 0},
                      {"menuName": "ibisMenu", "rw": 0, "avail": 4},
                      {"menuName": "connectionMenu", "rw": 32, "avail": 2},
                      {"menuName": "generalMenu", "rw": 0, "avail": 0}],
                  "static_top_menu_evidence": {
                      "getter": "MenuX2d::topMenus at 0x1706b40 returns global 0x2b4ce70",
                      "initializer": "_GLOBAL__sub_I_menux2d.cpp at 0x393050; records 0x3bde10-0x3bdfd8",
                      "count": "mov w3,#11 at 0x3bde3c; copy end +0x160 at 0x3bdf7c; stride 0x20",
                      "condition_pairs": {"32,0": "0x1d198a0", "0,4": "0x1d19b58", "32,2": "0x1d19f38"},
                      "limitation": "static candidates are not live FavoriteModel rows or enabled states"},
                  "native_evidence": {"roleNames": "0x16f3268", "init": "0x16f1f80", "reloadModel": "0x16f1f48", "metaObject": "0x2a8bb18"}},
        "icons": {"generalMenu": "image://svg/ic_menu_general", "flashMenu": "image://svg/ic_menu_flash",
                  "resource_paths": ["icons/ic_menu_general.svg", "icons/ic_menu_flash.svg"],
                  "native_evidence": {"initializer": "_GLOBAL__sub_I_favoritemodel.cpp at 0x2db320",
                                      "map": "GuiCommon::kMenuIcons at 0x2b4aa00",
                                      "general_literal": "0x1cedfa0, 27 UTF-16 code units",
                                      "flash_literal": "0x1cedf0c, 25 UTF-16 code units",
                                      "role_assignment": "FavoriteModel::addItem lookup 0x16f29c0, iconSrc role 0x105 at 0x16f2b18"},
                  "limitation": "original provider URL verified statically; camera rendering remains unverified"},
        "grid": {"rows": 3, "columns": 4, "capacity": 12, "interactive": False, "sparseFavoritesGrid": "readonly false",
                 "constraint": "discover source count and validate roles; never assume eleven; reject append if no visible capacity"},
        "route": {"signal": "MainScreen.loadSubMenuItem(string,string,bool,bool)",
                  "parameter_names": ["menuName", "subMenuItem", "openItem", "fromShortcut"],
                  "connection": "ControlDrawer.qml:222 (item as MainScreen).loadSubMenuItem.connect(mainMenu.loadSubmenu)",
                  "wrapper": "ControlDrawer.qml:272-280: state==control_screen snaps list; otherwise forwards four arguments",
                  "evidence": {"ControlDrawer_unit": "0x1ead4c0", "onLoaded_function": 38, "connect_bytecode_offset": 72,
                               "loadSubmenu_function": 59},
                  "extension_name": "x2diiMenuExtension", "stock_names": "forward exactly once through original wrapper"},
        "restore": {"inMenu": "Qt.binding(function(){return originalLoader.active})",
                    "preventSwipe": "Qt.binding(function(){return originalSwipe.preventSwipe})",
                    "drawerList_interactive": "Qt.binding(function(){return !drawerList.blockSwipe})",
                    "blockSwipe": "popupActive || screenEVF || exposing || drawer.swiping || drawer.state === 'main_menu'",
                    "source": ["MainMenu.qml:237-238", "ControlDrawer.qml:115-123"]},
        "states": {"drawer_default": "empty string is main grid", "drawer_main_menu": "stock submenu active",
                   "mainMenu_menu": "swipeArea.show", "outer": "drawer.mainState from MainContent.state; mainViewState from mainStateMachine.mainViewState",
                   "guards": ["mainState === 'main_menu'", "mainViewState === 'main_menu'", "!drawerAtTop", "list.currentIndex === mainScreenIx", "!swiping", "!list.moving", "!mediaProcessing", "!originalLoader.active"]},
        "keys": {"back_functions": {"Escape": 5, "JstkEscape": 31, "Menu": 1},
                 "stock_submenu_consumed": {"NavKey": 29, "Square": 3, "Cross": 2},
                 "main_grid_highlight_exit": {"Cross": 2, "Ael": 12},
                 "half_press": 11, "expose": 65, "enum_count": 104, "metaObject": "0x2a48a80",
                 "semantics": "use real Keys.js and KeyFn.isFn(key,modifiers,fn); accepting helpers accept only matches; unhandled events propagate",
                 "limitations": "desktop Qt key substitutes do not prove camera key routing"},
        "unknown": ["live original row count and enabled conditions", "actual camera key mappings under custom-button settings",
                    "live attach order and destruction behavior", "boot loading, installation and rollback qualification"]}


def write_outputs(files, manifest, destination, contract_path):
    trusted_root = PROJECT / "build"
    root = guard_output(destination, trusted_root)
    manifest_path = root / "manifest.json"
    manifest_path = guard_output(manifest_path, trusted_root)
    contract_path = guard_output(contract_path, trusted_root)
    metadata_paths = {manifest_path, contract_path}
    require(len(metadata_paths) == 2, "metadata output paths collide")
    for metadata_path in metadata_paths:
        require(not metadata_path.exists() or metadata_path.is_file(), "metadata output is not a file")
    targets = {}
    for relative, content in files.items():
        target = guard_output(root.joinpath(*PurePosixPath(relative).parts), trusted_root)
        require(target.is_relative_to(root), "output escapes destination")
        require(target not in metadata_paths, "metadata output collides with original resource")
        require(not any(p in metadata_paths for p in target.parents), "metadata output collides with resource directory")
        require(not target.exists() or (target.is_file() and target.read_bytes() == content), "refusing to overwrite different resource: " + relative)
        targets[target] = content
    metadata = {manifest_path: (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
                contract_path: (json.dumps(contract(manifest), indent=2, ensure_ascii=False) + "\n").encode("utf-8")}
    # Only generated manifests may be replaced. Original resource changes fail closed above.
    output_directory(root, trusted_root)
    for target, content in targets.items():
        if not target.exists():
            write_output(target, content, trusted_root)
        else:
            guard_output(target, trusted_root)
    for target, content in metadata.items():
        write_output(target, content, trusted_root)
    for target, content in targets.items():
        guard_output(target, trusted_root)
        require(hashlib.sha256(target.read_bytes()).digest() == hashlib.sha256(content).digest(), "written resource hash mismatch")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gui", type=Path, default=STOCK)
    parser.add_argument("--output", type=Path, default=PROJECT / "build" / "stock-qml")
    parser.add_argument("--contract", type=Path, default=PROJECT / "build" / "qml-contract.json")
    args = parser.parse_args()
    with args.gui.open("rb") as stream:
        require(os.fstat(stream.fileno()).st_size <= 512 * 1024 * 1024, "GUI input size limit")
        blob = stream.read()
    files, manifest = collect(blob)
    write_outputs(files, manifest, args.output, args.contract)
    print(json.dumps({"result": "PASS", "scope": "offline resource extraction only", "count": len(files),
                      "bytes": manifest["extracted_bytes"], "output": str(args.output.resolve()), "device_validated": False}))


if __name__ == "__main__":
    main()
