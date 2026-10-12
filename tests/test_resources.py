"""Independent malformed-RCC and exact-stock round-trip extraction checks."""
import hashlib
import json
import os
import struct
import subprocess
import tempfile
import unittest
import zlib
from pathlib import Path

from tools.extract_qml import (PROJECT, STOCK, REQUIRED, ResourceError, collect, decode_payload,
                               contract, parse_rcc, safe_component, write_outputs)
from tools.output_guard import output_directory


def fixture(name="a.qml", content=b"import QtQuick\nItem {}", flags=0):
    names = b"\0\0" + b"\0" * 4 + struct.pack(">HI", len(name), 0) + name.encode("utf-16be")
    tree = struct.pack(">IHIIQ", 0, 2, 1, 1, 0) + struct.pack(">IHHHIQ", 6, flags, 0, 0, 0, 0)
    data = struct.pack(">I", len(content)) + content
    return tree, names, data


class ResourceBoundaryTests(unittest.TestCase):
    def test_raw_and_qt_zlib_roundtrip(self):
        content = b"import QtQuick\nItem {}"
        tree, names, data = fixture(content=content)
        self.assertEqual(parse_rcc(tree, names, data), [("a.qml", 0, content)])
        packed = struct.pack(">I", len(content)) + zlib.compress(content)
        self.assertEqual(decode_payload(packed, 1, 100), content)

    def test_truncated_and_out_of_range_tree(self):
        t, n, d = fixture()
        for damaged in (t[:-1], t[:10] + struct.pack(">I", 999) + t[14:]):
            with self.assertRaises(ResourceError):
                parse_rcc(damaged, n, d)

    def test_cycle_and_unreachable_node(self):
        t, n, d = fixture()
        for damaged in (t[:10] + struct.pack(">I", 0) + t[14:], t + t[22:]):
            with self.assertRaises(ResourceError):
                parse_rcc(damaged, n, d)

    def test_invalid_name_and_payload_spans(self):
        t, n, d = fixture()
        with self.assertRaises(ResourceError):
            parse_rcc(t, n[:-1], d)
        with self.assertRaises(ResourceError):
            parse_rcc(t, n, d[:-1])

    def test_path_traversal_and_windows_aliases_rejected(self):
        for name in ("..", ".", "", "x/y", "x\\y", "C:", "nul.qml", "COM1", "x.", "x ",
                     "a<b", "a>b", 'a"b', "a|b", "a?b", "a*b", "a\0b", "a\x1fb"):
            with self.subTest(name=name), self.assertRaises(ResourceError):
                safe_component(name)

    def test_case_collision_between_files_and_directories_rejected(self):
        t, n, d = fixture(name="A.qml")
        second_name = struct.pack(">HI", 5, 0) + "a.qml".encode("utf-16be")
        for flags in (0, 2):
            second = (struct.pack(">IHIIQ", len(n), 2, 0, 3, 0) if flags == 2
                      else struct.pack(">IHHHIQ", len(n), 0, 0, 0, 0, 0))
            damaged = t[:6] + struct.pack(">I", 2) + t[10:] + second
            with self.subTest(flags=flags), self.assertRaisesRegex(ResourceError, "colliding"):
                parse_rcc(damaged, n + second_name, d)

    def test_invalid_directory_and_compression_flags_rejected(self):
        t, n, d = fixture()
        for flags in (3, 5, 6, 7, 8):
            with self.subTest(flags=flags), self.assertRaises(ResourceError):
                parse_rcc(t[:26] + struct.pack(">H", flags) + t[28:], n, d)

    def test_decompression_bomb_truncation_trailer_and_wrong_size(self):
        packed = struct.pack(">I", 1000) + zlib.compress(b"x" * 1000)
        with self.assertRaises(ResourceError):
            decode_payload(packed, 1, 100)
        for bad in (packed[:-1], packed + b"junk", struct.pack(">I", 10) + packed[4:]):
            with self.assertRaises(ResourceError):
                decode_payload(bad, 1, 2000)
        with self.assertRaises(ResourceError):
            decode_payload(b"anything", 4, 100)

    def test_gui_wrong_hash_rejected_before_parsing(self):
        with self.assertRaisesRegex(ResourceError, "SHA256"):
            collect(b"not the pinned GUI")


class StockResourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        output_directory(PROJECT / "build")
        cls.files, cls.manifest = collect(STOCK.read_bytes())

    def test_actual_sources_are_exact_and_original_paths_preserved(self):
        for path, digest in REQUIRED.items():
            self.assertEqual(hashlib.sha256(self.files[path]).hexdigest(), digest)
        screen = self.files["qt/qml/app/qml/mainmenu/MainScreen.qml"].decode()
        self.assertIn("required property string menuName", screen)
        self.assertIn("readonly property int numRows: 3", screen)
        self.assertIn("interactive: false", screen)
        self.assertIn("KeyFn.Cross, KeyFn.Ael", screen)
        drawer = self.files["qt/qml/app/qml/controlscreen/ControlDrawer.qml"].decode()
        self.assertIn("loadSubMenuItem.connect(mainMenu.loadSubmenu)", drawer)
        self.assertNotIn("app/qml/scripts/Keys.js", self.files)

    def test_contract_distinguishes_static_candidates_from_live_model(self):
        result = contract(self.manifest)
        self.assertFalse(result["device_validated"])
        self.assertIn("runtime-dependent", result["model"]["count"])
        self.assertIn("never assume eleven", result["grid"]["constraint"])
        candidates = result["model"]["static_top_menu_candidates"]
        self.assertEqual(len(candidates), 11)
        self.assertEqual(candidates[8], {"menuName": "ibisMenu", "rw": 0, "avail": 4})
        self.assertEqual(candidates[9], {"menuName": "connectionMenu", "rw": 32, "avail": 2})
        self.assertEqual(result["icons"]["generalMenu"], "image://svg/ic_menu_general")
        for path in result["icons"]["resource_paths"]:
            self.assertIn(path, self.files)

    def test_written_resources_match_and_repeat_is_idempotent(self):
        with tempfile.TemporaryDirectory(prefix="resources-", dir=PROJECT / "build") as tmp:
            root = Path(tmp) / "stock"
            contract = Path(tmp) / "contract.json"
            write_outputs(self.files, self.manifest, root, contract)
            first = (root / "manifest.json").read_bytes()
            write_outputs(self.files, self.manifest, root, contract)
            self.assertEqual((root / "manifest.json").read_bytes(), first)
            for path, content in self.files.items():
                self.assertEqual((root / path).read_bytes(), content)
            self.assertFalse(json.loads(contract.read_text())["device_validated"])

    def test_existing_modified_source_is_not_overwritten(self):
        with tempfile.TemporaryDirectory(prefix="resources-", dir=PROJECT / "build") as tmp:
            root = Path(tmp)
            path = next(iter(self.files))
            target = root / path
            target.parent.mkdir(parents=True)
            target.write_bytes(b"user modification")
            with self.assertRaisesRegex(ResourceError, "overwrite"):
                write_outputs(self.files, self.manifest, root, root / "contract.json")
            self.assertEqual(target.read_bytes(), b"user modification")

    def test_metadata_paths_cannot_replace_originals_or_each_other(self):
        with tempfile.TemporaryDirectory(prefix="resources-", dir=PROJECT / "build") as tmp:
            root = Path(tmp) / "stock"
            resource = next(iter(self.files))
            for contract_path in (root / resource, root / "manifest.json", root / Path(resource).parts[0]):
                with self.subTest(path=contract_path), self.assertRaisesRegex(ResourceError, "collid"):
                    write_outputs(self.files, self.manifest, root, contract_path)
                self.assertFalse(root.exists(), "collision must fail before any output is written")

    def test_redirected_output_root_and_parent_rejected_before_writes(self):
        for nested in (False, True):
            with self.subTest(nested=nested), tempfile.TemporaryDirectory(prefix="resources-redirect-", dir=PROJECT / "build") as tmp:
                base = Path(tmp)
                safe = base / "safe"
                safe.mkdir()
                link = base / "build"
                if os.name == "nt":
                    result = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(safe)], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                else:
                    link.symlink_to(safe, target_is_directory=True)
                try:
                    destination = link / "nested/output" if nested else link
                    with self.assertRaisesRegex(ValueError, "reparse|symlink|junction"):
                        write_outputs(self.files, self.manifest, destination, base / "contract.json")
                    self.assertEqual(list(safe.iterdir()), [])
                    self.assertFalse((base / "contract.json").exists())
                finally:
                    if os.name == "nt":
                        os.rmdir(link)
                    else:
                        link.unlink()

    def test_hardlinked_resource_manifest_and_contract_rejected(self):
        for kind in ("resource", "manifest", "contract"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix="resources-hardlink-", dir=PROJECT / "build") as tmp:
                base = Path(tmp)
                root = base / "stock"
                contract_path = base / "contract.json"
                relative = next(iter(self.files))
                target = {"resource": root / relative, "manifest": root / "manifest.json", "contract": contract_path}[kind]
                original = base / "preserved.bin"
                content = self.files[relative] if kind == "resource" else b"preserve this metadata alias"
                original.write_bytes(content)
                target.parent.mkdir(parents=True, exist_ok=True)
                os.link(original, target)
                try:
                    with self.assertRaisesRegex(ValueError, "hard-linked"):
                        write_outputs(self.files, self.manifest, root, contract_path)
                    self.assertEqual(original.read_bytes(), content)
                    self.assertEqual(target.read_bytes(), content)
                finally:
                    target.unlink()


if __name__ == "__main__":
    unittest.main()
