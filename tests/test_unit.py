"""Real pinned-firmware unit tests; no device access and no upstream execution.

Run from the project root with Python -B -m unittest discover -s tests -v.
Override X2D2_STOCK_GUI only to select another local copy of the same pinned ELF.
"""
from __future__ import annotations

import hashlib
import os
import struct
import subprocess
import sys
import unittest
from pathlib import Path

from tools.build_unit import DEVICE_URL, LOADER_NAME, PROJECT, build, validate_preservation
from tools.qt_unit import (GUI_SHA256, MAIN_SHA256, ValidationError, parse_unit,
                           read_main_screen, verify_file_hash)

STOCK = Path(os.environ.get("X2D2_STOCK_GUI",
             r"F:\Codex\2026-08-19\x2d2\work\reverse\vendor\x2dii_1_3_16_2_system_root\bin\camera-gui"))


def repaired(data: bytearray) -> bytes:
    """Bypass checksum rejection to exercise independent structural validation."""
    data[76:92] = hashlib.md5(data[92:]).digest()
    return bytes(data)


class UnitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = read_main_screen(STOCK)
        cls.old = parse_unit(cls.original)
        cls.device = build(cls.original, DEVICE_URL)
        cls.new = parse_unit(cls.device)

    def test_real_pinned_baseline_identity_and_content(self):
        self.assertEqual(hashlib.sha256(self.original).hexdigest(), MAIN_SHA256)
        self.assertEqual(len(self.original), 14896)
        self.assertEqual(self.old.tables["function"][0], 44)
        self.assertEqual(len(self.old.objects), 13)
        self.assertEqual(len(self.old.strings), 151)
        self.assertIn("MainScreen_root", self.old.strings)
        self.assertIn("MainScreen_grid", self.old.strings)
        self.assertEqual(self.old.checksum_mode, "before_static_and_pending_flags")

    def test_exact_loader_contract_and_original_root_bindings(self):
        self.assertEqual(len(self.new.objects), 14)
        self.assertEqual(self.new.objects[0].binding_count, 8)
        self.assertEqual(self.new.objects[0].bindings[:7], self.old.objects[0].bindings)
        self.assertEqual(self.new.objects[0].bindings[7], (0, 8 << 16, 13, 0, 0, 0))
        loader = self.new.objects[13]
        self.assertEqual(struct.unpack_from("<I", self.device, loader.offset + 8)[0], 0xFFFF0000)
        self.assertEqual(struct.unpack_from("<I", self.device, loader.offset + 12)[0], 0xFFFFFFFF)
        self.assertEqual(loader.binding_count, 2)
        values = {self.new.strings[b[0]]: self.new.strings[b[3]] for b in loader.bindings}
        self.assertEqual(values, {"objectName": LOADER_NAME, "source": DEVICE_URL})
        self.assertTrue(all(binding[1] == 3 << 16 for binding in loader.bindings))

    def test_original_byte_domain_preserved_and_only_declared_fields_change(self):
        # Independent interval diff, covering functions, lookup/constants, import
        # records, root storage and every original object's complete byte span.
        changes = [i for i in range(len(self.original)) if self.original[i] != self.device[i]]
        self.assertTrue(changes)
        for i in changes:
            self.assertTrue(24 <= i < 28 or 76 <= i < 92 or 112 <= i < 120
                            or self.old.qml_offset + 8 <= i < self.old.qml_offset + 16, i)
        self.assertEqual(self.new.object_offsets[1:13], self.old.object_offsets[1:])
        self.assertEqual(self.new.string_offsets[:151], self.old.string_offsets)
        self.assertEqual(self.device[120:248], self.original[120:248])
        root_old, root_new = self.old.objects[0], self.new.objects[0]
        old_body = bytearray(self.original[root_old.offset:root_old.end])
        new_body = bytearray(self.device[root_new.offset:root_new.offset + len(old_body)])
        old_body[46:52] = new_body[46:52]
        self.assertEqual(new_body, old_body)

    def test_actual_output_checksum_and_deterministic_rebuild(self):
        self.assertEqual(hashlib.md5(self.device[92:]).digest(), self.device[76:92])
        self.assertEqual(self.new.checksum_mode, "serialized")
        self.assertEqual(build(self.original, DEVICE_URL), self.device)

    def test_explicit_host_source_and_supplementary_unicode(self):
        url = "file:///C:/host/\U0001f4f7/Bootstrap.qml"
        candidate = parse_unit(build(self.original, url))
        self.assertEqual(candidate.strings[candidate.objects[-1].bindings[1][3]], url)
        self.assertNotEqual(candidate.data, self.device)

    def test_invalid_bootstrap_urls_rejected(self):
        for url in ("https://host/Bootstrap.qml", "Bootstrap.qml", "file://server/Bootstrap.qml",
                    "file:///tmp/a.qml?query=1", "file:///tmp/a.qml#fragment", "file:///tmp/evil\n.qml"):
            with self.subTest(url=url), self.assertRaises(ValidationError):
                build(self.original, url)

    def test_wrong_elf_hash_rejected(self):
        with self.assertRaisesRegex(ValidationError, "SHA256 mismatch"):
            verify_file_hash(STOCK, "0" * 64)
        self.assertEqual(len(GUI_SHA256), 64)

    def test_wrong_qt_data_version_and_magic_rejected(self):
        for offset, value, pattern in ((12, 0x60401, "Qt version"),
                                       (8, 65, "data version"), (0, 0, "magic")):
            data = bytearray(self.original)
            struct.pack_into("<I", data, offset, value)
            with self.subTest(offset=offset), self.assertRaisesRegex(ValidationError, pattern):
                parse_unit(repaired(data))

    def test_wrong_unit_content_rejected_even_with_valid_checksum(self):
        data = bytearray(self.original)
        data[16] ^= 1  # Valid timestamp/header variation, not the pinned unit.
        with self.assertRaisesRegex(ValidationError, "pinned original"):
            build(repaired(data), DEVICE_URL)

    def test_repeat_build_rejected(self):
        with self.assertRaises(ValidationError):
            build(self.device, DEVICE_URL)

    def test_checksum_and_truncation_rejected(self):
        data = bytearray(self.original)
        data[-1] ^= 1
        with self.assertRaisesRegex(ValidationError, "MD5 mismatch"):
            parse_unit(bytes(data))
        for data in (b"", self.original[:100], self.original[:-1], self.original + b"\0"):
            with self.subTest(length=len(data)), self.assertRaises(ValidationError):
                parse_unit(data)

    def test_table_count_and_offset_overflows_rejected(self):
        for offset in (112, 116, 120, 124, 244, self.old.qml_offset + 4, self.old.qml_offset + 12):
            data = bytearray(self.original)
            struct.pack_into("<I", data, offset, 0xFFFFFFF8)
            with self.subTest(offset=offset), self.assertRaisesRegex(ValidationError, "bounds"):
                parse_unit(repaired(data))

    def test_function_relative_code_span_cannot_escape_record(self):
        data = bytearray(self.original)
        function = struct.unpack_from("<I", data, self.old.tables["function"][1])[0]
        # Still inside the unit, but beyond the first function's allocation.
        struct.pack_into("<I", data, function, 4096)
        with self.assertRaisesRegex(ValidationError, "function code: out of bounds"):
            parse_unit(repaired(data))

    def test_object_relative_span_cannot_escape_record(self):
        data = bytearray(self.original)
        struct.pack_into("<I", data, self.old.objects[0].offset + 48, 512)
        with self.assertRaisesRegex(ValidationError, "bindings: out of bounds"):
            parse_unit(repaired(data))

    def test_overlapping_top_level_tables_rejected(self):
        data = bytearray(self.original)
        # Move the lookup table into the function-offset table, with an otherwise
        # valid aligned and in-file start. Its declared extent overlaps blocks.
        struct.pack_into("<I", data, 156, 252)
        with self.assertRaisesRegex(ValidationError, "bounds"):
            parse_unit(repaired(data))

    def test_overlapping_object_tables_rejected(self):
        data = bytearray(self.original)
        # The root's bindings must not overlap its declared properties.
        struct.pack_into("<I", data, self.old.objects[0].offset + 48, 84)
        with self.assertRaisesRegex(ValidationError, "overlapping"):
            parse_unit(repaired(data))

    def test_unimplemented_unit_feature_rejected_explicitly(self):
        data = bytearray(self.original)
        struct.pack_into("<I", data, 128, 1)
        with self.assertRaises(ValidationError):
            parse_unit(repaired(data))

    def test_string_negative_length_and_unterminated_data_rejected(self):
        data = bytearray(self.original)
        struct.pack_into("<i", data, self.old.string_offsets[1], -1)
        with self.assertRaisesRegex(ValidationError, "negative string"):
            parse_unit(repaired(data))
        data = bytearray(self.original)
        offset = self.old.string_offsets[1]
        length = struct.unpack_from("<I", data, offset)[0]
        data[offset + 4 + length * 2] = 65
        with self.assertRaisesRegex(ValidationError, "terminator"):
            parse_unit(repaired(data))

    def test_object_and_string_index_bounds_rejected(self):
        root = self.old.objects[0]
        for offset in (root.bindings_offset, root.bindings_offset + 3 * 24 + 8):
            data = bytearray(self.original)
            struct.pack_into("<I", data, offset, 0xFFFFFFFF)
            with self.subTest(offset=offset), self.assertRaisesRegex(ValidationError, "index out of bounds"):
                parse_unit(repaired(data))

    def test_original_function_damage_detected_by_preservation_audit(self):
        data = bytearray(self.device)
        function = struct.unpack_from("<I", data, self.old.tables["function"][1])[0]
        code_rel = struct.unpack_from("<I", data, function)[0]
        data[function + code_rel] ^= 1
        with self.assertRaisesRegex(ValidationError, "original bytes changed"):
            validate_preservation(self.original, repaired(data), DEVICE_URL)

    def test_output_directory_escape_rejected_before_reading_input(self):
        result = subprocess.run([sys.executable, "-B", str(PROJECT / "tools" / "build_unit.py"),
                                 "--gui", "nonexistent", "--host-url", "file:///test/Bootstrap.qml",
                                 "--output-dir", str(PROJECT.parent / "escape")],
                                cwd=PROJECT, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outputs must remain under project build/", result.stderr)

    def test_validations_remain_active_under_python_optimization(self):
        result = subprocess.run([sys.executable, "-B", "-O", "-c",
                                 "from tools.qt_unit import parse_unit; parse_unit(b'bad')"],
                                cwd=PROJECT, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ValidationError", result.stderr)


if __name__ == "__main__":
    unittest.main()
