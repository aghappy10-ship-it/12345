"""Exact-candidate payload staging is a host fixture, never an install package."""
import importlib
import json
import os
from pathlib import Path
import subprocess
import struct
import sys
import tempfile
import unittest
from copy import deepcopy
from unittest import mock

from tools import prepare_peer_install as peer
from tools.output_guard import output_directory


class PayloadStageTests(unittest.TestCase):
    def setUp(self):
        output_directory(peer.ROOT / "build")
        self.temp = tempfile.TemporaryDirectory(prefix="payload-stage-test-", dir=peer.ROOT / "build")
        self.root = Path(self.temp.name)
        self.manifest = peer.prepare(self.root / "unqualified")
        self.saved = self.root / "saved-unqualified.json"
        self.saved.write_bytes(peer.canonical(self.manifest))
        self.saved_sha = peer.sha(self.saved.read_bytes())
        self.sources = self.root / "sources"
        for source in [*(f["source"] for f in self.manifest["candidate"]["files"]),
                       self.manifest["candidate"]["rc"]["source"],
                       "build/units/main-screen-bootstrap-host.bin", "build/units/main-screen-bootstrap-device.bin"]:
            target = self.sources / source
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((peer.ROOT / source).read_bytes())

    def tearDown(self):
        self.temp.cleanup()

    def checker(self):
        return importlib.import_module("tools.check_payload_stage")

    def save(self, manifest):
        self.saved.write_bytes(peer.canonical(manifest))
        self.saved_sha = peer.sha(self.saved.read_bytes())

    def make_stage(self):
        destination = self.root / "checked"
        self.checker().prepare_stage(self.saved, self.saved_sha, destination, source_root=self.sources)
        return destination

    def test_public_stage_reads_back_exact_candidate_and_remains_local_only(self):
        checker = self.checker()
        destination = self.root / "checked"
        report = checker.prepare_stage(self.saved, self.saved_sha, destination, source_root=self.sources)
        self.assertEqual(report["status"], "LOCAL_PAYLOAD_ROUNDTRIP_PASS")
        self.assertFalse(report["installable"])
        self.assertFalse(report["package_created"])
        self.assertEqual(report["package_integrity_and_roundtrip"], "PENDING")
        self.assertEqual(report["source_hashes_before"], report["source_hashes_after"])
        self.assertEqual(report["candidate_sha256"], self.manifest["candidate_sha256"])
        payloads = destination / "payloads"
        self.assertEqual({p.name for p in payloads.iterdir()},
                         {"libx2dii_menu.so", "X2d2MenuBootstrap.qml", "X2d2MenuModel.qml",
                          "X2d2MenuPage.qml", "camera-gui.rc.proposed"})
        for entry in self.manifest["candidate"]["files"]:
            self.assertEqual((payloads / Path(entry["source"]).name).read_bytes(), (self.sources / entry["source"]).read_bytes())
        checked = checker.verify_stage(self.saved, self.saved_sha, payloads)
        self.assertEqual(checked["file_count"], 5)
        self.assertTrue(checked["rc_official_roundtrip"])
        self.assertTrue(checked["elf_units"]["stock_unit"]["matches_pinned_original"])
        self.assertTrue(checked["elf_units"]["extended_unit"]["matches_deterministic_device"])
        self.assertFalse(list(destination.rglob("*.sh")))
        self.assertEqual(json.loads((destination / "payload-stage.json").read_text()), report)

    def test_saved_hash_candidate_digest_and_fixed_source_target_allowlist_refused_before_output(self):
        checker = self.checker()
        for case in ("retained_hash", "candidate_hash", "source", "target", "duplicate", "rc_source", "gui", "qualified"):
            changed = deepcopy(self.manifest)
            if case == "source": changed["candidate"]["files"][0]["source"] = "../outside/libx2dii_menu.so"
            elif case == "target": changed["candidate"]["files"][0]["target"] = "/system/bin/camera-gui"
            elif case == "duplicate": changed["candidate"]["files"][1] = deepcopy(changed["candidate"]["files"][0])
            elif case == "rc_source": changed["candidate"]["rc"]["source"] = "qml/camera-gui.rc.proposed"
            elif case == "gui": changed["candidate"]["gui_sha256"] = "0" * 64
            elif case == "qualified": changed["status"] = "QUALIFIED_SCRIPT_SOURCE_NOT_EXECUTED"
            changed["candidate_sha256"] = peer.sha(peer.canonical(changed["candidate"]))
            if case == "candidate_hash": changed["candidate_sha256"] = "0" * 64
            self.save(changed)
            retained = "0" * 64 if case == "retained_hash" else self.saved_sha
            destination = self.root / case
            with self.subTest(case=case), self.assertRaises(ValueError):
                checker.prepare_stage(self.saved, retained, destination, source_root=self.sources)
            self.assertFalse(destination.exists())

    def test_source_hash_size_or_missing_input_refused_without_touching_destination(self):
        checker = self.checker()
        relative = self.manifest["candidate"]["files"][0]["source"]
        path = self.sources / relative
        original = path.read_bytes()
        for case in ("changed", "missing", "hardlink"):
            if case == "changed": path.write_bytes(original + b"changed")
            elif case == "missing": path.unlink()
            else: os.link(path, self.root / "shared-source")
            with self.subTest(case=case), self.assertRaises((ValueError, FileNotFoundError)):
                checker.prepare_stage(self.saved, self.saved_sha, self.root / case, source_root=self.sources)
            self.assertFalse((self.root / case).exists())
            if case == "hardlink": (self.root / "shared-source").unlink()
            else: path.write_bytes(original)

    def test_independent_elf_symbol_extraction_rejects_self_consistent_corrupted_units(self):
        checker = self.checker()
        path = self.sources / "build/native/libx2dii_menu.so"
        original = path.read_bytes()
        units = checker.extract_elf_units(original)
        for name in ("stock_unit", "extended_unit"):
            raw = bytearray(original)
            raw[units[name]["offset"] + 200] ^= 1
            path.write_bytes(raw)
            changed = deepcopy(self.manifest)
            changed["candidate"]["files"][0]["sha256"] = peer.sha(raw)
            changed["candidate_sha256"] = peer.sha(peer.canonical(changed["candidate"]))
            self.save(changed)
            with self.subTest(unit=name), self.assertRaises(ValueError):
                checker.prepare_stage(self.saved, self.saved_sha, self.root / name, source_root=self.sources)
            self.assertFalse((self.root / name).exists())

    def test_self_consistent_changed_rc_cannot_pass_official_roundtrip(self):
        checker = self.checker()
        path = self.sources / self.manifest["candidate"]["rc"]["source"]
        raw = path.read_bytes() + b"# additional unapproved content\n"
        path.write_bytes(raw)
        changed = deepcopy(self.manifest)
        changed["candidate"]["rc"]["after"] = peer.sha(raw)
        changed["candidate_sha256"] = peer.sha(peer.canonical(changed["candidate"]))
        self.save(changed)
        with self.assertRaisesRegex(ValueError, "unknown candidate"):
            checker.prepare_stage(self.saved, self.saved_sha, self.root / "bad-rc", source_root=self.sources)
        self.assertFalse((self.root / "bad-rc").exists())

    def test_readback_refuses_extra_missing_wrong_bytes_nonregular_and_hardlinks(self):
        checker = self.checker()
        payloads = self.make_stage() / "payloads"
        target = payloads / "X2d2MenuPage.qml"
        original = target.read_bytes()
        for case in ("extra", "missing", "changed", "directory", "hardlink"):
            extra = payloads / "unexpected"
            alias = self.root / "alias"
            if case == "extra": extra.write_bytes(b"not a candidate member")
            elif case == "missing": target.unlink()
            elif case == "changed": target.write_bytes(original + b"changed")
            elif case == "directory": target.unlink(); target.mkdir()
            else: os.link(target, alias)
            with self.subTest(case=case), self.assertRaises(ValueError):
                checker.verify_stage(self.saved, self.saved_sha, payloads)
            if case == "extra": extra.unlink()
            elif case == "hardlink": alias.unlink()
            else:
                if target.is_dir(): target.rmdir()
                target.write_bytes(original)

    def test_existing_destination_is_preserved_and_verified_stage_ignores_source_changes(self):
        checker = self.checker()
        destination = self.make_stage()
        before = (destination / "payload-stage.json").read_bytes()
        with self.assertRaisesRegex(ValueError, "already exists"):
            checker.prepare_stage(self.saved, self.saved_sha, destination, source_root=self.sources)
        self.assertEqual((destination / "payload-stage.json").read_bytes(), before)
        for entry in self.manifest["candidate"]["files"]:
            (self.sources / entry["source"]).unlink()
        self.assertEqual(checker.verify_stage(self.saved, self.saved_sha, destination / "payloads")["file_count"], 5)

    def test_source_changes_during_stage_keep_failure_evidence_without_pass_report(self):
        checker = self.checker()
        destination = self.root / "changed-during-stage"
        source = self.sources / "qml/X2d2MenuPage.qml"
        original_write = checker.write_output
        def write_then_change(path, raw, *args, **kwargs):
            result = original_write(path, raw, *args, **kwargs)
            if Path(path).name == "camera-gui.rc.proposed":
                source.write_bytes(source.read_bytes() + b"\n// changed while staging")
            return result
        with mock.patch.object(checker, "write_output", side_effect=write_then_change):
            with self.assertRaisesRegex(ValueError, "changed during"):
                checker.prepare_stage(self.saved, self.saved_sha, destination, source_root=self.sources)
        self.assertFalse((destination / "payload-stage.json").exists())
        failure = json.loads((destination / "payload-stage-failure.json").read_text())
        self.assertEqual(failure["status"], "LOCAL_PAYLOAD_ROUNDTRIP_FAIL")
        self.assertFalse(failure["installable"])
        self.assertEqual(failure["package_integrity_and_roundtrip"], "PENDING")
        self.assertIn("source_hashes_after", failure)
        self.assertNotEqual(failure["source_hashes_before"]["qml/X2d2MenuPage.qml"],
                            failure["source_hashes_after"]["qml/X2d2MenuPage.qml"])

    def test_readback_junction_is_refused_without_touching_its_target(self):
        checker = self.checker()
        destination = self.make_stage()
        payloads = destination / "payloads"
        preserved = destination / "preserved-payloads"
        payloads.rename(preserved)
        if os.name == "nt":
            result = subprocess.run(["cmd", "/c", "mklink", "/J", str(payloads), str(preserved)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            payloads.symlink_to(preserved, target_is_directory=True)
        try:
            with self.assertRaisesRegex(ValueError, "reparse|junction|symlink"):
                checker.verify_stage(self.saved, self.saved_sha, payloads)
            self.assertEqual(len(list(preserved.iterdir())), 5)
        finally:
            if os.name == "nt": os.rmdir(payloads)
            else: payloads.unlink()

    def test_cli_and_optimized_python_preserve_local_only_contract(self):
        destination = self.root / "cli"
        result = subprocess.run([sys.executable, "-B", "-O", "-m", "tools.check_payload_stage", "--saved-manifest", str(self.saved),
                                 "--saved-manifest-sha256", self.saved_sha, "--output", str(destination)],
                                cwd=peer.ROOT, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads(result.stdout)["installable"])
        self.assertTrue((destination / "payload-stage.json").is_file())
        refused = self.root / "optimized-refusal"
        result = subprocess.run([sys.executable, "-B", "-O", "-m", "tools.check_payload_stage", "--saved-manifest", str(self.saved),
                                 "--saved-manifest-sha256", "0" * 64, "--output", str(refused)],
                                cwd=peer.ROOT, capture_output=True, text=True, timeout=60)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(refused.exists())

    def test_elf_symbol_ranges_reject_duplicate_undefined_reverse_and_non_file_backed(self):
        import io
        from elftools.elf.elffile import ELFFile
        checker = self.checker()
        raw = (self.sources / "build/native/libx2dii_menu.so").read_bytes()
        elf = ELFFile(io.BytesIO(raw))
        symtab = elf.get_section_by_name(".symtab")
        table = {s.name: (index, s) for index, s in enumerate(symtab.iter_symbols()) if s.name}
        start_index, start = table["stock_unit"]
        end_index, _ = table["stock_unit_end"]
        start_offset = symtab["sh_offset"] + start_index * symtab["sh_entsize"]
        end_offset = symtab["sh_offset"] + end_index * symtab["sh_entsize"]
        for case in ("duplicate", "undefined", "reverse", "not_file_backed"):
            corrupt = bytearray(raw)
            if case == "duplicate":
                corrupt[end_offset:end_offset + 4] = raw[start_offset:start_offset + 4]
            elif case == "undefined":
                struct.pack_into("<H", corrupt, end_offset + 6, 0)
            elif case == "reverse":
                struct.pack_into("<Q", corrupt, end_offset + 8, start["st_value"] - 1)
            else:
                struct.pack_into("<Q", corrupt, end_offset + 8, start["st_value"] + 900000)
            with self.subTest(case=case), self.assertRaises(ValueError):
                checker.extract_elf_units(corrupt)

    def test_verified_stage_feeds_existing_filesystem_only_install_restore_harness(self):
        # Import the module only inside this test: no imported TestCase class is
        # exposed to discovery and none of the legacy test suite is rerun here.
        legacy = importlib.import_module("tests.test_peer_install")
        payloads = self.make_stage() / "payloads"
        legacy.PeerInstallTests.setUpClass()
        fixture = legacy.PeerInstallTests()
        fixture.setUp()
        try:
            self.assertEqual(fixture.manifest["candidate_sha256"], self.manifest["candidate_sha256"])
            source = fixture.shell_fixture()
            for path in payloads.iterdir():
                (source / path.name).write_bytes(path.read_bytes())
            result = fixture.run_script("install-files.sh")
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            for entry in self.manifest["candidate"]["files"]:
                self.assertEqual((fixture.root / entry["target"].lstrip("/")).read_bytes(),
                                 (payloads / Path(entry["source"]).name).read_bytes())
            result = fixture.run_script("activate-boot.sh")
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual((fixture.root / "system/etc/init/camera-gui.rc").read_bytes(),
                             (payloads / "camera-gui.rc.proposed").read_bytes())
            result = fixture.run_script("restore-boot.sh")
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual((fixture.root / "system/etc/init/camera-gui.rc").read_bytes(), peer.boot.STOCK.read_bytes())
            self.assertTrue(all(not (fixture.root / entry["target"].lstrip("/")).exists()
                                for entry in self.manifest["candidate"]["files"]))
        finally:
            fixture.tearDown()

    def test_partial_staging_write_failure_preserves_inputs_and_cannot_leave_pass(self):
        checker = self.checker()
        destination = self.root / "partial-write"
        original_write = checker.write_output
        def fail_later_member(path, raw, *args, **kwargs):
            if Path(path).name == "X2d2MenuModel.qml":
                raise OSError("injected staging write failure")
            return original_write(path, raw, *args, **kwargs)
        with mock.patch.object(checker, "write_output", side_effect=fail_later_member):
            with self.assertRaisesRegex(OSError, "injected staging"):
                checker.prepare_stage(self.saved, self.saved_sha, destination, source_root=self.sources)
        self.assertFalse((destination / "payload-stage.json").exists())
        self.assertEqual({p.name for p in (destination / "payloads").iterdir()},
                         {"libx2dii_menu.so", "X2d2MenuBootstrap.qml"})
        failure = json.loads((destination / "payload-stage-failure.json").read_text())
        self.assertEqual(failure["source_hashes_before"], failure["source_hashes_after"])
        self.assertEqual(failure["source_readback_errors"], {})
        with self.assertRaisesRegex(ValueError, "missing"):
            checker.verify_stage(self.saved, self.saved_sha, destination / "payloads")

    def test_report_readback_failure_retracts_only_this_runs_exact_success_report(self):
        checker = self.checker()
        destination = self.root / "report-readback-failed"
        original_write = checker.write_output
        def fail_after_report(path, raw, *args, **kwargs):
            result = original_write(path, raw, *args, **kwargs)
            if Path(path).name == "payload-stage.json":
                raise OSError("injected report readback failure after publication")
            return result
        with mock.patch.object(checker, "write_output", side_effect=fail_after_report):
            with self.assertRaisesRegex(OSError, "injected report"):
                checker.prepare_stage(self.saved, self.saved_sha, destination, source_root=self.sources)
        self.assertFalse((destination / "payload-stage.json").exists(), "selectable PASS survived failed publication")
        failure = json.loads((destination / "payload-stage-failure.json").read_text())
        self.assertEqual(failure["status"], "LOCAL_PAYLOAD_ROUNDTRIP_FAIL")
        self.assertEqual(len(list((destination / "payloads").iterdir())), 5)


if __name__ == "__main__":
    unittest.main()
