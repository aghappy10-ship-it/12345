"""Local byte-conversion checks; not camera or transaction qualification."""
import ast
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools import boot_config as boot
from tools.output_guard import output_directory


class BootConfigTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        output_directory(boot.ROOT / "build")
        cls.original = boot.STOCK.read_bytes()
        cls.upstream = boot.REFERENCE.read_bytes()

    def test_exact_official_input_and_minimal_byte_delta(self):
        self.assertEqual(hashlib.sha256(self.original).hexdigest(), boot.STOCK_SHA256)
        candidate = boot.activate(self.original)
        self.assertEqual(candidate, self.original.replace(boot.HEADER, boot.HEADER + boot.ADDITIONS, 1))
        self.assertEqual(len(candidate) - len(self.original), len(boot.ADDITIONS))
        self.assertEqual(candidate.count(b"setenv LD_PRELOAD"), 1)
        self.assertEqual(candidate.count(b"setenv X2DII_MENU_EXTENSION"), 1)

    def test_actual_services_and_triggers_preserved_byte_for_byte(self):
        before = boot.parse_config(self.original)
        after = boot.parse_config(boot.activate(self.original))
        self.assertEqual(len(before), 8)
        self.assertEqual([(x.kind, x.name) for x in before], [(x.kind, x.name) for x in after])
        for stock, proposed in zip(before, after):
            if stock.name == "camera-gui" and stock.kind == "service":
                self.assertEqual(len(proposed.commands), len(stock.commands) + 2)
            else:
                self.assertEqual(stock.raw, proposed.raw)

    def test_exact_round_trip(self):
        candidate = boot.activate(self.original)
        self.assertEqual(boot.deactivate(candidate, self.original), self.original)
        self.assertEqual(boot.activate(boot.deactivate(candidate, self.original)), candidate)

    def test_existing_preload_in_every_service_rejected(self):
        for name in boot.SERVICE_NAMES:
            header = next(s.raw.splitlines(keepends=True)[0] for s in boot.parse_config(self.original)
                          if s.kind == "service" and s.name == name)
            modified = self.original.replace(header, header + b"    setenv LD_PRELOAD /system/lib64/foreign.so\n", 1)
            with self.subTest(service=name), self.assertRaisesRegex(boot.BootConfigError, "existing LD_PRELOAD"):
                boot.activate(modified)

    def test_second_activation_and_existing_extension_rejected(self):
        with self.assertRaisesRegex(boot.BootConfigError, "existing extension"):
            boot.activate(boot.activate(self.original))

    def test_unknown_original_rejected(self):
        for modified in (self.original + b"\n", self.original.replace(b"priority -15", b"priority -14"),
                         self.original.replace(b"--touchtest", b"--other")):
            with self.subTest(hash=boot.sha256(modified)), self.assertRaisesRegex(boot.BootConfigError, "SHA256"):
                boot.activate(modified)

    def test_unknown_candidate_or_rollback_source_rejected(self):
        candidate = boot.activate(self.original)
        for modified in (candidate + b"\n", candidate.replace(b"--sutest", b"--other"), self.original,
                         candidate.replace(b"libx2dii_menu.so", b"other.so")):
            with self.subTest(hash=boot.sha256(modified)), self.assertRaises(boot.BootConfigError):
                boot.deactivate(modified, self.original)
        with self.assertRaises(boot.BootConfigError):
            boot.deactivate(candidate, self.original + b"\n")

    def test_conservative_syntax_rejects_malformed_inputs(self):
        cases = [b"", self.original[:-1], self.original.replace(b"\n", b"\r\n"),
                 b"    start camera-gui\n", b"on property:test\n    start camera-gui\n",
                 b"service camera-gui relative/path\n    disabled\n",
                 b"service camera-gui /system/bin/camera-gui\n    unknown option\n",
                 b"service camera-gui /system/bin/camera-gui\n    setenv KEY\n",
                 self.original.replace(b"user root", b"user root extra", 1),
                 self.original.replace(b"priority -15", b"priority twelve", 1),
                 self.original.replace(b"class core", b"class core\x00", 1),
                 self.original.replace(b"class core", b"class core \\\n next", 1),
                 self.original.replace(b"class core", b"class \xff", 1),
                 self.original + b"service camera-gui /system/bin/camera-gui\n    disabled\n"]
        for ix, data in enumerate(cases):
            with self.subTest(case=ix), self.assertRaises(boot.BootConfigError):
                boot.parse_config(data)

    def test_duplicate_environment_is_invalid(self):
        raw = self.original.replace(b"    setenv XDG_RUNTIME_DIR /tmp\n",
                                    b"    setenv XDG_RUNTIME_DIR /tmp\n    setenv XDG_RUNTIME_DIR /other\n", 1)
        with self.assertRaisesRegex(boot.BootConfigError, "duplicate service environment"):
            boot.parse_config(raw)

    def test_plan_is_unqualified_with_all_live_bindings_missing(self):
        report = boot.plan(self.original, boot.activate(self.original), self.upstream)
        self.assertTrue(report["local_only"])
        for key in ("installable", "installation_authorized", "device_access_performed", "executable_installer_generated"):
            self.assertFalse(report[key])
        self.assertEqual(report["status"], "LOCAL_ONLY_UNQUALIFIED")
        for key in ("native_library_sha256", "package_sha256", "active_camera_slot", "live_components"):
            self.assertIsNone(report["bindings"][key])
        gates = {g["id"]: g for g in report["required_live_gates"]}
        self.assertTrue(all(g["status"] == "PENDING" for g in gates.values()))
        self.assertTrue({"slot_mount_identity", "original_metadata", "volatile_tmpfs_runtime_paths", "root_selinux_loader_and_memory",
                         "independent_disable_and_rollback", "gui_exit_and_unmapped_library"}.issubset(gates))
        serialized = json.dumps(report)
        self.assertNotIn("mmcblk0p17", serialized)
        self.assertNotIn("system_2", serialized)

    def test_volatile_plan_requires_exact_tmpfs_namespace_policy_and_preserves_dev_rejection(self):
        report = boot.plan(self.original, boot.activate(self.original), self.upstream)
        paths = report["path_plan"]
        self.assertEqual(paths["volatile_runtime_directory"], "/tmp")
        self.assertEqual(paths["attempt_marker"], "/tmp/x2dii-menu.attempt")
        self.assertEqual(paths["diagnostic_template"], "/tmp/x2dii-menu.status-<positive-pid>")
        self.assertFalse(paths["volatile_runtime_qualified"])
        self.assertEqual(paths["rejected_previous_volatile_directory"]["path"], "/dev")
        self.assertEqual(paths["rejected_previous_volatile_directory"]["original_gate"], "dev_is_tmpfs")
        self.assertIn("lack create", paths["rejected_previous_volatile_directory"]["reason"])
        gate = next(g for g in report["required_live_gates"] if g["id"] == "volatile_tmpfs_runtime_paths")
        self.assertEqual(gate["status"], "PENDING")
        for condition in ("GUI mount namespace", "root:root mode 1777", "active policy identity",
                          "hbl_camera_service_tmpfs", "every existing inode", "not live-create"):
            self.assertIn(condition, gate["required_evidence"])

    def test_planned_transaction_order_and_recovery_are_explicit_not_implemented(self):
        report = boot.plan(self.original, boot.activate(self.original), self.upstream)
        transaction = report["transaction"]
        self.assertFalse(transaction["implemented"])
        order = [s["id"] for s in transaction["steps"]]
        self.assertEqual(order, ["qualify_and_approve", "attest_and_lock", "backup_official", "stage_all_new_files",
                                 "verify_all_staged_durable", "stop_gui_and_prove_exit", "activate_dependencies",
                                 "commit_rc_last_atomic", "verify_post_commit"])
        self.assertLess(order.index("verify_all_staged_durable"), order.index("activate_dependencies"))
        self.assertLess(order.index("stop_gui_and_prove_exit"), order.index("activate_dependencies"))
        self.assertLess(order.index("activate_dependencies"), order.index("commit_rc_last_atomic"))
        self.assertTrue(transaction["failure_priority"].startswith("Restore the exact official rc atomically"))
        self.assertIn("NOT_RUN", transaction["failure_injection"])
        self.assertNotIn("/etc/init/", report["path_plan"]["backup_template"])
        self.assertNotIn("/etc/init/", report["path_plan"]["staging_template"])

    def test_reference_is_hash_bound_and_never_executed(self):
        with self.assertRaisesRegex(boot.BootConfigError, "reference source SHA256"):
            boot.plan(self.original, boot.activate(self.original), self.upstream + b"\n")
        source = Path(boot.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        imports |= {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        self.assertTrue(imports.issubset({"__future__", "argparse", "difflib", "hashlib", "json", "re", "dataclasses", "pathlib", "output_guard"}))
        calls = {n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        self.assertFalse(calls & {"eval", "exec", "compile"})

    def test_output_is_four_non_executable_files_and_idempotent(self):
        with tempfile.TemporaryDirectory(prefix="boot-config-", dir=boot.ROOT / "build") as tmp:
            root = Path(tmp) / "boot"
            first = boot.write_proposal(self.original, self.upstream, root)
            second = boot.write_proposal(self.original, self.upstream, root)
            self.assertEqual(first, second)
            self.assertEqual({p.name for p in root.iterdir()},
                             {"camera-gui.rc.original", "camera-gui.rc.proposed", "before-after.diff", "boot-plan.json"})
            self.assertEqual((root / "camera-gui.rc.original").read_bytes(), self.original)
            diff = (root / "before-after.diff").read_text()
            added = [line for line in diff.splitlines() if line.startswith("+") and not line.startswith("+++")]
            removed = [line for line in diff.splitlines() if line.startswith("-") and not line.startswith("---")]
            self.assertEqual(added, ["+    setenv X2DII_MENU_EXTENSION 1", "+    setenv LD_PRELOAD /system/lib64/libx2dii_menu.so"])
            self.assertEqual(removed, [])

    def test_modified_local_output_refused_before_any_other_write(self):
        with tempfile.TemporaryDirectory(prefix="boot-config-", dir=boot.ROOT / "build") as tmp:
            root = Path(tmp)
            target = root / "camera-gui.rc.original"
            target.write_bytes(b"preserve user work")
            with self.assertRaisesRegex(boot.BootConfigError, "refusing to overwrite"):
                boot.write_proposal(self.original, self.upstream, root)
            self.assertEqual(target.read_bytes(), b"preserve user work")
            self.assertEqual(list(root.iterdir()), [target])

    def test_redirected_output_root_and_parent_rejected_before_writes(self):
        for nested in (False, True):
            with self.subTest(nested=nested), tempfile.TemporaryDirectory(prefix="boot-redirect-", dir=boot.ROOT / "build") as tmp:
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
                        boot.write_proposal(self.original, self.upstream, destination)
                    self.assertEqual(list(safe.iterdir()), [])
                finally:
                    if os.name == "nt":
                        os.rmdir(link)
                    else:
                        link.unlink()

    def test_hardlinked_original_and_proposed_outputs_rejected(self):
        for name, content in (("camera-gui.rc.original", self.original),
                              ("camera-gui.rc.proposed", boot.activate(self.original))):
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix="boot-hardlink-", dir=boot.ROOT / "build") as tmp:
                base = Path(tmp)
                root = base / "output"
                root.mkdir()
                original = base / "preserved.bin"
                original.write_bytes(content)
                target = root / name
                os.link(original, target)
                try:
                    with self.assertRaisesRegex(ValueError, "hard-linked"):
                        boot.write_proposal(self.original, self.upstream, root)
                    self.assertEqual(original.read_bytes(), content)
                    self.assertEqual(target.read_bytes(), content)
                    self.assertEqual(list(root.iterdir()), [target])
                finally:
                    target.unlink()


if __name__ == "__main__":
    unittest.main()
