"""Execute native ARM64 code; does not replace it with a Python implementation."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools.check_native import (CASES, MARKER_EXISTING_CASES, NONBLOCK, PROJECT, STATUS_EXISTING_CASES, STATUS_FAILURE_CASES,
                                APP, LIB, SCRATCH, STUBS, NativeHarness, Uc, runtime_identity, write_report)
from tools.output_guard import output_directory


class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.harness = NativeHarness()

    def test_actual_runtime_identity_not_distribution_metadata(self):
        identity = runtime_identity()
        self.assertEqual(identity["bindingVersion"], "2.0.1")
        self.assertEqual(identity["nativeVersion"], [2, 0, 33554943])
        self.assertEqual(len(identity["nativeLibrarySha256"]), 64)

    def test_native_padding_pc_is_rejected_before_interpretation(self):
        # Independent ELF/FDE/disassembly evidence for this exact candidate:
        # replace_pointer ends at 0x191f8, before the PLT at 0x19200.
        target = LIB + 0x191F8

        class RedirectedEmulator(Uc):
            def emu_start(self, begin, until, timeout=0, count=0):
                # The public emulator I/O seam supplies harmless mapped code;
                # it must not become executable merely because it is mapped.
                self.mem_write(target, bytes.fromhex("1f2003d5c0035fd6"))
                return super().emu_start(target, until, timeout, count)

        with mock.patch("tools.check_native.Uc", RedirectedEmulator):
            with self.assertRaisesRegex(ValueError,
                    r"execution PC outside verified native code: 0x4000191f8"):
                self.harness.run("success")

    def test_mapped_data_gaps_and_unknown_boundaries_are_not_executable(self):
        # Literal boundaries independently checked in current ELF/FDE and
        # disassembly, not copied from the harness's generated allowlist.
        targets = (APP + 0x40, SCRATCH + 0x1000, LIB + 0x1000,
                   LIB + 0x18C08, LIB + 0x191FC, LIB + 0x19200,
                   LIB + 0x1921C, LIB + 0x192E0, STUBS + 0x20,
                   STUBS + 0x10)  # A callback return without an active callback.
        for target in targets:
            with self.subTest(pc=hex(target)):
                class RedirectedEmulator(Uc):
                    def emu_start(self, begin, until, timeout=0, count=0):
                        self.mem_write(target, bytes.fromhex("1f2003d5c0035fd6"))
                        return super().emu_start(target, until, timeout, count)

                with mock.patch("tools.check_native.Uc", RedirectedEmulator):
                    with self.assertRaisesRegex(ValueError,
                            "execution PC outside verified native code: " + hex(target) + "$"):
                        self.harness.run("success")

    def test_execution_guard_preserves_genuine_scenario_abi_and_fatal_tail(self):
        starts = []

        class ObservedEmulator(Uc):
            def emu_start(self, begin, until, timeout=0, count=0):
                starts.append((begin, until))
                return super().emu_start(begin, until, timeout, count)

        with mock.patch("tools.check_native.Uc", ObservedEmulator):
            result = self.harness.run("success")
            # Genuine compiled install tail after its early RET at 0x18db0
            # reaches the _exit import at 0x18f1c on this failed restoration.
            fatal = self.harness.run("restore_write_fail")
        self.assertEqual(starts, [(0x400018C0C, 0x600000000)] * 2)
        self.assertEqual(result["status"], "MENU_POINTER_READY")
        self.assertEqual(result["memoryWrites"], 1)
        self.assertEqual(result["imageCallbackInvocations"], 2)
        self.assertTrue(result["x18Preserved"])
        self.assertTrue(result["calleeSavedAndStackRestored"])
        self.assertEqual(fatal["status"], "RESTORE_FAILED_EXIT")
        self.assertEqual(fatal["memoryWrites"], 2)
        self.assertEqual(fatal["exitCode"], 78)

    def test_compiled_constructor_all_fault_scenarios(self):
        for case in CASES:
            with self.subTest(case=case):
                result = self.harness.run(case)
                self.assertEqual(result["result"], "PASS")

    def test_every_aot_word_checked_before_any_attempt(self):
        for i in range(126):
            with self.subTest(word=i):
                result = self.harness.run("bad_aot", aot_index=i)
                self.assertEqual(result["memoryWrites"], 0)
                self.assertFalse(result["markerCreated"])
                self.assertEqual(result["status"], "AOT_MISMATCH")

    def test_actual_image_callback_and_layout_rejection(self):
        success = self.harness.run("success")
        rejected = self.harness.run("bad_load_flags")
        self.assertEqual(success["imageCallbackInvocations"], 2)
        self.assertGreater(success["imageInstructions"], rejected["imageInstructions"])
        self.assertGreater(rejected["imageInstructions"], 0)
        self.assertEqual(rejected["memoryWrites"], 0)
        self.assertNotIn("/proc/self/mem", rejected["opens"])

    def test_partial_pointer_and_failed_restore_require_exit(self):
        for case in ("restore_seek_fail", "restore_write_fail", "restore_readback_fail"):
            with self.subTest(case=case):
                result = self.harness.run(case)
                self.assertEqual(result["exitCode"], 78)
                self.assertEqual(result["status"], "RESTORE_FAILED_EXIT")

    def test_fifo_disable_never_reaches_loader_or_pointer_write(self):
        result = self.harness.run("disable_fifo")
        self.assertEqual(result["status"], "DISABLED")
        self.assertEqual(result["imageCallbackInvocations"], 0)
        self.assertEqual(result["memoryWrites"], 0)
        self.assertFalse(result["markerCreated"])
        self.assertEqual(result["openFlags"][0]["flags"] & NONBLOCK, NONBLOCK)
        self.assertIn(3, result["closes"])

    def test_existing_diagnostic_objects_never_open_or_modify_target(self):
        for case in STATUS_EXISTING_CASES:
            with self.subTest(case=case):
                result = self.harness.run(case)
                self.assertEqual(result["memoryWrites"], 1)
                self.assertEqual(result["status"], "")
                self.assertEqual(result["statusWrites"], 0)
                self.assertFalse(result["statusCreated"])
                self.assertTrue(result["existingStatusPreserved"])
                self.assertNotIn(6, result["closes"])

    def test_status_pid_decimal_boundaries_and_invalid_pid_fail_closed(self):
        for pid in (1, 9, 10, 2147483647, 0, -1):
            with self.subTest(pid=pid):
                result = self.harness.run("success", pid=pid)
                self.assertEqual(result["memoryWrites"], 1)
                self.assertEqual(result["statusPath"], "/tmp/x2dii-menu.status-" + str(pid) if pid > 0 else None)
                self.assertEqual(result["statusWrites"], 1 if pid > 0 else 0)

    def test_native_volatile_paths_confined_to_tmp_and_fixed_leaf_names(self):
        result = self.harness.run("success")
        self.assertIn("/tmp/x2dii-menu.attempt", result["opens"])
        self.assertIn("/tmp/x2dii-menu.status-3217", result["opens"])
        self.assertEqual(set(result["opens"]), {"/blackbox/x2dii-menu.disable", "/proc/self/mem",
                                               "/tmp/x2dii-menu.attempt", "/tmp/x2dii-menu.status-3217"})
        self.assertFalse(any(path.startswith("/dev/") for path in result["opens"]))

    def test_untrusted_tmp_marker_precreation_or_permission_denial_never_reaches_memory(self):
        for case in (*MARKER_EXISTING_CASES, "marker_permission"):
            with self.subTest(case=case):
                result = self.harness.run(case)
                self.assertEqual(result["status"], "SKIPPED_RETRY_OR_MARKER_ERROR")
                self.assertEqual(result["memoryWrites"], 0)
                self.assertFalse(result["markerCreated"])
                self.assertNotIn("/proc/self/mem", result["opens"])

    def test_diagnostic_failure_never_suppresses_required_restore_exit(self):
        for fault in (*STATUS_FAILURE_CASES, *STATUS_EXISTING_CASES):
            with self.subTest(fault=fault):
                result = self.harness.run("restore_write_fail", diagnostic_case=fault)
                self.assertEqual(result["exitCode"], 78)
                self.assertEqual(result["memoryWrites"], 2)

    def test_stack_platform_register_and_unwind_coverage(self):
        result = self.harness.run("success")
        self.assertTrue(result["x18Preserved"])
        self.assertTrue(result["calleeSavedAndStackRestored"])
        self.assertLessEqual(result["maxStackBytes"], 1024)
        self.assertEqual(set(self.harness.unwind["coveredFunctions"]),
                         {"install", "image", "status", "replace_pointer"})
        self.assertFalse(self.harness.unwind["runtimeExceptionUnwindTested"])


class NativeReportTests(unittest.TestCase):
    def test_report_roundtrip_and_hardlinked_destination_refused(self):
        output_directory(PROJECT / "build")
        with tempfile.TemporaryDirectory(prefix="native-report-test-", dir=PROJECT / "build") as temporary:
            root = Path(temporary)
            report = {"result": "PASS", "status": "LOCAL_EMULATION_ONLY", "installable": False}
            target = write_report(report, root / "report.json")
            self.assertEqual(json.loads(target.read_text(encoding="utf-8")), report)
            alias = root / "linked-report.json"
            os.link(target, alias)
            before = target.read_bytes()
            with self.assertRaisesRegex(ValueError, "hard-linked"):
                write_report({"unexpected": "overwrite"}, alias)
            self.assertEqual(target.read_bytes(), before)
            self.assertEqual(alias.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
