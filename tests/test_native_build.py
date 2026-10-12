"""Offline native builder path/publication regressions; never accesses a camera."""
import os
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from tools import build_native as native
from tools.output_guard import output_directory


FINAL_NAMES = native.FINAL_NAMES


class NativeBuildSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.baseline = native.inspect_baseline((native.STOCK_ROOT / "bin/camera-gui").read_bytes())

    def setUp(self):
        output_directory(native.PROJECT / "build")
        self.temp = tempfile.TemporaryDirectory(prefix="native-builder-test-", dir=native.PROJECT / "build")
        self.project = Path(self.temp.name)
        self.output = self.project / "build/native"
        self.output.mkdir(parents=True)
        (self.project / "build/units").mkdir()
        (self.project / "build/units/main-screen-bootstrap-device.bin").write_bytes(
            (native.PROJECT / "build/units/main-screen-bootstrap-device.bin").read_bytes())
        (self.project / "src").mkdir()
        (self.project / "src/menu_preload.c").write_bytes((native.PROJECT / "src/menu_preload.c").read_bytes())
        for name in FINAL_NAMES:
            (self.output / name).write_bytes(("unchanged-before-build:" + name).encode())
        self.before = {name: (self.output / name).read_bytes() for name in FINAL_NAMES}
        self.project_patch = mock.patch.object(native, "PROJECT", self.project)
        self.project_patch.start()
        self.baseline_patch = mock.patch.object(native, "inspect_baseline", return_value=self.baseline)
        self.baseline_patch.start()

    def tearDown(self):
        self.baseline_patch.stop()
        self.project_patch.stop()
        self.temp.cleanup()

    def assert_original_outputs(self):
        self.assertEqual({name: (self.output / name).read_bytes() for name in FINAL_NAMES}, self.before)

    @staticmethod
    def fake_compile(command, **kwargs):
        directory = Path(kwargs["cwd"])
        (directory / command[-1]).write_bytes(b"mock inspected ELF")
        return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

    @staticmethod
    def fake_inspect(raw, exports):
        return {"sha256": native.sha(raw), "bytes": len(raw)}

    def test_late_shared_library_hardlink_rejected_before_earlier_outputs_change(self):
        preserved = self.project / "preserved-library"
        preserved.write_bytes(self.before["libx2dii_menu.so"])
        target = self.output / "libx2dii_menu.so"
        target.unlink()
        os.link(preserved, target)
        with mock.patch.object(native.subprocess, "run") as compiler:
            with self.assertRaisesRegex(ValueError, "hard-linked"):
                native.build()
            compiler.assert_not_called()
        self.assert_original_outputs()
        self.assertEqual(preserved.read_bytes(), self.before["libx2dii_menu.so"])

    def test_parent_junction_rejected_before_any_output_change(self):
        safe = self.project / "junction-target"
        safe.mkdir()
        for name in FINAL_NAMES:
            (safe / name).write_bytes(self.before[name])
        original_output = self.output
        original_output.rename(self.project / "preserved-native")
        if os.name == "nt":
            result = subprocess.run(["cmd", "/c", "mklink", "/J", str(original_output), str(safe)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            original_output.symlink_to(safe, target_is_directory=True)
        try:
            with mock.patch.object(native.subprocess, "run") as compiler:
                with self.assertRaisesRegex(ValueError, "junction|symlink|reparse"):
                    native.build()
                compiler.assert_not_called()
            self.assert_original_outputs()
        finally:
            if os.name == "nt":
                os.rmdir(original_output)
            else:
                original_output.unlink()

    def test_backend_compile_failure_cannot_overwrite_old_outputs(self):
        failure = subprocess.CalledProcessError(2, ["test-compiler"], stderr="injected compile failure")
        with mock.patch.object(native.subprocess, "run", side_effect=failure):
            with self.assertRaises(subprocess.CalledProcessError):
                native.build()
        self.assert_original_outputs()
        stages = list((self.project / "build/native-staging").glob("run-*/build-1"))
        self.assertEqual(len(stages), 1)
        self.assertEqual((stages[0] / "compiler.stderr").read_text(), "injected compile failure")
        self.assertEqual(json.loads((stages[0] / "failure.json").read_text())["returncode"], 2)

    def test_report_hardlink_is_preflighted_before_staging(self):
        preserved = self.project / "preserved-report"
        preserved.write_bytes(self.before["native-build.json"])
        target = self.output / "native-build.json"
        target.unlink()
        os.link(preserved, target)
        with mock.patch.object(native.subprocess, "run") as compiler:
            with self.assertRaisesRegex(ValueError, "hard-linked"):
                native.build()
            compiler.assert_not_called()
        self.assert_original_outputs()
        self.assertFalse((self.project / "build/native-staging").exists())

    def test_directory_in_late_output_is_rejected_before_any_output_change(self):
        target = self.output / "native-build.json"
        target.unlink()
        target.mkdir()
        with mock.patch.object(native.subprocess, "run") as compiler:
            with self.assertRaisesRegex(ValueError, "output file required"):
                native.build()
            compiler.assert_not_called()
        for name in FINAL_NAMES[:-1]:
            self.assertEqual((self.output / name).read_bytes(), self.before[name])
        self.assertFalse((self.project / "build/native-staging").exists())

    def test_independent_builds_stage_only_small_inputs_and_publish_report_last(self):
        with mock.patch.object(native.subprocess, "run", side_effect=self.fake_compile) as compiler, \
                mock.patch.object(native, "inspect_library", side_effect=self.fake_inspect) as inspect, \
                mock.patch.object(native, "write_output", wraps=native.write_output) as writes:
            report = native.build()
        self.assertEqual(compiler.call_count, 2)
        self.assertEqual(inspect.call_count, 2)
        self.assertEqual(compiler.call_args_list[0].args, compiler.call_args_list[1].args)
        directories = [Path(call.kwargs["cwd"]) for call in compiler.call_args_list]
        self.assertNotEqual(*directories)
        cache_paths = []
        for call, directory in zip(compiler.call_args_list, directories):
            self.assertEqual(call.args[0][-1], "libx2dii_menu.so")
            for key in ("ZIG_LOCAL_CACHE_DIR", "ZIG_GLOBAL_CACHE_DIR"):
                cache = Path(call.kwargs["env"][key])
                self.assertEqual(cache.parent, directory)
                cache_paths.append(cache)
            self.assertEqual({p.name for p in directory.iterdir()},
                             set(FINAL_NAMES[:-1]) | {"zig-local", "zig-global", "command.json",
                                                     "compiler.stdout", "compiler.stderr"})
            self.assertTrue(all(p.stat().st_size < 100000 for p in directory.iterdir() if p.is_file()))
        self.assertEqual(len(set(cache_paths)), 4)
        publications = [Path(call.args[0]).name for call in writes.call_args_list
                        if Path(call.args[0]).parent == self.output]
        self.assertEqual(publications, list(FINAL_NAMES))
        self.assertTrue(report["reproducibility"]["exactLibraryBytesEqual"])
        for name, digest in report["artifactHashes"].items():
            self.assertEqual(native.sha((self.output / name).read_bytes()), digest)

    def test_nonidentical_independent_builds_cannot_publish(self):
        runs = 0

        def compile_different(command, **kwargs):
            nonlocal runs
            runs += 1
            (Path(kwargs["cwd"]) / command[-1]).write_bytes(b"mock ELF" + bytes([runs]))
            return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

        with mock.patch.object(native.subprocess, "run", side_effect=compile_different), \
                mock.patch.object(native, "inspect_library", side_effect=self.fake_inspect):
            with self.assertRaisesRegex(ValueError, "independent native builds differ"):
                native.build()
        self.assertEqual(runs, 2)
        self.assert_original_outputs()

    def test_library_inspection_failure_cannot_publish(self):
        with mock.patch.object(native.subprocess, "run", side_effect=self.fake_compile), \
                mock.patch.object(native, "inspect_library", side_effect=ValueError("injected invalid ELF")):
            with self.assertRaisesRegex(ValueError, "injected invalid ELF"):
                native.build()
        self.assert_original_outputs()

    def test_late_hardlink_after_compilation_is_rechecked_before_publication(self):
        runs = 0
        preserved = self.project / "preserved-report"
        preserved.write_bytes(self.before["native-build.json"])

        def compile_then_redirect(command, **kwargs):
            nonlocal runs
            runs += 1
            result = self.fake_compile(command, **kwargs)
            if runs == 2:
                target = self.output / "native-build.json"
                target.unlink()
                os.link(preserved, target)
            return result

        with mock.patch.object(native.subprocess, "run", side_effect=compile_then_redirect), \
                mock.patch.object(native, "inspect_library", side_effect=self.fake_inspect):
            with self.assertRaisesRegex(ValueError, "hard-linked"):
                native.build()
        self.assert_original_outputs()
        self.assertEqual(preserved.read_bytes(), self.before["native-build.json"])

    def test_second_compile_failure_cannot_publish_first_library(self):
        results = [None, subprocess.TimeoutExpired(["test-compiler"], 180, output=b"partial output")]

        def compile_then_timeout(command, **kwargs):
            error = results.pop(0)
            if error is not None:
                raise error
            return self.fake_compile(command, **kwargs)

        with mock.patch.object(native.subprocess, "run", side_effect=compile_then_timeout), \
                mock.patch.object(native, "inspect_library", side_effect=self.fake_inspect):
            with self.assertRaises(subprocess.TimeoutExpired):
                native.build()
        self.assert_original_outputs()
        stages = list((self.project / "build/native-staging").glob("run-*/build-2"))
        self.assertEqual(len(stages), 1)
        self.assertEqual((stages[0] / "compiler.stdout").read_bytes(), b"partial output")
        self.assertEqual(json.loads((stages[0] / "failure.json").read_text())["timeout"], 180)

    def test_late_parent_junction_after_compilation_cannot_publish(self):
        compiler_run = subprocess.run
        runs = 0
        safe = self.project / "junction-target"
        safe.mkdir()
        for name in FINAL_NAMES:
            (safe / name).write_bytes(self.before[name])

        def compile_then_redirect(command, **kwargs):
            nonlocal runs
            runs += 1
            result = self.fake_compile(command, **kwargs)
            if runs == 2:
                self.output.rename(self.project / "preserved-native")
                if os.name == "nt":
                    redirected = compiler_run(["cmd", "/c", "mklink", "/J", str(self.output), str(safe)],
                                              capture_output=True, text=True)
                    self.assertEqual(redirected.returncode, 0, redirected.stdout + redirected.stderr)
                else:
                    self.output.symlink_to(safe, target_is_directory=True)
            return result

        try:
            with mock.patch.object(native.subprocess, "run", side_effect=compile_then_redirect), \
                    mock.patch.object(native, "inspect_library", side_effect=self.fake_inspect):
                with self.assertRaisesRegex(ValueError, "junction|symlink|reparse"):
                    native.build()
            self.assert_original_outputs()
            for name in FINAL_NAMES:
                self.assertEqual((self.project / "preserved-native" / name).read_bytes(), self.before[name])
        finally:
            if runs == 2:
                if os.name == "nt":
                    os.rmdir(self.output)
                else:
                    self.output.unlink()


if __name__ == "__main__":
    unittest.main()
