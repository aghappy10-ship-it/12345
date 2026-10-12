"""Focused transfer regressions; synthetic files, no network or camera access."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import upload_project_archives as upload


class TransferIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.label = "fixture"
        self.override = patch.object(upload, "ARCHIVES", self.root)
        self.override.start()
        self.addCleanup(self.override.stop)
        for suffix in ("source-before.ndjson", "source-after.ndjson"):
            (self.root / f"fixture.{suffix}").write_bytes(b'{"path":"a","bytes":3}\n')
        volume = self.root / "fixture.7z.001"
        volume.write_bytes(b"abc")
        inventory_sha = upload.digest(self.root / "fixture.source-before.ndjson")
        self.state = {
            "state": "VERIFIED_LOCAL_NOT_UPLOADED",
            "archive_exit_code": 0, "archive_test_exit_code": 0,
            "source_before": {"sha256": inventory_sha, "files": 1, "bytes": 3},
            "source_after": {"sha256": inventory_sha, "files": 1, "bytes": 3},
            "volumes": [{"name": volume.name, "bytes": 3, "sha256": upload.digest(volume)}],
        }
        self.write_state()
        self.log = self.root / "fixture.archive-test.log"
        self.log.write_text("Volumes = 1\nEverything is Ok\nSize: 3\n", encoding="utf-8")

    def write_state(self):
        (self.root / "fixture.state.json").write_text(json.dumps(self.state), encoding="utf-8")

    def test_complete_family_is_accepted(self):
        self.assertEqual(len(upload.local_files(self.label, self.state)), 4)

    def test_unrecorded_tail_volume_is_rejected(self):
        (self.root / "fixture.7z.002").write_bytes(b"tail")
        with self.assertRaisesRegex(RuntimeError, "volume"):
            upload.local_files(self.label, self.state)

    def test_extra_temporary_volume_is_rejected(self):
        (self.root / "fixture.7z.001.tmp").write_bytes(b"incomplete")
        with self.assertRaisesRegex(RuntimeError, "volume"):
            upload.local_files(self.label, self.state)

    def test_test_log_volume_count_must_match(self):
        self.log.write_text("Volumes = 2\nEverything is Ok\nSize: 3\n", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "volume"):
            upload.local_files(self.label, self.state)

    def test_inventory_replacement_is_rejected(self):
        (self.root / "fixture.source-after.ndjson").write_bytes(b"replaced")
        with self.assertRaisesRegex(RuntimeError, "inventory"):
            upload.local_files(self.label, self.state)

    def test_declared_exclusion_must_be_absent_from_inventory(self):
        self.state["excluded_relative_paths"] = ["a"]
        self.write_state()
        with self.assertRaisesRegex(RuntimeError, "Excluded path"):
            upload.local_files(self.label, self.state)

    def test_transient_partial_state_is_reread(self):
        with patch.object(Path, "read_text", side_effect=["{", json.dumps(self.state)]), \
                patch.object(upload.time, "sleep") as wait:
            self.assertEqual(upload.read_state(self.root / "fixture.state.json"), self.state)
        wait.assert_called_once()

    def test_persistent_corrupt_state_is_not_ignored(self):
        with patch.object(Path, "read_text", return_value="{"), \
                patch.object(upload.time, "sleep") as wait:
            with self.assertRaises(json.JSONDecodeError):
                upload.read_state(self.root / "fixture.state.json")
        self.assertEqual(wait.call_count, 9)

    def test_valid_failure_state_is_returned_without_retry(self):
        failed = copy.deepcopy(self.state)
        failed["state"] = "FAILED_LOCAL_NOT_UPLOADED"
        with patch.object(Path, "read_text", return_value=json.dumps(failed)), \
                patch.object(upload.time, "sleep") as wait:
            self.assertEqual(upload.read_state(self.root / "fixture.state.json"), failed)
        wait.assert_not_called()


if __name__ == "__main__":
    unittest.main()
