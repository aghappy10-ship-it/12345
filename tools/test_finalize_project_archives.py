"""Final index/remote verification boundaries, without publishing or networking."""
import unittest
from unittest.mock import patch

import finalize_project_archives as finalize


class FinalIndexTests(unittest.TestCase):
    def setUp(self):
        self.row = {"name": "root.7z.001", "bytes": 10, "sha256": "abc"}
        self.asset = {"name": "root.7z.001", "size": 10, "digest": "sha256:abc", "state": "uploaded"}

    def test_incomplete_transfer_cannot_make_final_index(self):
        with self.assertRaisesRegex(RuntimeError, "not closed"):
            finalize.make_index({"state": "UPLOADING", "roots": {}}, {"assets": []})

    def test_matching_remote_asset_is_accepted(self):
        finalize.verify_assets({"assets": [self.asset]}, [self.row])

    def test_duplicate_remote_names_are_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "duplicate"):
            finalize.verify_assets({"assets": [self.asset, self.asset]}, [self.row])

    def test_final_set_rejects_unindexed_remote_attachment(self):
        extra = {**self.asset, "name": "unindexed-photo.3fr"}
        with self.assertRaisesRegex(RuntimeError, "attachment set"):
            finalize.verify_assets({"assets": [self.asset, extra]}, [self.row], exact=True)

    def test_matching_final_set_is_accepted(self):
        finalize.verify_assets({"assets": [self.asset]}, [self.row], exact=True)

    def test_wait_only_proceeds_after_terminal_transfer_state(self):
        states = [{"state": "UPLOADING", "roots": {}},
                  {"state": "ALL_ASSETS_UPLOADED_DRAFT_AWAITING_FINAL_INDEX", "roots": {}}]
        with patch.object(finalize.transfer, "read_state", side_effect=states), \
                patch.object(finalize.transfer.time, "sleep") as wait:
            finalize.wait_for_upload()
        wait.assert_called_once_with(10)

    def test_wait_aborts_on_failed_transfer(self):
        with patch.object(finalize.transfer, "read_state", return_value={"state": "FAILED_NOT_COMPLETE"}), \
                patch.object(finalize.transfer.time, "sleep") as wait, \
                self.assertRaisesRegex(RuntimeError, "keep the Release draft"):
            finalize.wait_for_upload()
        wait.assert_not_called()

    def test_wrong_remote_length_hash_and_state_are_rejected(self):
        for field, value in (("size", 9), ("digest", "sha256:wrong"), ("state", "starter")):
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, "mismatch"):
                finalize.verify_assets({"assets": [{**self.asset, field: value}]}, [self.row])

    def test_rendered_table_is_contiguous_and_missing_files_are_explicit(self):
        index = {"roots": [{"label": "fixture", "files": 1, "bytes": 20,
                            "volume_count": 1, "assets": [self.row]}]}
        text = finalize.render_index(index)
        self.assertIn("| 压缩字节数 |\n| --- |", text)
        self.assertIn("| fixture | 1 | 20 | 1 | 10 |", text)
        for name in finalize.MISSING:
            self.assertIn(name, text)
        self.assertIn("不是可安装固件", text)


if __name__ == "__main__":
    unittest.main()
