"""Current-session journal pagination, including real loopback HTTP requests."""
import http.client
import json
import os
from pathlib import Path
import sys
import subprocess
import stat
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from app import Server
from device_bridge import DeviceBridge, MAX_RAW_BYTES
from timeline_history import read_history


SESSION = "0123456789abcdef0123456789abcdef"


def event(identity):
    return {"id": identity, "section": "control", "phase": "capture-control",
            "label": "Observed control log", "deviceTime": "10-08 10:00:00.001",
            "receivedUtc": "2026-10-08T02:00:00Z", "raw": "control activity",
            "rawTruncated": False, "evidencePath": "local evidence",
            "correlation": "uncorrelated", "bootId": "boot-fixture", "inode": 12,
            "logWindowId": 1}


class HistoryFixture:
    def __init__(self, root):
        self.bridge = DeviceBridge(root, root / "data")
        self.folder = self.bridge.root / SESSION
        self.folder.mkdir(parents=True)
        self.bridge._monitor_folder = self.folder
        self.bridge.monitor.update(sessionId=SESSION, historyEventCount=0,
                                   timeline={"eventCount": 0})

    def segment(self, first, last, *, index=None, changes=None):
        value = {"sessionId": SESSION, "events": [event(i) for i in range(first, last + 1)],
                 "captures": [], "gaps": [], "eventCountBefore": first - 1,
                 "eventCountAfter": last}
        if changes:
            value.update(changes)
        path = self.folder / f"{index or first:02d}-events-{first}-{last}.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        self.bridge.monitor["historyEventCount"] = last
        self.bridge.monitor["timeline"]["eventCount"] = last
        return path


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.fixture = HistoryFixture(Path(self.temp.name))
        self.bridge, self.folder = self.fixture.bridge, self.fixture.folder

    def tearDown(self):
        self.bridge.close()
        self.temp.cleanup()

    def test_empty_current_session_is_explicit_and_not_other_session(self):
        value = read_history(self.bridge, SESSION)
        self.assertEqual([], value["events"])
        self.assertEqual(0, value["eventCount"])
        self.assertFalse(value["hasMore"])
        self.assertIsNone(value["nextBefore"])
        self.assertEqual("persisted-session-events", value["historicalScope"])
        with self.assertRaises(ValueError):
            read_history(self.bridge, "fedcba9876543210fedcba9876543210")

    def test_more_than_200_events_in_a_single_segment_are_all_retrievable(self):
        self.fixture.segment(1, 613)
        found, before = [], None
        while True:
            value = read_history(self.bridge, SESSION, before=before, limit=200)
            ids = [row["id"] for row in value["events"]]
            self.assertEqual(sorted(ids), ids)
            self.assertLessEqual(len(ids), 200)
            self.assertEqual(613, value["eventCount"])
            found = ids + found
            if not value["hasMore"]:
                break
            self.assertEqual(min(ids), value["nextBefore"])
            before = value["nextBefore"]
        self.assertEqual(list(range(1, 614)), found)

    def test_numeric_file_order_and_strict_before_across_segments(self):
        self.fixture.segment(1, 20, index=9)
        self.fixture.segment(21, 40, index=100)
        self.fixture.segment(41, 60, index=101)
        value = read_history(self.bridge, SESSION, before=42, limit=3)
        self.assertEqual([39, 40, 41], [row["id"] for row in value["events"]])
        self.assertEqual(39, value["nextBefore"])
        self.assertTrue(value["hasMore"])
        self.assertEqual([], read_history(self.bridge, SESSION, before=1)["events"])
        self.assertEqual([60], [row["id"] for row in
                               read_history(self.bridge, SESSION, before=500, limit=1)["events"]])

    def test_only_selected_segments_are_opened_not_all_journal_bytes(self):
        for index in range(1, 101):
            self.fixture.segment(index, index)
        opened = []
        original = os.open
        def observed(path, flags, *args, **kwargs):
            if str(path).endswith(".json"):
                opened.append(Path(path).name)
            return original(path, flags, *args, **kwargs)
        with patch("timeline_history.os.open", side_effect=observed):
            value = read_history(self.bridge, SESSION, before=5, limit=2)
        self.assertEqual([3, 4], [row["id"] for row in value["events"]])
        self.assertEqual(2, len(opened))

    def test_unpublished_temporary_file_is_ignored(self):
        self.fixture.segment(1, 4)
        (self.folder / "05-events-5-9.json.tmp").write_bytes(b"partial")
        self.assertEqual([1, 2, 3, 4], [row["id"] for row in read_history(self.bridge, SESSION)["events"]])

    def test_committed_snapshot_can_advance_while_older_files_are_read(self):
        self.fixture.segment(1, 4)
        original = os.open
        advanced = []
        def append_when_opening(path, flags, *args, **kwargs):
            if not advanced and str(path).endswith(".json"):
                self.fixture.segment(5, 8)
                advanced.append(True)
            return original(path, flags, *args, **kwargs)
        with patch("timeline_history.os.open", side_effect=append_when_opening):
            first = read_history(self.bridge, SESSION)
        self.assertEqual(4, first["eventCount"])
        self.assertEqual([1, 2, 3, 4], [row["id"] for row in first["events"]])
        self.assertEqual(8, read_history(self.bridge, SESSION)["eventCount"])

    def test_invalid_args_and_server_folder_binding_are_rejected(self):
        for sid in (None, "", "../secret", SESSION.upper(), True):
            with self.subTest(session=sid), self.assertRaises(ValueError):
                read_history(self.bridge, sid)
        for before in (0, -1, True, "2", 1.0, 2 ** 63):
            with self.subTest(before=before), self.assertRaises(ValueError):
                read_history(self.bridge, SESSION, before=before)
        for limit in (0, -1, 201, True, "2", 1.0):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                read_history(self.bridge, SESSION, limit=limit)
        self.bridge._monitor_folder = self.folder.parent / "other"
        with self.assertRaises(ValueError):
            read_history(self.bridge, SESSION)

    def test_schema_corruption_does_not_become_no_records(self):
        cases = ({"sessionId": "wrong"}, {"events": []}, {"eventCountBefore": 2},
                 {"eventCountAfter": 5}, {"captures": {}}, {"gaps": "bad"},
                 {"events": [event(2), event(1), event(3)]},
                 {"events": [event(1), event(1), event(3)]},
                 {"events": [event(1), {**event(2), "id": True}, event(3)]},
                 {"events": [event(1), {**event(2), "section": "unknown"}, event(3)]},
                 {"events": [event(1), {**event(2), "section": []}, event(3)]},
                 {"events": [event(1), {**event(2), "inode": 2 ** 63}, event(3)]},
                 {"events": [event(1), {"id": 2}, event(3)]})
        for changes in cases:
            with self.subTest(changes=changes):
                path = self.fixture.segment(1, 3, changes=changes)
                with self.assertRaisesRegex(ValueError, "history|历史"):
                    read_history(self.bridge, SESSION)
                path.unlink()
        path = self.fixture.segment(1, 3)
        path.write_bytes(b"not-json")
        with self.assertRaises(ValueError):
            read_history(self.bridge, SESSION)

    def test_duplicate_json_keys_and_nonfinite_numbers_are_rejected(self):
        path = self.fixture.segment(1, 1)
        raw = path.read_text(encoding="utf-8")
        for corrupt in (raw.replace('"sessionId":', f'"sessionId": "{SESSION}", "sessionId":', 1),
                        raw.replace('"inode": 12', '"inode": NaN')):
            path.write_text(corrupt, encoding="utf-8")
            with self.assertRaises(ValueError):
                read_history(self.bridge, SESSION)

    def test_file_ranges_and_committed_count_must_be_contiguous(self):
        self.fixture.segment(1, 2)
        path = self.fixture.segment(4, 5)
        with self.assertRaises(ValueError):
            read_history(self.bridge, SESSION)
        path.unlink()
        self.fixture.segment(3, 5)
        self.bridge.monitor["historyEventCount"] = 6
        with self.assertRaises(ValueError):
            read_history(self.bridge, SESSION)

    def test_malformed_duplicate_and_out_of_order_names_fail_explicitly(self):
        original = self.fixture.segment(1, 3)
        for filename in ("11-events-bad.json", "04-events-1-3.json", "00-events-4-5.json"):
            with self.subTest(filename=filename):
                bad = self.folder / filename
                bad.write_bytes(original.read_bytes())
                with self.assertRaises(ValueError):
                    read_history(self.bridge, SESSION)
                bad.unlink()

    def test_hardlinks_directories_and_oversized_files_are_rejected(self):
        path = self.fixture.segment(1, 1)
        sibling = self.folder / "link-source.json"
        os.link(path, sibling)
        with self.assertRaises(ValueError):
            read_history(self.bridge, SESSION)
        sibling.unlink()
        path.unlink()
        path.mkdir()
        with self.assertRaises(ValueError):
            read_history(self.bridge, SESSION)
        path.rmdir()
        path.write_bytes(b" " * (MAX_RAW_BYTES + 1))
        with self.assertRaises(ValueError):
            read_history(self.bridge, SESSION)

    def test_symlink_file_and_directory_are_rejected(self):
        path = self.fixture.segment(1, 1)
        if os.name == "nt":
            # Windows file-symlink creation needs a privilege unavailable in
            # this fixture. Exercise its lstat branch directly; the separate
            # junction test executes the real Windows reparse-path boundary.
            original = Path.lstat
            def symlink_metadata(candidate):
                if candidate == path:
                    return SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_file_attributes=0)
                return original(candidate)
            with patch.object(Path, "lstat", symlink_metadata), patch("timeline_history.os.open") as opened:
                with self.assertRaises(ValueError):
                    read_history(self.bridge, SESSION)
                opened.assert_not_called()
            return
        outside = self.folder.parent / "outside.json"
        outside.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(outside)
        with self.assertRaises(ValueError):
            read_history(self.bridge, SESSION)
        path.unlink()
        self.folder.rmdir()
        other = self.folder.parent / "other-folder"
        other.mkdir()
        self.folder.symlink_to(other, target_is_directory=True)
        with self.assertRaises(ValueError):
            read_history(self.bridge, SESSION)

    def test_file_replaced_after_guard_is_rejected_before_bytes_are_read(self):
        path = self.fixture.segment(1, 1)
        original = os.open
        replacement = path.with_suffix(".replacement")
        replacement.write_bytes(b"private data must never be returned")
        def replace_before_open(name, flags, *args, **kwargs):
            if Path(name) == path:
                os.replace(replacement, path)
            return original(name, flags, *args, **kwargs)
        with patch("timeline_history.os.open", side_effect=replace_before_open), self.assertRaises(ValueError):
            read_history(self.bridge, SESSION)

    @unittest.skipUnless(os.name == "nt", "Windows junction check")
    def test_actual_windows_directory_junction_is_rejected(self):
        self.folder.rmdir()
        other = self.folder.parent / "junction-target"
        other.mkdir()
        result = subprocess.run(["cmd", "/c", "mklink", "/J", str(self.folder), str(other)],
                                capture_output=True, timeout=5)
        self.assertEqual(0, result.returncode, result.stderr.decode(errors="replace"))
        try:
            with self.assertRaises(ValueError):
                read_history(self.bridge, SESSION)
            self.assertTrue(other.is_dir())
        finally:
            # Only remove this test's known junction itself, never its target.
            os.rmdir(self.folder)

    def test_actual_parser_event_capture_and_gap_schema_roundtrip(self):
        from camera_timeline import CaptureTimeline
        parser = CaptureTimeline()
        parser.ingest("", boot_id="boot-fixture", inode=12, size=0,
                      received_utc="2026-10-08T02:00:00Z", evidence_path="evidence", baseline=True)
        row = "10-08 10:00:00.001  100 200 I camera-service: SHOOTER-still: _x2dss_shoot(1), start_expo: [true] request_id=shot-1\n"
        delta = parser.ingest(row, boot_id="boot-fixture", inode=12, size=len(row),
                              received_utc="2026-10-08T02:00:00Z", evidence_path="evidence")
        parser.gap("rotated", received_utc="2026-10-08T02:00:01Z", evidence_path="evidence",
                   boot_id="boot-fixture", inode=12, size=0)
        self.fixture.segment(1, 1, changes={"events": delta["addedEvents"],
                             "captures": delta["addedCaptures"], "gaps": parser.snapshot()["gaps"]})
        value = read_history(self.bridge, SESSION)
        self.assertEqual(1, len(value["events"]))
        self.assertEqual("capture-request", value["events"][0]["phase"])
        self.assertEqual("shot-1", value["events"][0]["requestId"])

    def test_capture_and_gap_corruption_is_explicit(self):
        self.fixture.segment(1, 1, changes={"captures": [{"id": 1}], "gaps": []})
        with self.assertRaises(ValueError):
            read_history(self.bridge, SESSION)
        self.fixture.segment(1, 1, changes={"captures": [], "gaps": [{"reason": "changed"}]})
        with self.assertRaises(ValueError):
            read_history(self.bridge, SESSION)

    def test_evidence_ranges_are_bounded_and_ordered(self):
        good = [{"evidencePath": "range-a", "offset": 10, "bytes": 5},
                {"evidencePath": "range-b", "offset": 15, "bytes": 8}]
        self.fixture.segment(1, 1, changes={"events": [{**event(1), "evidenceRanges": good}]})
        self.assertEqual(good, read_history(self.bridge, SESSION)["events"][0]["evidenceRanges"])
        for ranges in ({}, [{"evidencePath": "range", "offset": -1, "bytes": 2}],
                       [{"evidencePath": "range", "offset": 10, "bytes": True}],
                       [{"evidencePath": "range", "offset": i, "bytes": 1} for i in range(129)],
                       [{"evidencePath": "range", "offset": 0, "bytes": 65536},
                        {"evidencePath": "range", "offset": 65536, "bytes": 2}],
                       [good[0], {**good[1], "offset": 14}]):
            self.fixture.segment(1, 1, changes={"events": [{**event(1), "evidenceRanges": ranges}]})
            with self.subTest(ranges=ranges), self.assertRaises(ValueError):
                read_history(self.bridge, SESSION)


class HistoryHttpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.fixture = HistoryFixture(Path(self.temp.name))
        fixture = self.fixture
        class LocalApp:
            token = "local-session-token"
            def __init__(self):
                self.device_bridge = fixture.bridge
                self.device_bridge.history = lambda session_id, before=None, limit=200: read_history(
                    self.device_bridge, session_id, before=before, limit=limit)
            def close(self):
                self.device_bridge.close()
        self.app = LocalApp()
        self.server = Server(("127.0.0.1", 0), self.app)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)
        self.temp.cleanup()

    def request(self, query, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        connection.request("GET", "/api/device/history?" + query, headers=headers or {})
        response = connection.getresponse()
        value = json.loads(response.read())
        connection.close()
        return response.status, value

    def test_authenticated_actual_http_pagination(self):
        self.fixture.segment(1, 421)
        headers = {"X-Session-Token": self.app.token}
        code, page = self.request(f"sessionId={SESSION}&before=222&limit=5", headers)
        self.assertEqual(200, code)
        self.assertEqual([217, 218, 219, 220, 221], [row["id"] for row in page["events"]])
        self.assertEqual(217, page["nextBefore"])
        self.assertEqual(421, page["eventCount"])

    def test_actual_collector_600_event_single_chunk_persisted_http_roundtrip(self):
        from device_bridge import PROJECT
        from test_incremental_log import IncrementalReader
        from test_device_bridge import BASE_LINE, SHOT_LINE
        reader = IncrementalReader(BASE_LINE.encode(), [SHOT_LINE.encode() * 600])
        collector = DeviceBridge(PROJECT, Path(self.temp.name) / "collector-data", reader_factory=lambda: reader)
        self.app.device_bridge.close()
        self.app.device_bridge = collector
        reader.stop_after = collector.monitor_stop.set
        with patch("device_bridge.MONITOR_INTERVAL_SECONDS", .001):
            collector.start("monitor-start", {})
            collector.thread.join(5)
        self.assertFalse(collector.thread.is_alive())
        state = collector.status()
        self.assertEqual("completed", state["current"]["state"], state["current"].get("error"))
        self.assertTrue(state["testFixtureOnly"])
        self.assertFalse(state["current"]["cameraWritten"])
        self.assertEqual(600, state["monitor"]["historyEventCount"])
        self.assertEqual(200, len(state["monitor"]["timeline"]["events"]))
        segments = list(Path(state["monitor"]["evidencePath"]).glob("*-events-*.json"))
        self.assertEqual(3, len(segments))
        journal = json.loads(segments[0].read_bytes())
        self.assertEqual(200, len(journal["events"]))
        self.assertEqual(200, len(journal["captures"]))
        self.assertNotIn("gaps", journal)
        self.assertTrue(journal["events"][0]["evidenceRanges"])
        session_id = state["monitor"]["sessionId"]
        headers = {"X-Session-Token": self.app.token}
        found, before = [], None
        for _ in range(4):
            query = f"sessionId={session_id}&limit=200" + (f"&before={before}" if before is not None else "")
            code, value = self.request(query, headers)
            self.assertEqual(200, code, value)
            self.assertEqual(600, value["eventCount"])
            found = [row["id"] for row in value["events"]] + found
            before = value["nextBefore"]
            if not value["hasMore"]:
                break
        self.assertEqual(list(range(1, 601)), found)
        self.assertIsNone(before)

    def test_get_requires_session_token_host_and_same_origin(self):
        query = f"sessionId={SESSION}"
        self.assertEqual(403, self.request(query)[0])
        self.assertEqual(403, self.request(query, {"X-Session-Token": "wrong"})[0])
        valid = {"X-Session-Token": self.app.token}
        self.assertEqual(403, self.request(query, {**valid, "Origin": "http://evil.example"})[0])
        self.assertEqual(403, self.request(query, {**valid, "Host": "evil.example"})[0])
        self.assertEqual(200, self.request(query, valid)[0])

    def test_malformed_unknown_duplicate_and_path_args_are_rejected(self):
        headers = {"X-Session-Token": self.app.token}
        for query in ("", "sessionId=", "sessionId=../outside", f"sessionId={SESSION}&limit=0",
                      f"sessionId={SESSION}&limit=201", f"sessionId={SESSION}&before=0",
                      f"sessionId={SESSION}&before=-1", f"sessionId={SESSION}&limit=1.5",
                      f"sessionId={SESSION}&limit=+2", f"sessionId={SESSION}&limit=2&limit=3",
                      f"sessionId={SESSION}&sessionId={SESSION}", f"sessionId={SESSION}&before=",
                      f"sessionId={SESSION}&path=anything", f"sessionId={SESSION}&command=id"):
            with self.subTest(query=query):
                code, value = self.request(query, headers)
                self.assertEqual(400, code)
                self.assertIn("error", value)

    def test_corruption_and_cross_session_never_return_empty_success(self):
        path = self.fixture.segment(1, 2)
        path.write_bytes(b"bad-json")
        headers = {"X-Session-Token": self.app.token}
        self.assertEqual(400, self.request(f"sessionId={SESSION}", headers)[0])
        self.assertEqual(400, self.request("sessionId=fedcba9876543210fedcba9876543210", headers)[0])


if __name__ == "__main__":
    unittest.main()
