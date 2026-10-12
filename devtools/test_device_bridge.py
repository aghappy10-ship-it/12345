from dataclasses import replace
import json
from pathlib import Path
import sys
import struct
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import device_bridge as bridge_module
from device_bridge import (BridgeConflict, DeviceBridge, MAX_RAW_BYTES, MAX_TEXT_BYTES,
                           PreparedExecution, PROFILES, PROJECT)

BOOT = "c182e5d2-2e15-4c57-aa15-31d0dc7d9413"
IDENTITY = ("uid=0(root) gid=0(root) groups=0(root) context=u:r:hbl_camera_service:s0\n"
            "u:r:hbl_camera_service:s0Android HB722 on Eagle2 HB722\n10.00.09.77\n" + BOOT + "\n")
NEW_BOOT = "00000000-0000-0000-0000-000000000001"
BASE_LINE = "10-08 12:00:00.000  10  11 I camera-gui: MainMenu ready\n"
SHOT_LINE = "10-08 12:00:01.000  10  11 I camera-service: SHOOTER-still: _x2dss_shoot (1), start_expo: [true]\n"


def log_sample(text, *, boot=BOOT, inode=17, size=None, after_boot=None, after_inode=None, after_size=None):
    size = len(text.encode("utf-8")) if size is None else size
    return (f"{boot}\n{inode} {size}\n" + text + "\n" +
            f"{inode if after_inode is None else after_inode} {size if after_size is None else after_size}\n"
            f"{boot if after_boot is None else after_boot}\n")


class TimelineReader:
    """Device-query boundary fixture, retaining the actual timeline parser."""
    sources = {"testFixtureOnly": True}

    def __init__(self, samples=(), *, identities=None, timeline_wait=None, stop_after=None, timeline_bytes=0):
        self.samples = list(samples)
        self.identities = list(identities or [IDENTITY, IDENTITY])
        self.names, self.sample_index = [], 0
        self.timeline_wait, self.stop_after, self.timeline_bytes = timeline_wait, stop_after, timeline_bytes

    def query(self, name):
        self.names.append(name)
        if name == "identity":
            if not self.identities:
                raise ValueError("unexpected identity query")
            text, rc = self.identities.pop(0), 0
        elif name == "boot":
            text, rc = "fixed boot\n", 0
        elif name == "timeline_log":
            if self.timeline_wait:
                self.timeline_wait[0].set()
                if not self.timeline_wait[1].wait(3):
                    raise TimeoutError("timeline fixture release missing")
            if self.sample_index >= len(self.samples):
                raise ValueError("unexpected extra log query")
            sample = self.samples[self.sample_index]
            self.sample_index += 1
            text, rc = sample if type(sample) is tuple else (sample, 0)
        else:
            raise ValueError("unexpected device query: " + name)
        # A source-change fixture may still owe the bridge its mandatory
        # identity revalidation. Stop only after that fixed reply is available.
        if self.sample_index and self.sample_index == len(self.samples) and not self.identities and self.stop_after:
            self.stop_after()
        raw = b"fixture raw" if name != "timeline_log" or not self.timeline_bytes else b"r" * self.timeline_bytes
        return {"name": name, "shellLastExitCode": rc, "text": text, "packets": raw, "rawReceived": raw}

    def check_unchanged(self):
        pass


class FakeReader:
    sources = {"testFixtureOnly": True}

    def __init__(self, fail=None, wait=None, after=IDENTITY):
        self.names, self.fail, self.wait, self.after = [], fail, wait, after

    def query(self, name):
        self.names.append(name)
        if self.wait:
            self.wait[0].set()
            if not self.wait[1].wait(3):
                raise TimeoutError("test release missing")
        if name == self.fail:
            error = ValueError("fixture receive failure")
            error.raw, error.packets = b"partial raw", b"partial validated"
            raise error
        text = self.after if name == "identity" and len(self.names) > 1 else IDENTITY if name == "identity" else "fixed " + name + "\n"
        return {"name": name, "shellLastExitCode": 0, "text": text, "packets": b"fixture packets", "rawReceived": b"fixture raw"}

    def check_unchanged(self):
        pass


class BridgeCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def bridge(self, reader=None, **kwargs):
        value = DeviceBridge(PROJECT, self.temp.name, reader_factory=lambda: reader or FakeReader(), **kwargs)
        self.addCleanup(value.close)
        return value

    def finish(self, bridge):
        bridge.thread.join(5)
        self.assertFalse(bridge.thread.is_alive(), "fixture worker did not terminate")
        return bridge.status()


class BridgeTests(BridgeCase):
    def test_status_and_construction_do_not_call_reader_or_provider(self):
        reader, provider = Mock(), Mock()
        bridge = DeviceBridge(PROJECT, self.temp.name, reader_factory=reader, execution_provider=provider)
        self.addCleanup(bridge.close)
        self.assertFalse(bridge.status()["connected"])
        self.assertFalse(bridge.status()["monitor"]["active"])
        self.assertEqual("stopped", bridge.status()["monitor"]["state"])
        bridge.status()
        reader.assert_not_called()
        provider.assert_not_called()
        self.assertFalse(Path(self.temp.name, "device-bridge").exists())

    def test_actual_identity_format_connect_and_raw_evidence(self):
        reader, bridge = FakeReader(), self.bridge()
        bridge.reader_factory = lambda: reader
        bridge.connect()
        state = self.finish(bridge)
        self.assertTrue(state["connected"])
        self.assertEqual(["identity", "boot", "identity"], reader.names)
        self.assertEqual("Android HB722 on Eagle2 HB722", state["identity"]["model"])
        self.assertEqual("u:r:hbl_camera_service:s0", state["identity"]["domain"])
        self.assertFalse(state["identity"]["installationPermissionVerified"])
        folder = Path(state["current"]["evidencePath"])
        self.assertEqual(b"fixture raw", (folder / "01-identity.received.bin").read_bytes())
        serialized = json.dumps(state)
        self.assertNotIn('"rawReceived":', serialized)
        self.assertNotIn('"packets":', serialized)
        self.assertNotIn("fixture raw", serialized)
        self.assertEqual(state["current"]["id"], json.loads((folder.parent / "latest.json").read_text())["id"])

    def test_every_component_uses_only_declared_queries_no_photos_or_calibration(self):
        reader, bridge = FakeReader(), self.bridge()
        bridge.reader_factory = lambda: reader
        for component, profile in PROFILES.items():
            reader.names.clear()
            bridge.read(component)
            state = self.finish(bridge)
            self.assertEqual(["identity", *profile["queries"], "identity"], reader.names)
            self.assertLessEqual(len(reader.names), 4)
            saved = state["lastRead"][component]
            self.assertEqual(component, state["latestReadComponent"])
            self.assertEqual(BOOT, saved["identity"]["bootId"])
            self.assertIn("fixed ", saved["text"])
            self.assertFalse(state["current"]["photosRead"])
            self.assertFalse(state["current"]["calibrationRead"])
        from tools import live_readout
        for profile in PROFILES.values():
            for name in profile["queries"]:
                self.assertIsInstance(live_readout.QUERIES[name], str)
                self.assertNotIn("DCIM", live_readout.QUERIES[name])
                self.assertNotIn("/calibration", live_readout.QUERIES[name])

    def test_failure_unknown_not_permission_or_absence_and_preserves_raw(self):
        reader, bridge = FakeReader(fail="boot"), self.bridge()
        bridge.reader_factory = lambda: reader
        bridge.connect()
        state = self.finish(bridge)
        self.assertIsNone(state["connected"])
        self.assertEqual("failed", state["current"]["state"])
        folder = Path(state["current"]["evidencePath"])
        self.assertEqual(b"partial raw", (folder / "02-boot.received.bin").read_bytes())
        self.assertEqual(["identity", "boot"], reader.names)
        self.assertIn("不把传输失败推断为权限拒绝", state["reason"])

    def test_boot_change_is_not_combined_with_prior_identity(self):
        bridge = self.bridge(FakeReader(after=IDENTITY.replace(BOOT, "00000000-0000-0000-0000-000000000001")))
        bridge.read("ui")
        state = self.finish(bridge)
        self.assertIsNone(state["connected"])
        self.assertNotIn("ui", state["lastRead"])
        self.assertIn("跨启动", state["current"]["error"])

    def test_untrusted_body_or_unknown_operations_never_query(self):
        reader, bridge = FakeReader(), self.bridge()
        bridge.reader_factory = lambda: reader
        for name, body in [("exec", {}), ("read", {"component": "photos"}), ("connect", {"approved": True}),
                           ("deploy", {"qualification": {"approved": True}}), ("restore", {"manifest": "path"}),
                           ("read", {"component": "ui", "source": "anything"}), ("connect", {"operation": "read"})]:
            with self.subTest(name=name, body=body), self.assertRaises(ValueError):
                bridge.start(name, body)
        self.assertEqual([], reader.names)

    def test_inflight_lock_and_nonblocking_status(self):
        entered, release = threading.Event(), threading.Event()
        reader, bridge = FakeReader(wait=(entered, release)), self.bridge()
        bridge.reader_factory = lambda: reader
        bridge.connect()
        self.assertTrue(entered.wait(1))
        started = time.monotonic()
        self.assertTrue(bridge.status()["workerActive"])
        self.assertLess(time.monotonic() - started, .5)
        with self.assertRaises(BridgeConflict):
            bridge.read("ui")
        release.set()
        self.finish(bridge)

    def test_close_stops_followup_queries_and_late_shared_publication(self):
        entered, release = threading.Event(), threading.Event()
        reader, bridge = FakeReader(wait=(entered, release)), self.bridge()
        bridge.reader_factory = lambda: reader
        bridge.connect()
        self.assertTrue(entered.wait(1))
        closer = threading.Thread(target=bridge.close)
        closer.start()
        for _ in range(100):
            if bridge.closed:
                break
            time.sleep(.001)
        release.set()
        closer.join(2)
        state = self.finish(bridge)
        self.assertTrue(state["closed"])
        self.assertEqual(["identity"], reader.names)
        self.assertFalse((bridge.root / "latest.json").exists())
        with self.assertRaises(BridgeConflict):
            bridge.connect()

    def test_write_without_server_context_is_blocked_not_completed(self):
        bridge = self.bridge()
        for name in ("deploy", "load", "restore"):
            bridge.start(name, {"operation": name})
            state = self.finish(bridge)
            self.assertEqual("blocked", state["current"]["state"])
            self.assertFalse(state["current"]["cameraWriteAttempted"])
            self.assertFalse(state["capabilities"][name]["enabled"])
            self.assertIn("server_owned_prepared_operation", state["current"]["missing"])

    def test_oversized_text_is_retained_bounded_but_not_accepted(self):
        reader = FakeReader()
        original = reader.query
        reader.query = lambda name: {**original(name), "text": "x" * (MAX_TEXT_BYTES + 1)} if name == "boot" else original(name)
        bridge = self.bridge(reader)
        bridge.connect()
        state = self.finish(bridge)
        self.assertEqual("failed", state["current"]["state"])
        self.assertIsNone(state["connected"])
        folder = Path(state["current"]["evidencePath"])
        self.assertEqual(MAX_TEXT_BYTES, (folder / "02-boot.txt").stat().st_size)
        self.assertTrue(json.loads((folder / "02-boot.json").read_text())["evidenceTruncated"])
        self.assertTrue(all(p.stat().st_size <= MAX_RAW_BYTES for p in folder.iterdir() if p.is_file()))

    def test_stopped_adbd_nonzero_pidof_is_known_absence_not_connection_failure(self):
        reader = FakeReader()
        original = reader.query
        def query(name):
            value = original(name)
            if name == "adb_state":
                value.update(text="rndis,mass_storage,bulk,acm\nrndis,mass_storage,bulk,acm\nstopped\n\n", shellLastExitCode=1)
            return value
        reader.query = query
        bridge = self.bridge(reader)
        bridge.read("maintenance")
        state = self.finish(bridge)
        self.assertEqual("completed", state["current"]["state"])
        self.assertTrue(state["connected"])
        self.assertEqual(1, state["lastRead"]["maintenance"]["queries"][2]["exit"])

    def test_other_nonzero_queries_do_not_claim_connection_success(self):
        reader = FakeReader()
        original = reader.query
        reader.query = lambda name: {**original(name), "shellLastExitCode": 1} if name == "gui_hash" else original(name)
        bridge = self.bridge(reader)
        bridge.read("ui")
        state = self.finish(bridge)
        self.assertEqual("failed", state["current"]["state"])
        self.assertIsNone(state["connected"])
        self.assertEqual(["identity", "gui_hash"], reader.names)

    def test_default_adapter_calls_existing_query_with_fixed_timeout_and_no_collect(self):
        from tools import live_readout
        reader = FakeReader()
        bridge = DeviceBridge(PROJECT, self.temp.name)
        self.addCleanup(bridge.close)
        transport = object()
        with (patch.object(live_readout, "load_transport", return_value=transport),
              patch.object(live_readout, "query", side_effect=lambda name, actual, timeout: reader.query(name)) as query,
              patch.object(live_readout, "collect") as collect):
            bridge.connect()
            state = self.finish(bridge)
        self.assertTrue(state["connected"])
        self.assertEqual([("identity", transport), ("boot", transport), ("identity", transport)], [call.args for call in query.call_args_list])
        self.assertTrue(all(call.kwargs == {"timeout": 8} for call in query.call_args_list))
        collect.assert_not_called()


class MonitorTests(BridgeCase):
    def monitor(self, samples, **kwargs):
        reader = TimelineReader(samples, **kwargs)
        bridge = self.bridge(reader)
        reader.stop_after = bridge.monitor_stop.set
        return reader, bridge

    def test_final_evidence_failure_marks_monitor_failed_not_stopped(self):
        reader, bridge = self.monitor([log_sample(BASE_LINE)])
        original = bridge._file
        def fail_final(path, raw):
            if path.name == "RESULT.json":
                raise OSError("final evidence unavailable")
            return original(path, raw)
        with patch.object(bridge, "_file", side_effect=fail_final):
            bridge.start("monitor-start", {})
            state = self.finish(bridge)
        self.assertEqual("failed", state["current"]["state"])
        self.assertFalse(state["monitor"]["active"])
        self.assertEqual("failed", state["monitor"]["state"])
        self.assertIn("final evidence unavailable", state["monitor"]["error"])
        failure = json.loads((Path(state["current"]["evidencePath"]) / "FINALIZATION_FAILURE.json").read_text(encoding="utf-8"))
        self.assertEqual("failed", failure["state"])

    def test_pointer_failure_preserves_result_and_marks_session_failed(self):
        reader, bridge = self.monitor([log_sample(BASE_LINE)])
        with patch.object(bridge, "_pointer", side_effect=OSError("publication unavailable")):
            bridge.start("monitor-start", {})
            state = self.finish(bridge)
        folder = Path(state["current"]["evidencePath"])
        original = json.loads((folder / "RESULT.json").read_text(encoding="utf-8"))
        failure = json.loads((folder / "FINALIZATION_FAILURE.json").read_text(encoding="utf-8"))
        self.assertEqual("completed", original["state"])
        self.assertEqual("failed", failure["state"])
        self.assertEqual("failed", state["monitor"]["state"])
        self.assertIn("publication unavailable", state["monitor"]["error"])

    def test_parser_initialization_failure_clears_active_monitor_without_query(self):
        reader = TimelineReader()
        bridge = self.bridge(reader, timeline_factory=Mock(side_effect=ImportError("parser unavailable")))
        bridge.start("monitor-start", {})
        state = self.finish(bridge)
        self.assertEqual("failed", state["current"]["state"])
        self.assertEqual("failed", state["monitor"]["state"])
        self.assertFalse(state["monitor"]["active"])
        self.assertIn("parser unavailable", state["monitor"]["error"])
        self.assertEqual([], reader.names)
        self.assertIsNone(state["connected"])

    def test_parser_uses_checked_current_bytes_not_a_cached_module_shadow(self):
        shadow = SimpleNamespace(__file__=str(PROJECT / "devtools" / "camera_timeline.py"),
                                 CaptureTimeline=Mock(side_effect=AssertionError("cached parser must not execute")))
        reader, bridge = self.monitor([log_sample(BASE_LINE)])
        with patch.dict(sys.modules, {"devtools.camera_timeline": shadow}):
            bridge.start("monitor-start", {})
            state = self.finish(bridge)
        self.assertEqual("completed", state["current"]["state"], state["current"].get("error"))
        self.assertEqual(1, state["monitor"]["timeline"]["samples"])
        shadow.CaptureTimeline.assert_not_called()

    def test_parser_source_change_during_poll_stops_before_attributing_events(self):
        parser_path = PROJECT / "devtools" / "camera_timeline.py"
        read_bytes, reads = Path.read_bytes, [0]
        reader, bridge = self.monitor([log_sample(BASE_LINE + SHOT_LINE)])
        def changed_bytes(path):
            raw = read_bytes(path)
            if path == parser_path:
                reads[0] += 1
                if reads[0] >= 3:
                    return raw + b"\n# injected source change\n"
            return raw
        with patch.object(Path, "read_bytes", changed_bytes):
            bridge.start("monitor-start", {})
            state = self.finish(bridge)
        self.assertEqual("failed", state["current"]["state"])
        self.assertEqual("failed", state["monitor"]["state"])
        self.assertFalse(state["monitor"]["active"])
        self.assertIn("解析器来源", state["current"]["error"])
        self.assertEqual(0, state["monitor"]["timeline"]["capturedCount"])
        self.assertEqual(1, reader.sample_index)

    def test_local_start_failures_clear_monitor_and_allow_safe_close(self):
        for boundary in ("evidence", "thread"):
            with self.subTest(boundary=boundary):
                reader, bridge = self.monitor([])
                target = patch.object(Path, "open", side_effect=OSError("START write denied")) if boundary == "evidence" else patch.object(threading.Thread, "start", side_effect=RuntimeError("thread start failed"))
                with target, self.assertRaises((OSError, RuntimeError)):
                    bridge.start("monitor-start", {})
                state = bridge.status()
                self.assertFalse(state["monitor"]["active"])
                self.assertEqual("failed", state["monitor"]["state"])
                self.assertEqual("failed", state["current"]["state"])
                self.assertFalse(state["workerActive"])
                self.assertEqual([], reader.names)
                self.assertTrue(bridge.close()["terminated"])

    def test_real_parser_baselines_first_tail_and_keeps_normal_append_capture(self):
        reader, bridge = self.monitor([
            log_sample(BASE_LINE),
            log_sample(BASE_LINE + SHOT_LINE, after_size=len((BASE_LINE + SHOT_LINE).encode()) + 10),
        ])
        with patch.object(bridge_module, "MONITOR_INTERVAL_SECONDS", .001):
            bridge.start("monitor-start", {})
            state = self.finish(bridge)
        self.assertEqual("completed", state["current"]["state"], state["current"].get("error"))
        self.assertEqual(["identity", "boot", "identity", "timeline_log", "timeline_log"], reader.names)
        timeline = state["monitor"]["timeline"]
        self.assertEqual(2, timeline["samples"])
        self.assertEqual(1, timeline["capturedCount"])
        self.assertEqual(0, timeline["gapCount"])
        self.assertEqual("capture-request", timeline["events"][0]["phase"])
        self.assertEqual(SHOT_LINE.rstrip("\n"), timeline["recentRaw"][-1])
        self.assertFalse(state["monitor"]["snapshotAtomic"])
        self.assertEqual(10, state["monitor"]["snapshotEndSizeRange"][1] - state["monitor"]["snapshotEndSizeRange"][0])
        self.assertFalse(state["monitor"]["active"])
        self.assertFalse(state["current"]["cameraWritten"])
        self.assertFalse(state["current"]["photosRead"])
        self.assertFalse(state["current"]["calibrationRead"])
        self.assertFalse(state["installable"])

    def test_received_sample_no_longer_displays_starting_reason(self):
        reader, bridge = self.monitor([log_sample(BASE_LINE), log_sample(BASE_LINE + SHOT_LINE)])
        query, observed = reader.query, []
        def inspect_query(name):
            if name == "timeline_log" and reader.sample_index == 1:
                observed.append(bridge.status()["monitor"])
            return query(name)
        reader.query = inspect_query
        with patch.object(bridge_module, "MONITOR_INTERVAL_SECONDS", .001):
            bridge.start("monitor-start", {})
            self.finish(bridge)
        self.assertEqual(1, len(observed))
        self.assertEqual(1, observed[0]["timeline"]["samples"])
        self.assertNotIn("启动中", observed[0]["reason"])
        self.assertIn("已收到", observed[0]["reason"])

    def test_eof_fragment_is_not_completed_by_bridge_separator_or_replayed(self):
        prefix = "10-08 12:00:02.000  10  11 I camera-gui: part"
        reader, bridge = self.monitor([
            log_sample(BASE_LINE), log_sample(BASE_LINE + SHOT_LINE + prefix),
            log_sample(BASE_LINE + SHOT_LINE + prefix + " complete\n"),
        ])
        with patch.object(bridge_module, "MONITOR_INTERVAL_SECONDS", .001):
            bridge.start("monitor-start", {})
            state = self.finish(bridge)
        self.assertEqual("completed", state["current"]["state"], state["current"].get("error"))
        timeline = state["monitor"]["timeline"]
        self.assertEqual(1, timeline["capturedCount"])
        self.assertEqual(2, len(timeline["events"]))
        folder = Path(state["current"]["evidencePath"])
        self.assertEqual(log_sample(BASE_LINE + SHOT_LINE + prefix), (folder / "05-timeline_log.txt").read_text())

    def test_initial_identity_change_stops_without_a_log_poll(self):
        reader, bridge = self.monitor([], identities=[IDENTITY, IDENTITY.replace(BOOT, NEW_BOOT)])
        bridge.start("monitor-start", {})
        state = self.finish(bridge)
        self.assertEqual(["identity", "boot", "identity"], reader.names)
        self.assertEqual("failed", state["monitor"]["state"])
        self.assertFalse(state["monitor"]["active"])
        self.assertIsNone(state["connected"])

    def test_mid_read_source_changes_are_gaps_then_baselines_not_captures(self):
        for changed in ({"after_boot": NEW_BOOT}, {"after_inode": 18}, {"after_size": 1}, {"after_size": 200 + 16385}):
            with self.subTest(changed=changed):
                boot = NEW_BOOT if "after_boot" in changed else BOOT
                inode = 18 if "after_inode" in changed else 17
                reader, bridge = self.monitor([
                    log_sample(BASE_LINE, size=200),
                    log_sample(BASE_LINE + SHOT_LINE, size=200, **changed),
                    log_sample(BASE_LINE + SHOT_LINE, boot=boot, inode=inode, size=300),
                ], identities=[IDENTITY, IDENTITY, IDENTITY.replace(BOOT, NEW_BOOT)] if boot == NEW_BOOT else None)
                with patch.object(bridge_module, "MONITOR_INTERVAL_SECONDS", .001):
                    bridge.start("monitor-start", {})
                    state = self.finish(bridge)
                self.assertEqual("completed", state["current"]["state"], state["current"].get("error"))
                self.assertGreaterEqual(state["monitor"]["timeline"]["gapCount"], 1)
                self.assertEqual(0, state["monitor"]["timeline"]["capturedCount"])
                self.assertEqual(3, state["monitor"]["polls"])

    def test_between_poll_boot_rotation_and_truncation_rebaseline_real_parser(self):
        for changed in ("boot", "inode", "truncate"):
            with self.subTest(changed=changed):
                boot, inode = (NEW_BOOT if changed == "boot" else BOOT), (18 if changed == "inode" else 17)
                reader, bridge = self.monitor([
                    log_sample(BASE_LINE, size=1000),
                    log_sample(BASE_LINE + SHOT_LINE, boot=boot, inode=inode, size=200 if changed == "truncate" else 1100),
                    log_sample(BASE_LINE + SHOT_LINE + SHOT_LINE.replace("12:00:01", "12:00:02"),
                               boot=boot, inode=inode, size=300 if changed == "truncate" else 1200),
                ], identities=[IDENTITY, IDENTITY, IDENTITY.replace(BOOT, NEW_BOOT)] if changed == "boot" else None)
                with patch.object(bridge_module, "MONITOR_INTERVAL_SECONDS", .001):
                    bridge.start("monitor-start", {})
                    state = self.finish(bridge)
                self.assertEqual("completed", state["current"]["state"], state["current"].get("error"))
                self.assertEqual(1, state["monitor"]["timeline"]["capturedCount"])
                self.assertEqual(1, state["monitor"]["timeline"]["gapCount"])
                self.assertEqual(boot, state["identity"]["bootId"])
                self.assertEqual(3 if changed == "boot" else 2, reader.names.count("identity"))

    def test_malformed_oversized_and_denied_log_queries_stop_without_write(self):
        for sample in ("malformed metadata\n", log_sample("x" * 16385), log_sample(BASE_LINE, inode=2 ** 63), ("Permission denied\n", 1)):
            with self.subTest(sample=str(sample)[:70]):
                reader, bridge = self.monitor([sample])
                bridge.start("monitor-start", {})
                state = self.finish(bridge)
                self.assertEqual("failed", state["current"]["state"])
                self.assertEqual("failed", state["monitor"]["state"])
                self.assertFalse(state["monitor"]["active"])
                self.assertIsNone(state["connected"])
                self.assertFalse(state["current"]["cameraWritten"])
                self.assertFalse(state["current"]["cameraWriteAttempted"])
                self.assertEqual(1, reader.sample_index)

    def test_stop_awaits_only_current_query_and_excludes_other_operations(self):
        entered, release = threading.Event(), threading.Event()
        reader, bridge = self.monitor([log_sample(BASE_LINE)], timeline_wait=(entered, release))
        publications = []
        class ObservedMonitor(dict):
            def update(self, *args, **kwargs):
                super().update(*args, **kwargs)
                if kwargs.get('lastSampleUtc') is not None:
                    publications.append((self["state"], self["reason"]))
        bridge.monitor = ObservedMonitor(bridge.monitor)
        bridge.start("monitor-start", {})
        self.assertTrue(entered.wait(1))
        self.assertFalse(bridge.thread.daemon)
        for operation, body in (("read", {"component": "ui"}), ("deploy", {}), ("connect", {}), ("monitor-start", {})):
            with self.assertRaises(BridgeConflict):
                bridge.start(operation, body)
        started = time.monotonic()
        stopping = bridge.start("monitor-stop", {})
        self.assertLess(time.monotonic() - started, .5)
        self.assertTrue(stopping["workerActive"])
        self.assertEqual("stopping", stopping["monitor"]["state"])
        release.set()
        state = self.finish(bridge)
        self.assertEqual(1, reader.sample_index)
        self.assertEqual("stopped", state["monitor"]["state"])
        self.assertFalse(state["monitor"]["active"])
        self.assertEqual(1, len(publications))
        self.assertEqual("stopping", publications[0][0])
        self.assertNotIn("持续读取", publications[0][1])

    def test_close_stops_monitor_without_late_pointer_and_releases_ownership_after_exit(self):
        entered, release, owner_released = threading.Event(), threading.Event(), threading.Event()
        reader, bridge = self.monitor([log_sample(BASE_LINE)], timeline_wait=(entered, release))
        bridge.start("monitor-start", {})
        self.assertTrue(entered.wait(1))
        with patch.object(bridge.thread, "join", return_value=None):
            state = bridge.close(on_idle=owner_released.set)
        self.assertEqual("closing", state["state"])
        self.assertFalse(bridge._idle_watcher.daemon)
        self.assertFalse(owner_released.is_set())
        release.set()
        self.assertTrue(owner_released.wait(2))
        state = self.finish(bridge)
        self.assertTrue(state["terminated"])
        self.assertFalse(state["monitor"]["active"])
        self.assertEqual(1, reader.sample_index)
        self.assertFalse((bridge.root / "latest.json").exists())

    def test_stop_during_final_evidence_does_not_reopen_stopping_state(self):
        entered, release = threading.Event(), threading.Event()
        reader, bridge = self.monitor([log_sample(BASE_LINE)])
        open_file = Path.open
        def delayed_result(path, *args, **kwargs):
            if path.name == "RESULT.json":
                entered.set()
                if not release.wait(3):
                    raise TimeoutError("final evidence fixture release missing")
            return open_file(path, *args, **kwargs)
        with patch.object(Path, "open", delayed_result):
            bridge.start("monitor-start", {})
            self.assertTrue(entered.wait(1))
            state = bridge.start("monitor-stop", {})
            self.assertEqual("stopped", state["monitor"]["state"])
            self.assertFalse(next(item for item in state["operations"] if item["id"] == "monitor-stop")["enabled"])
            release.set()
            state = self.finish(bridge)
        self.assertEqual("stopped", state["monitor"]["state"])

    def test_monitor_time_limit_stops_without_log_poll(self):
        reader = TimelineReader()
        bridge = self.bridge(reader, clock=Mock(side_effect=[0, 8 * 60 * 60, 8 * 60 * 60]))
        bridge.start("monitor-start", {})
        state = self.finish(bridge)
        self.assertEqual(["identity", "boot", "identity"], reader.names)
        self.assertEqual("limit-reached", state["monitor"]["state"])
        self.assertIn("8小时", state["monitor"]["reason"])
        self.assertFalse(state["monitor"]["active"])
        self.assertEqual(8 * 60 * 60, state["monitor"]["maxSeconds"])
        self.assertEqual(2 * 1024 ** 3, state["monitor"]["maxEvidenceBytes"])
        self.assertEqual(8 * 60 * 60, state["monitor"]["elapsedSeconds"])

    def test_old_thirty_minute_boundary_no_longer_stops_sampling(self):
        reader, bridge = self.monitor([log_sample(BASE_LINE)])
        bridge.clock = Mock(side_effect=[0, 1800, 1800])
        bridge.start("monitor-start", {})
        state = self.finish(bridge)
        self.assertEqual("stopped", state["monitor"]["state"])
        self.assertEqual(1, state["monitor"]["polls"])
        self.assertEqual(1800, state["monitor"]["elapsedSeconds"])

    def test_old_sixteen_mib_boundary_accepts_new_evidence(self):
        bridge = self.bridge()
        folder = bridge.root / "large-session-fixture"
        folder.mkdir(parents=True)
        bridge._monitor_folder = folder
        bridge._monitor_bytes = 16 * 1024 * 1024
        bridge._file(folder / "beyond-old-cap.bin", b"observed fixture")
        self.assertGreater(bridge.monitor["retainedBytes"], 16 * 1024 * 1024)

    def test_monitor_counter_does_not_retain_query_previews_or_reuse_indexes(self):
        from weakref import ref
        class Preview:
            pass
        tally = bridge_module._MonitorQueryCount()
        preview = Preview()
        reference = ref(preview)
        for _ in range(30_000):
            tally.append({"textPreview": preview})
        del preview
        self.assertIsNone(reference())
        self.assertEqual(30_000, len(tally))
        bridge = self.bridge()
        job = {"operation": "monitor-start", "deviceRequests": 0}
        written = []
        with patch.object(bridge, "_file", side_effect=lambda path, raw: written.append(path.name)):
            for _ in range(2):
                bridge._query(FakeReader(), "boot", bridge.root, job, tally)
        self.assertEqual(30_002, len(tally))
        self.assertIn("30001-boot.txt", written)
        self.assertIn("30002-boot.txt", written)
        self.assertEqual(len(written), len(set(written)))

    def test_low_disk_space_stops_without_deleting_evidence_and_preserves_result(self):
        reader, bridge = self.monitor([log_sample(BASE_LINE)])
        with patch.object(bridge_module.shutil, "disk_usage", side_effect=[
                SimpleNamespace(free=2 * 1024 ** 3), SimpleNamespace(free=0)]):
            bridge.start("monitor-start", {})
            state = self.finish(bridge)
        self.assertEqual("limit-reached", state["monitor"]["state"])
        self.assertIn("磁盘", state["monitor"]["reason"])
        folder = Path(state["current"]["evidencePath"])
        self.assertTrue((folder / "START.json").is_file())
        self.assertTrue((folder / "RESULT.json").is_file())
        self.assertFalse(state["current"]["cameraWritten"])

    def test_new_session_resets_elapsed_and_terminal_elapsed_is_frozen(self):
        reader = TimelineReader()
        bridge = self.bridge(reader, clock=Mock(side_effect=[0, 28800, 28800, 0, 28800, 28800]))
        entered, release, original_run = threading.Event(), threading.Event(), bridge._run
        self.addCleanup(release.set)
        def gated_run(*args):
            entered.set()
            if not release.wait(3):
                raise TimeoutError("elapsed reset fixture release missing")
            return original_run(*args)
        with patch.object(bridge, "_run", side_effect=gated_run):
            for _ in range(2):
                entered.clear()
                release.clear()
                reader.identities = [IDENTITY, IDENTITY]
                bridge.start("monitor-start", {})
                self.assertTrue(entered.wait(1))
                self.assertEqual(0, bridge.status()["monitor"]["elapsedSeconds"])
                release.set()
                state = self.finish(bridge)
                self.assertEqual("limit-reached", state["monitor"]["state"])
                self.assertEqual(28800, state["monitor"]["elapsedSeconds"])
                self.assertEqual(28800, bridge.status()["monitor"]["elapsedSeconds"])

    def test_final_query_elapsed_includes_manual_stop_and_error_endings(self):
        for ending in ("stop", "error"):
            with self.subTest(ending=ending):
                now = [0]
                reader, bridge = self.monitor([log_sample(BASE_LINE)])
                bridge.clock = lambda: now[0]
                original_query = reader.query
                def query(name):
                    if name == "timeline_log":
                        now[0] = 5
                        if ending == "error":
                            raise TimeoutError("fixed query fixture")
                    return original_query(name)
                reader.query = query
                bridge.start("monitor-start", {})
                state = self.finish(bridge)
                self.assertEqual(5, state["monitor"]["elapsedSeconds"])
                self.assertEqual("failed" if ending == "error" else "stopped", state["monitor"]["state"])
                now[0] = 999
                self.assertEqual(5, bridge.status()["monitor"]["elapsedSeconds"])

    def test_monitor_volume_limit_preserves_bounded_local_raw_and_final_summary(self):
        reader = TimelineReader([log_sample(BASE_LINE)] * 3, timeline_bytes=5000)
        bridge = self.bridge(reader)
        with patch.object(bridge_module, "MAX_MONITOR_BYTES", 20000), patch.object(bridge_module, "MONITOR_INTERVAL_SECONDS", .001):
            bridge.start("monitor-start", {})
            state = self.finish(bridge)
        self.assertEqual("limit-reached", state["monitor"]["state"])
        self.assertEqual("completed", state["current"]["state"], state["current"].get("error"))
        folder = Path(state["current"]["evidencePath"])
        self.assertTrue((folder / "RESULT.json").is_file())
        self.assertLessEqual(sum(path.stat().st_size for path in folder.iterdir()), 20000)
        self.assertEqual(sum(path.stat().st_size for path in folder.iterdir()), state["monitor"]["retainedBytes"])
        self.assertNotIn("r" * 5000, json.dumps(state))
        self.assertNotIn("queries", state["current"]["result"])
        self.assertFalse(state["current"]["cameraWritten"])

    def test_default_monitor_query_reuses_native_receiver_without_mutating_query_table(self):
        from tools import live_readout as live
        transport = live.load_transport()  # Compile checked source; no device IO.
        before = dict(live.QUERIES)
        metadata = f"{BOOT}\n17 {len(BASE_LINE.encode())}\n"
        commands, payloads = [], [IDENTITY, "fixed boot\n", IDENTITY, metadata + metadata]
        bridge = DeviceBridge(PROJECT, self.temp.name)
        self.addCleanup(bridge.close)

        def packet(text, function=4):
            command = bytearray(252)
            struct.pack_into("<III", command, 0, 0x41, function, 0)
            encoded = text.encode("utf-8")
            self.assertLess(len(encoded), 232)
            command[20:20 + len(encoded)] = encoded
            struct.pack_into("<I", command, 12, transport.crc16_hbl(command[16:]))
            return b"\x09\x00\x05\x09\xfc" + command + b"\x00" * 3

        def run(command, timeout, *, completion_marker, read_evidence):
            commands.append(command)
            self.assertEqual(8, timeout)
            self.assertLess(len(command.encode("ascii")), 232)
            text = payloads.pop(0) + "\n__RC_123456abcdef__0\n" + completion_marker + "\n"
            packets = [packet(text[index:index + 180]) for index in range(0, len(text), 180)]
            packets.append(packet("", function=1))
            wire = b"".join(value + b"\xa5" * 764 for value in packets)
            chunks = [wire[index:index + 1536] for index in range(0, len(wire), 1536)]

            class Socket:
                def settimeout(self, seconds):
                    pass
                def recv(self, size):
                    chunk = chunks.pop(0) if chunks else b""
                    transport.socket.chunks.append(chunk)
                    return chunk

            retained = transport.receive_packets(Socket(), timeout, completion_marker, read_evidence=read_evidence)
            if not payloads:
                bridge.monitor_stop.set()
            return retained, []

        with (patch.object(live, "load_transport", return_value=transport),
              patch.object(transport, "run", side_effect=run),
              patch.object(live.secrets, "token_hex", return_value="123456abcdef"),
              patch.object(live.socket, "create_connection", side_effect=AssertionError("offline test must not connect")) as network,
              patch.object(live, "collect") as collect):
            bridge.start("monitor-start", {})
            state = self.finish(bridge)
        self.assertEqual("completed", state["current"]["state"], state["current"].get("error"))
        self.assertEqual(before, live.QUERIES)
        self.assertNotIn("timeline_log", live.QUERIES)
        self.assertEqual(bridge_module._timeline_command(None) + ";printf '\\n__RC_123456abcdef__%s\\n__RD_123456abcdef__\\n' $?", commands[-1])
        self.assertEqual(1, state["monitor"]["polls"])
        self.assertNotIn('tailBytes', state['monitor'])
        self.assertEqual(65536, state['monitor']['chunkBytes'])
        self.assertEqual("/blackbox/camera/log/cam.log", state["monitor"]["path"])
        self.assertTrue(state["monitor"]["sources"]["timelineQuerySha256"])
        self.assertTrue(state["monitor"]["sources"]["parserSourceSha256"])
        folder = Path(state["current"]["evidencePath"])
        self.assertGreater((folder / "04-timeline_log.received.bin").stat().st_size,
                           (folder / "04-timeline_log.packets.bin").stat().st_size)
        self.assertNotIn('"rawReceived":', json.dumps(state))
        self.assertNotIn('"packets":', json.dumps(state))
        network.assert_not_called()
        collect.assert_not_called()


class DispatchTests(BridgeCase):
    def context(self, name):
        from tools import menu_prepared_transport as prepared
        kind = prepared.PreparedFormalPlacementOperation if name == "deploy" else prepared.PreparedBootOperation
        operation = object.__new__(kind)
        operation.manifest = {"candidate_sha256": "a" * 64}
        if name != "deploy":
            operation.action = "restore" if name == "restore" else "activate"
        return PreparedExecution(operation, b'{"original":"launch"}', Mock(), Mock(),
                                 {"trusted_local": True}, {"original_window": True},
                                 "saved-original.json" if name == "restore" else None,
                                 "b" * 64 if name == "restore" else None)

    def test_three_dispatches_call_real_existing_method_boundaries_and_validators(self):
        from tools import prepare_peer_install as install, prepare_peer_recovery as recovery
        for name in ("deploy", "load", "restore"):
            with self.subTest(name=name):
                context = self.context(name)
                bridge = self.bridge(execution_provider=lambda requested: context)
                with (patch.object(install, "validate_qualification") as iv,
                      patch.object(recovery, "validate_qualification") as rv,
                      patch.object(type(context.operation), "run_qualified", return_value={"status": "ORIGINAL_SCOPE_NOT_FUNCTION_VALIDATED"}) as dispatch):
                    bridge.start(name, {})
                    state = self.finish(bridge)
                self.assertEqual("completed", state["current"]["state"])
                self.assertFalse(state["current"]["result"]["runtimeLoadedVerified"])
                self.assertEqual("a" * 64, state["current"]["result"]["candidateSha256"])
                self.assertIn("不自动包含草稿", state["current"]["result"]["scope"])
                arguments = {"qualification": context.qualification, "window_authorization": context.window_authorization}
                if name == "restore":
                    rv.assert_called_once_with(context.saved_manifest, context.saved_manifest_sha256, context.qualification, for_publication=True)
                    iv.assert_not_called()
                    arguments.update(saved_manifest=context.saved_manifest, saved_manifest_sha256=context.saved_manifest_sha256)
                else:
                    iv.assert_called_once_with(context.operation.manifest, context.qualification, for_publication=True)
                    rv.assert_not_called()
                dispatch.assert_called_once_with(context.launch_report, context.maintenance_session, context.start_process, **arguments)

    def test_gate_rejection_never_dispatches_or_sends_commands(self):
        from tools import prepare_peer_install as install
        context = self.context("deploy")
        bridge = self.bridge(execution_provider=lambda requested: context)
        with (patch.object(install, "validate_qualification", side_effect=ValueError("complete_offline_audit NOT_RUN")),
              patch.object(type(context.operation), "run_qualified") as dispatch):
            bridge.start("deploy", {})
            state = self.finish(bridge)
        self.assertEqual("failed", state["current"]["state"])
        self.assertIn("NOT_RUN", state["current"]["error"])
        self.assertFalse(state["current"]["cameraWriteAttempted"])
        dispatch.assert_not_called()
        context.maintenance_session.command.assert_not_called()
        context.start_process.assert_not_called()

    def test_actual_publication_validator_rejects_synthetic_without_commands(self):
        context = self.context("deploy")
        context = replace(context, qualification={"candidate_sha256": "a" * 64, "synthetic": True})
        bridge = self.bridge(execution_provider=lambda requested: context)
        with patch.object(type(context.operation), "run_qualified") as dispatch:
            bridge.start("deploy", {})
            state = self.finish(bridge)
        self.assertIn("synthetic qualification cannot authorize", state["current"]["error"])
        self.assertFalse(state["current"]["cameraWriteAttempted"])
        dispatch.assert_not_called()
        context.maintenance_session.command.assert_not_called()

    def test_wrong_prepared_kind_is_not_dispatched(self):
        context = self.context("restore")
        bridge = self.bridge(execution_provider=lambda requested: context)
        bridge.start("load", {})
        self.assertIn("不匹配", self.finish(bridge)["current"]["error"])
        context.start_process.assert_not_called()

    def test_recovery_diagnosis_independent_of_new_candidate_failure(self):
        from tools import prepare_peer_install as install, prepare_peer_recovery as recovery
        context = self.context("restore")
        bridge = self.bridge(execution_provider=lambda name: context if name == "restore" else None)
        with (patch.object(install, "inventory", side_effect=ValueError("new candidate invalid")),
              patch.object(recovery, "validate_qualification") as validate):
            bridge.start("qualification", {})
            state = self.finish(bridge)
        self.assertEqual("unavailable", state["qualification"]["candidate"]["state"])
        self.assertTrue(state["qualification"]["routes"]["restore"]["ready"])
        validate.assert_called_once()
        context.start_process.assert_not_called()

    def test_original_route_bytes_are_evidence_files_not_sse_payloads(self):
        from tools import prepare_peer_install as install
        context = self.context("deploy")
        bridge = self.bridge(execution_provider=lambda name: context)
        with (patch.object(install, "validate_qualification"),
              patch.object(type(context.operation), "run_qualified", return_value={"payloads": [b"retained original reply"]})):
            bridge.start("deploy", {})
            state = self.finish(bridge)
        self.assertEqual("completed", state["current"]["state"])
        retained = state["current"]["result"]["routeResult"]["payloads"][0]
        self.assertEqual(b"retained original reply", Path(retained["evidenceFile"]).read_bytes())
        self.assertNotIn("retained original reply", json.dumps(state))

    def test_original_run_qualified_rechecks_gate_before_any_child(self):
        from tools import menu_prepared_transport as prepared, prepare_peer_install as install
        context = self.context("deploy")
        context.operation.preparation = SimpleNamespace(manifest_bytes=json.dumps(context.operation.manifest).encode())
        bridge = self.bridge(execution_provider=lambda name: context)
        with (patch.object(install, "validate_qualification", side_effect=[None, ValueError("changed gate rejected by original route")]) as validate,
              patch.object(prepared.content, "_validate_preparation")):
            bridge.start("deploy", {})
            state = self.finish(bridge)
        self.assertEqual(2, validate.call_count)
        self.assertIn("changed gate rejected by original route", state["current"]["error"])
        self.assertTrue(state["current"]["cameraWriteAttempted"])
        context.start_process.assert_not_called()
        context.maintenance_session.command.assert_not_called()

    def test_real_transaction_contact_marker_and_delayed_ownership_release(self):
        from tools import prepare_peer_install as install
        context = self.context("deploy")
        entered, release, ownership_released = threading.Event(), threading.Event(), threading.Event()
        def run(*args, **kwargs):
            entered.set()
            if not release.wait(3):
                raise TimeoutError("fixture release missing")
            return {"status": "ORIGINAL_SCOPE_NOT_LIFECYCLE_VALIDATED"}
        bridge = DeviceBridge(PROJECT, self.temp.name, execution_provider=lambda name: context)
        self.addCleanup(bridge.close)
        with (patch.object(install, "validate_qualification"), patch.object(type(context.operation), "run_qualified", side_effect=run)):
            bridge.start("deploy", {})
            self.assertTrue(entered.wait(1))
            self.assertTrue(bridge.status()["current"]["cameraContacted"])
            with patch.object(bridge.thread, "join", return_value=None):
                closing = bridge.close(on_idle=ownership_released.set)
            self.assertFalse(closing["terminated"])
            self.assertEqual("closing", closing["state"])
            self.assertFalse(ownership_released.is_set())
            with self.assertRaises(BridgeConflict):
                bridge.start("restore", {})
            release.set()
            self.assertTrue(ownership_released.wait(2))
            state = self.finish(bridge)
        self.assertTrue(state["terminated"])
        self.assertFalse((bridge.root / "latest.json").exists())


if __name__ == "__main__":
    unittest.main()
