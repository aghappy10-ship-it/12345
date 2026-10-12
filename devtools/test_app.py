import http.client
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from app import Board, Conflict, Jobs, Server, Workbench, atomic_json, safe_file, tail, ProcessJob


class FakePreview:
    def __init__(self):
        self.value = {"state": "not_started", "ready": False}
    def status(self):
        return dict(self.value)
    def start(self, mode):
        if mode not in ("stock", "candidate"):
            raise ValueError("未知预览模式")
        self.value = {"state": "running", "mode": mode, "ready": False}
        return self.status()
    def stop(self):
        self.value = {"state": "stopped", "ready": False}
        return self.status()
    def frame_path(self):
        return None
    def send_input(self, event):
        if self.value["state"] != "running":
            raise ValueError("预览未启动")
        self.last_event = event
        return {"accepted": True}


class BoardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
    def tearDown(self):
        self.temp.cleanup()
    def test_plan_does_not_claim_completed_or_live(self):
        value = Board(self.root).snapshot()
        self.assertEqual(5, len(value["tasks"]))
        self.assertTrue(all(t["state"] == "todo" and t["heartbeatUtc"] is None for t in value["tasks"]))
    def test_state_roundtrip_and_optimistic_concurrency(self):
        board = Board(self.root)
        value = board.change("entry", {"revision": 0, "state": "doing", "owner": "同事甲", "note": "等待真实点击", "heartbeat": True})
        self.assertEqual(1, value["revision"])
        self.assertIsNotNone(value["tasks"][0]["heartbeatUtc"])
        self.assertEqual(value, Board(self.root).snapshot())
        with self.assertRaises(Conflict):
            board.change("entry", {"revision": 0, "state": "done"})
        self.assertEqual("doing", board.snapshot()["tasks"][0]["state"])
    def test_invalid_change_does_not_persist(self):
        board = Board(self.root)
        before = board.path.read_bytes()
        with self.assertRaises(ValueError):
            board.change("entry", {"revision": 0, "state": "validated-on-camera"})
        self.assertEqual(before, board.path.read_bytes())
    def test_notes_and_created_tasks_survive_restart(self):
        board = Board(self.root)
        board.change("note", {"revision": 0, "text": "不改保存管线", "author": "用户"})
        board.change("create", {"revision": 1, "title": "入口点击", "owner": "AI"})
        loaded = Board(self.root).snapshot()
        self.assertEqual("不改保存管线", loaded["notes"][0]["text"])
        self.assertEqual("todo", loaded["tasks"][-1]["state"])
    def test_corrupt_board_is_not_overwritten(self):
        path = self.root / "board.json"
        path.write_bytes(b"broken-json")
        with self.assertRaises(ValueError):
            Board(self.root)
        self.assertEqual(b"broken-json", path.read_bytes())
    def test_safe_path_rejects_escape_and_tail_is_bounded(self):
        with self.assertRaises(ValueError):
            safe_file(self.root, "../outside.txt")
        path = self.root / "log.txt"
        path.write_bytes(b"private-start\n" + b"tail-line\n" * 100)
        result = tail(path, 50)
        self.assertNotIn("private-start", result)
        self.assertLessEqual(len(result), 50)


class WorkbenchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.app = Workbench(self.root, self.root / "data", preview=FakePreview())
    def tearDown(self):
        self.app.close()
        self.temp.cleanup()
    def test_unknown_live_state_never_passes(self):
        result = self.app.audit(probe=lambda *args: None)
        self.assertEqual("unknown", result["state"])
        self.assertFalse(result["qualified"])
        self.assertFalse(self.app.snapshot()["evidence"]["installable"])
    def test_stale_process_and_incomplete_audit_are_distinct(self):
        result = self.app.audit(probe=lambda *args: False)
        self.assertEqual("incomplete", result["state"])
        self.assertIsNone(result["result"])
    def test_failed_final_audit_is_not_release(self):
        from app import AUDIT
        atomic_json(self.root / AUDIT / "AUDIT.json", {"status": "LOCAL_AUDIT_FAILED", "exit_code": 1})
        value = self.app.audit(probe=lambda *args: False)
        self.assertEqual("finished", value["state"])
        self.assertEqual("LOCAL_AUDIT_FAILED", value["result"])
        self.assertFalse(value["qualified"])
    def test_source_allowlist_and_real_diff(self):
        from app import SOURCE_FILES
        for key in ("bootstrap", "candidate"):
            path = self.root / SOURCE_FILES[key]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(key + "\n", encoding="utf-8")
        self.assertIn("+candidate", self.app.diff()["text"])
        with self.assertRaises(ValueError):
            self.app.source("../../secret")
    def test_job_rejects_arbitrary_commands(self):
        with self.assertRaises(ValueError):
            self.app.jobs.start("powershell")
        self.assertIsNone(self.app.jobs.snapshot()["current"])
    def test_second_server_cannot_silently_overwrite_shared_board(self):
        with self.assertRaises(ValueError):
            Workbench(self.root, self.root / "data", preview=FakePreview())
        self.assertEqual(0, self.app.board.snapshot()["revision"])
        self.app.close()
        new = Workbench(self.root, self.root / "data", preview=FakePreview())
        new.close()
    def test_old_pass_cannot_be_attributed_to_changed_candidate(self):
        from app import PROTOTYPE
        import hashlib
        refs = [PROTOTYPE + "/candidate/" + name for name in ("X2d2MenuBootstrap.qml", "X2d2MenuModel.qml", "X2d2MenuPage.qml")]
        refs.append(PROTOTYPE + "/check_delegate_receipt.py")
        before = {}
        for relative in refs:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"bound-input")
            before[str(path)] = {"sha256": hashlib.sha256(b"bound-input").hexdigest()}
        atomic_json(self.root / PROTOTYPE / "runs/candidate-test/RESULT.json", {"result": "PASS", "inputsBefore": before})
        self.assertEqual("PASS", self.app.evidence()["receipt"]["result"])
        (self.root / refs[0]).write_bytes(b"different-candidate")
        self.app.cache = {}
        result = self.app.evidence()["receipt"]
        self.assertEqual("UNMATCHED", result["result"])
        self.assertEqual("PASS", result["historicalResult"])
        self.assertFalse(result["candidateSourceMatched"])
    def test_corrupt_model_jobs_release_data_lock_without_overwrite(self):
        self.app.close()
        path = self.root / "data/models/jobs.json"
        path.write_bytes(b"broken-model-jobs")
        with self.assertRaises(ValueError):
            Workbench(self.root, self.root / "data", preview=FakePreview())
        self.assertEqual(b"broken-model-jobs", path.read_bytes())
        from app import DataLock
        lock = DataLock(self.root / "data")
        lock.close()


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.app = Workbench(root, root / "data", preview=FakePreview())
        self.server = Server(("127.0.0.1", 0), self.app)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)
        self.temp.cleanup()
    def request(self, method, path, body=None, extra=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        headers = {"Content-Type": "application/json"}
        if extra:
            headers.update(extra)
        connection.request(method, path, json.dumps(body) if body is not None else None, headers)
        response = connection.getresponse()
        data = response.read()
        connection.close()
        return response.status, data, dict(response.getheaders())
    def test_webpage_serves_and_state_has_explicit_limits(self):
        code, html, headers = self.request("GET", "/")
        self.assertEqual(200, code)
        self.assertIn("界面实验室", html.decode())
        self.assertIn('id="overview-camera-status"', html.decode())
        self.assertIn('id="overview-scan-camera"', html.decode())
        self.assertIn("七部分代码可浏览与编辑", html.decode())
        self.assertIn("由 Codex 或页面编辑器", html.decode())
        self.assertIn("机内通道尚未连接", html.decode())
        self.assertIn('src="/system.js"', html.decode())
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertIn("img-src 'self' data: blob:", headers["Content-Security-Policy"])
        code, raw, _ = self.request("GET", "/api/state")
        self.assertEqual(200, code)
        self.assertFalse(json.loads(raw)["evidence"]["installable"])
    def test_token_and_origin_are_required_for_changes(self):
        body = {"revision": 0, "text": "test"}
        self.assertEqual(403, self.request("POST", "/api/notes", body)[0])
        self.assertEqual(403, self.request("POST", "/api/notes", body, {"X-Session-Token": self.app.token, "Origin": "http://evil.example"})[0])
        self.assertEqual(0, self.app.board.snapshot()["revision"])
    def test_dns_rebinding_host_rejected(self):
        self.assertEqual(403, self.request("GET", "/api/state", extra={"Host": "evil.example"})[0])
    def test_real_http_write_and_conflict(self):
        headers = {"X-Session-Token": self.app.token}
        code, raw, _ = self.request("POST", "/api/tasks/entry", {"revision": 0, "state": "doing"}, headers)
        self.assertEqual(200, code)
        self.assertEqual(1, json.loads(raw)["revision"])
        self.assertEqual(409, self.request("POST", "/api/tasks/entry", {"revision": 0, "state": "done"}, headers)[0])
    def test_fake_preview_is_test_seam_not_image(self):
        self.assertEqual(404, self.request("GET", "/api/frame")[0])
        headers = {"X-Session-Token": self.app.token}
        self.assertEqual(400, self.request("POST", "/api/preview/start", {"mode": "fake-camera"}, headers)[0])
    def test_http_input_adapter_preserves_fixed_worker_protocol(self):
        headers = {"X-Session-Token": self.app.token}
        self.assertEqual(200, self.request("POST", "/api/preview/start", {"mode": "candidate"}, headers)[0])
        self.assertEqual(200, self.request("POST", "/api/preview/input", {"kind": "tap", "x": 20, "y": 30}, headers)[0])
        self.assertEqual({"type": "tap", "x": 20, "y": 30}, self.app.preview.last_event)
        self.assertEqual(400, self.request("POST", "/api/preview/input", {"kind": "back", "type": "tap"}, headers)[0])
    def test_rejected_preview_input_is_not_silently_successful(self):
        from unittest.mock import patch
        headers = {"X-Session-Token": self.app.token}
        with patch.object(self.app.preview, "send_input", return_value={"accepted": False, "error": "preview is not ready"}):
            code, raw, _ = self.request("POST", "/api/preview/input", {"kind": "back"}, headers)
        self.assertEqual(409, code)
        self.assertFalse(json.loads(raw)["accepted"])
        self.assertEqual("preview is not ready", json.loads(raw)["error"])
    def test_no_file_or_shell_endpoint(self):
        self.assertEqual(404, self.request("GET", "/../../AGENTS.md")[0])
        self.assertEqual(404, self.request("POST", "/api/exec", {"command": "anything"}, {"X-Session-Token": self.app.token})[0])
    def test_system_catalog_and_real_http_draft_save_reset_preserve_source(self):
        source = self.app.project / "qml/X2d2MenuBootstrap.qml"
        source.parent.mkdir(parents=True)
        original = b"Item {\n    property string name: 'original'\n}\n"
        source.write_bytes(original)
        code, raw, _ = self.request("GET", "/api/system/catalog")
        self.assertEqual(200, code)
        catalog = json.loads(raw)
        self.assertEqual(["ui", "control", "hardware", "imaging", "storage", "platform", "maintenance"],
                         [section["id"] for section in catalog["sections"]])
        code, raw, _ = self.request("GET", "/api/system/file?id=ui-bootstrap")
        self.assertEqual(200, code)
        baseline = json.loads(raw)
        body = {"id": baseline["id"], "baseSha256": baseline["baseSha256"], "revision": baseline["revision"],
                "text": baseline["text"].replace("original", "draft")}
        self.assertEqual(403, self.request("POST", "/api/system/save", body)[0])
        headers = {"X-Session-Token": self.app.token}
        self.assertEqual(403, self.request("POST", "/api/system/save", body,
                         {**headers, "Origin": "http://evil.example"})[0])
        code, raw, _ = self.request("POST", "/api/system/save", body, headers)
        self.assertEqual(200, code)
        draft = json.loads(raw)
        self.assertTrue(draft["draft"])
        self.assertIn("draft", draft["text"])
        self.assertEqual(baseline["text"], draft["originalText"])
        self.assertIn("+", draft["diff"])
        self.assertEqual(original, source.read_bytes())
        self.assertFalse(draft["deploymentQualified"])
        self.assertEqual(409, self.request("POST", "/api/system/save", body, headers)[0])
        self.assertEqual(400, self.request("POST", "/api/system/save", {**body, "path": "../secret"}, headers)[0])
        code, raw, _ = self.request("POST", "/api/system/reset", {"id": draft["id"],
                    "baseSha256": draft["baseSha256"], "revision": draft["revision"]}, headers)
        self.assertEqual(200, code)
        self.assertFalse(json.loads(raw)["draft"])
        self.assertEqual(original, source.read_bytes())
    def test_system_unknown_paths_and_unqualified_device_writes_are_rejected(self):
        self.assertEqual(400, self.request("GET", "/api/system/file?id=../../AGENTS.md")[0])
        code, raw, _ = self.request("GET", "/api/device/status")
        self.assertEqual(200, code)
        status = json.loads(raw)
        for operation in ("deploy", "load", "restore"):
            self.assertFalse(status["capabilities"][operation]["enabled"])
        headers = {"X-Session-Token": self.app.token}
        self.assertEqual(403, self.request("POST", "/api/device/action", {"operation": "connect"})[0])
        for body in ({"operation": "connect", "command": "id"}, {"operation": "deploy", "approved": True},
                     {"operation": "read", "component": "../../photos"}):
            self.assertEqual(400, self.request("POST", "/api/device/action", body, headers)[0])
        code, raw, _ = self.request("GET", "/system.js")
        self.assertEqual(200, code)
        self.assertIn(b"loadSystemCatalog", raw)
    def test_legal_text_json_expansion_and_unrelated_body_limit(self):
        source = self.app.project / "qml/X2d2MenuBootstrap.qml"
        source.parent.mkdir(parents=True)
        source.write_bytes(b"Item {}\n")
        baseline = self.app.system_code.read("ui-bootstrap")
        text = "\n" * 32_000
        body = {"id": baseline["id"], "baseSha256": baseline["baseSha256"],
                "revision": baseline["revision"], "text": text}
        headers = {"X-Session-Token": self.app.token}
        self.assertGreater(len(json.dumps(body).encode()), 48_000)
        code, raw, _ = self.request("POST", "/api/system/save", body, headers)
        self.assertEqual(200, code)
        self.assertEqual(text, json.loads(raw)["text"])
        self.assertEqual(b"Item {}\n", source.read_bytes())
        self.assertEqual(400, self.request("POST", "/api/notes", {"text": text * 2}, headers)[0])
    def test_shutdown_waits_for_inflight_draft_writer_before_unlocking(self):
        entered, release = threading.Event(), threading.Event()
        original_save = self.app.system_code.save
        def blocked_save(*args):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("test writer not released")
            return original_save(*args)
        source = self.app.project / "qml/X2d2MenuBootstrap.qml"
        source.parent.mkdir(parents=True)
        source.write_bytes(b"Item {}\n")
        baseline = self.app.system_code.read("ui-bootstrap")
        body = {"id": baseline["id"], "baseSha256": baseline["baseSha256"],
                "revision": baseline["revision"], "text": "Item { /* draft */ }\n"}
        headers = {"X-Session-Token": self.app.token}
        results = []
        with patch.object(self.app.system_code, "save", side_effect=blocked_save):
            request_thread = threading.Thread(target=lambda: results.append(self.request("POST", "/api/system/save", body, headers)))
            request_thread.start()
            self.assertTrue(entered.wait(3))
            self.server.shutdown()
            close_thread = threading.Thread(target=self.server.server_close)
            close_thread.start()
            self.assertFalse(self.app.data_lock.stream.closed)
            self.assertTrue(close_thread.is_alive())
            release.set()
            request_thread.join(5)
            close_thread.join(5)
        self.assertFalse(request_thread.is_alive())
        self.assertFalse(close_thread.is_alive())
        self.assertEqual(200, results[0][0])
        self.assertTrue(self.app.data_lock.stream.closed)
    def test_idle_http_keepalive_does_not_block_safe_shutdown(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=8)
        connection.request("GET", "/api/device/status")
        response = connection.getresponse()
        self.assertEqual(200, response.status)
        response.read()  # Leave the HTTP/1.1 connection open deliberately.
        self.server.shutdown()
        closing = threading.Thread(target=self.server.server_close)
        closing.start()
        closing.join(7)
        connection.close()
        self.assertFalse(closing.is_alive())
        self.assertTrue(self.app.data_lock.stream.closed)
    def test_repeated_camera_scans_publish_fresh_result_not_previous_failure(self):
        results = [
            {"status": "discovery_failed", "present": None, "instances": [], "debug_connected": False},
            {"status": "usb_identified", "present": True, "instances": [{"problem": 28}],
             "metadata": {"complete": False}, "debug_connected": False},
            {"status": "not_detected", "present": False, "instances": [], "debug_connected": False},
        ]
        headers = {"X-Session-Token": self.app.token}
        with patch("camera.discover", side_effect=results) as discovery:
            for expected in results:
                code, raw, _ = self.request("POST", "/api/camera/scan", {}, headers)
                self.assertEqual(200, code)
                self.assertEqual(expected, json.loads(raw))
                _, raw_state, _ = self.request("GET", "/api/state")
                state = json.loads(raw_state)
                self.assertEqual(expected, state["camera"])
                self.assertFalse(state["evidence"]["installable"])
        self.assertEqual(3, discovery.call_count)
    def test_sse_emits_fresh_state(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        connection.request("GET", "/api/events")
        response = connection.getresponse()
        self.assertEqual("text/event-stream; charset=utf-8", response.getheader("Content-Type"))
        self.assertEqual(b"event: state\n", response.readline())
        row = response.readline()
        value = json.loads(row[len(b"data: "):])
        self.assertEqual(0, value["board"]["revision"])
        self.assertNotIn("sessionToken", value)
        connection.close()


class CameraDisplayTests(unittest.TestCase):
    def overview(self, value, scanning=False, error=""):
        script = r"""
const fs=require('node:fs'),vm=require('node:vm');
const source=fs.readFileSync(process.argv[1],'utf8');
const start=source.indexOf('function cameraOverview(');
const end=source.indexOf('\nfunction renderCameraOverview',start);
if(start<0||end<0)throw Error('Missing actual overview function');
const context={};vm.createContext(context);
vm.runInContext(source.slice(start,end),context);
process.stdout.write(JSON.stringify(context.cameraOverview(...JSON.parse(process.argv[2]))));
"""
        result = subprocess.run(["node", "-e", script,
            str(Path(__file__).resolve().parent / "web/app.js"), json.dumps([value, scanning, error])],
            capture_output=True, text=True, encoding="utf-8", timeout=10, check=True)
        return json.loads(result.stdout)
    def test_homepage_identifies_usb_without_claiming_body_modification(self):
        view = self.overview({"status": "usb_identified", "present": True,
            "instances": [{"problem": 28}], "metadata": {"complete": False},
            "timestamp_utc": "started", "finished_utc": "finished", "debug_connected": True})
        self.assertEqual("相机已连接（USB 已识别）", view["title"])
        self.assertEqual("connected", view["tone"])
        self.assertEqual("finished", view["time"])
        self.assertIn("尚未验证机身代码读取、部署或加载", view["detail"])
        self.assertIn("1 个接口缺少驱动", view["detail"])
        self.assertIn("接口详情不完整", view["detail"])
    def test_homepage_unknown_absent_and_query_failure_are_distinct(self):
        self.assertEqual("尚未检测相机", self.overview({})["title"])
        absent = self.overview({"status": "not_detected", "present": False})
        self.assertEqual("未检测到相机", absent["title"])
        self.assertEqual("absent", absent["tone"])
        for status, present in [("discovery_failed", None), ("discovery_incomplete", None),
                                ("usb_identified", False), ("not_detected", True)]:
            with self.subTest(status=status):
                view = self.overview({"status": status, "present": present})
                self.assertEqual("相机连接状态未知", view["title"])
                self.assertEqual("unknown", view["tone"])
    def test_homepage_pending_and_failed_rescans_never_reuse_green_state(self):
        camera = {"status": "usb_identified", "present": True, "finished_utc": "previous scan"}
        pending = self.overview(camera, scanning=True)
        self.assertEqual("正在检测相机…", pending["title"])
        self.assertEqual("unknown", pending["tone"])
        failed = self.overview(camera, error="HTTP request failed")
        self.assertEqual("检测请求失败 · 连接状态未知", failed["title"])
        self.assertEqual("unknown", failed["tone"])
        self.assertEqual("HTTP request failed", failed["detail"])

    def test_both_actual_scan_handlers_share_lock_token_and_update_visible_state(self):
        script = r"""
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const nodes=new Map();
function node(id){if(!nodes.has(id))nodes.set(id,{textContent:'',className:'',dataset:{},disabled:false,
  handlers:{},options:[],classList:{add(){},remove(){}},append(){},replaceChildren(){},
  setAttribute(){},addEventListener(event,handler){this.handlers[event]=handler;}});return nodes.get(id);}
const camera={status:'usb_identified',present:true,finished_utc:'2026-10-08T00:00:00Z'};
const initial={sessionToken:'test-session-token',camera,board:{revision:0,tasks:[],notes:[]},
  evidence:{receipt:null,audit:{state:'unknown',progress:null,failuresObserved:0},remaining:[]},
  preview:{state:'not_started'},jobs:{allowed:[],current:null},models:{models:[],jobs:[],scope:'local only'}};
let mode='success',calls=0,release;
const context={document:{getElementById:node,createElement:()=>node('new'+nodes.size),
  querySelectorAll:()=>[],addEventListener(){}},setTimeout(){},clearTimeout(){},setInterval(){},
  EventSource:class{addEventListener(){}},fetch:async(path,options)=>{
    if(path==='/api/state')return {ok:true,json:async()=>initial};
    assert.equal(path,'/api/camera/scan');calls++;
    assert.equal(options.method,'POST');assert.equal(options.headers['X-Session-Token'],'test-session-token');
    assert.deepEqual(JSON.parse(options.body),{});
    await new Promise(resolve=>release=resolve);
    if(mode==='failure')throw Error('scan request failed');
    return {ok:true,json:async()=>({status:'not_detected',present:false,instances:[],finished_utc:'fresh scan'})};
  }};
vm.createContext(context);
const source=fs.readFileSync(process.argv[1],'utf8');
vm.runInContext(source.replace(/\nconnect\(\);\s*$/, ''),context);
(async()=>{
  await context.connect();
  assert.equal(node('live-status').textContent,'● 工作台已连接');
  assert.equal(node('overview-camera-status').textContent,'相机已连接（USB 已识别）');
  const overview=node('overview-scan-camera'),devices=node('scan-camera');
  assert.equal(overview.handlers.click,devices.handlers.click);
  const pending=overview.handlers.click();
  assert.equal(overview.disabled,true);assert.equal(devices.disabled,true);
  assert.equal(node('overview-camera-status').textContent,'正在检测相机…');
  assert.match(node('camera-detail').textContent,/^正在检测相机…/);
  assert.match(node('camera-detail').textContent,/上次检测快照（不代表当前状态）/);
  await devices.handlers.click();assert.equal(calls,1);
  release();await pending;
  assert.equal(node('overview-camera-status').textContent,'未检测到相机');
  assert.match(node('camera-detail').textContent,/未检测到 X2D II/);
  assert.match(node('overview-camera-time').textContent,/手动检测快照/);
  assert.equal(overview.disabled,false);assert.equal(devices.disabled,false);
  initial.camera=camera;context.accept(initial);mode='failure';
  const failed=devices.handlers.click();release();await failed;
  assert.equal(node('overview-camera-status').textContent,'检测请求失败 · 连接状态未知');
  assert.equal(node('camera-connection').dataset.state,'unknown');
  assert.match(node('camera-detail').textContent,/^检测请求失败 · 连接状态未知/);
  assert.match(node('camera-detail').textContent,/上次检测快照（不代表当前状态）/);
  assert.equal(overview.disabled,false);assert.equal(devices.disabled,false);
  mode='success';const retry=overview.handlers.click();release();await retry;
  assert.equal(node('overview-camera-status').textContent,'未检测到相机');
  assert.equal(calls,3);
})().catch(error=>{console.error(error);process.exitCode=1;});
"""
        result = subprocess.run(["node", "-e", script, str(Path(__file__).resolve().parent / "web/app.js")],
            capture_output=True, text=True, encoding="utf-8", timeout=10)
        self.assertEqual(0, result.returncode, result.stderr)

    def describe(self, value):
        script = r"""
const fs=require('node:fs'),vm=require('node:vm');
const source=fs.readFileSync(process.argv[1],'utf8');
const start=source.indexOf('function cameraDescription(');
const end=source.indexOf('\nfunction renderDevices',start);
if(start<0||end<0)throw Error('Missing actual camera display function');
const context={fmtTime:value=>value};
vm.createContext(context);
vm.runInContext(source.slice(start,end),context);
process.stdout.write(context.cameraDescription(JSON.parse(process.argv[2])));
"""
        result = subprocess.run(["node", "-e", script,
            str(Path(__file__).resolve().parent / "web/app.js"), json.dumps(value)],
            capture_output=True, text=True, encoding="utf-8", timeout=10, check=True)
        return result.stdout
    def test_missing_interface_drivers_and_metadata_do_not_hide_usb_presence(self):
        text = self.describe({"status": "usb_identified", "present": True,
            "instances": [{"problem": 28}, {"problem": "28"}, {"problem": 0}],
            "metadata": {"complete": False}, "debug_connected": False})
        self.assertIn("已识别 X2D II USB 设备", text)
        self.assertIn("2 个接口缺少驱动", text)
        self.assertIn("接口详情不完整；不影响 USB 识别", text)
        self.assertIn("调试和拍摄通道：尚未接入", text)
        self.assertNotIn("未检测到", text)
    def test_empty_query_and_failed_query_remain_distinct(self):
        absent = self.describe({"status": "not_detected", "present": False,
            "instances": [], "metadata": {"complete": False}, "debug_connected": False})
        failed = self.describe({"status": "discovery_failed", "present": None,
            "instances": [], "error": "设备识别超时", "debug_connected": False})
        self.assertIn("未检测到 X2D II", absent)
        self.assertNotIn("USB 已识别", absent)
        self.assertIn("设备查询失败，连接状态未知", failed)
        self.assertIn("设备识别超时", failed)


class ProcessTests(unittest.TestCase):
    def test_owned_process_exits_and_logs_real_output(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "out.log"
            with path.open("wb") as log:
                owned = ProcessJob([sys.executable, "-B", "-c", "print('owned-child')"], folder, log)
                try:
                    self.assertEqual(0, owned.process.wait(timeout=10))
                finally:
                    owned.close()
            self.assertIn("owned-child", path.read_text())


if __name__ == "__main__":
    unittest.main()
