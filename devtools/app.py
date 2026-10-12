"""Loopback X2D II workbench with local drafts and qualified device boundaries."""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import difflib
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit, parse_qs
import uuid
import webbrowser
from system_code import CodeConflict
from device_bridge import BridgeConflict

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent
AUDIT = "build/peer-route-review-20261007-host-model"
PROTOTYPE = "build/menu-ready-development-20261008"
TASK_STATES = {"todo", "doing", "blocked", "done"}
SOURCE_FILES = {
    "bootstrap": "qml/X2d2MenuBootstrap.qml",
    "model": "qml/X2d2MenuModel.qml",
    "page": "qml/X2d2MenuPage.qml",
    "candidate": PROTOTYPE + "/candidate/X2d2MenuBootstrap.qml",
}


def now():
    return datetime.now(timezone.utc).isoformat()


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2) + "\n").encode("utf-8")


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with temp.open("xb") as stream:
            stream.write(json_bytes(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def safe_file(root, relative):
    root = Path(root).resolve()
    path = root / relative
    if not path.resolve().is_relative_to(root):
        raise ValueError("路径不属于当前工程")
    if any(p.is_symlink() for p in [path, *path.parents] if p.is_relative_to(root)):
        raise ValueError("不读取链接文件")
    return path


def read_json(path, maximum=2_000_000):
    try:
        if path.stat().st_size > maximum:
            return {"readError": "文件超过读取上限"}
        value = json.loads(path.read_text(encoding="utf-8-sig"))
        return value if isinstance(value, dict) else {"readError": "不是对象"}
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as error:
        return {"readError": str(error)}


def tail(path, limit=24_000):
    try:
        with Path(path).open("rb") as stream:
            stream.seek(0, 2)
            size = stream.tell()
            stream.seek(max(0, size - limit))
            raw = stream.read(limit)
        if size > limit:
            raw = raw.partition(b"\n")[2]
        return raw.decode("utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def process_matches(pid, birth):
    """True/False/None; unknown never means running. Query only, never terminate."""
    if type(pid) is not int or type(birth) is not int or pid < 1:
        return None
    if os.name != "nt":
        return None
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        return False if ctypes.get_last_error() == 87 else None
    try:
        times = [wintypes.FILETIME() for _ in range(4)]
        if not kernel.GetProcessTimes(handle, *[ctypes.byref(t) for t in times]):
            return None
        return (times[0].dwHighDateTime << 32 | times[0].dwLowDateTime) == birth
    finally:
        kernel.CloseHandle(handle)


class DataLock:
    """One workbench owns this data directory, including on a different port."""
    def __init__(self, directory):
        self.stream = (Path(directory) / "workbench.lock").open("a+b")
        if self.stream.seek(0, 2) == 0:
            self.stream.write(b"\0")
            self.stream.flush()
        self.stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            self.stream.close()
            raise ValueError("该工程工作台已在运行，请使用已有窗口，不重复启动") from error

    def close(self):
        if self.stream.closed:
            return
        if os.name == "nt":
            import msvcrt
            self.stream.seek(0)
            msvcrt.locking(self.stream.fileno(), msvcrt.LK_UNLCK, 1)
        self.stream.close()


class Board:
    """Small persistent collaboration plan; states are not release evidence."""
    def __init__(self, data_root):
        self.path = Path(data_root) / "board.json"
        self.lock = threading.RLock()
        value = read_json(self.path)
        if value and "readError" in value:
            raise ValueError("任务文件损坏；保留原文件，不覆盖：" + value["readError"])
        self.value = value or {"revision": 0, "updatedUtc": now(), "notes": [], "tasks": [
            {"id": key, "title": title, "owner": "待分配", "state": "todo", "note": "", "heartbeatUtc": None}
            for key, title in (("entry", "菜单入口与点击"), ("page", "页面进入、返回与焦点"),
                              ("boot", "开机加载"), ("withdraw", "撤回与原厂恢复"),
                              ("live", "机身拍摄与保存未受影响"))]}
        if not value:
            atomic_json(self.path, self.value)

    def snapshot(self):
        with self.lock:
            return json.loads(json.dumps(self.value))

    def change(self, operation, body):
        with self.lock:
            if type(body.get("revision")) is not int or body["revision"] != self.value["revision"]:
                raise Conflict("任务已被其他窗口更新，请刷新后重试")
            updated = self.snapshot()
            if operation == "note":
                text = checked_text(body.get("text"), 4000, "记录内容")
                updated["notes"].append({"id": uuid.uuid4().hex, "text": text, "utc": now(),
                                         "author": checked_text(body.get("author", "用户"), 80, "作者")})
                updated["notes"] = updated["notes"][-200:]
            elif operation == "create":
                if len(updated["tasks"]) >= 100:
                    raise ValueError("任务数上限100")
                updated["tasks"].append({"id": uuid.uuid4().hex, "title": checked_text(body.get("title"), 160, "任务名称"),
                                         "owner": checked_text(body.get("owner", "待分配"), 80, "负责人"),
                                         "state": "todo", "note": "", "heartbeatUtc": None})
            else:
                task = next((t for t in updated["tasks"] if t["id"] == operation), None)
                if task is None:
                    raise ValueError("任务不存在")
                for field, limit in (("title", 160), ("owner", 80), ("note", 4000)):
                    if field in body:
                        task[field] = checked_text(body[field], limit, field, allow_empty=(field == "note"))
                if "state" in body:
                    if body["state"] not in TASK_STATES:
                        raise ValueError("未知任务状态")
                    task["state"] = body["state"]
                if body.get("heartbeat") is True:
                    task["heartbeatUtc"] = now()
            updated.update(revision=updated["revision"] + 1, updatedUtc=now())
            atomic_json(self.path, updated)
            self.value = updated
            return self.snapshot()


class Conflict(ValueError):
    pass


def checked_text(value, maximum, field, allow_empty=False):
    if not isinstance(value, str) or len(value) > maximum or (not allow_empty and not value.strip()):
        raise ValueError(field + "不能为空或过长")
    return value.strip()


class ProcessJob:
    """Own a process tree, so Stop cannot target a historical or foreign PID."""
    def __init__(self, command, cwd, log):
        self.job = None
        self.process = None
        if os.name == "nt":
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            class Basic(ctypes.Structure):
                _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                            ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                            ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                            ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]
            class Io(ctypes.Structure):
                _fields_ = [(n, ctypes.c_uint64) for n in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount", "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]
            class Extended(ctypes.Structure):
                _fields_ = [("BasicLimitInformation", Basic), ("IoInfo", Io), ("ProcessMemoryLimit", ctypes.c_size_t),
                            ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]
            kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
            kernel.CreateJobObjectW.restype = wintypes.HANDLE
            kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
            kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
            kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
            kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            self.kernel = kernel
            self.job = kernel.CreateJobObjectW(None, None)
            if not self.job:
                raise ctypes.WinError(ctypes.get_last_error())
            limits = Extended()
            limits.BasicLimitInformation.LimitFlags = 0x2000
            if not kernel.SetInformationJobObject(self.job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
                self.close()
                raise RuntimeError("无法建立自有检查进程边界")
        try:
            self.process = subprocess.Popen(command, cwd=cwd, stdout=log, stderr=subprocess.STDOUT,
                                            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                                            start_new_session=(os.name != "nt"),
                                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
            if self.job and not self.kernel.AssignProcessToJobObject(self.job, int(self.process._handle)):
                self.process.kill()
                self.process.wait()
                raise RuntimeError("无法约束自有检查进程；已停止，不继续运行")
        except BaseException:
            self.close()
            raise

    def stop(self):
        if self.job:
            self.kernel.TerminateJobObject(self.job, 1)
        elif self.process and self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGTERM)

    def close(self):
        if self.job:
            self.kernel.CloseHandle(self.job)
            self.job = None


class Jobs:
    def __init__(self, project, data_root):
        self.project, self.root = Path(project), Path(data_root) / "jobs"
        self.lock, self.record, self.owned = threading.RLock(), None, None
        self.allowed = {
            "tool-tests": {"label": "开发者工具自身测试", "command": [sys.executable, "-B", "-m", "unittest", "discover", "-s", str(HERE), "-p", "test_*.py"], "timeout": 90},
            "menu-receipt": {"label": "本地菜单加载与失效检查", "command": [sys.executable, "-B", str(self.project / PROTOTYPE / "check_delegate_receipt.py"), "candidate"], "timeout": 90},
        }

    def snapshot(self):
        with self.lock:
            record = dict(self.record) if self.record else None
            if record:
                record["elapsedSeconds"] = round(time.monotonic() - self.started, 1) if record["state"] == "running" else record.get("durationSeconds")
            return {"allowed": [{"id": k, "label": v["label"]} for k, v in self.allowed.items()], "current": record}

    def start(self, key):
        with self.lock:
            if key not in self.allowed:
                raise ValueError("只允许界面列出的本地检查")
            if self.record and self.record["state"] == "running":
                raise Conflict("已有一项检查正在运行，不重复启动")
            spec = self.allowed[key]
            if key == "menu-receipt" and not Path(spec["command"][2]).is_file():
                raise ValueError("菜单候选检查器不存在")
            folder = self.root / uuid.uuid4().hex
            folder.mkdir(parents=True)
            self.started = time.monotonic()
            self.record = {"id": folder.name, "kind": key, "label": spec["label"], "state": "running", "startedUtc": now(),
                           "exitCode": None, "logPath": str(folder / "output.log"), "installable": False, "cameraAccesses": 0}
            thread = threading.Thread(target=self._run, args=(spec, folder, self.record, self.started), daemon=True)
            thread.start()
            return self.snapshot()

    def _run(self, spec, folder, record, started):
        terminal = {}
        try:
            with (folder / "output.log").open("wb", buffering=0) as log:
                owned = ProcessJob(spec["command"], self.project, log)
                with self.lock:
                    self.owned = owned
                    record["pid"] = owned.process.pid
                try:
                    code = owned.process.wait(timeout=spec["timeout"])
                    state = "stopped" if record.get("stopRequested") else ("passed" if code == 0 else "failed")
                except subprocess.TimeoutExpired:
                    owned.stop()
                    code = owned.process.wait(timeout=10)
                    state = "timeout"
                finally:
                    owned.close()
            terminal.update(state=state, exitCode=code)
        except Exception as error:
            terminal.update(state="failed", error=str(error))
        finally:
            with self.lock:
                record.update(terminal, finishedUtc=now(), durationSeconds=round(time.monotonic() - started, 1))
                self.owned = None
                atomic_json(folder / "result.json", record)

    def stop(self):
        with self.lock:
            if not self.record or self.record["state"] != "running" or self.owned is None:
                raise Conflict("没有可停止的自有检查进程")
            self.record["stopRequested"] = True
            self.owned.stop()
            return self.snapshot()


class Workbench:
    def __init__(self, project=PROJECT, data_root=None, preview=None):
        self.project = Path(project).resolve()
        self.data = Path(data_root or HERE / "data").resolve()
        if data_root is None and self.data != Path(os.path.abspath(HERE / "data")):
            raise ValueError("工作台数据目录不可重定向到工程之外")
        self.data.mkdir(parents=True, exist_ok=True)
        self.data_lock = DataLock(self.data)
        try:
            self.board, self.jobs = Board(self.data), Jobs(self.project, self.data)
            if preview is None:
                from preview import PreviewController
                preview = PreviewController(self.project, self.data)
            from local_models import LocalModels
            self.models = LocalModels(self.data, self.source, atomic_json)
            from system_code import SystemCode
            from device_bridge import DeviceBridge
            self.system_code = SystemCode(self.project, self.data)
            self.device_bridge = DeviceBridge(self.project, self.data)
        except BaseException:
            self.data_lock.close()
            raise
        self.preview = preview
        self.camera_state = {"status": "not-scanned", "instances": [], "debug_connected": False}
        self.camera_lock = threading.RLock()
        self.token = secrets.token_urlsafe(32)
        self.cache = {}
        self.cache_lock = threading.Lock()

    def audit(self, probe=process_matches):
        folder = safe_file(self.project, AUDIT)
        final = read_json(folder / "AUDIT.json")
        start = read_json(folder / "suite.start.json") or {}
        log = tail(folder / "suite.output.log")
        percentages = re.findall(r"\[\s*(\d{1,3})%\]", log)
        alive = probe(start.get("pid"), start.get("birth_filetime_100ns"))
        state = "finished" if final and "readError" not in final else "running" if alive is True else "incomplete" if alive is False else "unknown"
        return {"state": state, "progress": int(percentages[-1]) if percentages else None,
                "pid": start.get("pid"), "failuresObserved": len(list(folder.glob("failure-*.json"))),
                "result": final.get("status") if final else None,
                "qualified": False, "note": "旧候选全量检查；不代表当前候选通过，不授予安装资格。", "path": AUDIT}

    def evidence(self):
        with self.cache_lock:
            if time.monotonic() - self.cache.get("time", -100) < 4:
                return self.cache["value"]
            run_root = safe_file(self.project, PROTOTYPE + "/runs")
            paths = sorted(run_root.glob("candidate-*/RESULT.json"), key=lambda p: p.stat().st_mtime, reverse=True) if run_root.exists() else []
            result = read_json(paths[0]) if paths else None
            receipt = None
            if result:
                receipt = {key: result.get(key) for key in ("result", "failure", "finishedUtc", "workerPid", "workerExitCode", "processExitVerified", "sourceInputsUnchanged")}
                receipt["path"] = paths[0].relative_to(self.project).as_posix()
                receipt["scope"] = "桌面 Qt 菜单观察，不是 ARM64 或机身验收"
                refs = [PROTOTYPE + "/candidate/" + name for name in ("X2d2MenuBootstrap.qml", "X2d2MenuModel.qml", "X2d2MenuPage.qml")]
                refs.append(PROTOTYPE + "/check_delegate_receipt.py")
                before = result.get("inputsBefore", {})
                matched = True
                for relative in refs:
                    source = safe_file(self.project, relative)
                    recorded = before.get(str(source), {}).get("sha256")
                    if recorded is None or not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest() != recorded:
                        matched = False
                        break
                receipt["candidateSourceMatched"] = matched
                receipt["bindingScope"] = "本地候选三项QML和检查器；不是完整发布身份核验"
                if not matched:
                    receipt["historicalResult"] = receipt["result"]
                    receipt["result"] = "UNMATCHED"
            value = {"audit": self.audit(), "receipt": receipt, "installable": False,
                     "candidateLabel": "菜单扩展本地候选", "cameraState": "只读设备识别；不自动开启调试或写入",
                     "remaining": ["当前候选真实入口点击与页面返回", "目标机身加载与日志路径", "开机加载与撤回", "原厂拍摄和保存不受影响", "适用完整发布检查"]}
            self.cache = {"time": time.monotonic(), "value": value}
            return value

    def snapshot(self, include_token=False):
        result = {"utc": now(), "board": self.board.snapshot(), "jobs": self.jobs.snapshot(),
                  "preview": self.preview_status(), "evidence": self.evidence(),
                  "project": str(self.project), "camera": self.camera_snapshot(), "models": self.models.snapshot(),
                  "deviceBridge": self.device_bridge.status(),
                  "reference": {"url": "https://github.com/derrickyau9/Hasselblad-X-System-QEMU-DevKit", "commit": "d82dc3b0faa6456c260378df6352a07f929caed2",
                                "mode": "本工具为桌面 Qt 预览；QEMU 引擎未集成，拍摄/AF/真实存储不模拟"}}
        if include_token:
            result["sessionToken"] = self.token
        return result

    def camera_snapshot(self):
        with self.camera_lock:
            return dict(self.camera_state)

    def scan_camera(self):
        from camera import discover
        value = discover()
        with self.camera_lock:
            self.camera_state = value
        return value

    def preview_status(self):
        value = dict(self.preview.status())
        value["pid"] = value.get("worker_pid", value.get("pid"))
        value["receipt"] = value.get("latest_delegate_receipt", value.get("receipt"))
        session = value.get("session_dir")
        if session:
            value["logPath"] = str(Path(session) / "preview.log")
        if value.get("phase") == "stopped" and value.get("state") == "not_started":
            value["state"] = "stopped"
        return value

    def source(self, key):
        if key not in SOURCE_FILES:
            raise ValueError("未知源码项")
        path = safe_file(self.project, SOURCE_FILES[key])
        if path.stat().st_size > 200_000:
            raise ValueError("源码过大")
        raw = path.read_bytes()
        return {"name": SOURCE_FILES[key], "sha256": hashlib.sha256(raw).hexdigest(), "text": raw.decode("utf-8-sig")}

    def diff(self):
        old, new = self.source("bootstrap"), self.source("candidate")
        return {"oldSha": old["sha256"], "newSha": new["sha256"], "text": "".join(difflib.unified_diff(
            old["text"].splitlines(True), new["text"].splitlines(True), fromfile=old["name"], tofile=new["name"]))}

    def log(self, key):
        if key == "audit":
            return tail(safe_file(self.project, AUDIT + "/suite.output.log"))
        if key == "preview":
            value = self.preview_status()
            path = value.get("logPath")
            if path:
                candidate = Path(path).resolve()
                if not candidate.is_relative_to(self.data):
                    raise ValueError("预览日志超出本工具数据目录")
                return tail(candidate)
            return "尚未启动界面预览。"
        if key == "job":
            current = self.jobs.snapshot()["current"]
            return tail(current["logPath"]) if current else "尚未运行本地检查。"
        raise ValueError("未知日志项")

    def close(self):
        # First prevent local workers from publishing into shared data. Only
        # then may a terminated device transaction release directory ownership.
        self.models.close()
        self.preview.stop()
        try:
            self.jobs.stop()
        except Conflict:
            pass
        self.device_bridge.close(on_idle=self.data_lock.close)


class Server(ThreadingHTTPServer):
    # server_close joins in-flight API writers before releasing the DataLock.
    # SSE loops exit on stopping, so this does not leave a permanent stream.
    daemon_threads = False
    allow_reuse_address = False
    def __init__(self, address, workbench):
        if address[0] != "127.0.0.1":
            raise ValueError("只允许127.0.0.1")
        self.workbench, self.stopping = workbench, threading.Event()
        super().__init__(address, Handler)

    def server_close(self):
        self.stopping.set()
        super().server_close()
        self.workbench.close()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 5  # Bound idle keepalive/partial-body clients during shutdown.
    def log_message(self, format, *args):
        pass

    def allowed(self, write=False):
        if self.server.stopping.is_set():
            self.respond(503, {"error": "工作台正在关闭，不接受新请求"})
            return False
        port = self.server.server_port
        hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        if self.headers.get("Host") not in hosts:
            self.respond(403, {"error": "拒绝非本地Host"})
            return False
        origin = self.headers.get("Origin")
        if origin and origin not in {"http://" + h for h in hosts}:
            self.respond(403, {"error": "拒绝跨站请求"})
            return False
        if write and not secrets.compare_digest(self.headers.get("X-Session-Token", ""), self.server.workbench.token):
            self.respond(403, {"error": "缺少当前会话授权"})
            return False
        return True

    def respond(self, code, value, content_type="application/json; charset=utf-8"):
        raw = json_bytes(value) if isinstance(value, (dict, list)) else value
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        if code >= 400:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if not self.allowed():
            return
        url = urlsplit(self.path)
        app = self.server.workbench
        try:
            if url.path in ("/", "/app.js", "/system.js", "/timeline.js", "/style.css"):
                name = {"/": "index.html", "/app.js": "app.js", "/system.js": "system.js", "/timeline.js": "timeline.js", "/style.css": "style.css"}[url.path]
                kind = {"index.html": "text/html; charset=utf-8", "app.js": "text/javascript; charset=utf-8", "system.js": "text/javascript; charset=utf-8", "timeline.js": "text/javascript; charset=utf-8", "style.css": "text/css; charset=utf-8"}[name]
                return self.respond(200, (HERE / "web" / name).read_bytes(), kind)
            if url.path == "/api/state":
                return self.respond(200, app.snapshot(include_token=True))
            if url.path == "/api/events":
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                while not self.server.stopping.is_set():
                    raw = json.dumps(app.snapshot(), ensure_ascii=False, allow_nan=False)
                    self.wfile.write(("event: state\ndata: " + raw + "\n\n").encode("utf-8"))
                    self.wfile.flush()
                    self.server.stopping.wait(1)
                return
            if url.path == "/api/frame":
                if callable(getattr(app.preview, "frame_bytes", None)):
                    raw = app.preview.frame_bytes()
                    if raw is None:
                        return self.respond(404, {"error": "暂无真实预览画面"})
                    return self.respond(200, raw, "image/png")
                path = app.preview.frame_path()
                if path is None:
                    return self.respond(404, {"error": "暂无真实预览画面"})
                resolved = path.resolve()
                if not resolved.is_relative_to(app.data) or path.is_symlink():
                    raise ValueError("预览画面路径不属于本工具")
                return self.respond(200, path.read_bytes(), "image/png")
            query = parse_qs(url.query)
            if url.path == "/api/system/catalog":
                return self.respond(200, app.system_code.catalog())
            if url.path == "/api/system/file":
                return self.respond(200, app.system_code.read(query.get("id", [""])[0]))
            if url.path == "/api/device/status":
                return self.respond(200, app.device_bridge.status())
            if url.path == "/api/device/timeline":
                return self.respond(200, app.device_bridge.status().get("monitor", {}))
            if url.path == "/api/device/history":
                if not self.allowed(write=True):
                    return
                from timeline_history import history_query
                session_id, before, limit = history_query(url.query)
                return self.respond(200, app.device_bridge.history(session_id, before=before, limit=limit))
            if url.path == "/api/source":
                return self.respond(200, app.source(query.get("id", [""])[0]))
            if url.path == "/api/diff":
                return self.respond(200, app.diff())
            if url.path == "/api/log":
                return self.respond(200, {"text": app.log(query.get("id", [""])[0])})
            if url.path == "/api/model-task":
                return self.respond(200, app.models.detail(query.get("id", [""])[0]))
            return self.respond(404, {"error": "接口不存在"})
        except ConnectionError:
            pass
        except (CodeConflict, BridgeConflict) as error:
            self.respond(409, {"error": str(error)})
        except (OSError, ValueError) as error:
            if url.path != "/api/events":
                self.respond(400, {"error": str(error)})

    def do_POST(self):
        if not self.allowed(write=True):
            return
        try:
            if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                raise ValueError("只接收JSON")
            length = int(self.headers.get("Content-Length", "0"))
            path = urlsplit(self.path).path
            # JSON can expand a 32 KB text sixfold (control characters).
            # Keep every unrelated interface at its existing 48 KB bound.
            maximum = 200_000 if path == "/api/system/save" else 48_000
            if not 0 < length <= maximum:
                raise ValueError("请求大小不合法")
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError("请求必须是对象")
            app = self.server.workbench
            if path == "/api/tasks":
                result = app.board.change("create", body)
            elif re.fullmatch(r"/api/tasks/[a-zA-Z0-9_-]+", path):
                result = app.board.change(path.rsplit("/", 1)[1], body)
            elif path == "/api/notes":
                result = app.board.change("note", body)
            elif path == "/api/jobs/start":
                result = app.jobs.start(body.get("id"))
            elif path == "/api/jobs/stop":
                result = app.jobs.stop()
            elif path == "/api/preview/start":
                result = app.preview.start(body.get("mode", "stock"))
            elif path == "/api/preview/stop":
                result = app.preview.stop()
            elif path == "/api/preview/input":
                if "kind" in body:
                    if "type" in body:
                        raise ValueError("输入不能同时指定kind和type")
                    body = {("type" if k == "kind" else k): v for k, v in body.items()}
                result = app.preview.send_input(body)
                if result.get("accepted") is False:
                    return self.respond(409, result)
            elif path == "/api/camera/scan":
                result = app.scan_camera()
            elif path in ("/api/system/save", "/api/system/reset"):
                allowed = {"id", "baseSha256", "revision"} | ({"text"} if path.endswith("save") else set())
                if set(body) != allowed:
                    raise ValueError("代码修改只接受文件ID、原文哈希、版本及修改文本")
                if path.endswith("save"):
                    result = app.system_code.save(body["id"], body["text"], body["baseSha256"], body["revision"])
                else:
                    result = app.system_code.reset(body["id"], body["baseSha256"], body["revision"])
            elif path == "/api/device/action":
                result = app.device_bridge.start(body.get("operation"), body)
            elif path == "/api/models/probe":
                result = app.models.probe(body.get("endpoint"))
            elif path == "/api/models/submit":
                result = app.models.submit(body.get("prompt"), body.get("source", "candidate"), body.get("model"))
            else:
                return self.respond(404, {"error": "接口不存在"})
            self.respond(200, result)
        except (Conflict, CodeConflict, BridgeConflict) as error:
            self.respond(409, {"error": str(error)})
        except (OSError, ValueError, RuntimeError, TypeError) as error:
            self.respond(400, {"error": str(error)})


def main():
    parser = argparse.ArgumentParser(description="X2D II 本地开发工作台（代码副本与受控机内接入）")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--open", action="store_true", help="在默认浏览器打开工作台")
    options = parser.parse_args()
    app = Workbench()
    try:
        server = Server(("127.0.0.1", options.port), app)
    except OSError as error:
        app.close()
        raise SystemExit("工作台端口已占用或不可用：" + str(error))
    url = f"http://127.0.0.1:{server.server_port}"
    atomic_json(app.data / "connection.json", {"url": url, "token": app.token, "pid": os.getpid(), "startedUtc": now()})
    print("X2D II 开发工作台：" + url, flush=True)
    print("仅本地；任务登记≠实机验证；Ctrl+C关闭。", flush=True)
    if options.open:
        webbrowser.open(url)
    try:
        server.serve_forever(poll_interval=.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
