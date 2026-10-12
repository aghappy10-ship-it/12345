"""Explicit asynchronous bridge to reviewed, fixed device routes.

Construction/status never contact a camera. Read jobs use live_readout.query,
not its CLI/collector. Writes require a server-owned PreparedExecution and the
existing publication validators/run_qualified; HTTP data is never authority.
Boot activation is NOT proof of current GUI loading or lifecycle qualification.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import base64
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import threading
import time
from types import FunctionType, MappingProxyType, ModuleType
import uuid

PROJECT = Path(__file__).resolve().parents[1]
MAX_TEXT_BYTES = 512 * 1024
MAX_RAW_BYTES = 2 * 1024 * 1024 + 8192
PREVIEW_CHARS = 8000
LOG_TAIL_BYTES = 16384
LOG_CHUNK_BYTES = 65536
LOG_ANCHOR_BYTES = 64
MAX_JOURNAL_EVENTS = 200
MONITOR_INTERVAL_SECONDS = 1
MAX_MONITOR_SECONDS = 8 * 60 * 60
MAX_MONITOR_BYTES = 2 * 1024 ** 3
MAX_RECONNECT_SECONDS = 120
MIN_MONITOR_FREE_BYTES = 1024 * 1024
LOG_PATH = "/blackbox/camera/log/cam.log"
# 150 ASCII bytes plus the reviewed query's nonce/exit envelope fit its
# 232-byte text slot. && ensures a final cat cannot hide a denied stat/tail.
TIMELINE_COMMAND = ("b=/proc/sys/kernel/random/boot_id;p=/blackbox/camera/log/cam.log;"
    "cat $b&&stat -c '%i %s' $p&&tail -c 16384 $p&&printf '\\n'&&stat -c '%i %s' $p&&cat $b")
# Pin each range to an opened descriptor. ASCII base64 preserves bytes across the
# existing transport's individually decoded UTF-8 packets. No HTTP arguments.
STREAM_PREFIX = ("b=/proc/sys/kernel/random/boot_id;exec 3</blackbox/camera/log/cam.log;"
    "s(){ cat $b&&stat -Lc'%i %s' /proc/$$/fd/3;};")


def _timeline_command(offset):
    if offset is None:
        return STREAM_PREFIX + "s&&s"
    if type(offset) is not int or not 0 <= offset < 2 ** 63:
        raise ValueError("日志读取偏移不是合法的后端整数")
    # head intentionally terminates its tail producer after a bounded range.
    # Do not use pipefail: tail can legitimately receive SIGPIPE. Acceptance
    # instead requires the complete native envelope, strict base64, opened-fd
    # identity and exact size bounds below; empty/short/error output is rejected.
    return STREAM_PREFIX + f"s&&tail -c+{offset + 1} <&3|head -c{LOG_CHUNK_BYTES}|base64&&s"

PROFILES = {
    "ui": {"label": "界面菜单", "queries": ("gui_hash", "gui_init"),
           "scope": "原厂GUI摘要和启动配置文本；不是完整QML反编译"},
    "control": {"label": "相机控制", "queries": ("single_service_hash", "single_service_pid"),
                "scope": "拍摄服务文件摘要与PID；不触发曝光或改变参数"},
    "hardware": {"label": "硬件采集", "queries": ("single_sensor_hash",),
                 "scope": "传感器配置摘要；不读取校准或修改硬件"},
    "imaging": {"label": "图像处理", "queries": ("service_hash",),
                "scope": "现有拍摄服务/传感器配置身份；ISP/DSP代码读取尚未接入"},
    "storage": {"label": "保存与持久化", "queries": ("mounts",),
                "scope": "内核挂载状态摘要；不读取照片、校准或存储内容"},
    "platform": {"label": "基础系统与安全", "queries": ("selinux_policy",),
                 "scope": "安全策略状态及摘要；不改变SELinux/TEE权限"},
    "maintenance": {"label": "连接维护升级", "queries": ("transport_hash", "adb_state"),
                    "scope": "维护组件摘要及USB/ADB状态；不启用ADB或切换USB"},
}
WRITE_OPERATIONS = ("deploy", "load", "restore")
LABELS = {"connect": "连接机内只读通道", "read": "读取固定组件摘要",
          "qualification": "检查资格与执行接线", "deploy": "经哈希绑定的合格候选四文件放置；不自动包含本地草稿",
          "load": "合格启动配置激活（不证明当前GUI已加载）", "restore": "独立恢复原厂启动/清理已拥有文件",
          "monitor-start": "开启固定机内日志采样", "monitor-stop": "停止机内日志采样"}


def _now():
    return datetime.now(timezone.utc).isoformat()


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _json(value):
    return (json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2) + "\n").encode("utf-8")


def _guard(path, root):
    """Reject redirects/hardlinks in the literal server-selected evidence root."""
    path, root = Path(os.path.abspath(path)), Path(os.path.abspath(root))
    if not path.is_relative_to(root):
        raise ValueError("设备桥证据路径超出本地数据目录")
    for current in reversed((path, *path.parents)):
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("设备桥不使用链接/重定向证据路径")
        if current != path and not stat.S_ISDIR(info.st_mode):
            raise ValueError("设备桥证据父路径不是目录")
        if current == path and stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise ValueError("设备桥不使用硬链接证据文件")
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("设备桥证据路径已重定向")
    return path


@dataclass(frozen=True)
class PreparedExecution:
    """Trusted local provider only; never deserialize this from HTTP JSON.

    The prepared operation/observer/window must already come from the existing
    workflow. This bridge does not create an ADB lease or prepare an observer.
    """
    operation: object
    launch_report: bytes
    maintenance_session: object
    start_process: object
    qualification: dict
    window_authorization: dict
    saved_manifest: object = None
    saved_manifest_sha256: str | None = None


class BridgeConflict(ValueError):
    pass


class BridgeBlocked(ValueError):
    def __init__(self, reason, missing):
        super().__init__(reason)
        self.missing = list(missing)


class MonitorStopped(ValueError):
    pass


class MonitorLimit(ValueError):
    pass


class LogRangeFailed(ValueError):
    """A retained nonzero range read; only proven source change may recover."""


class LogTransportInterrupted(ValueError):
    """Retained incomplete transport result; never accepted as a valid read."""


def _transport_interrupted(error):
    # Only known transport termination, not arbitrary errors/messages. The
    # reviewed decoder checks every completed record before these stop reasons.
    # Bad checksums/duplicate completion/nonzero terminal remain fatal.
    receive = getattr(error, 'receive', None)
    if type(receive) is dict and receive:
        return receive.get('terminal_count') == 0 and receive.get('completion_line_count') in (0, 1) and receive.get('stop_reason') in (
            'socket_timeout', 'deadline', 'peer_eof', 'connection_reset', 'connection_aborted')
    cause = error
    while cause is not None:
        if isinstance(cause, (TimeoutError, ConnectionError)):
            return True
        if isinstance(cause, OSError) and (cause.errno in (51, 60, 61, 64, 65, 101, 110, 111, 113) or
                getattr(cause, 'winerror', None) in (10051, 10060, 10061, 10064, 10065)):
            return True
        cause = cause.__cause__
    return False


class _MonitorQueryCount:
    """Keep unique evidence sequence numbers, not hours of saved previews."""
    __slots__ = ("count",)

    def __init__(self):
        self.count = 0

    def __len__(self):
        return self.count

    def append(self, _record):
        self.count += 1  # Original records are already persisted by _query.


class _FixedReader:
    incremental_log = True

    def __init__(self, bridge):
        self.live = bridge._module("live_readout")
        self.transport = self.live.load_transport()
        self._base_sources = self.live.source_hashes()
        self.bridge_source = Path(__file__)
        self.log_offset = None
        self.sources = {**self._base_sources, "bridgeSha256": _sha(self.bridge_source.read_bytes()),
                        "bridgeSourceScope": "disk-snapshot-at-reader-construction-not-loaded-class-attestation",
                        "timelineQuerySha256": _sha((_timeline_command(None) + '\n' + _timeline_command(2 ** 63 - 1)).encode("ascii"))}

    def query(self, name):
        if name in ("timeline_log", "timeline_meta"):
            # Reuse the exact reviewed function/decoder, with a private literal
            # query table. Never mutate the original module's QUERIES or accept
            # a command/path/limit from HTTP. This is not a new shell executor.
            original = self.live.query
            offset = self.log_offset if name == "timeline_log" else None
            private_globals = {**original.__globals__, "QUERIES": MappingProxyType({name: _timeline_command(offset)})}
            query = FunctionType(original.__code__, private_globals, original.__name__, original.__defaults__)
            query.__kwdefaults__ = original.__kwdefaults__
            return query(name, self.transport, timeout=8)
        return self.live.query(name, self.transport, timeout=8)

    def check_unchanged(self):
        if (_sha(self.live.TRANSPORT.read_bytes()) != self.live.TRANSPORT_SHA or
                self._base_sources != self.live.source_hashes() or
                self.sources["bridgeSha256"] != _sha(self.bridge_source.read_bytes())):
            raise ValueError("固定读取来源在运行中改变；结果不得作为当前证据")


def _identity(text):
    """Accept observed missing newline/single domain NUL, not arbitrary stripping."""
    match = re.fullmatch(
        r"uid=([0-9]+)\([^\r\n]*\)[^\r\n]*\r?\n"
        r"(u:r:[a-z0-9_]+:s0)(?:\x00)?(?:\r?\n)?"
        r"([^\r\n\x00]{1,160})\r?\n([^\r\n\x00]{1,80})\r?\n"
        r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\r?\n?", text)
    if match is None:
        raise ValueError("机内身份回复格式不完整或未知；不推断权限")
    uid, domain, model, firmware, boot_id = match.groups()
    if model not in ("Android HB722 on Eagle2 HB722", "X2D II 100C", "Hasselblad X2D II 100C"):
        raise ValueError("机内实际型号不属于已研究的二代平台：" + model)
    return {"uid": int(uid), "domain": domain, "model": model, "firmware": firmware,
            "bootId": boot_id, "installationPermissionVerified": False}


class DeviceBridge:
    def __init__(self, project, data_root, *, reader_factory=None, execution_provider=None, timeline_factory=None, clock=None):
        self.project = Path(project).resolve()
        self.data_root = Path(os.path.abspath(data_root))
        self.root = _guard(self.data_root / "device-bridge", self.data_root)
        self.lock = threading.RLock()
        self.reader_factory, self.execution_provider = reader_factory, execution_provider
        self.test_fixture = reader_factory is not None or timeline_factory is not None
        self.timeline_factory, self.clock = timeline_factory, clock or time.monotonic
        self.monitor_stop = threading.Event()
        self._history_segment_index = 0
        self._monitor_folder, self._monitor_bytes = None, 0
        self.monitor = {"state": "stopped", "active": False, "reason": "日志采样未开启；不自动开启",
            "error": None, "sessionId": None, "evidencePath": None, "timeline": None,
            "scope": "固定cam.log只读增量补读；轮转/覆盖仍可能漏事件，不证明七层全链路或物理成片",
            "path": LOG_PATH, "intervalSeconds": 1,
            "maxSeconds": MAX_MONITOR_SECONDS, "maxEvidenceBytes": MAX_MONITOR_BYTES,
            "chunkBytes": LOG_CHUNK_BYTES, "readOffset": None, "backlogBytes": 0,
            "retainedBytes": 0, "polls": 0, "elapsedSeconds": 0, "sourceKind": "manual-live-fixed-byte-range",
            "historyEventCount": 0, "reconnectAttempts": 0, "totalReconnects": 0,
            "bytesRead": 0, "readBytesPerSecond": 0, "backlogTrend": "steady",
            "lastSuccessfulReadUtc": None, "maxReconnectSeconds": MAX_RECONNECT_SECONDS,
            "readState": "not-started",
            "logMayContainPhotoNames": True, "photosPixelsRead": False}
        self.closed, self.thread = False, None
        self._idle_callback, self._idle_watcher = None, None
        self._idle_callback_done, self._idle_callback_error = False, None
        self.state, self.connected = "not-connected", False
        self.reason = "尚未通过机内固定查询建立连接；USB枚举不是此通道的证明"
        self.identity, self.current, self.last_read = None, None, {}
        self.latest_read_component = None
        self.qualification = {"state": "not-checked", "routes": {}}

    def _module(self, name):
        # Names are developer literals only. Do not load an unrelated tools package.
        if str(self.project) not in sys.path:
            sys.path.insert(0, str(self.project))
        module = importlib.import_module("tools." + name)
        if Path(module.__file__).resolve().parent != self.project / "tools":
            raise ValueError("设备桥工具模块不属于当前活动工程")
        return module

    def status(self):
        with self.lock:
            active = bool(self.thread and self.thread.is_alive())
            caps = {"read": {"implemented": True, "enabled": not self.closed and not active,
                            "scope": "固定只读组件摘要；不是任意文件或完整机身源码", "reason": self.reason}}
            for name in WRITE_OPERATIONS:
                checked = self.qualification.get("routes", {}).get(name, {})
                fresh = False
                if checked.get("validatedUtc"):
                    age = (datetime.now(timezone.utc) - datetime.fromisoformat(checked["validatedUtc"])).total_seconds()
                    fresh = 0 <= age < 60
                caps[name] = {"implemented": True, "dispatchImplemented": True,
                              "enabled": not self.closed and not active and fresh and checked.get("ready") is True,
                              "scope": LABELS[name],
                              "reason": checked.get("reason", "缺少可信执行上下文和完整当前资格；未连接机身写执行器")}
                if name == "load":
                    caps[name]["runtimeLoadImplemented"] = False
            operations = [{"id": name, "label": label, "implemented": True,
                           "enabled": caps[name]["enabled"] if name in caps else not self.closed and not active,
                           "reason": caps[name]["reason"] if name in caps else "固定本地资格诊断/机内只读查询"}
                          for name, label in LABELS.items()]
            for item in operations:
                if item["id"] == "monitor-stop":
                    item["enabled"] = not self.closed and active and self.monitor["active"] and self.current.get("operation") == "monitor-start"
            caps["monitor"] = {"implemented": True, "enabled": not self.closed and not active,
                               "scope": self.monitor["scope"], "reason": self.monitor["reason"]}
            return deepcopy({"state": "closing" if self.closed and active else "closed" if self.closed else self.state,
                "connected": self.connected, "capabilities": caps, "operations": operations,
                "reason": self.reason, "identity": self.identity, "lastRead": self.last_read,
                "latestReadComponent": self.latest_read_component, "current": self.current,
                "qualification": self.qualification, "components": PROFILES,
                "monitor": self.monitor,
                "closed": self.closed, "workerActive": active, "terminated": not active,
                "ownershipCallbackPending": self._idle_callback is not None and not self._idle_callback_done,
                "ownershipCallbackError": self._idle_callback_error, "installable": False,
                "testFixtureOnly": self.test_fixture})

    def connect(self):
        return self.start("connect", {})

    def read(self, component):
        return self.start("read", {"component": component})

    def start(self, operation, body=None):
        if operation not in LABELS:
            raise ValueError("未知设备桥操作")
        body = {} if body is None else body
        if type(body) is not dict or set(body) - {"operation", "component"}:
            raise ValueError("仅允许operation/component；网页不能提供命令、路径、资格或批准")
        if "operation" in body and body["operation"] != operation:
            raise ValueError("设备桥操作不一致")
        component = body.get("component")
        if operation == "read":
            if type(component) is not str or component not in PROFILES:
                raise ValueError("只允许固定七类组件摘要")
        elif "component" in body:
            raise ValueError("此操作不接受component")
        with self.lock:
            if self.closed:
                raise BridgeConflict("设备桥已关闭；不启动新任务")
            if operation == "monitor-stop":
                if self.thread and self.thread.is_alive() and self.monitor["active"] and self.current.get("operation") == "monitor-start":
                    self.monitor_stop.set()
                    self.monitor.update(state="stopping", reason="正在停止；仅等待当前有界只读查询")
                return self.status()
            if self.thread and self.thread.is_alive():
                raise BridgeConflict("已有设备桥任务运行中；不并发发送查询或执行操作")
            self.root.mkdir(parents=True, exist_ok=True)
            _guard(self.root, self.data_root)
            folder = self.root / uuid.uuid4().hex
            folder.mkdir()
            job = {"id": folder.name, "operation": operation, "component": component,
                   "state": "running", "startedUtc": _now(), "finishedUtc": None,
                   "evidencePath": str(folder), "deviceRequests": 0, "cameraContacted": False,
                   "cameraWriteAttempted": False, "cameraWritten": False, "photosRead": False,
                   "calibrationRead": False, "installable": False, "testFixtureOnly": self.test_fixture}
            if operation == "monitor-start":
                self.monitor_stop.clear()
                self._monitor_folder, self._monitor_bytes = folder, 0
                self._history_segment_index = 0
                self.monitor.update(state="starting", active=True, error=None, sessionId=folder.name,
                    evidencePath=str(folder), timeline=None, retainedBytes=0, polls=0, elapsedSeconds=0, elapsedFinalizationError=None,
                    readOffset=None, backlogBytes=0,
                    historyEventCount=0, reconnectAttempts=0, totalReconnects=0, lastTransportError=None,
                    bytesRead=0, readBytesPerSecond=0, backlogTrend="steady", lastSuccessfulReadUtc=None,
                    readState='establishing-baseline', lastSampleUtc=None,
                    snapshotEndSizeRange=None, lastSampleStable=None,
                    reason="固定机内日志采样启动中；可能漏事件，不是全链路观测", startedUtc=_now(), finishedUtc=None)
            self.current = job
            self.state = "connecting" if operation == "connect" else "reading" if operation == "read" else "checking"
            if operation in ("connect", "read", "monitor-start"):
                self.connected, self.identity = None, None
                self.reason = "机内固定只读查询进行中；不是持续连接监测"
            # A process exit must not kill a still-recovering qualified write.
            # Monitor has an explicit stop event and bounded query; no daemon.
            worker = None
            try:
                self._file(folder / "START.json", _json(job))
                worker = threading.Thread(target=self._run, args=(operation, component, folder, job), daemon=False)
                self.thread = worker
                worker.start()
            except Exception as error:
                # Admission can fail before a worker exists. Do not retain an
                # unstarted thread or a permanently active "starting" monitor.
                self.thread = worker if worker and worker.is_alive() else None
                job.update(state="failed", error=type(error).__name__ + ": " + str(error)[:1000], finishedUtc=_now())
                self.state, self.reason = "failed", "本地证据/任务启动失败；未开始后续设备操作"
                if operation == "monitor-start":
                    self.monitor_stop.set()
                    self.monitor.update(state="failed", active=self.thread is not None, error=job["error"],
                                        reason=self.reason, finishedUtc=job["finishedUtc"])
                try:
                    self._file(folder / "RESULT.json", _json(job))
                except Exception as retaining_error:
                    job["evidenceError"] = type(retaining_error).__name__ + ": " + str(retaining_error)[:1000]
                raise
            return self.status()

    def _file(self, path, raw):
        path = _guard(path, self.data_root)
        if type(raw) is not bytes or len(raw) > MAX_RAW_BYTES:
            raise ValueError("设备桥证据文件超过有界上限")
        with self.lock:
            monitored = self._monitor_folder is not None and path.is_relative_to(self._monitor_folder)
            if monitored:
                reserve = min(32768, MAX_MONITOR_BYTES // 8)
                limit = MAX_MONITOR_BYTES if path.name in ("RESULT.json", "FINALIZATION_FAILURE.json") else MAX_MONITOR_BYTES - reserve
                if self._monitor_bytes + len(raw) > limit:
                    raise MonitorLimit("日志证据达到本地容量上限，已停止；未宣称连续无损")
                if path.name not in ("RESULT.json", "FINALIZATION_FAILURE.json") and \
                        shutil.disk_usage(path.parent).free < len(raw) + MIN_MONITOR_FREE_BYTES:
                    raise MonitorLimit("电脑磁盘剩余空间不足，已停止读取；已有证据保持不动")
        with path.open("xb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        _guard(path, self.data_root)
        with self.lock:
            if monitored:
                self._monitor_bytes += len(raw)
                self.monitor["retainedBytes"] = self._monitor_bytes

    def _pointer(self, value):
        # close() and publication share a lock. No late old-worker publication.
        with self.lock:
            if self.closed:
                return
            path = _guard(self.root / "latest.json", self.data_root)
            temporary = self.root / (".latest-" + uuid.uuid4().hex + ".tmp")
            self._file(temporary, _json(value))
            os.replace(temporary, path)
            _guard(path, self.data_root)

    def _open_check(self):
        with self.lock:
            if self.current and self.current.get("operation") == "monitor-start" and (self.closed or self.monitor_stop.is_set()):
                raise MonitorStopped("日志采样已请求停止")
            if self.closed:
                raise BridgeBlocked("工作台关闭，未开始后续设备操作", ["bridge_closed"])

    def _query(self, reader, name, folder, job, records):
        self._open_check()
        index = len(records) + 1
        stem = f"{index:02d}-{name}"
        with self.lock:
            if job["operation"] == "monitor-start" and self.monitor_stop.is_set():
                raise MonitorStopped("日志采样已请求停止")
            if self.closed:
                raise BridgeBlocked("工作台关闭，未开始后续设备查询", ["bridge_closed"])
            job["deviceRequests"] += 1
            job["cameraContacted"] = not self.test_fixture
        try:
            result = reader.query(name)
        except Exception as error:
            record = {"name": name, "error": type(error).__name__ + ": " + str(error)[:1000]}
            receive = getattr(error, 'receive', None)
            if type(receive) is dict:
                record['transportStopReason'] = receive.get('stop_reason')
                record['receive'] = {key: receive.get(key) for key in (
                    'stop_reason', 'elapsed_seconds', 'wire_bytes', 'complete_record_count',
                    'validated_record_count', 'incomplete_record_bytes', 'terminal_count',
                    'native_body_result', 'completion_line_count')}
            for attribute, suffix in (("raw", "received.bin"), ("packets", "packets.bin")):
                raw = getattr(error, attribute, None)
                if type(raw) is bytes:
                    retained = raw[:MAX_RAW_BYTES]
                    self._file(folder / (stem + "." + suffix), retained)
                    record[suffix] = {"bytes": len(raw), "retainedBytes": len(retained),
                                      "truncated": len(raw) > len(retained), "sha256": _sha(retained)}
            records.append(record)
            self._file(folder / (stem + ".json"), _json(record))
            if job['operation'] == 'monitor-start' and getattr(reader, 'incremental_log', False) is True and _transport_interrupted(error):
                raise LogTransportInterrupted(record['error']) from error
            raise
        if (type(result) is not dict or result.get("name") != name or type(result.get("text")) is not str
                or type(result.get("shellLastExitCode")) is not int or not 0 <= result["shellLastExitCode"] <= 255):
            raise ValueError("固定查询返回无效结构")
        text = result["text"].encode("utf-8")
        packets, raw = result.get("packets"), result.get("rawReceived")
        if type(packets) is not bytes or type(raw) is not bytes:
            raise ValueError("固定查询缺少原始回包证据")
        oversized = len(text) > MAX_TEXT_BYTES or len(packets) > MAX_RAW_BYTES or len(raw) > MAX_RAW_BYTES
        for value, suffix, limit in ((text, "txt", MAX_TEXT_BYTES), (packets, "packets.bin", MAX_RAW_BYTES),
                                     (raw, "received.bin", MAX_RAW_BYTES)):
            self._file(folder / (stem + "." + suffix), value[:limit])
        # The fixed adb_state query ends with pidof. Exact stock "stopped"
        # output plus no PID legitimately yields 1, not transport failure.
        expected_absence = (name == "adb_state" and result["shellLastExitCode"] == 1 and
            re.fullmatch(r"rndis,mass_storage,bulk,acm(?:,adb)?\r?\n"
                         r"rndis,mass_storage,bulk,acm(?:,adb)?\r?\nstopped\r?\n"
                         r"(?:[0-9]{1,5})?\r?\n", result["text"]) is not None)
        record = {"name": name, "exit": result["shellLastExitCode"], "textPreview": result["text"][:PREVIEW_CHARS],
                  "textBytes": len(text), "textSha256": _sha(text), "rawReceivedBytes": len(raw),
                  "rawReceivedSha256": _sha(raw), "packetsSha256": _sha(packets),
                  "evidenceTruncated": oversized, "previewTruncated": len(result["text"]) > PREVIEW_CHARS,
                  "timestampUtc": _now(), "expectedStoppedAdbdAbsence": expected_absence}
        if name in ("timeline_log", "timeline_meta") and getattr(reader, "incremental_log", False) is True:
            record["logRange"] = {"offset": reader.log_offset if name == "timeline_log" else None,
                                  "maxBytes": LOG_CHUNK_BYTES, "payloadEncoding": "ascii-base64"}
            if type(result.get("command")) is str:
                record["commandSha256"] = _sha(result["command"].encode("ascii"))
        records.append(record)
        self._file(folder / (stem + ".json"), _json(record))
        if oversized:
            raise ValueError("查询证据超过有界上限；保留截断前缀但不认定读取成功")
        if result["shellLastExitCode"] != 0 and not expected_absence:
            if name == "timeline_log" and getattr(reader, "incremental_log", False) is True and reader.log_offset is not None:
                raise LogRangeFailed(f"固定日志范围读取返回非零状态{result['shellLastExitCode']}；原失败证据已保留")
            raise ValueError(f"固定查询{name}返回非零状态{result['shellLastExitCode']}；不推断所有权限")
        return result["text"]

    def _read_job(self, operation, component, folder, job):
        reader = self.reader_factory() if self.reader_factory else _FixedReader(self)
        records = []
        before = _identity(self._query(reader, "identity", folder, job, records))
        selected = ("boot",) if operation == "connect" else PROFILES[component]["queries"]
        texts = []
        for name in selected:
            texts.append(self._query(reader, name, folder, job, records))
        after = _identity(self._query(reader, "identity", folder, job, records))
        if before != after:
            raise ValueError("机内启动/身份在查询期间变化；不将跨启动结果合并")
        reader.check_unchanged()
        result = {"component": component, "scope": "实际固定身份/启动查询；非安装资格" if operation == "connect" else PROFILES[component]["scope"],
                  "identity": after, "timestampUtc": _now(), "text": "\n\n".join(texts)[:2 * PREVIEW_CHARS],
                  "queries": records, "sources": getattr(reader, "sources", {}), "evidencePath": str(folder),
                  "testFixtureOnly": self.test_fixture, "installable": False}
        with self.lock:
            if not self.closed:
                self.identity, self.connected = after, True
                self.reason = "机内只读查询已返回；手动快照，不证明当前安装权限或代码已加载"
                if operation == "read":
                    self.last_read[component] = deepcopy(result)
                    self.latest_read_component = component
        return result

    def _timeline(self):
        if self.timeline_factory is not None:
            return self.timeline_factory(), {"parserTestFixtureOnly": True}
        path = self.project / "devtools" / "camera_timeline.py"
        if path.resolve().parent != self.project / "devtools":
            raise ValueError("时间线解析器不属于活动工程")
        # Execute exactly the current bytes attributed to this session; never
        # pair a cached module/pyc class with a new on-disk source hash.
        raw = path.read_bytes()
        module = ModuleType("x2dii_bridge_timeline")
        module.__file__ = str(path)
        exec(compile(raw, str(path), "exec"), module.__dict__)
        return module.CaptureTimeline(), {"parserSourceSha256": _sha(raw)}

    def _timeline_unchanged(self, sources):
        if sources.get("parserTestFixtureOnly"):
            return
        path = self.project / "devtools" / "camera_timeline.py"
        if path.resolve().parent != self.project / "devtools" or _sha(path.read_bytes()) != sources["parserSourceSha256"]:
            raise ValueError("日志解析器来源在采样期间变化；不得归为当前解析证据")

    @staticmethod
    def _log_sample(text):
        boot = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
        match = re.fullmatch(r"(" + boot + r")\r?\n([1-9][0-9]*) ([0-9]+)\r?\n([\s\S]*)\n"
                             r"([1-9][0-9]*) ([0-9]+)\r?\n(" + boot + r")\r?\n?", text)
        if match is None:
            raise ValueError("日志固定查询缺少前后boot/inode/size边界；不推断连续性")
        before_boot, before_inode, before_size, tail, after_inode, after_size, after_boot = match.groups()
        numbers = [int(value) for value in (before_inode, before_size, after_inode, after_size)]
        if any(value >= 2 ** 63 for value in numbers) or len(tail.encode("utf-8")) > LOG_TAIL_BYTES:
            raise ValueError("日志元数据或tail片段超过固定上限")
        return {"bootId": before_boot, "inode": int(before_inode), "size": int(before_size), "text": tail,
                "afterBootId": after_boot, "afterInode": int(after_inode), "afterSize": int(after_size)}

    def history(self, session_id, *, before=None, limit=200):
        if __package__:
            from .timeline_history import read_history
        else:
            from timeline_history import read_history
        return read_history(self, session_id, before=before, limit=limit)

    def _journal(self, folder, records, result):
        events = result['addedEvents']
        if not events:
            return
        # A legal64KiB chunk can contain thousands of short rows; JSON expands
        # each with provenance and must not exceed the unchanged evidence cap.
        captures = {capture['startEventId']: capture for capture in result['addedCaptures']}
        for offset in range(0, len(events), MAX_JOURNAL_EVENTS):
            batch = events[offset:offset + MAX_JOURNAL_EVENTS]
            first, last = batch[0]['id'], batch[-1]['id']
            with self.lock:
                if first != self.monitor['historyEventCount'] + 1:
                    raise ValueError('历史事件编号不连续；不宣称已保存')
                segment_index = self._history_segment_index + 1
            path = folder / f'{segment_index:02d}-events-{first}-{last}.json'
            temporary = path.with_suffix('.json.tmp')
            self._file(temporary, _json({'sessionId': folder.name,
                'eventCountBefore': first - 1, 'eventCountAfter': last,
                'events': batch, 'captures': [captures[event['id']] for event in batch if event['id'] in captures]}))
            # Readers see only durable immutable segments. Failure of a later
            # batch leaves earlier committed history intact, never retried.
            with self.lock:
                _guard(path, self.data_root)
                if path.exists():
                    raise ValueError('历史段文件名冲突；不覆盖原证据')
                os.replace(temporary, path)
                self._history_segment_index = segment_index
                self.monitor['historyEventCount'] = last

    def _stream_gap(self, timeline, reason, *, folder, records, evidence, received,
                    boot_id, inode, size, cursor, source):
        previous = timeline.snapshot()
        with self.lock:
            sizes = self.monitor.get('snapshotEndSizeRange') or []
            observed_size = max([previous.get('size') or 0, *sizes])
        unread = {'bootId': source[0] if source else previous.get('bootId'),
            'inode': source[1] if source else previous.get('inode'),
            'fromOffset': cursor, 'toObservedSize': observed_size,
            'knownUnreadBytes': max(0, observed_size - cursor) if cursor is not None else None,
            'unfinishedLine': previous.get('trailingFragment', False),
            'recovered': False, 'lossBeyondObservedSizeUnknown': True}
        timeline.gap(reason, received_utc=received, evidence_path=evidence,
            boot_id=boot_id, inode=inode, size=size, previous_source_unread=unread)
        snapshot = timeline.snapshot()
        with self.lock:
            self.monitor.update(timeline=snapshot, readOffset=None, backlogBytes=None,
                readState='resynchronizing', lastSampleStable=False)
        self._file(folder / f'{len(records):02d}-continuity.json', _json(snapshot['gaps'][-1]))

    def _monitor_query(self, reader, name, folder, job, records, sources, started):
        interrupted_at, attempts = None, 0
        while True:
            self._open_check()
            if interrupted_at is not None:
                elapsed = max(0, self.clock() - started)
                if elapsed >= MAX_MONITOR_SECONDS:
                    raise MonitorLimit('达到会话时限；停止断线重试')
                reader.check_unchanged()
                self._timeline_unchanged(sources)
            try:
                if interrupted_at is not None and name in ('timeline_log', 'timeline_meta'):
                    observed = _identity(self._query(reader, 'identity', folder, job, records))
                    with self.lock:
                        expected = self.identity
                    if expected and any(observed[key] != expected[key] for key in ('uid', 'domain', 'model', 'firmware')):
                        raise ValueError('重连后身份/固件改变；停止原会话，不能混合数据')
                    # Boot/inode are checked again against the actual range;
                    # do not throw away the pending line or advance the cursor.
                text = self._query(reader, name, folder, job, records)
                if interrupted_at is not None:
                    with self.lock:
                        self.connected = True
                        self.monitor.update(state='stopping' if self.monitor_stop.is_set() else 'running', reconnectAttempts=0,
                            reason=self.monitor['reason'] if self.monitor_stop.is_set() else
                                '连接已恢复；从原已确认位置继续补读')
                return text
            except LogTransportInterrupted as error:
                if self.monitor_stop.is_set():
                    raise MonitorStopped('日志采样已停止；取消重连') from error
                if interrupted_at is None:
                    interrupted_at = self.clock()
                attempts += 1
                remaining = min(MAX_RECONNECT_SECONDS - (self.clock() - interrupted_at),
                                MAX_MONITOR_SECONDS - (self.clock() - started))
                with self.lock:
                    self.connected = None
                    self.monitor.update(state='reconnecting', reconnectAttempts=attempts,
                        totalReconnects=self.monitor['totalReconnects'] + 1,
                        lastTransportError=str(error)[:1000],
                        reason='通信中断；保留读取位置与半行，正在自动重连（最多120秒）')
                if remaining <= 0:
                    raise LogTransportInterrupted('自动重连窗口已耗尽；原读取位置和证据保留') from error
                if self.monitor_stop.wait(min(2 ** min(attempts - 1, 3), remaining)):
                    raise MonitorStopped('日志采样已停止；取消重连')
                if self.clock() - interrupted_at >= MAX_RECONNECT_SECONDS:
                    raise LogTransportInterrupted('自动重连窗口已耗尽；原读取位置和证据保留') from error

    def _monitor_job(self, folder, job):
        records, baseline, started = _MonitorQueryCount(), True, None
        cursor, stream_source, anchor = None, None, b''
        stream_baseline = True
        reset_from_zero = False
        bytes_read, last_data_clock = 0, None
        previous_backlog = 0
        timeline = None
        try:
            timeline, parser_sources = self._timeline()
            started = self.clock()
            reader = self.reader_factory() if self.reader_factory else _FixedReader(self)
            query = lambda name: self._monitor_query(reader, name, folder, job, records, parser_sources, started)
            first = _identity(query('identity'))
            query('boot')
            identity = _identity(query('identity'))
            if first != identity:
                raise ValueError("日志监控初始boot/身份变化；拒绝合并")
            reader.check_unchanged()
            self._timeline_unchanged(parser_sources)
            with self.lock:
                self.identity, self.connected = identity, True
                self.reason = "已建立固定只读日志查询；不是物理拍摄/保存成功证明"
                self.monitor.update(state="running", sources={**getattr(reader, "sources", {}), **parser_sources}, timeline=timeline.snapshot())
            while not self.monitor_stop.is_set():
                elapsed = max(0, self.clock() - started)
                with self.lock:
                    self.monitor["elapsedSeconds"] = int(elapsed)
                if elapsed >= MAX_MONITOR_SECONDS:
                    raise MonitorLimit(f"达到{MAX_MONITOR_SECONDS / 3600:g}小时采样期限，已停止；可重新开启会话")
                try:
                    text = query('timeline_log')
                except LogRangeFailed:
                    # od can fail when its saved offset is beyond a newly
                    # truncated file. Preserve the failed range, then recover
                    # only if a separate fixed metadata read proves a change.
                    metadata = self._stream_sample(query('timeline_meta'), None)
                    reader.check_unchanged()
                    self._timeline_unchanged(parser_sources)
                    changed_source = ((metadata["bootId"], metadata["inode"]) != stream_source or
                                      (metadata["afterBootId"], metadata["afterInode"]) != stream_source)
                    if not changed_source and min(metadata["size"], metadata["afterSize"]) >= cursor:
                        raise
                    self._stream_gap(timeline, '范围读取失败且确认日志来源改变/截断；旧来源尾部未恢复，新来源从开头补读',
                        folder=folder, records=records, received=_now(),
                        evidence=str(folder / f'{len(records):02d}-timeline_meta.txt'),
                        boot_id=metadata['afterBootId'], inode=metadata['afterInode'],
                        size=metadata['afterSize'], cursor=cursor, source=stream_source)
                    cursor, stream_source, anchor, stream_baseline = None, None, b'', True
                    reset_from_zero = True
                    reader.log_offset = None
                    with self.lock:
                        self.monitor.update(timeline=timeline.snapshot(), readOffset=None, backlogBytes=None)
                    continue
                incremental = getattr(reader, "incremental_log", False) is True
                sample = self._stream_sample(text, reader.log_offset) if incremental else self._log_sample(text)
                reader.check_unchanged()
                self._timeline_unchanged(parser_sources)
                received, evidence = _now(), str(folder / f"{len(records):02d}-timeline_log.txt")
                if incremental:
                    source = (sample["bootId"], sample["inode"])
                    unstable = (source != (sample["afterBootId"], sample["afterInode"]) or
                                sample["afterSize"] < sample["size"])
                    changed = stream_source is not None and (source != stream_source or sample["size"] < cursor)
                    if unstable or changed:
                        self._stream_gap(timeline, '日志boot/inode变化或截断；旧来源尾部未恢复，新来源从开头补读',
                            folder=folder, records=records, received=received, evidence=evidence,
                            boot_id=sample['afterBootId'], inode=sample['afterInode'], size=sample['afterSize'], cursor=cursor, source=stream_source)
                        cursor, stream_source, anchor, stream_baseline = None, None, b'', True
                        reset_from_zero = True
                        reader.log_offset = None
                    else:
                        if identity["bootId"] != sample["bootId"]:
                            identity = _identity(query('identity'))
                            if identity["bootId"] != sample["bootId"]:
                                raise ValueError("重启后的身份与日志boot不一致；停止监控")
                        stream_source = source
                        if reader.log_offset is None:
                            # An explicit EOF cutoff, then read its last byte to
                            # distinguish old unfinished rows from new requests.
                            if reset_from_zero:
                                # New source began after this monitoring session.
                                # Its beginning is not old history: read from 0.
                                cursor, anchor, stream_baseline = 0, b'', False
                                timeline.ingest_chunk(b'', offset=0, boot_id=source[0], inode=source[1],
                                    size=sample['afterSize'], received_utc=received, evidence_path=evidence, baseline=True)
                                reader.log_offset = 0
                                reset_from_zero = False
                            else:
                                cursor = sample["afterSize"]
                                reader.log_offset = max(0, cursor - 1)
                        else:
                            raw, start = sample["raw"], reader.log_offset
                            if not stream_baseline and raw[:len(anchor)] != anchor:
                                self._stream_gap(timeline, '已读字节锚点变化；原文件可能被改写，无法判定新旧事件，重新建立EOF基线',
                                    folder=folder, records=records, received=received, evidence=evidence,
                                    boot_id=source[0], inode=source[1], size=sample['afterSize'], cursor=cursor, source=stream_source)
                                cursor, stream_source, anchor, stream_baseline = None, None, b'', True
                                reset_from_zero = False
                                reader.log_offset = None
                            else:
                                if stream_baseline:
                                    # Only the final OLD byte is baseline, not
                                    # new rows appended during this range read.
                                    anchor_size = min(1, cursor)
                                    timeline.ingest_chunk(raw[:anchor_size], offset=start,
                                        boot_id=source[0], inode=source[1], size=sample["afterSize"],
                                        received_utc=received, evidence_path=evidence, baseline=True)
                                    new_raw = raw[anchor_size:]
                                else:
                                    new_raw = raw[len(anchor):]
                                result = timeline.ingest_chunk(new_raw, offset=cursor, boot_id=source[0], inode=source[1],
                                    size=sample["afterSize"], received_utc=received, evidence_path=evidence)
                                self._journal(folder, records, result)
                                bytes_read += len(new_raw)
                                now_clock = self.clock()
                                duration = now_clock - last_data_clock if last_data_clock is not None else now_clock - started
                                rate = len(new_raw) / max(.001, duration)
                                last_data_clock = now_clock
                                with self.lock:
                                    self.monitor.update(bytesRead=bytes_read, readBytesPerSecond=round(rate, 1),
                                        lastSuccessfulReadUtc=received)
                                cursor = start + len(raw)
                                anchor, stream_baseline = raw[-LOG_ANCHOR_BYTES:], False
                                reader.log_offset = cursor - len(anchor)
                    backlog = max(0, sample["afterSize"] - cursor) if cursor is not None else None
                    with self.lock:
                        self.identity = identity
                        self.monitor.update(timeline=timeline.snapshot(), lastSampleUtc=received,
                            reason=self.monitor["reason"] if self.monitor_stop.is_set() else
                                '日志来源改变，正在重新建立读取位置；旧来源缺口仍保留' if backlog is None else
                                "已收到机内日志，正在按位置补读积压" if backlog else "已收到机内日志，正在持续增量读取",
                            readOffset=cursor, backlogBytes=backlog,
                            backlogTrend='unknown' if backlog is None else
                                'growing' if backlog > previous_backlog else 'draining' if backlog < previous_backlog else 'steady',
                            readState='resynchronizing' if backlog is None else 'catching-up' if backlog else 'caught-up',
                            snapshotEndSizeRange=[sample["size"], sample["afterSize"]], snapshotAtomic=False,
                            lastSampleStable=not unstable and not changed and cursor is not None, polls=self.monitor["polls"] + 1)
                    if backlog is not None:
                        previous_backlog = backlog
                    # No artificial delay while catching up; the loop still
                    # checks stop/time/evidence/disk bounds before every range.
                    if backlog or reader.log_offset is None or stream_baseline:
                        continue
                    if self.monitor_stop.wait(MONITOR_INTERVAL_SECONDS):
                        break
                    continue
                unstable = (sample["bootId"] != sample["afterBootId"] or sample["inode"] != sample["afterInode"] or
                            sample["afterSize"] < sample["size"] or sample["afterSize"] - sample["size"] > LOG_TAIL_BYTES)
                if unstable:
                    timeline.gap("采样期间boot/轮转/截断变化或追加超过tail窗口；片段未归为连续新事件",
                        received_utc=received, evidence_path=evidence, boot_id=sample["afterBootId"],
                        inode=sample["afterInode"], size=sample["afterSize"])
                    baseline = True
                else:
                    if identity["bootId"] != sample["bootId"]:
                        identity = _identity(self._query(reader, "identity", folder, job, records))
                        if identity["bootId"] != sample["bootId"]:
                            raise ValueError("重启后的身份与日志boot不一致；停止监控")
                    # Normal append is accepted, NOT rebaselined. The exact tail
                    # end is between before/after sizes; use before conservatively
                    # and let the parser's content overlap expose missing samples.
                    result = timeline.ingest(sample["text"], boot_id=sample["bootId"], inode=sample["inode"],
                                    size=sample["size"], received_utc=received,
                                    evidence_path=evidence, baseline=baseline)
                    self._journal(folder, records, result)
                    baseline = False
                with self.lock:
                    self.identity = identity
                    self.monitor.update(timeline=timeline.snapshot(), lastSampleUtc=received,
                        reason=self.monitor["reason"] if self.monitor_stop.is_set() else
                            "已收到机内日志，正在持续读取；未观测环节不代表没有运行",
                        snapshotEndSizeRange=[sample["size"], sample["afterSize"]], snapshotAtomic=False,
                        lastSampleStable=not unstable, polls=self.monitor["polls"] + 1)
                if self.monitor_stop.wait(MONITOR_INTERVAL_SECONDS):
                    break
            with self.lock:
                self.monitor.update(state="stopped", reason="手动停止/关闭；已结束当前只读查询")
        except (MonitorStopped, MonitorLimit) as error:
            with self.lock:
                self.monitor.update(state="limit-reached" if isinstance(error, MonitorLimit) else "stopped", reason=str(error))
        except Exception as error:
            with self.lock:
                self.connected, self.identity = None, None
                self.monitor.update(state="failed", error=type(error).__name__ + ": " + str(error)[:1000],
                                    reason="读取/权限/协议边界失败；停止采样，不修改机身配置")
            raise
        finally:
            with self.lock:
                if timeline is not None:
                    snapshot = timeline.snapshot()
                    self.monitor['timeline'] = snapshot
                    # A summary is diagnostic evidence, not a restart checkpoint.
                    # Keep parsed and durable counts separate after partial IO.
                    job['logMonitorSummary'] = {'sessionId': folder.name, 'state': self.monitor['state'],
                        'readOffset': self.monitor['readOffset'], 'parsedEventCount': snapshot['eventCount'],
                        'historyEventCount': self.monitor['historyEventCount'], 'gapCount': snapshot['gapCount'],
                        'bootId': snapshot['bootId'], 'inode': snapshot['inode'],
                        'pendingLineBytes': len(timeline.stream_pending),
                        'lastSuccessfulReadUtc': self.monitor['lastSuccessfulReadUtc'],
                        'sources': self.monitor.get('sources', {})}
                if started is not None:
                    try:
                        self.monitor["elapsedSeconds"] = max(self.monitor["elapsedSeconds"], int(self.clock() - started))
                    except Exception as error:
                        # Timing must never replace the actual read failure.
                        self.monitor["elapsedFinalizationError"] = type(error).__name__ + ": " + str(error)[:200]
                self.monitor.update(active=False, finishedUtc=_now())
        return {"scope": self.monitor["scope"], "monitorState": self.monitor["state"], "stopReason": self.monitor["reason"],
                "samples": self.monitor["polls"], "queryCount": len(records), "evidencePath": str(folder),
                "cameraWritten": False, "photosPixelsRead": False, "installable": False}

    @staticmethod
    def _stream_sample(text, offset):
        boot = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
        match = re.fullmatch(r"(" + boot + r")\r?\n([1-9][0-9]*) ([0-9]+)\r?\n([\s\S]*?)"
            r"(" + boot + r")\r?\n([1-9][0-9]*) ([0-9]+)\r?\n?", text)
        if match is None:
            raise ValueError("增量日志缺少前后boot/inode/size边界")
        before_boot, inode, size, encoded, after_boot, after_inode, after_size = match.groups()
        numbers = [int(value) for value in (inode, size, after_inode, after_size)]
        if any(value >= 2 ** 63 for value in numbers):
            raise ValueError("增量日志元数据超出整数范围")
        if len(encoded) > LOG_CHUNK_BYTES * 2 or re.fullmatch(r"[A-Za-z0-9+/=\r\n]*", encoded) is None:
            raise ValueError("增量日志不是完整ASCII字节编码")
        compact = encoded.replace('\r', '').replace('\n', '')
        raw = base64.b64decode(compact, validate=True)
        if base64.b64encode(raw).decode('ascii') != compact:
            raise ValueError("增量日志字节编码非规范或未完整结束")
        if len(raw) > LOG_CHUNK_BYTES or (offset is None and raw):
            raise ValueError("增量日志超过固定分块或基线含未请求字节")
        stable = before_boot == after_boot and inode == after_inode and numbers[3] >= numbers[1]
        if offset is not None and stable:
            lower = min(LOG_CHUNK_BYTES, max(0, numbers[1] - offset))
            upper = min(LOG_CHUNK_BYTES, max(0, numbers[3] - offset))
            if not lower <= len(raw) <= upper:
                raise ValueError("增量日志字节数不符合固定读取范围；不推进游标")
        return {"bootId": before_boot, "inode": numbers[0], "size": numbers[1], "raw": raw,
                "afterBootId": after_boot, "afterInode": numbers[2], "afterSize": numbers[3]}

    def _context(self, name):
        if self.execution_provider is None:
            raise BridgeBlocked("缺少可信本地执行上下文；未连接机身写执行器", [
                "server_owned_prepared_operation", "current_complete_qualification_and_separate_authorization",
                "original_session_launch_bytes_and_window", "existing_prepared_observer_and_process_boundary"])
        context = self.execution_provider(name)
        if type(context) is not PreparedExecution:
            raise BridgeBlocked("本地provider未提供该操作的完整可信上下文", ["server_owned_prepared_execution:" + name])
        prepared = self._module("menu_prepared_transport")
        valid = ((name == "deploy" and type(context.operation) is prepared.PreparedFormalPlacementOperation) or
                 (name == "load" and type(context.operation) is prepared.PreparedBootOperation and context.operation.action == "activate") or
                 (name == "restore" and ((type(context.operation) is prepared.PreparedBootOperation and context.operation.action == "restore") or
                                          type(context.operation) is prepared.PreparedCleanupOperation)))
        if not valid:
            raise ValueError("可信prepared对象与请求的固定操作不匹配")
        if (type(context.launch_report) is not bytes or not 0 < len(context.launch_report) <= 1024 * 1024 or
                not callable(context.start_process) or not callable(getattr(context.maintenance_session, "command", None)) or
                type(context.qualification) is not dict or type(context.window_authorization) is not dict):
            raise ValueError("可信执行上下文缺少原始launch/session/process/qualification")
        return context

    def _validate_context(self, name, context):
        if name == "restore":
            if context.saved_manifest is None or context.saved_manifest_sha256 is None:
                raise ValueError("独立恢复缺少保存的原安装manifest及其SHA256")
            self._module("prepare_peer_recovery").validate_qualification(
                context.saved_manifest, context.saved_manifest_sha256, context.qualification, for_publication=True)
        else:
            self._module("prepare_peer_install").validate_qualification(
                context.operation.manifest, context.qualification, for_publication=True)

    def _run_prepared(self, name, job):
        self._open_check()
        context = self._context(name)
        self._validate_context(name, context)
        self._open_check()
        # Once the original transaction begins, it owns recovery/exit. close()
        # must not kill it between a write and its existing recovery boundary.
        with self.lock:
            if self.closed:
                raise BridgeBlocked("工作台关闭，未开始prepared事务", ["bridge_closed"])
            job["cameraWriteAttempted"] = True
            job["cameraContacted"] = not self.test_fixture
            job["cameraWritten"] = None  # Failure may have partial original evidence.
        arguments = {"qualification": context.qualification, "window_authorization": context.window_authorization}
        if name == "restore":
            arguments.update(saved_manifest=context.saved_manifest, saved_manifest_sha256=context.saved_manifest_sha256)
        result = context.operation.run_qualified(context.launch_report, context.maintenance_session,
                                                 context.start_process, **arguments)
        return {"operation": name, "candidateSha256": context.operation.manifest["candidate_sha256"],
                "routeResult": result, "runtimeLoadedVerified": False,
                "featureQualified": False, "installable": False,
                "scope": "仅原始qualification哈希绑定候选，不自动包含草稿；不提升为机内加载/拍摄/生命周期PASS"}

    def _retain_route_value(self, value, folder, *, counter=None, depth=0):
        """Keep original route byte payloads in bounded files, never in SSE."""
        counter = [0, 0] if counter is None else counter
        if depth > 20:
            raise ValueError("原事务证据嵌套超过有界上限")
        if isinstance(value, bytes) or isinstance(value, str) and len(value) > PREVIEW_CHARS:
            raw = value if isinstance(value, bytes) else value.encode("utf-8")
            counter[0] += 1
            counter[1] += len(raw)
            if counter[0] > 1000 or len(raw) > MAX_RAW_BYTES or counter[1] > 8 * 1024 * 1024:
                raise ValueError("原事务证据超过桥的保留上限；不提升为完成")
            name = f"route-artifact-{counter[0]:04d}." + ("bin" if isinstance(value, bytes) else "txt")
            self._file(folder / name, raw)
            return {"evidenceFile": str(folder / name), "bytes": len(raw), "sha256": _sha(raw),
                    "preview": None if isinstance(value, bytes) else value[:PREVIEW_CHARS]}
        if type(value) is dict:
            if len(value) > 1000 or any(type(key) is not str for key in value):
                raise ValueError("原事务证据字典结构无效")
            return {key: self._retain_route_value(item, folder, counter=counter, depth=depth + 1)
                    for key, item in value.items()}
        if type(value) in (list, tuple):
            if len(value) > 1000:
                raise ValueError("原事务证据列表超过上限")
            return [self._retain_route_value(item, folder, counter=counter, depth=depth + 1) for item in value]
        if value is None or type(value) in (str, bool, int, float):
            return value
        raise ValueError("原事务返回非JSON证据类型")

    def _qualification_job(self):
        result = {"state": "checked-local-only", "routes": {}, "installable": False}
        try:
            manifest = self._module("prepare_peer_install").inventory()
            result["candidate"] = {"sha256": manifest["candidate_sha256"], "state": manifest["status"],
                                   "requiredGates": manifest["required_gates"]}
        except Exception as error:
            result["candidate"] = {"state": "unavailable", "error": str(error)[:1000]}
        # Recovery is deliberately evaluated independently of new inventory.
        for name in WRITE_OPERATIONS:
            try:
                context = self._context(name)
                self._validate_context(name, context)
                result["routes"][name] = {"ready": True, "validatedUtc": _now(),
                    "reason": "既有publication资格验证通过；执行前及原run_qualified仍会再次验证"}
            except Exception as error:
                result["routes"][name] = {"ready": False, "reason": str(error)[:1000],
                    "missing": getattr(error, "missing", ["existing_publication_qualification:" + name])}
        with self.lock:
            if not self.closed:
                self.qualification = deepcopy(result)
        return result

    def _run(self, operation, component, folder, job):
        try:
            if operation in ("connect", "read"):
                result = self._read_job(operation, component, folder, job)
            elif operation == "monitor-start":
                result = self._monitor_job(folder, job)
            elif operation == "qualification":
                result = self._qualification_job()
            else:
                result = self._retain_route_value(self._run_prepared(operation, job), folder)
            with self.lock:
                job.update(state="completed", result=result)
                if not self.closed:
                    self.state = "connected" if self.connected else "not-connected"
        except Exception as error:
            original_evidence = getattr(error, "prepared_operation_evidence", None)
            retained = None
            if original_evidence is not None:
                try:
                    retained = self._retain_route_value(original_evidence, folder)
                except Exception as retaining_error:
                    retained = {"retentionError": str(retaining_error)[:1000]}
            with self.lock:
                job.update(state="blocked" if isinstance(error, BridgeBlocked) else "failed",
                           error=type(error).__name__ + ": " + str(error)[:1200],
                           missing=getattr(error, "missing", []))
                if retained is not None:
                    job["originalOperationEvidence"] = retained
                if operation in ("connect", "read", "monitor-start"):
                    self.connected, self.identity = None, None
                    self.reason = "机内读取未完成，连接状态未知；不把传输失败推断为权限拒绝或相机不存在"
                if not self.closed:
                    self.state = job["state"]
        finally:
            with self.lock:
                job["finishedUtc"] = _now()
                final = deepcopy(job)
            try:
                self._file(folder / "RESULT.json", _json(final))
                self._pointer({"id": job["id"], "state": job["state"], "evidencePath": str(folder), "finishedUtc": job["finishedUtc"]})
            except Exception as error:
                with self.lock:
                    job["evidenceError"] = type(error).__name__ + ": " + str(error)[:1000]
                    job["state"] = "failed"
                    if operation == "monitor-start":
                        self.monitor.update(state="failed", active=False, error=job["evidenceError"],
                            reason="本次读取的最终证据保存失败；保留已有片段，不认定会话验证完成")
                    if not self.closed:
                        self.state = "failed"
                        if operation in ("connect", "read", "monitor-start"):
                            self.connected, self.identity = None, None
                            self.reason = "证据保存失败；不认定当前连接/读取已通过"
                    failure = deepcopy(job)
                # RESULT may already exist when publishing latest.json failed.
                # Preserve it and append the contradictory finalization failure
                # rather than letting a disk reader mistake it for a clean end.
                try:
                    self._file(folder / "FINALIZATION_FAILURE.json", _json(failure))
                except Exception as retention_error:
                    with self.lock:
                        job["finalizationFailureRetentionError"] = type(retention_error).__name__ + ": " + str(retention_error)[:1000]

    def _release_after_worker(self, worker):
        if worker and worker is not threading.current_thread():
            threading.Thread.join(worker)  # Actual termination, not a timeout/poll claim.
        with self.lock:
            callback = self._idle_callback
            if callback is None or self._idle_callback_done:
                return
            self._idle_callback_done = True
        try:
            callback()
        except Exception as error:
            with self.lock:
                self._idle_callback_error = type(error).__name__ + ": " + str(error)[:1000]

    def close(self, *, on_idle=None):
        """Stop admission; caller retains its ownership lock until terminated.

        A local on_idle callback (e.g. DataLock.close) is run once, only after
        the old worker has really exited. No web callback/context is accepted.
        Already-started prepared transactions retain their original recovery.
        """
        if on_idle is not None and not callable(on_idle):
            raise ValueError("on_idle必须为可信本地完成回调")
        with self.lock:
            self.closed = True
            self.monitor_stop.set()
            if on_idle is not None and self._idle_callback is None:
                self._idle_callback = on_idle
            worker = self.thread
        if worker and worker is not threading.current_thread():
            worker.join(timeout=10)
        with self.lock:
            if self._idle_callback is not None and not self._idle_callback_done:
                if worker and worker.is_alive():
                    if self._idle_watcher is None:
                        self._idle_watcher = threading.Thread(target=self._release_after_worker, args=(worker,), daemon=False)
                        self._idle_watcher.start()
                else:
                    self._release_after_worker(None)
        return self.status()
