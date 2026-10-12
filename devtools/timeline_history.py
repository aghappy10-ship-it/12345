"""Read bounded pages from the bridge's current immutable event journal.

Filename ranges form a lightweight index: a request enumerates names, verifies
the complete committed range chain, and opens only files containing its page.
The reader accepts no caller-controlled file, directory, command or other
session, and never contacts a camera.
"""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import parse_qs

if __package__:
    from .device_bridge import MAX_RAW_BYTES, _guard
else:
    from device_bridge import MAX_RAW_BYTES, _guard

SESSION_ID = re.compile(r"[0-9a-f]{32}")
SEGMENT_NAME = re.compile(r"([0-9]{1,19})-events-([1-9][0-9]{0,18})-([1-9][0-9]{0,18})\.json")
POSITIVE_NUMBER = re.compile(r"[1-9][0-9]{0,18}")
MAX_ID = 2 ** 63 - 1
MAX_DIRECTORY_ENTRIES = 500_000
SECTIONS = {"ui", "control", "hardware", "imaging", "storage", "platform", "maintenance"}
EVENT_FIELDS = {"id", "section", "phase", "label", "deviceTime", "receivedUtc", "raw",
                "rawTruncated", "evidencePath", "correlation", "bootId", "inode", "logWindowId"}


def _failure(reason):
    raise ValueError("历史记录读取失败 / history: " + reason)


def _positive(value, maximum=MAX_ID):
    return type(value) is int and 0 < value <= maximum


def history_query(raw_query):
    """Strict HTTP argument parsing; blank, duplicate and unknown keys fail."""
    if type(raw_query) is not str or len(raw_query) > 1024:
        _failure("请求参数过长")
    try:
        query = parse_qs(raw_query, keep_blank_values=True, strict_parsing=True, max_num_fields=3)
    except ValueError:
        _failure("请求参数格式不合法")
    if not {"sessionId"} <= set(query) <= {"sessionId", "before", "limit"} or any(
            len(values) != 1 for values in query.values()):
        _failure("仅接受单一sessionId、before和limit")
    before, limit = None, 200
    for name in ("before", "limit"):
        if name in query:
            raw = query[name][0]
            if not POSITIVE_NUMBER.fullmatch(raw):
                _failure(name + "必须是正整数")
            value = int(raw)
            if name == "before":
                before = value
            else:
                limit = value
    session_id = query["sessionId"][0]
    _arguments(session_id, before, limit)
    return session_id, before, limit


def _arguments(session_id, before, limit):
    if type(session_id) is not str or not SESSION_ID.fullmatch(session_id):
        _failure("sessionId不是当前会话标识格式")
    if before is not None and not _positive(before):
        _failure("before必须是有界正整数")
    if not _positive(limit, 200):
        _failure("limit必须为1至200")


def _directory(folder, data_root):
    folder = _guard(folder, data_root)
    info = folder.lstat()
    if not stat.S_ISDIR(info.st_mode):
        _failure("会话证据目录缺失或不是目录")
    return info.st_dev, info.st_ino


def _ranges(folder, count):
    segments = []
    with os.scandir(folder) as entries:
        for number, entry in enumerate(entries, 1):
            if number > MAX_DIRECTORY_ENTRIES:
                _failure("会话证据目录超过有界索引上限")
            name = entry.name
            if not name.endswith(".json") or "-events" not in name:
                continue  # Atomic publication hides unfinished .json.tmp files.
            match = SEGMENT_NAME.fullmatch(name)
            if match is None:
                _failure("事件文件名格式不合法")
            index, first, last = map(int, match.groups())
            if not _positive(index) or not _positive(first) or not _positive(last) or first > last:
                _failure("事件文件名范围不合法")
            segments.append((index, first, last, name))
    segments.sort(reverse=True)
    expected, previous_index = count, None
    for index, first, last, _ in segments:
        if last != expected or (previous_index is not None and index >= previous_index):
            _failure("事件文件范围缺失、重复或与已提交总数不一致")
        expected, previous_index = first - 1, index
    if expected != 0:
        _failure("已提交事件文件不完整")
    return segments


def _signature(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_nlink, getattr(info, "st_file_attributes", 0))


def _regular(info):
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or \
            getattr(info, "st_file_attributes", 0) & 0x400:
        _failure("事件文件不是独立普通文件，拒绝链接或重定向")
    if not 0 < info.st_size <= MAX_RAW_BYTES:
        _failure("事件文件大小超过有界上限或为空")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _failure("JSON包含重复字段")
        result[key] = value
    return result


def _nonfinite(value):
    _failure("JSON包含非有限数值")


def _read_segment(path, data_root):
    path = _guard(path, data_root)
    original = path.lstat()
    _regular(original)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            opened = os.fstat(stream.fileno())
            _regular(opened)
            # Bind the opened descriptor before reading any potentially foreign
            # content, including platforms without an O_NOFOLLOW open option.
            if _signature(original) != _signature(opened):
                _failure("事件文件在打开期间被替换")
            _guard(path, data_root)
            if _signature(path.lstat()) != _signature(opened):
                _failure("事件文件路径在打开期间发生变化")
            raw = stream.read(MAX_RAW_BYTES + 1)
            if len(raw) != opened.st_size or _signature(os.fstat(stream.fileno())) != _signature(opened):
                _failure("事件文件在读取期间发生变化")
        _guard(path, data_root)
        if _signature(path.lstat()) != _signature(opened):
            _failure("事件文件在读取期间被替换")
    finally:
        if descriptor is not None:
            os.close(descriptor)
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_nonfinite)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        _failure("事件文件不是合法的有界JSON")


def _text(value, maximum, nullable=False):
    return (nullable and value is None) or (type(value) is str and 0 < len(value) <= maximum)


def _inode(value, nullable=False):
    return (nullable and value is None) or (type(value) is int and 0 <= value <= MAX_ID) or _text(value, 128)


def _validate_segment(value, session_id, first, last):
    required = {"sessionId", "events", "captures", "eventCountBefore", "eventCountAfter"}
    if type(value) is not dict or not required <= set(value) <= required | {"gaps"}:
        _failure("事件文件结构不合法")
    if value["sessionId"] != session_id or type(value["eventCountBefore"]) is not int or \
            type(value["eventCountAfter"]) is not int or value["eventCountBefore"] != first - 1 or \
            value["eventCountAfter"] != last:
        _failure("事件文件会话或计数与文件名不一致")
    events, captures, gaps = value["events"], value["captures"], value.get("gaps", [])
    if any(type(records) is not list for records in (events, captures, gaps)) or len(events) != last - first + 1:
        _failure("事件文件记录数量或数组结构不合法")
    for identity, row in enumerate(events, first):
        if type(row) is not dict or not EVENT_FIELDS <= set(row) <= EVENT_FIELDS | {"frameId", "requestId", "evidenceRanges"}:
            _failure("事件结构不合法")
        if type(row["id"]) is not int or row["id"] != identity or type(row["section"]) is not str or \
                row["section"] not in SECTIONS or \
                not _positive(row["logWindowId"]) or type(row["rawTruncated"]) is not bool or \
                row["correlation"] not in ("uncorrelated", "explicit-id") or not _inode(row["inode"]):
            _failure("事件ID、顺序或元数据不合法")
        for key, maximum in (("phase", 128), ("label", 1000), ("deviceTime", 128),
                             ("receivedUtc", 128), ("raw", 2000), ("evidencePath", 2048), ("bootId", 128)):
            if not _text(row[key], maximum):
                _failure("事件文本字段不合法")
        for key in ("frameId", "requestId"):
            if key in row and not _text(row[key], 64):
                _failure("事件显式标识不合法")
        if "evidenceRanges" in row:
            ranges = row["evidenceRanges"]
            if type(ranges) is not list or len(ranges) > 128:
                _failure("事件字节证据范围结构不合法")
            previous_end, total_bytes = None, 0
            for item in ranges:
                if type(item) is not dict or set(item) != {"evidencePath", "offset", "bytes"} or \
                        not _text(item.get("evidencePath"), 2048) or type(item.get("offset")) is not int or \
                        not 0 <= item["offset"] <= MAX_ID or not _positive(item.get("bytes"), 65536) or \
                        item["offset"] + item["bytes"] > MAX_ID or \
                        previous_end is not None and item["offset"] != previous_end:
                    _failure("事件字节证据范围不连续或超界")
                previous_end = item["offset"] + item["bytes"]
                total_bytes += item["bytes"]
                if total_bytes > 65537:
                    _failure("事件字节证据总数超过单行上限")
    previous_capture = 0
    starts = []
    for row in captures:
        required = {"id", "startEventId", "startDeviceTime", "receivedUtc", "label", "scope",
                    "bootId", "logWindowId", "evidencePath"}
        if type(row) is not dict or not required <= set(row) <= required | {"windowStartRetained"} or \
                not _positive(row.get("id")) or row["id"] <= previous_capture or \
                not _positive(row.get("startEventId")) or not first <= row["startEventId"] <= last or \
                not _positive(row.get("logWindowId")) or row.get("scope") != "log-window-not-single-frame-proof":
            _failure("拍摄日志窗口结构或ID不合法")
        if "windowStartRetained" in row and type(row["windowStartRetained"]) is not bool:
            _failure("拍摄日志窗口保留状态不合法")
        for key, maximum in (("startDeviceTime", 128), ("receivedUtc", 128), ("label", 1000),
                             ("bootId", 128), ("evidencePath", 2048)):
            if not _text(row[key], maximum):
                _failure("拍摄日志窗口文本字段不合法")
        previous_capture = row["id"]
        starts.append(row["startEventId"])
    if starts != [row["id"] for row in events if row["phase"] == "capture-request"]:
        _failure("拍摄日志窗口与事件关联不一致")
    for row in gaps:
        if type(row) is not dict or set(row) != {"reason", "receivedUtc", "evidencePath", "bootId",
                                              "inode", "size", "logWindowId"} or \
                not _positive(row.get("logWindowId")) or not _inode(row.get("inode"), nullable=True) or \
                not (row.get("size") is None or type(row["size"]) is int and row["size"] >= 0):
            _failure("连续性缺口结构不合法")
        for key, maximum in (("reason", 1000), ("receivedUtc", 128), ("evidencePath", 2048), ("bootId", 128)):
            if not _text(row[key], maximum, nullable=key != "reason"):
                _failure("连续性缺口文本字段不合法")
    return events


def read_history(bridge, session_id, before=None, limit=200):
    """Return an ascending page strictly before the caller's event cursor."""
    _arguments(session_id, before, limit)
    with bridge.lock:
        if bridge.monitor.get("sessionId") != session_id or bridge._monitor_folder is None:
            _failure("仅允许读取当前监控会话")
        data_root = Path(os.path.abspath(bridge.data_root))
        folder = Path(os.path.abspath(bridge._monitor_folder))
        if folder != data_root / "device-bridge" / session_id:
            _failure("会话证据目录与后端所有权不一致")
        count = bridge.monitor.get("historyEventCount")
        if type(count) is not int or not 0 <= count <= MAX_ID:
            _failure("缺少合法的已提交事件总数")
        directory_identity = _directory(folder, data_root)
        segments = _ranges(folder, count)
        if _directory(folder, data_root) != directory_identity:
            _failure("会话目录在建立索引期间发生变化")
    end = min(count, before - 1) if before is not None else count
    start = max(1, end - limit + 1)
    selected = []
    for _, first, last, name in segments:
        if first > end:
            continue
        if last < start:
            break
        rows = _validate_segment(_read_segment(folder / name, data_root), session_id, first, last)
        selected.extend(row for row in rows if start <= row["id"] <= end)
    selected.sort(key=lambda row: row["id"])
    if [row["id"] for row in selected] != list(range(start, end + 1)):
        _failure("分页事件范围不完整")
    with bridge.lock:
        if bridge.monitor.get("sessionId") != session_id or bridge._monitor_folder != folder or \
                _directory(folder, data_root) != directory_identity:
            _failure("读取期间当前会话发生变化")
    has_more = bool(selected and selected[0]["id"] > 1)
    return {"sessionId": session_id, "events": deepcopy(selected), "hasMore": has_more,
            "nextBefore": selected[0]["id"] if has_more else None, "eventCount": count,
            "historicalScope": "persisted-session-events"}
