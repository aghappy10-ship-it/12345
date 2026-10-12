"""Bounded parsing of observed log windows/byte ranges; no device/file/network IO.

Local capture ordinals denote log windows, not sensor frame IDs or completed
photographs. Preview AF/AE, configuration changes and idle queue waits are not
silently promoted to capture/encoding/storage completion evidence.
"""
from __future__ import annotations

from collections import deque
from copy import deepcopy
import re
import threading

SECTION_TITLES = (
    ('ui', '界面与菜单'), ('control', '拍摄控制'), ('hardware', '硬件采集与控制'),
    ('imaging', '图像与算法'), ('storage', '保存与持久化'),
    ('platform', '基础系统'), ('maintenance', '通信与维护'),
)
MAX_EVENTS = 200
MAX_RAW_CHARS = 2000
MAX_INPUT_BYTES = 65536
MAX_LINE_EVIDENCE_RANGES = 128
LOG_LINE = re.compile(r'^(?P<time>\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)'
                      r'\s+\d+\s+\d+\s+[VDIWEF]\s+(?P<tag>[^:]+?)\s*:\s*(?P<body>.*)$')
SHOOT_REQUEST = re.compile(r'\ASHOOTER-still:\s*_x2dss_shoot\s*\(\d+\),\s*start_expo:\s*\[true\]')
EXPLICIT_ID = re.compile(r'(?<![\w])(?P<key>frame[_-]?id|request[_-]?id)\s*[:=]\s*'
                         r'[\["\']?(?P<value>[A-Za-z0-9_.:\-]{1,64})', re.I)


def _classify(tag, body):
    lower, lower_tag = body.lower(), tag.lower()
    if SHOOT_REQUEST.match(body.lstrip()):
        return 'control', '拍摄请求日志（非完成/单帧证明）', 'capture-request'
    if 'graphmgr' in lower and 'ienc_jls' in lower and re.search(r'\b(open|destroy)\b', lower):
        return 'imaging', '编码图配置变化（不是编码完成）', 'graph-configuration'
    if 'shooter_post_process_metadata_queue' in lower and 'timeout' in lower:
        return 'imaging', '队列等待超时（可能空闲，不证明死锁）', 'queue-wait'
    if ('fileio::itemfinished' in lower and 'io::write' in lower and
            'processed, successfully' in lower):
        return 'storage', '日志报告文件写入成功（未读回校验）', 'storage-write-reported-success'
    if any(marker in lower for marker in ('libaf', 'libae', 'af_libaf', 'ae_update')):
        return 'imaging', 'AF/AE 活动（可能是预览，不自动关联照片）', 'algorithm-activity'
    if 'shooter-still:' in lower:
        return 'control', '拍摄控制日志（未证明新拍/完成）', 'capture-control'
    if lower_tag == 'camera-gui' or 'mainmenu' in lower:
        return 'ui', '界面/菜单日志', 'ui-log'
    if re.search(r'\b(sensor|mipi|csi|lens|mcu)\b', lower):
        return 'hardware', '硬件采集/控制日志（未证明完成采集）', 'hardware-log'
    if lower_tag == 'camera-service':
        return 'control', '拍摄控制服务日志（未证明新拍/完成）', 'capture-control'
    if lower_tag == 'camera-storage' or 'fileio::' in lower:
        return 'storage', '存储日志（未证明持久化完成）', 'storage-log'
    if lower_tag in ('init', 'camera-system', 'weston', 'watchdogd'):
        return 'platform', '基础系统日志', 'platform-log'
    if lower_tag in ('phocus', 'camera-upgrade', 'usb', 'adbd') or 'usb ' in lower:
        return 'maintenance', '通信/维护日志', 'maintenance-log'
    return None


def _overlap(previous, current):
    """Longest exact suffix/prefix overlap, including repeated-line multiplicity."""
    if not previous or not current:
        return 0
    sequence = current + [None] + previous[-len(current):]
    prefix = [0] * len(sequence)
    for index in range(1, len(sequence)):
        length = prefix[index - 1]
        while length and sequence[index] != sequence[length]:
            length = prefix[length - 1]
        if sequence[index] == sequence[length]:
            length += 1
        prefix[index] = length
    return prefix[-1]


class CaptureTimeline:
    def __init__(self):
        self.lock = threading.RLock()
        self.events = deque(maxlen=MAX_EVENTS)
        self.captures = deque(maxlen=MAX_EVENTS)
        self.gaps = deque(maxlen=50)
        self.stats = {section: {'id': section, 'title': title, 'count': 0,
                               'lastEvent': None, 'observation': 'unobserved'}
                      for section, title in SECTION_TITLES}
        self.source_stats = deepcopy(self.stats)
        self.recent_raw = []
        self.previous = None
        self.boot_id = None
        self.inode = None
        self.size = None
        self.baseline_utc = None
        self.last_read_utc = None
        self.samples = 0
        self.next_event_id = 1
        self.captured_count = 0
        self.window_id = 1
        self.continuity = 'not-established'
        self.await_baseline = False
        self.baseline_fragment = None
        self.leading_fragment = False
        self.trailing_fragment = False
        self.raw_truncated = 0
        self.gap_count = 0
        self.stream_offset = None
        self.stream_pending = b''
        self.stream_pending_ranges = []
        self.stream_skip_line = False
        self.read_mode = 'tail-snapshot'

    def ingest_chunk(self, raw, *, offset, boot_id, inode, size, received_utc, evidence_path, baseline=False):
        """Consume exact, validated byte ranges, not content-overlap guesses.

        Baseline bytes are old history; only an unfinished old row's completion
        is absorbed. UTF-8 is decoded after newline assembly, never per packet.
        """
        if type(raw) is not bytes or len(raw) > MAX_INPUT_BYTES:
            raise ValueError('Log range must be bytes and at most 65536 bytes')
        if type(offset) is not int or offset < 0 or type(size) is not int or size < offset + len(raw):
            raise ValueError('Log range offset/end exceeds observed file size')
        if (type(boot_id) is not str or not boot_id or len(boot_id) > 128 or
                type(inode) not in (int, str) or not str(inode) or len(str(inode)) > 128 or
                type(received_utc) is not str or not received_utc or len(received_utc) > 128 or
                type(evidence_path) is not str or not evidence_path or len(evidence_path) > 2048 or
                type(baseline) is not bool):
            raise ValueError('Explicit bounded range source and evidence are required')
        with self.lock:
            changed = (self.boot_id is not None and
                (self.boot_id != boot_id or str(self.inode) != str(inode) or size < self.size))
            jumped = self.stream_offset is not None and offset != self.stream_offset
            if jumped and not baseline and not changed and not self.await_baseline:
                self.gap('byte_offset_discontinuity', received_utc=received_utc,
                         evidence_path=evidence_path, boot_id=boot_id, inode=inode, size=size)
            effective_baseline = baseline or changed or jumped or self.await_baseline or self.stream_offset is None
            if effective_baseline:
                result = self.ingest('', boot_id=boot_id, inode=inode, size=size,
                    received_utc=received_utc, evidence_path=evidence_path, baseline=True)
                self.stream_pending = b''
                self.stream_pending_ranges = []
                self.stream_skip_line = bool(raw and not raw.endswith(b'\n'))
                self.stream_offset = offset + len(raw)
                self.read_mode = 'byte-range'
                self.trailing_fragment = self.stream_skip_line
                result['snapshot'] = self.snapshot()
                return result
            combined = self.stream_pending + raw
            ranges = list(self.stream_pending_ranges)
            if raw:
                ranges.append({'evidencePath': evidence_path, 'offset': offset, 'bytes': len(raw)})
            parts = combined.split(b'\n')
            pending = parts.pop()
            if len(pending) > MAX_INPUT_BYTES or any(len(part) > MAX_INPUT_BYTES for part in parts):
                raise ValueError('Unterminated/oversized log line exceeds bounded assembly buffer')
            consumed, skip_line = 0, self.stream_skip_line
            if skip_line and parts:
                consumed = len(parts[0]) + 1
                parts = parts[1:]
                skip_line = False
            # Decode all complete rows before committing events or the cursor.
            lines = [part.decode('utf-8', errors='strict').rstrip('\r') for part in parts]
            line_ranges = []
            for part in parts:
                end = consumed + len(part) + 1
                line_ranges.append(self._byte_evidence(ranges, consumed, end))
                consumed = end
            pending_ranges = self._byte_evidence(ranges, len(combined) - len(pending), len(combined))
            self.boot_id, self.inode, self.size = boot_id, inode, size
            self.samples += 1
            self.last_read_utc = received_utc
            self.leading_fragment = False
            self.trailing_fragment = bool(pending) or skip_line
            self.recent_raw = [line[:MAX_RAW_CHARS] for line in lines[-MAX_EVENTS:]]
            self.raw_truncated = sum(len(line) > MAX_RAW_CHARS for line in lines)
            added, captures = [], []
            for line, sources in zip(lines, line_ranges):
                event, capture = self._event(line, received_utc, evidence_path, sources)
                if event is not None:
                    added.append(event)
                if capture is not None:
                    captures.append(capture)
            self.stream_pending, self.stream_offset = pending, offset + len(raw)
            self.stream_pending_ranges = pending_ranges
            self.stream_skip_line = skip_line
            self.read_mode = 'byte-range'
            if self.continuity != 'gapped':
                self.continuity = 'byte-offset-observed'
            # Each input is bounded to 64KiB. Return every delta to the disk
            # journal; only the live snapshot, not history, is a 200-row view.
            return {'addedEvents': deepcopy(added), 'addedCaptures': deepcopy(captures),
                    'addedEventCount': len(added), 'addedCaptureCount': len(captures),
                    'baseline': False, 'resynchronized': False, 'snapshot': self.snapshot()}

    @staticmethod
    def _byte_evidence(ranges, start, end):
        position, selected = 0, []
        for item in ranges:
            left, right = max(start, position), min(end, position + item['bytes'])
            if right > left:
                selected.append({'evidencePath': item['evidencePath'],
                    'offset': item['offset'] + left - position, 'bytes': right - left})
            position += item['bytes']
        if len(selected) > MAX_LINE_EVIDENCE_RANGES:
            raise ValueError('One log row spans excessive evidence blocks; cannot preserve bounded provenance')
        return selected

    def _event(self, raw, received_utc, evidence_path, evidence_ranges=None):
        match = LOG_LINE.match(raw)
        if not match:
            return None, None
        classification = _classify(match['tag'].strip(), match['body'])
        if classification is None:
            return None, None
        section, label, phase = classification
        event = {'id': self.next_event_id, 'section': section, 'label': label,
                 'phase': phase, 'deviceTime': match['time'], 'receivedUtc': received_utc,
                 'raw': raw[:MAX_RAW_CHARS], 'rawTruncated': len(raw) > MAX_RAW_CHARS,
                 'evidencePath': evidence_path, 'correlation': 'uncorrelated',
                 'evidenceRanges': evidence_ranges or [],
                 'bootId': self.boot_id, 'inode': self.inode, 'logWindowId': self.window_id}
        self.next_event_id += 1
        for identity in EXPLICIT_ID.finditer(match['body']):
            key = 'frameId' if identity['key'].lower().startswith('frame') else 'requestId'
            event[key] = identity['value']
            event['correlation'] = 'explicit-id'
        self.events.append(event)
        state = self.stats[section]
        state.update(count=state['count'] + 1, lastEvent=event, observation='observed')
        source_state = self.source_stats[section]
        source_state.update(count=source_state['count'] + 1, lastEvent=event, observation='observed')
        capture = None
        if phase == 'capture-request':
            self.captured_count += 1
            capture = {'id': self.captured_count, 'startEventId': event['id'],
                       'startDeviceTime': event['deviceTime'], 'receivedUtc': received_utc,
                       'label': f'本地拍摄日志窗口 #{self.captured_count}（非单帧证明）',
                       'scope': 'log-window-not-single-frame-proof', 'bootId': self.boot_id,
                       'logWindowId': self.window_id, 'evidencePath': evidence_path}
            self.captures.append(capture)
        return event, capture

    def ingest(self, text, *, boot_id, inode, size, received_utc, evidence_path, baseline=False):
        """Add a tail snapshot, not an append stream; return deltas and snapshot."""
        if type(text) is not str or len(text.encode('utf-8')) > MAX_INPUT_BYTES:
            raise ValueError('Log-tail text must be UTF-8 and at most 65536 bytes')
        if type(boot_id) is not str or not boot_id or len(boot_id) > 128:
            raise ValueError('A bounded explicit boot ID is required')
        if type(inode) not in (int, str) or not str(inode) or len(str(inode)) > 128:
            raise ValueError('A bounded explicit log inode is required')
        if type(size) is not int or size < 0:
            raise ValueError('Log size must be a nonnegative integer')
        if type(received_utc) is not str or not received_utc or len(received_utc) > 128:
            raise ValueError('An explicit bounded receive timestamp is required')
        if type(evidence_path) is not str or not evidence_path or len(evidence_path) > 2048:
            raise ValueError('An explicit bounded evidence reference is required')
        if type(baseline) is not bool:
            raise ValueError('baseline must be boolean')
        with self.lock:
            changes = []
            if self.boot_id is not None:
                if self.boot_id != boot_id:
                    changes.append('boot_id_changed')
                if str(self.inode) != str(inode):
                    changes.append('inode_changed')
                if size < self.size:
                    changes.append('log_truncated')
            if changes:
                if not self.await_baseline:
                    self._record_gap(', '.join(changes), received_utc, evidence_path, boot_id, inode, size)
                self.await_baseline = True
                self.previous = None
                self.baseline_fragment = None
                for state in self.source_stats.values():
                    state.update(count=0, lastEvent=None, observation='unobserved')
            self.samples += 1
            self.boot_id, self.inode, self.size = boot_id, inode, size
            self.last_read_utc = received_utc
            lines = text.splitlines()
            self.leading_fragment = bool(lines and not LOG_LINE.match(lines[0]))
            self.trailing_fragment = bool(text and not text.endswith('\n'))
            self.recent_raw = [line[:MAX_RAW_CHARS] for line in lines[-MAX_EVENTS:]]
            self.raw_truncated = sum(len(line) > MAX_RAW_CHARS for line in lines)
            trailing_line = lines[-1] if self.trailing_fragment and lines else None
            # The tail collector must remove its own framing separator, preserving
            # the actual EOF newline. An unfinished row cannot enter overlap or
            # produce an event until a later snapshot contains its real terminator.
            if self.trailing_fragment:
                lines = lines[:-1]
            if self.leading_fragment:
                lines = lines[1:]
            effective_baseline = baseline or self.await_baseline
            resynchronized = self.await_baseline
            if effective_baseline:
                self.baseline_utc = received_utc
                self.await_baseline = False
                new_lines = []
            elif self.previous is not None:
                overlap = _overlap(self.previous['lines'], lines)
                new_lines = lines[overlap:]
                if lines == self.previous['lines'] and size > self.previous['size'] and not self.trailing_fragment:
                    self._record_gap('ambiguous_identical_tail_growth; repeated occurrences may be unobserved',
                                     received_utc, evidence_path, boot_id, inode, size)
                elif size == self.previous['size'] and lines != self.previous['lines']:
                    self._record_gap('same_size_content_changed; continuity cannot be established',
                                     received_utc, evidence_path, boot_id, inode, size)
                    effective_baseline = True
                    resynchronized = True
                    self.baseline_utc = received_utc
                    new_lines = []
                elif self.previous['lines'] and not overlap:
                    self._record_gap('no_tail_overlap; intervening observations may be lost',
                                     received_utc, evidence_path, boot_id, inode, size)
                elif overlap and self.continuity != 'gapped':
                    self.continuity = 'overlap-observed'
            else:
                new_lines = lines
            if effective_baseline:
                self.baseline_fragment = trailing_line or None
            elif self.baseline_fragment is not None:
                # Only the unfinished row already present at baseline is old.
                # Absorb its eventual completion once, preserving later duplicates.
                if new_lines and new_lines[0].startswith(self.baseline_fragment):
                    new_lines = new_lines[1:]
                    self.baseline_fragment = None
                elif (not new_lines and trailing_line is not None and
                      trailing_line.startswith(self.baseline_fragment)):
                    self.baseline_fragment = trailing_line
                else:
                    self.baseline_fragment = None
            added, captures = [], []
            for raw in new_lines:
                event, capture = self._event(raw, received_utc, evidence_path)
                if event is not None:
                    added.append(event)
                if capture is not None:
                    captures.append(capture)
            self.previous = {'bootId': boot_id, 'inode': inode, 'size': size, 'lines': lines}
            return {'addedEvents': deepcopy(added), 'addedCaptures': deepcopy(captures),
                    'addedEventCount': len(added), 'addedCaptureCount': len(captures),
                    'baseline': effective_baseline, 'resynchronized': resynchronized, 'snapshot': self.snapshot()}

    def gap(self, reason, *, received_utc=None, evidence_path=None, boot_id=None, inode=None, size=None,
            previous_source_unread=None):
        with self.lock:
            self._record_gap(reason, received_utc, evidence_path, boot_id, inode, size)
            if previous_source_unread is not None:
                self.gaps[-1]['previousSourceUnread'] = deepcopy(previous_source_unread)
            self.await_baseline = True
            self.previous = None
            self.baseline_fragment = None
            self.stream_offset, self.stream_pending, self.stream_skip_line = None, b'', False
            self.stream_pending_ranges = []
            return {'addedEvents': [], 'addedCaptures': [], 'baseline': False,
                    'addedEventCount': 0, 'addedCaptureCount': 0,
                    'resynchronized': True, 'snapshot': self.snapshot()}

    def _record_gap(self, reason, received_utc, evidence_path, boot_id, inode, size):
        self.window_id += 1
        self.gap_count += 1
        self.continuity = 'gapped'
        self.gaps.append({'reason': str(reason)[:1000], 'receivedUtc': received_utc,
                          'evidencePath': evidence_path, 'bootId': boot_id or self.boot_id,
                          'inode': inode, 'size': size, 'logWindowId': self.window_id})

    def snapshot(self):
        with self.lock:
            retained_ids = {event['id'] for event in self.events}
            captures = [dict(capture, windowStartRetained=capture['startEventId'] in retained_ids)
                        for capture in self.captures]
            return deepcopy({'schema': 'x2dii-observed-log-window-timeline-v1',
                'scope': 'observed-log-windows-not-single-frame-proof',
                'bootId': self.boot_id, 'inode': self.inode, 'size': self.size,
                'baselineUtc': self.baseline_utc, 'lastReadUtc': self.last_read_utc,
                'samples': self.samples, 'continuity': self.continuity,
                'readMode': self.read_mode, 'readOffset': self.stream_offset,
                'gapCount': self.gap_count, 'sectionCountScope': 'session',
                'logWindowId': self.window_id, 'sections': list(self.stats.values()),
                'currentSourceSections': list(self.source_stats.values()),
                'events': list(self.events), 'captures': captures, 'gaps': list(self.gaps),
                'eventCount': self.next_event_id - 1,
                'droppedEventCount': self.next_event_id - 1 - len(self.events),
                'retainedEventCount': len(self.events), 'retainedCaptureCount': len(self.captures),
                'recentRaw': self.recent_raw, 'leadingFragment': self.leading_fragment,
                'trailingFragment': self.trailing_fragment,
                'truncatedRawLines': self.raw_truncated,
                'capturedCount': self.captured_count, 'capturedCountBasis': 'observed-start-request-lines',
                'missingEvidence': ['日志未覆盖未记录的内部函数；轮转或覆盖仍可能造成缺口。', '相邻事件不是同一帧关联证明。',
                    '拍摄请求不是照片完成或存储校验通过。', '未观测不代表该层没工作。'],
                'limits': {'events': MAX_EVENTS, 'captures': MAX_EVENTS, 'rawLineChars': MAX_RAW_CHARS}})
