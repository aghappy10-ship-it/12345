"""Byte-range collector fixtures; not live camera or photo qualification."""
import unittest
import base64
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import device_bridge as bridge
from camera_timeline import CaptureTimeline
from test_device_bridge import BOOT, IDENTITY, BASE_LINE, SHOT_LINE, BridgeCase


def sample(raw=b'', *, size=0, inode=17, after_size=None, boot=BOOT):
    payload = base64.b64encode(raw).decode('ascii')
    return (f'{boot}\n{inode} {size}\n' + (payload + '\n' if raw else '') +
            f'{boot}\n{inode} {size if after_size is None else after_size}\n')


class IncrementalReader:
    incremental_log = True
    sources = {'testFixtureOnly': True}

    def __init__(self, log, additions=()):
        self.log = log
        self.additions = list(additions)
        self.log_offset = None
        self.offsets = []
        self.stop_after = None

    def query(self, name):
        if name == 'identity':
            text = IDENTITY
        elif name == 'boot':
            text = 'fixture boot\n'
        else:
            assert name == 'timeline_log'
            self.offsets.append(self.log_offset)
            if self.log_offset is not None and self.additions:
                self.log += self.additions.pop(0)
            raw = b'' if self.log_offset is None else self.log[self.log_offset:self.log_offset + bridge.LOG_CHUNK_BYTES]
            text = sample(raw, size=len(self.log))
            if self.log_offset is not None and self.log_offset + len(raw) == len(self.log) and not self.additions:
                self.stop_after()
        return {'name': name, 'text': text, 'shellLastExitCode': 0,
                'packets': b'fixture', 'rawReceived': b'fixture'}

    def check_unchanged(self):
        pass


class IncrementalCollectorTests(BridgeCase):
    def test_dense_short_rows_are_journaled_in_bounded_segments(self):
        rows = b'10-08 12:00:00 1 1 I usb: \n' * 2520
        reader = IncrementalReader(BASE_LINE.encode(), [rows])
        collector = bridge.DeviceBridge(bridge.PROJECT,
            Path(self.temp.name) / ('dense-journal-' + 'x' * 80), reader_factory=lambda: reader)
        self.addCleanup(collector.close)
        reader.stop_after = collector.monitor_stop.set
        collector.start('monitor-start', {})
        state = self.finish(collector)
        self.assertEqual('completed', state['current']['state'], state['current'].get('error'))
        self.assertEqual(2520, state['monitor']['historyEventCount'])
        segments = list(Path(state['monitor']['evidencePath']).glob('*-events-*.json'))
        self.assertGreater(len(segments), 1)
        self.assertTrue(all(path.stat().st_size <= bridge.MAX_RAW_BYTES for path in segments))
        page = collector.history(state['monitor']['sessionId'], limit=200)
        self.assertEqual(list(range(2321, 2521)), [row['id'] for row in page['events']])

    def test_connection_failure_wrapped_with_empty_receive_diagnostics_retries(self):
        from tools.live_readout import QueryFailure
        class ConnectionFailed(IncrementalReader):
            failed = False
            def query(self, name):
                if name == 'timeline_log' and self.log_offset is not None and not self.failed:
                    self.failed = True
                    self.log += SHOT_LINE.encode()
                    try:
                        raise ConnectionRefusedError('fixture endpoint absent')
                    except ConnectionRefusedError as cause:
                        raise QueryFailure('fixture connection failed', b'', b'', {}) from cause
                return super().query(name)
        reader = ConnectionFailed(BASE_LINE.encode())
        collector = self.bridge(reader)
        reader.stop_after = collector.monitor_stop.set
        collector.start('monitor-start', {})
        state = self.finish(collector)
        self.assertEqual('completed', state['current']['state'], state['current'].get('error'))
        self.assertEqual(1, state['monitor']['timeline']['capturedCount'])
        self.assertEqual(1, state['monitor']['totalReconnects'])

    def test_timeout_with_duplicate_completion_is_protocol_failure_not_retry(self):
        from tools.live_readout import QueryFailure
        class Duplicate(IncrementalReader):
            def query(self, name):
                if name == 'timeline_log' and self.log_offset is not None:
                    raise QueryFailure('missing native terminal', b'raw', b'packets',
                        {'stop_reason': 'socket_timeout', 'terminal_count': 0, 'completion_line_count': 2})
                return super().query(name)
        reader = Duplicate(BASE_LINE.encode())
        collector = self.bridge(reader)
        collector.start('monitor-start', {})
        state = self.finish(collector)
        self.assertEqual('failed', state['monitor']['state'])
        self.assertEqual(0, state['monitor']['totalReconnects'])
        record = json.loads((Path(state['monitor']['evidencePath']) / '05-timeline_log.json').read_text(encoding='utf-8'))
        self.assertEqual(2, record['receive']['completion_line_count'])

    def test_reconnect_exhaustion_preserves_cursor_and_terminal_evidence(self):
        clock = [0]
        class Offline(IncrementalReader):
            failures = 0
            def query(self, name):
                if name == 'timeline_log' and self.log_offset is not None:
                    self.failures += 1
                    if self.failures == 2:
                        clock[0] += bridge.MAX_RECONNECT_SECONDS + 1
                    raise ConnectionResetError('fixture still offline')
                return super().query(name)
        reader = Offline(BASE_LINE.encode())
        collector = self.bridge(reader)
        collector.clock = lambda: clock[0]
        with patch.object(collector.monitor_stop, 'wait', return_value=False):
            collector.start('monitor-start', {})
            state = self.finish(collector)
        self.assertEqual('failed', state['monitor']['state'])
        self.assertEqual(len(BASE_LINE.encode()), state['monitor']['readOffset'])
        self.assertTrue((Path(state['monitor']['evidencePath']) / 'RESULT.json').exists())
        self.assertEqual(2, reader.failures)

    def test_stop_during_reconnect_cancels_without_next_query(self):
        class Offline(IncrementalReader):
            def query(self, name):
                if name == 'timeline_log' and self.log_offset is not None:
                    self.stop_after()
                    raise ConnectionResetError('fixture stopped after unplug')
                return super().query(name)
        reader = Offline(BASE_LINE.encode())
        collector = self.bridge(reader)
        reader.stop_after = collector.monitor_stop.set
        collector.start('monitor-start', {})
        state = self.finish(collector)
        self.assertEqual('stopped', state['monitor']['state'])
        self.assertEqual(5, state['current']['deviceRequests'])

    def test_event_journal_failure_does_not_retry_or_claim_saved_events(self):
        reader = IncrementalReader(BASE_LINE.encode(), [SHOT_LINE.encode()])
        collector = self.bridge(reader)
        reader.stop_after = collector.monitor_stop.set
        save = collector._file
        def denied(path, raw):
            if '-events-' in path.name:
                raise OSError('fixture journal disk failed')
            return save(path, raw)
        with patch.object(collector, '_file', side_effect=denied):
            collector.start('monitor-start', {})
            state = self.finish(collector)
        self.assertEqual('failed', state['monitor']['state'])
        self.assertEqual(0, state['monitor']['historyEventCount'])
        self.assertEqual(0, state['monitor']['totalReconnects'])

    def test_later_journal_segment_failure_keeps_earlier_history_readable(self):
        for boundary in ('write', 'rename'):
            with self.subTest(boundary=boundary):
                reader = IncrementalReader(BASE_LINE.encode(), [SHOT_LINE.encode() * 600])
                collector = self.bridge(reader)
                reader.stop_after = collector.monitor_stop.set
                save, replace = collector._file, bridge.os.replace
                def denied(path, raw):
                    if '-events-201-' in path.name:
                        raise OSError('fixture second segment failed')
                    return save(path, raw)
                def rename_denied(source, destination):
                    if '-events-201-' in Path(destination).name:
                        raise OSError('fixture second segment publication failed')
                    return replace(source, destination)
                failure = patch.object(collector, '_file', side_effect=denied) if boundary == 'write' else \
                    patch.object(bridge.os, 'replace', side_effect=rename_denied)
                with failure:
                    collector.start('monitor-start', {})
                    state = self.finish(collector)
                self.assertEqual('failed', state['monitor']['state'])
                self.assertEqual(200, state['monitor']['historyEventCount'])
                self.assertEqual(600, state['monitor']['timeline']['eventCount'])
                page = collector.history(state['monitor']['sessionId'])
                self.assertEqual(list(range(1, 201)), [row['id'] for row in page['events']])
                self.assertEqual(0, state['monitor']['totalReconnects'])
                result = json.loads((Path(state['monitor']['evidencePath']) / 'RESULT.json').read_text(encoding='utf-8'))
                self.assertEqual(200, result['logMonitorSummary']['historyEventCount'])

    def test_established_anchor_rewrite_does_not_replay_old_requests(self):
        class Rewritten(IncrementalReader):
            ranges = 0
            def query(self, name):
                if name == 'timeline_log' and self.log_offset is not None:
                    self.ranges += 1
                    if self.ranges == 2:
                        self.log = self.log.replace(b'[true]', b'[fals]')
                return super().query(name)
        reader = Rewritten(BASE_LINE.encode(), [SHOT_LINE.encode()])
        collector = self.bridge(reader)
        reader.stop_after = lambda: collector.monitor_stop.set() if reader.ranges >= 3 else None
        with patch.object(bridge, 'MONITOR_INTERVAL_SECONDS', .001):
            collector.start('monitor-start', {})
            state = self.finish(collector)
        self.assertEqual('completed', state['current']['state'], state['current'].get('error'))
        self.assertEqual(1, state['monitor']['timeline']['capturedCount'])
        self.assertEqual(1, state['monitor']['timeline']['gapCount'])

    def test_transport_retry_keeps_cursor_and_half_line_without_replay(self):
        class Interrupted(IncrementalReader):
            def __init__(self):
                super().__init__(BASE_LINE.encode())
                self.stage = 0
            def query(self, name):
                if name == 'timeline_log' and self.log_offset is not None:
                    self.stage += 1
                    if self.stage == 1:
                        self.additions = [SHOT_LINE[:47].encode()]
                        result = super().query(name)
                        return result
                    if self.stage == 2:
                        self.log += SHOT_LINE[47:].encode()
                        raise ConnectionResetError('fixture unplugged')
                return super().query(name)
        reader = Interrupted()
        collector = self.bridge(reader)
        reader.stop_after = lambda: collector.monitor_stop.set() if reader.stage >= 3 else None
        with patch.object(bridge, 'MONITOR_INTERVAL_SECONDS', .001):
            collector.start('monitor-start', {})
            state = self.finish(collector)
        self.assertEqual('completed', state['current']['state'], state['current'].get('error'))
        self.assertEqual(1, state['monitor']['timeline']['capturedCount'])
        self.assertEqual(0, state['monitor']['timeline']['gapCount'])
        self.assertEqual(1, state['monitor']['totalReconnects'])
        self.assertEqual(len(reader.log), state['monitor']['readOffset'])

    def test_rotation_reads_new_file_from_start_instead_of_skipping_to_eof(self):
        class Rotation(IncrementalReader):
            def __init__(self):
                super().__init__(BASE_LINE.encode() * 500)
                self.rotated = False
            def query(self, name):
                if name == 'timeline_log' and self.log_offset is not None:
                    self.rotated = True
                    self.log = SHOT_LINE.encode() * 3
                result = super().query(name)
                if self.rotated:
                    result['text'] = result['text'].replace('\n17 ', '\n18 ')
                return result
        reader = Rotation()
        collector = self.bridge(reader)
        reader.stop_after = lambda: collector.monitor_stop.set() if reader.log_offset == 0 else None
        with patch.object(bridge, 'MONITOR_INTERVAL_SECONDS', .001):
            collector.start('monitor-start', {})
            state = self.finish(collector)
        self.assertEqual('completed', state['current']['state'], state['current'].get('error'))
        self.assertEqual(3, state['monitor']['timeline']['capturedCount'])
        self.assertEqual(1, state['monitor']['timeline']['gapCount'])

    def test_202kib_growth_is_drained_from_cursor_without_tail_gap(self):
        reader = IncrementalReader(BASE_LINE.encode(), [SHOT_LINE.encode() * 2400])
        collector = self.bridge(reader)
        reader.stop_after = collector.monitor_stop.set
        with patch.object(bridge, 'MONITOR_INTERVAL_SECONDS', .001):
            collector.start('monitor-start', {})
            state = self.finish(collector)
        self.assertEqual('completed', state['current']['state'], state['current'].get('error'))
        timeline = state['monitor']['timeline']
        self.assertEqual(2400, timeline['capturedCount'])
        self.assertEqual(0, timeline['gapCount'])
        self.assertEqual(len(reader.log), state['monitor']['readOffset'])
        self.assertEqual(0, state['monitor']['backlogBytes'])
        self.assertGreater(len(reader.offsets), 4)

    def test_range_error_without_proven_change_is_terminal_and_retained(self):
        class Denied(IncrementalReader):
            def query(self, name):
                if name == 'timeline_meta':
                    return {'name': name, 'text': sample(size=len(self.log)), 'shellLastExitCode': 0,
                            'packets': b'metadata', 'rawReceived': b'metadata'}
                if name == 'timeline_log' and self.log_offset is not None:
                    return {'name': name, 'text': 'Permission denied\n', 'shellLastExitCode': 1,
                            'packets': b'denied', 'rawReceived': b'denied'}
                return super().query(name)
        reader = Denied(BASE_LINE.encode())
        collector = self.bridge(reader)
        collector.start('monitor-start', {})
        state = self.finish(collector)
        self.assertEqual('failed', state['monitor']['state'])
        folder = Path(state['monitor']['evidencePath'])
        self.assertIn('Permission denied', (folder / '05-timeline_log.txt').read_text())
        self.assertTrue((folder / '06-timeline_meta.txt').exists())

    def test_after_boundary_truncation_alone_recovers_failed_range(self):
        class AfterTruncate(IncrementalReader):
            def query(self, name):
                if name == 'timeline_meta':
                    self.stop_after()
                    return {'name': name, 'text': sample(size=len(self.log), after_size=1), 'shellLastExitCode': 0,
                            'packets': b'metadata', 'rawReceived': b'metadata'}
                if name == 'timeline_log' and self.log_offset is not None:
                    return {'name': name, 'text': 'range error\n', 'shellLastExitCode': 1,
                            'packets': b'failure', 'rawReceived': b'failure'}
                return super().query(name)
        reader = AfterTruncate(BASE_LINE.encode())
        collector = self.bridge(reader)
        reader.stop_after = collector.monitor_stop.set
        collector.start('monitor-start', {})
        state = self.finish(collector)
        self.assertEqual('completed', state['current']['state'], state['current'].get('error'))
        self.assertEqual(1, state['monitor']['timeline']['gapCount'])

    def test_truncated_range_error_rebaselines_then_counts_new_request(self):
        class Truncated(IncrementalReader):
            def __init__(self):
                super().__init__(BASE_LINE.encode() * 500)
                self.failed_once = False
                self.anchored = False
            def query(self, name):
                if name == 'timeline_meta':
                    return {'name': name, 'text': sample(size=len(self.log)), 'shellLastExitCode': 0,
                            'packets': b'metadata', 'rawReceived': b'metadata'}
                if name == 'timeline_log' and self.log_offset is not None:
                    if not self.failed_once:
                        self.failed_once = True
                        self.log = BASE_LINE.encode()
                        return {'name': name, 'text': 'od: skip past end\n', 'shellLastExitCode': 1,
                                'packets': b'failure', 'rawReceived': b'failure'}
                    if not self.anchored:
                        self.anchored = True
                        self.additions = [SHOT_LINE.encode()]
                return super().query(name)
        reader = Truncated()
        collector = self.bridge(reader)
        reader.stop_after = collector.monitor_stop.set
        with patch.object(bridge, 'MONITOR_INTERVAL_SECONDS', .001):
            collector.start('monitor-start', {})
            state = self.finish(collector)
        self.assertEqual('completed', state['current']['state'], state['current'].get('error'))
        self.assertEqual(1, state['monitor']['timeline']['gapCount'])
        self.assertEqual(1, state['monitor']['timeline']['capturedCount'])

    def test_stop_during_first_full_backlog_range_does_not_query_again(self):
        class Stopped(IncrementalReader):
            def query(self, name):
                result = super().query(name)
                if name == 'timeline_log' and self.log_offset is not None:
                    self.stop_after()
                return result
        reader = Stopped(BASE_LINE.encode(), [SHOT_LINE.encode() * 2400])
        collector = self.bridge(reader)
        reader.stop_after = collector.monitor_stop.set
        collector.start('monitor-start', {})
        state = self.finish(collector)
        self.assertEqual(2, len(reader.offsets))
        self.assertEqual('stopped', state['monitor']['state'])
        self.assertGreater(state['monitor']['backlogBytes'], 0)

    def test_time_limit_checked_between_backlog_ranges(self):
        clock = [0]
        class Slow(IncrementalReader):
            def query(self, name):
                result = super().query(name)
                if name == 'timeline_log' and self.log_offset is not None:
                    clock[0] = bridge.MAX_MONITOR_SECONDS
                return result
        reader = Slow(BASE_LINE.encode(), [SHOT_LINE.encode() * 2400])
        collector = self.bridge(reader)
        collector.clock = lambda: clock[0]
        reader.stop_after = collector.monitor_stop.set
        collector.start('monitor-start', {})
        state = self.finish(collector)
        self.assertEqual(2, len(reader.offsets))
        self.assertEqual('limit-reached', state['monitor']['state'])

    def test_rotated_source_is_not_processed_until_new_baseline(self):
        class Rotated(IncrementalReader):
            def query(self, name):
                result = super().query(name)
                if name == 'timeline_log' and self.log_offset is not None:
                    result['text'] = result['text'].replace('\n17 ', '\n18 ')
                return result
        reader = Rotated(BASE_LINE.encode(), [SHOT_LINE.encode()])
        collector = self.bridge(reader)
        reader.stop_after = collector.monitor_stop.set
        collector.start('monitor-start', {})
        state = self.finish(collector)
        self.assertEqual('completed', state['current']['state'], state['current'].get('error'))
        self.assertEqual(1, state['monitor']['timeline']['gapCount'])
        self.assertEqual(0, state['monitor']['timeline']['capturedCount'])
        self.assertIsNone(state['monitor']['backlogBytes'])
        self.assertFalse(state['monitor']['lastSampleStable'])
        gap = state['monitor']['timeline']['gaps'][0]
        self.assertEqual(17, gap['previousSourceUnread']['inode'])
        self.assertFalse(gap['previousSourceUnread']['recovered'])
        self.assertTrue(any(Path(state['monitor']['evidencePath']).glob('*-continuity.json')))

    def test_old_half_line_and_its_provenance_are_discarded_across_rotation(self):
        class Turnover(IncrementalReader):
            def __init__(self):
                super().__init__(BASE_LINE.encode())
                self.stage = 0
                self.rotated = False
            def query(self, name):
                if name == 'timeline_log' and self.log_offset is not None:
                    self.stage += 1
                    if self.stage == 1:
                        self.additions = [SHOT_LINE[:47].encode()]
                    elif self.stage == 2:
                        self.log = SHOT_LINE.encode()
                        self.rotated = True
                result = super().query(name)
                if self.rotated:
                    result['text'] = result['text'].replace('\n17 ', '\n18 ')
                return result
        reader = Turnover()
        collector = self.bridge(reader)
        reader.stop_after = lambda: collector.monitor_stop.set() if reader.log_offset == 0 else None
        with patch.object(bridge, 'MONITOR_INTERVAL_SECONDS', .001):
            collector.start('monitor-start', {})
            state = self.finish(collector)
        self.assertEqual('completed', state['current']['state'], state['current'].get('error'))
        timeline = state['monitor']['timeline']
        self.assertEqual(1, timeline['capturedCount'])
        self.assertTrue(timeline['gaps'][0]['previousSourceUnread']['unfinishedLine'])
        self.assertEqual(1, len(timeline['events'][0]['evidenceRanges']))
        self.assertEqual(0, timeline['events'][0]['evidenceRanges'][0]['offset'])


class IncrementalParserTests(unittest.TestCase):
    def ingest(self, raw, offset, **kwargs):
        return self.timeline.ingest_chunk(raw, offset=offset, boot_id=BOOT, inode=17,
            size=offset + len(raw), received_utc='fixture-time', evidence_path='fixture-evidence', **kwargs)

    def setUp(self):
        self.timeline = CaptureTimeline()

    def test_unicode_and_partial_line_across_chunks_are_counted_once(self):
        raw = (SHOT_LINE + BASE_LINE.replace('MainMenu ready', '界面准备完成')).encode()
        cut = raw.index('界'.encode()) + 1
        self.ingest(b'\n', 40, baseline=True)
        self.ingest(raw[:cut], 41)
        state = self.ingest(raw[cut:], 41 + cut)['snapshot']
        self.assertEqual(1, state['capturedCount'])
        self.assertEqual(2, state['eventCount'])
        self.assertEqual(0, state['gapCount'])
        self.assertIn('界面准备完成', state['events'][-1]['raw'])

    def test_three_block_line_keeps_all_exact_evidence_ranges(self):
        self.ingest(b'\n', 40, baseline=True)
        raw = SHOT_LINE.encode()
        for start, end, name in ((0, 20, 'block-a'), (20, 50, 'block-b'), (50, len(raw), 'block-c')):
            self.timeline.ingest_chunk(raw[start:end], offset=41 + start, boot_id=BOOT,
                inode=17, size=41 + end, received_utc='fixture-time', evidence_path=name)
        event = self.timeline.snapshot()['events'][0]
        self.assertEqual([
            {'evidencePath': 'block-a', 'offset': 41, 'bytes': 20},
            {'evidencePath': 'block-b', 'offset': 61, 'bytes': 30},
            {'evidencePath': 'block-c', 'offset': 91, 'bytes': len(raw) - 50},
        ], event['evidenceRanges'])

    def test_all_events_in_large_chunk_are_journal_deltas_not_only_200(self):
        self.ingest(b'\n', 0, baseline=True)
        result = self.ingest(SHOT_LINE.encode() * 600, 1)
        self.assertEqual(600, len(result['addedEvents']))
        self.assertEqual(200, len(result['snapshot']['events']))

    def test_baseline_old_partial_line_is_absorbed_not_next_request(self):
        self.ingest(b'old part', 100, baseline=True)
        state = self.ingest(b' finishes\n' + SHOT_LINE.encode(), 108)['snapshot']
        self.assertEqual(1, state['capturedCount'])
        self.assertEqual(0, state['gapCount'])

    def test_offset_jump_is_explicit_gap_and_not_counted_as_fresh_capture(self):
        self.ingest(b'\n', 10, baseline=True)
        state = self.ingest(SHOT_LINE.encode(), 99)['snapshot']
        self.assertEqual(1, state['gapCount'])
        self.assertEqual(0, state['capturedCount'])

    def test_range_command_fits_native_slot_at_maximum_offset(self):
        from tools import live_readout
        transport = live_readout.load_transport()
        command = bridge._timeline_command(2 ** 63 - 1)
        suffix = ";printf '\\n__RC_123456abcdef__%s\\n__RD_123456abcdef__\\n' $?"
        self.assertLess(len((command + suffix).encode('ascii')), transport.SUTEST_TEXT_CAPACITY)
        self.assertIn('exec 3</blackbox/camera/log/cam.log', command)
        self.assertIn('<&3', command)
        # The target's stat child does not inherit fd 3. Bind the opening
        # shell's descriptor, not /proc/self evaluated by the stat process.
        self.assertIn('/proc/$$/fd/3', command)
        self.assertNotIn('/proc/self/fd/3', command)

    def test_invalid_hex_short_and_oversize_ranges_are_rejected(self):
        for text, offset in ((sample(b'abc', size=4), 0),
                             (sample(b'x' * (bridge.LOG_CHUNK_BYTES + 1), size=bridge.LOG_CHUNK_BYTES + 1), 0),
                             (sample(b'abc', size=3).replace('YWJj', 'YWJ!'), 0)):
            with self.subTest(length=len(text)), self.assertRaises(ValueError):
                bridge.DeviceBridge._stream_sample(text, offset)

    def test_prior_gap_and_new_source_baseline_do_not_double_count_truncation(self):
        self.ingest(b'\n', 100, baseline=True)
        self.timeline.gap('confirmed truncation')
        self.ingest(b'\n', 10, baseline=True)
        self.assertEqual(1, self.timeline.snapshot()['gapCount'])

    def test_base64_must_have_complete_canonical_padding(self):
        for payload in ('YQ', 'YQ====', 'YR==', 'YWJj!'):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                bridge.DeviceBridge._stream_sample(sample(b'a', size=1).replace('YQ==', payload), 0)

    def test_invalid_utf8_does_not_commit_events_or_offset(self):
        self.ingest(b'\n', 40, baseline=True)
        with self.assertRaises(UnicodeDecodeError):
            self.ingest(SHOT_LINE.encode() + b'\xff\n', 41)
        state = self.timeline.snapshot()
        self.assertEqual(0, state['eventCount'])
        self.assertEqual(41, state['readOffset'])

    def test_unterminated_line_is_bounded(self):
        self.ingest(b'\n', 10, baseline=True)
        self.ingest(b'x' * 65536, 11)
        with self.assertRaises(ValueError):
            self.ingest(b'x', 65547)


if __name__ == '__main__':
    unittest.main()
