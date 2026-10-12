"""Synthetic log-shape fixtures; not live camera/per-frame evidence."""
import unittest

if __package__:
    from .camera_timeline import CaptureTimeline
else:
    from camera_timeline import CaptureTimeline


def line(body, *, tag='DUSS51', time='17:31:20.966', level='I'):
    return f'08-30 {time}   381  1915 {level} {tag}  : {body}\n'


REQUEST = 'SHOOTER-still: _x2dss_shoot (3772), start_expo:[true] (want_raw: true, want_preview: true)'


class CaptureTimelineTests(unittest.TestCase):
    def setUp(self):
        self.timeline = CaptureTimeline()

    def ingest(self, text, *, size=None, baseline=False, boot='fixture-boot', inode=42):
        return self.timeline.ingest(text, boot_id=boot, inode=inode,
            size=len(text.encode('utf-8')) if size is None else size,
            received_utc='2026-10-08T12:00:00Z', evidence_path='fixture://synthetic-log-shapes', baseline=baseline)

    def test_only_true_shooter_start_is_a_request_and_nearby_logs_are_not_frame_links(self):
        text = (line(REQUEST) +
                line('GraphMgr destroy/open ienc_jls') +
                line('BufferQueue(shooter_post_process_metadata_queue):peek waiting timeout:-1002') +
                line('libaf/libae preview update') +
                line('fileio.cpp:0287 void FileIO::itemFinished(const IO::Result &): "B0000272.3FR" IO::Write processed, successfully', tag='camera-storage') +
                line(REQUEST.replace('[true]', '[false]')))
        result = self.ingest(text)
        snapshot = result['snapshot']
        self.assertEqual(snapshot['capturedCount'], 1)
        self.assertEqual(len(result['addedCaptures']), 1)
        capture = snapshot['captures'][0]
        self.assertEqual(capture['startEventId'], snapshot['events'][0]['id'])
        self.assertEqual(capture['scope'], 'log-window-not-single-frame-proof')
        self.assertTrue(all(event['correlation'] == 'uncorrelated' for event in snapshot['events']))
        self.assertTrue(all('captureId' not in event for event in snapshot['events']))
        phases = {event['phase'] for event in snapshot['events']}
        self.assertIn('graph-configuration', phases)
        self.assertIn('queue-wait', phases)
        self.assertIn('algorithm-activity', phases)
        self.assertIn('storage-write-reported-success', phases)
        self.assertNotIn('encoding-complete', phases)
        sections = {section['id']: section for section in snapshot['sections']}
        self.assertEqual(sections['ui']['observation'], 'unobserved')
        self.assertEqual(sections['storage']['observation'], 'observed')

    def test_tail_baseline_overlap_and_duplicate_occurrences_do_not_replay_old_shots(self):
        baseline = self.ingest(line(REQUEST), size=1000, baseline=True)
        self.assertEqual(baseline['snapshot']['capturedCount'], 0)
        self.assertEqual(baseline['addedEvents'], [])
        grown = self.ingest(line(REQUEST) * 3, size=2000)
        self.assertEqual(len(grown['addedCaptures']), 2)
        self.assertEqual(grown['snapshot']['capturedCount'], 2)
        replay = self.ingest(line(REQUEST) * 3, size=2000)
        self.assertEqual(replay['addedEvents'], [])
        self.assertEqual(replay['snapshot']['capturedCount'], 2)
        appended = self.ingest(line(REQUEST) * 4, size=3000)
        self.assertEqual(len(appended['addedCaptures']), 1)
        self.assertEqual(appended['snapshot']['capturedCount'], 3)
        self.assertEqual([event['id'] for event in appended['snapshot']['events']], [1, 2, 3])

    def test_boot_inode_and_truncation_boundaries_gap_then_absorb_a_new_baseline(self):
        for metadata, cause in (({'boot': 'new-fixture-boot', 'inode': 42, 'size': 1100}, 'boot'),
                                ({'boot': 'fixture-boot', 'inode': 99, 'size': 1100}, 'inode'),
                                ({'boot': 'fixture-boot', 'inode': 42, 'size': 900}, 'truncate')):
            with self.subTest(cause=cause):
                self.timeline = CaptureTimeline()
                self.ingest(line(REQUEST), size=1000)
                changed = self.ingest(line(REQUEST), **metadata)
                self.assertEqual(changed['addedCaptures'], [])
                self.assertTrue(changed['baseline'])
                self.assertTrue(changed['resynchronized'])
                self.assertEqual(changed['snapshot']['capturedCount'], 1)
                self.assertTrue(any(cause in gap['reason'] for gap in changed['snapshot']['gaps']))
                sections = {section['id']: section for section in changed['snapshot']['currentSourceSections']}
                self.assertEqual(sections['control']['observation'], 'unobserved')
                self.assertEqual(changed['snapshot']['sections'][1]['count'], 1)

    def test_no_overlap_and_identical_tail_growth_disclose_missing_observation(self):
        self.ingest(line('camera startup', tag='camera-system'), size=1000, baseline=True)
        lost = self.ingest(line(REQUEST), size=2000)
        self.assertEqual(len(lost['addedCaptures']), 1)
        self.assertEqual(lost['snapshot']['continuity'], 'gapped')
        self.assertTrue(any('overlap' in gap['reason'] for gap in lost['snapshot']['gaps']))
        ambiguous = self.ingest(line(REQUEST), size=3000)
        self.assertEqual(ambiguous['addedCaptures'], [])
        self.assertEqual(ambiguous['snapshot']['capturedCount'], 1)
        self.assertTrue(any('identical' in gap['reason'] for gap in ambiguous['snapshot']['gaps']))

    def test_quoted_diagnostic_marker_is_not_a_real_shooter_request(self):
        result = self.ingest(line('diagnostic example: "' + REQUEST + '"'))
        self.assertEqual(result['snapshot']['capturedCount'], 0)

    def test_only_literal_explicit_ids_are_correlation_evidence(self):
        result = self.ingest(line(REQUEST + ' frame_id:[42] requestId="req-A"') +
                             line('libaf/libae preview update filename B0000272.3FR'))
        first, second = result['snapshot']['events']
        self.assertEqual(first['frameId'], '42')
        self.assertEqual(first['requestId'], 'req-A')
        self.assertEqual(first['correlation'], 'explicit-id')
        self.assertEqual(second['correlation'], 'uncorrelated')
        self.assertNotIn('frameId', second)

    def test_tail_first_fragment_is_not_promoted_and_remainder_still_overlaps(self):
        old = line('libaf preview') + line(REQUEST)
        self.ingest(old, size=1000, baseline=True)
        current = 'fragment of old log\n' + line(REQUEST) + line('sensor register update')
        result = self.ingest(current, size=2000)
        self.assertTrue(result['snapshot']['leadingFragment'])
        self.assertEqual(result['addedCaptures'], [])
        self.assertEqual(len(result['addedEvents']), 1)
        self.assertEqual(result['addedEvents'][0]['section'], 'hardware')

    def test_explicit_gap_requires_next_sample_baseline_not_replayed_capture(self):
        self.ingest(line(REQUEST), size=1000)
        result = self.timeline.gap('fixture transport loss', received_utc='fixture-time',
                                   evidence_path='fixture://transport-loss')
        self.assertEqual(result['snapshot']['continuity'], 'gapped')
        resynchronized = self.ingest(line(REQUEST) * 2, size=3000)
        self.assertTrue(resynchronized['baseline'])
        self.assertTrue(resynchronized['resynchronized'])
        self.assertEqual(resynchronized['addedCaptures'], [])
        appended = self.ingest(line(REQUEST) * 3, size=4000)
        self.assertEqual(len(appended['addedCaptures']), 1)

    def test_bounded_snapshots_disclose_events_no_longer_retained_and_are_copies(self):
        text = ''.join(line('sensor ' + str(index) + ' ' + 'x' * 2000) for index in range(25))
        self.ingest(text, size=100000)
        current = ''.join(line(REQUEST, time=f'17:31:{index % 60:02d}.966') for index in range(205))
        result = self.ingest(current, size=200000)
        snapshot = result['snapshot']
        self.assertEqual(len(snapshot['events']), 200)
        self.assertEqual(len(snapshot['captures']), 200)
        self.assertTrue(all(len(event['raw']) <= 2000 for event in snapshot['events']))
        self.assertTrue(all(len(raw) <= 2000 for raw in snapshot['recentRaw']))
        self.assertGreater(snapshot['droppedEventCount'], 0)
        snapshot['sections'][0]['title'] = 'mutated fixture'
        self.assertEqual(self.timeline.snapshot()['sections'][0]['title'], '界面与菜单')

    def test_invalid_metadata_or_oversized_input_never_mutates_state(self):
        defaults = {'boot_id': 'fixture-boot', 'inode': 42, 'size': 1,
                    'received_utc': 'fixture-time', 'evidence_path': 'fixture://input'}
        for key, value in (('boot_id', ''), ('inode', True), ('size', True),
                           ('size', -1), ('received_utc', None), ('evidence_path', ''), ('baseline', 1)):
            with self.assertRaises(ValueError):
                self.timeline.ingest(line(REQUEST), **{**defaults, key: value})
        with self.assertRaises(ValueError):
            self.timeline.ingest('x' * 65537, **defaults)
        self.assertEqual(self.timeline.snapshot()['samples'], 0)

    def test_seven_layers_use_literal_activity_and_never_normal_or_completion_flags(self):
        empty = self.timeline.snapshot()
        self.assertEqual([section['title'] for section in empty['sections']], [
            '界面与菜单', '拍摄控制', '硬件采集与控制', '图像与算法',
            '保存与持久化', '基础系统', '通信与维护'])
        self.assertTrue(all(section['observation'] == 'unobserved' for section in empty['sections']))
        text = (line('menu activated', tag='camera-gui') + line(REQUEST) +
                line('sensor register update', tag='camera-service') + line('libaf preview update') +
                line('FileIO::itemFinished: IO::Write processed, successfully', tag='camera-storage') +
                line('service lifecycle', tag='camera-system') + line('usb cable status', tag='usb'))
        sections = self.ingest(text)['snapshot']['sections']
        self.assertTrue(all(section['count'] == 1 for section in sections), sections)
        self.assertTrue(all(section['observation'] == 'observed' for section in sections))
        self.assertTrue(all('normal' not in section and 'complete' not in section for section in sections))

    def test_same_size_content_change_is_not_counted_as_continuous_new_shot(self):
        self.ingest(line('service startup', tag='camera-system'), size=1000, baseline=True)
        changed = self.ingest(line(REQUEST), size=1000)
        self.assertTrue(changed['baseline'])
        self.assertEqual(changed['addedCaptures'], [])
        self.assertTrue(any('same_size' in gap['reason'] for gap in changed['snapshot']['gaps']))

    def test_unfinished_eof_line_does_not_replay_the_previous_complete_request(self):
        self.ingest(line('startup', tag='camera-system'), size=1000, baseline=True)
        partial = line(REQUEST) + '08-30 17:31:21.000   381  1915 I DUSS51 : sensor reg'
        first = self.ingest(partial, size=2000)
        self.assertEqual(first['snapshot']['capturedCount'], 1)
        self.assertTrue(first['snapshot']['trailingFragment'])
        complete = line(REQUEST) + line('sensor register update', time='17:31:21.000')
        second = self.ingest(complete, size=3000)
        self.assertEqual(second['snapshot']['capturedCount'], 1)
        self.assertEqual(second['addedCaptures'], [])
        self.assertEqual(len(second['addedEvents']), 1)
        self.assertEqual(second['addedEvents'][0]['section'], 'hardware')

    def test_request_without_real_final_newline_is_deferred_until_terminated(self):
        pending = self.ingest(line(REQUEST).rstrip('\n'), size=1000)
        self.assertEqual(pending['snapshot']['capturedCount'], 0)
        self.assertTrue(pending['snapshot']['trailingFragment'])
        terminated = self.ingest(line(REQUEST), size=1001)
        self.assertEqual(terminated['snapshot']['capturedCount'], 1)
        self.assertFalse(terminated['snapshot']['trailingFragment'])

    def test_baseline_unfinished_request_is_absorbed_when_completed_not_a_new_capture(self):
        startup = line('startup', tag='camera-system')
        request = line(REQUEST)
        prefix = request[:request.index('start_expo:') + len('start_expo:[')]
        self.ingest(startup + prefix, size=1000, baseline=True)
        extended = self.ingest(startup + request.rstrip('\n'), size=1100)
        self.assertEqual(extended['addedEvents'], [])
        completed = self.ingest(startup + request, size=1200)
        self.assertEqual(completed['addedEvents'], [])
        self.assertEqual(completed['addedCaptures'], [])
        self.assertEqual(completed['snapshot']['capturedCount'], 0)
        # A distinct occurrence begun after baseline must still count on completion.
        pending = self.ingest(startup + request + request.rstrip('\n'), size=1300)
        self.assertEqual(pending['addedEvents'], [])
        new_request = self.ingest(startup + request * 2, size=1400)
        self.assertEqual(new_request['addedCaptureCount'], 1)
        self.assertEqual(new_request['snapshot']['capturedCount'], 1)
        # An empty split row is not a prefix of a historical request.
        self.timeline = CaptureTimeline()
        self.ingest('\r', size=1000, baseline=True)
        after_empty_row = self.ingest('\r' + request, size=1200)
        self.assertEqual(after_empty_row['addedCaptureCount'], 1)

    def test_resynchronized_unfinished_request_is_absorbed_when_completed(self):
        request = line(REQUEST)
        prefix = request[:request.index('start_expo:') + len('start_expo:[')]
        startup = line('resumed service', tag='camera-system')
        for cause in ('explicit-gap', 'boot', 'inode', 'truncation', 'same-size'):
            with self.subTest(cause=cause):
                self.timeline = CaptureTimeline()
                self.ingest(request, size=1000)
                metadata = {'boot': 'fixture-boot', 'inode': 42, 'size': 2000}
                if cause == 'explicit-gap':
                    self.timeline.gap('fixture transport loss')
                elif cause == 'boot':
                    metadata['boot'] = 'new-fixture-boot'
                elif cause == 'inode':
                    metadata['inode'] = 99
                elif cause == 'truncation':
                    metadata['size'] = 900
                else:
                    metadata['size'] = 1000
                resumed = self.ingest(startup + prefix, **metadata)
                self.assertTrue(resumed['baseline'])
                self.assertTrue(resumed['resynchronized'])
                self.assertEqual(resumed['addedEvents'], [])
                metadata['size'] += 100
                completed = self.ingest(startup + request, **metadata)
                self.assertEqual(completed['addedEvents'], [])
                self.assertEqual(completed['addedCaptures'], [])
                self.assertEqual(completed['snapshot']['capturedCount'], 1)
                metadata['size'] += 100
                new_request = self.ingest(startup + request * 2, **metadata)
                self.assertEqual(new_request['addedCaptureCount'], 1)
                self.assertEqual(new_request['snapshot']['capturedCount'], 2)


if __name__ == '__main__':
    unittest.main()
