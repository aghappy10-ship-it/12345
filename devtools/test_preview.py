"""Public PreviewController seam; mock only the external subprocess boundary."""
import io
import json
import os
import struct
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    from .preview import PreviewController
except ImportError:
    from preview import PreviewController

PROJECT = Path(__file__).resolve().parents[1]


class BoundaryProcess:
    def __init__(self, *args, **kwargs):
        self.stdin = io.StringIO()
        self.pid = 1234
        self.returncode = None

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.returncode = 0
        return 0

    def terminate(self):
        self.returncode = 1

    def kill(self):
        self.returncode = 1


class PreviewTests(unittest.TestCase):
    def setUp(self):
        self.controller = PreviewController(PROJECT, PROJECT / 'devtools/data')

    def tearDown(self):
        self.controller.stop()

    @staticmethod
    def frame_fixture(*, payload=None, header=None):
        import zlib
        def chunk(kind, data):
            return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data) & 0xffffffff)
        header = header if header is not None else struct.pack('>IIBBBBB', 1024, 768, 8, 6, 0, 0, 0)
        data = payload if payload is not None else zlib.compress((b'\0' + b'\0' * (1024 * 4)) * 768)
        return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', header) + chunk(b'IDAT', data) + chunk(b'IEND', b'')

    def test_crc_valid_but_undecodable_png_is_rejected_with_bounded_inflate(self):
        import zlib
        controller = PreviewController(PROJECT, PROJECT / 'devtools/data')
        controller._session = controller.data_root / 'fixture-frame-reader'
        rows = (b'\0' + b'\0' * (1024 * 4)) * 768
        malformed = [
            self.frame_fixture(payload=b'not a zlib stream'),
            self.frame_fixture(payload=zlib.compress(rows)[:-1]),
            self.frame_fixture(payload=zlib.compress(rows) + b'extra'),
            self.frame_fixture(payload=zlib.compress(rows[:-1])),
            self.frame_fixture(payload=zlib.compress(rows + b'\0')),
            self.frame_fixture(payload=zlib.compress(b'\5' + rows[1:])),
            self.frame_fixture(header=struct.pack('>IIBBBBB', 1024, 768, 8, 6, 0, 0, 1)),
            self.frame_fixture(header=struct.pack('>IIBBBBB', 1024, 768, 7, 6, 0, 0, 0)),
        ]
        for raw in malformed:
            with self.subTest(size=len(raw)), patch.object(Path, 'open', return_value=io.BytesIO(raw)) as opening:
                with self.assertRaises(ValueError):
                    controller.frame_bytes()
                self.assertEqual(1, opening.call_count)

    def test_actual_preview_rgb_and_rgba_scanlines_are_accepted(self):
        import zlib
        controller = PreviewController(PROJECT, PROJECT / 'devtools/data')
        controller._session = controller.data_root / 'fixture-frame-reader'
        for channels, color_type in ((3, 2), (4, 6)):
            rows = b''.join(bytes([row % 5]) + b'\0' * (1024 * channels) for row in range(768))
            raw = self.frame_fixture(payload=zlib.compress(rows),
                header=struct.pack('>IIBBBBB', 1024, 768, 8, color_type, 0, 0, 0))
            with patch.object(Path, 'open', return_value=io.BytesIO(raw)):
                self.assertEqual(raw, controller.frame_bytes())

    def test_single_open_frame_snapshot_retries_transient_windows_access(self):
        controller = PreviewController(PROJECT, PROJECT / 'devtools/data')
        controller._session = controller.data_root / 'fixture-frame-reader'
        png = self.frame_fixture()
        with patch('os.name', 'nt'), patch.object(Path, 'open', side_effect=[PermissionError(13, 'sharing'), io.BytesIO(png)]) as opening:
            self.assertEqual(png, controller.frame_bytes())
        self.assertEqual(2, opening.call_count)

    def test_permanent_frame_access_and_invalid_png_are_not_hidden(self):
        controller = PreviewController(PROJECT, PROJECT / 'devtools/data')
        controller._session = controller.data_root / 'fixture-frame-reader'
        with patch('os.name', 'nt'), patch.object(Path, 'open', side_effect=PermissionError(13, 'lasting')) as opening:
            with self.assertRaises(PermissionError):
                controller.frame_bytes()
        self.assertEqual(10, opening.call_count)
        for raw in (self.frame_fixture()[:-12], b'not PNG', self.frame_fixture()[:-1] + b'0'):
            with patch.object(Path, 'open', return_value=io.BytesIO(raw)) as opening:
                with self.assertRaises(ValueError):
                    controller.frame_bytes()
                self.assertEqual(1, opening.call_count)

    def test_start_uses_fixed_python_worker_in_own_session(self):
        controller = PreviewController(PROJECT, PROJECT / 'devtools/data')
        with patch('subprocess.Popen', side_effect=BoundaryProcess) as boundary:
            state = controller.start('stock')
            self.assertEqual(state['state'], 'running')
            self.assertFalse(state['ready'])
            command = boundary.call_args.args[0]
            import sys
            self.assertEqual(command[0], sys.executable)
            self.assertIn('--worker', command)
            self.assertFalse(boundary.call_args.kwargs.get('shell', False))
            controller.stop()

    def test_not_started_is_transparent_and_rejects_input(self):
        self.assertEqual(self.controller.status()['state'], 'not_started')
        self.assertFalse(self.controller.status()['ready'])
        self.assertIsNone(self.controller.frame_path())
        self.assertFalse(self.controller.send_input({'type': 'back'})['accepted'])

    def test_start_twice_keeps_single_process_and_mode_switch_requires_stop(self):
        with patch('subprocess.Popen', side_effect=BoundaryProcess) as boundary:
            first = self.controller.start('stock')
            second = self.controller.start('stock')
            self.assertEqual(first['session_id'], second['session_id'])
            self.assertEqual(boundary.call_count, 1)
            with self.assertRaises(ValueError):
                self.controller.start('candidate')
            result = self.controller.stop()
            self.assertTrue(result['process_exit_verified'])
            self.assertEqual(result['state'], 'not_started')

    def test_spawn_failure_and_unexpected_exit_are_not_ready(self):
        with patch('subprocess.Popen', side_effect=OSError('boundary launch denied')):
            state = self.controller.start('stock')
            self.assertEqual(state['state'], 'failed')
            self.assertFalse(state['ready'])
            self.assertIn('boundary launch denied', state['error'])
        boundary_process = BoundaryProcess()
        with patch('subprocess.Popen', return_value=boundary_process):
            self.controller.start('stock')
            boundary_process.returncode = 2
            state = self.controller.status()
            self.assertEqual(state['state'], 'failed')
            self.assertFalse(state['ready'])
            self.assertEqual(state['worker_exit_code'], 2)

    def test_only_bounded_input_crosses_external_worker_boundary(self):
        processes = []
        def external_worker(command, **kwargs):
            process = BoundaryProcess()
            processes.append(process)
            session = Path(command[-2])
            (session / 'status.json').write_text(json.dumps({'state': 'running', 'ready': True}), encoding='utf-8')
            return process
        with patch('subprocess.Popen', side_effect=external_worker):
            self.controller.start('stock')
            answer = self.controller.send_input({'type': 'tap', 'x': 1023.9, 'y': 767.9})
            self.assertTrue(answer['accepted'])
            payload = json.loads(processes[0].stdin.getvalue())
            self.assertEqual(payload, {'type': 'tap', 'x': 1023, 'y': 767, 'id': 1})
            for invalid in ({'type': 'shell', 'command': 'anything'}, {'type': 'tap', 'x': -1, 'y': 0},
                {'type': 'tap', 'x': True, 'y': 0}, {'type': 'tap', 'x': float('nan'), 'y': 0},
                {'type': 'key', 'key': ['escape']}, {'type': 'key', 'key': 'dispatch'},
                {'type': 'back', 'extra': True}, ['back']):
                with self.assertRaises(ValueError, msg=repr(invalid)):
                    self.controller.send_input(invalid)

    def test_external_output_root_and_unknown_mode_are_rejected(self):
        with self.assertRaises(ValueError):
            PreviewController(PROJECT, PROJECT / 'build')
        with self.assertRaises(ValueError):
            self.controller.start('camera')

    def test_atomic_publication_retries_only_transient_windows_reader_locks(self):
        if __package__:
            from . import preview
        else:
            import preview
        locked = PermissionError('temporary reader lock')
        locked.winerror = 5
        with patch.object(preview.os, 'replace', side_effect=[locked, None]) as replace, patch.object(preview.time, 'sleep') as pause:
            preview._replace_shared('temporary', 'target')
        self.assertEqual(2, replace.call_count)
        pause.assert_called_once()
        with patch.object(preview.os, 'replace', side_effect=ValueError('bad path')) as replace:
            with self.assertRaises(ValueError):
                preview._replace_shared('temporary', 'target')
        self.assertEqual(1, replace.call_count)
        with patch.object(preview.os, 'replace', side_effect=locked) as replace, patch.object(preview.time, 'sleep'):
            with self.assertRaises(PermissionError):
                preview._replace_shared('temporary', 'target')
        self.assertEqual(10, replace.call_count)


@unittest.skipUnless(os.environ.get('X2DII_RUN_REAL_PREVIEW') == '1', 'opt-in real pinned desktop Qt process')
class RealPreviewTests(unittest.TestCase):
    def test_real_window_mouse_extension_back_and_clean_stop(self):
        # Resolve the test's HTTP adapter before launching an owned Qt process.
        if __package__:
            from .app import Server
        else:
            from app import Server
        controller = PreviewController(PROJECT, PROJECT / 'devtools/data')
        evidence = {'scope': 'real-desktop-qt-mouse-preview-only', 'camera_accesses': 0, 'installable': False}
        started = controller.start('candidate')
        session = Path(started['session_dir'])
        evidence['session_id'] = started['session_id']
        from types import SimpleNamespace
        import http.client
        # Exercise the same HTTP/read handles as the real browser, concurrently.
        server = Server(('127.0.0.1', 0), SimpleNamespace(preview=controller,
            data=PROJECT / 'devtools/data', close=lambda: None))
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        reader_stop = threading.Event()
        reads, read_errors = [], []
        def read_frames():
            while not reader_stop.is_set():
                connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
                try:
                    connection.request('GET', '/api/frame')
                    response = connection.getresponse()
                    raw = response.read()
                    if response.status != 200 or not raw.startswith(b'\x89PNG\r\n\x1a\n'):
                        raise ValueError('HTTP frame response status=' + str(response.status) +
                            ', bytes=' + str(len(raw)) + ', prefix=' + repr(raw[:240]))
                    reads.append(len(raw))
                except Exception as error:
                    read_errors.append(str(error))
                    return
                finally:
                    connection.close()
                reader_stop.wait(.005)
        reader = threading.Thread(target=read_frames, daemon=True)
        def await_state(predicate):
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                state = controller.status()
                if state['state'] == 'failed':
                    self.fail('real Qt worker failed: ' + repr(state))
                if predicate(state):
                    return state
                time.sleep(.1)
            self.fail('real Qt preview state timeout: ' + repr(controller.status()))
        try:
            initial = await_state(lambda s: s.get('ready') and s.get('frame_count', 0) >= 2)
            frame = controller.frame_path()
            self.assertIsNotNone(frame)
            png = frame.read_bytes()
            self.assertTrue(png.startswith(b'\x89PNG\r\n\x1a\n'))
            self.assertEqual(struct.unpack('>II', png[16:24]), (1024, 768))
            self.assertGreater(len(png), 1024)
            (session / 'evidence-initial.png').write_bytes(png)
            evidence['initial'] = initial
            reader.start()
            target = initial['controls']['extension']
            response = controller.send_input(dict(type='tap', **target))
            self.assertTrue(response['accepted'])
            opened = await_state(lambda s: s.get('last_input_id') == response['input_id'] and s.get('page_visible'))
            # One more actual render tick prevents attributing a pre-input frame.
            opened = await_state(lambda s: s.get('page_visible') and s.get('frame_count', 0) > opened['frame_count'])
            page_png = controller.frame_path().read_bytes()
            self.assertNotEqual(page_png, png)
            (session / 'evidence-page.png').write_bytes(page_png)
            evidence['opened_by_real_mouse'] = opened
            response = controller.send_input(dict(type='tap', **opened['controls']['back']))
            self.assertTrue(response['accepted'])
            returned = await_state(lambda s: s.get('last_input_id') == response['input_id'] and s.get('page_visible') is False)
            returned = await_state(lambda s: s.get('page_visible') is False and s.get('frame_count', 0) > returned['frame_count'])
            (session / 'evidence-returned.png').write_bytes(controller.frame_path().read_bytes())
            evidence['returned_by_real_mouse'] = returned
            sustained = await_state(lambda s: s.get('frame_count', 0) >= initial['frame_count'] + 30)
            self.assertFalse(read_errors, read_errors)
            self.assertGreater(len(reads), 50)
            evidence['concurrent_http_stream'] = dict(reads=len(reads), errors=read_errors,
                first_frame=initial['frame_count'], last_frame=sustained['frame_count'])
        finally:
            reader_stop.set()
            if reader.ident is not None:
                reader.join(6)
            server.shutdown()
            server.server_close()
            server_thread.join(3)
            stopped = controller.stop()
            evidence['stopped'] = stopped
            evidence['result'] = 'PASS' if stopped.get('process_exit_verified') and 'concurrent_http_stream' in evidence else 'FAIL'
            (session / 'integration-evidence.json').write_text(json.dumps(evidence, indent=2), encoding='utf-8')
        self.assertEqual(stopped['worker_exit_code'], 0)
        self.assertTrue(stopped['process_exit_verified'])
        self.assertTrue(json.loads((session / 'status.json').read_text())['complete_qt_teardown'])
        print('REAL_PREVIEW_EVIDENCE ' + str(session / 'integration-evidence.json'))


if __name__ == '__main__':
    unittest.main()
