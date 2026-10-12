"""Real desktop Qt preview with explicit camera-service boundary substitutes.

Only this Python worker is launched, with sys.executable and shell=False.
All generated state/cache/frame/log files stay in devtools/data/preview/<uuid>.
No camera, USB, network, QEMU, deployment, or arbitrary command/JS interface.
"""
from __future__ import annotations
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import sys
import threading
import time
import traceback
import uuid

sys.dont_write_bytecode = True
PROJECT = Path(__file__).resolve().parents[1]
CANDIDATE_SHA = '1068d682b840ec573f7caef188643cec8274b2321c44ce8ebf19ef0a68a1e889'
WIDTH, HEIGHT = 1024, 768
MAX_FRAME_BYTES = 8 * 1024 * 1024
KEYS = {'escape', 'back', 'return', 'left', 'right', 'up', 'down', 'menu', 'nav'}
LIMITATIONS = ['Real desktop Qt 6.8.2 stock MainScreen; not QEMU or camera firmware execution',
    'Camera services/state and native FavoriteModel substituted',
    'UiImage is the existing geometry substitute: camera SVG icons are not rendered',
    'Desktop fonts/software rendering/key codes; not camera pixels, touch hardware, AOT or capture proof']


def _guard(path, root):
    path, root = Path(os.path.abspath(path)), Path(os.path.abspath(root))
    if not path.is_relative_to(root):
        raise ValueError('preview output outside declared session root')
    if not root.is_relative_to(PROJECT / 'devtools'):
        raise ValueError('preview root must stay in owning devtools directory')
    ancestors = [p for p in root.parents if p.is_relative_to(PROJECT)]
    for current in [*reversed(ancestors), root, *reversed([p for p in path.parents if p.is_relative_to(root)]), path]:
        if current.exists() or current.is_symlink():
            info = current.lstat()
            if current.is_symlink() or getattr(info, 'st_file_attributes', 0) & 0x400:
                raise ValueError('preview reparse/symlink paths forbidden')
            if current.is_file() and info.st_nlink != 1:
                raise ValueError('preview shared output file forbidden')
    return path


def _replace_shared(temporary, path):
    """Windows readers briefly deny replacement; never mask a lasting failure."""
    for attempt in range(10):
        try:
            os.replace(temporary, path)
            return
        except PermissionError as error:
            if os.name != 'nt' or getattr(error, 'winerror', None) not in (5, 32, 33) or attempt == 9:
                raise
            time.sleep(.01)


def _atomic_json(path, value, session):
    path = _guard(path, session)
    temporary = _guard(session / ('.status-' + uuid.uuid4().hex + '.tmp'), session)
    with temporary.open('xb') as stream:
        stream.write((json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8'))
        stream.flush()
        os.fsync(stream.fileno())
    _guard(path, session)
    _replace_shared(temporary, path)


def _input(event):
    if type(event) is not dict:
        raise ValueError('input must be a JSON object')
    kind = event.get('type')
    if kind == 'tap' and set(event) == {'type', 'x', 'y'}:
        if any(type(event[k]) not in (int, float) for k in ('x', 'y')):
            raise ValueError('tap coordinates must be numbers, not booleans')
        if not 0 <= event['x'] < WIDTH or not 0 <= event['y'] < HEIGHT:
            raise ValueError('tap outside actual 1024x768 preview')
        return {'type': 'tap', 'x': min(WIDTH - 1, round(event['x'])), 'y': min(HEIGHT - 1, round(event['y']))}
    if kind == 'key' and set(event) == {'type', 'key'} and type(event['key']) is str and event['key'] in KEYS:
        return dict(event)
    if kind == 'back' and set(event) == {'type'}:
        return {'type': 'back'}
    raise ValueError('only bounded tap, whitelisted key, and back inputs are supported')


class PreviewController:
    def __init__(self, project_root: Path, data_root: Path):
        self.project_root = Path(project_root).resolve()
        if self.project_root != PROJECT:
            raise ValueError('preview must use its actual owning project')
        expected = PROJECT / 'devtools/data'
        data_root = Path(os.path.abspath(data_root))
        if data_root not in (expected, expected / 'preview'):
            raise ValueError('preview data root must be this project devtools/data[/preview]')
        self.data_root = _guard(expected / 'preview', PROJECT / 'devtools')
        self._lock = threading.RLock()
        self._process = None
        self._log = None
        self._session = None
        self._sequence = 0
        self._state = self._base('not_started')

    def _base(self, state, **values):
        return dict(state=state, ready=False, camera_services_substituted=True,
                    scope='desktop-qt-real-stock-menu-boundary-substitutes',
                    camera_accesses=0, installable=False, limitations=list(LIMITATIONS), **values)

    def start(self, mode='stock'):
        with self._lock:
            if mode not in ('stock', 'candidate'):
                raise ValueError('mode must be stock or candidate')
            if self._process is not None and self._process.poll() is None:
                if self._state.get('mode') != mode:
                    raise ValueError('stop current preview before changing mode')
                return self.status()
            if self._log is not None:
                self._log.close()
                self._log = None
            if self._process is not None and self._process.stdin is not None:
                self._process.stdin.close()
            self._process = None
            _guard(self.data_root, PROJECT / 'devtools')
            self.data_root.mkdir(parents=True, exist_ok=True)
            self._session = _guard(self.data_root / uuid.uuid4().hex, self.data_root)
            self._session.mkdir(exist_ok=False)
            self._sequence = 0
            self._state = self._base('running', phase='starting', mode=mode,
                session_id=self._session.name, session_dir=str(self._session),
                started_utc=datetime.now(timezone.utc).isoformat())
            _atomic_json(self._session / 'status.json', self._state, self._session)
            self._log = (self._session / 'preview.log').open('xb')
            command = [sys.executable, '-B', '-X', 'faulthandler', str(Path(__file__)),
                       '--worker', str(self._session), mode]
            environment = os.environ.copy()
            environment.update(PYTHONDONTWRITEBYTECODE='1')
            environment.pop('QML_DISABLE_DISK_CACHE', None)
            try:
                self._process = subprocess.Popen(command, cwd=PROJECT, env=environment,
                    stdin=subprocess.PIPE, stdout=self._log, stderr=subprocess.STDOUT,
                    text=True, encoding='utf-8', bufsize=1, shell=False)
                self._state['worker_pid'] = self._process.pid
            except Exception as error:
                self._state.update(state='failed', phase='spawn-failed', error=str(error))
                self._log.close()
                self._log = None
                _atomic_json(self._session / 'status.json', self._state, self._session)
            return dict(self._state)

    def stop(self):
        with self._lock:
            if self._process is None:
                return self.status()
            forced = False
            if self._process.poll() is None:
                try:
                    self._process.stdin.write('{"type":"stop"}\n')
                    self._process.stdin.flush()
                    self._process.wait(timeout=8)
                except (OSError, subprocess.TimeoutExpired):
                    forced = True
                    self._process.terminate()
                    try:
                        self._process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        self._process.kill()
                        self._process.wait(timeout=3)
            exit_code = self._process.poll()
            if self._log is not None:
                self._log.close()
                self._log = None
            if self._process.stdin is not None:
                self._process.stdin.close()
            self._state = self._base('failed' if forced or exit_code != 0 else 'not_started',
                phase='forced-stop' if forced else 'stopped', mode=self._state.get('mode'),
                session_id=self._session.name, session_dir=str(self._session), worker_exit_code=exit_code,
                process_exit_verified=exit_code == 0 and not forced)
            _atomic_json(self._session / 'controller-stop.json', self._state, self._session)
            self._process = None
            return dict(self._state)

    def status(self):
        with self._lock:
            result = dict(self._state)
            if self._process is None:
                return result
            path = _guard(self._session / 'status.json', self._session)
            if path.is_file() and path.stat().st_size <= 1024 * 1024:
                try:
                    result.update(json.loads(path.read_text(encoding='utf-8')))
                except (OSError, ValueError):
                    pass  # Atomic file publication may race a read on Windows.
            result.update(worker_pid=self._process.pid, session_id=self._session.name,
                          session_dir=str(self._session))
            code = self._process.poll()
            if code is not None:
                result.update(state='failed', ready=False, phase='worker-exited', worker_exit_code=code)
                result.setdefault('error', 'preview worker exited; inspect preview.log')
            return result

    def frame_path(self):
        with self._lock:
            if self._session is None:
                return None
            path = _guard(self._session / 'frame.png', self._session)
            if path.is_file() and path.stat().st_size > 8:
                with path.open('rb') as stream:
                    if stream.read(8) == b'\x89PNG\r\n\x1a\n':
                        return path
            return None

    def frame_bytes(self):
        """Serve one complete byte snapshot, not a path checked then reopened.

        Windows replacement can temporarily deny a reader. Retry only those
        local sharing/access failures, never malformed image bytes or a lasting
        denied file. The publisher's complete temporary PNG is still required.
        """
        import errno
        import struct
        import zlib
        with self._lock:
            if self._session is None:
                return None
            for attempt in range(10):
                try:
                    path = _guard(self._session / 'frame.png', self._session)
                    with path.open('rb') as stream:
                        raw = stream.read(MAX_FRAME_BYTES + 1)
                    break
                except OSError as error:
                    transient = os.name == 'nt' and (isinstance(error, FileNotFoundError) or
                        isinstance(error, PermissionError) and
                        (getattr(error, 'winerror', None) in (5, 32, 33) or error.errno == errno.EACCES))
                    if transient and attempt < 9:
                        time.sleep(.01)
                        continue
                    if isinstance(error, FileNotFoundError):
                        return None
                    raise
            if len(raw) > MAX_FRAME_BYTES or not raw.startswith(b'\x89PNG\r\n\x1a\n'):
                raise ValueError('preview frame is oversized or not PNG')
            position, seen_header, seen_data, seen_end = 8, False, False, False
            compressed, data_closed, channels = bytearray(), False, None
            while position + 12 <= len(raw):
                length = struct.unpack('>I', raw[position:position + 4])[0]
                end = position + 12 + length
                if end > len(raw):
                    raise ValueError('preview PNG contains an incomplete chunk')
                kind, data = raw[position + 4:position + 8], raw[position + 8:end - 4]
                crc = struct.unpack('>I', raw[end - 4:end])[0]
                if zlib.crc32(kind + data) & 0xffffffff != crc:
                    raise ValueError('preview PNG chunk checksum differs')
                if not seen_header:
                    if kind != b'IHDR' or length != 13 or struct.unpack('>II', data[:8]) != (WIDTH, HEIGHT):
                        raise ValueError('preview PNG header or dimensions differ')
                    # The pinned Qt publisher emits non-interlaced 8-bit RGB/A.
                    # Reject unsupported layouts instead of guessing row sizes.
                    depth, color, compression, filtering, interlace = data[8:]
                    if depth != 8 or color not in (2, 6) or (compression, filtering, interlace) != (0, 0, 0):
                        raise ValueError('preview PNG pixel layout is unsupported')
                    channels = 3 if color == 2 else 4
                    seen_header = True
                elif kind == b'IHDR':
                    raise ValueError('preview PNG has multiple headers')
                if kind == b'IDAT':
                    if data_closed:
                        raise ValueError('preview PNG data chunks are not contiguous')
                    compressed.extend(data)
                    seen_data = True
                elif seen_data:
                    data_closed = True
                if kind not in (b'IHDR', b'IDAT', b'IEND') and not kind[0] & 0x20:
                    raise ValueError('preview PNG contains an unsupported critical chunk')
                if kind == b'IEND':
                    if length != 0 or end != len(raw):
                        raise ValueError('preview PNG end is invalid')
                    seen_end = True
                    break
                position = end
            if not (seen_header and seen_data and seen_end):
                raise ValueError('preview PNG is incomplete')
            row_bytes = 1 + WIDTH * channels
            expected = HEIGHT * row_bytes
            decoder = zlib.decompressobj()
            try:
                # One extra byte detects excess output, without an unbounded
                # flush/decompress on a corrupt or compressed-bomb frame.
                pixels = decoder.decompress(compressed, expected + 1)
            except zlib.error as error:
                raise ValueError('preview PNG data cannot be decompressed') from error
            if (len(pixels) != expected or not decoder.eof or
                    decoder.unused_data or decoder.unconsumed_tail):
                raise ValueError('preview PNG data size or stream end differs')
            if any(pixels[offset] > 4 for offset in range(0, expected, row_bytes)):
                raise ValueError('preview PNG has an invalid scanline filter')
            return raw

    def send_input(self, event):
        validated = _input(event)
        with self._lock:
            status = self.status()
            if status['state'] != 'running' or not status.get('ready'):
                return {'accepted': False, 'error': 'real desktop preview is not ready', 'state': status['state']}
            self._sequence += 1
            validated['id'] = self._sequence
            try:
                self._process.stdin.write(json.dumps(validated) + '\n')
                self._process.stdin.flush()
            except OSError as error:
                return {'accepted': False, 'error': str(error), 'state': 'failed'}
            return {'accepted': True, 'input_id': self._sequence, 'state': 'queued'}


def _worker(session, mode):
    """Qt stays entirely in this child process and on its main thread."""
    session = _guard(session, PROJECT / 'devtools/data/preview')
    if session.parent != PROJECT / 'devtools/data/preview' or not re.fullmatch('[0-9a-f]{32}', session.name):
        raise ValueError('worker requires a dedicated controller UUID session')
    if mode not in ('stock', 'candidate'):
        raise ValueError('unsupported preview mode')
    if os.name != 'nt' or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise ValueError('pinned preview requires Windows x64; no emulated fallback')
    base = dict(state='running', ready=False, phase='loading', mode=mode,
        camera_services_substituted=True, camera_accesses=0, installable=False,
        scope='desktop-qt-real-stock-menu-boundary-substitutes', limitations=LIMITATIONS,
        worker_pid=os.getpid(), session_id=session.name, session_dir=str(session))
    _atomic_json(session / 'status.json', base, session)
    sys.path.insert(0, str(PROJECT / 'tools'))
    from build_host_bridge import HOST, BUILD, REFERENCE_HASHES, EXPORTS, runtime_snapshot, pe_exports, sha
    from extract_qml import STOCK, collect
    from qt_unit import read_main_screen
    from build_unit import build
    from host_cache import CachedUnit, Lookup, Registration, REGISTER_SYMBOL, UNREGISTER_SYMBOL, EQUALS_SYMBOL, validate_cache

    runtime = runtime_snapshot()
    bridge_report = json.loads((BUILD / 'native/BUILD.json').read_text(encoding='utf-8'))
    if not bridge_report.get('reproduced') or bridge_report['runtime_files'] != runtime:
        raise ValueError('pinned desktop bridge/runtime identity mismatch')
    for name, digest in bridge_report['inputs'].items():
        if sha(PROJECT / name) != digest:
            raise ValueError('bridge input changed: ' + name)
    for name, digest in REFERENCE_HASHES.items():
        if sha(BUILD / 'qt-source' / name) != digest:
            raise ValueError('Qt reference identity mismatch')
    bridge_path = BUILD / 'native/host_cache_bridge.dll'
    if sha(bridge_path) != bridge_report['dll_sha256'] or pe_exports(bridge_path) != EXPORTS:
        raise ValueError('desktop cache bridge identity/exports mismatch')
    official, _ = collect(STOCK.read_bytes())
    fixture = json.loads((PROJECT / 'build/host/fixture-manifest.json').read_text(encoding='utf-8'))
    for name, digest in fixture['preserved'].items():
        data = (PROJECT / 'build/host/stock' / name).read_bytes()
        if data != official['qt/qml/app/qml/' + name] or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError('stock QML differs from pinned official GUI: ' + name)
    for name, digest in fixture['substitutes'].items():
        if sha(PROJECT / 'build/host' / name) != digest:
            raise ValueError('named camera boundary substitute changed: ' + name)
    if sha(PROJECT / 'build/host/keys.rcc') != fixture['rccSha256']:
        raise ValueError('stock key resource identity mismatch')
    candidate = PROJECT / 'build/menu-ready-development-20261008/candidate/X2d2MenuBootstrap.qml'
    if mode == 'candidate' and sha(candidate) != CANDIDATE_SHA:
        raise ValueError('candidate Bootstrap changed; independent preview requalification required')
    if mode == 'candidate':
        for name, digest in {
            'X2d2MenuModel.qml': '79f2c6d5c986dda3e68fa754f63a6b08803230bcd8c905fac376cd39b0f41022',
            'X2d2MenuPage.qml': '65b6fca7e3fb273077b619881de0a1aafeb97de37fb2989c3052570bcc19e7de'
        }.items():
            if sha(candidate.parent / name) != digest:
                raise ValueError('candidate dependency changed: ' + name)
    original = read_main_screen(STOCK)
    unit_data = build(original, candidate.as_uri()) if mode == 'candidate' else original
    validate_cache(unit_data)
    unit_path = session / 'MainScreen.bin'
    with unit_path.open('xb') as stream:
        stream.write(unit_data)
    cache_path = session / 'qml-cache'
    cache_path.mkdir(exist_ok=False)
    sys.path.insert(0, str(HOST))
    os.environ.update(QT_QPA_PLATFORM='offscreen', QT_QUICK_BACKEND='software', QML_DISK_CACHE_PATH=str(cache_path))
    os.environ.pop('QML_DISABLE_DISK_CACHE', None)
    from PySide6.QtCore import QAbstractListModel, QModelIndex, Qt, Slot, QUrl, QResource, QCoreApplication, QEvent, QTimer, QPoint, qVersion, qInstallMessageHandler
    from PySide6.QtGui import QGuiApplication, QFontDatabase
    from PySide6.QtQml import QQmlApplicationEngine, qmlClearTypeRegistrations
    from PySide6.QtQuick import QQuickItem
    from PySide6.QtTest import QTest
    from shiboken6 import getCppPointer, delete, isValid
    if qVersion() != '6.8.2':
        raise ValueError('exact pinned desktop Qt 6.8.2 required')

    class SourceModel(QAbstractListModel):
        roles = ['menuName', 'label', 'labelContext', 'itemEnabled', 'iconSrc']
        def rowCount(self, parent=QModelIndex()):
            return 0 if parent.isValid() else 11
        def roleNames(self):
            return {257 + i: n.encode() for i, n in enumerate(self.roles)}
        def data(self, index, role):
            if not index.isValid() or not 0 <= index.row() < 11:
                return None
            name = self.roleNames().get(role)
            row = dict(menuName='menu' + str(index.row()), label='Menu ' + str(index.row()),
                       labelContext='Fixture', itemEnabled=True, iconSrc='generalMenu')
            return row.get(name.decode()) if name else None
        @Slot(int, result=bool)
        def itemEnabled(self, index):
            return 0 <= index < 11

    receipts = []
    def qt_log(kind, context, message):
        print(message, flush=True)
        prefix = 'X2DII_MENU_DELEGATE '
        if message.startswith(prefix):
            receipts.append(json.loads(message[len(prefix):]))
    previous_handler = qInstallMessageHandler(qt_log)
    app = QGuiApplication([])
    fonts = []
    for name in ('arial.ttf', 'msyh.ttc'):
        path = Path('C:/Windows/Fonts') / name
        if not path.is_file():
            raise ValueError('required readable desktop font missing: ' + str(path))
        font_id = QFontDatabase.addApplicationFont(str(path))
        if font_id < 0:
            raise ValueError('Qt cannot load desktop font: ' + str(path))
        fonts.append(dict(path=str(path), sha256=sha(path), families=QFontDatabase.applicationFontFamilies(font_id)))
    default_font = app.font()
    default_font.setFamily('Microsoft YaHei')
    app.setFont(default_font)
    source = SourceModel()
    if not QResource.registerResource(str(PROJECT / 'build/host/keys.rcc')):
        raise ValueError('real stock Keys.js registration failed')
    core = ctypes.CDLL(str(HOST / 'PySide6/Qt6Core.dll'))
    qml = ctypes.CDLL(str(HOST / 'PySide6/Qt6Qml.dll'))
    bridge = ctypes.CDLL(str(bridge_path))
    storage = ctypes.create_string_buffer(unit_data)
    unit = CachedUnit(ctypes.addressof(storage), None, None)
    url = QUrl((PROJECT / 'build/host/stock/mainmenu/MainScreen.qml').as_uri())
    callback = Lookup(('bridge_lookup', bridge))
    registration = Registration(0, callback)
    if (ctypes.sizeof(CachedUnit) != bridge.bridge_unit_size() or
            ctypes.sizeof(Registration) != bridge.bridge_hook_size() or
            Registration.lookup.offset != bridge.bridge_hook_lookup_offset()):
        raise ValueError('native preview cache hook layout mismatch')
    bridge.bridge_configure.argtypes, bridge.bridge_configure.restype = [ctypes.c_void_p] * 3, ctypes.c_int
    bridge.bridge_deactivate.argtypes, bridge.bridge_deactivate.restype = [ctypes.c_void_p], ctypes.c_int
    bridge.bridge_hits.restype = ctypes.c_uint64
    register = getattr(qml, REGISTER_SYMBOL)
    register.argtypes, register.restype = [ctypes.c_int, ctypes.c_void_p], ctypes.c_int
    unregister = getattr(qml, UNREGISTER_SYMBOL)
    unregister.argtypes, unregister.restype = [ctypes.c_int, ctypes.c_size_t], None
    if bridge.bridge_configure(getattr(core, EQUALS_SYMBOL), getCppPointer(url)[0], ctypes.byref(unit)) != 1 or register(6, ctypes.byref(registration)) != 0:
        raise ValueError('real compiled MainScreen cache registration failed')
    engine = QQmlApplicationEngine()
    engine.addImportPath(str(PROJECT / 'build/host/imports'))
    engine.rootContext().setContextProperty('stockSource', source)
    warnings = []
    engine.warnings.connect(lambda ws: warnings.extend(str(w) for w in ws))
    engine.load(QUrl.fromLocalFile(str(PROJECT / 'build/menu-ready-development-20261008/StockHarness.qml')))
    if not engine.rootObjects():
        raise ValueError('stock fixture cannot load: ' + repr(warnings))
    window = engine.rootObjects()[0]
    advance = getattr(qml, '?incubateFor@QQmlIncubationController@@QEAAXH@Z')
    advance.argtypes, advance.restype = [ctypes.c_void_p, ctypes.c_int], None
    wait = getattr(core, '?qWait@QTest@@YAXH@Z')
    wait.argtypes, wait.restype = [ctypes.c_int], None
    deadline = time.monotonic() + 6
    while window.findChild(QQuickItem, 'MainScreen_grid') is None or (mode == 'candidate' and window.findChild(QQuickItem, 'X2d2MenuExtension') is None):
        if time.monotonic() >= deadline:
            raise ValueError('real stock MainScreen did not instantiate')
        controller = engine.incubationController()
        if controller is None:
            raise ValueError('real Qt incubation controller missing')
        advance(getCppPointer(controller)[0], 5)
        wait(10)
    wait(50)
    if warnings or bridge.bridge_hits() < 1:
        raise ValueError('real compiled stock menu not active: ' + repr(warnings))
    grid = window.findChild(QQuickItem, 'MainScreen_grid')
    extension = window.findChild(QQuickItem, 'X2d2MenuExtension')
    page = window.findChild(QQuickItem, 'X2d2ExtensionPage')
    if mode == 'candidate' and (not extension.property('attached') or grid.property('count') != 12):
        raise ValueError('candidate not attached to actual stock grid')
    events = queue.Queue(maxsize=128)
    stdin_closed = threading.Event()
    def read_inputs():
        for line in sys.stdin:
            if len(line) > 4096:
                continue
            try:
                events.put_nowait(json.loads(line))
            except (ValueError, queue.Full):
                continue
        stdin_closed.set()
    threading.Thread(target=read_inputs, daemon=True).start()
    frame_count, last_input = 0, None
    key_map = dict(escape=Qt.Key_Escape, back=Qt.Key_Back, return_=Qt.Key_Return,
                   left=Qt.Key_Left, right=Qt.Key_Right, up=Qt.Key_Up, down=Qt.Key_Down,
                   menu=Qt.Key_Menu, nav=Qt.Key_F3)
    key_map['return'] = key_map.pop('return_')
    worker_error = None
    def refresh():
        nonlocal frame_count, last_input, worker_error
        try:
            if stdin_closed.is_set():
                app.quit()
                return
            for _ in range(16):
                try:
                    event = events.get_nowait()
                except queue.Empty:
                    break
                if type(event) is dict and event == {'type': 'stop'}:
                    app.quit()
                    return
                if type(event) is not dict:
                    continue
                request = dict(event)
                input_id = request.pop('id', None)
                checked = _input(request)
                if checked['type'] == 'tap':
                    QTest.mousePress(window, Qt.LeftButton, Qt.NoModifier, QPoint(checked['x'], checked['y']))
                    QTest.mouseRelease(window, Qt.LeftButton, Qt.NoModifier, QPoint(checked['x'], checked['y']))
                else:
                    QTest.keyClick(window, Qt.Key_Escape if checked['type'] == 'back' else key_map[checked['key']])
                last_input = input_id
            image = window.grabWindow()
            if image.isNull() or image.width() != WIDTH or image.height() != HEIGHT:
                raise ValueError('real Qt window cannot render a nonempty 1024x768 frame')
            temporary = _guard(session / ('.frame-' + uuid.uuid4().hex + '.png'), session)
            if not image.save(str(temporary), 'PNG'):
                raise ValueError('real Qt window PNG write failed')
            _replace_shared(temporary, _guard(session / 'frame.png', session))
            frame_count += 1
            controls = {}
            if extension is not None and extension.property('attached') and extension.property('extensionIndex') >= 0:
                controls['extension'] = json.loads(window.point(extension.property('extensionIndex')))
            if page is not None and page.isVisible():
                button = window.findChild(QQuickItem, 'X2d2ExtensionBack')
                if button is not None:
                    point = button.mapToItem(window.contentItem(), button.width() / 2, button.height() / 2)
                    controls['back'] = {'x': point.x(), 'y': point.y()}
            state = dict(base)
            state.update(ready=True, phase='host-ready', frame_count=frame_count,
                frame_width=image.width(), frame_height=image.height(), last_input_id=last_input,
                page_visible=bool(page is not None and page.isVisible()),
                grid_count=grid.property('count'), extension_index=extension.property('extensionIndex') if extension else -1,
                controls=controls, candidate_sha256=CANDIDATE_SHA if mode == 'candidate' else None,
                cache_hits=int(bridge.bridge_hits()), desktop_application_fonts=fonts,
                latest_delegate_receipt=receipts[-1] if receipts else None,
                updated_utc=datetime.now(timezone.utc).isoformat())
            _atomic_json(session / 'status.json', state, session)
            if warnings:
                raise ValueError('real QML runtime warnings: ' + repr(warnings))
        except Exception as error:
            worker_error = str(error)
            print(traceback.format_exc(), flush=True)
            app.quit()
    timer = QTimer()
    timer.setInterval(150)
    timer.timeout.connect(refresh)
    timer.start()
    refresh()
    if worker_error is None:
        app.exec()
    timer.stop()
    window.setScreenActive(False)
    wait(30)
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    window.close()
    delete(engine)
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    delete(source)
    unregister(6, ctypes.cast(callback, ctypes.c_void_p).value)
    if bridge.bridge_deactivate(ctypes.byref(unit)) != 1:
        raise ValueError('cache bridge did not close cleanly')
    qmlClearTypeRegistrations()
    QResource.unregisterResource(str(PROJECT / 'build/host/keys.rcc'))
    delete(app)
    qInstallMessageHandler(previous_handler)
    if isValid(engine) or isValid(source) or isValid(app) or warnings:
        raise ValueError('real Qt teardown incomplete or emitted QML warnings')
    final = dict(base)
    final.update(state='failed' if worker_error else 'not_started', ready=False,
                 phase='failed' if worker_error else 'stopped', error=worker_error,
                 complete_qt_teardown=True, frame_count=frame_count)
    _atomic_json(session / 'status.json', final, session)
    print('TEARDOWN_COMPLETE', flush=True)
    return 1 if worker_error else 0


if __name__ == '__main__':
    if len(sys.argv) != 4 or sys.argv[1] != '--worker':
        raise SystemExit('preview.py is a controller-owned worker, not a command runner')
    session = Path(sys.argv[2])
    try:
        raise SystemExit(_worker(session, sys.argv[3]))
    except Exception as error:
        print(traceback.format_exc(), flush=True)
        try:
            _atomic_json(session / 'status.json', dict(state='failed', ready=False,
                phase='worker-failure', error=str(error), camera_services_substituted=True,
                camera_accesses=0, installable=False, limitations=LIMITATIONS), session)
        except Exception:
            print('Failed to persist worker error', flush=True)
        raise SystemExit(1)
