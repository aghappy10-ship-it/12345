"""Bounded offscreen harness scheduling; never changes Loader asynchronous mode."""
import ctypes
from functools import lru_cache
import time


def runtime_inputs():
    """Pure file inspection for the supervisor; does not import/load Qt."""
    try:
        from .build_host_bridge import HOST, runtime_snapshot
    except ImportError:
        from build_host_bridge import HOST, runtime_snapshot
    return [HOST / name for name in runtime_snapshot()]


@lru_cache(maxsize=2)
def _native_call(library_name, symbol, argument_types):
    try:
        from .host_cache import prepare_host, HOST, pe_exports
    except ImportError:
        from host_cache import prepare_host, HOST, pe_exports
    prepare_host()
    library_path = HOST / 'PySide6' / library_name
    if symbol not in pe_exports(library_path):
        raise RuntimeError('Pinned Qt native export missing: ' + symbol)
    library = ctypes.CDLL(str(library_path))
    function = getattr(library, symbol)
    function.argtypes, function.restype = list(argument_types), None
    return library, function


def wait_events(milliseconds):
    """QTest's native event-pumping wait with the GIL released, same thread."""
    from PySide6.QtCore import QCoreApplication, QThread
    app = QCoreApplication.instance()
    if app is None or QThread.currentThread() != app.thread():
        raise RuntimeError('Qt event pumping must stay on the application thread')
    if type(milliseconds) is not int or not 0 <= milliseconds <= 3000:
        raise ValueError('Event wait must be an integer from 0 through 3000 ms')
    library, wait = _native_call('Qt6Core.dll', '?qWait@QTest@@YAXH@Z', (ctypes.c_int,))
    wait(milliseconds)


def wait_for(engine, predicate, description, timeout_seconds=3):
    # Offscreen windows need not receive device-style frame ticks. Drive the
    # engine's existing native incubator, not a replacement state machine.
    from PySide6.QtCore import QThread
    from shiboken6 import getCppPointer
    if QThread.currentThread() != engine.thread():
        raise RuntimeError('Qt incubation must stay on the engine thread')
    library, advance = _native_call('Qt6Qml.dll', '?incubateFor@QQmlIncubationController@@QEAAXH@Z',
                                    (ctypes.c_void_p, ctypes.c_int))
    deadline = time.monotonic() + timeout_seconds
    while True:
        result = predicate()
        if result:
            return result
        if time.monotonic() >= deadline:
            raise RuntimeError('Timed out waiting for actual Qt state: ' + description)
        controller = engine.incubationController()
        if controller is None:
            raise RuntimeError('Missing real Qt incubation controller: ' + description)
        # PySide's incubateFor wrapper holds the GIL while Qt can wait for its
        # loader thread. That thread may need the GIL for a Python URL
        # interceptor. CDLL calls the same pinned x64 member export on this
        # engine thread, releasing the GIL for the duration of the native call.
        advance(getCppPointer(controller)[0], 5)
        wait_events(10)
