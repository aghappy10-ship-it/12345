"""Host-only fault injection at the real QQmlEngine destruction boundary."""
from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT / 'tools'))
from host_cache import prepare_host
prepare_host()
import shiboken6
from PySide6.QtQml import QQmlApplicationEngine
from PySide6.QtCore import QUrl

real_delete = shiboken6.delete
injected = False


def delete_with_warning(obj):
    global injected
    if isinstance(obj, QQmlApplicationEngine):
        # Generate a real engine warning, without Python signal meta-type
        # emission or introducing another object's ownership during teardown.
        missing = Path(sys.argv[sys.argv.index('--child') + 1]) / 'TEST_LATE_ENGINE_WARNING.qml'
        if missing.exists():
            raise RuntimeError('Late-warning missing-file fixture unexpectedly exists')
        obj.load(QUrl.fromLocalFile(str(missing)))
        injected = True
    real_delete(obj)


shiboken6.delete = delete_with_warning
from check_stock_menu import main
result = main()
if not injected:
    raise RuntimeError('Late-warning injection did not reach the engine boundary')
raise SystemExit(result)
