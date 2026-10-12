"""Execute the II menu adapter under Qt 6.8.2; native camera model is a substitute."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import sys
from output_guard import guard_output, write_output

# Keep this branch above every Qt import, including helper modules that import
# Qt themselves. The observer verifies the worker's entire process lifetime.
if __name__ == '__main__' and '--child' not in sys.argv:
    from qt_supervisor import PROJECT, supervise_worker
    report = supervise_worker(Path(__file__), 'menu-model-validation.json', 'menu-model-runs',
                              input_paths=[*sorted((PROJECT / 'qml').glob('*.qml')),
                                           PROJECT / 'tests/fixtures/ModelHarness.qml'])
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report['result'] == 'PASS' else 1)

sys.dont_write_bytecode = True
PROJECT = Path(__file__).resolve().parents[1]
QT_ROOT = PROJECT.parent / 'x2d2/work/reverse/vendor/qt_host_6_8_2'
sys.path.insert(0, str(QT_ROOT))
os.environ['QT_QPA_PLATFORM'] = 'offscreen'
os.environ['QT_QUICK_BACKEND'] = 'software'
os.environ['QML_DISABLE_DISK_CACHE'] = '1'
os.environ['QML_DISK_CACHE_PATH'] = str(PROJECT / 'build/qt-cache')
from PySide6.QtCore import QAbstractListModel, QModelIndex, Qt, Slot, QUrl, QPoint, qVersion, QCoreApplication, QEvent
from PySide6.QtGui import QGuiApplication
from PySide6.QtQml import QQmlApplicationEngine
from PySide6.QtTest import QTest

ROLES = ['menuName', 'label', 'labelContext', 'itemEnabled', 'iconSrc']
EXTENSION = 'x2diiMenuExtension'


def require(condition, message):
    if not condition: raise RuntimeError(message)


def make_row(index):
    return dict(menuName='menu' + str(index), label='Menu ' + str(index),
                labelContext='Fixture', itemEnabled=True, iconSrc='generalMenu')


class SourceModel(QAbstractListModel):
    """Substitute only for documented FavoriteModel roles and itemEnabled method."""
    def __init__(self, count=11):
        super().__init__()
        self.rows = [make_row(i) for i in range(count)]

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def roleNames(self):
        return {257 + i: name.encode() for i, name in enumerate(ROLES)}

    def data(self, index, role):
        name = self.roleNames().get(role)
        if name and index.isValid() and 0 <= index.row() < len(self.rows):
            return self.rows[index.row()].get(name.decode())
        return None

    @Slot(int, result=bool)
    def itemEnabled(self, index):
        return 0 <= index < len(self.rows) and self.rows[index]['itemEnabled'] is True

    @Slot(result=int)
    def count(self): return len(self.rows)

    def reset(self, count):
        self.beginResetModel()
        self.rows = [make_row(i) for i in range(count)]
        self.endResetModel()

    def change(self, index, **changes):
        self.rows[index].update(changes)
        self.dataChanged.emit(self.index(index), self.index(index),
                              [r for r, n in self.roleNames().items() if n.decode() in changes])

    def insert(self, index, row):
        self.beginInsertRows(QModelIndex(), index, index)
        self.rows.insert(index, row)
        self.endInsertRows()

    def remove(self, index):
        self.beginRemoveRows(QModelIndex(), index, index)
        self.rows.pop(index)
        self.endRemoveRows()

    def move(self, source, destination):
        require(self.beginMoveRows(QModelIndex(), source, source, QModelIndex(), destination), 'move rejected')
        row = self.rows.pop(source)
        self.rows.insert(destination - 1 if destination > source else destination, row)
        self.endMoveRows()


def main():
    require(len(sys.argv) == 3 and sys.argv[1] == '--child', 'worker requires exact --child run-directory arguments')
    run_directory = guard_output(Path(sys.argv[2]))
    require(qVersion() == '6.8.2', 'host Qt version mismatch')
    app = QGuiApplication([])
    engine = QQmlApplicationEngine()
    source = SourceModel()
    engine.rootContext().setContextProperty('stockSource', source)
    warnings = []
    engine.warnings.connect(lambda ws: warnings.extend(str(w) for w in ws))
    engine.load(QUrl.fromLocalFile(str(PROJECT / 'tests/fixtures/ModelHarness.qml')))
    require(bool(engine.rootObjects()), 'fixture load failed: ' + repr(warnings))
    window = engine.rootObjects()[0]
    cases = []

    def settle(): QTest.qWait(30)

    def check(label, expected_extension=True):
        settle()
        rows = json.loads(window.snapshot())
        require(window.property('hasExtension') == expected_extension, label + ': extension state ' + str(window.property('rejection')))
        expected_count = len(source.rows) + int(expected_extension)
        require(len(rows) == expected_count and window.property('displayedCount') == expected_count, label + ': count')
        require([r['name'] for r in rows[:len(source.rows)]] == [r['menuName'] for r in source.rows], label + ': source ordering changed')
        # A QVariant-invalid role is undefined in QML and omitted by JSON.stringify.
        require([r.get('label') for r in rows[:len(source.rows)]] == [r['label'] for r in source.rows], label + ': source labels changed')
        require(all(rows[i]['selectable'] == source.itemEnabled(i) for i in range(len(source.rows))), label + ': enabled mapping')
        if expected_extension:
            require(rows[-1]['name'] == EXTENSION and window.property('extensionIndex') == len(source.rows), label + ': extension index')
        else: require(window.property('extensionIndex') == -1, label + ': stale extension index')
        require(not warnings, label + ': ' + repr(warnings))
        cases.append(label)
        return rows

    check('initial-eleven')
    for count in (1, 7, 10, 11, 12, 13, 0, 11):
        source.reset(count)
        check('reset-' + str(count), 0 < count < 12)
    source.change(3, label='Changed', itemEnabled=False)
    check('label-and-disabled-propagation')
    source.change(0, menuName=EXTENSION)
    check('reserved-name-collision', False)
    require(window.property('rejection') == 'reserved-name-collision', 'collision not reported')
    source.change(0, menuName='menu0')
    check('collision-recovery')
    source.change(0, menuName='menu1')
    check('duplicate-source-name', False)
    source.change(0, menuName='menu0')
    check('duplicate-name-recovery')
    source.change(0, label=None)
    check('role-contract-rejection', False)
    source.change(0, label='Menu 0')
    check('role-contract-recovery')
    source.remove(5)
    check('row-remove')
    source.insert(2, make_row(100))
    check('row-insert-before-extension')
    source.move(0, len(source.rows))
    check('row-move')
    source.insert(len(source.rows), make_row(101))
    check('row-insert-capacity', False)
    source.remove(len(source.rows) - 1)
    check('capacity-recovery')
    window.setProperty('supported', False)
    check('unsupported-layout', False)
    window.setProperty('supported', True)
    check('layout-recovery')
    window.setProperty('extensionEnabled', False)
    rows = check('extension-disabled')
    require(not rows[-1]['enabled'] and not rows[-1]['selectable'], 'extension disable mismatch')
    window.setProperty('extensionEnabled', True)
    check('extension-enabled')
    QTest.mouseClick(window, Qt.LeftButton, Qt.NoModifier, QPoint(896, 480))
    settle()
    require(window.property('clicked').toVariant() == [EXTENSION], 'adapter mouse event did not select extension')
    for _ in range(20):
        source.reset(10); settle(); source.reset(11); settle()
    check('repeated-model-reset')
    report = {'result': 'EXECUTED_PENDING_PROCESS_EXIT', 'scope': 'host-model-only', 'qt': qVersion(), 'cases': cases,
              'sourceModelSubstitute': True, 'cameraAccesses': 0, 'installable': False,
              'sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in [PROJECT / 'qml/X2d2MenuModel.qml', PROJECT / 'tests/fixtures/ModelHarness.qml']},
              'limitations': ['no stock compiled MainScreen, actual camera model, hardware keys, visuals or AOT in this test']}
    from shiboken6 import delete, isValid
    window.close()
    # Destroy all native Qt objects synchronously. The engine owns its root
    # window; keep the model alive until those QML bindings have gone away.
    delete(engine)
    require(not isValid(engine) and not isValid(window), 'QML engine/root teardown incomplete')
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    app.processEvents()
    delete(source)
    require(not isValid(source), 'source model teardown incomplete')
    delete(app)
    require(not isValid(app), 'application teardown incomplete')
    report['completeQtTeardown'] = True
    write_output(run_directory / 'observations.json', (json.dumps(report, indent=2) + '\n').encode('utf-8'))
    print(json.dumps(report, indent=2))
    return 0


if __name__ == '__main__': raise SystemExit(main())
