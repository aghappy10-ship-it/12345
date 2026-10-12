"""Execute the cloned real II MainScreen unit, stock delegates and menu extension.

Outer camera services/state, native FavoriteModel and device rendering/key codes
are named substitutes. The actual original bytecode, stock grid/button QML and
new extension files execute under desktop Qt 6.8.2. No camera access.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import sys
import faulthandler

# The observer process, which never loads Qt, publishes PASS only after the Qt
# worker has exited cleanly. A result printed before interpreter teardown is
# not sufficient evidence; native shutdown failures must invalidate it.
if __name__ == '__main__' and '--child' not in sys.argv:
    from output_guard import PROJECT
    from qt_supervisor import supervise_worker
    from qt_readiness import runtime_inputs
    inputs = [PROJECT / name for name in (
        'tools/check_menu_model.py', 'tools/host_cache.py', 'tools/qt_readiness.py',
        'tools/build_host_bridge.py', 'tools/prepare_host_fixture.py',
        'tools/menu_inputs.py', 'tools/qt_unit.py', 'tools/build_unit.py',
        'tools/extract_qml.py', 'src/host_cache_bridge.c',
        'build/host-bridge/native/host_cache_bridge.dll', 'build/host-bridge/native/BUILD.json',
        'build/units/main-screen-bootstrap-host.bin',
        'build/units/main-screen-bootstrap-device.bin',
        'build/stock-qml/manifest.json', 'tests/fixtures/StockHarness.qml')]
    inputs.extend(sorted((PROJECT / 'qml').glob('*.qml')))
    evidence = supervise_worker(Path(__file__), 'stock-menu-validation.json',
                                'stock-menu-runs', timeout=60, input_paths=inputs,
                                input_provider=runtime_inputs)
    print(json.dumps({key: evidence.get(key) for key in (
        'result', 'failure', 'scope', 'cases', 'runDirectory',
        'workerExitCode', 'completeQtTeardown', 'processExitVerified',
        'sourceInputsUnchanged', 'installable', 'error')}, indent=2))
    raise SystemExit(0 if evidence['result'] == 'PASS' else 1)

from check_menu_model import SourceModel, PROJECT, require, QGuiApplication, QQmlApplicationEngine, QTest, Qt, QPoint, QUrl
os.environ.pop('QML_DISABLE_DISK_CACHE', None)
from host_cache import HostCache, prepare_host
from prepare_host_fixture import prepare
from output_guard import write_output
from menu_inputs import verify_current_pair
from qt_readiness import wait_for


def main():
    faulthandler.enable()
    unit_pair = verify_current_pair()
    fixture = prepare()
    runtime = prepare_host(PROJECT / 'build/host/runtime')
    from PySide6.QtCore import QResource, QCoreApplication, QEvent, qInstallMessageHandler, qFormatLogMessage
    from PySide6.QtQuick import QQuickItem
    from PySide6.QtQml import qmlClearTypeRegistrations
    from shiboken6 import getCppPointer, delete, isValid
    # Windows Qt may route info to the debugger rather than inherited stderr.
    # Capture actual Qt messages; do not manufacture receipts from properties.
    # Real camera qualification separately requires its actual gui.log bytes.
    qt_menu_receipts = []
    def retain_qt_message(kind, context, message):
        if message.startswith('X2DII_MENU_STATE_V1:'):
            qt_menu_receipts.append(message.removeprefix('X2DII_MENU_STATE_V1:'))
        print(qFormatLogMessage(kind, context, message), file=sys.stderr, flush=True)
    previous_message_handler = qInstallMessageHandler(retain_qt_message)
    app = QGuiApplication([])
    require(QResource.registerResource(str(PROJECT / 'build/host/keys.rcc')), 'stock Keys.js resource registration')
    unit = PROJECT / 'build/units/main-screen-bootstrap-host.bin'
    url = (PROJECT / 'build/host/stock/mainmenu/MainScreen.qml').as_uri()
    cache = HostCache(unit, url, PROJECT / 'build/host/runtime', expected_sha256=unit_pair['host']['candidateUnitSha256'])
    source = SourceModel()
    engine = QQmlApplicationEngine()
    engine.addImportPath(str(PROJECT / 'build/host/imports'))
    engine.rootContext().setContextProperty('stockSource', source)
    warnings = []
    engine.warnings.connect(lambda ws: warnings.extend(str(w) for w in ws))
    engine.load(QUrl.fromLocalFile(str(PROJECT / 'tests/fixtures/StockHarness.qml')))
    require(bool(engine.rootObjects()), 'stock fixture failed: ' + repr(warnings))
    window = engine.rootObjects()[0]
    wait_for(engine, lambda: window.findChild(QQuickItem, 'X2d2MenuExtension'), 'initial extension creation')
    QTest.qWait(20)
    extension = window.findChild(QQuickItem, 'X2d2MenuExtension')
    wrapper = window.findChild(QQuickItem, 'HblLoader')
    parent_state = {name: wrapper.property(name) for name in ('status', 'active', 'asynchronous', 'source', 'progress')} if wrapper else {}
    require(extension is not None, 'compiled Loader not instantiated: ' + repr((warnings, parent_state, cache.hits)))
    require(cache.hits > 0, 'compiled cache was not used')
    require(extension.property('attached'), 'extension not attached: ' + str(extension.property('attachmentState')) + repr(warnings))
    parent_loader = extension.property('screenLoader')
    require(parent_loader is not None and parent_loader.objectName() == 'HblLoader_internal_loader'
            and parent_loader.property('asynchronous') is True
            and parent_loader.parentItem().objectName() == 'HblLoader', 'original asynchronous parent Loader was not used')
    parent_loader_evidence = {'internalObjectName': parent_loader.objectName(),
                              'wrapperObjectName': parent_loader.parentItem().objectName(),
                              'asynchronous': parent_loader.property('asynchronous')}
    grid = window.findChild(QQuickItem, 'MainScreen_grid')
    page = window.findChild(QQuickItem, 'X2d2ExtensionPage')
    require(grid is not None and page is not None, 'real grid/page not found')
    page_pointer = getCppPointer(page)[0]
    require(grid.property('count') == 12, 'extended stock grid count')
    cases = ['compiled-loader-automatic-attachment']
    menu_state_observations = []

    def settle(): QTest.qWait(20)
    def routes(): return window.property('routes').toVariant()
    def click(index, *, highlight=True):
        position = json.loads(window.point(index))
        point = QPoint(round(position['x']), round(position['y']))
        QTest.mousePress(window, Qt.LeftButton, Qt.NoModifier, point)
        settle()
        if highlight:
            require(grid.property('currentIndex') == index, 'pressed highlight: ' + str((index, grid.property('currentIndex'))))
        QTest.mouseRelease(window, Qt.LeftButton, Qt.NoModifier, point)
        settle()
    def shown(expected, label):
        require(extension.isVisible() == expected and page.isVisible() == expected, label + ': page visibility')
        require(window.property('inMenu') == expected, label + ': inMenu binding')
        require(window.property('swipeBlocked') == expected, label + ': swipe binding')
        require(getCppPointer(page)[0] == page_pointer, label + ': page instance changed')
        require(not warnings, label + ': ' + repr(warnings))

    def menu_receipt(phase, expected):
        # Observe the public wire emitted by this actual QML instance. The
        # caller's known stock-grid/page state supplies independent expectations.
        wire = extension.property('lastMenuReceipt')
        fields = wire.split(':') if isinstance(wire, str) else []
        require(len(fields) == 8 and fields[0].isdigit(), phase + ': missing menu receipt')
        require([int(value) for value in fields[1:]] == expected,
                phase + ': receipt does not match actual grid/page state: ' + repr(wire))
        require(qt_menu_receipts and qt_menu_receipts[-1] == wire,
                phase + ': property has no matching latest actual Qt message')
        menu_state_observations.append({'phase': phase, 'wire': wire, 'expected': expected,
                                       'emittedIndex': len(qt_menu_receipts) - 1})

    menu_receipt('rendered', [1, 1, 1, 1, 1, 12, 11])

    for i in range(11): click(i)
    require([r['name'] for r in routes()] == ['menu' + str(i) for i in range(11)], 'original routes must forward once')
    cases.append('eleven-original-touch-routes-once')
    for i in range(30):
        click(11)
        shown(True, 'open-' + str(i))
        if i == 0: menu_receipt('page-open', [1, 1, 1, 0, 0, 12, 11])
        require(not window.property('listInteractive'), 'drawer remains swipeable under page')
        if i % 4 == 0: QTest.keyClick(window, Qt.Key_Escape)
        elif i % 4 == 1: window.closeMenu()
        elif i % 4 == 2: window.exitMenu()
        else:
            button = window.findChild(QQuickItem, 'X2d2ExtensionBack')
            point = button.mapToItem(window.contentItem(), button.width()/2, button.height()/2)
            QTest.mouseClick(window, Qt.LeftButton, Qt.NoModifier, QPoint(round(point.x()), round(point.y())))
        settle()
        shown(False, 'return-' + str(i))
        if i == 0: menu_receipt('page-return', [1, 1, 1, 1, 1, 12, 11])
        require(window.property('listInteractive'), 'drawer swipe not restored')
        require(window.focusInStock(), 'return did not restore stock keyboard focus')
    cases.append('thirty-touch-key-signal-returns-one-page')
    window.select(11)
    QTest.keyClick(window, Qt.Key_Return)
    settle(); shown(True, 'keyboard-select')
    QTest.keyClick(window, Qt.Key_Back)
    settle(); shown(False, 'joystick-escape')
    cases.append('stock-delegate-keyboard-path')
    external_focus_observations = []
    for prop, value in [('mediaBusy', True), ('activeError', True), ('exposing', True), ('popup', True),
                        ('mainState', 'liveview'), ('viewState', 'control_screen'), ('drawerAtTop', True),
                        ('drawerSwiping', True), ('listMoving', True), ('listIndex', 0), ('stockState', 'menu')]:
        before = window.property(prop)
        click(11); shown(True, prop + '-before')
        focus_target = None
        if prop in ('popup', 'activeError'):
            object_name = 'FixturePopupFocusOwner' if prop == 'popup' else 'FixtureErrorFocusOwner'
            focus_target = window.findChild(QQuickItem, object_name)
            require(focus_target is not None and focus_target.parentItem() == window.contentItem(),
                    prop + ': external focus owner must survive outside the stock screen/extension')
            focus_target.setVisible(True)
            focus_target.forceActiveFocus()
            settle()
            focused_before_block = window.activeFocusItem() == focus_target
            require(focused_before_block, prop + ': external owner did not acquire focus')
            routes_before_block = len(routes())
            keys_before = focus_target.property('receivedKeys')
        window.setProperty(prop, value); settle(); shown(False, prop + '-closes')
        if focus_target is not None:
            focused_after_dismiss = window.activeFocusItem() == focus_target
            require(focused_after_dismiss, prop + ': dismissal stole external focus')
        extension.dispatch('x2diiMenuExtension', '', False, False)
        settle(); shown(False, prop + '-rejects')
        if focus_target is not None:
            focused_after_rejected_dispatch = window.activeFocusItem() == focus_target
            require(focused_after_rejected_dispatch, prop + ': rejected dispatch stole external focus')
            # The page survives dismissal. A late Back signal from that same
            # public object must not take focus from a stock popup/error owner.
            page.backRequested.emit(); settle()
            focused_after_back_signal = window.activeFocusItem() == focus_target
            require(focused_after_back_signal, prop + ': late Back signal stole external focus')
            QTest.keyClick(window, Qt.Key_Return); settle()
            received_keys = focus_target.property('receivedKeys') - keys_before
            require(received_keys == 1,
                    prop + ': external owner did not receive its real Qt key event')
            require(len(routes()) == routes_before_block, prop + ': external key leaked to a stock menu route')
            row = {'role': prop, 'focusedBeforeBlock': focused_before_block,
                   'focusedAfterDismiss': focused_after_dismiss,
                   'focusedAfterRejectedDispatch': focused_after_rejected_dispatch,
                   'focusedAfterBackSignal': focused_after_back_signal,
                   'receivedKeys': received_keys,
                   'stockRouteDeltaWhileBlocked': len(routes()) - routes_before_block,
                   'pageHiddenWhileBlocked': not page.isVisible()}
            require(before is False, prop + ': unexpected pre-existing block')
            # The external lifecycle releases its own owner BEFORE its state
            # clears. Do not select a stock row or manually force screen focus.
            window.releaseExternalFocus(prop); settle()
            require(not focus_target.isVisible() and window.focusInStock(),
                    prop + ': external release did not restore stock focus')
            row['stockFocusAfterExternalRelease'] = bool(window.focusInStock())
            # Original MainScreen stops highlighting when focus leaves. Its
            # real NavKey restores the saved index before arrow navigation.
            QTest.keyClick(window, Qt.Key_F3); settle()
            require(grid.property('currentIndex') == 11, prop + ': stock NavKey did not resume its saved row')
            QTest.keyClick(window, Qt.Key_Left); settle()
            require(grid.property('currentIndex') == 10, prop + ': stock arrow navigation did not resume')
            QTest.keyClick(window, Qt.Key_Return); settle()
            require(len(routes()) == routes_before_block + 1 and routes()[-1]['name'] == 'menu10',
                    prop + ': stock select did not resume exactly once')
            row['stockRouteDeltaAfterRelease'] = len(routes()) - routes_before_block
            external_focus_observations.append(row)
        else:
            window.setProperty(prop, before); settle()
        shown(False, prop + '-no-stale-reopen')
        if prop in ('mediaBusy', 'activeError', 'exposing', 'popup'):
            require(window.focusInStock(), prop + ': stock keyboard focus lost after recovery')
        cases.append(prop + '-gating')
    window.setProperty('evf', True)
    click(11, highlight=False); shown(False, 'evf-touch')
    window.select(11); QTest.keyClick(window, Qt.Key_Return); settle(); shown(True, 'evf-keyboard')
    # EVF overlay must suppress the new page's touch return too.
    button = window.findChild(QQuickItem, 'X2d2ExtensionBack')
    point = button.mapToItem(window.contentItem(), button.width()/2, button.height()/2)
    QTest.mouseClick(window, Qt.LeftButton, Qt.NoModifier, QPoint(round(point.x()), round(point.y())))
    settle(); shown(True, 'evf-page-touch-blocked')
    QTest.keyClick(window, Qt.Key_Menu); settle(); shown(False, 'evf-menu-return')
    window.setProperty('evf', False)
    cases.append('evf-touch-block-keyboard-preserved')
    original_route_count = 11 + len(external_focus_observations)
    require(len(routes()) == original_route_count, 'extension name leaked to native stock route')
    window.go('menu0', 'detail', True, True)
    require(routes()[-1] == dict(name='menu0', sub='detail', openItem=True, shortcut=True), 'four argument route lost')
    source.reset(10); settle()
    require(grid.property('count') == 11 and extension.property('extensionIndex') == 10, 'dynamic stock count')
    menu_receipt('source-reset', [1, 1, 1, 1, 1, 11, 10])
    click(10); shown(True, 'dynamic-index'); extension.back(); settle()
    source.reset(11); settle()
    require(grid.property('count') == 12 and extension.property('extensionIndex') == 11,
            'selected-extension capacity baseline')
    click(11); shown(True, 'selected-extension-before-capacity')
    routes_before_capacity_removal = len(routes())
    source.reset(12); settle()
    require(grid.property('count') == 12 and extension.property('extensionIndex') == -1, 'full grid should exclude extension')
    shown(False, 'selected-extension-disappears-at-capacity')
    menu_receipt('full-grid', [0, 1, 0, 0, 0, 12, -1])
    require(window.focusInStock(), 'selected-extension disappearance did not restore stock focus')
    # Use the real stock NavKey to resume its saved row, as after external focus
    # release. Do not repair the surviving stock row or focus from the checker.
    QTest.keyClick(window, Qt.Key_F3); settle()
    require(grid.property('currentIndex') == 11, 'capacity removal stock NavKey did not resume its saved row')
    QTest.keyClick(window, Qt.Key_Left); settle()
    require(grid.property('currentIndex') == 10, 'capacity removal stock arrow navigation did not resume')
    QTest.keyClick(window, Qt.Key_Return); settle()
    require(len(routes()) == routes_before_capacity_removal + 1 and routes()[-1]['name'] == 'menu10',
            'capacity removal stock select did not resume exactly once')
    shown(False, 'capacity-removal-stock-route-no-reopen')
    extension.dispatch('x2diiMenuExtension', '', False, False); settle(); shown(False, 'full-grid-route')
    source.reset(11); settle()
    menu_receipt('source-restored', [1, 1, 1, 1, 1, 12, 11])
    cases.append('dynamic-grid-count-and-capacity')
    cases.append('selected-extension-capacity-removal-stock-key-route-once')
    extension.detach()
    # No event processing here: unloading must invalidate the wire synchronously.
    menu_receipt('detached', [0, 0, 0, 0, 0, -1, -1])
    settle()
    require(grid.property('count') == 11 and not extension.property('attached'), 'detach source model restore')
    click(0)
    require(len(routes()) == original_route_count + 3 and routes()[-1]['name'] == 'menu0', 'detach stock route restored exactly once')
    require(not warnings, repr(warnings))
    cases.append('detach-original-model-route-bindings')
    # Destroy only the injected Loader, retaining all stock objects. Toggling
    # the original sources afterwards detects bindings tied to a dead context.
    window.setExtensionActive(False); settle()
    require(window.findChild(QQuickItem, 'X2d2MenuExtension') is None, 'extension not destroyed')
    for value in (True, False, True, False):
        window.setStockActive(value); window.setStockSwipe(value); window.setProperty('popup', value); settle()
        require(window.property('inMenu') == value and window.property('swipeBlocked') == value,
                'original dynamic binding died when extension context was destroyed')
        require(window.property('listInteractive') != value, 'original interactive binding died')
    source.reset(10); settle(); require(grid.property('count') == 10, 'original grid model binding died')
    source.reset(11); settle()
    cases.append('destroyed-context-stock-bindings-stay-live')
    for initial in (0, 12):
        source.reset(initial); settle(); window.setExtensionActive(True); settle()
        extension = window.findChild(QQuickItem, 'X2d2MenuExtension')
        require(extension is not None and not extension.property('attached'), 'invalid initial source attached')
        source.reset(11)
        wait_for(engine, lambda: extension.property('attached'), 'delayed model attachment')
        require(extension.property('attached') and grid.property('count') == 12, 'delayed model did not automatically attach')
        before_routes = len(routes())
        window.go('menu0', '', False, False)
        require(len(routes()) == before_routes + 1, 'late attach duplicated stock signal route')
        click(11)
        require(extension.isVisible(), 'late attach cannot open page')
        # Exercise destructor detach directly, not only a manual prior detach.
        window.setExtensionActive(False); settle()
        require(grid.property('count') == 11, 'destructor did not restore original delegate')
        window.setStockActive(True); settle(); require(window.property('inMenu'), 'destructor binding restore')
        window.setStockActive(False); settle(); require(not window.property('inMenu'), 'destructor stale binding')
        before_routes = len(routes()); window.go('menu0', '', False, False)
        require(len(routes()) == before_routes + 1, 'destructor did not restore exactly one stock route')
        before_routes = len(routes())
        window.select(0); settle()
        require(grid.property('currentIndex') == 0 and window.focusInStock(),
                'destructor stock keyboard row/focus not selected')
        QTest.keyClick(window, Qt.Key_Return); settle()
        require(len(routes()) == before_routes + 1 and routes()[-1]['name'] == 'menu0',
                'destructor did not restore exactly one real stock keyboard route')
    cases.append('empty-full-initial-model-recovery-and-direct-unload')
    cases.append('direct-unload-original-stock-keyboard-route-once')
    # Recreate the real parent Loader while mainScreenLoaded remains true, as
    # in ControlDrawer. Attachment must wait until its new onLoaded route exists.
    window.setExtensionActive(True)
    wait_for(engine, lambda: window.findChild(QQuickItem, 'X2d2MenuExtension'), 'reload baseline extension')
    settle()
    require(window.findChild(QQuickItem, 'X2d2MenuExtension').property('attached'), 'reload baseline not attached')
    menu_instance_observations = []
    for generation in range(4):
        receipt_start = len(qt_menu_receipts)
        window.setScreenActive(False); settle()
        require(window.findChild(QQuickItem, 'MainScreen_root') is None, 'parent loader did not unload')
        unloaded_receipts = qt_menu_receipts[receipt_start:]
        require(unloaded_receipts and unloaded_receipts[-1].split(':')[1:] ==
                ['0', '0', '0', '0', '0', '-1', '-1'], 'destructor did not emit unavailable state')
        receipt_start = len(qt_menu_receipts)
        window.setScreenActive(True)
        wait_for(engine, lambda: window.findChild(QQuickItem, 'X2d2MenuExtension'), 'parent Loader recreation')
        QTest.qWait(20)
        extension = window.findChild(QQuickItem, 'X2d2MenuExtension')
        grid = window.findChild(QQuickItem, 'MainScreen_grid')
        require(extension is not None and extension.property('attached'), 'screen reload not attached')
        reloaded_receipts = qt_menu_receipts[receipt_start:]
        require(reloaded_receipts and reloaded_receipts[0] == '1:0:0:0:0:0:-1:-1',
                'new Loader did not invalidate the previous instance ready receipt')
        require(reloaded_receipts[-1] == extension.property('lastMenuReceipt') and
                reloaded_receipts[-1].split(':')[1:] == ['1', '1', '1', '1', '1', '12', '11'],
                'reloaded actual Qt receipt not ready')
        menu_instance_observations.append({'generation': generation + 1,
                                          'unloadedReceipts': unloaded_receipts,
                                          'reloadedReceipts': reloaded_receipts})
        before_routes = len(routes())
        window.go('menu0', 'after-reload', False, False)
        require(len(routes()) == before_routes + 1, 'screen reload duplicates original route')
        click(11)
        require(extension.isVisible() and len(routes()) == before_routes + 1, 'extension leaked after parent reload')
        extension.back(); settle()
        require(window.focusInStock(), 'reload focus restoration')
    cases.append('parent-loader-recreation-route-order-and-focus')
    # Repeated equal state is silent. A genuine gating change advances once,
    # then repeated assignment of the same input must not create another wire.
    window.setProperty('exposing', True); settle()
    before_repeated = len(qt_menu_receipts)
    for _ in range(3):
        window.setProperty('exposing', True); settle()
    repeated_count = len(qt_menu_receipts) - before_repeated
    require(repeated_count == 0, 'identical state was reported again')
    window.setProperty('exposing', False); settle()
    while extension.property('menuReportSequence') < 256:
        window.setProperty('exposing', not window.property('exposing')); settle()
    last_normal_sequence = extension.property('menuReportSequence')
    before_overflow = len(qt_menu_receipts)
    window.setProperty('exposing', not window.property('exposing')); settle()
    overflow_receipts = qt_menu_receipts[before_overflow:]
    require(overflow_receipts == ['OVERFLOW'] and extension.property('lastMenuReceipt') == 'OVERFLOW',
            'state budget did not become one sticky unknown receipt')
    before_after = len(qt_menu_receipts)
    for _ in range(3):
        window.setProperty('exposing', not window.property('exposing')); settle()
    after_overflow_count = len(qt_menu_receipts) - before_after
    after_overflow_wire = extension.property('lastMenuReceipt')
    before_detach = len(qt_menu_receipts)
    extension.detach()
    after_detach_count = len(qt_menu_receipts) - before_detach
    after_detach_wire = extension.property('lastMenuReceipt')
    require(after_overflow_count == 0 and after_detach_count == 0 and
            after_overflow_wire == after_detach_wire == 'OVERFLOW', 'exhaustion reused an old ready state')
    menu_report_budget = {'repeatedStateReceiptCount': repeated_count,
                          'lastNormalSequence': last_normal_sequence, 'overflowReceipts': overflow_receipts,
                          'afterOverflowReceiptCount': after_overflow_count,
                          'afterDetachReceiptCount': after_detach_count,
                          'afterOverflowLastWire': after_overflow_wire, 'afterDetachLastWire': after_detach_wire}
    cases.append('menu-receipt-dedup-256-overflow-and-detach')
    require(not warnings, 'lifecycle warnings: ' + repr(warnings))
    report = {'result': 'EXECUTED_PENDING_PROCESS_EXIT', 'scope': 'real-compiled-unit-and-stock-delegates-desktop-only',
              'cases': cases, 'cacheHits': cache.hits, 'originalStockResources': fixture['preserved'],
              'parentLoaderEvidence': parent_loader_evidence,
              'externalFocusObservations': external_focus_observations,
              'menuStateObservations': menu_state_observations,
              'menuInstanceObservations': menu_instance_observations,
              'menuReportBudget': menu_report_budget,
              'incubationPolicy': 'Existing native Qt controller is advanced in bounded 5ms slices; asynchronous Loader remains enabled.',
              'substitutes': fixture['substitutes'], 'qtRuntimeFiles': runtime['runtime_files'],
              'hostUnitSha256': hashlib.sha256(unit.read_bytes()).hexdigest(),
              'unitPair': unit_pair,
              'extensionSha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((PROJECT / 'qml').glob('*.qml'))},
              'cameraAccesses': 0, 'installable': False,
              'limitations': ['Windows bytecode fallback instead of native ARM64 AOT execution',
                              'outer camera state/services, native model and key codes are substitutes',
                              'external popup/error focus owners are fixture boundary substitutes, not camera dialogs',
                              'Windows Qt logging is forwarded to stderr through its real message handler; target gui.log is not observed',
                              'UiImage geometry substitute; no device rendering or capture validation']}
    # Dispose dynamically injected contexts while their original owners still
    # exist, then synchronously dispose the engine (and its owned root window).
    window.setScreenActive(False); settle()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    require(window.findChild(QQuickItem, 'MainScreen_root') is None, 'screen remains during shutdown')
    require(not warnings, 'shutdown produced QML errors: ' + repr(warnings))
    window.close()
    print('TEARDOWN_ENGINE', file=sys.stderr, flush=True)
    delete(engine)
    require(not isValid(engine) and not isValid(window), 'engine/root teardown incomplete')
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    delete(source)
    require(not isValid(source), 'model teardown incomplete')
    print('TEARDOWN_CACHE', file=sys.stderr, flush=True)
    cache.close()
    # No engine remains. Drain Qt's global compilation-unit references while
    # the Python-owned static cache storage is still alive, before module exit.
    qmlClearTypeRegistrations()
    report['qmlTypeRegistrationsCleared'] = True
    QResource.unregisterResource(str(PROJECT / 'build/host/keys.rcc'))
    print('TEARDOWN_APPLICATION', file=sys.stderr, flush=True)
    delete(app)
    require(not isValid(app), 'application teardown incomplete')
    qInstallMessageHandler(previous_message_handler)
    require(not warnings, 'late Qt teardown warnings: ' + repr(warnings))
    print('TEARDOWN_COMPLETE', file=sys.stderr, flush=True)
    report['completeQtTeardown'] = True
    out = Path(sys.argv[sys.argv.index('--child') + 1]) / 'observations.json'
    write_output(out, (json.dumps(report, indent=2) + '\n').encode('utf-8'))
    return 0


if __name__ == '__main__': raise SystemExit(main())
