"""Exact production detach methods with actual desktop Qt signal connections.

This concrete fixture is not a full Bootstrap/menu qualification.
Pre-operation exceptions and minimal owners are substituted.
"""
from pathlib import Path
import hashlib
import json
import os
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
BASE = ROOT / 'qml/X2d2MenuBootstrap.qml'
QT_ROOT = ROOT.parent / 'x2d2/work/reverse/vendor/qt_host_6_8_2'


def current_methods():
    raw = BASE.read_bytes()
    text = raw.decode('utf-8')
    anchors = ('    function dispatch(', '    function back(',
               '    function detach(', '    onBlockedChanged:')
    if any(text.count(anchor) != 1 for anchor in anchors):
        raise ValueError('exact unique production function anchors required')
    helpers = text[text.index(anchors[0]):text.index(anchors[1])]
    detach = text[text.index(anchors[2]):text.index(anchors[3])]
    receipt_anchor = '    function reportMenuState('
    if text.count(receipt_anchor) != 1:
        raise ValueError('exact unique production receipt function required')
    receipt = text[text.index(receipt_anchor):text.index(anchors[2])]
    destruction = '    Component.onDestruction: detach()'
    if text.count(destruction) != 1:
        raise ValueError('exact unique production destruction callback required')
    find_item = '    function findItem('
    if text.count(find_item) != 1 or text.count('    function attach(') != 1:
        raise ValueError('exact unique production attachment function anchors required')
    attachment = text[text.index(find_item):text.index(anchors[0])]
    return raw, helpers + receipt + detach, destruction, attachment


BOUNDARY = '''import QtQml
QtObject {
    id: root
    property bool attached: true
    property bool open: false
    property bool restoring: false
    property bool routeConnected: true
    property bool stockRouteRemoved: true
    property bool autoAttach: true
    property bool focusRestorePending: false
    property bool menuActive: false
    property bool blocked: true
    property string attachmentState: "attached"
    property bool extensionRowConfirmed: false
    property int menuReportSequence: 0
    property string reportedMenuState: ""
    property string lastMenuReceipt: ""
    property bool menuReportExhausted: false
    // This minimal boundary only exercises cleanup, after attached becomes
    // false. It does not claim rendered entry or readiness qualification.
    readonly property bool entryReady: false
    readonly property bool entryModelMatched: false
    readonly property bool entryVisible: false
    readonly property bool entryEligible: false
    property var grid: null
    property var originalDelegate: null
    property var extensionButton: null
    property var drawer: null
    property var screen: null
    property string fault: ""
    property bool injected: false
    property bool disconnectInjected: false
    property bool connectInjected: false
    property int disconnectCalls: 0
    property int connectCalls: 0
    property int delegateRestoreCalls: 0
    property QtObject adapter: QtObject { property string extensionName: "x2diiMenuExtension" }
    property QtObject emitter: QtObject {
        signal loadSubMenuItem(string name, string sub, bool openItem, bool shortcut)
    }
    property QtObject menu: QtObject {
        property int received: 0
        function loadSubmenu(name, sub, openItem, shortcut) { received++ }
    }
    function prepare(mode) {
        fault = mode
        emitter.loadSubMenuItem.connect(menu.loadSubmenu)
        emitter.loadSubMenuItem.disconnect(menu.loadSubmenu)
        emitter.loadSubMenuItem.connect(dispatch)
        screen = {loadSubMenuItem: {
            disconnect: function(callback) {
                disconnectCalls++
                if (root.fault === "persistent-disconnect"
                        || ((root.fault === "disconnect" || root.fault === "sequential") && !root.disconnectInjected)) {
                    root.injected = true
                    root.disconnectInjected = true
                    throw new Error("INJECTED_BEFORE_NATIVE_DISCONNECT")
                }
                root.emitter.loadSubMenuItem.disconnect(callback)
            },
            connect: function(callback) {
                connectCalls++
                if (root.fault === "persistent-stock-connect"
                        || ((root.fault === "stock-connect" || root.fault === "sequential") && !root.connectInjected)) {
                    root.injected = true
                    root.connectInjected = true
                    throw new Error("INJECTED_BEFORE_NATIVE_STOCK_CONNECT")
                }
                root.emitter.loadSubMenuItem.connect(callback)
            }
        }}
    }
    function fire() { emitter.loadSubMenuItem("menu0", "", false, false) }
    function observe(savedReceiver) {
        var receiver = savedReceiver || menu
        var before = receiver.received
        fire()
        return {routeDelta: receiver.received - before,
                routeConnected: routeConnected, stockRouteRemoved: stockRouteRemoved,
                disconnectCalls: disconnectCalls, connectCalls: connectCalls,
                delegateRestoreCalls: delegateRestoreCalls,
                delegateRestored: !!grid && grid.delegate === originalDelegate,
                attachmentState: attachmentState, attached: attached, restoring: restoring,
                autoAttach: autoAttach}
    }
    function exercise(mode) {
        prepare(mode)
        var baseline = observe()
        var firstResult = detach()
        var first = observe()
        first.cleanupResult = typeof firstResult === "undefined" ? "undefined" : firstResult
        var secondResult = detach()
        var retry = observe()
        retry.cleanupResult = typeof secondResult === "undefined" ? "undefined" : secondResult
        return JSON.stringify({mode: mode, injected: injected,
                               disconnectInjected: disconnectInjected, connectInjected: connectInjected,
                               baseline: baseline, firstDetach: first, secondDetach: retry})
    }
    function exercisePersistent(mode) {
        prepare(mode)
        var baseline = observe()
        var firstResult = detach()
        var first = observe(); first.cleanupResult = firstResult
        var secondResult = detach()
        var second = observe(); second.cleanupResult = secondResult
        fault = "none"
        var recoveryResult = detach()
        var recovery = observe(); recovery.cleanupResult = recoveryResult
        var repeatedResult = detach()
        var repeated = observe(); repeated.cleanupResult = repeatedResult
        return JSON.stringify({mode: mode, injected: injected,
                               baseline: baseline, firstDetach: first, secondDetach: second,
                               faultClearedExplicitRetry: recovery, repeatedSuccess: repeated})
    }
    function exerciseMissingOwner(mode) {
        prepare("none")
        var savedScreen = screen
        var savedMenu = menu
        var baseline = observe(savedMenu)
        if (mode === "missing-screen") screen = null
        else menu = null
        var firstResult = detach()
        var first = observe(savedMenu); first.cleanupResult = firstResult
        var secondResult = detach()
        var second = observe(savedMenu); second.cleanupResult = secondResult
        screen = savedScreen
        menu = savedMenu
        var recoveryResult = detach()
        var recovery = observe(savedMenu); recovery.cleanupResult = recoveryResult
        var repeatedResult = detach()
        var repeated = observe(savedMenu); repeated.cleanupResult = repeatedResult
        return JSON.stringify({mode: mode, baseline: baseline,
                               firstDetach: first, secondDetach: second,
                               ownerRestoredExplicitRetry: recovery, repeatedSuccess: repeated})
    }
    function exerciseDelegateFault() {
        prepare("delegate-restore")
        originalDelegate = {name: "saved-stock-delegate"}
        var currentDelegate = {name: "substituted-extension-delegate"}
        var delegateBoundary = {}
        Object.defineProperty(delegateBoundary, "delegate", {
            get: function() { return currentDelegate },
            set: function(value) {
                root.delegateRestoreCalls++
                if (root.fault === "delegate-restore") {
                    root.injected = true
                    throw new Error("INJECTED_BEFORE_DELEGATE_RESTORE")
                }
                currentDelegate = value
            }
        })
        grid = delegateBoundary
        var baseline = observe()
        var firstResult = detach()
        var first = observe(); first.cleanupResult = firstResult
        var secondResult = detach()
        var second = observe(); second.cleanupResult = secondResult
        fault = "none"
        var recoveryResult = detach()
        var recovery = observe(); recovery.cleanupResult = recoveryResult
        var repeatedResult = detach()
        var repeated = observe(); repeated.cleanupResult = repeatedResult
        return JSON.stringify({mode: "delegate-restore", injected: injected, baseline: baseline,
                               firstDetach: first, secondDetach: second,
                               faultClearedExplicitRetry: recovery, repeatedSuccess: repeated})
    }
__EXACT_PRODUCTION_METHODS__
}
'''


ATTACH_BOUNDARY = '''import QtQml
import QtQuick
QtObject {
    id: root
    property bool attached: false
    property bool open: false
    property bool restoring: false
    property bool routeConnected: false
    property bool stockRouteRemoved: false
    property bool autoAttach: true
    property bool focusRestorePending: false
    property bool menuActive: false
    property bool blocked: true
    property int attachAttempts: 0
    property string attachmentState: "not-ready"
    property bool extensionRowConfirmed: false
    property int menuReportSequence: 0
    property string reportedMenuState: ""
    property string lastMenuReceipt: ""
    property bool menuReportExhausted: false
    readonly property bool entryReady: false
    readonly property bool entryModelMatched: false
    readonly property bool entryVisible: false
    readonly property bool entryEligible: false
    property var screen: null
    property var screenLoader: null
    property var grid: null
    property var drawer: null
    property var originalLoader: null
    property var originalSwipe: null
    property var drawerList: null
    property var originalModel: null
    property var originalDelegate: null
    property var extensionButton: null
    property int disconnectCalls: 0
    property int dispatchConnectCalls: 0
    property int stockConnectCalls: 0
    property string fault: ""
    property Component stockDelegate: Component { QtObject {} }
    property QtObject adapter: QtObject {
        property string extensionName: "x2diiMenuExtension"
        property var sourceModel: null
        property var stockDelegate: null
        property bool extensionPresent: true
        property string rejectionReason: ""
        property int reconcileCalls: 0
        function reconcile() { reconcileCalls++ }
    }
    property QtObject emitter: QtObject {
        signal loadSubMenuItem(string name, string sub, bool openItem, bool shortcut)
    }
    property QtObject menu: QtObject {
        property var parent: root.drawer
        property var children: [
            {objectName: "menu_loader", children: []},
            {objectName: "MainMenu_swipeArea", children: []}]
        property int received: 0
        function loadSubmenu(name, sub, openItem, shortcut) { received++ }
    }
    function observe() {
        var before = menu.received
        emitter.loadSubMenuItem("menu0", "", false, false)
        return {routeDelta: menu.received - before,
                attachmentState: attachmentState, attachAttempts: attachAttempts,
                reconcileCalls: adapter.reconcileCalls,
                attached: attached, restoring: restoring, autoAttach: autoAttach,
                routeConnected: routeConnected, stockRouteRemoved: stockRouteRemoved,
                disconnectCalls: disconnectCalls, dispatchConnectCalls: dispatchConnectCalls,
                stockConnectCalls: stockConnectCalls,
                delegateRestored: !!grid && grid.delegate === originalDelegate}
    }
    function exerciseAttachCatch(mode) {
        fault = mode
        emitter.loadSubMenuItem.connect(menu.loadSubmenu)
        drawer = {objectName: "ControlDrawer_root", mainScreenLoaded: true,
                  controlScreenViewModel: {}, children: [
                      {objectName: "ControlDrawer_list", children: []}]}
        var stockGrid = {objectName: "MainScreen_grid", children: [],
                         numRows: 3, numCols: 4, delegate: stockDelegate}
        screenLoader = {status: Loader.Ready}
        screen = {objectName: "MainScreen_root", mainMenu: menu,
                  viewModel: {favoriteModel: {itemEnabled: function(index) { return true }}},
                  children: [stockGrid], loadSubMenuItem: {
            disconnect: function(callback) {
                root.disconnectCalls++
                root.emitter.loadSubMenuItem.disconnect(callback)
            },
            connect: function(callback) {
                if (callback === root.dispatch) {
                    root.dispatchConnectCalls++
                    throw new Error("INJECTED_ATTACH_BEFORE_NATIVE_DISPATCH_CONNECT")
                }
                root.stockConnectCalls++
                if (root.fault === "pending-cleanup")
                    throw new Error("INJECTED_ATTACH_CLEANUP_BEFORE_STOCK_CONNECT")
                root.emitter.loadSubMenuItem.connect(callback)
            }
        }}
        var baseline = observe()
        attach()
        var failed = observe()
        attach()
        var refusedAutomaticRetry = observe()
        fault = "none"
        var cleanupResult = detach()
        var recovery = observe(); recovery.cleanupResult = cleanupResult
        var repeatedResult = detach()
        var repeated = observe(); repeated.cleanupResult = repeatedResult
        return JSON.stringify({mode: mode, baseline: baseline, afterAttachCatch: failed,
            refusedAutomaticRetry: refusedAutomaticRetry,
            faultClearedExplicitDetach: recovery, repeatedSuccess: repeated})
    }
__EXACT_PRODUCTION_ATTACHMENT_METHODS__
__EXACT_PRODUCTION_METHODS__
}
'''


def destruction_boundary(methods, callback):
    # Keep the actual emitter/stock receiver outside the QObject being deleted.
    owners = '''    property QtObject emitter: QtObject {
        signal loadSubMenuItem(string name, string sub, bool openItem, bool shortcut)
    }
    property QtObject menu: QtObject {
        property int received: 0
        function loadSubmenu(name, sub, openItem, shortcut) { received++ }
    }
'''
    if BOUNDARY.count(owners) != 1:
        raise ValueError('specific signal owner declaration must be unique')
    subject = BOUNDARY.removeprefix('import QtQml\n').replace(owners,
        '    property var emitter: carrier.emitter\n    property var menu: carrier.menu\n')
    subject = subject.replace('                disconnectCalls++',
        '                disconnectCalls++\n                carrier.disconnectCalls++')
    subject = subject.replace('                connectCalls++',
        '                connectCalls++\n                carrier.connectCalls++')
    subject = subject.replace('                    root.injected = true',
        '                    root.injected = true\n                    carrier.injected = true')
    subject = subject.replace('__EXACT_PRODUCTION_METHODS__', methods)
    subject = subject.removesuffix('}\n') + callback + '\n}\n'
    return '''import QtQml
QtObject {
    id: carrier
    property int disconnectCalls: 0
    property int connectCalls: 0
    property bool injected: false
''' + owners + '''    function observeSurvivingRoute() {
        var before = menu.received
        emitter.loadSubMenuItem("menu0", "", false, false)
        return JSON.stringify({routeDelta: menu.received - before,
                               disconnectCalls: disconnectCalls, connectCalls: connectCalls,
                               injected: injected})
    }
    property Component cleanupFactory: Component {
''' + subject + '''    }
    property QtObject subject: cleanupFactory.createObject(carrier)
    function destroyCleanupSubject() { subject.destroy() }
}
'''


def main():
    raw, methods, destruction_callback, attachment_methods = current_methods()
    if '--child' not in sys.argv:
        from tools.qt_supervisor import supervise_worker
        from tools.qt_readiness import runtime_inputs
        report = supervise_worker(Path(__file__), 'bootstrap-detach-fault-validation.json',
            'bootstrap-detach-fault-runs', timeout=45,
            input_paths=[BASE, ROOT / 'tests/test_stock_menu.py',
                         ROOT / 'tools/qt_readiness.py', ROOT / 'tools/build_host_bridge.py'],
            input_provider=runtime_inputs)
        print(json.dumps({key: report.get(key) for key in (
            'result', 'failure', 'candidateContract', 'scope', 'routeObservations',
            'runDirectory', 'workerExitCode', 'completeQtTeardown',
            'processExitVerified', 'sourceInputsUnchanged', 'installable', 'error')}, indent=2))
        return 0 if report['result'] == 'PASS' else 1
    os.environ['QML_DISABLE_DISK_CACHE'] = '1'
    sys.path.insert(0, str(QT_ROOT))
    from PySide6.QtCore import QCoreApplication, QEvent, QUrl, qVersion
    from PySide6.QtQml import QQmlComponent, QQmlEngine, qmlClearTypeRegistrations
    from shiboken6 import delete, isValid
    from tools.output_guard import guard_output, write_output
    run = guard_output(Path(sys.argv[sys.argv.index('--child') + 1]))
    if qVersion() != '6.8.2':
        raise ValueError('expected actual desktop Qt 6.8.2')
    fixture = BOUNDARY.replace('__EXACT_PRODUCTION_METHODS__', methods)
    destructor_fixture = destruction_boundary(methods, destruction_callback)
    attachment_fixture = ATTACH_BOUNDARY.replace('__EXACT_PRODUCTION_ATTACHMENT_METHODS__',
                                                 attachment_methods).replace('__EXACT_PRODUCTION_METHODS__', methods)
    write_output(run / 'production-Bootstrap.qml', raw)
    write_output(run / 'executed-boundary.qml', fixture.encode('utf-8'))
    write_output(run / 'executed-destruction-boundary.qml', destructor_fixture.encode('utf-8'))
    write_output(run / 'executed-attachment-boundary.qml', attachment_fixture.encode('utf-8'))
    app = QCoreApplication([])
    engine = QQmlEngine()
    warnings = []
    engine.warnings.connect(lambda rows: warnings.extend(str(row) for row in rows))
    component = QQmlComponent(engine)
    component.setData(fixture.encode('utf-8'), QUrl('file:///bootstrap-detach-fault-boundary.qml'))
    if component.isError():
        raise RuntimeError('QML boundary error: ' + repr([str(e) for e in component.errors()]))
    observations = []
    pending_observations = []
    missing_owner_observations = []
    delegate_observations = []
    destruction_observations = []
    attachment_observations = []
    owners = []
    for mode in ('none', 'disconnect', 'stock-connect', 'sequential'):
        owner = component.create()
        if owner is None:
            raise RuntimeError('QML boundary create failed')
        row = json.loads(owner.exercise(mode))
        if row['baseline']['routeDelta'] != 1:
            raise AssertionError('actual pre-detach Qt route must deliver once: ' + repr(row))
        if row['injected'] != (mode != 'none'):
            raise AssertionError('one-shot fault boundary reachability mismatch')
        row['stockRouteContractExpectedDelta'] = 1
        row['stockRouteContract'] = ('PASS' if all(row[phase]['routeDelta'] == 1
            for phase in ('firstDetach', 'secondDetach')) else 'FAIL')
        observations.append(row)
        owners.append(owner)
        print(json.dumps(row), flush=True)
    for mode in ('persistent-disconnect', 'persistent-stock-connect'):
        owner = component.create()
        if owner is None:
            raise RuntimeError('persistent boundary create failed')
        row = json.loads(owner.exercisePersistent(mode))
        pending_observations.append(row)
        owners.append(owner)
        print(json.dumps(row), flush=True)
    for mode in ('missing-screen', 'missing-menu'):
        owner = component.create()
        if owner is None:
            raise RuntimeError('missing owner boundary create failed')
        row = json.loads(owner.exerciseMissingOwner(mode))
        missing_owner_observations.append(row)
        owners.append(owner)
        print(json.dumps(row), flush=True)
    owner = component.create()
    if owner is None:
        raise RuntimeError('delegate boundary create failed')
    row = json.loads(owner.exerciseDelegateFault())
    delegate_observations.append(row)
    owners.append(owner)
    print(json.dumps(row), flush=True)
    destruction_component = QQmlComponent(engine)
    destruction_component.setData(destructor_fixture.encode('utf-8'),
                                  QUrl('file:///bootstrap-destruction-fault-boundary.qml'))
    if destruction_component.isError():
        raise RuntimeError('QML destruction boundary error: ' +
                           repr([str(e) for e in destruction_component.errors()]))
    carriers = []
    for mode in ('none', 'disconnect', 'stock-connect', 'sequential'):
        carrier = destruction_component.create()
        if carrier is None:
            raise RuntimeError('destruction carrier create failed')
        carriers.append((mode, carrier, carrier.property('subject'),
                         carrier.property('emitter'), carrier.property('menu')))
    # Keep factory/context and every owner alive while the behavior is observed.
    # The documented factory-before-root-products order applies to final teardown.
    for mode, carrier, subject, emitter, receiver in carriers:
        subject.prepare(mode)
        baseline = json.loads(carrier.observeSurvivingRoute())
        # Use actual QML-created-object destruction, not direct Shiboken deletion
        # that bypasses this usable QML lifecycle and leaves a stale JS connection.
        carrier.destroyCleanupSubject()
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        QCoreApplication.processEvents()
        row = {'mode': mode, 'baseline': baseline,
               'afterActualDestruction': json.loads(carrier.observeSurvivingRoute()),
               'repeatedEmission': json.loads(carrier.observeSurvivingRoute()),
               'subjectDestroyed': not isValid(subject),
               'emitterSurvived': isValid(emitter), 'stockReceiverSurvived': isValid(receiver)}
        destruction_observations.append(row)
        owners.append(carrier)
        print(json.dumps(row), flush=True)
    attachment_component = QQmlComponent(engine)
    attachment_component.setData(attachment_fixture.encode('utf-8'),
                                 QUrl('file:///bootstrap-attachment-fault-boundary.qml'))
    if attachment_component.isError():
        raise RuntimeError('QML attachment boundary error: ' +
                           repr([str(e) for e in attachment_component.errors()]))
    for mode in ('cleanup-succeeds', 'pending-cleanup'):
        owner = attachment_component.create()
        if owner is None:
            raise RuntimeError('attachment boundary create failed')
        row = json.loads(owner.exerciseAttachCatch(mode))
        attachment_observations.append(row)
        owners.append(owner)
        print(json.dumps(row), flush=True)
    if warnings:
        raise AssertionError('unexpected Qt engine warning: ' + repr(warnings))
    # Qt setData lifetime: destroy the factory before its created products.
    delete(attachment_component)
    delete(destruction_component)
    delete(component)
    for owner in owners:
        delete(owner)
        if isValid(owner):
            raise AssertionError('actual QObject owner not destroyed')
    delete(engine)
    qmlClearTypeRegistrations()
    delete(app)
    if any(isValid(obj) for obj in (attachment_component, destruction_component, component, engine, app)):
        raise AssertionError('Qt boundary teardown incomplete')
    if warnings:
        raise AssertionError('late Qt boundary teardown warning: ' + repr(warnings))
    report = {'result': 'EXECUTED_PENDING_PROCESS_EXIT',
        'candidateContract': 'PASS' if all(row['stockRouteContract'] == 'PASS' for row in observations) else 'FAIL',
        'scope': 'exact-production-QML-cleanup-fault-boundaries-actual-desktop-Qt-signals',
        'productionBootstrapSha256': hashlib.sha256(raw).hexdigest(),
        'exactProductionMethodsSha256': hashlib.sha256(methods.encode('utf-8')).hexdigest(),
        'exactProductionDestructionCallbackSha256': hashlib.sha256(destruction_callback.encode('utf-8')).hexdigest(),
        'exactProductionAttachmentMethodsSha256': hashlib.sha256(attachment_methods.encode('utf-8')).hexdigest(),
        'executedBoundarySha256': hashlib.sha256(fixture.encode('utf-8')).hexdigest(),
        'executedDestructionBoundarySha256': hashlib.sha256(destructor_fixture.encode('utf-8')).hexdigest(),
        'executedAttachmentBoundarySha256': hashlib.sha256(attachment_fixture.encode('utf-8')).hexdigest(),
        'routeObservations': observations, 'pendingObservations': pending_observations,
        'missingOwnerObservations': missing_owner_observations,
        'delegateObservations': delegate_observations,
        'destructionObservations': destruction_observations,
        'attachmentObservations': attachment_observations,
        'qmlWarnings': warnings,
        'substitutions': ['Exact dispatch/restoreFocusIfNeeded/dismiss/detach functions execute from retained current source.',
            'Minimal QObject owners and counter-only stock receiver replace full menu/UI owners.',
            'Signal facade injects one-shot or persistent pre-operation exceptions; successful operations delegate to actual Qt signals.',
            'Missing screen/menu references substitute unavailable owners while actual signal/receiver owners survive.',
            'JS delegate property setter throws before assignment; this is not a real visual delegate qualification.',
            'QML Component creates cleanup subject dynamically; actual QML destroy plus deferred-delete delivery invokes extracted exact callback while native siblings survive.',
            'Attachment boundary executes extracted exact findItem/attach and actual QtQuick Loader.Ready enum; minimal prerequisites and adapter reconciliation replace full stock graph.',
            'Dispatch-connect throws before native operation to enter actual attach catch; pending case also injects persistent stock restore failure.',
            'Full successful attachment, visual/model/delegate/focus paths are excluded.'],
        'limitations': ['No proof that an unmodified native Qt signal spontaneously fails this way.',
            'No full Bootstrap/stock-harness or Android/native ARM64/camera qualification.'],
        'completeQtTeardown': True, 'qmlTypeRegistrationsCleared': True,
        'cameraAccesses': 0, 'installable': False}
    write_output(run / 'observations.json', (json.dumps(report, indent=2) + '\n').encode('utf-8'))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
