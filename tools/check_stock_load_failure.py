"""Exercise actual compiled Loader failure without changing candidate QML.

This uses the same declared desktop substitutes as check_stock_menu. Only the
Page URL is redirected to a run-owned missing or malformed dependency. No
camera, installation, target rendering or physical-key claim is made.
"""
from __future__ import annotations

import faulthandler
import hashlib
import json
import os
from pathlib import Path
import sys
import time


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
    evidence = supervise_worker(Path(__file__), 'stock-load-failure-validation.json',
                                'stock-load-failure-runs', timeout=60, input_paths=inputs,
                                input_provider=runtime_inputs)
    print(json.dumps(evidence, indent=2))
    raise SystemExit(0 if evidence['result'] == 'PASS' else 1)


from check_menu_model import SourceModel, PROJECT, require, QGuiApplication, QQmlApplicationEngine, QTest, Qt, QPoint, QUrl
os.environ.pop('QML_DISABLE_DISK_CACHE', None)
from host_cache import HostCache, prepare_host
from prepare_host_fixture import prepare
from menu_inputs import verify_current_pair
from output_guard import output_directory, write_output
from qt_readiness import wait_for, wait_events


def main():
    faulthandler.enable()
    faulthandler.dump_traceback_later(10, repeat=True)
    from PySide6.QtCore import QResource, QCoreApplication, QEvent
    from PySide6.QtQml import QQmlAbstractUrlInterceptor, QQmlExpression, qmlContext, qmlClearTypeRegistrations
    from PySide6.QtQuick import QQuickItem
    from shiboken6 import delete, isValid

    run = Path(sys.argv[sys.argv.index('--child') + 1])
    pair = verify_current_pair()
    fixture = prepare()
    runtime = prepare_host(PROJECT / 'build/host/runtime')
    unit = PROJECT / 'build/units/main-screen-bootstrap-host.bin'
    url = (PROJECT / 'build/host/stock/mainmenu/MainScreen.qml').as_uri()
    cache = HostCache(unit, url, PROJECT / 'build/host/runtime', expected_sha256=pair['host']['candidateUnitSha256'])
    app = QGuiApplication([])
    require(QResource.registerResource(str(PROJECT / 'build/host/keys.rcc')), 'stock key resource registration')
    page_url = QUrl.fromLocalFile(str(PROJECT / 'qml/X2d2MenuPage.qml'))
    bootstrap_url = QUrl.fromLocalFile(str(PROJECT / 'qml/X2d2MenuBootstrap.qml')).toString()

    def evaluate(item, code):
        expression = QQmlExpression(qmlContext(item), item, code)
        value, undefined = expression.evaluate()
        error = expression.hasError()
        delete(expression)
        require(not error and not undefined, 'QML observation failed: ' + code)
        return value

    class PageFault(QQmlAbstractUrlInterceptor):
        def __init__(self, replacement):
            super().__init__()
            self.replacement = replacement
            self.hits = 0

        def intercept(self, path, kind):
            if kind == self.DataType.QmlFile and path == page_url:
                self.hits += 1
                return self.replacement
            return path

    cases = []
    for scenario in ('missing-page', 'malformed-page'):
        print('PHASE ' + scenario + ': preparing engine', file=sys.stderr, flush=True)
        directory = output_directory(run / scenario)
        bad_page = directory / 'X2d2MenuPage.qml'
        if scenario == 'malformed-page':
            write_output(bad_page, b'import QtQuick\nItem {\n')
        else:
            require(not bad_page.exists(), 'missing dependency fixture already exists')
        replacement = QUrl.fromLocalFile(str(bad_page))
        interceptor = PageFault(replacement)
        source = SourceModel()
        engine = QQmlApplicationEngine()
        engine.addImportPath(str(PROJECT / 'build/host/imports'))
        engine.addUrlInterceptor(interceptor)
        engine.rootContext().setContextProperty('stockSource', source)
        warnings = []
        engine.warnings.connect(lambda rows: warnings.extend(
            {'url': row.url().toString(), 'description': row.description(), 'line': row.line()}
            for row in rows))
        hits_before = cache.hits
        print('PHASE ' + scenario + ': engine.load', file=sys.stderr, flush=True)
        engine.load(QUrl.fromLocalFile(str(PROJECT / 'tests/fixtures/StockHarness.qml')))
        print('PHASE ' + scenario + ': initial incubation', file=sys.stderr, flush=True)
        require(bool(engine.rootObjects()), 'stock envelope failed: ' + repr(warnings))
        window = engine.rootObjects()[0]
        wait_for(engine, lambda: window.findChild(QQuickItem, 'X2d2MenuBootstrapLoader'), 'failed dependency Loader creation')
        wait_for(engine, lambda: window.property('loaded'), 'original parent loaded signal')
        wait_events(20)
        require(interceptor.hits > 0 and cache.hits > hits_before, 'real dependency/cache path was not exercised')
        loader = window.findChild(QQuickItem, 'X2d2MenuBootstrapLoader')
        grid = window.findChild(QQuickItem, 'MainScreen_grid')
        require(loader is not None and grid is not None, 'original screen/Loader absent')
        parent_loader = window.findChild(QQuickItem, 'HblLoader_internal_loader')
        require(parent_loader is not None and parent_loader.property('asynchronous') is True
                and parent_loader.parentItem().objectName() == 'HblLoader',
                'original asynchronous parent Loader was not used')
        parent_evidence = {'internalObjectName': parent_loader.objectName(),
                           'wrapperObjectName': parent_loader.parentItem().objectName(),
                           'asynchronous': parent_loader.property('asynchronous')}
        wait_for(engine, lambda: evaluate(loader, 'Number(status)') == 3, 'actual dependency error')
        status = evaluate(loader, 'Number(status)')
        require(status == 3 and evaluate(loader, 'item === null'), 'actual Loader did not enter empty Error state')
        require(window.findChild(QQuickItem, 'X2d2MenuExtension') is None, 'failed extension unexpectedly instantiated')
        require(window.findChild(QQuickItem, 'X2d2ExtensionPage') is None, 'failed page survived')
        identity_check = 'screen.viewModel.favoriteModel === stockSource && findItem(screen, "MainScreen_grid").model === stockSource'
        require(evaluate(window, identity_check), 'original model identities changed')
        require(grid.property('count') == 11, 'failed extension changed original model')

        for index in range(11):
            point = json.loads(window.point(index))
            QTest.mouseClick(window, Qt.LeftButton, Qt.NoModifier,
                             QPoint(round(point['x']), round(point['y'])))
            wait_events(20)
        routes = window.property('routes').toVariant()
        require([row['name'] for row in routes] == ['menu' + str(i) for i in range(11)],
                'original touch routing lost or duplicated after dependency failure')
        window.select(0)
        QTest.keyClick(window, Qt.Key_Return)
        wait_events(20)
        routes = window.property('routes').toVariant()
        require(len(routes) == 12 and routes[-1]['name'] == 'menu0', 'original keyboard routing lost')
        for value in (True, False, True, False):
            window.setStockActive(value)
            window.setStockSwipe(value)
            window.setProperty('popup', value)
            wait_events(20)
            require(window.property('inMenu') == value and window.property('swipeBlocked') == value
                    and window.property('listInteractive') != value, 'original bindings stopped updating')
        source.reset(10)
        wait_events(20)
        require(grid.property('count') == 10, 'original source-model updates lost')
        source.reset(11)
        wait_events(20)
        require(grid.property('count') == 11, 'original model reset did not restore eleven entries')

        stable_hits, stable_warnings = interceptor.hits, len(warnings)
        print('PHASE ' + scenario + ': before reload', file=sys.stderr, flush=True)
        # Python 3.11 Windows monotonic uses coarse GetTickCount64 (15.625ms).
        # Use the high-resolution monotonic performance clock for this short
        # observation; a coarse 141ms delta is not proof Qt under-waited.
        observation_start = time.perf_counter()
        while time.perf_counter() - observation_start < 0.150:
            wait_events(10)
        retry_observation = {'requestedMs': 150, 'elapsedMs': (time.perf_counter() - observation_start) * 1000,
                             'clock': 'perf_counter', 'clockResolutionSeconds': time.get_clock_info('perf_counter').resolution,
                             'urlHitsBefore': stable_hits, 'urlHitsAfter': interceptor.hits,
                             'warningsBefore': stable_warnings, 'warningsAfter': len(warnings),
                             'scope': 'no retry observed within measured window only'}
        require((interceptor.hits, len(warnings)) == (stable_hits, stable_warnings), 'spontaneous dependency retry loop')
        window.setScreenActive(False)
        wait_events(20)
        require(window.findChild(QQuickItem, 'MainScreen_root') is None, 'parent did not unload')
        window.setScreenActive(True)
        wait_for(engine, lambda: window.findChild(QQuickItem, 'X2d2MenuBootstrapLoader'), 'failed dependency parent recreation')
        wait_events(20)
        loader = window.findChild(QQuickItem, 'X2d2MenuBootstrapLoader')
        grid = window.findChild(QQuickItem, 'MainScreen_grid')
        wait_for(engine, lambda: loader is not None and evaluate(loader, 'Number(status)') == 3,
                 'recreated dependency error')
        require(loader is not None and grid is not None and evaluate(loader, 'Number(status)') == 3
                and evaluate(loader, 'item === null'), 'recreated screen did not retain actual loader failure')
        require(window.findChild(QQuickItem, 'X2d2MenuExtension') is None and evaluate(window, identity_check),
                'failed objects or replaced models survived reload')
        before_routes = len(window.property('routes').toVariant())
        point = json.loads(window.point(0))
        QTest.mouseClick(window, Qt.LeftButton, Qt.NoModifier, QPoint(round(point['x']), round(point['y'])))
        wait_events(20)
        require(len(window.property('routes').toVariant()) == before_routes + 1, 'recreated original route duplicated or missing')

        # Only the exact dependency failure chain is expected. Unexpected errors
        # in original menu routing, bindings or teardown still invalidate the run.
        leaf_description = 'No such file or directory' if scenario == 'missing-page' else "Expected token `}'"
        allowed = {(bootstrap_url, 'Type X2d2MenuPage unavailable'),
                   (page_url.toString(), leaf_description),
                   (replacement.toString(), leaf_description)}
        unexpected = [row for row in warnings if (row['url'], row['description']) not in allowed]
        require(warnings and any(row['description'] == leaf_description for row in warnings)
                and not unexpected, 'unexpected/missing dependency diagnostics: ' + repr(warnings))
        before_teardown = len(warnings)
        print('PHASE ' + scenario + ': before teardown', file=sys.stderr, flush=True)
        record = {'scenario': scenario, 'compiledCacheHits': cache.hits - hits_before,
                  'injectedUrlHits': interceptor.hits, 'loaderStatus': status,
                  'stockTouchRoutes': 11, 'stockKeyboardRoute': True,
                  'originalBindingsRemainLive': True, 'extensionInstantiated': False,
                  'originalModelIdentitiesPreserved': True, 'parentReloadStockRouteOnce': True,
                  'retryObservation': retry_observation, 'parentLoaderEvidence': parent_evidence,
                  'expectedWarnings': list(warnings), 'unexpectedWarnings': [],
                  'faultFixture': str(bad_page),
                  'faultFixtureSha256': hashlib.sha256(bad_page.read_bytes()).hexdigest() if bad_page.exists() else None}
        window.setScreenActive(False)
        wait_events(20)
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        require(window.findChild(QQuickItem, 'MainScreen_root') is None, 'stock screen survived unload')
        window.close()
        engine.removeUrlInterceptor(interceptor)
        delete(engine)
        require(not isValid(engine) and not isValid(window), 'engine/window teardown incomplete')
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        delete(source)
        delete(interceptor)
        require(not isValid(source) and not isValid(interceptor), 'model/interceptor teardown incomplete')
        require(len(warnings) == before_teardown, 'unexpected teardown warnings: ' + repr(warnings[before_teardown:]))
        cases.append(record)

    cache.close()
    # Both failure-case engines have been synchronously destroyed. Clear their
    # global type-cache references before Python releases borrowed unit bytes.
    qmlClearTypeRegistrations()
    QResource.unregisterResource(str(PROJECT / 'build/host/keys.rcc'))
    delete(app)
    faulthandler.cancel_dump_traceback_later()
    require(not isValid(app), 'application teardown incomplete')
    report = {'result': 'EXECUTED_PENDING_PROCESS_EXIT', 'cases': cases,
              'scope': 'actual-compiled-loader-dependency-failure-desktop-only',
              'completeQtTeardown': True, 'qmlTypeRegistrationsCleared': True,
              'cameraAccesses': 0, 'installable': False,
              'incubationPolicy': 'Existing native Qt controller advances in 5ms slices; native QTest event waits release the GIL on the same thread; asynchronous Loader remains enabled. External supervisor enforces hard timeout.',
              'unitPair': pair, 'originalStockResources': fixture['preserved'],
              'substitutes': fixture['substitutes'], 'qtRuntimeFiles': runtime['runtime_files'],
              'extensionSha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                  for p in sorted((PROJECT / 'qml').glob('*.qml'))},
              'limitations': ['Windows bytecode fallback, not ARM64 AOT',
                              'MainMenu, ControlDrawer, model, key codes and image provider are substitutes',
                              'No device rendering, capture or live recovery proof']}
    write_output(run / 'observations.json', (json.dumps(report, indent=2) + '\n').encode())
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
