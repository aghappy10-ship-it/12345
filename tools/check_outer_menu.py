"""Execute original outer menu/drawer QML with explicitly limited host services."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]

if __name__ == "__main__" and "--child" not in sys.argv:
    from qt_supervisor import supervise_worker
    from qt_readiness import runtime_inputs
    from prepare_outer_menu_fixture import FILES
    inputs = [ROOT / name for name in (
        "tools/prepare_outer_menu_fixture.py", "tools/prepare_host_fixture.py", "tools/check_menu_model.py",
        "tools/host_cache.py", "tools/qt_readiness.py", "tools/build_host_bridge.py", "tools/menu_inputs.py",
        "tools/qt_unit.py", "tools/build_unit.py", "tools/extract_qml.py", "src/host_cache_bridge.c",
        "build/host-bridge/native/host_cache_bridge.dll", "build/host-bridge/native/BUILD.json",
        "build/stock-qml/manifest.json", "build/units/main-screen-bootstrap-host.bin",
        "build/units/main-screen-bootstrap-device.bin", "tests/fixtures/OuterMenuHarness.qml")]
    inputs.extend(ROOT / "build/stock-qml/qt/qml/app/qml" / name for name in FILES)
    inputs.extend(sorted((ROOT / "qml").glob("*.qml")))
    report = supervise_worker(Path(__file__), "outer-menu-validation.json", "outer-menu-runs", timeout=70,
                              input_paths=inputs, input_provider=runtime_inputs)
    print(json.dumps({key: report.get(key) for key in ("result", "failure", "runDirectory", "workerExitCode", "error")}))
    raise SystemExit(0 if report["result"] == "PASS" else 1)

from check_menu_model import SourceModel, QGuiApplication, QQmlApplicationEngine, QTest, Qt, QPoint, QUrl, require
os.environ.pop("QML_DISABLE_DISK_CACHE", None)
from host_cache import HostCache, prepare_host
from prepare_outer_menu_fixture import prepare
from menu_inputs import verify_current_pair
from qt_readiness import wait_for, wait_events
from output_guard import write_output


def main():
    import faulthandler
    faulthandler.enable()
    faulthandler.dump_traceback_later(15, repeat=True)
    from PySide6.QtCore import QResource, QCoreApplication, QEvent
    import ctypes
    from PySide6.QtQuick import QQuickWindow
    from PySide6.QtQml import QQmlAbstractUrlInterceptor
    from shiboken6 import delete, isValid
    run = Path(sys.argv[sys.argv.index("--child") + 1])
    scenario = os.environ.get("X2DII_OUTER_MENU_SCENARIO", "normal")
    require(scenario in ("normal", "stock-control", "unload-control", "missing-page", "malformed-page"), "unknown outer-menu scenario")
    print("SCENARIO " + scenario, file=sys.stderr, flush=True)
    out = run / "fixture"
    fixture = prepare(out)
    pair = verify_current_pair()
    runtime = prepare_host(run / "runtime")
    app = QGuiApplication([])
    require(QResource.registerResource(str(out / "keys.rcc")), "key resource registration failed")
    unit = ROOT / "build/units/main-screen-bootstrap-host.bin"
    expected_unit_hash = pair["host"]["candidateUnitSha256"]
    if scenario == "stock-control":
        from menu_inputs import GUI
        from qt_unit import read_main_screen, MAIN_SHA256
        unit = run / "original-main-screen.bin"
        write_output(unit, read_main_screen(GUI))
        expected_unit_hash = MAIN_SHA256
    url = (out / "stock/mainmenu/MainScreen.qml").as_uri()
    cache = HostCache(unit, url, run / "runtime", expected_sha256=expected_unit_hash)
    source = SourceModel()
    engine = QQmlApplicationEngine()
    interceptor = None
    allowed_warnings = set()
    dependency_failure = None
    if scenario in ("missing-page", "malformed-page"):
        page_url = QUrl.fromLocalFile(str(ROOT / "qml/X2d2MenuPage.qml"))
        bad_page = run / (scenario + "-X2d2MenuPage.qml")
        require(not bad_page.exists(), "fault fixture path unexpectedly exists")
        if scenario == "malformed-page":
            write_output(bad_page, b"import QtQuick\nItem {\n")
        leaf_description = "No such file or directory" if scenario == "missing-page" else "Expected token `}'"
        replacement = QUrl.fromLocalFile(str(bad_page))
        class PageFault(QQmlAbstractUrlInterceptor):
            def __init__(self):
                super().__init__()
                self.hits = 0
            def intercept(self, path, kind):
                if kind == self.DataType.QmlFile and path == page_url:
                    self.hits += 1
                    return replacement
                return path
        interceptor = PageFault()
        engine.addUrlInterceptor(interceptor)
        allowed_warnings = {(QUrl.fromLocalFile(str(ROOT / "qml/X2d2MenuBootstrap.qml")).toString(), "Type X2d2MenuPage unavailable"),
                            (page_url.toString(), leaf_description),
                            (replacement.toString(), leaf_description)}
    engine.addImportPath(str(out / "imports"))
    engine.rootContext().setContextProperty("stockSource", source)
    warnings = []
    engine.warnings.connect(lambda rows: warnings.extend({"url": row.url().toString(), "description": row.description(),
                                                          "line": row.line()} for row in rows))
    def assert_warnings(label):
        unexpected = [row for row in warnings if (row["url"], row["description"]) not in allowed_warnings]
        require(not unexpected, label + ": " + repr(unexpected))
    engine.load(QUrl.fromLocalFile(str(out / "OuterMenuHarness.qml")))
    require(bool(engine.rootObjects()), "outer fixture failed: " + repr(warnings))
    window = engine.rootObjects()[0]
    require(isinstance(window, QQuickWindow), "QtQuick root wrapper type was not registered")
    lifetimes = []
    def record_lifecycle(name):
        lifetimes.append(name)
        print("DESTROY " + name, file=sys.stderr, flush=True)
    window.lifecycle.connect(record_lifecycle)
    def visual_items():
        pending = [window.contentItem()]
        while pending:
            item = pending.pop()
            yield item
            pending.extend(item.childItems())
    def find(name):
        return next((item for item in visual_items() if item.objectName() == name), None)
    drawer = find("ControlDrawer_root")
    wait_for(engine, lambda: drawer.property("controlScreenLoaded") and drawer.property("mainScreenLoaded"),
             "real ControlDrawer async delegate loaded signals")
    extension = None
    if scenario in ("normal", "unload-control"):
        wait_for(engine, lambda: find("X2d2MenuExtension"), "unchanged compiled candidate extension")
        extension = find("X2d2MenuExtension")
        wait_for(engine, lambda: extension.property("attached"), "extension attachment to actual outer menu")
    elif interceptor is not None:
        wait_for(engine, lambda: find("X2d2MenuBootstrapLoader"), "failed extension's actual injected Loader")
        wait_for(engine, lambda: json.loads(window.bootstrapSnapshot())["status"] == 3, "actual dependency Loader.Error")
        state = json.loads(window.bootstrapSnapshot())
        require(state["nullItem"] and find("X2d2MenuExtension") is None and interceptor.hits > 0
                and window.modelIsOriginal(), "dependency failure replaced original models or instantiated extension")
        require(any(row["description"] == leaf_description for row in warnings), "missing exact dependency diagnostic")
        dependency_failure = {"loaderStatus": state["status"], "nullItem": state["nullItem"],
                              "urlHits": interceptor.hits, "faultPath": str(bad_page),
                              "faultSha256": hashlib.sha256(bad_page.read_bytes()).hexdigest() if bad_page.exists() else None}
    require(cache.hits > 0, "new actual MainScreen URL did not use the unchanged compiled unit")
    window.showMain()
    grid = find("MainScreen_grid")
    menu = find("MainMenu_root")
    loader = find("menu_loader")
    swipe = find("MainMenu_swipeArea")
    listview = find("ControlDrawer_list")
    cover = find("MainMenu_coverScreen")
    require(all(item is not None for item in (grid, menu, loader, swipe, listview, cover)), "original envelope objects missing")
    wait_for(engine, lambda: not listview.property("moving") and listview.property("currentIndex") == 1,
             "original drawer main-screen positioning")
    require(grid.property("count") == (11 if extension is None else 12) and drawer.property("state") == "",
            "expected grid/default drawer state")
    assert_warnings("outer initialization warnings")
    cases = ["original-control-drawer-async-readiness"]
    observations = []

    def counters(): return json.loads(window.counters())
    def click(index):
        position = json.loads(window.point(index))
        QTest.mouseClick(window, Qt.LeftButton, Qt.NoModifier, QPoint(round(position["x"]), round(position["y"])))
        wait_events(20)
    def stock_open(name):
        wait_for(engine, lambda: loader.property("status") == 1 and menu.property("state") == "menu"
                 and loader.x() == 0, "original stock loader ready/in-position")
        require(menu.property("show") and drawer.property("state") == "main_menu", "original menu/drawer show states")
        require((extension is None or not extension.isVisible()) and not listview.property("interactive"), "stock menu overlap/swipe block")
        require(json.loads(window.menuData())["name"] == name and cover.property("opacity") == 0, "original menu data/cover")
        assert_warnings("stock opening warnings")
    def closed(label):
        wait_for(engine, lambda: not loader.property("active") and not menu.property("show")
                 and drawer.property("state") == "", label)
        wait_events(20)
        data = json.loads(window.menuData())
        require(data["name"] == "" and data["file"] == "" and data["shortcut"] is False, "real MenuData was not cleared")
        require(window.focusInStock() and listview.property("interactive"), "real stock focus/list binding not restored")
        assert_warnings("stock return warnings")
    def stock_close():
        QTest.keyClick(window, Qt.Key_Escape)
        closed("original Escape animation and loader deactivation")

    before = counters()
    click(0)
    stock_open("menu0")
    after = counters()
    require(after["rw"] == before["rw"] + 1 and after["file"] == before["file"] + 1
            and after["leafOpen"] == before["leafOpen"] + 1, "original stock route duplicated/missing")
    observations.append({"before": before, "opened": after, "loaderX": loader.x(), "swipeState": swipe.property("state")})
    stock_close()
    require(counters()["close"] > after["close"], "native close seam was not called")
    cases.append("original-stock-route-menu-swipe-escape-return")
    before = counters()
    if extension is not None:
        click(11)
        wait_for(engine, lambda: extension.isVisible(), "extension page entry over actual drawer")
        require(not listview.property("interactive") and not loader.property("active") and drawer.property("state") == "",
                "extension changed original loader/state or left drawer swipe enabled")
        require(counters() == before, "extension name leaked to native menu-name substitute")
        button = find("X2d2ExtensionBack")
        point = button.mapToItem(window.contentItem(), button.width() / 2, button.height() / 2)
        QTest.mouseClick(window, Qt.LeftButton, Qt.NoModifier, QPoint(round(point.x()), round(point.y())))
        wait_for(engine, lambda: not extension.isVisible(), "extension back")
        require(window.focusInStock() and listview.property("interactive"), "extension back did not restore real focus/binding")
        cases.append("extension-back-real-drawer-focus-and-bindings")
    click(0)
    stock_open("menu0")
    require(counters()["rw"] == before["rw"] + 1 and counters()["file"] == before["file"] + 1,
            "stock route duplicated after extension return")
    stock_close()
    cases.append("original-stock-route-after-extension-once" if extension is not None
                 else "original-stock-route-second-open-once")
    window.deferLeafLoaded(True)
    before = counters()
    window.shortcut("menu1", "detail", True)
    wait_for(engine, lambda: loader.property("status") == 1 and loader.x() == 0,
             "shortcut loader ready while host leaf defers completion")
    shortcut_data = json.loads(window.menuData())
    require(shortcut_data["name"] == "menu1" and shortcut_data["sub"] == "detail"
            and shortcut_data["shortcut"] and shortcut_data["openItem"], "original shortcut lost arguments")
    require(cover.property("opacity") == 1 and counters()["leafOpen"] == before["leafOpen"] + 1,
            "shortcut cover was not retained while leaf completion is outstanding")
    shortcut = {"data": shortcut_data, "opacityWhileWaiting": cover.property("opacity")}
    window.completeLeaf()
    wait_for(engine, lambda: cover.property("opacity") == 0, "original loaded signal hides shortcut cover")
    shortcut["opacityAfterLoaded"] = cover.property("opacity")
    stock_open("menu1")
    stock_close()
    window.deferLeafLoaded(False)
    cases.append("original-shortcut-arguments-cover-lifecycle")
    click(2)
    stock_open("menu2")
    trace = []
    QTest.mousePress(window, Qt.LeftButton, Qt.NoModifier, QPoint(100, 400))
    wait_events(10)
    for x in (160, 280, 430, 610, 790):
        QTest.mouseMove(window, QPoint(x, 400))
        wait_events(10)
        trace.append({"pointerX": x, **json.loads(window.swipeSnapshot())})
    require(any(row["dragActive"] for row in trace) and loader.x() > loader.width() / 3,
            "sent pointer events did not execute actual original drag: " + repr(trace))
    pointer_drag = {"trace": trace, "xBeforeRelease": loader.x()}
    QTest.mouseRelease(window, Qt.LeftButton, Qt.NoModifier, QPoint(790, 400))
    closed("original drag release threshold, animation and loader deactivation")
    pointer_drag["activeAfterClose"] = loader.property("active")
    require(loader.property("asynchronous"), "original drag release did not restore asynchronous loader")
    cases.append("original-pointer-drag-close")
    click(3)
    stock_open("menu3")
    window.setLeafPreventSwipe(True)
    wait_events(20)
    blocked = json.loads(window.snapshotBindings())
    require(blocked["inMenu"] and blocked["preventSwipe"] and blocked["swipePrevent"]
            and not blocked["swipeEnabled"], "typed leaf preventSwipe did not propagate through original bindings")
    prevented_trace = []
    QTest.mousePress(window, Qt.LeftButton, Qt.NoModifier, QPoint(100, 400))
    wait_events(10)
    for x in (160, 280, 430, 610, 790):
        QTest.mouseMove(window, QPoint(x, 400))
        wait_events(10)
        prevented_trace.append({"pointerX": x, **json.loads(window.swipeSnapshot())})
    QTest.mouseRelease(window, Qt.LeftButton, Qt.NoModifier, QPoint(790, 400))
    wait_events(100)
    require(not any(row["dragActive"] or row["x"] != 0 for row in prevented_trace)
            and loader.property("active") and loader.x() == 0, "preventSwipe allowed menu drag/close")
    prevent_swipe = {"blocked": blocked, "trace": prevented_trace, "activeAfterRelease": loader.property("active")}
    window.setLeafPreventSwipe(False)
    wait_for(engine, lambda: not json.loads(window.snapshotBindings())["preventSwipe"] and swipe.isEnabled(),
             "original readonly binding observes leaf preventSwipe release")
    stock_close()
    require(not json.loads(window.snapshotBindings())["inMenu"], "original inMenu binding did not observe actual loader close")
    cases.append("original-leaf-prevent-swipe-binding")
    extension_unload = None
    if extension is not None:
        click(11)
        wait_for(engine, lambda: extension.isVisible(), "open extension before direct unload")
        window.setExtensionActive(False)
        wait_for(engine, lambda: find("X2d2MenuExtension") is None and grid.property("count") == 11,
                 "direct extension context destruction restores stock grid")
        extension = None
        require(window.focusInStock(), "direct extension unload lost original focus")
        popup_bindings = []
        for value in (True, False, True, False):
            window.setPopup(value)
            wait_events(20)
            state = json.loads(window.snapshotBindings())
            require(state["interactive"] is not value and not state["inMenu"] and not state["preventSwipe"],
                    "original bindings depended on destroyed extension context")
            popup_bindings.append({"popup": value, **state})
        counts = []
        for count in (10, 11):
            source.reset(count)
            wait_for(engine, lambda: grid.property("count") == count, "original model remains bound after extension unload")
            counts.append(grid.property("count"))
        before = counters()
        click(4)
        stock_open("menu4")
        require(counters()["rw"] == before["rw"] + 1 and counters()["file"] == before["file"] + 1,
                "unload did not restore exactly one original route")
        for value in (True, False, True, False):
            window.setLeafPreventSwipe(value)
            wait_events(20)
            state = json.loads(window.snapshotBindings())
            require(state["inMenu"] and state["preventSwipe"] is value and state["swipeEnabled"] is not value,
                    "original leaf/loader bindings died with extension context")
        stock_close()
        require(not json.loads(window.snapshotBindings())["inMenu"], "restored loader binding stuck after actual close")
        window.setExtensionActive(True)
        wait_for(engine, lambda: find("X2d2MenuExtension"), "recreated extension before whole-tree destruction")
        extension = find("X2d2MenuExtension")
        wait_for(engine, lambda: extension.property("attached") and grid.property("count") == 12,
                 "extension reattachment to existing original outer objects")
        click(11)
        wait_for(engine, lambda: extension.isVisible(), "recreated extension routes successfully")
        QTest.keyClick(window, Qt.Key_Escape)
        wait_for(engine, lambda: not extension.isVisible(), "recreated extension Escape return")
        require(window.focusInStock(), "recreated extension focus restore")
        extension_unload = {"popupBindings": popup_bindings, "sourceCounts": counts, "originalBindingsLive": True,
                            "reattachedBeforeWholeTreeTeardown": True}
        cases.append("extension-unload-original-bindings-remain-live")
    drawer_transitions = None
    if extension is not None:
        click(11)
        wait_for(engine, lambda: extension.isVisible(), "extension open before control-screen transition")
        window.setOuterState("control_screen")
        wait_for(engine, lambda: drawer.property("state") == "control_screen" and not listview.property("moving"),
                 "original drawer control-screen state")
        require(not extension.isVisible() and window.focusInControl(), "control-screen transition lost original focus or extension dismissal")
        drawer_transitions = {"control": json.loads(window.drawerSnapshot()), "controlFocus": window.focusInControl()}
        window.setOuterState("main_menu")
        wait_for(engine, lambda: drawer.property("state") == "" and listview.property("currentIndex") == 1
                 and not listview.property("moving"), "original drawer main-screen return")
        require(window.focusInStock() and not extension.isVisible(), "original main-screen focus or stale extension reopen")
        click(11)
        wait_for(engine, lambda: extension.isVisible(), "extension before outer vertical-swipe input")
        window.setDrawerSwiping(True)
        wait_events(20)
        require(not extension.isVisible() and not listview.property("interactive"), "vertical-swipe input did not block extension/list")
        window.setDrawerSwiping(False)
        wait_events(20)
        require(not extension.isVisible() and listview.property("interactive") and window.focusInStock(),
                "vertical-swipe release left stale extension or lost binding/focus")
        before_top = json.loads(window.drawerSnapshot())
        click(11)
        wait_for(engine, lambda: extension.isVisible(), "extension before drawer-top input")
        window.setDrawerAtTop(True)
        wait_for(engine, lambda: drawer.property("state") == "control_screen", "original drawerClosed resets to control screen")
        at_top = json.loads(window.drawerSnapshot())
        require(not extension.isVisible() and not at_top["allowWritingIndicator"]
                and at_top["resetCount"] == before_top["resetCount"] + 1 and at_top["mainState"] == "",
                "original drawerClosed/service-input or writing-indicator contract")
        window.setDrawerAtTop(False)
        wait_for(engine, lambda: json.loads(window.drawerSnapshot())["allowWritingIndicator"],
                 "original writing indicator binding after drawer returns to bottom")
        drawer_transitions.update(atTop=at_top, atBottomControl=json.loads(window.drawerSnapshot()))
        window.setOuterState("main_menu")
        wait_for(engine, lambda: listview.property("currentIndex") == 1 and not listview.property("moving"),
                 "original main-screen after drawer-top cycle")
        require(window.focusInStock() and not extension.isVisible(), "drawer-top cycle focus or stale extension")
        cases.append("original-drawer-state-focus-and-top-transitions")
    if dependency_failure is not None:
        before_routes = len(counters()["names"])
        for index in range(11):
            before = counters()
            click(index)
            stock_open("menu" + str(index))
            require(counters()["rw"] == before["rw"] + 1 and counters()["file"] == before["file"] + 1,
                    "original outer route lost/duplicated after failed dependency")
            stock_close()
        names = counters()["names"][before_routes:]
        require(names == ["menu" + str(i) for i in range(11)], "failed dependency damaged stock route names/order")
        cases.append("outer-dependency-error-original-eleven-routes")
        for value in (True, False, True, False):
            window.setPopup(value)
            wait_events(20)
            require(json.loads(window.snapshotBindings())["interactive"] is not value,
                    "failed dependency damaged original drawer interaction binding")
        for count in (10, 11):
            source.reset(count)
            wait_for(engine, lambda: grid.property("count") == count, "original model reset after dependency error")
            require(window.modelIsOriginal(), "failed dependency replaced original source/model identity")
        require(json.loads(window.bootstrapSnapshot()) == {"status": 3, "nullItem": True}, "failed Loader state unexpectedly changed")
        dependency_failure.update(stockNames=names, expectedWarnings=list(warnings))
        cases.append("outer-dependency-error-original-bindings")
    assert_warnings("outer lifecycle warnings")
    report = {"result": "EXECUTED_PENDING_PROCESS_EXIT", "cameraAccesses": 0, "installable": False,
              "scope": "original outer QML states on desktop only", "cases": cases, "observations": observations,
              "shortcut": shortcut, "pointerDrag": pointer_drag, "preventSwipe": prevent_swipe, "scenario": scenario,
              "extensionUnload": extension_unload,
              "drawerTransitions": drawer_transitions,
              "dependencyFailure": dependency_failure,
              "cacheHits": cache.hits, "registeredMainScreenUrl": url, "unitPair": pair,
              "hostUnitSha256": hashlib.sha256(unit.read_bytes()).hexdigest(), "originalStockResources": fixture["preserved"],
              "substitutes": fixture["substitutes"], "hostSwipeParameters": fixture["hostSwipeParameters"],
              "qtRuntimeFiles": runtime["runtime_files"], "unexpectedWarnings": [],
              "limitations": ["Windows bytecode execution, not ARM64 AOT", "Native model/SubMenu routing and leaf content are named substitutes",
                              "ControlScreen and status services are geometry/state substitutes; no camera rendering, AF or capture",
                              "Host key mappings, image geometry and swipe timing are not target hardware evidence"]}
    if scenario == "unload-control":
        print("PHASE unload extension", file=sys.stderr, flush=True)
        window.setExtensionActive(False)
        wait_for(engine, lambda: find("X2d2MenuExtension") is None and grid.property("count") == 11,
                 "extension destruction before original owner teardown")
    window.close()
    warning_count_before_teardown = len(warnings)
    print("PHASE teardown engine", file=sys.stderr, flush=True)
    require(cache.unit.data == ctypes.addressof(cache.storage), "registered unit pointer changed")
    memory_unit = ctypes.string_at(cache.unit.data, len(unit.read_bytes()))
    require(hashlib.sha256(memory_unit).hexdigest() == expected_unit_hash, "registered unit memory changed")
    report["registeredUnitMemory"] = {"sha256": hashlib.sha256(memory_unit).hexdigest(),
                                      "dataPointer": hex(cache.unit.data), "pid": os.getpid(),
                                      "flags": int.from_bytes(memory_unit[108:112], "little"),
                                      "qmlUnitOffset": int.from_bytes(memory_unit[244:248], "little")}
    if interceptor is not None:
        engine.removeUrlInterceptor(interceptor)
    delete(engine)
    print("PHASE after teardown engine", file=sys.stderr, flush=True)
    require(not isValid(engine) and not isValid(window), "outer engine/window teardown incomplete")
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    delete(source)
    if interceptor is not None:
        delete(interceptor)
        require(not isValid(interceptor), "fault interceptor teardown incomplete")
    print("PHASE before cache close", file=sys.stderr, flush=True)
    cache.close()
    print("PHASE after cache close", file=sys.stderr, flush=True)
    # Qt's global type cache can retain CompilationUnit references beyond app
    # deletion. Clear only after every engine is destroyed, while StaticData
    # bytes still live. HostCache.close alone deliberately does not do this.
    from PySide6.QtQml import qmlClearTypeRegistrations
    qmlClearTypeRegistrations()
    report["qmlTypeRegistrationsCleared"] = True
    print("PHASE after type registration clear", file=sys.stderr, flush=True)
    QResource.unregisterResource(str(out / "keys.rcc"))
    delete(app)
    print("PHASE after app delete", file=sys.stderr, flush=True)
    require(not isValid(source) and not isValid(app), "outer model/application teardown incomplete")
    assert_warnings("late outer teardown warnings")
    require(len(warnings) == warning_count_before_teardown, "unexpected new teardown warnings")
    faulthandler.cancel_dump_traceback_later()
    report["completeQtTeardown"] = True
    report["lifecycleSignals"] = lifetimes
    write_output(run / "observations.json", (json.dumps(report, indent=2) + "\n").encode())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        import traceback
        traceback.print_exc()
        raise
