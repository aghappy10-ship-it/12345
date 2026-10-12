"""Separate host envelope preserving nineteen original menu resources."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path

try:
    from . import prepare_host_fixture as base
    from .output_guard import guard_output, output_directory, write_output
except ImportError:
    import prepare_host_fixture as base
    from output_guard import guard_output, output_directory, write_output

ROOT = Path(__file__).resolve().parents[1]
ADDITIONAL = ["mainmenu/" + name + ".qml" for name in
              ("MainMenu", "MenuSwipe", "MenuBase", "SubMenuBase", "MenuData")] + [
                  "controlscreen/ControlDrawer.qml", "components/HblListView.qml", "components/PageIndicator.qml"]
FILES = [*base.FILES, *ADDITIONAL]


def substitutes(out):
    prefix = (out / "stock").as_uri() + "/"
    constants = base.STUBS["imports/com/hasselblad/constants/Constants.qml"].replace(
        ' property color mainBackgroundColor:',
        ' property string appPrefix: ' + json.dumps(prefix) + '\n'
        ' property real cameraViewRightMargin: 16\n'
        ' property int menuSwipeDuration: 80\n'
        ' property real swipeLengthDividor: 3\n'
        ' property color mainBackgroundColor:')
    return {
        "imports/com/hasselblad/constants/Constants.qml": constants,
        "imports/com/hasselblad/menumodel/qmldir": "module com.hasselblad.menumodel\nsingleton SubMenu 1.0 SubMenu.qml\n",
        "imports/com/hasselblad/menumodel/SubMenu.qml": '''pragma Singleton
import QtQuick
import com.hasselblad.constants
QtObject {
 property int rwCount: 0
 property int fileCount: 0
 property int closeCount: 0
 property var names: []
 signal menuChanged()
 function known(name) { return /^menu([0-9]|10)$/.test(name) }
 function menuRw(name) { rwCount++; names.push(name); return known(name) }
 function menuFile(name) { fileCount++; return known(name) ? Constants.appPrefix + "mainmenu/HostLeaf.qml" : "" }
 function closeMenu(level) { closeCount++ }
}
''',
        "stock/mainmenu/MainMenuViewModel.qml": '''import QtQuick
Item {
 property var favoriteModel: null
 property bool sparseFavoritesGrid: false
 property bool screenEVF: false
 property bool mediaProcessing: false
 property bool activeError: false
 property bool inMenu: false
 property bool preventSwipe: false
 property bool swipingDrawer: false
 property bool debugTouch: false
 property bool keepStateOnExit: false
 property string errorReturnState: ""
 property int blockedCount: 0
 property int leafOpenCount: 0
 property int leafCloseCount: 0
 property int popupCloseCount: 0
 property bool holdLeafLoaded: false
 property alias menu: data
 MenuData { id: data }
 signal closeMenu()
 signal loadMenu(string menuName, string menuItem, bool openItem)
 function showMenuBlockedProcessingImages() { blockedCount++ }
}
''',
        "stock/mainmenu/HostLeaf.qml": '''import QtQuick
SubMenuBase {
 objectName: "HostSubMenuLeaf"
 property MainMenuViewModel viewModel: null
 function openTopMenu() { viewModel.leafOpenCount++; if (!viewModel.holdLeafLoaded) loaded() }
 function closeSubMenus() { viewModel.leafCloseCount++ }
 function closePopup() { viewModel.popupCloseCount++ }
}
''',
        "stock/controlscreen/ControlScreenViewModel.qml": '''import QtQuick
Item {
 property bool popupActive: false
 property bool screenEVF: false
 property bool exposing: false
 property bool allowWritingIndicator: false
 property bool flashReady: false
 property bool flashCharging: false
 property bool batteryStatusValid: false
 property bool batteryWarning: false
 property bool batteryLevelCritical: false
 property bool charging: false
 property int batteryLevel: 0
 property bool showTemperatureWarning: false
 property int connectedHosts: 0
 property bool usbSuperSpeed: false
 property int resetCount: 0
 signal mainStateRequested(string value)
 signal drawerStateRequested(string value)
 function setMainState(value) { resetCount++; mainStateRequested(value) }
 function toggle_drawer_state(value) { drawerStateRequested(value) }
}
''',
        "stock/controlscreen/ControlScreen.qml": '''import QtQuick
FocusScope {
 objectName: "HostControlScreen"
 // Original ControlScreen root declares focus:true; content stays substituted.
 focus: true
 property ControlScreenViewModel viewModel: null
 function resetState() { viewModel.setMainState("") }
}
''',
        "stock/controlscreen/StatusRow.qml": '''import QtQuick
Item {
 height: 40
 property bool alwaysShowBattery: false
 property bool showUsb: false
 property bool flashReady: false
 property bool flashCharging: false
 property bool batteryStatusValid: false
 property bool batteryWarning: false
 property bool batteryLevelCritical: false
 property bool charging: false
 property int batteryLevel: 0
 property bool showBatteryLevelText: false
 property bool showTemperatureWarning: false
 property int connectedHosts: 0
 property bool usbSuperSpeed: false
}
''',
    }


def prepare(out, extracted=ROOT / "build/stock-qml"):
    out = guard_output(Path(out), must_be_new=True)
    manifest = json.loads((extracted / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("schema") != 1 or manifest.get("gui_sha256") != base.GUI_SHA256 or manifest.get("qt_version") != "6.8.2":
        raise ValueError("outer fixture extracted identity mismatch")
    official, _ = base.collect(base.STOCK.read_bytes())
    original = {}
    for name in FILES:
        resource = "qt/qml/app/qml/" + name
        raw = (extracted / resource).read_bytes()
        if raw != official[resource] or hashlib.sha256(raw).hexdigest() != manifest["files"][resource]["sha256"]:
            raise ValueError("outer resource differs from pinned official GUI: " + name)
        original[name] = raw
    # Reuse only the unchanged small fixture builder with a fresh separate out;
    # the pre-existing build/host tree and its passing fixture stay untouched.
    initial = base.prepare(extracted, out)
    for name in ADDITIONAL:
        write_output(out / "stock" / name, original[name])
    generated = substitutes(out)
    for name, source in generated.items():
        write_output(out / name, source.encode())
    write_output(out / "OuterMenuHarness.qml", (ROOT / "tests/fixtures/OuterMenuHarness.qml").read_bytes())
    declared = dict(initial["substitutes"])
    declared.pop("stock/mainmenu/MainMenu.qml")
    declared.update({name: hashlib.sha256(source.encode()).hexdigest() for name, source in generated.items()})
    result = {"originalGuiSha256": base.GUI_SHA256, "preserved": {name: hashlib.sha256(raw).hexdigest() for name, raw in original.items()},
              "substitutes": declared, "verifiedAgainstPinnedElf": True, "cameraAccesses": 0, "installable": False,
              "rccSha256": initial["rccSha256"], "hostSwipeParameters": {"menuSwipeDurationMs": 80, "swipeLengthDividor": 3},
              "scope": "original outer QML states; native models, leaf contents, ControlScreen and services substituted"}
    write_output(out / "fixture-manifest.json", (json.dumps(result, indent=2) + "\n").encode())
    return result
