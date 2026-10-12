"""Prepare small local-only fixtures; preserve actual II MainScreen/grid/key resources."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from xml.sax.saxutils import escape
try:
    from .output_guard import guard_output, output_directory, write_output
    from .extract_qml import collect, STOCK, GUI_SHA256
except ImportError:
    from output_guard import guard_output, output_directory, write_output
    from extract_qml import collect, STOCK, GUI_SHA256

PROJECT = Path(__file__).resolve().parents[1]
QT_ROOT = PROJECT.parent / 'x2d2/work/reverse/vendor/qt_host_6_8_2/PySide6'
FILES = ['mainmenu/MainScreen.qml', 'components/Background.qml', 'components/HblLoader.qml',
         'components/CustomGridView.qml', 'components/BounceGridView.qml',
         'components/ViewHelper.qml', 'components/GridNavigation.qml',
         'components/ScaledImage.qml', 'components/buttons/FramedImage.qml',
         'components/buttons/FramedItem.qml', 'scripts/Keys.js']
STUBS = {
    'imports/com/hasselblad/menumodel/qmldir': 'module com.hasselblad.menumodel\nUnused 1.0 Unused.qml\n',
    'imports/com/hasselblad/menumodel/Unused.qml': 'import QtQuick\nQtObject {}\n',
    'imports/com/hasselblad/constants/qmldir': 'module com.hasselblad.constants\nsingleton Constants 1.0 Constants.qml\n',
    'imports/com/hasselblad/constants/Constants.qml': '''pragma Singleton
import QtQuick
QtObject {
 property color mainBackgroundColor: "black"
 property color popupTextColor: "white"
 property color colorWhite: "white"
 property color highlightColor: "red"
 property color framedItemOutlineColor: "white"
 property real framedItemBorderwidth: 2
 property string latinFont: "Arial"
 property int wheelTimeoutTimeMs: 3000
 property real svgScaleFactor: 1.6
}
''',
    'imports/com/hasselblad/keys/qmldir': 'module com.hasselblad.keys\nsingleton KeyFn 1.0 KeyFn.qml\n',
    'imports/com/hasselblad/keys/KeyFn.qml': '''pragma Singleton
import QtQuick
QtObject {
 enum Function { Square, Afd, Select, NavKey, Cross, Ael, JstkUp, JstkDown, Left, Up, Right, Down, Escape, JstkEscape, Menu }
 function isFn(key, modifiers, fn) {
   var keys = [Qt.Key_F1,Qt.Key_F2,Qt.Key_Return,Qt.Key_F3,Qt.Key_F4,Qt.Key_F5,
               Qt.Key_Up,Qt.Key_Down,Qt.Key_Left,Qt.Key_PageUp,Qt.Key_Right,Qt.Key_PageDown,
               Qt.Key_Escape,Qt.Key_Back,Qt.Key_Menu]
   return key === keys[fn]
 }
}
''',
    'stock/mainmenu/MainMenuViewModel.qml': '''import QtQuick
Item {
 property var favoriteModel:null
 property bool sparseFavoritesGrid:false
 property bool screenEVF:false
 property bool mediaProcessing:false
 property bool activeError:false
 property bool inMenu:false
 property bool preventSwipe:false
 signal closeMenu()
}
''',
    'stock/mainmenu/MainMenu.qml': '''import QtQuick
Item {
 property var viewModel:null
 signal stockRequested(string name,string sub,bool openItem,bool shortcut)
 function loadSubmenu(name,sub,openItem,shortcut) { stockRequested(name,sub,openItem,shortcut) }
 Item { id:loader; objectName:"menu_loader"; property bool active:false }
 Item { id:swipe; objectName:"MainMenu_swipeArea"; property bool preventSwipe:false }
 Component.onCompleted: {
   viewModel.inMenu = Qt.binding(function() { return loader.active })
   viewModel.preventSwipe = Qt.binding(function() { return swipe.preventSwipe })
 }
}
''',
    'stock/components/UiImage.qml': '''import QtQuick
Item {
 property url source
 property size sourceSize:Qt.size(160,102)
 property bool asynchronous:false
 property bool stretch:false
 width:160; height:102
}
''',
}


def prepare(extracted: Path = PROJECT / 'build/stock-qml', out: Path = PROJECT / 'build/host'):
    manifest = json.loads((extracted / 'manifest.json').read_text(encoding='utf-8'))
    if (manifest.get('schema') != 1 or manifest.get('gui_sha256') != GUI_SHA256
            or manifest.get('qt_version') != '6.8.2'):
        raise ValueError('extracted resource manifest identity mismatch')
    # A self-consistent editable manifest is not an authority. Re-read the
    # hash-pinned GUI and compare the resources used by this exact harness.
    official_files, _ = collect(STOCK.read_bytes())
    guard_output(out)
    preserved, substitutes = {}, {}
    outputs = {}
    for name in FILES:
        resource = 'qt/qml/app/qml/' + name
        data = (extracted / resource).read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if data != official_files[resource] or digest != manifest['files'][resource]['sha256']:
            raise ValueError('stock resource differs from pinned official GUI: ' + name)
        preserved[name] = digest
        outputs['stock/' + name] = data
    for name, source in STUBS.items():
        outputs[name] = source.encode('utf-8')
        substitutes[name] = hashlib.sha256(outputs[name]).hexdigest()
    qrc = '<RCC><qresource prefix="/qt/qml/app/qml/scripts"><file alias="Keys.js">' + escape(str(out / 'stock/scripts/Keys.js')) + '</file></qresource></RCC>'
    outputs['keys.qrc'] = qrc.encode('utf-8')
    final_names = set(outputs) | {'keys.rcc', 'fixture-manifest.json'}
    for name in final_names:
        target = guard_output(out / name)
        if target.exists() and not target.is_file():
            raise ValueError('fixture file target is not a regular file: ' + str(target))
    for directory in ('stock', 'imports'):
        base = out / directory
        guard_output(base)
        if base.exists():
            for path in base.rglob('*'):
                guard_output(path)
                if path.is_file() and path.relative_to(out).as_posix() not in final_names:
                    raise ValueError('unexpected fixture source/import: ' + str(path))
    # rcc only writes to a fresh staging directory. No fixture changes until
    # compilation succeeds, so a compiler failure cannot leave mixed inputs.
    stage_root = output_directory(PROJECT / 'build/rcc-staging')
    stage = Path(tempfile.mkdtemp(prefix='run-', dir=stage_root))
    write_output(stage / 'Keys.js', outputs['stock/scripts/Keys.js'])
    stage_qrc = '<RCC><qresource prefix="/qt/qml/app/qml/scripts"><file alias="Keys.js">Keys.js</file></qresource></RCC>'
    write_output(stage / 'keys.qrc', stage_qrc.encode('utf-8'))
    command = [str(QT_ROOT / 'rcc.exe'), '--binary', '--format-version', '1', '--no-compress', str(stage / 'keys.qrc'), '-o', str(stage / 'keys.rcc')]
    subprocess.run(command, check=True, timeout=30)
    outputs['keys.rcc'] = (stage / 'keys.rcc').read_bytes()
    if outputs['keys.rcc'][:4] != b'qres': raise ValueError('rcc did not produce a binary resource')
    result = {'originalGuiSha256': manifest['gui_sha256'], 'preserved': preserved, 'substitutes': substitutes,
              'rccSha256': hashlib.sha256(outputs['keys.rcc']).hexdigest(), 'rccCommand': command,
              'verifiedAgainstPinnedElf': True,
              'cameraAccesses': 0, 'notVisualOrHardwareVerification': True}
    outputs['fixture-manifest.json'] = (json.dumps(result, indent=2) + '\n').encode('utf-8')
    for name in outputs: guard_output(out / name)
    for name, data in outputs.items(): write_output(out / name, data)
    return result


if __name__ == '__main__': print(json.dumps(prepare(), indent=2))
