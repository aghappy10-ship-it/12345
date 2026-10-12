import QtQuick
import QtQuick.Window
import "../../build/host/stock/mainmenu" as Stock
import "../../build/host/stock/components" as StockComponents

Window {
    id: window
    width: 1024; height: 768; visible: true
    property var routes: []
    property alias mediaBusy: vm.mediaProcessing
    property alias activeError: vm.activeError
    property alias evf: vm.screenEVF
    property alias inMenu: vm.inMenu
    property alias swipeBlocked: vm.preventSwipe
    property alias listInteractive: list.interactive
    property alias mainState: drawer.mainState
    property alias viewState: drawer.mainViewState
    property alias drawerAtTop: drawer.drawerAtTop
    property alias drawerSwiping: drawer.swiping
    property alias listMoving: list.moving
    property alias listIndex: list.currentIndex
    property alias exposing: control.exposing
    property alias popup: control.popupActive
    property alias stockState: menu.state
    property alias loaded: drawer.mainScreenLoaded
    readonly property var screen: screenLoader.item
    property var screenObject: screen
    property alias menuObject: menu
    function closeMenu() { vm.closeMenu() }
    function exitMenu() { drawer.mainMenuExited() }
    function select(index) { var grid = findItem(screen, "MainScreen_grid"); grid.highlightIndex(index); screen.forceActiveFocus() }
    function go(name, sub, openItem, shortcut) { screen.loadSubMenuItem(name, sub, openItem, shortcut) }
    function setStockActive(value) { findItem(menu,"menu_loader").active = value }
    function setStockSwipe(value) { findItem(menu,"MainMenu_swipeArea").preventSwipe = value }
    function setExtensionActive(value) { findItem(screen,"X2d2MenuBootstrapLoader").active = value }
    function setScreenActive(value) { screenLoader.active = value }
    function focusInStock() {
        var item = activeFocusItem
        while (item) { if (item === screen) return true; item = item.parent }
        return false
    }
    function findItem(item, name) {
        if (item.objectName === name) return item
        for (var i=0; i<item.children.length; ++i) {
            var result = findItem(item.children[i], name)
            if (result) return result
        }
        return null
    }
    function point(index) {
        var item = findItem(screen, "MainScreen_grid").itemAtIndex(index)
        var pos = item.mapToItem(contentItem, item.width/2, 40)
        return JSON.stringify({x:pos.x,y:pos.y})
    }
    function snapshotBindings() { return JSON.stringify({inMenu:vm.inMenu,preventSwipe:vm.preventSwipe,interactive:list.interactive}) }
    // Boundary substitutes for surviving stock popup/error focus owners,
    // outside both the real compiled screen and the injected extension.
    function releaseExternalFocus(role) {
        var owner = role === "popup" ? popupFocusOwner : errorFocusOwner
        owner.focus = false
        owner.visible = false
        if (role === "popup") control.popupActive = false
        else vm.activeError = false
    }
    Item {
        id: popupFocusOwner
        objectName: "FixturePopupFocusOwner"
        visible: false
        width: 1; height: 1
        property int receivedKeys: 0
        Keys.onPressed: (event) => {
            if (event.key === Qt.Key_Return) { receivedKeys++; event.accepted = true }
            else event.accepted = false
        }
    }
    Item {
        id: errorFocusOwner
        objectName: "FixtureErrorFocusOwner"
        visible: false
        width: 1; height: 1
        property int receivedKeys: 0
        Keys.onPressed: (event) => {
            if (event.key === Qt.Key_Return) { receivedKeys++; event.accepted = true }
            else event.accepted = false
        }
    }
    Item {
        id: drawer
        objectName: "ControlDrawer_root"
        anchors.fill: parent
        property string mainState: "main_menu"
        property string mainViewState: "main_menu"
        property bool drawerAtTop: false
        property bool swiping: false
        property bool mainScreenLoaded: false
        readonly property int mainScreenIx: 1
        property alias controlScreenViewModel: control
        signal mainMenuExited()
        QtObject { id: control; property bool exposing:false; property bool popupActive:false }
        Item {
            id: list; objectName:"ControlDrawer_list"
            property bool moving:false
            property int currentIndex:1
            property bool blockSwipe: control.popupActive || vm.screenEVF || control.exposing || drawer.swiping || drawer.state === "main_menu"
            property bool interactive:!blockSwipe
        }
        Stock.MainMenuViewModel { id:vm; favoriteModel:stockSource }
        Stock.MainMenu {
            id:menu
            viewModel:vm
            onStockRequested: (name, sub, openItem, shortcut) => {
                window.routes.push({name:name,sub:sub,openItem:openItem,shortcut:shortcut})
            }
        }
        StockComponents.HblLoader {
            id:screenLoader
            anchors.fill:parent
            active: true
            asynchronous: true
            verbose: false
            arguments: ({"viewModel": vm, "mainMenu": menu})
            source: Qt.resolvedUrl("../../build/host/stock/mainmenu/MainScreen.qml")
            onLoaded: {
                item.loadSubMenuItem.connect(menu.loadSubmenu)
                drawer.mainScreenLoaded = true
            }
        }
    }
}
