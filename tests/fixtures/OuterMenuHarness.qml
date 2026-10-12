import QtQuick
import QtQuick.Window
import com.hasselblad.menumodel
import "stock/mainmenu" as Stock
import "stock/controlscreen" as Control

Window {
    id: window
    width: 1024; height: 768; visible: true
    property alias drawerObject: drawer
    property alias viewModelObject: vm
    property alias controlModelObject: control
    signal lifecycle(string component)
    function findItem(item, name) {
        if (!item) return null
        if (item.objectName === name) return item
        for (var i=0; i<item.children.length; ++i) {
            var found = findItem(item.children[i], name)
            if (found) return found
        }
        return null
    }
    function showMain() {
        setOuterState("main_menu")
        drawer.forceActiveFocus()
    }
    function setOuterState(value) {
        drawer.mainState = value
        drawer.drawerState = value
        drawer.mainViewState = value
    }
    function point(index) {
        var grid = findItem(drawer, "MainScreen_grid")
        var item = grid.itemAtIndex(index)
        var pos = item.mapToItem(contentItem, item.width/2, 40)
        return JSON.stringify({x:pos.x,y:pos.y})
    }
    function focusInStock() {
        var screen = findItem(drawer, "MainScreen_root")
        var item = activeFocusItem
        while (item) { if (item === screen) return true; item = item.parent }
        return false
    }
    function counters() {
        return JSON.stringify({rw:SubMenu.rwCount,file:SubMenu.fileCount,close:SubMenu.closeCount,
                               names:SubMenu.names,leafOpen:vm.leafOpenCount,leafClose:vm.leafCloseCount})
    }
    function menuData() {
        return JSON.stringify({name:vm.menu.menuName,file:vm.menu.file,sub:vm.menu.scrollToItem,
                               shortcut:vm.menu.fromShortcut,openItem:vm.menu.openItem})
    }
    function shortcut(name, sub, openItem) { vm.loadMenu(name, sub, openItem) }
    function deferLeafLoaded(value) { vm.holdLeafLoaded = value }
    function completeLeaf() { findItem(drawer, "HostSubMenuLeaf").loaded() }
    function setExtensionActive(value) { findItem(drawer, "X2d2MenuBootstrapLoader").active = value }
    function bootstrapSnapshot() {
        var loader = findItem(drawer, "X2d2MenuBootstrapLoader")
        return JSON.stringify({status:Number(loader.status),nullItem:loader.item === null})
    }
    function modelIsOriginal() {
        var screen = findItem(drawer, "MainScreen_root")
        return screen.viewModel.favoriteModel === stockSource && findItem(screen, "MainScreen_grid").model === stockSource
    }
    function swipeSnapshot() {
        var swipe = findItem(drawer, "MainMenu_swipeArea")
        var loader = findItem(drawer, "menu_loader")
        return JSON.stringify({dragActive:swipe.drag.active,pressed:swipe.pressed,
                               x:loader.x,show:swipe.show,active:loader.active,state:swipe.state})
    }
    function setLeafPreventSwipe(value) { findItem(drawer, "HostSubMenuLeaf").preventSwipe = value }
    function snapshotBindings() {
        var swipe = findItem(drawer, "MainMenu_swipeArea")
        return JSON.stringify({inMenu:vm.inMenu,preventSwipe:vm.preventSwipe,
                               swipePrevent:swipe.preventSwipe,swipeEnabled:swipe.enabled,
                               interactive:findItem(drawer, "ControlDrawer_list").interactive})
    }
    function setPopup(value) { control.popupActive = value }
    function setDrawerSwiping(value) { drawer.swiping = value; vm.swipingDrawer = value }
    function setDrawerAtTop(value) { drawer.drawerAtTop = value }
    function drawerSnapshot() {
        var list = findItem(drawer, "ControlDrawer_list")
        return JSON.stringify({state:drawer.state,index:list.currentIndex,interactive:list.interactive,
                               mainState:drawer.mainState,viewState:drawer.mainViewState,
                               allowWritingIndicator:control.allowWritingIndicator,resetCount:control.resetCount})
    }
    function focusInControl() {
        var screen = findItem(drawer, "HostControlScreen")
        var item = activeFocusItem
        while (item) { if (item === screen) return true; item = item.parent }
        return false
    }
    function requestClose() { vm.closeMenu() }
    Stock.MainMenuViewModel {
        id:vm; favoriteModel:stockSource
        Component.onDestruction: window.lifecycle("menu-view-model")
    }
    Control.ControlScreenViewModel {
        id:control
        Component.onDestruction: window.lifecycle("control-view-model")
        onMainStateRequested: (value) => { drawer.mainState = value }
        onDrawerStateRequested: (value) => {
            drawer.drawerState = value
            drawer.mainViewState = value
        }
    }
    Control.ControlDrawer {
        id:drawer
        anchors.fill: parent
        mainMenuViewModel: vm
        controlScreenViewModel: control
        Component.onDestruction: window.lifecycle("control-drawer")
    }
}
