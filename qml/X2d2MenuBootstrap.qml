import QtQuick
import com.hasselblad.keys
import "qrc:/qt/qml/app/qml/scripts/Keys.js" as MKeys

// Exact II contract: MainScreen signal -> ControlDrawer's MainMenu.loadSubmenu.
// See THIRD_PARTY_NOTICES.txt. No replacement of camera or menu property objects.
FocusScope {
    id: root
    objectName: "X2d2MenuExtension"
    anchors.fill: parent
    z: 20
    visible: showing
    enabled: showing
    focus: showing
    property var screen: null
    property var screenLoader: null
    property var menu: null
    property var drawer: null
    property var grid: null
    property var originalLoader: null
    property var originalSwipe: null
    property var drawerList: null
    property var originalModel: null
    property Component originalDelegate: null
    property var extensionButton: null
    property bool attached: false
    property bool open: false
    property bool restoring: false
    property bool routeConnected: false
    property bool stockRouteRemoved: false
    property bool focusRestorePending: false
    property bool autoAttach: true
    property int attachAttempts: 0
    property string attachmentState: "not-ready"
    property bool extensionRowConfirmed: false
    property int menuReportSequence: 0
    property string reportedMenuState: ""
    property string lastMenuReceipt: ""
    property bool menuReportExhausted: false
    readonly property bool menuActive: attached && screen && menu && drawer && drawerList
        && drawer.mainState === "main_menu" && drawer.mainViewState === "main_menu"
        && !drawer.drawerAtTop && !drawer.swiping && !drawerList.moving
        && drawerList.currentIndex === drawer.mainScreenIx && drawer.state === ""
    readonly property bool blocked: !menuActive || !adapter.extensionPresent
        || !adapter.extensionEnabled || screen.viewModel.mediaProcessing
        || screen.viewModel.activeError || drawer.controlScreenViewModel.exposing
        || drawer.controlScreenViewModel.popupActive || originalLoader.active
        || menu.state === "menu"
    readonly property bool showing: attached && open && !blocked
    readonly property int extensionIndex: adapter.extensionIndex
    readonly property bool entryModelMatched: attached && grid && grid.model === adapter
        && grid.count === adapter.items.count
    readonly property bool entryReady: entryModelMatched && routeConnected && stockRouteRemoved
        && extensionRowConfirmed && extensionButton !== null
    // Instantiation, visibility and eligibility are observations, not proof of
    // a click, focus, physical rendering or successful stock photo storage.
    readonly property bool entryVisible: entryReady && menuActive && !showing
        && grid.visible && extensionButton.visible
    readonly property bool entryEligible: entryVisible && !blocked && extensionButton.selectable

    function findItem(item, name) {
        if (!item) return null
        if (item.objectName === name) return item
        for (var i=0; i<item.children.length; ++i) {
            var found = findItem(item.children[i], name)
            if (found) return found
        }
        return null
    }

    function attach() {
        if (attached || restoring || !autoAttach) return
        attachAttempts++
        if (!screen || !screenLoader || screenLoader.status !== Loader.Ready
                || !screen.mainMenu || !screen.viewModel) return
        menu = screen.mainMenu
        drawer = menu.parent
        if (!drawer || drawer.objectName !== "ControlDrawer_root"
                || !drawer.mainScreenLoaded || !drawer.controlScreenViewModel) return
        grid = findItem(screen, "MainScreen_grid")
        originalLoader = findItem(menu, "menu_loader")
        originalSwipe = findItem(menu, "MainMenu_swipeArea")
        drawerList = findItem(drawer, "ControlDrawer_list")
        if (!grid || !originalLoader || !originalSwipe || !drawerList
                || grid.numRows !== 3 || grid.numCols !== 4
                || typeof menu.loadSubmenu !== "function") return
        originalModel = screen.viewModel.favoriteModel
        originalDelegate = grid.delegate
        if (!originalModel || typeof originalModel.itemEnabled !== "function" || !originalDelegate) return
        adapter.sourceModel = originalModel
        adapter.stockDelegate = originalDelegate
        adapter.reconcile()
        if (!adapter.extensionPresent) {
            attachmentState = adapter.rejectionReason
            return
        }
        try {
            screen.loadSubMenuItem.disconnect(menu.loadSubmenu)
            stockRouteRemoved = true
            screen.loadSubMenuItem.connect(dispatch)
            routeConnected = true
            parent = drawer
            attached = true
            attachmentState = "attached"
            Qt.callLater(refreshExtensionButton)
        } catch (error) {
            // Restore the exact original named route if an attachment step fails.
            attached = false
            if (detach()) attachmentState = "attach-failed"
            autoAttach = false
            console.warn("X2DII_MENU_ATTACH_FAILED", error)
        }
    }

    function dispatch(name, sub, openItem, shortcut) {
        if (name !== adapter.extensionName) {
            dismiss()
            menu.loadSubmenu(name, sub, openItem, shortcut)
            return false
        }
        // Never send our name to the native stock menu-name lookup.
        if (!blocked && !open) {
            open = true
            page.forceActiveFocus()
        }
        return true
    }

    function restoreFocusIfNeeded() {
        if (focusRestorePending && menuActive && screen && !screen.viewModel.activeError
                && !drawer.controlScreenViewModel.popupActive && !drawer.controlScreenViewModel.exposing) {
            screen.forceActiveFocus()
            focusRestorePending = false
        }
    }
    function dismiss() {
        if (open) focusRestorePending = true
        open = false
        restoreFocusIfNeeded()
    }
    function back() {
        dismiss()
    }
    function refreshExtensionButton() {
        extensionRowConfirmed = false
        extensionButton = null
        if (entryModelMatched && adapter.extensionPresent && adapter.extensionIndex >= 0
                && adapter.extensionIndex < grid.count && grid.count <= adapter.stockGridCapacity) {
            var row = adapter.items.get(adapter.extensionIndex)
            extensionRowConfirmed = row.isUnresolved && row.model.menuName === adapter.extensionName
            if (extensionRowConfirmed)
                extensionButton = findItem(grid.itemAtIndex(adapter.extensionIndex), "FramedItem_root")
        }
        Qt.callLater(reportMenuState)
    }
    function reportMenuState() {
        var state = [entryReady ? 1 : 0, entryModelMatched ? 1 : 0,
                     extensionButton !== null ? 1 : 0, entryVisible ? 1 : 0,
                     entryEligible ? 1 : 0, attached && grid ? grid.count : -1,
                     attached ? adapter.extensionIndex : -1].join(":")
        if (state === reportedMenuState || menuReportExhausted) return
        if (menuReportSequence >= 256) {
            menuReportExhausted = true
            lastMenuReceipt = "OVERFLOW"
            console.info("X2DII_MENU_STATE_V1:OVERFLOW")
            return
        }
        reportedMenuState = state
        menuReportSequence++
        lastMenuReceipt = menuReportSequence + ":" + state
        console.info("X2DII_MENU_STATE_V1:" + lastMenuReceipt)
    }
    function detach() {
        autoAttach = false
        if (restoring) return false
        restoring = true
        var cleanupComplete = true
        try {
            try { dismiss() }
            catch (dismissError) {
                cleanupComplete = false
                open = false
                console.warn("X2DII_MENU_DISMISS_FAILED", dismissError)
            }
            // Release saved stock bindings before any signal operation can fail.
            attached = false
            // QQuickItemView drops its own delegate when a DelegateModel becomes
            // the model. Restore the original literal Component, not a new binding.
            try { if (grid && originalDelegate) grid.delegate = originalDelegate }
            catch (delegateError) {
                cleanupComplete = false
                console.warn("X2DII_MENU_DELEGATE_RESTORE_FAILED", delegateError)
            }
            // Destruction calls cleanup only once. Retry each unresolved native
            // operation once here, without yielding into a dying QML context.
            var releaseAttempts = 0
            while (routeConnected && screen && releaseAttempts < 2) {
                releaseAttempts++
                try {
                    screen.loadSubMenuItem.disconnect(dispatch)
                    routeConnected = false
                } catch (disconnectError) {
                    console.warn("X2DII_MENU_ROUTE_RELEASE_FAILED", disconnectError)
                }
            }
            // A still-live dispatch already forwards stock requests. Adding the
            // stock connection alongside it would deliver every request twice.
            var restoreAttempts = 0
            while (!routeConnected && stockRouteRemoved && screen && menu && restoreAttempts < 2) {
                restoreAttempts++
                try {
                    screen.loadSubMenuItem.connect(menu.loadSubmenu)
                    stockRouteRemoved = false
                } catch (routeError) {
                    console.warn("X2DII_MENU_STOCK_ROUTE_RESTORE_FAILED", routeError)
                }
            }
            extensionButton = null
            extensionRowConfirmed = false
            cleanupComplete = cleanupComplete && !routeConnected && !stockRouteRemoved
            attachmentState = cleanupComplete ? "detached" : "detach-pending"
            // A queued callback may never run during Loader destruction.
            reportMenuState()
            return cleanupComplete
        } finally { restoring = false }
    }
    onBlockedChanged: { if (blocked) dismiss(); else restoreFocusIfNeeded() }
    onMenuActiveChanged: { if (!menuActive) dismiss() }
    onEntryReadyChanged: Qt.callLater(reportMenuState)
    onEntryVisibleChanged: Qt.callLater(reportMenuState)
    onEntryEligibleChanged: Qt.callLater(reportMenuState)
    onEntryModelMatchedChanged: Qt.callLater(refreshExtensionButton)

    // Qt owns and restores the *original* bindings, including their original
    // QML context. Recreating them in this unloadable extension would leave
    // dead bindings after the Loader is destroyed. FavoriteModel is not changed.
    Binding {
        target: root.grid; property: "model"; value: adapter
        when: root.attached; restoreMode: Binding.RestoreBindingOrValue
    }
    Binding {
        target: root.screen ? root.screen.viewModel : null
        property: "inMenu"; value: root.originalLoader ? root.originalLoader.active || root.showing : false
        when: root.attached; restoreMode: Binding.RestoreBindingOrValue
    }
    Binding {
        target: root.screen ? root.screen.viewModel : null
        property: "preventSwipe"; value: root.originalSwipe ? root.originalSwipe.preventSwipe || root.showing : false
        when: root.attached; restoreMode: Binding.RestoreBindingOrValue
    }
    Binding {
        target: root.drawerList; property: "interactive"
        value: root.drawerList ? !root.drawerList.blockSwipe && !root.showing : false
        when: root.attached; restoreMode: Binding.RestoreBindingOrValue
    }

    X2d2MenuModel {
        id: adapter
        supportedLayout: root.screen !== null && !root.screen.viewModel.sparseFavoritesGrid
        onExtensionPresentChanged: {
            Qt.callLater(root.refreshExtensionButton)
            if (extensionPresent && !root.attached && root.autoAttach) Qt.callLater(root.attach)
        }
        onExtensionIndexChanged: Qt.callLater(root.refreshExtensionButton)
    }
    Connections {
        target: root.screenLoader
        function onLoaded() { Qt.callLater(root.attach) }
    }
    Connections {
        target: root.extensionButton
        function onPressed() {
            // An unresolved DelegateModel row has no original index. Preserve the
            // original pressed/highlight logic but correct its displayed position.
            if (root.attached && adapter.extensionPresent && root.extensionButton.selectable)
                root.grid.highlightIndex(adapter.extensionIndex)
        }
    }
    Connections { target: root.grid; function onCountChanged() { Qt.callLater(root.refreshExtensionButton) } }
    Connections {
        target: root.grid ? root.grid.contentItem : null
        function onChildrenChanged() { Qt.callLater(root.refreshExtensionButton) }
    }
    Connections { target: root.drawer; function onMainMenuExited() { root.dismiss() } }
    Connections {
        target: root.drawer
        function onMainScreenLoadedChanged() { Qt.callLater(root.attach) }
    }
    Connections {
        target: root.screen ? root.screen.viewModel : null
        function onCloseMenu() { root.dismiss() }
    }
    X2d2MenuPage {
        id: page
        anchors.fill: parent
        showing: root.showing
        onBackRequested: root.back()
    }
    // Respect original EVF touch block even though this page overlays the drawer.
    MouseArea {
        anchors.fill: parent
        enabled: root.showing && root.screen.viewModel.screenEVF
        onPressed: (mouse) => { mouse.accepted = true }
    }
    Keys.onPressed: (event) => {
        if (showing && MKeys.pressedFnListAcc([KeyFn.Escape, KeyFn.JstkEscape, KeyFn.Menu], event)) back()
        else if (showing && MKeys.pressedFnListAcc([KeyFn.NavKey, KeyFn.Square, KeyFn.Cross], event)) {}
        else event.accepted = false
    }
    Component.onCompleted: {
        screen = parent ? parent.parent : null
        screenLoader = screen ? screen.parent : null
        reportMenuState()
        Qt.callLater(attach)
    }
    Component.onDestruction: detach()
}
