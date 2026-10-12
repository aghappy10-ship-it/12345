import QtQuick
import QtQml.Models

// Adapted from the pinned MIT reference; see THIRD_PARTY_NOTICES.txt.
// Original FavoriteModel stays untouched. Only our unresolved row is appended.
DelegateModel {
    id: root
    objectName: "X2d2MenuModel"
    property var sourceModel: null
    property Component stockDelegate: null
    property bool supportedLayout: true
    property bool extensionEnabled: true
    property string extensionLabel: "扩展"
    property string extensionIcon: "image://svg/ic_menu_general"
    readonly property string extensionName: "x2diiMenuExtension"
    readonly property int stockGridCapacity: 12
    property bool ready: false
    property bool reconciling: false
    property bool extensionPresent: false
    property int extensionIndex: -1
    property int originalCount: 0
    property string rejectionReason: "not-ready"
    model: sourceModel
    delegate: stockDelegate

    function itemEnabled(ix) {
        if (ix < 0 || ix >= items.count || !sourceModel)
            return false
        var entry = items.get(ix)
        if (entry.isUnresolved)
            return extensionPresent && extensionEnabled
                && ix === extensionIndex && entry.model.menuName === extensionName
        // Preserve source indexing even while a source insertion is being reconciled.
        var sourceIndex = ix
        for (var i = 0; i < ix; ++i)
            if (items.get(i).isUnresolved) sourceIndex--
        return sourceModel.itemEnabled(sourceIndex)
    }

    function requestReconcile() {
        if (ready && !reconciling) Qt.callLater(reconcile)
    }

    function reconcile() {
        if (!ready || reconciling) return
        reconciling = true
        try {
            var tails = []
            var originals = 0
            var names = {}
            var reason = ""
            for (var i = 0; i < items.count; ++i) {
                var entry = items.get(i)
                var data = entry.model
                if (entry.isUnresolved) {
                    if (data.menuName === extensionName) tails.push(i)
                    else reason = "foreign-unresolved-row"
                } else {
                    originals++
                    if (data.menuName === extensionName) reason = "reserved-name-collision"
                    else if (typeof data.menuName !== "string" || !data.menuName.length
                             || typeof data.label !== "string"
                             || typeof data.labelContext !== "string"
                             || typeof data.iconSrc !== "string"
                             || typeof data.itemEnabled !== "boolean") reason = "source-role-contract"
                    else if (names["key:" + data.menuName]) reason = "duplicate-source-name"
                    names["key:" + data.menuName] = true
                }
            }
            originalCount = originals
            if (sourceModel === null) reason = "no-source"
            else if (!supportedLayout) reason = "unsupported-layout"
            else if (originals < 1) reason = "empty-source"
            else if (originals >= stockGridCapacity) reason = "stock-grid-full"
            if (tails.length > 1) reason = "duplicate-extension"
            if (reason !== "") {
                for (var j = tails.length - 1; j >= 0; --j) items.remove(tails[j], 1)
                extensionPresent = false
                extensionIndex = -1
            } else {
                if (tails.length === 0) {
                    items.insert(items.count, {
                        label: extensionLabel, labelContext: "X2d2MenuExtension",
                        iconSrc: extensionIcon, itemEnabled: extensionEnabled,
                        menuName: extensionName
                    })
                } else {
                    var tail = tails[0]
                    if (tail !== items.count - 1) items.move(tail, items.count - 1, 1)
                    var item = items.get(items.count - 1).model
                    item.label = extensionLabel
                    item.iconSrc = extensionIcon
                    item.itemEnabled = extensionEnabled
                }
                extensionIndex = items.count - 1
                extensionPresent = true
            }
            rejectionReason = reason
        } finally { reconciling = false }
    }

    items.onChanged: requestReconcile()
    property Connections sourceChanges: Connections {
        target: root.sourceModel
        ignoreUnknownSignals: true
        function onDataChanged() { root.requestReconcile() }
        function onModelReset() { root.requestReconcile() }
        function onRowsInserted() { root.requestReconcile() }
        function onRowsRemoved() { root.requestReconcile() }
        function onRowsMoved() { root.requestReconcile() }
        function onLayoutChanged() { root.requestReconcile() }
    }
    onSourceModelChanged: requestReconcile()
    onSupportedLayoutChanged: requestReconcile()
    onExtensionEnabledChanged: requestReconcile()
    onExtensionLabelChanged: requestReconcile()
    onExtensionIconChanged: requestReconcile()
    Component.onCompleted: { ready = true; requestReconcile() }
}
