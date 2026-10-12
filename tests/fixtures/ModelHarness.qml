import QtQuick
import QtQuick.Window
import "../../qml"

Window {
    id: root
    width: 1024
    height: 768
    visible: true
    property bool supported: true
    property bool extensionEnabled: true
    property alias hasExtension: adapter.extensionPresent
    property alias rejection: adapter.rejectionReason
    property alias extensionIndex: adapter.extensionIndex
    property alias displayedCount: grid.count
    property var clicked: []
    function snapshot() {
        var rows = []
        for (var i=0; i<adapter.items.count; ++i) {
            var entry = adapter.items.get(i)
            rows.push({name:entry.model.menuName, label:entry.model.label,
                       enabled:entry.model.itemEnabled, selectable:adapter.itemEnabled(i)})
        }
        return JSON.stringify(rows)
    }
    X2d2MenuModel {
        id: adapter
        sourceModel: stockSource
        supportedLayout: root.supported
        extensionEnabled: root.extensionEnabled
        stockDelegate: Component {
            Rectangle {
                width: 256; height: 192
                color: "black"
                Text { anchors.centerIn: parent; text: model.label ?? ""; color: "white" }
                MouseArea {
                    anchors.fill: parent
                    enabled: model.itemEnabled
                    onClicked: root.clicked.push(model.menuName)
                }
            }
        }
    }
    GridView { id: grid; anchors.fill: parent; model: adapter; cellWidth:256; cellHeight:192 }
}
