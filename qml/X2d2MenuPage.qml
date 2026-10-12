import QtQuick

// First release is a menu-integration feature, not a new capture pipeline.
// No camera properties, file IO, network or capture commands are used here.
FocusScope {
    id: root
    objectName: "X2d2ExtensionPage"
    property bool showing: false
    visible: showing
    enabled: showing
    focus: showing
    signal backRequested()

    Rectangle { anchors.fill: parent; color: "#171717" }
    // Consume page background touch; never let it trigger a hidden stock row.
    MouseArea { anchors.fill: parent; onPressed: (mouse) => { mouse.accepted = true } }
    Text {
        anchors.horizontalCenter: parent.horizontalCenter
        y: parent.height * 0.13
        text: "扩展"
        color: "white"
        font.pixelSize: Math.max(24, parent.height * 0.055)
    }
    Text {
        anchors.centerIn: parent
        width: parent.width * 0.78
        text: "菜单扩展已加载\n\n拍摄仍使用原厂功能"
        color: "#dedede"
        font.pixelSize: Math.max(18, parent.height * 0.036)
        horizontalAlignment: Text.AlignHCenter
        wrapMode: Text.WordWrap
    }
    Rectangle {
        objectName: "X2d2ExtensionBack"
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.bottom: parent.bottom
        anchors.bottomMargin: parent.height * 0.10
        width: parent.width * 0.30
        height: parent.height * 0.12
        radius: 6
        color: backArea.pressed ? "#666666" : "#393939"
        Text { anchors.centerIn: parent; text: "返回"; color: "white"; font.pixelSize: parent.height * 0.38 }
        MouseArea { id: backArea; anchors.fill: parent; onClicked: root.backRequested() }
    }
}
