# 参考来源

## 主要实现参考

[dash8097/Hasselblad-Feature-Extensions](https://github.com/dash8097/Hasselblad-Feature-Extensions)

本地既有研究固定提交：`9f6c9baffeaf30ac805905f8052973f60b11acf6`。历史上机记录参考提交：`dc517d8ba8ea10dfb6e1a1535cd7525a6088c061`。本次整理没有检查远端是否更新。

学习的核心是独立原生加载器、compiled-QML Loader、原厂模型 / 点击路由接入、开机加载与撤回，不是重写整个CIM。对方X2D记录不等于我们已在X2D II复现；菜单和模型扩展不等于AF算法已提升。

相关适配部分的MIT声明保留在仓库根部 `THIRD_PARTY_NOTICES.txt`。本仓库没有重新授权原厂代码或第三方安装器。

## 开发工作台设计参考

[derrickyau9/Hasselblad-X-System-QEMU-DevKit](https://github.com/derrickyau9/Hasselblad-X-System-QEMU-DevKit)

既有参考提交：`d82dc3b0faa6456c260378df6352a07f929caed2`。学习原厂UI、输入、日志与工作区的可视化组织。当前工具使用桌面Qt，不是QEMU，也不模拟真实拍摄、ISP、镜头或SSD。没有复制其AGPL源码或固件材料。

## 用户提供的其他研究线索

- [radium-wang/Hasselblad-X-System-CIM-Firmware-Research-Feature-Extensions](https://github.com/radium-wang/Hasselblad-X-System-CIM-Firmware-Research-Feature-Extensions)
- [WeiCheng97/Hasselblad-X2d-series-5g-unlock](https://github.com/WeiCheng97/Hasselblad-X2d-series-5g-unlock)
- [derrickyau9/Hasselblad-X2DII-ADB-Enable](https://github.com/derrickyau9/Hasselblad-X2DII-ADB-Enable)

这些链接保留为研究来源，不代表本次重新读取、已适配或已验证。不能把Wi-Fi解锁、ADB开启、菜单扩展与CIM验签绕过等不同工作合并称为“全部固件破解”。
