# PencilGen1Compat

让 **Apple Pencil 1（Lightning / A1603）** 在苹果未列入白名单的 iPad 上完成**有线带外配对**，
从而拿到一把会持久保存的蓝牙链路密钥（这正是"每次断连都要忽略设备重配"的根因）。

## 状态

已在 iPad Pro 11" (M2) / iPadOS 16.1 上验证：插线不再弹"配件不受支持"，
**铅笔完成配对并连接成功**。

运行时自检（越狱设备上可直接查看）：

```bash
cat /tmp/PencilGen1Compat.loaded     # 插件是否注入到了 accessoryd（内容为 pid）
cat /tmp/PencilGen1Compat.log        # 钩子命中记录（前 32 次调用）
```

## 原理

`accessoryd` 在铅笔插上时执行（`0x1000700CC`）：

```c
BOOL isApplePencilGen1Supported(void) {
    if (!MGGetBoolAnswer("yhHcB0iH0d1XzPO/CFd3ow")) return NO;
    ProductType = MGCopyAnswer("ProductType");
    return MGGetBoolAnswer("DeviceSupports9Pin")     // 9 针 Lightning 能力
        || ProductType == "iPad13,18"                // iPad 10 Wi-Fi
        || ProductType == "iPad13,19";               // iPad 10 Cellular
}
```

型号是 A1603 且该函数返回 NO 时，accessoryd 弹出 "Accessory Not Supported"
并**跳过** `iAP2BLEPairing _startFeatureFromDevice`（`0x10014E36C`）——也就是那条
把链路密钥交给 iPad 的带外配对流程。

本插件只做一件事：在 accessoryd 进程内，对上面那两个 MobileGestalt 键返回 true。
这两个键在整个 accessoryd 里各自**只被读取一次**（就是上面这段判定），所以影响面仅限该判定。

## 构建

- 云端（推荐）：`../.github/workflows/build.yml` 已配好 Theos + 缓存，push 后取 artifact。
- 本地：`make package THEOS_PACKAGE_SCHEME=rootless`（需要 Theos + iOS SDK）。

## 安装与验证

```bash
dpkg -i com.xingchenrs.pencilgen1_0.1.0_iphoneos-arm64.deb
killall -9 accessoryd
```

插上铅笔（转接头）后：

1. 不再出现"配件不受支持"；
2. 观察日志（本机 USB 或设备端）：

```bash
# PC 端（USB）：pymobiledevice3 syslog live --process-name accessoryd
# 或设备端 os_log 落盘后检索
```

期望看到 `PencilGen1Compat: forcing DeviceSupports9Pin -> true`，
随后 accessoryd 走 `iAP2BLEPairing _startFeatureFromDevice` → 开始配对，
铅笔出现在蓝牙设置中且**断连后可自动重连**。

## 卸载 / 回滚

```bash
dpkg -r com.xingchenrs.pencilgen1 && killall -9 accessoryd
```

## 待验证 / 后续

- 若配对流程仍被蓝牙侧拒绝（accessoryd 内另有 `OOBBTPairing … oobBtPairing2, not supported` 分支），
  再针对该分支做第二步。
- 设置页点击铅笔仍可能提示"不兼容的设备"（`+[CBUtil isDeviceSupportedWithType:VIDsrc:VID:PID:]`
  对 `type == 25` 直接返回 NO）。若带外配对已完成，此路径通常不再需要；否则再补一个针对
  `BluetoothSettings`/`CoreBluetooth` 的插件。
