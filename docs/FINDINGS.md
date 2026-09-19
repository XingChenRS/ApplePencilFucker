# appencil 取证与分析记录

设备：iPad Pro 11" (M2) `iPad14,3`，iPadOS **16.1 (20B82)**，Dopamine 越狱（rootless，`/var/jb`，ellekit + libhooker）。
目标：让 Apple Pencil 1（Lightning）在 USB-C iPad Pro 上可用，且断连后无需"忽略设备"再重配。

本文件记录已经**确认**的证据（全部来自设备本体，只读取证）。

---

## 1. 取证工具链（本次搭建，可复用）

| 脚本 | 作用 |
|---|---|
| `scripts/dev.py` | SSH 到 iPad（普通用户登录后 sudo 提权；主机/账号/口令走环境变量，不入库）、`pull` / `pull-tree` / `push`。注意 iOS 无 `/bin/sh`，脚本自动用 `/var/jb/bin/sh`；sudo 会重置 PATH，故用绝对路径。 |
| `scripts/pull_dsc.py` | 拉取整份 dyld 共享缓存（45 个分片 + `.symbols`，约 3.1 GB）。 |
| `scripts/dsc_extract.py` | **零依赖提取器**：从分片缓存里还原任意 dylib 为可分析的 Mach-O（`list` / `extract` / `info`）。 |
| `scripts/objc_walk.py` | 解析 Mach-O 里的 ObjC 元数据（类/方法/实现地址），含 iOS 16 的相对方法列表与 chained fixup 指针解码。 |
| `scripts/dsc_symbols.py` | 解析 `.symbols` 旁挂符号表：**地址 → 符号名**（含 ObjC 方法名），整个缓存可用。 |
| `idamcp.py`（用户提供） | 驱动 IDA 9.3 idalib MCP，静态分析上述产物。 |

提取器要点（踩过的坑，供后续复用）：
- 缓存**明文**，位于 `/System/Cryptexes/OS/System/Library/Caches/com.apple.dyld/`；镜像按 **4 KB** 对齐；新格式里 `dylibsImageArray` 字段为 0，改为扫描 `mach_header_64` + `LC_ID_DYLIB` 恢复镜像表。
- `__LINKEDIT` 是所有 dylib **共享**的一大段（本例 312 MB），必须按 LC 引用范围搬移并改写各表偏移，不能整段复制。
- 段的 `fileoff` 与**节**的 `offset` 都要重写，否则 ObjC 元数据读不出来。
- 指针是 chained fixup：普通形式低 43 位是绝对地址；**带认证**（ptrauth）形式低 32 位是"缓存基址 0x180000000 起算的偏移"。提取时已把指针拍平成普通地址，IDA 可直接跟引用。

---

## 2. 决定性发现

### 2.0 【决定性】插线时的"配件不受支持"来自 accessoryd 的型号白名单

用户插上铅笔时看到的"配件不受支持"，由
`/System/Library/PrivateFrameworks/CoreAccessories.framework/Support/accessoryd` 发出
（该二进制内含 `Accessory Not Supported` / `This accessory is not supported by this device.` /
`Displaying accessory not supported dialog...`）。

判定函数（accessoryd `0x1000700CC`，反编译自设备固件）：

```c
// 混淆键可用社区公式还原：obfs(name) = base64(md5("MGCopyAnswer"+name))  去掉 "="
// 实测 "yhHcB0iH0d1XzPO/CFd3ow" == DeviceSupportsApplePencil
BOOL isApplePencilGen1Supported(void) {
    if ( !MGGetBoolAnswer(CFSTR("yhHcB0iH0d1XzPO/CFd3ow")) )   // DeviceSupportsApplePencil
        return NO;
    CFStringRef model = MGCopyAnswer(CFSTR("ProductType"));
    return MGGetBoolAnswer(CFSTR("DeviceSupports9Pin"))         // 9 针 Lightning 能力
        || CFStringCompare(model, CFSTR("iPad13,18"), 0) == 0   // iPad 10 Wi-Fi
        || CFStringCompare(model, CFSTR("iPad13,19"), 0) == 0;  // iPad 10 Cellular
}
```

`iPad13,18 / iPad13,19` 是 accessoryd 里**仅有的两个型号标识**——就是官方唯一支持
Pencil 1 转接头的 iPad 10。iPad14,3（M2 Pro，USB-C，无 9 针）自然不在其中。

调用点：`sub_10014E36C`（日志串 `iAP2BLEPairing _startFeatureFromDevice`，行号 864）：

```c
// accessoryModel 来自 iAP2 识别结果，"A1603" 正是 Apple Pencil 1 的型号号
if ( CFStringCompare(accessoryModel, CFSTR("A1603"), 0) != 0 || isApplePencilGen1Supported() )
    sub_100059F2C(...);            // ← 开始带外配对（下发链路密钥）
else if ( <弹窗开关> )
    /* 弹 "iap2_pairing_not_supported" —— 用户看到的那句 */;
```

日志串 `"%s:%d model %@, isApplePencilGen1Supported %d"`（`0x1001fa2fb`）可直接用于验证。

**两个 MobileGestalt 键在 accessoryd 全文中各只出现 1 次**（即只服务于这段判定），
因此"在 accessoryd 进程内让这两个键返回 true"是精确且低风险的改法 —— 见 `tweak/`。

**为什么不能直接改 MG 缓存**：本机 MG 缓存
（`systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist`）
的 `CacheExtra` 里共 53 个混淆键，实测：

| 键 | 是否在缓存 |
|---|---|
| `DeviceSupportsApplePencil`（`yhHcB0iH0d1XzPO/CFd3ow`） | **不在**（运行时/硬件派生） |
| `DeviceSupports9Pin`（`qWGVjnlN/wWMhlWgfNcSBg`） | **不在**（运行时/硬件派生） |
| `ProductType`（`h9jDsbgj7xIVeIQ8S3/X3Q`） | 在（但我们并不需要改型号） |

两个判定键都不落盘，只能运行时干预；且 MG 是进程内库，凭证式钩子天然按进程生效 —— 钩在
accessoryd 里既有效、影响面又最小（全局改会让所有进程都以为这台机器有 9 针 Lightning 口）。

### 2.1 Pencil 1 是 BLE 设备



bluetoothd 内的埋点字符串：`IsApplePencilConnected`、**`NumberOfAppleLEPencilPairedDeviceCount`**、`NumberOfAppleLEPencilSessionPerDay`（"LE Pencil"）。
这解释了为何"蓝牙调试 App"能配上它（BLE 配对，配对码 1234）。

### 2.2 Settings 里的"不兼容"是**有意**的硬编码判定

调用链（BluetoothSettings.bundle，已从缓存提取，地址为缓存地址）：

```
-[BTSDevicesController tableView:accessoryButtonTappedForRowWithIndexPath:]   0x209803D2C
    └─ +[CBUtil isDeviceSupportedWithType:VIDsrc:VID:PID:]                    0x1a6d3240C   (CoreBluetooth)
           └─ +[CBUtil isDeviceSupportedOnWatchOSWithType:VIDsrc:VID:PID:]    0x1a6d32374
```

反编译后的逻辑（CoreBluetooth `CBUtil`）：

```objc
+ (BOOL)isDeviceSupportedOnWatchOSWithType:(int)type VIDsrc:… VID:… PID:… {
    if (type == 25) return NO;                       // ← 直接判"不支持"
    if (type != 24 || !<内部检查(pid)>) return YES;   // ← 其它类型一律支持
    return <内部查表>;
}
```

对应 UI 文案（`BluetoothSettings.bundle/Devices.loctable`）：

| key | 英文 | 中文 |
|---|---|---|
| `CANNOT_CONNECT_UNSUPPORTED_DEVICE_TITLE` | Incompatible Device | 不兼容的设备 |
| `CANNOT_CONNECT_UNSUPPORTED_DEVICE_MESSAGE` | This device is not currently supported | 此设备当前不受支持 |
| `ERROR_MISSING_LINK_KEY` | "%@ can no longer connect to … **Forget this device and pair it again.**" | 无法连接…请忽略此设备后重新配对 |
| `PLUG_IN_APPLE_PENCIL` | **Plug in Apple Pencil to use it with this iPad.** | 插接 Apple Pencil 以在此 iPad 上使用 |
| `ATTACH_APPLE_PENCIL` | Attach Apple Pencil to use it with this iPad. | 吸附 Apple Pencil… |

其中 `ERROR_MISSING_LINK_KEY` 正是用户遇到的"每次断连都要忽略设备重新配对"；`PLUG_IN_APPLE_PENCIL` 说明官方路径要求**插线**配对。铅笔专用的弹窗由 `-[BTSDevicesController showPencilConnectionAttemptAlert:]`（0x209805E04）呈现，参数 `<=1` 时用 `ATTACH_…`，否则 `PLUG_IN_…`。

> 结论：苹果在 **UI 层面明确拒绝**通过"设置里点一下"来连接该铅笔（type==25 直接 NO），而不是功能不可用。

### 2.3 官方配对机制是"带外（OOB）配对"

CoreAccessories 内的实现（`AccessoryOOBBTPairing` / 插件 `OOBBTPairing-iOS.feature`）：

```
-[ACCOOBBTPairingProvider accessoryOOBBTPairingAttached:accInfoDict:]
-[ACCOOBBTPairingProvider accessoryOOBBTPairingBTAccessoryInfo:oobBtPairingUID:accessoryMacAddr:deviceClass:]
-[ACCOOBBTPairingProvider accessoryOOBBTPairingCompletionStatus:oobBtPairingUID:accessoryMacAddr:result:]
```

即：附件通过**有线链路**（Lightning，或 iPad 10 的 USB-C↔Lightning 转接头）把 BT 地址/链路密钥交给 iPad，之后铅笔用这把密钥直接连 BLE。这是"必须插上去配对"的原因，也说明**密钥是可通过带外通道建立并持久化的**。

bluetoothd 侧对应能力（字符串证据）：
`BTAccessoryManagerGetLinkKey`、`kCBMsgIdAccessoryGenerateLinkKeyMsg`、`kCBMsgIdAccessorySetLinkKeyExMsg`、`kCBArgLinkKey`、
`Generate linkkey to pair between "%s" and "%s"`、`Seeing if paired device Link Key already exists for iohid ref %p`、
`Failed to write link key data for device %{public}s to keychain with result %d`（**密钥写 keychain**）、
`link key request: retrieving stored key for %:`、`OI_LinkKeyStorage_*`。

### 2.4 参与配对的进程/框架清单（已提取，`analysis/out/`）

- `bluetoothd`（`/usr/sbin/bluetoothd`，9.2 MB，C++/CSR Synergy 血统 + 少量 ObjC）
- `BluetoothManager`（`-[BluetoothDevice isServiceSupported:]` 等客户端策略）
- `MobileBluetooth`、`BluetoothServices(UI)`
- `BluetoothSettings`（设置面板逻辑，含上述门禁）
- `PencilPairingUI`（`PNP*` 配对向导：`PNPPencilView`、`PNPChargingStatusViewController`…）
- `CoreAccessories` + 插件 `OOBBTPairing-iOS` / `BLEPairing-iOS` / `Platform-Bluetooth` / `HID`
- `CoreBluetooth`（`CBUtil` 门禁）

---

## 3. 已确认 / 待确认

已确认（2026-09-20，用户实测）：
- **配对成功后铅笔功能完全正常**（书写、压感等），说明输入通路在 iPad Pro M2 上本来就通——问题只在配对与密钥持久化。
- 插上转接头时 accessoryd 直接弹"配件不受支持"，并跳过带外配对（见 2.0）。

待确认：
1. 解除 accessoryd 门禁后，带外（iAP2BLEPairing）流程能否完整跑通；铅笔是否从此自动重连。
2. accessoryd 内 `OOBBTPairing linkKeyInfo: … oobBtPairing2, not supported` 那条分支是否构成第二道门。
3. type==25 对应的设备类型枚举名（仅影响设置页 UI 路径）。

---

## 4. 方案与进度

**方案**：插件注入 `accessoryd`，只让 `isApplePencilGen1Supported()` 用到的两个 MobileGestalt 键
（`yhHcB0iH0d1XzPO/CFd3ow`、`DeviceSupports9Pin`）返回 true。这两个键在 accessoryd 内各只出现一次，
即只影响这一处判定。此后 accessoryd 会走 `iAP2BLEPairing _startFeatureFromDevice` →
`sub_100059F2C`（带外配对，把链路密钥写入 keychain）。

代码与构建见 [`tweak/`](../tweak/)（Theos rootless 工程 + GitHub Actions 工作流）。

后续按需处理：
- 若带外流程仍被拒 → 查 accessoryd 的 `oobBtPairing2` 分支。
- 若希望设置页也能直接点连/断 → 再处理 `+[CBUtil isDeviceSupportedWithType:…]`（type==25）。

---

## 5. 关键地址速查

| 对象 | 地址 |
|---|---|
| `-[BTSDevicesController showPencilConnectionAttemptAlert:]` | `0x209805E04` |
| `-[BTSDevicesController tableView:accessoryButtonTappedForRowWithIndexPath:]` | `0x209803D2C` |
| `+[CBUtil isDeviceSupportedWithType:VIDsrc:VID:PID:]` | `0x1a6d3240C` |
| `+[CBUtil isDeviceSupportedOnWatchOSWithType:VIDsrc:VID:PID:]` | `0x1a6d32374` |
| `-[BTSDeviceLE isApplePencil:]` | `0x20980aa84` |
| `-[BTSDeviceClassic isApplePencil:]` | `0x20980a488` |
| 选择符 `isApplePencil:` | `0x209812026` |
| CFString `PLUG_IN_APPLE_PENCIL` | `0x2153b7340` |
| CFString `CANNOT_CONNECT_UNSUPPORTED_DEVICE_TITLE` | `0x2153b7140` |
| accessoryd `isApplePencilGen1Supported()` | `0x1000700CC` |
| accessoryd `iAP2BLEPairing _startFeatureFromDevice`（调用点） | `0x10014E36C` |
| accessoryd 弹窗函数（"Displaying accessory not supported dialog"） | `0x1001308D8` |
| accessoryd 日志串 `model %@, isApplePencilGen1Supported %d` | `0x1001fa2fb` |
