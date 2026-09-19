# PencilGen1Compat

**让初代 Apple Pencil（Lightning / 型号 A1603）在 USB-C 的 iPad 上复活。**

[![build](https://github.com/XingChenRS/ApplePencilFucker/actions/workflows/build.yml/badge.svg)](https://github.com/XingChenRS/ApplePencilFucker/actions/workflows/build.yml)

> English TL;DR — A rootless jailbreak tweak that clears `accessoryd`'s model
> gate so Apple Pencil (1st generation) can complete its wired out-of-band
> pairing on USB-C iPads Apple never listed. Verified on iPad Pro 11" (M2) /
> iPadOS 16.1: the pencil pairs, and the Bluetooth link key persists — after a
> reboot it reconnects without "Forget This Device", even with the jailbreak
> inactive.

---

## 问题

初代 Apple Pencil 是 **BLE** 设备，配对靠一条**有线带外通道**：铅笔插在 iPad 的
Lightning 口（iPad 10 则通过 USB-C 转接头）时，iPadOS 会把蓝牙地址和链路密钥
交给铅笔；此后铅笔用这把密钥直接连 BLE，断连也能自动重连。

USB-C 的 iPad Pro 没有 Lightning 口。苹果的做法不是"功能做不到"，而是在
`accessoryd` 里用机型白名单直接放行或拒绝：

```c
// accessoryd 0x1000700CC
BOOL isApplePencilGen1Supported(void) {
    if (!MGGetBoolAnswer(CFSTR("yhHcB0iH0d1XzPO/CFd3ow")))   // DeviceSupportsApplePencil
        return NO;
    CFStringRef model = MGCopyAnswer(CFSTR("ProductType"));
    return MGGetBoolAnswer(CFSTR("DeviceSupports9Pin"))        // 9 针 Lightning 能力
        || CFEqual(model, CFSTR("iPad13,18"))                  // iPad 10 Wi-Fi
        || CFEqual(model, CFSTR("iPad13,19"));                 // iPad 10 Cellular
}
```

`iPad13,18 / iPad13,19` 是 iPad 10——**官方唯一支持该转接头的机型**。其余 USB-C
iPad 一律返回 NO，随后 accessoryd 弹出"配件不受支持"并**跳过配对流程**，
链路密钥永远不会下发。用户只能靠第三方 BLE 工具手动配对，而那种配对
**不落系统钥匙串** → 每次断连都要"忽略设备"重新配对。

## 效果（本机实测）

| 场景 | 装插件前 | 装插件后 |
|---|---|---|
| 插上铅笔 | 弹"配件不受支持" | 无弹窗，**完成配对** |
| 蓝牙列表 | 需调试 App 手动配对 | 正常出现并连接 |
| 断开之后 | 必须"忽略设备"再重配 | **自动重连** |
| 重启 iPad | 依旧要重配 | **直接连上**，甚至无需重新越狱 |

配对成功后密钥存在系统钥匙串里——这正是"断连就丢"问题的根治点。

## 安装

要求：**rootless 越狱**（Dopamine / palera1n 等 `/var/jb` 布局）+ ElleKit。

```bash
dpkg -i com.xingchenrs.pencilgen1_1.0.0_iphoneos-arm64.deb
```

插件自带的 `postinst` 会重启 accessoryd（守护进程是按需启动的，必须让它重新
拉起才会加载插件），**不需要 respring**，也不需要 userspace reboot。
也可以把 deb 导入 Sileo / Filza 安装。

**使用**：把铅笔插进转接头，等配对完成即可；之后断连自动重连，无需任何操作。

### 自检

```bash
cat /tmp/PencilGen1Compat.loaded   # 插件是否已注入 accessoryd（内容是 pid）
cat /tmp/PencilGen1Compat.log      # 钩子命中记录（前 32 次调用）
```

预期看到 `loaded into accessoryd (pid …)` 和 `-> forcing DeviceSupports9Pin = true`。

### 卸载

```bash
dpkg -r com.xingchenrs.pencilgen1 && killall -9 accessoryd
```

已建立的配对**不会**被卸载，仍然可以正常连接；只是下次点"忽略此设备"后需要
重装插件才能再配一次。

## 原理

插件注入 `accessoryd`（过滤器见 [tweak/PencilGen1Compat.plist](tweak/PencilGen1Compat.plist)），
只让上面那段判定用到的两个 MobileGestalt 键返回 true：

* `yhHcB0iH0d1XzPO/CFd3ow` —— 混淆键，原文是 **`DeviceSupportsApplePencil`**
  （还原公式：`base64(md5("MGCopyAnswer" + name))` 去掉尾部 `=`）
* `DeviceSupports9Pin`

改动之所以安全且克制：

1. 这两个键在**整个 accessoryd 里各只出现一次**，就服务于这一段判定；
2. 它们**不在** MobileGestalt 磁盘缓存中（`CacheExtra` 的 53 个键里都没有），
   属于运行时/硬件派生值——只能进程内干预，因此天然只影响 accessoryd，
   不会让其它进程误以为这台机器有 Lightning 口。

## 构建

CI 走 GitHub Actions（[.github/workflows/build.yml](.github/workflows/build.yml)）：

* **手动触发**：Actions → build → Run workflow
* **推送触发（可选）**：提交信息里带 `[build]` 才编译，普通 push 不消耗额度
* Theos / 工具链 / SDK 用 `actions/cache` 缓存，命中时单次编译约 **35 秒**

> 两个非显而易见的构建坑（本仓库已处理，细节见 [docs/FINDINGS.md](docs/FINDINGS.md)）：
>
> 1. Linux 工具链产出的 arm64e 切片带**旧 ABI**（`cpusubtype 0x00000002`），
>    在 iOS 16 的 ABI v2 进程（`0x80000002`）里 dyld 会按错误方式修复认证
>    指针，宿主进程一碰就 SIGBUS。构建后由
>    [tools/fix_arm64e_abi.py](tweak/tools/fix_arm64e_abi.py) 重标为 ABI v2
>    并重新签名（改了头就破坏了签名范围）。
> 2. Logos 的钩子安装构造函数与 `%ctor` 的执行顺序由**链接器**决定，比较键
>    必须在钩子内**惰性初始化**，否则首次调用会拿到 NULL 而崩溃。

## 目录

```
tweak/                插件本体（Theos rootless 工程）
  Tweak.x             钩子实现
  tools/              构建后处理（arm64e ABI 修正）
docs/FINDINGS.md      完整逆向记录：定位过程、反编译、关键地址、踩坑
scripts/              取证工具链（从设备提取 dyld 缓存 / 符号 / ObjC 元数据、SSH 助手）
.github/workflows/    CI
```

## 复现这次分析

```bash
# 0) 设备连接信息走环境变量，不入库
export PENCIL_HOST=<device-ip> PENCIL_USER=<ssh-user> PENCIL_PASS=<ssh-password>

# 1) 取回整份 dyld 共享缓存（明文，位于 OS Cryptex）
python scripts/dev.py root 'id'
python scripts/pull_dsc.py                              # ~3.1 GB，含 .symbols

# 2) 把任意系统库还原成可分析的 Mach-O
python scripts/dsc_extract.py extract PencilPairingUI CoreAccessories
python scripts/dsc_symbols.py addr 0x1a6d3240c          # 地址 → 符号名
python scripts/objc_walk.py analysis/out/BluetoothSettings classes BTSDevice

# 3) 交给 IDA
python idamcp.py start "$(pwd)/analysis/binaries/accessoryd" --port 8746
```

## 已知边界

* 未越狱时插线**仍会**提示"配件不受支持"（插件只在越狱环境生效），
  但**已建立的配对不受影响**，连接与重连照常；
* 手动点过"忽略此设备"后，需要重新越狱并再插一次线才能重配；
* 插件只处理带外配对的门禁。设置页对已配对设备的"不兼容"提示属于另一条 UI
  路径（`+[CBUtil isDeviceSupportedWithType:VIDsrc:VID:PID:]` 对 `type == 25`
  直接返回 NO），不影响已经配对好的使用。

## 免责声明

仅供个人设备互操作性与逆向研究使用，风险自负；请遵守当地法律与 Apple 的相关条款。
