# appencil

让 **Apple Pencil 1（Lightning）** 在 USB-C 的 **iPad Pro (M2, iPad14,3) / iPadOS 16.1** 上可用的越狱插件项目。

现状与证据见 [docs/FINDINGS.md](docs/FINDINGS.md)。

## 目录

```
scripts/
  dev.py            设备助手：SSH 登录、sudo 提权执行、上传/下载
  pull_dsc.py       拉取设备上的 dyld 共享缓存（含符号表）
  dsc_extract.py    从分片缓存中提取任意 dylib 为可分析 Mach-O
  objc_walk.py      解析 ObjC 元数据（类/方法/实现地址）
  dsc_symbols.py    缓存符号表查询：地址 → 符号名
analysis/
  binaries/         从设备直接取回的可执行文件（如 bluetoothd）
  dsc/              dyld 共享缓存分片 + .symbols
  out/              提取出的 dylib
  device/           设备上的 plist / bundle 等小文件
docs/
  FINDINGS.md       已确认的拦截点、调用链、关键地址
```

## 常用命令

```bash
python scripts/dev.py root 'id'                                   # 设备上以 root 执行
python scripts/dsc_extract.py list Pencil                          # 缓存里找镜像
python scripts/dsc_extract.py extract BluetoothSettings            # 提取到 analysis/out/
python scripts/dsc_symbols.py addr 0x1a6d3240c                     # 地址查符号
python scripts/objc_walk.py analysis/out/BluetoothSettings classes BTSDevice
python idamcp.py start "$(pwd)/analysis/binaries/bluetoothd" --port 8745
```

## 环境依赖

- 本机：Python 3.12（`paramiko`）、IDA Pro + idalib（`idamcp.py`）。
- 设备：Dopamine 越狱（rootless，`/var/jb`），SSH 可达。

设备连接信息不写进仓库，用环境变量提供（示例值请自行替换）：

```bash
export PENCIL_HOST=<device-ip>
export PENCIL_USER=<ssh-user>
export PENCIL_PASS=<ssh-password>
```

## 构建（GitHub Actions）

工作流 `.github/workflows/build.yml`：

- **手动触发**：Actions → build → Run workflow（任意分支）
- **推送触发（可选）**：提交信息里带 `[build]` 才会编译，普通 push 不占用额度
- Theos / 工具链 / SDK 走 `actions/cache`，缓存命中时后续编译只需十几秒

产物在对应 run 的 Artifacts 里（`PencilGen1Compat-<sha>`）。

## 注意

`analysis/` 与 `.idamcp/` 是本地取证产物（设备固件、提取出的系统库、IDA 数据库、日志），
体积大且含设备相关信息，已在 `.gitignore` 中排除，**不要提交**。
