# WeChat 4.x Database Decryptor

微信 4.0 (Windows / macOS / Linux) 本地数据库解密工具。从运行中的微信进程内存提取加密密钥，解密 SQLCipher 4 数据库 + `.dat` 图片，并提供实时消息监听。

## 本 fork 相对原项目的增强

- **`decrypt --with-wal` + CLI override + 分级退出码** — 把当天 `.db-wal` 缓冲合进产物（opt-in），`--db-dir` / `--keys-file` / `--out-dir` 覆盖配置，退出码区分"完全 fresh" / "DB 失败" / "WAL stale"
- **`decode-images` 子命令** — 一次性把所有 `.dat` 图片解密成镜像 attach 结构的明文文件树，幂等可重跑、原子写、错误隔离
- **macOS 图片密钥派生** — 从磁盘 kvcomm 缓存推算 AES key，免重签名、免 root、免提前查看图片，解决 [issue #23](https://github.com/ylytdeng/wechat-decrypt/issues/23) 的内存扫描候选爆炸
- **`config.json` 路径支持 `~` 展开**

## 快速开始

```bash
pip install -r requirements.txt   # Python 3.10+，微信需运行
```

| 平台 | 权限 | 解密 DB | 图片密钥 † |
|---|---|---|---|
| Windows | 管理员 | `python main.py decrypt` | `python -m wxdec.find_image_key_monitor` |
| Linux | root / `CAP_SYS_PTRACE` | `python3 main.py decrypt` | `python -m wxdec.find_image_key_monitor` |
| macOS | root + 重签 ‡ | `python3 -m wxdec.decrypt_db` | `python -m wxdec.find_image_key_macos` |

† Windows / Linux 提图片密钥前需先在微信中点开几张图片让 key 载入内存；macOS 从磁盘派生，无此要求。
‡ macOS 首次（及微信升级后）需重签 + 编译扫描器：

```bash
sudo codesign --force --deep --sign - /Applications/WeChat.app
cc -O2 -o bin/find_all_keys_macos c_src/find_all_keys_macos.c -framework Foundation
sudo ./bin/find_all_keys_macos
```

首次运行会自动检测微信数据目录并生成 `config.json`。`decrypt` 加 `--with-wal` 把当天 WAL 合进产物（默认关闭以保稳定）；退出码 `0`/`1`/`2` 区分全成功 / DB 失败 / WAL stale；`--db-dir` / `--keys-file` / `--out-dir` 覆盖配置。

**批量解图**：`python main.py decode-images` → `<chat_hash>/<YYYY-MM>/<file_md5>.<ext>`，幂等、原子写，wxgf 输出 `.hevc` 裸流。

**朋友圈解密**：`python -m wxdec.cli.decrypt_sns --start YYYY-MM-DD --decrypt-media` → `<decoded_image_dir>/sns/<md5>.<ext>`，纯 Python ISAAC-64 解密、幂等、原子写。CDN URL 通常仅存活数天，需要在窗口内本地化（落盘后即永久缓存，不再依赖远端）。

**实时消息流**：`python main.py` → http://localhost:5678（SSE，~100ms 延迟，图片内联预览）。HTTP API: `/api/history`、`/api/tags`、`/stream`。

**Claude MCP 集成**：`claude mcp add wechat -- python /path/to/wechat-decrypt/wxdec/mcp_server.py`。可用工具：`get_recent_sessions` / `get_chat_history` / `search_messages` / `get_contacts` / `get_contact_tags` / `get_tag_members` / `get_new_messages`。

**[使用案例（截图）→](docs/usage.md)**

<details>
<summary><b>详细配置 / 平台前置 / config.json 模板</b></summary>

### 平台前置

- **Windows**：Windows 10/11，管理员权限（读取进程内存）
- **Linux**：64-bit，root 或 `CAP_SYS_PTRACE`（读取 `/proc/<pid>/mem`），`db_dir` 默认 `~/Documents/xwechat_files/<wxid>/db_storage`
- **macOS**：10.15+（Apple Silicon / Intel），Xcode Command Line Tools (`xcode-select --install`)，对 `/Applications/WeChat.app` 做 ad-hoc 重签名（首次及微信升级后），root 运行扫描器；`db_dir` 默认 `~/Library/Containers/com.tencent.xinWeChat/.../Message`

### config.json 模板

如果自动检测失败（例如微信安装在非默认位置），手动创建：

Windows：
```json
{
    "db_dir": "D:\\xwechat_files\\你的微信ID\\db_storage",
    "keys_file": "all_keys.json",
    "decrypted_dir": "decrypted",
    "wechat_process": "Weixin.exe"
}
```

Linux：
```json
{
    "db_dir": "/home/yourname/Documents/xwechat_files/your_wxid/db_storage",
    "keys_file": "all_keys.json",
    "decrypted_dir": "decrypted",
    "wechat_process": "wechat"
}
```

macOS：
```json
{
    "db_dir": "/Users/yourname/Library/Containers/com.tencent.xinWeChat/Data/Library/Application Support/com.tencent.xinWeChat/2.0b4.0.9/<hash>/Message",
    "keys_file": "all_keys.json",
    "decrypted_dir": "decrypted",
    "wechat_process": "WeChat"
}
```

`db_dir` 路径：Windows 可在微信设置 → 文件管理中找到；Linux 默认在 `~/Documents/xwechat_files/<wxid>/db_storage`；macOS 在 `~/Library/Containers/com.tencent.xinWeChat/.../Message`（`<hash>` 是微信随机生成的账号目录）。

</details>

<details>
<summary><b>原理与技术细节</b></summary>

### SQLCipher 4 加密参数

- **算法**：AES-256-CBC + HMAC-SHA512
- **KDF**：PBKDF2-HMAC-SHA512, 256,000 iterations
- **页面**：4096 bytes, reserve = 80（IV 16 + HMAC 64）
- 每个数据库有独立的 salt 和 enc_key

WCDB（微信的 SQLCipher 封装）会在进程内存中缓存派生后的 raw key，格式为 `x'<64hex_enc_key><32hex_salt>'`。三个平台均通过扫描进程内存匹配此模式，再通过 HMAC 校验 page 1 确认密钥正确性。

### WAL 处理

微信使用 SQLite WAL 模式，WAL 文件**预分配固定大小**（4MB）。检测变化时：
- 不能用文件大小（永远不变）
- 使用 mtime 检测写入
- 解密 WAL frame 时需校验 salt 值，跳过旧周期遗留的 frame

### 图片 .dat 加密格式

| 格式 | 时期 | Magic | 加密方式 | 密钥来源 |
|------|------|-------|---------|---------|
| 旧 XOR | ~2025-07 | 无 | 单字节 XOR | 自动检测（对比 magic bytes） |
| V1 | 过渡期 | `07 08 V1 08 07` | AES-ECB + XOR | 固定 key: `cfcd208495d565ef` |
| V2 | 2025-08+ | `07 08 V2 08 07` | AES-128-ECB + XOR | 从进程内存提取 / macOS 派生 |

V2 文件结构：`[6B signature] [4B aes_size LE] [4B xor_size LE] [1B padding]` + `[AES-ECB encrypted] [raw unencrypted] [XOR encrypted]`。

**macOS 派生算法**：扫描 `~/Library/Containers/com.tencent.xinWeChat/.../app_data/net/kvcomm/key_*.statistic` 文件名提取派生码 `code`，配合 `db_dir` 路径里的 wxid，按 `aes_key = MD5(str(code) + cleaned_wxid)[:16]` / `xor_key = code & 0xFF` 推算密钥，并用一张 V2 `_t.dat` 缩略图做 AES 模板验证。算法发现归功于 [@hicccc77](https://github.com/hicccc77) 在 [issue #23 评论](https://github.com/ylytdeng/wechat-decrypt/issues/23)，参考实现见其 [WeFlow](https://github.com/hicccc77/WeFlow/blob/dev/electron/services/keyServiceMac.ts)（CC BY-NC-SA 4.0）；本仓库的 `find_image_key_macos.py` 是基于该算法的独立 Python clean-room 实现。

### 数据库结构

解密后约 26 个数据库：
- `session/session.db` — 会话列表（最新消息摘要）
- `message/message_*.db` — 聊天记录
- `contact/contact.db` — 联系人
- `media_*/media_*.db` — 媒体文件索引
- 其他：head_image、favorite、sns、emoticon 等

### 文件清单

| 文件 | 说明 |
|------|------|
| `main.py` | 一键入口（自动配置、提取密钥、启动服务） |
| `wxdec/config.py` | 配置加载器（自动检测微信数据目录） |
| `wxdec/find_all_keys.py` / `find_all_keys_{windows,linux}.py` | DB 密钥扫描（Windows / Linux） |
| `c_src/find_all_keys_macos.c` | DB 密钥扫描（macOS, Mach VM API） |
| `wxdec/decrypt_db.py` | 全量解密所有数据库 |
| `wxdec/decode_image.py` | 图片 .dat 解密模块（XOR / V1 / V2） |
| `wxdec/find_image_key.py` / `find_image_key_monitor.py` | 图片 AES 密钥提取（Windows / Linux） |
| `wxdec/find_image_key_macos.py` | 图片 AES 密钥派生（macOS） |
| `wxdec/cli/monitor_web.py` / `wxdec/cli/monitor.py` | 实时消息监听（Web / CLI） |
| `wxdec/mcp_server.py` | MCP Server |
| `wxdec/latency_test.py` | 延迟诊断工具 |

</details>

## 免责声明

本工具仅用于学习和研究目的，用于解密**自己的**微信数据。请遵守相关法律法规。

## 许可证

[MIT License](LICENSE)。

## 致谢

- [ylytdeng/wechat-decrypt](https://github.com/ylytdeng/wechat-decrypt) — 本仓库 fork 的上游，提供 SQLCipher 解密、密钥提取等核心能力
- [LifeArchiveProject/WeChatDataAnalysis](https://github.com/LifeArchiveProject/WeChatDataAnalysis) — 朋友圈 XML 解析与时间线结构的参考实现
- [nobiyou/wx_channel](https://github.com/nobiyou/wx_channel) (MIT) — `pkg/util/isaac64.go` 提供了 WeFlow `WxIsaac64` 的 Go clean-room 实现，本仓库 [wxdec/sns_isaac.py](wxdec/sns_isaac.py) 据此移植到 Python（关键差异：PHI 常数尾字节是 `0x13` 而非标准 ISAAC-64 的 `0x15`）
- [hicccc77/WeFlow](https://github.com/hicccc77/WeFlow) — 朋友圈媒体 ISAAC-64 keystream 与 macOS 图片密钥派生算法的权威参考
