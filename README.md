# wx-data-toolkit

WeChat 4.0 本地数据导出工具（Windows / macOS / Linux）。导出聊天记录、还原图片与朋友圈媒体、提供实时消息流与 MCP 集成。仅访问用户自己机器上的数据。

## 快速开始

```bash
pip install -r requirements.txt   # Python 3.10+，微信需运行
```

| 平台 | 权限 | DB 导出 | 图片 key |
|---|---|---|---|
| Windows | 管理员 | `python main.py decrypt` | `python -m wxdec.find_image_key_monitor` |
| Linux | root / `CAP_SYS_PTRACE` | `python3 main.py decrypt` | `python -m wxdec.find_image_key_monitor` |
| macOS | root + 重签 † | `python3 -m wxdec.decrypt_db` | `python -m wxdec.find_image_key_macos` |

Windows / Linux 提图片 key 前需先在微信中点开几张图片让 key 载入内存；macOS 从磁盘派生，无此要求。

† macOS 首次（及微信升级后）需重签 + 编译扫描器：

```bash
sudo codesign --force --deep --sign - /Applications/WeChat.app
cc -O2 -o bin/find_all_keys_macos c_src/find_all_keys_macos.c -framework Foundation
sudo ./bin/find_all_keys_macos
```

首次运行会自动检测微信数据目录并生成 `config.json`。

## 功能

**导出数据库** — `python main.py decrypt` 解密导出全部数据库。`--with-wal` 把当天写入缓冲合进产物；`--db-dir` / `--keys-file` / `--out-dir` 可覆盖默认配置。

**批量解图** — `python main.py decode-images` 把图片导出到 `<chat_hash>/<YYYY-MM>/<file_md5>.<ext>`，wxgf 视频输出为 `.hevc` 裸流。

**朋友圈数据** — `python -m wxdec.cli.decrypt_sns --start YYYY-MM-DD --decrypt-media` 导出朋友圈到 `sns/<md5>.<ext>`。媒体 CDN 仅存活数天，需在窗口内拉取（落盘即永久缓存）。

**每日同步** — `python -m wxdec.cli.daily_sync` 一次跑完导出 + 解图 + 最近 7 天朋友圈，给系统定时任务（launchd / systemd / schtasks）当触发目标。

**实时消息流** — `python main.py` 启动本地 web（http://localhost:5678），实时推送新消息、图片内联预览，~100ms 延迟。

**Claude MCP 集成** — `claude mcp add wechat -- python /path/to/wx-data-toolkit/wxdec/mcp_server.py`。可用工具：`get_recent_sessions` / `get_chat_history` / `search_messages` / `get_contacts` / `get_contact_tags` / `get_tag_members` / `get_new_messages`。

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

## 免责声明

本工具仅供用户读取**自己机器上**的本地微信数据，用于个人备份 / 数据迁移 / 数字取证 / 分析等场景。请遵守相关法律法规。

## 许可证

[MIT License](LICENSE)。

## 致谢

- [nobiyou/wx_channel](https://github.com/nobiyou/wx_channel) (MIT) — 朋友圈媒体 ISAAC-64 keystream 的 Go 参考实现，本仓库 [wxdec/sns_isaac.py](wxdec/sns_isaac.py) 据此 clean-room 移植到 Python
- [hicccc77/WeFlow](https://github.com/hicccc77/WeFlow) — macOS 图片 key 派生算法的参考实现
