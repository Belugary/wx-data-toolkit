# wx-data-toolkit

把你自己设备上的微信 4.0 聊天记录、图片、朋友圈整理成可读、可备份、可分析的本地文件。 支持 Windows / macOS / Linux。

> 适用场景:个人备份、迁移到新机器、长期备份、把对话喂给本地大模型分析。 工具仅在你自己授权的设备上、读取你自己账号下的内容。

## 快速开始

```bash
git clone https://github.com/Belugary/wx-data-toolkit.git
cd wx-data-toolkit
pip install -r requirements.txt    # Python 3.10+
```

运行前请保持微信处于登录状态。

| 平台 | 系统授权 | 命令 | 备注 |
|---|---|---|---|
| Windows | 管理员 | `python main.py decrypt` | 导出图片前先在微信里点开几张图(让缓存载入内存) |
| Linux | root 或 `CAP_SYS_PTRACE` | `python3 main.py decrypt` | 仅支持文字与数据库, 图片暂不直接导出 |
| macOS | root + 一次性签名授权 † | `python3 main.py decrypt` | 见下方 macOS 章节 |

首次运行会自动定位你的微信数据目录并生成 `config.json`。

### macOS 一次性签名授权 †

macOS 系统对应用做了签名校验, 因此首次使用、以及微信版本升级之后, 需要手动给微信做一次"本地签名授权"——这只是让 wx-data-toolkit 能在 macOS 下与微信本地数据正常交互, 不修改微信功能, 数据不离开本机, 不通过任何远端 API。 命令一目了然:

```bash
# 一次性给微信本体做本地签名(仅本机有效, 不修改微信代码)
sudo codesign --force --deep --sign - /Applications/WeChat.app

# 编译一个用来读取本地数据的小工具(放到 ./bin/)
cc -O2 -o bin/find_all_keys_macos c_src/find_all_keys_macos.c -framework Foundation

# 跑一次, 完成 wx-data-toolkit 的本地初始化
sudo ./bin/find_all_keys_macos
```

需要先安装命令行工具:`xcode-select --install`。 macOS 10.15 起的版本均实测可用 (Apple Silicon 与 Intel)。 完整说明见 [docs/macos-permission-guide.md](docs/macos-permission-guide.md)。

## 功能

**导出聊天数据库** — `python main.py decrypt` 全部对话导出到 `decrypted/`。`--with-wal` 合并当天最新数据; `--db-dir` / `--keys-file` / `--out-dir` 覆盖默认路径。

**导出图片** — `python main.py decode-images` 按 `<会话>/<年-月>/<文件名>` 整理。wxgf 小视频以 `.hevc` 裸流落盘, ffmpeg 可封装为 mp4。

**导出朋友圈** — `python -m wxdec.cli.decrypt_sns --start YYYY-MM-DD --decrypt-media` 整理到 `sns/`。注意: **朋友圈媒体在服务端只保留几天**, `--decrypt-media` 在窗口期内把文件落到本地。更多朋友圈工具(视频补还原、采集度报告、本地缓存整理)见 `tools/` 目录。

**实时消息流** — `python main.py` 启动 `http://localhost:5678`, 浏览器看新消息推送, 图片内联预览, ~100ms 延迟。

**每日定时同步** — `python -m wxdec.cli.daily_sync` 一次跑完导出 + 图片 + 最近 7 天朋友圈, 配 launchd / systemd / schtasks 当定时任务。

**Claude MCP 集成** — 在 Claude Code 里直接查微信数据:

```bash
claude mcp add wechat -- python /path/to/wx-data-toolkit/wxdec/mcp_server.py
```

<details>
<summary>可用工具</summary>

| 工具 | 说明 |
|---|---|
| `get_recent_sessions` | 最近会话列表 |
| `get_chat_history(chat_name)` | 聊天历史，支持时间范围、分页、按类型过滤（`msg_types`） |
| `search_messages(keyword)` | 全聊天记录搜索，支持多聊天对象 |
| `get_contacts()` | 联系人列表 |
| `get_contact_tags()` / `get_tag_members(tag_name)` | 标签与成员 |
| `get_new_messages()` | 自上次调用以来的新消息 |
| `get_chat_images` / `get_voice_messages` | 列出图片/语音消息，支持时间范围和分页 |
| `decode_image` / `decode_voice` / `transcribe_voice` | 图片解密、语音解码与转录 |
| `decode_file_message` | 定位文件消息（PDF/docx 等）的本地副本 |

语音转录默认使用本地 FunASR [SenseVoice-Small](https://www.modelscope.cn/models/iic/SenseVoiceSmall)(多语种, 中文表现优于 Whisper-large-v3), 数据留在本机, 首次运行下载 ~900MB 权重 (`pip install funasr`)。下载源由 `local_sensevoice_hub` 控制, 默认 `"ms"` (ModelScope, 国内最快); 海外用户可设 `"hf"` (HuggingFace) 并把 `local_sensevoice_model` 改为 `"FunAudioLLM/SenseVoiceSmall"`。在 `config.json` 设 `"transcription_backend": "openai"` + `"openai_api_key"` 可切换到 OpenAI Whisper API(**语音会上传至 OpenAI**)。

</details>

→ [使用案例与示例](docs/usage.md)

## 配置

<details>
<summary><b>config.json 模板与平台细节</b></summary>

如果自动检测失败(例如微信安装在非默认位置), 在项目根手动创建 `config.json`。

Windows:

```json
{
    "db_dir": "D:\\xwechat_files\\你的微信ID\\db_storage",
    "keys_file": "all_keys.json",
    "decrypted_dir": "decrypted",
    "wechat_process": "Weixin.exe"
}
```

Linux:

```json
{
    "db_dir": "/home/yourname/Documents/xwechat_files/your_wxid/db_storage",
    "keys_file": "all_keys.json",
    "decrypted_dir": "decrypted",
    "wechat_process": "wechat"
}
```

macOS:

```json
{
    "db_dir": "/Users/yourname/Library/Containers/com.tencent.xinWeChat/Data/Library/Application Support/com.tencent.xinWeChat/2.0b4.0.9/<hash>/Message",
    "keys_file": "all_keys.json",
    "decrypted_dir": "decrypted",
    "wechat_process": "WeChat"
}
```

`db_dir` 路径来源:Windows 可在微信设置 → 文件管理中找到; Linux 默认在 `~/Documents/xwechat_files/<wxid>/db_storage`; macOS 在 `~/Library/Containers/com.tencent.xinWeChat/.../Message` (`<hash>` 是微信随机生成的账号目录)。

</details>

## 适用范围与免责

本工具仅在用户本机运行, 不进行任何网络上传, 不修改微信的代码与功能逻辑。 读取范围限于用户本机已存在的微信本地数据, 适用于个人备份、设备迁移、数据归档与本地分析等场景。 使用本工具应遵守所在地区的相关法律法规。

## 许可证

[MIT License](LICENSE)。

## 致谢

- [nobiyou/wx_channel](https://github.com/nobiyou/wx_channel)(MIT) — 朋友圈媒体处理算法的 Go 参考实现, 本仓库 [wxdec/sns_isaac.py](wxdec/sns_isaac.py) 据此 clean-room 移植到 Python
- [hicccc77/WeFlow](https://github.com/hicccc77/WeFlow) — macOS 图片读取流程、朋友圈视频访问凭据字段位置的参考实现
- 依赖的开源 Python 库、Anthropic 的 Model Context Protocol
