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

**导出聊天数据库** — `python main.py decrypt` 把全部对话导出到 `decrypted/`。 加 `--with-wal` 可以把当天最新写入的数据一起合进来; `--db-dir` / `--keys-file` / `--out-dir` 可以覆盖默认路径。

**导出图片** — `python main.py decode-images` 把图片整理成 `<会话>/<年-月>/<文件名>` 的目录结构, 直接打开就能看。 聊天里的小视频 (wxgf 格式) 会以 `.hevc` 裸流形式落盘, 用 ffmpeg 可以再封装成 mp4。

**导出朋友圈** — `python -m wxdec.cli.decrypt_sns --start YYYY-MM-DD --decrypt-media` 整理朋友圈到 `sns/` 目录。 注意:**朋友圈的图片/视频在服务端只保留几天**, 过期就拿不到了; 加上 `--decrypt-media` 才会在窗口期内把媒体文件落到本地, 之后就一直可用。

输出 JSON 包含每条朋友圈的完整 metadata: `contentDesc / location / locationDetail / media[] (含 description / videoDuration / size) / videoEncKey / isPrivate / finderFeed (视频号转发) / likes / comments`。 互动数据(点赞、评论)从 sns.db 的 `SnsMessage_tmp3` 表读取。

**朋友圈视频批量补还原** — 下载朋友圈视频时若之前缺失访问凭据, 视频会以 `.mp4.enc` 形式临时落盘。 拿到完整 `sns.db` 后用以下命令批量整理:

```bash
python tools/decrypt_existing_videos.py --enc-dir <存放 .mp4.enc 的目录> \
    --sns-db ~/Documents/wechat_decrypted/sns/sns.db
```

视频访问凭据(post 级别 `<enc key>` 字段)从 sns.db XML 中读取, 不依赖网络。

**朋友圈采集度报告** — `python tools/sns_health.py --user <你的 wxid>` 输出当前 sns.db 里数据的健康度: 月度直方图、字段采集深度、媒体落盘覆盖率、`SnsUserTimeLineBreakFlagV2` 反映的"完整加载锚点"(早于该时间点的数据可能不全)。 报告末尾给出针对性补全建议(例如要补全早期历史, 在微信客户端打开自己朋友圈一直下拉到底, 让客户端向服务器请求历史并写入本地 DB)。

**整理朋友圈本地图片缓存** — `python tools/decode_sns_cache.py` 把微信本地缓存目录(`xwechat_files/<wxid>/cache/<YYYY-MM>/Sns/Img/`)里所有曾经浏览过的朋友圈图片整理为 jpg / png, 按月落到 `<decoded_image_dir>/sns_cache/<YYYY-MM>/<原始 md5>.<ext>`。 即使腾讯 CDN 已经过期、`--decrypt-media` 拿不到的早期媒体, 只要曾经浏览过就能从本地找回来。 默认多进程并行。

**每日定时同步** — `python -m wxdec.cli.daily_sync` 一次跑完"导出 + 整理图片 + 最近 7 天朋友圈", 配 launchd / systemd / schtasks 当定时任务用。

**实时消息流(本地 Web)** — `python main.py` 启动 `http://localhost:5678`, 浏览器里看新消息推送, 图片内联预览, 大约 100 毫秒延迟。

**Claude MCP 集成** — 把对话数据接进 Claude Code, 直接在对话里查微信:

```bash
claude mcp add wechat -- python /path/to/wx-data-toolkit/wxdec/mcp_server.py
```

可用工具:

| 工具 | 说明 |
|---|---|
| `get_recent_sessions` | 获取最近会话列表 |
| `get_chat_history(chat_name)` | 获取与指定联系人的聊天历史 |
| `search_messages(keyword)` | 在所有聊天记录中搜索关键词 |
| `get_contacts()` | 列出所有联系人 |
| `get_contact_tags()` | 列出所有联系人标签及成员数量 |
| `get_tag_members(tag_name)` | 获取指定标签下的所有联系人 |
| `get_new_messages()` | 获取自上次调用以来的新消息 |
| `get_voice_messages(chat_name)` | 列出某会话所有语音消息(local_id、时长、时间戳) |
| `decode_voice(chat_name, local_id)` | 解码 SILK 语音为本地 WAV 文件 |
| `transcribe_voice(chat_name, local_id)` | 转录语音为文字(自动检测语言) |

#### ⚠️ 语音转录隐私

`transcribe_voice` 默认使用本地 Whisper(CPU), 数据全程留在本机。 `python -m wxdec.cli.transcribe_chat` 批量 CLI 共享同一份配置。

如需切换到 OpenAI Whisper API(更快、中文精度更高), 在 `config.json` 中:

```json
{
    "transcription_backend": "openai",
    "openai_api_key": "sk-..."
}
```

启用后**语音文件会上传至 OpenAI 服务器**进行转录。 需 `pip install openai`。

- 成本:约 $0.006 / 分钟(OpenAI 计价)
- 文件 > 25MB 在上传前被拒绝(OpenAI 上限)
- 首次启用云后端时 stderr 会打一行警告
- `transcription_backend` 或 `openai_api_key` 任一缺失时静默回退 local
- 切换后端后, 旧缓存条目(backend 不匹配)会自动重新转录

→ [使用案例:在 Claude 对话里查询微信数据](docs/usage.md)

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
