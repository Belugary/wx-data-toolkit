# 聊天记录导出 JSON 格式 (schema v3)

`wxdec.cli.export_chat` (单聊) 和 `wxdec.cli.export_all_chats` (批量) 产出同一种 JSON 结构,本文是该结构的 SOT。

## 顶层字段

```json
{
  "chat": "<display name>",
  "username": "<wxid 或 @chatroom 或自定义微信号>",
  "exported_at": "YYYY-MM-DD HH:MM:SS",
  "schema_version": 3,

  "date_first_msg": "YYYY-MM-DD HH:MM:SS",
  "date_last_msg":  "YYYY-MM-DD HH:MM:SS",

  "contact_remark":   "<remark>",      // 仅单聊
  "contact_nick_name": "<nick name>",  // 仅单聊
  "contact_tags":     [...],           // 仅单聊, 缺省时省略
  "contact_memo":     "<description>", // 仅单聊

  "is_group": true,                     // 仅群聊

  "last_cursor": {                      // 续跑用,按消息表分片记录
    "message_0.db": {"create_time": 1700000200, "local_id": 42},
    "message_3.db": {"create_time": 1660000000, "local_id": 9876}
  },

  "messages": [
    {"local_id": 1, "timestamp": 1713..., "sender": "me", "content": "..."},
    {"local_id": 2, "timestamp": 1713..., "sender": "<name>", "type": "voice"}
  ]
}
```

### 字段省略规则
- 单聊不产 `is_group`,群聊不产 `contact_*`
- `contact_tags` / `contact_memo` 缺省时不写出 (而非空数组 / 空串)
- text 消息省略 `type` 字段;无可提取内容时省略 `content`
- 单聊 `contact_remark` / `contact_nick_name` 为空时省略 (回落取 `username` 作显示名)

## last_cursor 跨 shard 设计

fork 的消息表是 sharded 跨多个 `message_N.db`,且 `local_id` 仅在单 shard 内自增,**跨 shard 重复**(实测 `decode_image.py:483` 注释:同 chat 最高出现 7 条同 local_id)。所以续跑的 dedup key 不能裸用 `local_id`,必须 `(shard_basename, create_time, local_id)`。

`last_cursor` 按 shard 文件名分组保存。每次增量续跑时,对每个 shard 查:

```sql
WHERE create_time > ? OR (create_time = ? AND local_id > ?)
```

(展开式,避开 SQLite row-value 语法版本依赖)。新拉的消息按 `(create_time, local_id)` Python 端排序合并到 `messages` 列表后追加,同时刷新该 shard 的 cursor。

### 老 JSON 兼容
- 无 `schema_version` 字段、或 `last_cursor` 是 list 形 → 不识别,stderr WARN + 全量重导
- `schema_version > 3` → CLI exit 3 拒绝降级 (索引文件由更新版本写入)

## sender 字段
- `"me"` = 当前账号(登录用户)
- `<其他>` = 群成员显示名(优先取群名片 → 备注 → 昵称)或单聊对端显示名
- `""` = 系统消息 / 撤回 等无明确归属的事件

## type 字段
当 type ≠ "text" 时显式产出。主要类型:

| type             | 来源 local_type    | 备注 |
|------------------|--------------------|------|
| text             | 1 (默认省略)        | `content` 是纯文本 |
| image            | 3                  | `content` 是占位 `[图片]` 等 |
| voice            | 34                 | 无 `transcription` 字段;运行 `transcribe_chat.py` 补转录 |
| contact_card     | 42                 | |
| video            | 43                 | `content` 含时长摘要 |
| sticker          | 47                 | `content` 取 emoji desc 默认语言 |
| location         | 48                 | |
| link_or_file     | 49 (子分类参看 extras) | 见 `transfer` / `quote` 子分类 |
| call             | 50                 | VoIP 通话 |
| system           | 10000              | 群事件 / 关系变动 |
| recall           | 10002              | "[撤回消息]" |
| transfer         | 49 (appmsg type=2000) | 含结构化 `transfer` extras |
| quote            | 49 (appmsg type=57)   | 含结构化 `quote` extras (引用回复) |
| type_<n>         | 其他未识别 local_type | fallback,数字保留 |

## extras 字段
某些 type 携带结构化补充字段,与 `content` 并列:

- `type=transfer` 含 `transfer: {direction, paysubtype, fee_desc, pay_memo, payer_username, receiver_username, transfer_id, transcation_id, pay_msg_id, begin_transfer_time, invalid_time}`,空值省略
- `type=quote` 含 `quote: {reply_text, refer_type, refer_type_label, refer_summary, refer_svrid, refer_fromusr, refer_chatusr, refer_displayname, refer_createtime}`,空值省略

## 增量续跑

```
# 第一次导出
python -m wxdec.cli.export_all_chats /tmp/exports

# 之后只导出新增 (按 last_cursor 续跑)
python -m wxdec.cli.export_all_chats /tmp/exports -i
```

`-i` 模式下:
- 读老 JSON 的 `last_cursor`,对每个 shard 跑 `WHERE ct > ? OR (ct = ? AND lid > ?)`
- 新消息按 `(create_time, local_id)` 排序追加到老 `messages` 末尾
- 写入用 `<chat>_export.json.partial.<pid>` 再 `os.replace` 替换,中断不破坏老文件

性能注意:`create_time` 列在 fork message 表上**无索引**, 续跑 SQL 仍走全表过滤,只省 Python 端的解密 / JSON 序列化时间,不省 IO。50K+ 消息的群续跑时间 ~ 全量的 70-80%。

## CSV 计划工作流

```
# 1) 生成清单 (扫所有会话, 仅查 message DB metadata, ~5s/千会话)
python -m wxdec.cli.export_all_chats --write-plan-csv plan.csv

# 2) 用户编辑 plan.csv 的 export 列, 标 0 跳过 / 1 导出
#    blacklist 模式 (默认): 所有行默认 export=1, 标 0 跳过
#    whitelist 模式 --plan-mode whitelist: 默认 export=0, 标 1 包含
#    系统帐号 (weixin / filehelper / gh_* 公众号) 默认预填 0

# 3) 按计划执行
python -m wxdec.cli.export_all_chats /tmp/exports --from-plan-csv plan.csv
```

CSV 是 UTF-8 BOM, Excel / WPS 直接打开中文不乱码。**Excel 可能把大数字 (message_count, body_bytes) 显示为科学计数法**,只要 `export` 列改对其他列不影响导出结果。

## 跟上游差异

本 fork 的 schema v3 跟上游 `ylytdeng/wechat-decrypt` 的对应字段不完全兼容。主要差异:

| 字段               | fork v3                          | upstream                              |
|--------------------|----------------------------------|---------------------------------------|
| `schema_version`   | 顶层 int                          | 不存在                                |
| `last_cursor`      | per-shard dict (`{basename: {ct, lid}}`) | 不存在 (上游单 shard, 全量 dedup 用裸 local_id) |
| `contact_memo`     | 来自 contact.db description 列    | 来自 contact.db description 列 (字段名相同) |
| 文件名规则         | `<chat>_export.json` / `<chat>__<username>_export.json` | `single_<chat>.json` / `group_<chat>.json` |
| 索引文件           | `_export_index.json` (schema v3) | `_export_index.json` (无 schema_version) |

源自 fork 的多 shard 架构 (message_0.db ~ message_N.db) 与上游单文件架构不同。本 port 与上游永久 diverge,upstream 后续对该模块的 patch 需手动 backport。
