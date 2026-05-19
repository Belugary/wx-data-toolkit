"""
将单个聊天的全部消息导出为 JSON。

用法:
    .venv/bin/python3 -m wxdec.cli.export_chat <chat_name> [output.json]

参数:
    <chat_name>    联系人显示名、备注名、群名或 wxid。
    [output.json]  可选输出路径，默认 "<chat_name>_export.json"。

示例:
    .venv/bin/python3 -m wxdec.cli.export_chat <contact_name>
    .venv/bin/python3 -m wxdec.cli.export_chat <group_name> /tmp/out.json

输出 JSON 的紧凑结构 (schema_version=3):
    {
      "chat": "<display name>",
      "username": "<wxid 或 @chatroom>",
      "exported_at": "YYYY-MM-DD HH:MM:SS",
      "schema_version": 3,
      "date_first_msg": "YYYY-MM-DD HH:MM:SS",
      "date_last_msg": "YYYY-MM-DD HH:MM:SS",
      "contact_remark": "...",        // 仅单聊
      "contact_nick_name": "...",     // 仅单聊
      "contact_tags": [...],          // 仅单聊, 缺省字段省略
      "contact_memo": "...",          // 仅单聊
      "is_group": true,               // 仅群聊
      "last_cursor": {                // 续跑用,按消息表分片记录
        "Msg_<md5>": {"create_time": ..., "local_id": ...}
      },
      "messages": [
        {"local_id": 1, "timestamp": 1713..., "sender": "me", "content": "..."},
        {"local_id": 2, "timestamp": 1713..., "sender": "<name>", "type": "voice"}
      ]
    }

默认值/空值会被省略: text 消息省略 "type"，无可提取内容时省略 "content"，
1-on-1 聊天省略 "is_group"，群聊省略所有 contact_* 字段。

语音消息以 type "voice" 导出且不带 transcription 字段；运行
transcribe_chat.py 可用 FunASR SenseVoice-Small 补齐转录。

需先完成 WeChat DB 解密（详见 README）。

完整 schema、字段语义与加载示例: docs/chat_export_format.md
"""
import json
import sqlite3
import sys
from contextlib import closing
from datetime import datetime

from wxdec import msg_format, msg_query
from wxdec.cli.export_helpers import (
    MSG_TYPE_MAP,
    _decode_sticker_desc,
    _extract_content,
    _extract_refer_extras,
    _extract_transfer_extras,
    _format_sticker_message,
    _format_system_message,
    _format_video_message,
    _msg_type_str,
    _resolve_sender,
)
from wxdec.contact import (
    get_contact_full,
    get_contact_names,
    get_contact_tag_names_by_username,
)


SCHEMA_VERSION = 3


def _format_msg_ts(ts):
    """Unix timestamp → 'YYYY-MM-DD HH:MM:SS' (local time, same convention as exported_at)."""
    if not ts:
        return ""
    try:
        return datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, ValueError):
        return ""


def _contact_metadata_for_export(username):
    """Look up contact metadata (remark / nick / tags / memo) for a 1-on-1 chat.

    Returns a dict with only the keys that have non-empty values, so callers
    can `output.update(metadata)` without polluting the JSON with empty fields.
    Group chats should not call this — see `_resolve_chat_context['is_group']`.
    """
    out = {}
    full = get_contact_full()
    info = next((c for c in full if c.get('username') == username), None)
    if info:
        if info.get('remark'):
            out['contact_remark'] = info['remark']
        if info.get('nick_name'):
            out['contact_nick_name'] = info['nick_name']
        if info.get('description'):
            out['contact_memo'] = info['description']
    tags_by_user = get_contact_tag_names_by_username()
    user_tags = tags_by_user.get(username)
    if user_tags:
        out['contact_tags'] = list(user_tags)
    return out


def export_chat(chat_name, output_path):
    ctx = msg_query._resolve_chat_context(chat_name)
    if ctx is None:
        print(f"Could not resolve chat: {chat_name}")
        sys.exit(1)

    username = ctx["username"]
    display_name = ctx["display_name"]
    # resolve_username 对模糊匹配会静默选第一个命中，打印一下便于用户核对。
    print(f"Resolved to: {display_name} ({username})")

    if not ctx["message_tables"]:
        print(f"No message tables found for {username}")
        sys.exit(1)

    names = get_contact_names()

    # Each shard has its own Name2Id table, so we must pair rows with the
    # id_to_username map from their source DB. Track table_name per row to
    # produce per-shard `last_cursor` for incremental resume.
    all_rows = []
    last_cursor_per_shard = {}  # {table_name: {create_time, local_id}}
    for table_info in ctx["message_tables"]:
        db_path = table_info["db_path"]
        table_name = table_info["table_name"]
        shard_max = None  # (create_time, local_id) max for this shard
        with closing(sqlite3.connect(db_path)) as conn:
            id_to_username = msg_format._load_name2id_maps(conn)
            rows = msg_query._query_messages(conn, table_name, limit=None, oldest_first=True)
            for row in rows:
                local_id, local_type, create_time, real_sender_id, content, ct = row
                all_rows.append((row, id_to_username, table_name))
                cur = (create_time or 0, local_id)
                if shard_max is None or cur > shard_max:
                    shard_max = cur
        if shard_max is not None:
            last_cursor_per_shard[table_name] = {
                "create_time": shard_max[0],
                "local_id": shard_max[1],
            }

    # Sort across shards by create_time (defensive "or 0" in case a row has NULL).
    all_rows.sort(key=lambda triple: triple[0][2] or 0)

    messages = []
    for row, id_to_username, _table_name in all_rows:
        local_id, local_type, create_time, real_sender_id, content, ct = row
        sender = _resolve_sender(row, ctx, names, id_to_username)
        type_str = _msg_type_str(local_type)
        rendered, extras = _extract_content(
            local_id, local_type, content, ct, username, display_name
        )

        # Compact format: omit defaults/nulls. type defaults to "text", transcription
        # is added later by transcribe_chat.py only for voice messages. See CLAUDE.md.
        msg = {
            "local_id": local_id,
            "timestamp": create_time,
            "sender": sender,
        }
        # extras may override type with a more specific value (e.g. "transfer"
        # narrower than the generic "link_or_file" base=49 maps to).
        effective_type = (extras or {}).get("type") or type_str
        if effective_type != "text":
            msg["type"] = effective_type
        if rendered is not None:
            msg["content"] = rendered
        if extras:
            for k, v in extras.items():
                if k == "type":
                    continue
                msg[k] = v
        messages.append(msg)

    output = {
        "chat": display_name,
        "username": username,
        "exported_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "schema_version": SCHEMA_VERSION,
    }
    if messages:
        first_ts = messages[0].get("timestamp")
        last_ts = messages[-1].get("timestamp")
        if first_ts:
            output["date_first_msg"] = _format_msg_ts(first_ts)
        if last_ts:
            output["date_last_msg"] = _format_msg_ts(last_ts)

    if ctx["is_group"]:
        output["is_group"] = True
    else:
        output.update(_contact_metadata_for_export(username))

    if last_cursor_per_shard:
        output["last_cursor"] = last_cursor_per_shard
    output["messages"] = messages

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    print(f"Exported {len(messages)} messages to {output_path}")


__all__ = [
    "SCHEMA_VERSION",
    "export_chat",
    # Re-exported helpers for backward compatibility with consumers that
    # import via `wxdec.cli.export_chat.<helper>` (notably tests).
    "MSG_TYPE_MAP",
    "_msg_type_str",
    "_resolve_sender",
    "_decode_sticker_desc",
    "_format_sticker_message",
    "_format_system_message",
    "_format_video_message",
    "_extract_transfer_extras",
    "_extract_refer_extras",
    "_extract_content",
]


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 -m wxdec.cli.export_chat <chat_name> [output.json]")
        sys.exit(1)
    chat = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else f"{chat}_export.json"
    export_chat(chat, out)
