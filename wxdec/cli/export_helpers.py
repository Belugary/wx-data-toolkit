"""Shared message rendering helpers used by single-chat and batch exporters.

Extracted from `wxdec.cli.export_chat` so both `export_chat` (single chat,
interactive) and `export_all_chats` (batch, plan-driven) consume the same
content-extraction logic. `wxdec.cli.export_chat` re-exports the public
names here for backward compatibility with consumers that import via
`wxdec.cli.export_chat.<helper>` (notably tests/test_record_decoders.py).
"""
from wxdec import msg_format


MSG_TYPE_MAP = {
    1: "text",
    3: "image",
    34: "voice",
    42: "contact_card",
    43: "video",
    47: "sticker",
    48: "location",
    49: "link_or_file",
    50: "call",
    10000: "system",
    10002: "recall",
}


def _msg_type_str(local_type):
    base, _ = msg_format._split_msg_type(local_type)
    return MSG_TYPE_MAP.get(base, f"type_{local_type}")


def _resolve_sender(row, ctx, names, id_to_username):
    """Resolve the sender of a message.

    Returns "me" for the logged-in user, or the sender's display name otherwise
    (the contact's name in 1-on-1 chats, the member's name in groups). Empty
    string for unattributable messages (e.g. system notifications).
    """
    local_id, local_type, create_time, real_sender_id, content, ct = row
    decoded = msg_format._decompress_content(content, ct)
    sender_from_content, _ = msg_format._format_message_text(
        local_id, local_type, decoded, ctx["is_group"], ctx["username"], ctx["display_name"], names
    )
    label = msg_format._resolve_sender_label(
        real_sender_id,
        sender_from_content,
        ctx["is_group"],
        ctx["username"],
        ctx["display_name"],
        names,
        id_to_username,
    )
    return label or ""


def _decode_sticker_desc(b64_desc):
    """WeChat encodes sticker labels as base64 protobuf: repeated (lang, text) pairs.
    Returns the 'default' language label (usually Chinese), or None.

    Limitation: treats the length byte as a single octet rather than a real protobuf
    varint — labels >127 bytes would be misread. In practice sticker descriptions are
    short (<30 chars), so this is adequate. Also sensitive to the bytes b"default"
    appearing inside a preceding value; no such cases observed.
    """
    import base64
    try:
        raw = base64.b64decode(b64_desc)
    except Exception:
        return None
    i = raw.find(b"default")
    if i < 0 or i + 7 >= len(raw) or raw[i + 7] != 0x12:
        return None
    try:
        text_len = raw[i + 8]
        text_bytes = raw[i + 9 : i + 9 + text_len]
        return text_bytes.decode("utf-8") or None
    except (IndexError, UnicodeDecodeError):
        return None


def _format_sticker_message(content):
    root = msg_format._parse_xml_root(content) if content else None
    if root is None:
        return "[表情]"
    emoji = root.find(".//emoji")
    if emoji is None:
        return "[表情]"
    desc = emoji.get("desc") or ""
    label = _decode_sticker_desc(desc) if desc else None
    return f"[表情] {label}" if label else "[表情]"


def _format_system_message(content):
    if not content:
        return "[系统消息]"
    if "<sysmsg" not in content:
        return content
    root = msg_format._parse_xml_root(content)
    if root is None:
        return content
    inner = root.findtext(".//content")
    return inner.strip() if inner else content


def _format_video_message(content):
    root = msg_format._parse_xml_root(content) if content else None
    if root is None:
        return "[视频]"
    video = root.find(".//videomsg")
    if video is None:
        return "[视频]"
    playlength = video.get("playlength")
    return f"[视频] {playlength}秒" if playlength else "[视频]"


def _extract_transfer_extras(content):
    """Detect appmsg type=2000 and return structured transfer fields, else None.

    Reuses msg_format._extract_transfer_info so the schema/version-quirks logic
    lives in one place. Empty values are dropped to keep the export compact.
    Numeric timestamps are returned as ints (consistent with the top-level
    `timestamp` field), not iso strings — downstream consumers can format.
    """
    if not content or '<appmsg' not in content:
        return None
    root = msg_format._parse_app_message_outer(content)
    if root is None:
        return None
    appmsg = root.find('.//appmsg')
    if appmsg is None:
        return None
    app_type = msg_format._parse_int(
        msg_format._collapse_text(appmsg.findtext('type') or ''), 0
    )
    if app_type != 2000:
        return None

    info = msg_format._extract_transfer_info(appmsg)
    if not info:
        return None

    out = {}
    if info['paysubtype_label']:
        out['direction'] = info['paysubtype_label']
    for k in ('paysubtype', 'fee_desc', 'pay_memo',
              'payer_username', 'receiver_username',
              'transfer_id', 'transcation_id', 'pay_msg_id'):
        v = info.get(k)
        if v:
            out[k] = v
    for k in ('begin_transfer_time', 'invalid_time'):
        v = msg_format._parse_int(info.get(k) or '', 0)
        if v:
            out[k] = v
    return out or None


def _extract_refer_extras(content):
    """Detect appmsg type=57 and return structured refer fields, else None.

    Reuses msg_format helpers (_extract_refer_info + _summarize_refer_content) so the
    schema/inner-type-summary logic lives in one place. Empty values are
    dropped to keep the export compact. refer_createtime is returned as int
    (consistent with the top-level `timestamp` field).
    """
    if not content or '<appmsg' not in content:
        return None
    root = msg_format._parse_app_message_outer(content)
    if root is None:
        return None
    appmsg = root.find('.//appmsg')
    if appmsg is None:
        return None
    app_type = msg_format._parse_int(
        msg_format._collapse_text(appmsg.findtext('type') or ''), 0
    )
    if app_type != 57:
        return None

    info = msg_format._extract_refer_info(appmsg)
    if not info:
        return None

    out = {}
    if info['reply_text']:
        out['reply_text'] = info['reply_text']
    if info['refer_type']:
        out['refer_type'] = info['refer_type']
        label = msg_format._REFER_INNER_TYPE_LABEL.get(info['refer_type'])
        if label:
            out['refer_type_label'] = label
    summary = msg_format._summarize_refer_content(
        info['refer_type'], info['refer_content']
    )
    if summary:
        out['refer_summary'] = summary
    for k in ('refer_svrid', 'refer_fromusr', 'refer_chatusr',
              'refer_displayname'):
        v = info.get(k)
        if v:
            out[k] = v
    refer_ts = msg_format._parse_int(info.get('refer_createtime') or '', 0)
    if refer_ts:
        out['refer_createtime'] = refer_ts
    return out or None


def _extract_content(local_id, local_type, content, ct, chat_username, chat_display_name):
    """Return (rendered_text, extras_dict). Either may be None.

    extras carries structured fields for non-text message types where caller
    wants more than the human-readable string. Currently transfer (type=2000)
    and quote/refer (type=57). Future additions (视频号 metadata, merged-forward
    expansion, …) can flow through the same channel without changing the
    caller signature.
    """
    content = msg_format._decompress_content(content, ct)
    if content is None:
        return None, None

    base, _ = msg_format._split_msg_type(local_type)
    if base == 1:
        return (content or ""), None
    if base == 43:
        return _format_video_message(content), None
    if base == 47:
        return _format_sticker_message(content), None
    if base == 49:
        rendered = msg_format._format_app_message_text(
            content, local_type, False, chat_username, chat_display_name, {}
        )
        transfer = _extract_transfer_extras(content)
        if transfer:
            return rendered, {'type': 'transfer', 'transfer': transfer}
        refer = _extract_refer_extras(content)
        if refer:
            return rendered, {'type': 'quote', 'quote': refer}
        return rendered, None
    if base == 50:
        return msg_format._format_voip_message_text(content), None
    if base == 10000:
        return _format_system_message(content), None
    if base == 10002:
        return "[撤回消息]", None
    return None, None


__all__ = [
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
