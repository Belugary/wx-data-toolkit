"""
Contact operations — loading, caching, and resolving WeChat contacts.

Imports from db_core for database access.
"""

import os
import re
import sqlite3

from wxdec.db_core import _cache, DB_DIR, DECRYPTED_DIR, ALL_KEYS

# ============ Contact caches ============

_contact_names = None  # {username: display_name}
_contact_full = None   # [{username, nick_name, remark}]
_contact_tags = None   # {label_id: {name, sort_order, members: [{username, display_name}]}}
_self_username = None


def _load_contacts_from(db_path):
    names = {}
    full = []
    conn = sqlite3.connect(db_path)
    try:
        for r in conn.execute("SELECT username, nick_name, remark FROM contact").fetchall():
            uname, nick, remark = r
            display = remark if remark else nick if nick else uname
            names[uname] = display
            full.append({'username': uname, 'nick_name': nick or '', 'remark': remark or ''})
    finally:
        conn.close()
    return names, full


def get_contact_names():
    global _contact_names, _contact_full
    if _contact_names is not None:
        return _contact_names

    # 优先用已解密的 contact.db
    pre_decrypted = os.path.join(DECRYPTED_DIR, "contact", "contact.db")
    if os.path.exists(pre_decrypted):
        try:
            _contact_names, _contact_full = _load_contacts_from(pre_decrypted)
            return _contact_names
        except Exception:
            pass

    # 实时解密
    path = _cache.get(os.path.join("contact", "contact.db"))
    if path:
        try:
            _contact_names, _contact_full = _load_contacts_from(path)
            return _contact_names
        except Exception:
            pass

    return {}


def get_contact_full():
    global _contact_full
    if _contact_full is None:
        get_contact_names()
    return _contact_full or []


def _get_contact_db_path():
    """获取 contact.db 路径（优先已解密，其次实时解密）"""
    pre = os.path.join(DECRYPTED_DIR, "contact", "contact.db")
    if os.path.exists(pre):
        return pre
    return _cache.get(os.path.join("contact", "contact.db"))


def _extract_pb_field_30(data):
    """从 extra_buffer (protobuf) 中提取 Field #30 的字符串值（联系人标签ID）"""
    if not data:
        return None
    pos = 0
    n = len(data)
    while pos < n:
        # 读 varint tag
        tag = 0
        shift = 0
        while pos < n:
            b = data[pos]; pos += 1
            tag |= (b & 0x7f) << shift
            if not (b & 0x80):
                break
            shift += 7
        field_num = tag >> 3
        wire_type = tag & 0x07
        if wire_type == 0:  # varint
            while pos < n and data[pos] & 0x80:
                pos += 1
            pos += 1
        elif wire_type == 2:  # length-delimited
            length = 0; shift = 0
            while pos < n:
                b = data[pos]; pos += 1
                length |= (b & 0x7f) << shift
                if not (b & 0x80):
                    break
                shift += 7
            if field_num == 30:
                try:
                    return data[pos:pos + length].decode('utf-8')
                except Exception:
                    return None
            pos += length
        elif wire_type == 1:  # 64-bit
            pos += 8
        elif wire_type == 5:  # 32-bit
            pos += 4
        else:
            break
    return None


def _load_contact_tags():
    """加载并缓存联系人标签数据"""
    global _contact_tags
    if _contact_tags is not None:
        return _contact_tags

    db_path = _get_contact_db_path()
    if not db_path:
        return {}

    try:
        conn = sqlite3.connect(db_path)
    except Exception:
        return {}

    try:
        # 1. 加载标签定义
        try:
            label_rows = conn.execute(
                "SELECT label_id_, label_name_, sort_order_ FROM contact_label ORDER BY sort_order_"
            ).fetchall()
        except sqlite3.OperationalError:
            return {}
        if not label_rows:
            return {}

        labels = {}
        for lid, lname, sort_order in label_rows:
            labels[lid] = {'name': lname, 'sort_order': sort_order, 'members': []}

        # 2. 扫描联系人的标签关联
        names = get_contact_names()
        rows = conn.execute(
            "SELECT username, extra_buffer FROM contact WHERE extra_buffer IS NOT NULL"
        ).fetchall()

        for username, buf in rows:
            label_str = _extract_pb_field_30(buf)
            if not label_str:
                continue
            display = names.get(username, username)
            for lid_s in label_str.split(','):
                try:
                    lid = int(lid_s.strip())
                except (ValueError, AttributeError):
                    continue
                if lid in labels:
                    labels[lid]['members'].append({'username': username, 'display_name': display})

        _contact_tags = labels
        return _contact_tags
    except Exception:
        return {}
    finally:
        conn.close()


def resolve_username(chat_name):
    """将聊天名/备注名/wxid 解析为 username"""
    names = get_contact_names()

    # 直接是 username
    if chat_name in names or chat_name.startswith('wxid_') or '@chatroom' in chat_name:
        return chat_name

    # 模糊匹配(优先精确包含)
    chat_lower = chat_name.lower()
    for uname, display in names.items():
        if chat_lower == display.lower():
            return uname
    for uname, display in names.items():
        if chat_lower in display.lower():
            return uname

    return None


def _get_self_username():
    global _self_username
    if _self_username:
        return _self_username

    if not DB_DIR:
        return ''

    names = get_contact_names()
    account_dir = os.path.basename(os.path.dirname(DB_DIR))
    candidates = [account_dir]

    m = re.fullmatch(r'(.+)_([0-9a-fA-F]{4,})', account_dir)
    if m:
        candidates.insert(0, m.group(1))

    for candidate in candidates:
        if candidate and candidate in names:
            _self_username = candidate
            return _self_username

    return ''
