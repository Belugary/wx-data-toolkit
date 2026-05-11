"""
Query engine — finding message tables, filtering, pagination, search.

Imports from db_core, contact, and msg_format.
"""

import hashlib
import re
import sqlite3
from contextlib import closing
from datetime import datetime

from wxdec.db_core import _cache, MSG_DB_KEYS
from wxdec.contact import resolve_username, get_contact_names, get_contact_full
from wxdec.msg_format import (
    _format_message_text, _decompress_content, _resolve_sender_label,
    _load_name2id_maps, format_msg_type,
)

# ============ Constants ============

_QUERY_LIMIT_MAX = 500
_HISTORY_QUERY_BATCH_SIZE = 500


# ============ Table discovery ============

def _is_safe_msg_table_name(table_name):
    return bool(re.fullmatch(r'Msg_[0-9a-f]{32}', table_name))


def _find_msg_table_for_user(username):
    """在所有 message_N.db 中查找用户的消息表，返回 (db_path, table_name)"""
    table_hash = hashlib.md5(username.encode()).hexdigest()
    table_name = f"Msg_{table_hash}"
    if not _is_safe_msg_table_name(table_name):
        return None, None

    for rel_key in MSG_DB_KEYS:
        path = _cache.get(rel_key)
        if not path:
            continue
        conn = sqlite3.connect(path)
        try:
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (table_name,)
            ).fetchone()
            if exists:
                conn.close()
                return path, table_name
        except Exception:
            pass
        finally:
            conn.close()

    return None, None


def _find_msg_tables_for_user(username):
    """返回用户在所有 message_N.db 中对应的消息表，按最新消息时间倒序排列。"""
    table_hash = hashlib.md5(username.encode()).hexdigest()
    table_name = f"Msg_{table_hash}"
    if not _is_safe_msg_table_name(table_name):
        return []

    matches = []
    for rel_key in MSG_DB_KEYS:
        path = _cache.get(rel_key)
        if not path:
            continue
        conn = sqlite3.connect(path)
        try:
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (table_name,)
            ).fetchone()
            if not exists:
                continue
            max_create_time = conn.execute(
                f"SELECT MAX(create_time) FROM [{table_name}]"
            ).fetchone()[0] or 0
            matches.append({
                'db_path': path,
                'table_name': table_name,
                'max_create_time': max_create_time,
            })
        except Exception:
            pass
        finally:
            conn.close()

    matches.sort(key=lambda item: item['max_create_time'], reverse=True)
    return matches


# ============ Pagination & time parsing ============

def _validate_pagination(limit, offset=0, limit_max=_QUERY_LIMIT_MAX):
    if limit <= 0:
        raise ValueError("limit 必须大于 0")
    if limit_max is not None and limit > limit_max:
        raise ValueError(f"limit 不能大于 {limit_max}")
    if offset < 0:
        raise ValueError("offset 不能小于 0")


def _parse_time_value(value, field_name, is_end=False):
    value = (value or '').strip()
    if not value:
        return None

    formats = [
        ('%Y-%m-%d %H:%M:%S', False),
        ('%Y-%m-%d %H:%M', False),
        ('%Y-%m-%d', True),
    ]
    for fmt, date_only in formats:
        try:
            dt = datetime.strptime(value, fmt)
            if date_only and is_end:
                dt = dt.replace(hour=23, minute=59, second=59)
            return int(dt.timestamp())
        except ValueError:
            continue

    raise ValueError(
        f"{field_name} 格式无效: {value}。支持 YYYY-MM-DD / YYYY-MM-DD HH:MM / YYYY-MM-DD HH:MM:SS"
    )


def _parse_time_range(start_time='', end_time=''):
    start_ts = _parse_time_value(start_time, 'start_time', is_end=False)
    end_ts = _parse_time_value(end_time, 'end_time', is_end=True)
    if start_ts is not None and end_ts is not None and start_ts > end_ts:
        raise ValueError('start_time 不能晚于 end_time')
    return start_ts, end_ts


# ============ Query building ============

def _build_message_filters(start_ts=None, end_ts=None, keyword='', type_filter=None):
    clauses = []
    params = []
    if start_ts is not None:
        clauses.append('create_time >= ?')
        params.append(start_ts)
    if end_ts is not None:
        clauses.append('create_time <= ?')
        params.append(end_ts)
    if keyword:
        clauses.append('message_content LIKE ?')
        params.append(f'%{keyword}%')
    if type_filter:
        placeholders = ','.join('?' * len(type_filter))
        clauses.append(f'(local_type & 0xFFFF) IN ({placeholders})')
        params.extend(type_filter)
    return clauses, params


def _query_messages(conn, table_name, start_ts=None, end_ts=None, keyword='', limit=20, offset=0, oldest_first=False, type_filter=None):
    if not _is_safe_msg_table_name(table_name):
        raise ValueError(f'非法消息表名: {table_name}')

    clauses, params = _build_message_filters(start_ts, end_ts, keyword, type_filter=type_filter)
    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ''
    order = 'ASC' if oldest_first else 'DESC'
    sql = f"""
        SELECT local_id, local_type, create_time, real_sender_id, message_content,
               WCDB_CT_message_content
        FROM [{table_name}]
        {where_sql}
        ORDER BY create_time {order}
    """
    if limit is None:
        return conn.execute(sql, params).fetchall()
    sql += "\n        LIMIT ? OFFSET ?"
    return conn.execute(sql, (*params, limit, offset)).fetchall()


# ============ Chat context resolution ============

def _resolve_chat_context(chat_name):
    username = resolve_username(chat_name)
    if not username:
        return None

    names = get_contact_names()
    display_name = names.get(username, username)
    message_tables = _find_msg_tables_for_user(username)
    if not message_tables:
        return {
            'query': chat_name,
            'username': username,
            'display_name': display_name,
            'db_path': None,
            'table_name': None,
            'message_tables': [],
            'is_group': '@chatroom' in username,
        }

    primary = message_tables[0]
    return {
        'query': chat_name,
        'username': username,
        'display_name': display_name,
        'db_path': primary['db_path'],
        'table_name': primary['table_name'],
        'message_tables': message_tables,
        'is_group': '@chatroom' in username,
    }


def _resolve_chat_contexts(chat_names):
    if not chat_names:
        raise ValueError('chat_names 不能为空')

    resolved = []
    unresolved = []
    missing_tables = []
    seen = set()

    for chat_name in chat_names:
        name = (chat_name or '').strip()
        if not name:
            unresolved.append('(空)')
            continue
        ctx = _resolve_chat_context(name)
        if not ctx:
            unresolved.append(name)
            continue
        if not ctx['message_tables']:
            missing_tables.append(ctx['display_name'])
            continue
        if ctx['username'] in seen:
            continue
        seen.add(ctx['username'])
        resolved.append(ctx)

    return resolved, unresolved, missing_tables


def _normalize_chat_names(chat_name):
    if chat_name is None:
        return []
    if isinstance(chat_name, str):
        value = chat_name.strip()
        return [value] if value else []
    if isinstance(chat_name, (list, tuple, set)):
        normalized = []
        for item in chat_name:
            if item is None:
                continue
            value = str(item).strip()
            if value:
                normalized.append(value)
        return normalized
    value = str(chat_name).strip()
    return [value] if value else []


# ============ History & search line builders ============

def _format_history_lines(rows, username, display_name, is_group, names, id_to_username):
    lines = []
    ctx = {
        'username': username,
        'display_name': display_name,
        'is_group': is_group,
    }
    for row in reversed(rows):
        _, line = _build_history_line(row, ctx, names, id_to_username)
        lines.append(line)
    return lines


def _build_search_entry(row, ctx, names, id_to_username):
    local_id, local_type, create_time, real_sender_id, content, ct = row
    content = _decompress_content(content, ct)
    if content is None:
        return None

    sender, text = _format_message_text(
        local_id, local_type, content, ctx['is_group'], ctx['username'], ctx['display_name'], names,
        create_time=create_time,
    )
    if text and len(text) > 300:
        text = text[:300] + '...'

    sender_label = _resolve_sender_label(
        real_sender_id,
        sender,
        ctx['is_group'],
        ctx['username'],
        ctx['display_name'],
        names,
        id_to_username,
    )
    time_str = datetime.fromtimestamp(create_time).strftime('%Y-%m-%d %H:%M')
    entry = f"[{time_str}] [{ctx['display_name']}]"
    if sender_label:
        entry += f" {sender_label}:"
    entry += f" {text}"
    return create_time, entry


def _build_history_line(row, ctx, names, id_to_username):
    local_id, local_type, create_time, real_sender_id, content, ct = row
    time_str = datetime.fromtimestamp(create_time).strftime('%Y-%m-%d %H:%M')
    content = _decompress_content(content, ct)
    if content is None:
        content = '(无法解压)'

    sender, text = _format_message_text(
        local_id, local_type, content, ctx['is_group'], ctx['username'], ctx['display_name'], names,
        create_time=create_time,
    )

    sender_label = _resolve_sender_label(
        real_sender_id, sender, ctx['is_group'], ctx['username'], ctx['display_name'], names, id_to_username
    )
    if sender_label:
        return create_time, f'[{time_str}] {sender_label}: {text}'
    return create_time, f'[{time_str}] {text}'


# ============ Table iteration helpers ============

def _get_chat_message_tables(ctx):
    if ctx.get('message_tables'):
        return ctx['message_tables']
    if ctx.get('db_path') and ctx.get('table_name'):
        return [{'db_path': ctx['db_path'], 'table_name': ctx['table_name']}]
    return []


def _iter_table_contexts(ctx):
    for table in _get_chat_message_tables(ctx):
        yield {
            'query': ctx['query'],
            'username': ctx['username'],
            'display_name': ctx['display_name'],
            'db_path': table['db_path'],
            'table_name': table['table_name'],
            'is_group': ctx['is_group'],
        }


# ============ Page size helpers ============

def _candidate_page_size(limit, offset):
    return limit + offset


def _message_query_batch_size(candidate_limit):
    return candidate_limit


def _history_query_batch_size(candidate_limit):
    return min(candidate_limit, _HISTORY_QUERY_BATCH_SIZE)


def _page_ranked_entries(entries, limit, offset, oldest_first=False):
    ordered = sorted(entries, key=lambda item: item[0], reverse=not oldest_first)
    paged = ordered[offset:offset + limit]
    paged.sort(key=lambda item: item[0])
    return paged


# ============ Collection functions ============

def _collect_chat_history_lines(ctx, names, start_ts=None, end_ts=None, limit=20, offset=0, oldest_first=False, type_filter=None):
    collected = []
    failures = []
    candidate_limit = _candidate_page_size(limit, offset)
    batch_size = _history_query_batch_size(candidate_limit)

    for table_ctx in _iter_table_contexts(ctx):
        try:
            with closing(sqlite3.connect(table_ctx['db_path'])) as conn:
                id_to_username = _load_name2id_maps(conn)
                fetch_offset = 0
                collected_before_table = len(collected)
                # 当前页上的消息一定落在各分表最近的 offset+limit 条记录内。
                while len(collected) - collected_before_table < candidate_limit:
                    rows = _query_messages(
                        conn,
                        table_ctx['table_name'],
                        start_ts=start_ts,
                        end_ts=end_ts,
                        limit=batch_size,
                        offset=fetch_offset,
                        oldest_first=oldest_first,
                        type_filter=type_filter,
                    )
                    if not rows:
                        break
                    fetch_offset += len(rows)

                    for row in rows:
                        try:
                            collected.append(_build_history_line(row, table_ctx, names, id_to_username))
                        except Exception as e:
                            failures.append(
                                f"{table_ctx['display_name']} local_id={row[0]} create_time={row[2]}: {e}"
                            )
                        if len(collected) - collected_before_table >= candidate_limit:
                            break

                    if len(rows) < batch_size:
                        break
        except Exception as e:
            failures.append(f"{table_ctx['db_path']}: {e}")

    paged = _page_ranked_entries(collected, limit, offset, oldest_first=oldest_first)
    return [line for _, line in paged], failures


def _collect_chat_search_entries(ctx, names, keyword, start_ts=None, end_ts=None, candidate_limit=20):
    collected = []
    failures = []
    contexts_by_db = {}
    for table_ctx in _iter_table_contexts(ctx):
        contexts_by_db.setdefault(table_ctx['db_path'], []).append(table_ctx)

    for db_path, db_contexts in contexts_by_db.items():
        try:
            with closing(sqlite3.connect(db_path)) as conn:
                db_entries, db_failures = _collect_search_entries(
                    conn,
                    db_contexts,
                    names,
                    keyword,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    candidate_limit=candidate_limit,
                )
                collected.extend(db_entries)
                failures.extend(db_failures)
        except Exception as e:
            failures.extend(f"{table_ctx['display_name']}: {e}" for table_ctx in db_contexts)

    return collected, failures


def _load_search_contexts_from_db(conn, db_path, names):
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'"
    ).fetchall()

    table_to_username = {}
    try:
        for (user_name,) in conn.execute("SELECT user_name FROM Name2Id").fetchall():
            if not user_name:
                continue
            table_hash = hashlib.md5(user_name.encode()).hexdigest()
            table_to_username[f"Msg_{table_hash}"] = user_name
    except sqlite3.Error:
        pass

    contexts = []
    for (table_name,) in tables:
        username = table_to_username.get(table_name, '')
        display_name = names.get(username, username) if username else table_name
        contexts.append({
            'query': display_name,
            'username': username,
            'display_name': display_name,
            'db_path': db_path,
            'table_name': table_name,
            'is_group': '@chatroom' in username,
        })
    return contexts


def _collect_search_entries(conn, contexts, names, keyword, start_ts=None, end_ts=None, candidate_limit=20):
    collected = []
    failures = []
    id_to_username = _load_name2id_maps(conn)
    batch_size = _message_query_batch_size(candidate_limit)

    for ctx in contexts:
        try:
            fetch_offset = 0
            collected_before_table = len(collected)
            # 全局分页只需要每个分表最新的 offset+limit 条有效命中，无需把整表命中读进内存。
            while len(collected) - collected_before_table < candidate_limit:
                rows = _query_messages(
                    conn,
                    ctx['table_name'],
                    start_ts=start_ts,
                    end_ts=end_ts,
                    keyword=keyword,
                    limit=batch_size,
                    offset=fetch_offset,
                )
                if not rows:
                    break
                fetch_offset += len(rows)

                for row in rows:
                    formatted = _build_search_entry(row, ctx, names, id_to_username)
                    if formatted:
                        collected.append(formatted)
                        if len(collected) - collected_before_table >= candidate_limit:
                            break

                if len(rows) < batch_size:
                    break
        except Exception as e:
            failures.append(f"{ctx['display_name']}: {e}")

    return collected, failures


def _page_search_entries(entries, limit, offset):
    return _page_ranked_entries(entries, limit, offset)


def _search_single_chat(ctx, keyword, start_ts, end_ts, start_time, end_time, limit, offset):
    names = get_contact_names()
    candidate_limit = _candidate_page_size(limit, offset)

    entries, failures = _collect_chat_search_entries(
        ctx,
        names,
        keyword,
        start_ts=start_ts,
        end_ts=end_ts,
        candidate_limit=candidate_limit,
    )

    paged = _page_search_entries(entries, limit, offset)

    if not paged:
        if failures:
            return "查询失败: " + "；".join(failures)
        return f"未在 {ctx['display_name']} 中找到包含 \"{keyword}\" 的消息"

    header = f"在 {ctx['display_name']} 中搜索 \"{keyword}\" 找到 {len(paged)} 条结果（offset={offset}, limit={limit}）"
    if start_time or end_time:
        header += f"\n时间范围: {start_time or '最早'} ~ {end_time or '最新'}"
    if failures:
        header += "\n查询失败: " + "；".join(failures)
    result = header + ":\n\n" + "\n\n".join(item[1] for item in paged)
    if len(paged) >= limit:
        result += f"\n\n（可能还有更多结果，可设 offset={offset + limit} 继续查询）"
    return result


def _search_multiple_chats(chat_names, keyword, start_ts, end_ts, start_time, end_time, limit, offset):
    try:
        resolved_contexts, unresolved, missing_tables = _resolve_chat_contexts(chat_names)
    except ValueError as e:
        return f"错误: {e}"

    if not resolved_contexts:
        details = []
        if unresolved:
            details.append("未找到联系人: " + "、".join(unresolved))
        if missing_tables:
            details.append("无消息表: " + "、".join(missing_tables))
        suffix = f"\n{chr(10).join(details)}" if details else ""
        return f"错误: 没有可查询的聊天对象{suffix}"

    names = get_contact_names()
    candidate_limit = _candidate_page_size(limit, offset)
    collected = []
    failures = []
    for ctx in resolved_contexts:
        chat_entries, chat_failures = _collect_chat_search_entries(
            ctx,
            names,
            keyword,
            start_ts=start_ts,
            end_ts=end_ts,
            candidate_limit=candidate_limit,
        )
        collected.extend(chat_entries)
        failures.extend(chat_failures)

    paged = _page_search_entries(collected, limit, offset)

    notes = []
    if unresolved:
        notes.append("未找到联系人: " + "、".join(unresolved))
    if missing_tables:
        notes.append("无消息表: " + "、".join(missing_tables))
    if failures:
        notes.append("查询失败: " + "；".join(failures))

    if not paged:
        header = f"在 {len(resolved_contexts)} 个聊天对象中未找到包含 \"{keyword}\" 的消息"
        if start_time or end_time:
            header += f"\n时间范围: {start_time or '最早'} ~ {end_time or '最新'}"
        if notes:
            header += "\n" + "\n".join(notes)
        return header

    header = (
        f"在 {len(resolved_contexts)} 个聊天对象中搜索 \"{keyword}\" 找到 {len(paged)} 条结果"
        f"（offset={offset}, limit={limit}）"
    )
    if start_time or end_time:
        header += f"\n时间范围: {start_time or '最早'} ~ {end_time or '最新'}"
    if notes:
        header += "\n" + "\n".join(notes)
    result = header + ":\n\n" + "\n\n".join(item[1] for item in paged)
    if len(paged) >= limit:
        result += f"\n\n（可能还有更多结果，可设 offset={offset + limit} 继续查询）"
    return result


def _search_all_messages(keyword, start_ts, end_ts, start_time, end_time, limit, offset):
    names = get_contact_names()
    collected = []
    failures = []
    candidate_limit = _candidate_page_size(limit, offset)

    for rel_key in MSG_DB_KEYS:
        path = _cache.get(rel_key)
        if not path:
            continue

        try:
            with closing(sqlite3.connect(path)) as conn:
                contexts = _load_search_contexts_from_db(conn, path, names)
                db_entries, db_failures = _collect_search_entries(
                    conn,
                    contexts,
                    names,
                    keyword,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    candidate_limit=candidate_limit,
                )
                collected.extend(db_entries)
                failures.extend(db_failures)
        except Exception as e:
            failures.append(f"{rel_key}: {e}")

    paged = _page_search_entries(collected, limit, offset)

    if not paged:
        header = f"未找到包含 \"{keyword}\" 的消息"
        if start_time or end_time:
            header += f"\n时间范围: {start_time or '最早'} ~ {end_time or '最新'}"
        if failures:
            header += "\n查询失败: " + "；".join(failures)
        return header

    header = f"搜索 \"{keyword}\" 找到 {len(paged)} 条结果（offset={offset}, limit={limit}）"
    if start_time or end_time:
        header += f"\n时间范围: {start_time or '最早'} ~ {end_time or '最新'}"
    if failures:
        header += "\n查询失败: " + "；".join(failures)
    result = header + ":\n\n" + "\n\n".join(item[1] for item in paged)
    if len(paged) >= limit:
        result += f"\n\n（可能还有更多结果，可设 offset={offset + limit} 继续查询）"
    return result
