#!/usr/bin/env python3
"""Real-time WeChat private message watcher for Claude Code Agent.

Designed to be launched via Claude Code's Monitor tool so the Agent
receives a notification (with full chat context) whenever a private
contact sends a new message — enabling conversational assistance,
auto-reply drafting, or any other agent-driven workflow.

Mechanism:
  - FSEvents (watchdog) detects session.db writes in near-real-time,
    with a long-interval poll as safety net.
  - Only private contacts (local_type=1, verify_flag=0) are monitored;
    group chats, service accounts, and system messages are excluded.
  - Each notification includes the last 50 messages of chat history.
  - Image messages are auto-decoded to local files (image_path).
  - Voice messages are decoded to WAV (voice_path, voice_duration_s).
  - Semantic interpretation (voice transcription, image description)
    is left to the consuming Agent via MCP tools.

Usage:
  uv run --with watchdog --with silk-python python scripts/watch_messages.py

Output: one JSON line per new incoming message to stdout, prefixed [NEW].
"""

import argparse
import json
import os
import sqlite3
import sys
import threading
from contextlib import closing
from datetime import datetime, timezone

import zstandard as zstd
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import io
import re
import wave

from wxdec.db_core import (
    _cache, _cfg, DB_DIR, DECRYPTED_DIR, WECHAT_BASE_DIR,
    DECODED_IMAGE_DIR, ALL_KEYS, open_db_readonly,
)
from wxdec.msg_query import (
    _find_msg_table_for_user,
    _resolve_chat_context,
    _collect_chat_history_lines,
)
from wxdec.msg_format import _load_name2id_maps
from wxdec.decode_image import ImageResolver
from wxdec.key_utils import key_path_variants

HISTORY_LINES = 50

_zstd_dctx = zstd.ZstdDecompressor()

MSG_TYPE_NAMES = {
    1: "文本", 3: "图片", 34: "语音", 42: "名片",
    43: "视频", 47: "表情", 48: "位置", 49: "链接/文件",
    50: "通话", 10000: "系统", 10002: "撤回",
}

# Built-in WeChat tools and system aggregators — not real private chats.
_BUILTIN_TOOL_USERNAMES = frozenset({
    "filehelper", "medianote", "weixin", "tmessage",
    "blogapp", "notification_messages", "notifymessage",
    "brandsessionholder",       # 公众号 aggregator
    "brandservicesessionholder",
    "fmessage", "floatbottle",
    "qmessage", "qqsync", "mphelper", "newsapp",
    "voipchat", "voicevoipnotifier",
    "qqfriend", "qqmail",
})


_image_resolver = ImageResolver(
    WECHAT_BASE_DIR, DECODED_IMAGE_DIR, _cache,
    aes_key=_cfg.get("image_aes_key"),
    xor_key=_cfg.get("image_xor_key", 0x88),
)

DECODED_VOICE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "wxdec", "decoded_voices",
)

MEDIA_DB_KEYS = sorted([
    k for k in ALL_KEYS
    if any(v.startswith("message/") for v in key_path_variants(k))
    and any(re.search(r"media_\d+\.db$", v) for v in key_path_variants(k))
])


def _iter_media_db_paths():
    for rel_key in MEDIA_DB_KEYS:
        path = _cache.get(rel_key)
        if path:
            yield path


def _get_chat_name_id(conn, username):
    row = conn.execute(
        "SELECT rowid FROM Name2Id WHERE user_name = ?", (username,)
    ).fetchone()
    return row[0] if row else None


def load_private_chat_whitelist():
    """Return the set of usernames representing real private contacts —
    matching what WeChat's UI shows under "联系人".

    Filter: contact.local_type = 1 AND verify_flag = 0
      - local_type=1 distinguishes actively-added contacts from group-only
        acquaintances (local_type=3, ~107k entries)
      - verify_flag=0 excludes public/service accounts that carry a badge
    Plus: exclude @chatroom, gh_*, and built-in tools (filehelper etc.).
    """
    db_path = _contact_db_path()
    if not db_path:
        return set()
    whitelist = set()
    with closing(sqlite3.connect(db_path)) as conn:
        rows = conn.execute(
            "SELECT username FROM contact "
            "WHERE local_type = 1 AND verify_flag = 0"
        )
        for (un,) in rows:
            if not un:
                continue
            if "@chatroom" in un:
                continue
            if un.startswith("gh_"):
                continue
            if un in _BUILTIN_TOOL_USERNAMES:
                continue
            whitelist.add(un)
    return whitelist


# Resolve self username from db_dir path (e.g. ".../xwechat_files/<wxid>_<hash>/...").
def _resolve_self_username():
    account_dir = os.path.basename(os.path.dirname(DB_DIR))
    candidates = [account_dir]
    m = re.fullmatch(r"(.+)_([0-9a-fA-F]{4,})", account_dir)
    if m:
        candidates.insert(0, m.group(1))
    # Verify candidate exists in contact.db.
    db_path = _contact_db_path()
    if not db_path:
        return ""
    with closing(sqlite3.connect(db_path)) as conn:
        for cand in candidates:
            if not cand:
                continue
            row = conn.execute("SELECT 1 FROM contact WHERE username = ?", (cand,)).fetchone()
            if row:
                return cand
    return ""


_SELF_USERNAME = None


def _get_self_username():
    global _SELF_USERNAME
    if _SELF_USERNAME is None:
        _SELF_USERNAME = _resolve_self_username() or ""
    return _SELF_USERNAME


def _fetch_chat_history(username, names):
    """Return the last HISTORY_LINES messages for this chat, oldest-first,
    so Claude has full conversational context bundled in the notification
    without needing a separate MCP round-trip."""
    try:
        ctx = _resolve_chat_context(username)
        if not ctx:
            return []
        # oldest_first=False fetches the most-recent N rows by DESC order;
        # the underlying pager then re-sorts the slice chronologically.
        lines, _failures = _collect_chat_history_lines(
            ctx, names, limit=HISTORY_LINES, oldest_first=False
        )
        return lines
    except Exception as e:
        return [f"(history fetch failed: {e})"]


def _last_message_info(username):
    """Return (sender_wxid, local_id, local_type) for the latest message.

    Returns ("", 0, 0) if the message table or sender cannot be located.
    """
    db_path, table_name = _find_msg_table_for_user(username)
    if not db_path or not table_name:
        return "", 0, 0
    with closing(sqlite3.connect(db_path)) as conn:
        id_map = _load_name2id_maps(conn)
        row = conn.execute(
            f"SELECT real_sender_id, local_id, local_type "
            f"FROM [{table_name}] ORDER BY create_time DESC LIMIT 1"
        ).fetchone()
        if not row:
            return "", 0, 0
        real_sender_id, local_id, local_type = row
    return id_map.get(real_sender_id, ""), local_id or 0, local_type or 0


def _try_decode_image(username, local_id):
    try:
        result = _image_resolver.decode_image(username, local_id)
        if result["success"]:
            return result["path"]
    except Exception:
        pass
    return None


def _try_decode_voice(username, local_id):
    try:
        import pysilk
    except ImportError:
        return None, None
    for media_db in _iter_media_db_paths():
        try:
            with closing(open_db_readonly(media_db)) as conn:
                cid = _get_chat_name_id(conn, username)
                if cid is None:
                    continue
                row = conn.execute(
                    "SELECT voice_data, create_time FROM VoiceInfo "
                    "WHERE chat_name_id = ? AND local_id = ?",
                    (cid, local_id),
                ).fetchone()
                if not row:
                    continue
                voice_data, create_time = row
                data = bytes(voice_data)
                silk_data = data[1:] if data[0] == 0x02 else data
                os.makedirs(DECODED_VOICE_DIR, exist_ok=True)
                time_str = datetime.fromtimestamp(create_time).strftime("%Y%m%d_%H%M%S")
                out_path = os.path.join(
                    DECODED_VOICE_DIR, f"{username}_{time_str}_{local_id}.wav"
                )
                inp = io.BytesIO(silk_data)
                out = io.BytesIO()
                pysilk.decode(inp, out, 24000)
                pcm = out.getvalue()
                with wave.open(out_path, "wb") as wf:
                    wf.setnchannels(1)
                    wf.setsampwidth(2)
                    wf.setframerate(24000)
                    wf.writeframes(pcm)
                return out_path, len(pcm) / 2 / 24000
        except Exception:
            continue
    return None, None



def _format_msg_type(t):
    try:
        t = int(t)
    except (TypeError, ValueError):
        return f"type={t}"
    base = t & 0xFFFFFFFF if t > 0xFFFFFFFF else t
    return MSG_TYPE_NAMES.get(base, f"type={t}")


def _contact_db_path():
    """Always use the live cache (mtime-refreshed) — the pre-decrypted
    copy in DECRYPTED_DIR can lag behind newly-added friends."""
    return _cache.get(os.path.join("contact", "contact.db"))


def _invalidate_cache(rel_key):
    """Force DBCache to re-decrypt this DB on next .get() call.

    Used when SQLite reports a malformed image — usually means we
    decrypted the source file while WeChat was mid-write.
    """
    entry = _cache._cache.pop(rel_key, None)
    if entry:
        _, _, tmp_path = entry
        try:
            os.remove(tmp_path)
        except OSError:
            pass


def load_contact_names():
    db_path = _contact_db_path()
    if not db_path:
        return {}
    names = {}
    with closing(sqlite3.connect(db_path)) as conn:
        for uname, nick, remark in conn.execute(
            "SELECT username, nick_name, remark FROM contact"
        ):
            names[uname] = remark or nick or uname
    return names


def _decompress_summary(summary):
    if isinstance(summary, bytes):
        try:
            summary = _zstd_dctx.decompress(summary).decode("utf-8", errors="replace")
        except Exception:
            return "(compressed)"
    if isinstance(summary, str) and ":\n" in summary:
        summary = summary.split(":\n", 1)[1]
    return summary or ""


def poll_session_db():
    path = _cache.get(os.path.join("session", "session.db"))
    if not path:
        return {}
    with closing(sqlite3.connect(path)) as conn:
        rows = conn.execute(
            """SELECT username, unread_count, summary, last_timestamp,
                      last_msg_type, last_msg_sender, last_sender_display_name
               FROM SessionTable
               WHERE last_timestamp > 0
               ORDER BY last_timestamp DESC"""
        ).fetchall()
    state = {}
    for r in rows:
        username, unread, summary, ts, msg_type, sender, sender_name = r
        state[username] = {
            "timestamp": ts,
            "unread": unread or 0,
            "summary": summary,
            "msg_type": msg_type,
            "sender": sender or "",
            "sender_name": sender_name or "",
        }
    return state


def detect_new_activity(prev_state, curr_state, private_whitelist):
    results = []
    self_un = _get_self_username()
    for username, s in curr_state.items():
        if username not in private_whitelist:
            continue
        prev_ts = prev_state.get(username, {}).get("timestamp", 0)
        if s["timestamp"] <= prev_ts:
            continue
        sender, local_id, local_type = _last_message_info(username)
        if sender and self_un and sender == self_un:
            continue
        if sender and sender != username:
            continue
        results.append({
            "username": username,
            "timestamp": s["timestamp"],
            "summary": _decompress_summary(s["summary"]),
            "msg_type": _format_msg_type(s["msg_type"]),
            "local_id": local_id,
            "local_type": local_type,
        })
    return results


class _SessionDBHandler(FileSystemEventHandler):
    """Wake the main thread whenever session.db or its WAL is touched."""

    def __init__(self, wake_event):
        self._wake = wake_event

    def _is_session_db(self, path):
        base = os.path.basename(path)
        return base == "session.db" or base.startswith("session.db-")

    def on_any_event(self, event):
        if event.is_directory:
            return
        if self._is_session_db(event.src_path):
            self._wake.set()


def _run_check(prev_state, whitelist, names_holder):
    """Run one detection pass. Returns (new_msgs, curr_state_or_None)."""
    try:
        curr_state = poll_session_db()
        new_msgs = detect_new_activity(prev_state, curr_state, whitelist)
        return new_msgs, curr_state
    except sqlite3.DatabaseError as e:
        if "malformed" in str(e):
            _invalidate_cache(os.path.join("session", "session.db"))
            _invalidate_cache(os.path.join("contact", "contact.db"))
            print(f"[watcher] recovered from malformed DB: {e}", flush=True)
        else:
            print(f"[watcher] db error: {e}", flush=True)
        return [], None
    except Exception as e:
        print(f"[watcher] error: {e}", flush=True)
        return [], None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fallback-interval", type=int, default=30,
                        help="Safety-net poll interval (s) when FSEvents stays quiet.")
    parser.add_argument("--debounce", type=float, default=1.0,
                        help="Coalesce bursts of writes by waiting this many "
                             "seconds after the last event before querying.")
    args = parser.parse_args()

    names = load_contact_names()
    whitelist = load_private_chat_whitelist()
    prev_state = poll_session_db()
    print(
        f"[watcher] fsevents+debounce={args.debounce}s, "
        f"fallback poll={args.fallback_interval}s",
        flush=True,
    )
    print(
        f"[watcher] initial state: {len(prev_state)} sessions, "
        f"{len(whitelist)} private contacts whitelisted, "
        f"self={_get_self_username()!r}",
        flush=True,
    )

    wake = threading.Event()
    handler = _SessionDBHandler(wake)
    session_dir = os.path.join(DB_DIR, "session")
    observer = Observer()
    observer.schedule(handler, session_dir, recursive=False)
    observer.start()
    print(f"[watcher] FSEvents watching {session_dir}", flush=True)

    try:
        while True:
            triggered = wake.wait(timeout=args.fallback_interval)
            if triggered:
                # Debounce: keep absorbing writes until the bus quiets down.
                while True:
                    wake.clear()
                    if not wake.wait(timeout=args.debounce):
                        break

            new_msgs, curr_state = _run_check(prev_state, whitelist, names)
            if curr_state is not None:
                prev_state = curr_state
            if new_msgs:
                names = load_contact_names()
                for msg in new_msgs:
                    msg["contact"] = names.get(msg["username"], msg["username"])
                    msg["time"] = datetime.fromtimestamp(
                        msg["timestamp"], tz=timezone.utc
                    ).strftime("%H:%M:%S UTC")
                    msg["history"] = _fetch_chat_history(msg["username"], names)
                    lt = msg.pop("local_type", 0)
                    lid = msg.pop("local_id", 0)
                    base_type = lt & 0xFFFFFFFF if lt > 0xFFFFFFFF else lt
                    if base_type == 3 and lid:
                        path = _try_decode_image(msg["username"], lid)
                        if path:
                            msg["image_path"] = path
                    elif base_type == 34 and lid:
                        wav_path, duration = _try_decode_voice(msg["username"], lid)
                        if wav_path:
                            msg["voice_path"] = wav_path
                            msg["voice_duration_s"] = round(duration, 1)
                    print(f'[NEW] {json.dumps(msg, ensure_ascii=False)}', flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join(timeout=2)


if __name__ == "__main__":
    main()
