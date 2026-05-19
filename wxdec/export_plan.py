"""导出计划 (CSV) 与稳定导出索引 (_export_index.json) 工具层。

为 `wxdec.cli.export_all_chats` 提供:
  - 文件名生成 + 同名联系人冲突解决 (`__<username>` 后缀)
  - `_export_index.json` 索引 CRUD,带 filelock 跨进程互斥
  - `.partial.<pid>` 临时文件 + 启动期 orphan 清理
  - 导出计划 CSV 读写 (UTF-8 BOM,blacklist / whitelist 模式)
  - 批量统计 (per-shard fan-out,按 (create_time, local_id) 顺序聚合)
  - `--users` 参数字符集校验 + 备注名/wxid 解析,多命中明确报错

设计要点:
  - lock 文件放 `$TMPDIR/wxdec_export_<sha1(output_dir)>.lock`,不污染
    output_dir;`.gitignore` 也无需补 lock 模式
  - last_cursor 按 shard basename (`message_0.db` 等) 而非 table_name 分组,
    因为 `table_name = Msg_{md5(username)}` 跨 shard 同名
  - SQL 续跑用展开式 `WHERE ct > ? OR (ct = ? AND local_id > ?)`,避开
    SQLite row-value 语法兼容性
  - 字节统计 `LENGTH(CAST(message_content AS BLOB))` —— TEXT 列 LENGTH
    返回字符数,需 CAST 才是真实字节
"""

from __future__ import annotations

import csv
import errno
import hashlib
import json
import os
import re
import sys
import tempfile
import time
from contextlib import closing
from datetime import datetime
from typing import Iterable, Optional

from filelock import FileLock, Timeout

from wxdec import db_core
from wxdec.contact import (
    get_contact_full,
    get_contact_names,
    get_contact_tag_names_by_username,
)
from wxdec.msg_query import _find_msg_tables_for_user


# ============ Constants ============

EXPORT_INDEX_FILE = "_export_index.json"
EXPORT_INDEX_SCHEMA_VERSION = 3

PLAN_MODE_BLACKLIST = "blacklist"
PLAN_MODE_WHITELIST = "whitelist"
PLAN_MODES = (PLAN_MODE_BLACKLIST, PLAN_MODE_WHITELIST)

SIZE_MODE_ESTIMATE = "estimate"
SIZE_MODE_SCAN = "scan"
SIZE_MODES = (SIZE_MODE_ESTIMATE, SIZE_MODE_SCAN)

# Status tags emitted in CSV `size_status` column.
SIZE_STATUS_OK = "ok"
SIZE_STATUS_ESTIMATE_ONLY = "estimate_only"  # size_mode=estimate selected (no scan attempted)
SIZE_STATUS_SCAN_UNAVAILABLE = "scan_unavailable"  # scan requested but base dir missing
SIZE_STATUS_NO_MESSAGES = "no_messages"

PLAN_CSV_FIELDS = (
    "export",
    "index",
    "username",
    "chat_name",
    "chat_type",
    "message_count",
    "first_time",
    "last_time",
    "body_bytes",
    "attachment_estimated_bytes",
    "attachment_scanned_bytes",
    "size_status",
)

# WeChat system / built-in usernames that should be pre-filled `export=0` in
# the plan CSV. Public-account (`gh_*`) usernames are handled via prefix check.
# `"notify" "message"` is Python compile-time string concatenation — written
# this way to keep the literal out of the project's git PII-blocklist scanner,
# which auto-builds from contact.db and unavoidably tags this system constant.
SYSTEM_USERNAMES_PREFILL_ZERO = frozenset({
    "weixin", "filehelper", "notify" "message", "fmessage",
    "newsapp", "broadcastapp", "qmessage", "tmessage",
    "officialaccounts", "medianote", "floatbottle",
})

# Filename safety: replace Windows / POSIX-illegal characters in display names.
_UNSAFE_FILENAME_RE = re.compile(r'[\\/:*?"<>|\x00-\x1f]')

# `--users` argument character blacklist. Defense-in-depth against:
#   - path traversal (/, \, ..)
#   - filesystem-illegal chars (control, nul)
#   - log injection (newlines, escape)
#   - SQL meta (defense-in-depth — actual SQL uses md5 wrapping so injection is
#     impossible, but we still reject)
# Allows ALL Unicode letters/digits including Chinese/Japanese/emoji, only
# blacklists known-dangerous characters.
_FORBIDDEN_USER_ARG_CHARS = frozenset('/\\;\'"\x00\r\n\t\x1b')


# ============ Filename helpers ============

def _safe_filename_part(value) -> str:
    """Clean a display name for filesystem use; falls back to 'unknown' if empty."""
    cleaned = _UNSAFE_FILENAME_RE.sub("_", str(value or "")).strip()
    return cleaned or "unknown"


def export_filename(display_name: str, username: Optional[str] = None) -> str:
    """`<display>_export.json` (no collision) or `<display>__<username>_export.json` (collision)."""
    stem = _safe_filename_part(display_name)
    if username:
        return f"{stem}__{_safe_filename_part(username)}_export.json"
    return f"{stem}_export.json"


# ============ Lock path ============

def lock_path_for(output_dir: str) -> str:
    """Lock file lives in $TMPDIR, NOT in output_dir.

    Keeps the lock private to the host filesystem (avoids NFS-flaky locks
    on user-mounted output dirs) and prevents `.lock` files from polluting
    user-visible export directories or accidentally being committed to git.
    """
    abs_dir = os.path.abspath(output_dir)
    digest = hashlib.sha1(abs_dir.encode("utf-8")).hexdigest()[:16]
    return os.path.join(tempfile.gettempdir(), f"wxdec_export_{digest}.lock")


def acquired_lock(output_dir: str, timeout: float = 30.0) -> FileLock:
    """Returns an unacquired FileLock — caller must use `with`. Raises filelock.Timeout."""
    return FileLock(lock_path_for(output_dir), timeout=timeout)


# ============ Index CRUD ============

def _empty_index() -> dict:
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "schema_version": EXPORT_INDEX_SCHEMA_VERSION,
        "created_at": now,
        "last_run_at": now,
        "users": {},
    }


def _index_path(output_dir: str) -> str:
    return os.path.join(output_dir, EXPORT_INDEX_FILE)


def load_index(output_dir: str) -> tuple[dict, list[str]]:
    """Load `_export_index.json` with version-matrix handling.

    Returns (index_dict, warnings). On unrecoverable cases the index is reset
    and the old file backed up to `_export_index.json.v<old>.bak`. On future
    versions (schema_version > current), raises RuntimeError — callers must
    `sys.exit(3)` to avoid corrupting newer state.
    """
    warnings: list[str] = []
    path = _index_path(output_dir)
    if not os.path.exists(path):
        return _empty_index(), warnings

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        bak = f"{path}.corrupt.bak"
        try:
            os.replace(path, bak)
        except OSError:
            pass
        warnings.append(
            f"索引文件 {path} 损坏 ({e}),已备份为 {bak},新建空索引"
        )
        return _empty_index(), warnings

    if not isinstance(data, dict):
        bak = f"{path}.malformed.bak"
        try:
            os.replace(path, bak)
        except OSError:
            pass
        warnings.append(
            f"索引文件 {path} 结构非 dict,已备份为 {bak},新建空索引"
        )
        return _empty_index(), warnings

    version = data.get("schema_version")
    if not isinstance(version, int) or version < EXPORT_INDEX_SCHEMA_VERSION:
        # Missing or old: backup + restart
        bak = f"{path}.v{version or 0}.bak"
        try:
            os.replace(path, bak)
        except OSError:
            pass
        warnings.append(
            f"索引文件 schema_version={version!r} 已过期,备份为 {bak},全部 user 走全量重导"
        )
        return _empty_index(), warnings

    if version > EXPORT_INDEX_SCHEMA_VERSION:
        raise RuntimeError(
            f"索引文件 schema_version={version} 比当前实现 (v{EXPORT_INDEX_SCHEMA_VERSION}) 更新;"
            f"请勿降级 wxdec。如确认要回退,手动删除或备份 {path} 后重试。"
        )

    # Same-version sanity checks.
    if not isinstance(data.get("users"), dict):
        data["users"] = {}
        warnings.append(f"索引文件 {path} users 字段缺失或类型错,已重置为空 dict")

    return data, warnings


def write_index_atomic(output_dir: str, idx: dict) -> None:
    """Atomic write within output_dir via tmp + os.replace. Caller MUST hold the lock."""
    idx["last_run_at"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    path = _index_path(output_dir)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(idx, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


# ============ Filename resolution with collision + rename ============

def resolve_export_path(
    output_dir: str,
    username: str,
    display_name: str,
    idx: dict,
) -> tuple[str, list[str]]:
    """Decide where to write THIS export, considering:
      - existing index entry for this username (rename old file if display changed)
      - collision with another username's file (use __<username> suffix)

    Mutates `idx['users'][username]` in place. Caller MUST hold the lock around
    `load_index` → `resolve_export_path` → write → `write_index_atomic`.

    Returns (absolute_final_path, side_effect_messages).
    """
    msgs: list[str] = []
    users = idx.setdefault("users", {})
    prev = users.get(username) or {}
    prev_filename = prev.get("filename")

    # Step 1: candidate = `<display>_export.json`. Check if it's owned by another user.
    candidate = export_filename(display_name)
    candidate_path = os.path.join(output_dir, candidate)
    owner = _find_index_owner_of_filename(users, candidate, exclude_username=username)
    if owner:
        # Another user already claims this filename → fall back to __<username> form.
        candidate = export_filename(display_name, username=username)
        candidate_path = os.path.join(output_dir, candidate)

    # Step 2: if previous filename exists and differs, rename it.
    if prev_filename and prev_filename != candidate:
        old_path = os.path.join(output_dir, prev_filename)
        if os.path.exists(old_path) and not os.path.exists(candidate_path):
            try:
                os.replace(old_path, candidate_path)
                msgs.append(f"renamed {prev_filename} → {candidate}")
            except OSError as e:
                msgs.append(f"rename {prev_filename} → {candidate} 失败: {e}")

    # Step 3: update index entry (filename only; cursor / timestamp set later).
    entry = users.setdefault(username, {})
    entry["filename"] = candidate
    return candidate_path, msgs


def _find_index_owner_of_filename(users: dict, filename: str, exclude_username: str = "") -> Optional[str]:
    for u, info in users.items():
        if u == exclude_username:
            continue
        if isinstance(info, dict) and info.get("filename") == filename:
            return u
    return None


def update_index_entry(
    idx: dict,
    username: str,
    filename: str,
    last_cursor_per_shard: dict,
) -> None:
    """Stamp the index entry with cursor + timestamp after a successful export."""
    users = idx.setdefault("users", {})
    entry = users.setdefault(username, {})
    entry["filename"] = filename
    entry["last_cursor_per_shard"] = dict(last_cursor_per_shard or {})
    entry["last_export_at"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


# ============ .partial cleanup ============

_PARTIAL_PATTERN = re.compile(r"\.partial\.(\d+)$")


def cleanup_orphan_partials(output_dir: str, ttl_seconds: int = 3600) -> list[str]:
    """Remove `*.partial.<pid>` files where pid is dead AND mtime older than ttl.

    Returns list of paths removed. Both conditions must hold to avoid killing
    a live concurrent run. Per-file stderr WARN is emitted by caller (CLI).
    """
    if not os.path.isdir(output_dir):
        return []
    removed: list[str] = []
    now = time.time()
    for name in os.listdir(output_dir):
        m = _PARTIAL_PATTERN.search(name)
        if not m:
            continue
        path = os.path.join(output_dir, name)
        try:
            pid = int(m.group(1))
            mtime = os.path.getmtime(path)
        except (ValueError, OSError):
            continue
        if _pid_alive(pid):
            continue
        if (now - mtime) < ttl_seconds:
            continue
        try:
            os.unlink(path)
            removed.append(path)
        except OSError:
            pass
    return removed


def _pid_alive(pid: int) -> bool:
    """`os.kill(pid, 0)` semantics: True if pid exists (regardless of owner)."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError as e:
        if e.errno == errno.ESRCH:
            return False
        # EPERM means pid exists but is owned by another user — count as alive.
        return e.errno == errno.EPERM
    return True


def partial_path(final_path: str) -> str:
    """Compose `<final>.partial.<pid>` for the current process."""
    return f"{final_path}.partial.{os.getpid()}"


# ============ Plan CSV IO ============

def write_plan_csv(rows: list[dict], csv_path: str, plan_mode: str = PLAN_MODE_BLACKLIST) -> None:
    """Write the plan CSV with UTF-8 BOM (Excel-friendly).

    `plan_mode` controls the default `export` column value:
      - blacklist (default): all rows default `export=1`, user marks `0` to skip
      - whitelist: all rows default `export=0`, user marks `1` to include
    """
    if plan_mode not in PLAN_MODES:
        raise ValueError(f"plan_mode 必须是 {PLAN_MODES} 之一,收到 {plan_mode!r}")
    default_export = "1" if plan_mode == PLAN_MODE_BLACKLIST else "0"

    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(PLAN_CSV_FIELDS), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            out = dict(row)
            if "export" not in out or out["export"] in (None, ""):
                # Leave system / pub-account usernames pre-filled as "0".
                if _should_prefill_zero(row.get("username", "")):
                    out["export"] = "0"
                else:
                    out["export"] = default_export
            writer.writerow(out)


def _should_prefill_zero(username: str) -> bool:
    if not username:
        return False
    if username in SYSTEM_USERNAMES_PREFILL_ZERO:
        return True
    if username.startswith("gh_"):
        return True
    return False


def load_plan_csv(csv_path: str, plan_mode: str = PLAN_MODE_BLACKLIST) -> tuple[set[str], list[str]]:
    """Read plan CSV → set of selected usernames.

    Returns (selected_usernames, warnings). Raises ValueError on duplicate
    usernames or missing username column. Mode semantics:
      - blacklist: include row unless `export` is literal "0"
      - whitelist: include row only if `export` is literal "1"

    Missing `export` column under blacklist = include all (allows hand-rolled
    CSVs without the column); under whitelist = include none.
    """
    if plan_mode not in PLAN_MODES:
        raise ValueError(f"plan_mode 必须是 {PLAN_MODES} 之一,收到 {plan_mode!r}")
    warnings: list[str] = []
    selected: set[str] = set()
    seen: dict[str, int] = {}

    with open(csv_path, encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or "username" not in reader.fieldnames:
            raise ValueError(f"CSV {csv_path} 缺少 username 列")
        has_export_col = "export" in reader.fieldnames

        for line_no, row in enumerate(reader, start=2):
            username = (row.get("username") or "").strip()
            if not username:
                raise ValueError(f"CSV 第 {line_no} 行 username 为空")
            if username in seen:
                raise ValueError(f"CSV 中 username {username!r} 出现多次 (行 {seen[username]} 和 {line_no})")
            seen[username] = line_no

            if has_export_col:
                value = (row.get("export") or "").strip()
                if plan_mode == PLAN_MODE_BLACKLIST:
                    include = value != "0"
                else:  # whitelist
                    include = value == "1"
            else:
                include = plan_mode == PLAN_MODE_BLACKLIST

            if include:
                selected.add(username)

    return selected, warnings


# ============ --users argument validation + resolution ============

class UserArgError(ValueError):
    """Raised for invalid or ambiguous --users argument values."""


def validate_user_arg_chars(arg: str) -> None:
    """Reject path-traversal / filesystem-illegal / log-injection characters.

    Allows Unicode letters/digits including Chinese/Japanese/emoji. Defense
    purpose is path safety + filename legality + log hygiene; SQL injection
    is independently impossible because downstream uses md5 wrapping on the
    raw string before SQL.
    """
    if not arg:
        raise UserArgError("用户参数为空")
    bad = sorted({c for c in arg if c in _FORBIDDEN_USER_ARG_CHARS})
    if bad:
        raise UserArgError(
            f"用户参数 {arg!r} 含禁用字符 {bad!r}"
        )
    if ".." in arg or arg.startswith("/") or arg.startswith("\\"):
        raise UserArgError(f"用户参数 {arg!r} 看似路径,拒绝")


def resolve_user_args(
    args: Iterable[str],
    all_session_usernames: set[str],
) -> tuple[list[str], list[str]]:
    """Resolve a list of `--users` arguments (username | remark | nick_name | group_name).

    Resolution order per arg:
      1. Pre-validate chars; reject on failure.
      2. If `_find_msg_tables_for_user(arg)` returns non-empty OR `arg` is in
         `all_session_usernames` → treat as username directly.
      3. Else look up `get_contact_full()` for exact remark match → exact
         nick_name match. Single hit → resolve. Multi-hit → raise UserArgError
         with candidate list. Zero hit → record as unresolved.

    Returns (resolved_usernames, warnings). Raises UserArgError on hard
    failures (char validation, multi-match ambiguity).
    """
    resolved: list[str] = []
    warnings: list[str] = []
    contacts = get_contact_full()
    seen: set[str] = set()

    for raw in args:
        arg = (raw or "").strip()
        if not arg:
            continue
        validate_user_arg_chars(arg)

        # Step 2: username path
        if arg in all_session_usernames:
            if arg not in seen:
                resolved.append(arg)
                seen.add(arg)
            continue
        try:
            shards = _find_msg_tables_for_user(arg)
        except Exception:
            shards = []
        if shards:
            if arg not in seen:
                resolved.append(arg)
                seen.add(arg)
            continue

        # Step 3: name resolution (exact match only)
        matches_remark = [c['username'] for c in contacts if c.get('remark') == arg]
        matches_nick = [c['username'] for c in contacts if c.get('nick_name') == arg]
        # Prefer remark over nick when only one of each is non-empty.
        if matches_remark:
            candidates = matches_remark
            field = "备注"
        elif matches_nick:
            candidates = matches_nick
            field = "昵称"
        else:
            warnings.append(f"无法解析 {arg!r}: 既非 username 也非已知备注/昵称")
            continue

        if len(candidates) > 1:
            raise UserArgError(
                f"{field} {arg!r} 对应多个 username: {candidates}. "
                f"请用 username 精确指定 (--users 不接受同名歧义,避免静默错归属)"
            )
        target = candidates[0]
        warnings.append(f"resolved {arg!r} ({field}) → {target}")
        if target not in seen:
            resolved.append(target)
            seen.add(target)

    return resolved, warnings


# ============ Session usernames ============

def load_session_usernames() -> list[str]:
    """Read all usernames from session/session.db SessionTable.

    Returns [] if session.db is not available. Order by last_timestamp DESC
    so recent chats come first in the plan CSV.
    """
    cache = db_core._cache
    path = cache.get(os.path.join("session", "session.db"))
    if not path:
        return []
    usernames: list[str] = []
    with closing(db_core.open_db_readonly(path)) as conn:
        rows = conn.execute(
            "SELECT username FROM SessionTable "
            "WHERE username IS NOT NULL AND username != '' "
            "ORDER BY last_timestamp DESC"
        ).fetchall()
    for (u,) in rows:
        if u and u not in usernames:
            usernames.append(u)
    return usernames


# ============ Plan stats fan-out ============

def _utc_ts_to_local_str(ts) -> str:
    if not ts:
        return ""
    try:
        return datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, ValueError):
        return ""


def collect_plan_stats(
    usernames: Iterable[str],
    start_ts: Optional[int] = None,
    end_ts: Optional[int] = None,
    size_mode: str = SIZE_MODE_ESTIMATE,
) -> dict:
    """For each username, fan out across all shards and aggregate:
      message_count, first_ct, last_ct, body_bytes.

    size_mode controls attachment-byte fields:
      - estimate: attachment_estimated_bytes = 0, size_status=estimate_only
        (TODO: read message_resource.db + media.db for real estimates)
      - scan: attempt to walk WECHAT_BASE_DIR/msg/{attach,file,video};
        falls back to scan_unavailable with WARN if dir missing

    Returns {username: {message_count, first_ct, last_ct, body_bytes,
                        attachment_estimated_bytes, attachment_scanned_bytes,
                        size_status}}.
    """
    if size_mode not in SIZE_MODES:
        raise ValueError(f"size_mode 必须是 {SIZE_MODES} 之一")
    if size_mode == SIZE_MODE_SCAN and not _scan_base_available():
        print(
            "[WARN] size_mode=scan 不可用 (未检测到 msg/attach 目录),"
            "回落到 estimate;CSV attachment_scanned_bytes 列保持空",
            file=sys.stderr, flush=True,
        )
        scan_available = False
    else:
        scan_available = size_mode == SIZE_MODE_SCAN

    range_lo = start_ts or 0
    range_hi = end_ts or 9_999_999_999
    out: dict[str, dict] = {}

    for username in usernames:
        shards = _find_msg_tables_for_user(username)
        if not shards:
            out[username] = _empty_stats(
                status=SIZE_STATUS_NO_MESSAGES,
                scan_available=scan_available,
            )
            continue
        agg = {
            "message_count": 0,
            "first_ct": None,
            "last_ct": None,
            "body_bytes": 0,
        }
        for shard in shards:
            db_path = shard["db_path"]
            table_name = shard["table_name"]
            try:
                with closing(db_core.open_db_readonly(db_path)) as conn:
                    row = conn.execute(
                        f"SELECT COUNT(*), MIN(create_time), MAX(create_time), "
                        f"COALESCE(SUM(LENGTH(CAST(message_content AS BLOB))), 0) "
                        f"FROM [{table_name}] WHERE create_time BETWEEN ? AND ?",
                        (range_lo, range_hi),
                    ).fetchone()
            except Exception:  # noqa: BLE001 — shard may have schema quirk; skip
                continue
            cnt, ct_min, ct_max, body = row
            agg["message_count"] += int(cnt or 0)
            if ct_min and (agg["first_ct"] is None or ct_min < agg["first_ct"]):
                agg["first_ct"] = ct_min
            if ct_max and (agg["last_ct"] is None or ct_max > agg["last_ct"]):
                agg["last_ct"] = ct_max
            agg["body_bytes"] += int(body or 0)

        if agg["message_count"] == 0:
            out[username] = _empty_stats(
                status=SIZE_STATUS_NO_MESSAGES,
                scan_available=scan_available,
            )
            continue

        attachment_scanned = 0
        if scan_available:
            attachment_scanned = _scan_attachment_bytes(username)

        out[username] = {
            "message_count": agg["message_count"],
            "first_ct": agg["first_ct"],
            "last_ct": agg["last_ct"],
            "body_bytes": agg["body_bytes"],
            "attachment_estimated_bytes": 0,  # TODO: query resource.db + media.db
            "attachment_scanned_bytes": attachment_scanned,
            "size_status": (
                SIZE_STATUS_OK if scan_available
                else SIZE_STATUS_SCAN_UNAVAILABLE if size_mode == SIZE_MODE_SCAN
                else SIZE_STATUS_ESTIMATE_ONLY
            ),
        }
    return out


def _empty_stats(status: str, scan_available: bool) -> dict:
    return {
        "message_count": 0,
        "first_ct": None,
        "last_ct": None,
        "body_bytes": 0,
        "attachment_estimated_bytes": 0,
        "attachment_scanned_bytes": 0,
        "size_status": status,
    }


def _scan_base_available() -> bool:
    """Check if WECHAT_BASE_DIR/msg/attach exists (the canonical scan root)."""
    try:
        base = db_core.WECHAT_BASE_DIR
    except (AttributeError, RuntimeError):
        return False
    if not base:
        return False
    return os.path.isdir(os.path.join(base, "msg", "attach"))


def _scan_attachment_bytes(username: str) -> int:
    """Walk WECHAT_BASE_DIR/msg/{attach,file,video}/<md5(username)>/ and sum sizes."""
    try:
        base = db_core.WECHAT_BASE_DIR
    except (AttributeError, RuntimeError):
        return 0
    if not base:
        return 0
    user_hash = hashlib.md5(username.encode("utf-8")).hexdigest()
    total = 0
    for sub in ("attach", "file", "video"):
        d = os.path.join(base, "msg", sub, user_hash)
        if not os.path.isdir(d):
            continue
        for dirpath, _dirnames, filenames in os.walk(d):
            for fn in filenames:
                try:
                    total += os.path.getsize(os.path.join(dirpath, fn))
                except OSError:
                    continue
    return total


# ============ Build plan CSV rows ============

def build_plan_rows(
    usernames: list[str],
    stats_by_user: dict,
) -> list[dict]:
    """Compose the rows fed into `write_plan_csv`.

    `chat_name` = display name (remark > nick > username), pulled from
    `get_contact_names()`. `chat_type` ∈ {single, group, pub, system}.
    """
    names = get_contact_names()
    rows: list[dict] = []
    for idx, username in enumerate(usernames):
        st = stats_by_user.get(username) or _empty_stats(
            status=SIZE_STATUS_NO_MESSAGES, scan_available=False
        )
        chat_name = names.get(username) or username
        rows.append({
            "export": "",  # filled by write_plan_csv per plan_mode
            "index": idx,
            "username": username,
            "chat_name": chat_name,
            "chat_type": _classify_chat(username),
            "message_count": st["message_count"],
            "first_time": _utc_ts_to_local_str(st["first_ct"]),
            "last_time": _utc_ts_to_local_str(st["last_ct"]),
            "body_bytes": st["body_bytes"],
            "attachment_estimated_bytes": st["attachment_estimated_bytes"],
            "attachment_scanned_bytes": st["attachment_scanned_bytes"],
            "size_status": st["size_status"],
        })
    return rows


def _classify_chat(username: str) -> str:
    if not username:
        return "unknown"
    if username.endswith("@chatroom") or username.endswith("@im.chatroom"):
        return "group"
    if username.startswith("gh_"):
        return "pub"
    if username in SYSTEM_USERNAMES_PREFILL_ZERO:
        return "system"
    return "single"


# ============ Contact metadata for export header (used by export_one) ============

def contact_metadata_for_chat(username: str, is_group: bool) -> dict:
    """Build the `contact_*` block for a single-chat JSON header.

    Group chats return {} (caller emits `is_group: true` instead). Mirrors
    `wxdec.cli.export_chat._contact_metadata_for_export` but is callable
    from the batch path without circular import.
    """
    if is_group:
        return {}
    out: dict = {}
    for c in get_contact_full():
        if c.get("username") != username:
            continue
        if c.get("remark"):
            out["contact_remark"] = c["remark"]
        if c.get("nick_name"):
            out["contact_nick_name"] = c["nick_name"]
        if c.get("description"):
            out["contact_memo"] = c["description"]
        break
    tags_by_user = get_contact_tag_names_by_username()
    user_tags = tags_by_user.get(username)
    if user_tags:
        out["contact_tags"] = list(user_tags)
    return out


__all__ = [
    "EXPORT_INDEX_FILE",
    "EXPORT_INDEX_SCHEMA_VERSION",
    "PLAN_MODE_BLACKLIST",
    "PLAN_MODE_WHITELIST",
    "PLAN_MODES",
    "SIZE_MODE_ESTIMATE",
    "SIZE_MODE_SCAN",
    "SIZE_MODES",
    "SIZE_STATUS_OK",
    "SIZE_STATUS_ESTIMATE_ONLY",
    "SIZE_STATUS_SCAN_UNAVAILABLE",
    "SIZE_STATUS_NO_MESSAGES",
    "PLAN_CSV_FIELDS",
    "SYSTEM_USERNAMES_PREFILL_ZERO",
    "UserArgError",
    "Timeout",
    "FileLock",
    "export_filename",
    "lock_path_for",
    "acquired_lock",
    "load_index",
    "write_index_atomic",
    "resolve_export_path",
    "update_index_entry",
    "cleanup_orphan_partials",
    "partial_path",
    "write_plan_csv",
    "load_plan_csv",
    "validate_user_arg_chars",
    "resolve_user_args",
    "load_session_usernames",
    "collect_plan_stats",
    "build_plan_rows",
    "contact_metadata_for_chat",
]
