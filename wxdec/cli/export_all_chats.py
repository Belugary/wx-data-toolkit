"""批量导出微信聊天记录为 JSON 文件,可选 CSV 计划驱动。

输出 JSON 格式 (schema v3) 与 `export_chat` 完全一致;详见
`docs/chat_export_format.md`。

用法:
    # 全量导出所有会话到当前目录
    python -m wxdec.cli.export_all_chats

    # 1) 生成 CSV 计划交给用户编辑
    python -m wxdec.cli.export_all_chats --write-plan-csv /tmp/plan.csv

    # 2) 用户编辑 CSV 标 export 列后,按计划导出
    python -m wxdec.cli.export_all_chats /tmp/exports --from-plan-csv /tmp/plan.csv

    # 增量导出 (按 per-shard cursor 续跑)
    python -m wxdec.cli.export_all_chats /tmp/exports -i

    # 按日期范围
    python -m wxdec.cli.export_all_chats --start 2025-01-01 --end 2025-12-31

    # 仅特定联系人 (接受 wxid / 备注名 / 昵称, 多命中报错)
    python -m wxdec.cli.export_all_chats --users wxid_abc,张三,12345@chatroom

设计:
  - 文件名 `<chat>_export.json`,同名联系人冲突 `<chat>__<username>_export.json`
  - 索引 `_export_index.json` (schema v3) 追踪 username → filename 映射,
    备注名变更时自动 rename 旧 JSON
  - 增量去重 cursor `(create_time, local_id)` 按 shard 分组保存,因 fork 的
    消息表是 sharded 且 local_id 跨 shard 不全局唯一
  - filelock ($TMPDIR) 跨进程互斥,timeout=30 → exit 2
  - `.partial.<pid>` 临时文件 + 启动期 orphan 清理
  - 不带 `-t/--with-transcriptions` 标志:fork 转录走独立的 transcribe_chat
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time
from contextlib import closing
from datetime import datetime
from typing import Optional

from filelock import Timeout

from wxdec import export_plan as ep
from wxdec import msg_format, msg_query
from wxdec.cli.export_chat import SCHEMA_VERSION
from wxdec.cli.export_helpers import _extract_content, _msg_type_str, _resolve_sender
from wxdec.contact import get_contact_names


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_LOCK_TIMEOUT = 2
EXIT_FUTURE_INDEX = 3


# ============ Date parsing ============

def _parse_date(s: Optional[str]) -> Optional[int]:
    """Accept YYYY-MM-DD / YYYY-MM-DD HH:MM(:SS)? / unix ts (int)."""
    if not s:
        return None
    s = s.strip()
    for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return int(datetime.strptime(s, fmt).timestamp())
        except ValueError:
            pass
    try:
        return int(s)
    except ValueError:
        raise argparse.ArgumentTypeError(f"无法解析时间 {s!r}: 用 YYYY-MM-DD 或 unix 时间戳")


def _format_msg_ts(ts) -> str:
    if not ts:
        return ""
    try:
        return datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, ValueError):
        return ""


# ============ Single-chat export ============

def export_one(
    username: str,
    output_dir: str,
    contact_names: dict,
    idx: dict,
    *,
    start_ts: Optional[int] = None,
    end_ts: Optional[int] = None,
    incremental: bool = False,
) -> tuple[bool, int, int, str]:
    """Export ONE chat. Caller holds the FileLock around the index portions.

    Returns (success, total_msgs, new_msgs, reason).
    On success: total_msgs includes any existing-merged messages.
    On skip: success=False, reason explains.
    """
    ctx = msg_query._resolve_chat_context(username)
    if ctx is None:
        return False, 0, 0, "无法解析 chat context"
    if not ctx["message_tables"]:
        return False, 0, 0, "无消息表 (空 chat)"

    display_name = ctx["display_name"]

    # Lock-required portion: pick final_path (handles collision + rename)
    final_path, side_effects = ep.resolve_export_path(
        output_dir, username, display_name, idx
    )
    for m in side_effects:
        print(f"  [{username}] {m}", flush=True)

    # Load existing JSON if incremental
    existing_msgs: list[dict] = []
    last_cursor_per_shard: dict = {}
    if incremental and os.path.exists(final_path):
        try:
            with open(final_path, encoding="utf-8") as f:
                existing = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print(f"  [{username}] 读老 JSON 失败 ({e}),走全量重导", file=sys.stderr, flush=True)
            existing = None
        if existing is not None:
            old_version = existing.get("schema_version")
            old_cursor = existing.get("last_cursor")
            if (old_version == SCHEMA_VERSION
                    and isinstance(old_cursor, dict)
                    and all(isinstance(v, dict) for v in old_cursor.values())):
                existing_msgs = existing.get("messages") or []
                last_cursor_per_shard = dict(old_cursor)
            else:
                print(
                    f"  [{username}] 老 JSON schema 不兼容 (version={old_version!r}, "
                    f"cursor type={type(old_cursor).__name__});全量重导",
                    file=sys.stderr, flush=True,
                )

    # Fan out: per-shard query with optional per-shard cursor
    names = contact_names
    all_new_rows = []  # [(row, id_to_username, shard_key)]
    new_cursor_per_shard = dict(last_cursor_per_shard)

    for table_info in ctx["message_tables"]:
        db_path = table_info["db_path"]
        table_name = table_info["table_name"]
        shard_key = os.path.basename(db_path)
        cursor = last_cursor_per_shard.get(shard_key) if incremental else None

        with closing(sqlite3.connect(db_path)) as conn:
            id_to_username = msg_format._load_name2id_maps(conn)
            rows = list(_query_shard_rows(
                conn, table_name, cursor=cursor,
                start_ts=start_ts, end_ts=end_ts,
            ))
        if not rows:
            continue

        shard_max = None
        for row in rows:
            local_id, _local_type, create_time, _real_sender_id, _content, _ct = row
            all_new_rows.append((row, id_to_username, shard_key))
            cur = (create_time or 0, local_id)
            if shard_max is None or cur > shard_max:
                shard_max = cur
        if shard_max is not None:
            new_cursor_per_shard[shard_key] = {
                "create_time": shard_max[0],
                "local_id": shard_max[1],
            }

    # Sort across shards by (create_time, local_id) — incremental keeps stable order
    all_new_rows.sort(key=lambda triple: (triple[0][2] or 0, triple[0][0]))

    new_msgs = []
    for row, id_to_username, _shard_key in all_new_rows:
        msg = _render_message(row, ctx, names, id_to_username)
        new_msgs.append(msg)

    if incremental:
        messages = existing_msgs + new_msgs
    else:
        messages = new_msgs

    # Assemble JSON
    output = _build_output_header(
        ctx, username, display_name, messages, new_cursor_per_shard
    )
    output["messages"] = messages

    # Atomic write via .partial.<pid>
    tmp = ep.partial_path(final_path)
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(output, f, ensure_ascii=False, indent=2)
        os.replace(tmp, final_path)
    except OSError as e:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
        return False, 0, 0, f"写文件失败: {e}"

    # Update index entry (caller will write_index_atomic under lock at the end)
    ep.update_index_entry(idx, username, os.path.basename(final_path), new_cursor_per_shard)

    return True, len(messages), len(new_msgs), "ok"


def _query_shard_rows(
    conn,
    table_name: str,
    *,
    cursor: Optional[dict] = None,
    start_ts: Optional[int] = None,
    end_ts: Optional[int] = None,
):
    """Yield raw rows from a single shard with optional WHERE filters.

    Uses展开式 row-value comparison `ct > ? OR (ct = ? AND lid > ?)` to avoid
    SQLite row-value syntax dependency and to play nice with the unindexed
    create_time column (predicate pushes selection down where possible).
    """
    range_lo = start_ts if start_ts is not None else 0
    range_hi = end_ts if end_ts is not None else 9_999_999_999

    select_clause = (
        f"SELECT local_id, local_type, create_time, real_sender_id, "
        f"message_content, COALESCE(WCDB_CT_message_content, 0) "
        f"FROM [{table_name}]"
    )
    if cursor:
        ct = int(cursor.get("create_time") or 0)
        lid = int(cursor.get("local_id") or 0)
        sql = (
            f"{select_clause} WHERE create_time BETWEEN ? AND ? "
            f"AND (create_time > ? OR (create_time = ? AND local_id > ?))"
        )
        params = (range_lo, range_hi, ct, ct, lid)
    else:
        sql = f"{select_clause} WHERE create_time BETWEEN ? AND ?"
        params = (range_lo, range_hi)

    try:
        for row in conn.execute(sql, params):
            yield row
    except sqlite3.OperationalError:
        # Schema mismatch on this shard (e.g. missing WCDB_CT column on older
        # version) → retry without the CT column.
        select_clause = (
            f"SELECT local_id, local_type, create_time, real_sender_id, "
            f"message_content, 0 FROM [{table_name}]"
        )
        if cursor:
            sql = (
                f"{select_clause} WHERE create_time BETWEEN ? AND ? "
                f"AND (create_time > ? OR (create_time = ? AND local_id > ?))"
            )
        else:
            sql = f"{select_clause} WHERE create_time BETWEEN ? AND ?"
        for row in conn.execute(sql, params):
            yield row


def _render_message(row, ctx, names, id_to_username) -> dict:
    """Mirror of export_chat._render_message; kept inline to avoid circular import."""
    local_id, local_type, create_time, _real_sender_id, content, ct = row
    sender = _resolve_sender(row, ctx, names, id_to_username)
    type_str = _msg_type_str(local_type)
    rendered, extras = _extract_content(
        local_id, local_type, content, ct, ctx["username"], ctx["display_name"]
    )
    msg = {
        "local_id": local_id,
        "timestamp": create_time,
        "sender": sender,
    }
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
    return msg


def _build_output_header(ctx, username, display_name, messages, last_cursor_per_shard) -> dict:
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
        output.update(ep.contact_metadata_for_chat(username, is_group=False))
    if last_cursor_per_shard:
        output["last_cursor"] = last_cursor_per_shard
    return output


# ============ CLI ============

def _parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="wxdec.cli.export_all_chats",
        description="批量导出微信聊天记录为 JSON,可选 CSV 计划驱动",
    )
    p.add_argument(
        "output_dir", nargs="?", default="./exported_chats",
        help="输出目录 (默认 ./exported_chats)",
    )
    p.add_argument(
        "--write-plan-csv", metavar="PATH",
        help="只生成 CSV 计划,不导出。用户编辑 CSV 后用 --from-plan-csv 执行",
    )
    p.add_argument(
        "--from-plan-csv", metavar="PATH",
        help="读 CSV 计划按勾选执行 (与 --write-plan-csv 互斥)",
    )
    p.add_argument(
        "--plan-mode", choices=ep.PLAN_MODES, default=ep.PLAN_MODE_BLACKLIST,
        help="计划模式: blacklist=默认全导出, export=0 跳过; "
             "whitelist=默认全跳过, export=1 导出 (默认 blacklist)",
    )
    p.add_argument(
        "--size-mode", choices=ep.SIZE_MODES, default=ep.SIZE_MODE_ESTIMATE,
        help="附件大小: estimate (默认,不扫本地)|scan (扫 WECHAT_BASE_DIR)",
    )
    p.add_argument(
        "-i", "--incremental", action="store_true",
        help="增量模式:按 per-shard cursor 续跑,跳过已导出消息",
    )
    p.add_argument(
        "--start", type=_parse_date, default=None,
        help="起始时间 YYYY-MM-DD",
    )
    p.add_argument(
        "--end", type=_parse_date, default=None,
        help="结束时间 YYYY-MM-DD",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="预览要导出的清单,不实际写文件",
    )
    p.add_argument(
        "--users", default="",
        help="逗号分隔白名单,接受 wxid / 备注 / 昵称 / 群名。"
             "多命中备注名会报错,需用 username 精确指定",
    )
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = _parse_args(argv)

    if args.write_plan_csv and args.from_plan_csv:
        print("ERROR: --write-plan-csv 与 --from-plan-csv 互斥", file=sys.stderr)
        return EXIT_ERROR

    output_dir = args.output_dir
    os.makedirs(output_dir, exist_ok=True)

    # Startup: clean dead .partial.<pid> orphans
    removed = ep.cleanup_orphan_partials(output_dir, ttl_seconds=3600)
    for path in removed:
        print(f"[INFO] cleanup orphan partial: {path}", file=sys.stderr, flush=True)

    # Load session usernames
    session_usernames = ep.load_session_usernames()
    if not session_usernames:
        print("ERROR: 无法读取 session/session.db (是否已解密?)", file=sys.stderr)
        return EXIT_ERROR

    # Filter via --users if provided
    if args.users:
        user_args = [s for s in args.users.split(",") if s.strip()]
        try:
            resolved, warnings = ep.resolve_user_args(
                user_args, all_session_usernames=set(session_usernames)
            )
        except ep.UserArgError as e:
            print(f"ERROR: --users 解析失败: {e}", file=sys.stderr)
            return EXIT_ERROR
        for w in warnings:
            print(f"[INFO] {w}", file=sys.stderr, flush=True)
        if not resolved:
            print("ERROR: --users 全部解析失败,无可导出对象", file=sys.stderr)
            return EXIT_ERROR
        target_usernames = [u for u in session_usernames if u in set(resolved)]
        # Include any resolved usernames not in session (rare; just append)
        for u in resolved:
            if u not in target_usernames:
                target_usernames.append(u)
    else:
        target_usernames = list(session_usernames)

    # Branch: --write-plan-csv
    if args.write_plan_csv:
        return _cmd_write_plan_csv(
            target_usernames, args.write_plan_csv,
            plan_mode=args.plan_mode,
            size_mode=args.size_mode,
            start_ts=args.start, end_ts=args.end,
        )

    # Branch: --from-plan-csv → load selected usernames
    if args.from_plan_csv:
        try:
            selected, _ = ep.load_plan_csv(args.from_plan_csv, plan_mode=args.plan_mode)
        except (OSError, ValueError) as e:
            print(f"ERROR: 读取 CSV 计划失败: {e}", file=sys.stderr)
            return EXIT_ERROR
        target_usernames = [u for u in target_usernames if u in selected]

    if not target_usernames:
        print("没有可导出的会话")
        return EXIT_OK

    # Branch: normal / dry-run export
    return _cmd_export(
        target_usernames, output_dir,
        start_ts=args.start, end_ts=args.end,
        incremental=args.incremental,
        dry_run=args.dry_run,
    )


def _cmd_write_plan_csv(
    usernames: list[str],
    csv_path: str,
    *,
    plan_mode: str,
    size_mode: str,
    start_ts: Optional[int],
    end_ts: Optional[int],
) -> int:
    print(f"扫描 {len(usernames)} 个会话生成 CSV 计划 (size_mode={size_mode})...", flush=True)
    t0 = time.time()
    stats = ep.collect_plan_stats(
        usernames, start_ts=start_ts, end_ts=end_ts, size_mode=size_mode,
    )
    rows = ep.build_plan_rows(usernames, stats)
    try:
        ep.write_plan_csv(rows, csv_path, plan_mode=plan_mode)
    except OSError as e:
        print(f"ERROR: 写 CSV 失败: {e}", file=sys.stderr)
        return EXIT_ERROR
    dt = time.time() - t0
    print(f"CSV 计划已写到 {csv_path} ({len(rows)} 行, {dt:.1f}s)")
    print(f"模式 = {plan_mode}: 编辑 CSV 后用 --from-plan-csv {csv_path} 执行")
    return EXIT_OK


def _cmd_export(
    usernames: list[str],
    output_dir: str,
    *,
    start_ts: Optional[int],
    end_ts: Optional[int],
    incremental: bool,
    dry_run: bool,
) -> int:
    if dry_run:
        names = get_contact_names()
        print(f"[DRY-RUN] 将导出 {len(usernames)} 个会话:")
        for u in usernames:
            print(f"  {u}  ({names.get(u, '?')})")
        return EXIT_OK

    contact_names_map = get_contact_names()

    # Acquire lock, load index, run exports, write index
    try:
        lock = ep.acquired_lock(output_dir, timeout=30)
    except Exception as e:  # noqa: BLE001
        print(f"ERROR: 初始化 lock 失败: {e}", file=sys.stderr)
        return EXIT_ERROR

    try:
        try:
            with lock:
                try:
                    idx, warnings = ep.load_index(output_dir)
                except RuntimeError as e:
                    print(f"ERROR: {e}", file=sys.stderr)
                    return EXIT_FUTURE_INDEX
                for w in warnings:
                    print(f"[WARN] {w}", file=sys.stderr, flush=True)

                ok = 0
                skip = 0
                err = 0
                t0 = time.time()
                for i, username in enumerate(usernames):
                    elapsed = time.time() - t0
                    eta = (elapsed / max(i, 1)) * (len(usernames) - i) if i else 0
                    print(
                        f"[{i+1}/{len(usernames)}] {username} "
                        f"(elapsed {elapsed:.0f}s, eta {eta:.0f}s)",
                        flush=True,
                    )
                    try:
                        success, total, new, reason = export_one(
                            username, output_dir,
                            contact_names=contact_names_map,
                            idx=idx,
                            start_ts=start_ts,
                            end_ts=end_ts,
                            incremental=incremental,
                        )
                    except Exception as e:  # noqa: BLE001
                        print(f"  [{username}] EXCEPTION: {e}", file=sys.stderr, flush=True)
                        err += 1
                        continue
                    if success:
                        ok += 1
                        print(
                            f"  [{username}] ok: total={total} new={new}",
                            flush=True,
                        )
                    else:
                        skip += 1
                        print(f"  [{username}] skip: {reason}", flush=True)

                # Final index write
                ep.write_index_atomic(output_dir, idx)
                print(f"完成: ok={ok} skip={skip} err={err}, 用时 {time.time()-t0:.1f}s")
                return EXIT_OK if err == 0 else EXIT_ERROR
        except Timeout:
            print(
                f"ERROR: 另一个导出进程持有 lock 超过 30s,放弃。"
                f"lock={ep.lock_path_for(output_dir)};如确认无其他进程,删除 lock 后重试",
                file=sys.stderr,
            )
            return EXIT_LOCK_TIMEOUT
    except KeyboardInterrupt:
        print("\n[INTERRUPTED] 用户中断;`.partial.<pid>` 临时文件会在下次启动时清理",
              file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
