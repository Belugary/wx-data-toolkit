#!/usr/bin/env python3
"""SNS coverage health report — what we have vs what's possible to capture.

Inspects the exported sns.db plus on-disk media outputs and prints:
  1. Total posts by year/month (bar chart) — spot zero-post months
  2. Field capture depth — which fields the parser is filling in
  3. Media download coverage — image / video on-disk vs in-XML
  4. Data integrity (key insight): SnsUserTimeLineBreakFlagV2 tells us how far
     back the local DB was paginated. Posts before the break_flag=1 anchor
     are NOT guaranteed to be complete — only what the user happened to
     scroll through is stored.
  5. Long gaps (>30 days between consecutive posts) — could be either real
     inactivity or data loss; the script flags both for human review.

Usage:
  python tools/sns_health.py [--user WXID] [--db PATH]
                              [--image-dir PATH] [--video-dir PATH]
"""
from __future__ import annotations

import argparse
import functools
import os
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wxdec.cli.decrypt_sns import (
    _decode_blob_to_xml,
    _infer_self_wxid_from_path,
    _resolve_self_wxid,
    parse_timeline_xml,
    query_interactions,
    resolve_sns_db,
)
from wxdec.config import load_config

print = functools.partial(print, flush=True)


def _next_month(dt: datetime) -> datetime:
    return datetime(dt.year + (dt.month == 12), (dt.month % 12) + 1, 1, tzinfo=timezone.utc)


def render_monthly_histogram(month_counts: dict[str, int],
                             earliest: datetime, latest: datetime) -> list[str]:
    lines = [f'{"month":<10}{"count":<8}bar']
    cur = datetime(earliest.year, earliest.month, 1, tzinfo=timezone.utc)
    end = datetime(latest.year, latest.month, 1, tzinfo=timezone.utc)
    while cur <= end:
        ym = f"{cur.year}-{cur.month:02d}"
        n = month_counts.get(ym, 0)
        bar = "#" * min(n, 40)
        marker = "  <-- ZERO" if n == 0 else ""
        lines.append(f"{ym:<10}{n:<8}{bar}{marker}")
        cur = _next_month(cur)
    return lines


def find_long_gaps(times: list[int], threshold_days: int = 30) -> list[tuple[datetime, datetime, int]]:
    sorted_t = sorted(times)
    gaps = []
    for i in range(1, len(sorted_t)):
        delta = sorted_t[i] - sorted_t[i - 1]
        if delta > threshold_days * 86400:
            prev = datetime.fromtimestamp(sorted_t[i - 1], tz=timezone.utc)
            nxt = datetime.fromtimestamp(sorted_t[i], tz=timezone.utc)
            gaps.append((prev, nxt, delta // 86400))
    return gaps


def analyze_break_anchor(conn: sqlite3.Connection, user: str) -> dict:
    """Find the break_flag=1 anchor — earliest tid below which data may be incomplete."""
    try:
        rows = conn.execute(
            "SELECT tid, break_flag FROM SnsUserTimeLineBreakFlagV2 WHERE user_name=?",
            (user,),
        ).fetchall()
    except sqlite3.OperationalError:
        return {"available": False}

    flag_tids = {tid: bf for tid, bf in rows}
    sns_tids = {tid for (tid,) in conn.execute(
        "SELECT tid FROM SnsTimeLine WHERE user_name=?", (user,)
    )}

    # tid for break_flag=1 (the deepest paginated point)
    anchor_tids = [tid for tid, bf in flag_tids.items() if bf == 1]
    anchor_time = None
    if anchor_tids:
        # Translate the first anchor tid to its createTime via SnsTimeLine join
        for tid in anchor_tids:
            row = conn.execute(
                "SELECT content FROM SnsTimeLine WHERE tid=?", (tid,)
            ).fetchone()
            if row:
                p = parse_timeline_xml(_decode_blob_to_xml(row[0]))
                if p["createTime"]:
                    anchor_time = datetime.fromtimestamp(
                        p["createTime"], tz=timezone.utc
                    )
                    break

    # Posts in SnsTimeLine but NOT in BreakFlagV2 — usually older "island" posts
    orphans = sns_tids - flag_tids.keys()
    orphan_times = []
    for tid in orphans:
        row = conn.execute("SELECT content FROM SnsTimeLine WHERE tid=?", (tid,)).fetchone()
        if row:
            p = parse_timeline_xml(_decode_blob_to_xml(row[0]))
            if p["createTime"]:
                orphan_times.append(p["createTime"])

    return {
        "available": True,
        "tracked_count": len(flag_tids),
        "sns_count": len(sns_tids),
        "anchors_count": len(anchor_tids),
        "anchor_time": anchor_time,
        "orphan_count": len(orphans),
        "orphan_times": sorted(orphan_times),
    }


def analyze(db_path: str, user: Optional[str], image_dir: Optional[str],
            video_dir: Optional[str]) -> int:
    if not os.path.isfile(db_path):
        print(f"[!] sns.db not found: {db_path}", file=sys.stderr)
        return 2

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    if user is None:
        rows = conn.execute(
            "SELECT user_name, COUNT(*) c FROM SnsTimeLine GROUP BY user_name "
            "ORDER BY c DESC LIMIT 1"
        ).fetchall()
        if not rows:
            print(f"[!] SnsTimeLine empty in {db_path}", file=sys.stderr)
            return 2
        # Heuristic fallback only kicks in when caller didn't pass --user
        user = rows[0]["user_name"]
        print(f"[*] no --user given, falling back to most-frequent user_name: {user}",
              file=sys.stderr)

    print(f"=== SNS health report ===")
    print(f"  db_path:   {db_path}")
    print(f"  user:      {user}")
    print(f"  image_dir: {image_dir or '(none)'}")
    print(f"  video_dir: {video_dir or '(none)'}")
    print()

    rows = conn.execute(
        "SELECT tid, content FROM SnsTimeLine WHERE user_name=?", (user,)
    ).fetchall()
    total = len(rows)
    if not total:
        print(f"[!] no posts for user_name={user!r}")
        return 1

    interactions = query_interactions(db_path)

    # ---- pass 1: per-post stats ----
    times: list[int] = []
    month_counts: dict[str, int] = defaultdict(int)
    posts_by_kind: dict[str, int] = defaultdict(int)

    captured = defaultdict(int)
    img_total = vid_total = 0
    img_done = vid_done = 0

    img_have = set()
    if image_dir and os.path.isdir(image_dir):
        for p in os.listdir(image_dir):
            if p.endswith(".part"):
                continue
            stem = p.rsplit(".", 1)[0]
            img_have.add(stem)
    vid_have = set()
    if video_dir and os.path.isdir(video_dir):
        for p in os.listdir(video_dir):
            if p.endswith(".part") or p.endswith(".enc"):
                continue
            if p.endswith(".mp4"):
                vid_have.add(p[:-4])

    for r in rows:
        xml = _decode_blob_to_xml(r["content"])
        p = parse_timeline_xml(xml)
        if "_parseError" in p:
            captured["parse_error"] += 1
            continue

        ct = p["createTime"]
        if ct:
            times.append(ct)
            dt = datetime.fromtimestamp(ct, tz=timezone.utc)
            month_counts[f"{dt.year}-{dt.month:02d}"] += 1

        # post kind
        types = {m["type"] for m in p["media"]}
        if p["type"] == 7:
            posts_by_kind["cover"] += 1
        elif p["finderFeed"]:
            posts_by_kind["finder_share"] += 1
        elif 6 in types:
            posts_by_kind["video"] += 1
        elif types & {1, 2}:
            posts_by_kind["image"] += 1
        elif p["contentUrl"]:
            posts_by_kind["link"] += 1
        else:
            posts_by_kind["text"] += 1

        # field capture
        for f in ("contentDesc", "title", "contentUrl", "videoEncKey", "sourceName"):
            if p[f]:
                captured[f] += 1
        if p["location"]:
            captured["location_str"] += 1
        if p["locationDetail"]:
            captured["locationDetail"] += 1
        if p["isPrivate"]:
            captured["isPrivate"] += 1
        if p["finderFeed"]:
            captured["finderFeed"] += 1

        ix = interactions.get(r["tid"], {"likes": [], "comments": []})
        if ix["likes"]:
            captured["has_likes"] += 1
        if ix["comments"]:
            captured["has_comments"] += 1
        captured["like_total"] += len(ix["likes"])
        captured["comment_total"] += len(ix["comments"])

        # media counts
        for m in p["media"]:
            if m["type"] in (1, 2):
                img_total += 1
                if m["urlAttrs"].get("md5") in img_have:
                    img_done += 1
            elif m["type"] == 6:
                vid_total += 1
                if m["urlAttrs"].get("videomd5") in vid_have:
                    vid_done += 1
            if m.get("description"):
                captured["media_description"] += 1
            if m.get("videoDuration"):
                captured["media_duration"] += 1
            if m.get("size"):
                captured["media_size"] += 1
            captured["media_total"] += 1

    # ---- summary ----
    print(f"--- 1. 帖子总览 ---")
    print(f"  total posts: {total}")
    if times:
        earliest = datetime.fromtimestamp(min(times), tz=timezone.utc)
        latest = datetime.fromtimestamp(max(times), tz=timezone.utc)
        print(f"  time span:   {earliest.date()} → {latest.date()} "
              f"({(latest - earliest).days} 天)")
    print(f"  by kind:     {dict(posts_by_kind)}")
    print()

    print(f"--- 2. 媒体下载覆盖率 ---")
    print(f"  image:   {img_done}/{img_total} = "
          f"{100 * img_done / max(1, img_total):.0f}%")
    print(f"  video:   {vid_done}/{vid_total} = "
          f"{100 * vid_done / max(1, vid_total):.0f}%")
    print()

    print(f"--- 3. 字段采集深度 ---")
    for f in ("contentDesc", "title", "contentUrl", "location_str", "locationDetail",
              "videoEncKey", "isPrivate", "finderFeed",
              "media_description", "media_duration", "media_size",
              "has_likes", "has_comments"):
        n = captured[f]
        bar = "#" * min(int(40 * n / total), 40) if total else ""
        print(f"  {f:<22}{n:>5}/{total}   {bar}")
    print(f"  likes累计 = {captured['like_total']}, comments累计 = {captured['comment_total']}")
    if captured["parse_error"]:
        print(f"  [!] {captured['parse_error']} posts failed to parse")
    print()

    if times:
        print(f"--- 4. 月度分布(< 1 帖月份是定向采集线索) ---")
        for line in render_monthly_histogram(month_counts, earliest, latest):
            print(f"  {line}")
        zero_months = [
            ym for ym, n in month_counts.items() if n == 0
        ]
        zero_in_span = []
        cur = datetime(earliest.year, earliest.month, 1, tzinfo=timezone.utc)
        end = datetime(latest.year, latest.month, 1, tzinfo=timezone.utc)
        while cur <= end:
            ym = f"{cur.year}-{cur.month:02d}"
            if month_counts.get(ym, 0) == 0:
                zero_in_span.append(ym)
            cur = _next_month(cur)
        print(f"\n  zero-post months in range: {len(zero_in_span)}")
    print()

    # Long gaps
    if times:
        print(f"--- 5. 长空档(>30 天连续无新帖) ---")
        gaps = find_long_gaps(times, threshold_days=30)
        if not gaps:
            print(f"  (none)")
        else:
            for prev, nxt, days in gaps:
                print(f"  {prev.date()} → {nxt.date()}  ({days} 天)")
        print()

    # Break anchor — the killer signal
    print(f"--- 6. 数据完整性诊断 ---")
    anchor = analyze_break_anchor(conn, user)
    if not anchor["available"]:
        print(f"  (SnsUserTimeLineBreakFlagV2 not present — old DB schema)")
    else:
        print(f"  BreakFlagV2 records (self): {anchor['tracked_count']}")
        print(f"  SnsTimeLine posts (self):   {anchor['sns_count']}")
        print(f"  break_flag=1 anchors:       {anchor['anchors_count']}")
        if anchor["anchor_time"]:
            print(f"  anchor time → {anchor['anchor_time'].isoformat()}")
            print(f"  =>  {anchor['anchor_time'].date()} 之前的数据可能"
                  f"不完整(微信只在用户主动浏览时回填本地 DB)")
        if anchor["orphan_count"]:
            print(f"  孤岛帖子(在 SnsTimeLine 但无 BreakFlag 索引): "
                  f"{anchor['orphan_count']}")
            for ts in anchor["orphan_times"]:
                d = datetime.fromtimestamp(ts, tz=timezone.utc).date()
                print(f"    {d}")
            print(f"  这些是早期被加载到的零散帖子, 真实历史可能比这更多。")
    print()

    # Recommendations
    print(f"--- 7. 定向采集建议 ---")
    if anchor.get("anchor_time"):
        print(f"  ► 对早于 {anchor['anchor_time'].date()} 的数据: "
              f"在微信客户端打开自己朋友圈, 一直下拉到底, 让微信向服务器拉历史; "
              f"然后重新 `python main.py decrypt` 导出 sns.db。")
    if img_total - img_done > 0:
        print(f"  ► 还有 {img_total - img_done} 张图片未还原: "
              f"`python main.py decrypt-sns --decrypt-media`")
    if vid_total - vid_done > 0:
        print(f"  ► 还有 {vid_total - vid_done} 段视频未还原: "
              f"`python main.py decrypt-sns --decrypt-media`")

    return 0


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="sns_health.py",
        description="Coverage health report for exported SNS database.",
    )
    p.add_argument("--db", help="path to exported sns.db (default: from config.json)")
    p.add_argument("--user", help="user_name to scope (default: auto-detect from path)")
    p.add_argument("--image-dir", help="path where decrypted images live (default: from config)")
    p.add_argument("--video-dir",
                   help="path where restored videos live (default: same as --image-dir)")
    args = p.parse_args(argv)

    # Only load config when an arg is missing — the worktree's example config
    # would otherwise abort before any explicit --db could take effect.
    needs_cfg = not (args.db and args.image_dir)
    cfg: dict = {}
    if needs_cfg:
        try:
            cfg = load_config()
        except SystemExit:
            if not args.db:
                raise
            cfg = {}  # explicit --db given, config wasn't strictly needed

    decrypted_dir = os.path.expanduser(cfg.get("decrypted_dir", "decrypted"))
    db_path = args.db or resolve_sns_db(decrypted_dir, None)

    user = args.user
    if not user and cfg:
        candidate = _infer_self_wxid_from_path(os.path.expanduser(cfg.get("db_dir", "")))
        user = _resolve_self_wxid(db_path, candidate) or candidate

    image_dir = args.image_dir or os.path.join(
        os.path.expanduser(cfg.get("decoded_image_dir", "decoded_images")), "sns"
    )
    # 视频和图片都落到 <decoded_image_dir>/sns/ 同目录(只是后缀不同), 默认共用
    video_dir = args.video_dir or image_dir

    return analyze(db_path, user, image_dir, video_dir)


if __name__ == "__main__":
    sys.exit(main())
