#!/usr/bin/env python3
"""Extract PII needles from local WeChat contact database into .git/info/pii-blocklist.

Reads contact.db and outputs unique strings (usernames, nicknames, aliases,
remarks) that should never appear in committed code. The blocklist is consumed
by the global pre-commit hook (~/.claude/scripts/check_pii_blocklist.py).

Manual entries below the ``# MANUAL`` marker are preserved across runs.

Usage
-----
  python scripts/extract_pii_blocklist.py            # update blocklist
  python scripts/extract_pii_blocklist.py --full-scan # also scan all tracked files
  python scripts/extract_pii_blocklist.py --dry-run   # print needles, don't write
"""
from __future__ import annotations

import argparse
import os
import re
import sqlite3
import subprocess
import sys

MANUAL_MARKER = "# MANUAL"
DEFAULT_BLOCKLIST = os.path.join(".git", "info", "pii-blocklist")

DEFAULT_CONTACT_DB = "~/Documents/wechat_decrypted/contact/contact.db"
DEFAULT_SESSION_DB = "~/Documents/wechat_decrypted/session/session.db"

MIN_CN_LEN_REMARK = 2
MIN_CN_LEN_OTHER = 3
MIN_ASCII_LEN = 5

SYSTEM_USERNAMES = frozenset({
    "filehelper", "newsapp", "fmessage", "floatbottle", "medianote",
    "weixin", "tmessage", "qmessage", "qqmail", "qqsafe",
})

GENERIC_SKIP = frozenset({
    "", "test", "test1", "test2", "admin", "user", "null", "none",
    "hello", "world", "demo", "default", "system", "service",
    "apple", "google", "microsoft", "amazon", "tesla",
    "simple", "grace", "mirror", "smile", "carol", "angel", "lucky",
    "happy", "sunny", "summer", "winter", "spring", "tiger", "jason",
    "david", "kevin", "peter", "jenny", "alice", "vivian", "stella",
    "shang", "frank", "chris", "brian", "scott", "steve", "sandy",
    "公众号", "微信转账", "微信支付", "视频号直播", "朋友圈",
    "李明", "小明", "小王", "小李", "张三", "李四", "王五",
})

_WXID_RE = re.compile(r"^wxid_[a-zA-Z0-9]+$")
_GH_RE = re.compile(r"^gh_[a-fA-F0-9]+$")
_ALL_DIGITS = re.compile(r"^\d+$")


def _is_ascii_only(s: str) -> bool:
    try:
        s.encode("ascii")
        return True
    except UnicodeEncodeError:
        return False


def _should_include(needle: str, is_remark: bool = False) -> bool:
    if not needle or needle.lower() in GENERIC_SKIP:
        return False
    if len(needle) <= 1:
        return False
    if _GH_RE.match(needle):
        return False
    if "@chatroom" in needle:
        return False
    if _ALL_DIGITS.match(needle) and len(needle) < 6:
        return False
    alnum_count = sum(1 for c in needle if c.isalnum())
    if alnum_count < 2:
        return False
    if _is_ascii_only(needle):
        return len(needle) >= MIN_ASCII_LEN
    min_cn = MIN_CN_LEN_REMARK if is_remark else MIN_CN_LEN_OTHER
    return len(needle) >= min_cn


def _resolve_db(path: str) -> str | None:
    expanded = os.path.expanduser(path)
    return expanded if os.path.isfile(expanded) else None


def _load_session_usernames(session_db: str) -> set[str]:
    """Return usernames that have a chat session (i.e. user actually interacted)."""
    path = _resolve_db(session_db)
    if not path:
        return set()
    try:
        conn = sqlite3.connect(path)
        cur = conn.cursor()
        cur.execute("SELECT username FROM SessionTable")
        users = {r[0] for r in cur.fetchall()}
        conn.close()
        return {u for u in users
                if not u.endswith("@chatroom") and u not in SYSTEM_USERNAMES}
    except (sqlite3.Error, OSError):
        return set()


def extract_needles(contact_db: str, session_db: str | None = None) -> set[str]:
    """Extract PII needles from contacts the user actually interacts with.

    Scope: contacts with remark set UNION contacts with a chat session.
    This covers ~5k real contacts instead of ~115k (mostly public accounts).
    """
    db_path = _resolve_db(contact_db)
    if not db_path:
        return set()

    session_users = _load_session_usernames(session_db) if session_db else set()

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT username, nick_name, alias, remark FROM contact")

    needles: set[str] = set()
    for username, nick_name, alias, remark in cur.fetchall():
        has_remark = remark is not None and remark != ""
        in_session = username in session_users if session_users else False
        if not has_remark and not in_session:
            continue
        for raw, is_remark in ((username, False), (nick_name, False),
                                (alias, False), (remark, True)):
            if raw:
                cleaned = raw.strip()
                if _should_include(cleaned, is_remark=is_remark):
                    needles.add(cleaned)

    conn.close()
    return needles


def read_manual_entries(blocklist_path: str) -> list[str]:
    if not os.path.isfile(blocklist_path):
        return []
    lines: list[str] = []
    in_manual = False
    with open(blocklist_path, encoding="utf-8") as f:
        for line in f:
            if line.strip() == MANUAL_MARKER:
                in_manual = True
                continue
            if in_manual:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    lines.append(stripped)
    return lines


def write_blocklist(
    blocklist_path: str,
    auto_needles: set[str],
    manual_entries: list[str],
) -> int:
    os.makedirs(os.path.dirname(blocklist_path), exist_ok=True)

    all_needles = sorted(auto_needles)
    with open(blocklist_path, "w", encoding="utf-8") as f:
        f.write("# AUTO-GENERATED — do not edit above the MANUAL marker\n")
        f.write(f"# {len(all_needles)} entries extracted from contact.db\n")
        f.write(f"# scope: contacts with remark OR chat session\n")
        f.write("\n")
        for n in all_needles:
            f.write(n + "\n")
        f.write("\n")
        f.write(MANUAL_MARKER + "\n")
        for m in manual_entries:
            f.write(m + "\n")

    return len(all_needles) + len(manual_entries)


def full_scan(blocklist_path: str) -> list[tuple[str, int, str, str]]:
    if not os.path.isfile(blocklist_path):
        print(f"[!] Blocklist not found: {blocklist_path}", file=sys.stderr, flush=True)
        return []

    needles: list[str] = []
    with open(blocklist_path, encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                needles.append(stripped)

    if not needles:
        print("[!] Blocklist is empty", file=sys.stderr, flush=True)
        return []

    result = subprocess.run(
        ["git", "ls-files", "-z"],
        capture_output=True, text=True,
    )
    tracked = [f for f in result.stdout.split("\0") if f]

    skip_ext = frozenset({
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg",
        ".woff", ".woff2", ".ttf", ".eot",
        ".zip", ".gz", ".tar", ".bz2",
        ".pyc", ".pyo", ".so", ".dll", ".dylib",
        ".db", ".sqlite", ".sqlite3",
    })

    violations: list[tuple[str, int, str, str]] = []
    for fpath in tracked:
        ext = os.path.splitext(fpath)[1].lower()
        if ext in skip_ext:
            continue
        try:
            with open(fpath, encoding="utf-8", errors="ignore") as f:
                for lineno, line in enumerate(f, 1):
                    for needle in needles:
                        if needle in line:
                            violations.append((fpath, lineno, needle, line.rstrip()))
        except (OSError, UnicodeDecodeError):
            continue

    return violations


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract PII blocklist from contact.db")
    parser.add_argument("--contact-db", help=f"Path to contact.db (default: {DEFAULT_CONTACT_DB})")
    parser.add_argument("--session-db", help=f"Path to session.db (default: {DEFAULT_SESSION_DB})")
    parser.add_argument("--blocklist", default=DEFAULT_BLOCKLIST,
                        help=f"Output path (default: {DEFAULT_BLOCKLIST})")
    parser.add_argument("--full-scan", action="store_true",
                        help="Scan all tracked files for PII after extraction")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print needles without writing")
    args = parser.parse_args()

    contact_db = args.contact_db or DEFAULT_CONTACT_DB
    session_db = args.session_db or DEFAULT_SESSION_DB

    if not _resolve_db(contact_db):
        print(f"[!] contact.db not found at {contact_db}. Use --contact-db to specify.",
              file=sys.stderr, flush=True)
        sys.exit(1)

    print(f"[*] contact.db: {os.path.expanduser(contact_db)}", flush=True)
    if _resolve_db(session_db):
        print(f"[*] session.db: {os.path.expanduser(session_db)}", flush=True)
    else:
        print(f"[*] session.db not found, using remark-only scope", flush=True)
        session_db = None

    needles = extract_needles(contact_db, session_db)
    print(f"[+] Extracted {len(needles)} unique needles", flush=True)

    manual = read_manual_entries(args.blocklist)
    if manual:
        print(f"[+] Preserving {len(manual)} manual entries", flush=True)

    if args.dry_run:
        print("\n--- Auto-extracted needles ---")
        for n in sorted(needles):
            print(f"  {n}")
        if manual:
            print("\n--- Manual entries ---")
            for m in manual:
                print(f"  {m}")
        return

    total = write_blocklist(args.blocklist, needles, manual)
    print(f"[+] Wrote {total} entries to {args.blocklist}", flush=True)

    if args.full_scan:
        print("\n[*] Scanning all tracked files...", flush=True)
        violations = full_scan(args.blocklist)
        if violations:
            print(f"\n[!] Found {len(violations)} PII violations:", flush=True)
            for fpath, lineno, needle, line in violations[:50]:
                print(f"  {fpath}:{lineno}  needle={needle!r}", flush=True)
                print(f"    {line[:120]}", flush=True)
            if len(violations) > 50:
                print(f"  ... and {len(violations) - 50} more", flush=True)
            sys.exit(1)
        else:
            print("[+] No PII found in tracked files", flush=True)


if __name__ == "__main__":
    main()
