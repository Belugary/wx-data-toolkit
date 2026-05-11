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

DEFAULT_DB_PATHS = [
    "~/Documents/wechat_decrypted/contact/contact.db",
]

MIN_CN_LEN = 2
MIN_ASCII_LEN = 5

GENERIC_SKIP = frozenset({
    "", "test", "test1", "test2", "admin", "user", "null", "none",
    "hello", "world", "demo", "default", "system", "service",
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


def _should_include(needle: str) -> bool:
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
    return len(needle) >= MIN_CN_LEN


def find_contact_db() -> str | None:
    for p in DEFAULT_DB_PATHS:
        expanded = os.path.expanduser(p)
        if os.path.isfile(expanded):
            return expanded
    return None


def extract_needles(db_path: str, remark_only: bool = True) -> set[str]:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    if remark_only:
        cur.execute(
            "SELECT username, nick_name, alias, remark "
            "FROM contact "
            "WHERE remark IS NOT NULL AND remark != ''"
        )
    else:
        cur.execute("SELECT username, nick_name, alias, remark FROM contact")

    needles: set[str] = set()
    for username, nick_name, alias, remark in cur.fetchall():
        for raw in (username, nick_name, alias, remark):
            if raw:
                cleaned = raw.strip()
                if _should_include(cleaned):
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
        f.write(f"# remark-only filter: contacts with remark set\n")
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
    parser.add_argument("--db", help="Path to contact.db")
    parser.add_argument("--blocklist", default=DEFAULT_BLOCKLIST,
                        help=f"Output path (default: {DEFAULT_BLOCKLIST})")
    parser.add_argument("--all-contacts", action="store_true",
                        help="Include all contacts, not just those with remark")
    parser.add_argument("--full-scan", action="store_true",
                        help="Scan all tracked files for PII after extraction")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print needles without writing")
    args = parser.parse_args()

    db_path = args.db or find_contact_db()
    if not db_path or not os.path.isfile(db_path):
        print("[!] contact.db not found. Use --db to specify path.", file=sys.stderr, flush=True)
        sys.exit(1)

    print(f"[*] Reading {db_path}", flush=True)
    needles = extract_needles(db_path, remark_only=not args.all_contacts)
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
