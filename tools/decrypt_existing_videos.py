#!/usr/bin/env python3
"""Batch-restore previously downloaded .mp4.enc files.

Use case: an earlier run downloaded SNS video bytes but had no way to extract
the post-level <enc key="..."/> seed, so it parked the encrypted bytes as
<videomd5>.mp4.enc. This script reads the seed from sns.db and restores the
plaintext .mp4 alongside (or to a separate --out-dir).

Usage:
  python tools/decrypt_existing_videos.py \
      --enc-dir /tmp/sns_v_test \
      --sns-db ~/Documents/wechat_decrypted/sns/sns.db

The script:
  - Maps every <videomd5> in sns.db to its post-level <enc key>.
  - Walks --enc-dir for *.mp4.enc and looks each one up by stem (= videomd5).
  - XORs first 128KB with the ISAAC-64 keystream and validates ftyp.
  - Writes <videomd5>.mp4 next to the .enc (or in --out-dir).
  - Skips files where the .mp4 output already exists (idempotent).
  - Leaves the .mp4.enc untouched (use --remove-enc to drop them after success).
"""
from __future__ import annotations

import argparse
import functools
import os
import re
import sqlite3
import sys
from pathlib import Path
from typing import Optional

# Allow running as a script without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wxdec.cli.decrypt_sns import _decode_blob_to_xml
from wxdec.sns_isaac import decrypt_video_bytes, detect_mp4

print = functools.partial(print, flush=True)


_VIDEOMD5_RE = re.compile(r'videomd5="([0-9a-f]{32})"')
_ENC_KEY_RE = re.compile(r'<enc\s+key="(\d+)"', re.IGNORECASE)


def build_videomd5_to_key_map(db_path: str) -> dict[str, str]:
    """Walk SnsTimeLine and collect every (videomd5 -> post-level enc seed) pair.

    A single post may contain multiple <media type=6> entries — they share the
    same post-level <enc key>. Returns a flat dict.
    """
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute("SELECT content FROM SnsTimeLine").fetchall()
    finally:
        conn.close()

    mapping: dict[str, str] = {}
    for (content,) in rows:
        xml = _decode_blob_to_xml(content)
        if not xml or "<type>6</type>" not in xml:
            continue
        m = _ENC_KEY_RE.search(xml)
        if not m:
            continue
        enc_key = m.group(1)
        for vmd5 in _VIDEOMD5_RE.findall(xml):
            # 同一 videomd5 在多帖子 (转发) 出现, 后写覆盖前; 但 enc_key 也跟着
            # 那帖子, 任意一个 key 都能解出同一字节流, 不影响正确性。
            mapping[vmd5] = enc_key
    return mapping


def restore_one(enc_path: Path, key: str, out_path: Path) -> tuple[bool, str]:
    """Read enc_path, decrypt, validate, write out_path. Returns (ok, status)."""
    if out_path.exists():
        return True, "skip-existing"

    try:
        payload = enc_path.read_bytes()
    except OSError as e:
        return False, f"error-read({e})"

    if detect_mp4(payload[:8]):
        # Already plaintext on disk (rename mishap?) — just copy bytes as-is.
        out_path.write_bytes(payload)
        return True, "ok-already-plain"

    plain = decrypt_video_bytes(payload, key)
    if plain is None:
        return False, "error-bad-magic"

    tmp = out_path.with_suffix(out_path.suffix + ".part")
    tmp.write_bytes(plain)
    os.replace(tmp, out_path)
    return True, "ok"


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="decrypt_existing_videos.py",
        description="Restore previously downloaded *.mp4.enc files using <enc key> from sns.db.",
    )
    p.add_argument(
        "--enc-dir",
        required=True,
        help="Directory containing *.mp4.enc files (e.g., /tmp/sns_v_test)",
    )
    p.add_argument(
        "--sns-db",
        required=True,
        help="Path to exported sns.db (e.g., ~/Documents/wechat_decrypted/sns/sns.db)",
    )
    p.add_argument(
        "--out-dir",
        default=None,
        help="Output directory for restored .mp4 (default: same as --enc-dir)",
    )
    p.add_argument(
        "--remove-enc",
        action="store_true",
        help="Delete the .mp4.enc after a successful restore (default: keep)",
    )

    args = p.parse_args(argv)
    enc_dir = Path(os.path.expanduser(args.enc_dir))
    sns_db = Path(os.path.expanduser(args.sns_db))
    out_dir = Path(os.path.expanduser(args.out_dir)) if args.out_dir else enc_dir

    if not enc_dir.is_dir():
        print(f"[!] --enc-dir not found: {enc_dir}", file=sys.stderr)
        return 2
    if not sns_db.is_file():
        print(f"[!] --sns-db not found: {sns_db}", file=sys.stderr)
        return 2
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] reading seed map from: {sns_db}", file=sys.stderr)
    seed_map = build_videomd5_to_key_map(str(sns_db))
    print(f"[*] {len(seed_map)} (videomd5 -> seed) pairs in sns.db", file=sys.stderr)

    enc_files = sorted(enc_dir.glob("*.mp4.enc"))
    if not enc_files:
        print(f"[!] no *.mp4.enc found in {enc_dir}", file=sys.stderr)
        return 1

    print(f"[*] {len(enc_files)} encrypted videos to process", file=sys.stderr)
    counts: dict[str, int] = {}
    for i, enc_path in enumerate(enc_files, 1):
        videomd5 = enc_path.stem.removesuffix(".mp4")
        out_path = out_dir / f"{videomd5}.mp4"
        seed = seed_map.get(videomd5)

        if not seed:
            status = "error-no-seed-in-db"
            print(f"  [{i}/{len(enc_files)}] {videomd5[:12]}... {status}", file=sys.stderr)
            counts[status] = counts.get(status, 0) + 1
            continue

        ok, status = restore_one(enc_path, seed, out_path)
        counts[status] = counts.get(status, 0) + 1
        marker = "OK  " if ok else "FAIL"
        print(f"  [{i}/{len(enc_files)}] {marker} {videomd5[:12]}... -> {out_path.name} ({status})",
              file=sys.stderr)
        if ok and args.remove_enc and status in ("ok", "ok-already-plain"):
            enc_path.unlink(missing_ok=True)

    detail = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    fail = sum(v for k, v in counts.items() if k.startswith("error"))
    print(f"[+] done: {detail}", file=sys.stderr)
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
