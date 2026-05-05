#!/usr/bin/env python3
"""Decode WeChat's local SNS image cache (V2 format) into standard images.

Background: WeChat keeps a per-month local copy of every SNS image the user
has scrolled past, under
    <wxfile_root>/cache/<YYYY-MM>/Sns/Img/<md5_prefix>/<md5_rest>
These files share the same V2 / V1 / XOR magic as msg/attach .dat files, so
they decode with the existing wxdec.decode_image.decrypt_dat_file routine
- they just don't carry the .dat suffix.

This script walks every cache month, decodes each cache file, and writes the
result as <out_dir>/<YYYY-MM>/<original_md5>.<ext>. Useful when the SNS CDN
has long since expired the original media (>3-7 days) but a local copy is
still on disk.

Usage:
  python tools/decode_sns_cache.py \
      --cache-dir ~/Library/Containers/.../your_wxid/cache \
      --out-dir ~/Documents/wechat_decoded_images/sns_cache \
      [-j 4]

Idempotent: existing <out_dir>/<YYYY-MM>/<md5>.* are skipped.
"""
from __future__ import annotations

import argparse
import functools
import os
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

# Allow running as a script
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
# decrypt_dat_file lives in the main repo, not the worktree. Resolve via the
# wxdec installed by sys.path.insert (worktree's wxdec or main repo's).
from wxdec.decode_image import decrypt_dat_file
from wxdec.config import load_config

print = functools.partial(print, flush=True)


def _decode_one(args: tuple) -> tuple[str, str, str]:
    """Worker: decode a single cache file. Returns (cache_path, out_path, status)."""
    cache_path, out_dir, aes_key, xor_key = args
    md5 = os.path.basename(os.path.dirname(cache_path)) + os.path.basename(cache_path)
    if len(md5) != 32:
        return cache_path, "", "skip-bad-name"

    # path layout: <cache>/<YYYY-MM>/Sns/Img/<prefix>/<rest>
    # need 4 dirname() to get from <rest> back to <YYYY-MM>
    month_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(cache_path))))
    month = os.path.basename(month_dir)
    target_month_dir = os.path.join(out_dir, month)
    for ext in ("jpg", "png", "gif", "webp", "bmp"):
        if os.path.isfile(os.path.join(target_month_dir, f"{md5}.{ext}")):
            return cache_path, "", "skip-existing"

    os.makedirs(target_month_dir, exist_ok=True)
    out_stub = os.path.join(target_month_dir, md5)  # decrypt_dat_file appends .ext

    try:
        out_path, fmt = decrypt_dat_file(
            cache_path, out_path=None, aes_key=aes_key, xor_key=xor_key
        )
    except Exception as e:
        return cache_path, "", f"error-{type(e).__name__}"

    if not out_path or not fmt:
        return cache_path, "", "error-no-format"

    # decrypt_dat_file writes next to the input file (no .dat suffix to strip).
    # Move to <out_dir>/<YYYY-MM>/<md5>.<ext>.
    final_path = f"{out_stub}.{fmt}"
    try:
        os.replace(out_path, final_path)
    except OSError as e:
        return cache_path, out_path, f"error-move-{e.errno}"
    return cache_path, final_path, "ok"


def _safe_listdir(path: str, retries: int = 5) -> list[str]:
    """listdir with EINTR retry — macOS sometimes interrupts long syscalls."""
    last_exc: Optional[Exception] = None
    for _ in range(retries):
        try:
            return os.listdir(path)
        except InterruptedError as e:
            last_exc = e
            continue
    raise last_exc if last_exc else RuntimeError("listdir failed")


def collect_cache_files(cache_dir: str) -> list[str]:
    """Walk cache_dir and return every Sns/Img/<prefix>/<rest> file."""
    out = []
    if not os.path.isdir(cache_dir):
        return out
    for month in sorted(_safe_listdir(cache_dir)):
        img_dir = os.path.join(cache_dir, month, "Sns", "Img")
        if not os.path.isdir(img_dir):
            continue
        for prefix in _safe_listdir(img_dir):
            prefix_path = os.path.join(img_dir, prefix)
            if not os.path.isdir(prefix_path):
                continue
            for fname in _safe_listdir(prefix_path):
                full = os.path.join(prefix_path, fname)
                if os.path.isfile(full):
                    out.append(full)
    return out


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="decode_sns_cache.py",
        description="Decode WeChat local SNS image cache (V2/V1) to standard images.",
    )
    p.add_argument("--cache-dir", help="WeChat cache root, e.g. .../your_wxid/cache")
    p.add_argument("--out-dir", help="output dir; defaults to <decoded_image_dir>/sns_cache")
    p.add_argument("--aes-key", help="V2 AES key (16 ascii chars); from config if omitted")
    p.add_argument("--xor-key", default="0x88", help="V2 XOR key (default 0x88)")
    p.add_argument("-j", "--jobs", type=int, default=max(1, (os.cpu_count() or 4) - 1),
                   help="parallel processes (default: cpu-1)")
    args = p.parse_args(argv)

    cfg = {}
    try:
        cfg = load_config()
    except SystemExit:
        if not (args.cache_dir and args.aes_key and args.out_dir):
            raise

    cache_dir = args.cache_dir or os.path.join(
        os.path.expanduser(cfg.get("db_dir", "")).rstrip("/").rsplit("/", 1)[0],
        "cache",
    )
    cache_dir = os.path.expanduser(cache_dir)

    out_dir = args.out_dir or os.path.join(
        os.path.expanduser(cfg.get("decoded_image_dir", "decoded_images")),
        "sns_cache",
    )
    out_dir = os.path.expanduser(out_dir)

    aes_key = args.aes_key or cfg.get("image_aes_key")
    xor_key = int(args.xor_key, 0) if isinstance(args.xor_key, str) else args.xor_key

    if not os.path.isdir(cache_dir):
        print(f"[!] cache dir not found: {cache_dir}", file=sys.stderr)
        return 2

    print(f"[*] cache_dir = {cache_dir}", file=sys.stderr)
    print(f"[*] out_dir   = {out_dir}", file=sys.stderr)
    print(f"[*] jobs      = {args.jobs}", file=sys.stderr)

    files = collect_cache_files(cache_dir)
    print(f"[*] {len(files)} cache files to process", file=sys.stderr)
    if not files:
        return 0

    counts: dict[str, int] = {}
    done = 0
    work_args = [(f, out_dir, aes_key, xor_key) for f in files]

    if args.jobs == 1:
        for w in work_args:
            _, _, status = _decode_one(w)
            counts[status] = counts.get(status, 0) + 1
            done += 1
            if done % 500 == 0:
                print(f"  progress: {done}/{len(files)} {dict(counts)}", file=sys.stderr)
    else:
        with ProcessPoolExecutor(max_workers=args.jobs) as ex:
            futures = [ex.submit(_decode_one, w) for w in work_args]
            for fut in as_completed(futures):
                _, _, status = fut.result()
                counts[status] = counts.get(status, 0) + 1
                done += 1
                if done % 500 == 0:
                    print(f"  progress: {done}/{len(files)} {dict(counts)}", file=sys.stderr)

    detail = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    fail = sum(v for k, v in counts.items() if k.startswith("error"))
    print(f"[+] done: {detail}", file=sys.stderr)
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
