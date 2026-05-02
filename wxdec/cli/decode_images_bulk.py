"""Bulk-decrypt all V2 (and V1) .dat images under WeChat attach/.

Reads keys from config.json (image_aes_key / image_xor_key), scans attach/
recursively, and writes decoded images to OUTDIR preserving the
attach/-relative path. Resume-safe: skips sources whose decoded counterpart
already exists in OUTDIR.

Usage:
  python3 bulk_decrypt_v2.py --out /path/to/outdir [--dry-run N]
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import traceback
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from wxdec.decode_image import V2_MAGIC_FULL, V1_MAGIC_FULL, decrypt_dat_file


KNOWN_OUT_SUFFIXES = (".jpg", ".png", ".gif", ".webp", ".hevc", ".wxgf", ".bin")


def existing_output(out_base: Path) -> Path | None:
    """Return existing decoded file (any known suffix) for resume."""
    for suf in KNOWN_OUT_SUFFIXES:
        p = out_base.with_suffix(out_base.suffix + suf) if out_base.suffix == "" else Path(str(out_base) + suf)
        if p.exists():
            return p
    return None


def classify_magic(head6: bytes) -> str:
    if head6 == V2_MAGIC_FULL:
        return "v2"
    if head6 == V1_MAGIC_FULL:
        return "v1"
    if len(head6) >= 2 and head6[:2] in (b"\xff\xd8", b"\x89P", b"GI", b"RI"):
        return "plain_image"
    return "unknown"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, help="output directory")
    parser.add_argument("--dry-run", type=int, default=0, help="process only first N files")
    parser.add_argument("--config", default="config.json")
    args = parser.parse_args()

    cfg = json.loads(Path(args.config).read_text())
    aes_key = cfg.get("image_aes_key")
    xor_key = cfg.get("image_xor_key")
    db_dir = cfg.get("db_dir")
    if not (aes_key and xor_key is not None and db_dir):
        print("[ERROR] config.json missing image_aes_key / image_xor_key / db_dir", file=sys.stderr, flush=True)
        return 2

    attach_dir = Path(db_dir).parent / "msg" / "attach"
    if not attach_dir.is_dir():
        print(f"[ERROR] attach dir not found: {attach_dir}", file=sys.stderr, flush=True)
        return 2

    out_dir = Path(args.out).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / "bulk.log"
    err_csv_path = out_dir / "errors.csv"

    print(f"[*] attach_dir = {attach_dir}", flush=True)
    print(f"[*] out_dir    = {out_dir}", flush=True)
    print(f"[*] aes_key    = {aes_key}", flush=True)
    print(f"[*] xor_key    = {hex(xor_key)}", flush=True)
    started = datetime.now(timezone.utc)
    print(f"[*] started_at = {started.isoformat()}", flush=True)

    print("[*] scanning ...", flush=True)
    all_dat = sorted(str(p) for p in attach_dir.rglob("*.dat"))
    total = len(all_dat)
    print(f"[*] total .dat = {total}", flush=True)

    if args.dry_run > 0:
        all_dat = all_dat[: args.dry_run]
        print(f"[*] dry-run    = {len(all_dat)} files", flush=True)

    fmt_counts: Counter[str] = Counter()
    fmt_bytes: Counter[str] = Counter()
    skipped_existing = 0
    n_v1 = 0
    n_v2 = 0
    n_plain = 0
    n_unknown = 0
    n_failed = 0
    chat_counts: Counter[str] = Counter()

    err_csv = open(err_csv_path, "w", newline="", encoding="utf-8")
    err_writer = csv.writer(err_csv)
    err_writer.writerow(["path", "magic_class", "status", "error"])
    err_csv.flush()

    log = open(log_path, "a", encoding="utf-8")

    def log_line(msg: str) -> None:
        line = f"{datetime.now(timezone.utc).isoformat()} {msg}"
        print(line, flush=True)
        log.write(line + "\n")
        log.flush()

    log_line(f"[*] start total={total} dry_run={args.dry_run}")

    try:
        for i, dat_path in enumerate(all_dat, 1):
            rel = Path(dat_path).relative_to(attach_dir)
            # chat id = first path component under attach/
            try:
                chat_id = rel.parts[0]
            except IndexError:
                chat_id = "_unknown_"
            out_base = out_dir / rel  # extension still .dat — we'll strip it
            out_no_ext = out_base.with_suffix("")  # drop the .dat
            out_no_ext.parent.mkdir(parents=True, exist_ok=True)

            existing = existing_output(out_no_ext)
            if existing is not None:
                skipped_existing += 1
                if i % 100 == 0:
                    log_line(
                        f"[{i}/{len(all_dat)}] {i*100/len(all_dat):.1f}%  "
                        f"v2={n_v2} v1={n_v1} fail={n_failed} skip={skipped_existing}  "
                        + " ".join(f"{k}={v}" for k, v in fmt_counts.most_common())
                    )
                continue

            # Read magic
            try:
                with open(dat_path, "rb") as f:
                    head = f.read(6)
            except Exception as e:
                n_failed += 1
                err_writer.writerow([dat_path, "read_error", "failed", str(e)])
                err_csv.flush()
                continue

            magic_class = classify_magic(head)

            if magic_class == "unknown":
                # could still be old XOR — try anyway, decode_image handles it
                pass

            try:
                tmp_out = str(out_no_ext) + ".tmp"
                result_path, fmt = decrypt_dat_file(dat_path, tmp_out, aes_key=aes_key, xor_key=xor_key)
                if result_path is None or fmt is None:
                    raise RuntimeError("decrypt returned (None, None)")

                # Map fmt to extension
                fmt_ext = {
                    "jpg": ".jpg",
                    "png": ".png",
                    "gif": ".gif",
                    "webp": ".webp",
                    "hevc": ".hevc",
                    "wxgf": ".wxgf",
                    "bin": ".bin",
                }.get(fmt, f".{fmt}")

                final = Path(str(out_no_ext) + fmt_ext)
                final.parent.mkdir(parents=True, exist_ok=True)
                # If result_path != tmp_out (decode_image may have appended a suffix), handle it
                rp = Path(result_path)
                if rp.exists():
                    rp.replace(final)
                elif Path(tmp_out).exists():
                    Path(tmp_out).replace(final)
                else:
                    raise RuntimeError(f"output file missing: {result_path}")

                fmt_counts[fmt] += 1
                fmt_bytes[fmt] += final.stat().st_size
                chat_counts[chat_id] += 1

                if magic_class == "v2":
                    n_v2 += 1
                elif magic_class == "v1":
                    n_v1 += 1
                elif magic_class == "plain_image":
                    n_plain += 1
                else:
                    n_unknown += 1

            except Exception as e:
                n_failed += 1
                err_writer.writerow([dat_path, magic_class, "failed", repr(e)])
                err_csv.flush()
                # Cleanup any partial tmp
                tmp_path = Path(str(out_no_ext) + ".tmp")
                if tmp_path.exists():
                    try:
                        tmp_path.unlink()
                    except Exception:
                        pass

            if i % 100 == 0 or i == len(all_dat):
                log_line(
                    f"[{i}/{len(all_dat)}] {i*100/len(all_dat):.1f}%  "
                    f"v2={n_v2} v1={n_v1} plain={n_plain} unknown_or_xor={n_unknown} "
                    f"fail={n_failed} skip={skipped_existing}  "
                    + " ".join(f"{k}={v}" for k, v in fmt_counts.most_common())
                )

    except KeyboardInterrupt:
        log_line(f"[!] interrupted at {i}/{len(all_dat)}; rerun to resume (existing outputs skipped)")
        return 130
    finally:
        err_csv.close()
        elapsed = (datetime.now(timezone.utc) - started).total_seconds()
        total_bytes = sum(fmt_bytes.values())
        # Write summary
        summary = {
            "started_utc": started.isoformat(),
            "finished_utc": datetime.now(timezone.utc).isoformat(),
            "elapsed_s": elapsed,
            "attach_dir": str(attach_dir),
            "out_dir": str(out_dir),
            "total_dat_scanned": total,
            "processed_in_run": len(all_dat),
            "v2_decoded": n_v2,
            "v1_decoded": n_v1,
            "plain_image_seen": n_plain,
            "unknown_or_xor_decoded": n_unknown,
            "failed": n_failed,
            "skipped_existing": skipped_existing,
            "fmt_counts": dict(fmt_counts),
            "fmt_bytes": dict(fmt_bytes),
            "total_decoded_bytes": total_bytes,
            "top_chats_by_image_count": chat_counts.most_common(10),
            "dry_run_limit": args.dry_run,
        }
        (out_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2))
        log_line(f"[*] done. summary -> {out_dir/'summary.json'}")
        log.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
