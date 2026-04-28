"""
wechat-decrypt 每日自动同步入口 — 由外部 OS 调度器(launchd / systemd-user /
schtasks)触发, 串联本项目的三件套:

  1. python main.py decrypt --with-wal           (DB 解密, 用 cached key 不需 sudo)
  2. python main.py decode-images                 (.dat → 明文图片镜像树)
  3. python -m wxdec.cli.decrypt_sns
       --start <today-7d> --decrypt-media         (朋友圈图: CDN ~5d 窗口期内本地化)

为什么放这里(而不是在下游消费方比如 RewindMe):
  "daily 同步 = 这三件事" 这个知识应该归属 ETL 项目自己; 下游消费方(viewer
  / analyzer / 任何用本项目产出的工具)只该知道"在 X 时间触发 wxdec 的 daily
  入口", 不该知道入口内部跑哪几步。日后这里要新增 / 调整步骤 → 改这一个文件,
  调度方零改动。

日志: 全部 stdout / stderr 给到调用方, 调度器(launchd 的 StandardOutPath /
systemd 的 journal / schtasks 的 .bat 重定向)负责落到具体日志文件。

设计原则:
  - 步骤 1 / 2 任一失败 → 整体 fail (DB / 明文图是后续步骤的输入)
  - 步骤 3 失败 → log warn 但 rc 0 (朋友圈是 best-effort, 单天 CDN 抽风
    不应阻塞下次跑)
"""
import datetime
import functools
import os
import platform
import subprocess
import sys

print = functools.partial(print, flush=True)


def _project_root():
    """`wxdec/cli/daily_sync.py` → wechat-decrypt root."""
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _project_python():
    """Prefer this project's own venv so wxdec module + zstandard / pilk / etc
    resolve;调度器通常清洗 PATH, sys.executable 是 launchd / schtasks 自己的
    Python 不可靠。"""
    root = _project_root()
    candidates = [
        os.path.join(root, "venv", "bin", "python"),
        os.path.join(root, ".venv", "bin", "python"),
        os.path.join(root, "venv", "Scripts", "python.exe"),
        os.path.join(root, ".venv", "Scripts", "python.exe"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return sys.executable


def _log(msg):
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    print(f"[{ts}] {msg}")


def _run_step(label, cmd, cwd, *, timeout=1800):
    """Run a subprocess, mirror its stdout / stderr into our own stdout / stderr
    so launchd / systemd / schtasks 的日志重定向能把全部内容打包。"""
    _log(f"--- step: {label} ---")
    _log(f"RUN: {' '.join(cmd)}")
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        _log(f"TIMEOUT after {timeout}s: {e}")
        return None
    if proc.stdout:
        _log("STDOUT:\n" + proc.stdout.rstrip())
    if proc.stderr:
        _log("STDERR:\n" + proc.stderr.rstrip())
    _log(f"rc={proc.returncode}")
    return proc


def main():
    _log("=" * 60)
    _log(f"daily-sync starting (host={platform.node()}, system={platform.system()})")
    root = _project_root()
    py = _project_python()
    _log(f"project root: {root}")
    _log(f"python:       {py}")

    # 1. DB decrypt — picks up today's WAL increments.
    proc = _run_step("decrypt --with-wal", [py, "main.py", "decrypt", "--with-wal"], cwd=root)
    if proc is None or proc.returncode != 0:
        _log("step 1 (decrypt) failed; aborting")
        return 1

    # 2. .dat image decryption (mirrors attach tree to plain image tree).
    proc = _run_step("decode-images", [py, "main.py", "decode-images"], cwd=root)
    if proc is None or proc.returncode != 0:
        _log("step 2 (decode-images) failed; aborting")
        return 1

    # 3. SNS media — only the recent 7-day window. CDN URLs typically expire
    # in ~5 days; 2 days of buffer absorbs sleep cycles / network blips.
    # Best-effort: a single bad day shouldn't fail the whole job.
    today = datetime.date.today()
    start = today - datetime.timedelta(days=7)
    end = today + datetime.timedelta(days=1)
    proc = _run_step(
        f"decrypt_sns --decrypt-media [{start}, {end})",
        [py, "-m", "wxdec.cli.decrypt_sns",
         "--start", start.isoformat(),
         "--end", end.isoformat(),
         "--decrypt-media",
         "-o", os.devnull],
        cwd=root,
    )
    if proc is None or proc.returncode != 0:
        _log("step 3 (decrypt_sns) failed — non-fatal, DB/.dat already done")

    _log("daily-sync completed OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
