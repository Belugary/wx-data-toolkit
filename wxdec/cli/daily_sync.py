"""
wx-data-toolkit 每日自动同步入口 — 由外部 OS 调度器(launchd / systemd-user /
schtasks)触发, 串联本项目的三件套:

  1. python main.py decrypt --with-wal           (DB 导出, 用 cached key 不需 sudo)
  2. python main.py decode-images                 (.dat → 标准格式图片镜像树)
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
  - 三步独立, 任一步失败不阻塞其余步骤 — 它们的输入彼此解耦:
      * step 1 读微信进程内存 (需 WeChat 在跑) → 写 decrypted/
      * step 2 读 msg/attach/*.dat (微信自己落盘) + config.json image_aes_key
        → 写 decoded_image_dir/   不依赖 step 1 当日是否成功
      * step 3 读已存在的 decrypted/sns/sns.db (可以是上次跑的旧版) + CDN
        → 写 sns 媒体目录   不依赖 step 1 当日是否成功
  - 任一步失败 → 整体 rc=1 (调度器能感知), 但失败步骤不阻塞后续步骤运行
  - 历史版本曾让 step 1 失败直接 abort, 导致微信偶尔没开的那一天连图片备份
    一并停摆 — 这是错误的依赖假设, 已修正
"""
import datetime
import functools
import os
import platform
import subprocess
import sys
import threading

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
    """Run a subprocess, streaming its merged stdout / stderr line-by-line into
    our log so 长跑步骤(decrypt 全量 + WAL 合并 7.6GB 可能数分钟)在 launchd /
    systemd / schtasks 日志里实时可见 — buffering 到结束才一次性倾倒, 中途看起来
    像 hung, 而且 timeout 杀掉时丢失最有价值的卡死前最后输出。"""
    _log(f"--- step: {label} ---")
    _log(f"RUN: {' '.join(cmd)}")
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    proc = subprocess.Popen(
        cmd, cwd=cwd, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )

    def _stream():
        assert proc.stdout is not None
        for line in proc.stdout:
            _log(line.rstrip())

    t = threading.Thread(target=_stream, daemon=True)
    t.start()
    try:
        rc = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        rc = proc.wait()
        t.join(timeout=5)
        _log(f"TIMEOUT after {timeout}s: killed (rc={rc})")
        return None
    t.join(timeout=5)
    _log(f"rc={rc}")
    return proc


def main():
    _log("=" * 60)
    _log(f"daily-sync starting (host={platform.node()}, system={platform.system()})")
    root = _project_root()
    py = _project_python()
    _log(f"project root: {root}")
    _log(f"python:       {py}")

    failures = []

    # 1. DB decrypt — picks up today's WAL increments. Needs WeChat process
    # running (key dump from process memory). If WeChat is not running, this
    # step fails but downstream steps continue using the previous run's exports.
    proc = _run_step("decrypt --with-wal", [py, "main.py", "decrypt", "--with-wal"], cwd=root)
    if proc is None or proc.returncode != 0:
        _log("step 1 (decrypt) failed — continuing with previous run's exports")
        failures.append("decrypt")

    # 2. .dat image decryption (mirrors attach tree to plain image tree).
    # Independent of step 1: reads msg/attach/*.dat (written by WeChat itself)
    # and uses image_aes_key from config.json (static, no process dump needed).
    proc = _run_step("decode-images", [py, "main.py", "decode-images"], cwd=root)
    if proc is None or proc.returncode != 0:
        _log("step 2 (decode-images) failed")
        failures.append("decode-images")

    # 3. SNS media — only the recent 7-day window. CDN URLs typically expire
    # in ~5 days; 2 days of buffer absorbs sleep cycles / network blips.
    # Reads existing decrypted/sns/sns.db (may be stale if step 1 failed today,
    # which only means the latest day of posts is missing — still worth running
    # for the prior 6 days of CDN catch-up).
    today = datetime.datetime.now(datetime.timezone.utc).date()
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
        _log("step 3 (decrypt_sns) failed")
        failures.append("decrypt_sns")

    if failures:
        _log(f"daily-sync completed with failures: {failures}")
        return 1
    _log("daily-sync completed OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
