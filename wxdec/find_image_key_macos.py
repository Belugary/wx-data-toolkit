"""macOS WeChat 4.x 图片 AES key 派生（无需读运行进程）。

通过 macOS 微信 4.x 在磁盘上的命名约定派生出 V2 .dat 图片解密所需的
(xor_key, aes_key)。解决 issue #23：macOS 用户无法用 C 版扫描器从运行
进程读取出有效的访问凭据（197K 候选全部失败）。

uin 来源（两条路径，dispatcher 自动 fallback）
----------------------------------------------
方案1（kvcomm 缓存文件名，主路径）：
  读 ~/.../app_data/net/kvcomm/key_<uin>_*.statistic 提 uin。
  优点：~毫秒级；缺点：依赖缓存文件，多账号下可能歧义。

方案2（wxid 后缀候选搜索，fallback 路径）：
  委托给跨平台模块 find_image_key_offline.bruteforce_image_key()。

致谢
----
- 方案1（kvcomm 派生）算法源自 @hicccc77 在 issue #23 的评论，参考实现
  位于 https://github.com/hicccc77/WeFlow （CC BY-NC-SA 4.0）。
- 方案2（wxid 后缀候选搜索）思路源自 @H3CoF6 在 issue #68 的评论。

用法
----
  python find_image_key_macos.py
"""
import json
import os
import platform
import re
import sys

# 跨平台核心算法 — 从 find_image_key_offline 导入
from wxdec.find_image_key_offline import (  # noqa: F401 — re-exported for tests/callers
    V2_MAGIC,
    IMAGE_MAGICS,
    _aes_template_match,
    _bruteforce_worker_chunk,
    bruteforce_image_key,
    bruteforce_uin_candidates,
    bruteforce_with_aes_parallel,
    derive_image_keys,
    derive_xor_key_from_v2_dat,
    extract_wxid_parts,
    find_image_key_offline,
    find_v2_template_ciphertexts,
    normalize_wxid,
    save_config_atomic,
    verify_aes_key,
    verify_aes_key_against_all,
)

# backward-compat aliases (tests reference private names)
_IMAGE_MAGICS = IMAGE_MAGICS
_bruteforce_with_aes_parallel = bruteforce_with_aes_parallel
_find_via_bruteforce = bruteforce_image_key
_save_config_atomic = save_config_atomic

# ──────────────────────────────── macOS-only: kvcomm (方案1) ──────── #

_KVCOMM_FILENAME_RE = re.compile(r"^key_(\d+)_.+\.statistic$", re.IGNORECASE)


def derive_kvcomm_dir_candidates(db_dir):
    """从 db_dir 推算所有可能的 kvcomm 缓存目录（按优先级排序）。"""
    parts = db_dir.rstrip(os.sep).split(os.sep)
    candidates = []
    if "xwechat_files" in parts:
        idx = parts.index("xwechat_files")
        documents_root = os.sep.join(parts[:idx])
        candidates.append(os.path.join(documents_root, "app_data", "net", "kvcomm"))
        candidates.append(os.path.join(documents_root, "xwechat", "net", "kvcomm"))
        if idx >= 1:
            container_root = os.sep.join(parts[:idx - 1])
            candidates.append(os.path.join(
                container_root, "Library", "Application Support",
                "com.tencent.xinWeChat", "xwechat", "net", "kvcomm"))
            candidates.append(os.path.join(
                container_root, "Library", "Application Support",
                "com.tencent.xinWeChat", "net", "kvcomm"))
    home = os.path.expanduser("~")
    candidates.append(os.path.join(
        home, "Library", "Containers", "com.tencent.xinWeChat", "Data",
        "Documents", "app_data", "net", "kvcomm"))
    seen = set()
    deduped = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            deduped.append(c)
    return deduped


def find_existing_kvcomm_dir(db_dir):
    """从候选路径中返回第一个存在的 kvcomm 目录；都不存在返回 None。"""
    for candidate in derive_kvcomm_dir_candidates(db_dir):
        if os.path.isdir(candidate):
            return candidate
    return None


def collect_kvcomm_codes(kvcomm_dir):
    """扫 kvcomm 目录，返回去重排序的 code 列表。"""
    if not kvcomm_dir or not os.path.isdir(kvcomm_dir):
        return []
    codes = set()
    try:
        names = os.listdir(kvcomm_dir)
    except OSError:
        return []
    for name in names:
        m = _KVCOMM_FILENAME_RE.match(name)
        if not m:
            continue
        try:
            code = int(m.group(1))
        except ValueError:
            continue
        if 0 < code <= 0xFFFFFFFF:
            codes.add(code)
    return sorted(codes)


def collect_wxid_candidates(db_dir):
    """从 db_dir 提取候选 wxid（含原值和归一化值）。"""
    parts = db_dir.rstrip(os.sep).split(os.sep)
    if "xwechat_files" not in parts:
        return []
    idx = parts.index("xwechat_files")
    if idx + 1 >= len(parts):
        return []
    raw = parts[idx + 1]
    candidates = [raw]
    normalized = normalize_wxid(raw)
    if normalized and normalized != raw:
        candidates.append(normalized)
    return candidates


# ────────────────────────────── Dispatcher + 方案1 ──────────────── #

def _find_via_kvcomm(db_dir, templates):
    """方案1：从 kvcomm 缓存文件名提 uin 候选。"""
    kvcomm_dir = find_existing_kvcomm_dir(db_dir)
    if not kvcomm_dir:
        print("[!] 方案1: 找不到 kvcomm 缓存目录，已尝试以下候选:", flush=True)
        for c in derive_kvcomm_dir_candidates(db_dir):
            print(f"      {c}", flush=True)
        return None
    print(f"[+] 方案1: 使用 kvcomm 目录 {kvcomm_dir}", flush=True)

    codes = collect_kvcomm_codes(kvcomm_dir)
    if not codes:
        print("[!] 方案1: kvcomm 目录无 key_*.statistic 文件", flush=True)
        return None
    print(f"[+] 方案1: 找到 {len(codes)} 个 uin 候选", flush=True)

    wxid_candidates = collect_wxid_candidates(db_dir)
    if not wxid_candidates:
        print("[!] 方案1: 无法从 db_dir 提取 wxid", flush=True)
        return None
    print(f"[+] 方案1: wxid 候选 {wxid_candidates}", flush=True)

    for wxid in wxid_candidates:
        for code in codes:
            xor_key, aes_key = derive_image_keys(code, wxid)
            if verify_aes_key_against_all(aes_key, templates):
                print()
                print("[OK] 方案1 验证成功（所有模板均通过）:", flush=True)
                print(f"    uin      = {code}", flush=True)
                print(f"    wxid     = {wxid}", flush=True)
                print(f"    xor_key  = 0x{xor_key:02x}", flush=True)
                print(f"    aes_key  = {aes_key}", flush=True)
                return xor_key, aes_key

    print("[!] 方案1: 所有 (wxid × uin) 组合都未通过交叉验证", flush=True)
    return None


def find_image_key_macos(db_dir):
    """在 macOS 上派生并交叉验证 V2 图片密钥。

    Dispatcher：先尝试方案1 (kvcomm)，失败 fallback 到方案2 (候选搜索)。

    Returns:
        (xor_key, aes_key_ascii) on success；失败返回 None。
    """
    base_dir = os.path.dirname(db_dir)
    attach_dir = os.path.join(base_dir, "msg", "attach")
    templates = find_v2_template_ciphertexts(attach_dir)
    if not templates:
        print(f"[!] 在 {attach_dir} 下找不到 V2 模板文件", flush=True)
        print("    请先在微信中查看 1-2 张图片，让微信生成 V2 .dat 文件",
              flush=True)
        return None
    print(f"[+] 找到 {len(templates)} 个不同模板用于交叉验证", flush=True)

    result = _find_via_kvcomm(db_dir, templates)
    if result is not None:
        return result

    print()
    print("[*] 方案1 失败, 尝试方案2 (wxid 后缀候选搜索, fallback)", flush=True)
    return bruteforce_image_key(db_dir, attach_dir, templates)


# ──────────────────────────────────────────────────────────── CLI ──── #

def main(config_path=None):
    """CLI 入口。`config_path` 默认是脚本同目录下的 config.json，
    暴露此参数主要为方便单元测试注入隔离的临时配置。"""
    if platform.system().lower() != "darwin":
        print("此脚本只在 macOS 上工作。其他平台请用 find_image_key_offline.py。",
              file=sys.stderr, flush=True)
        sys.exit(1)

    if config_path is None:
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "config.json")
    try:
        with open(config_path, encoding="utf-8") as f:
            config = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"[!] 读取 {config_path} 失败: {e}", file=sys.stderr, flush=True)
        sys.exit(1)

    db_dir = config.get("db_dir", "")
    if not db_dir:
        print("[!] config.json 中未配置 db_dir", file=sys.stderr, flush=True)
        sys.exit(1)
    db_dir = os.path.expanduser(os.path.expandvars(db_dir))
    print(f"[*] db_dir = {db_dir}", flush=True)

    existing_aes = config.get("image_aes_key")
    if existing_aes:
        base_dir = os.path.dirname(db_dir)
        attach_dir = os.path.join(base_dir, "msg", "attach")
        templates = find_v2_template_ciphertexts(attach_dir)
        if templates and verify_aes_key_against_all(existing_aes, templates):
            print(f"[+] 已有 image_aes_key={existing_aes} 在 "
                  f"{len(templates)} 个模板上仍然有效，无需重新派生", flush=True)
            return

    result = find_image_key_macos(db_dir)
    if result is None:
        sys.exit(1)

    xor_key, aes_key = result
    config["image_aes_key"] = aes_key
    config["image_xor_key"] = xor_key
    save_config_atomic(config_path, config)
    print()
    print(f"[+] 已写入 {config_path}", flush=True)
    print("    下次启动 monitor_web.py 时会自动加载新密钥，图片消息显示内联预览",
          flush=True)


if __name__ == "__main__":
    main()
