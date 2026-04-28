"""macOS WeChat 4.x 图片 AES key 派生（无需扫描进程内存）。

通过 macOS 微信 4.x 在磁盘上的 kvcomm 缓存文件命名约定，派生出 V2 .dat
图片解密所需的 (xor_key, aes_key)。解决 issue #23：macOS 用户无法用
C 版扫描器从进程内存提取图片密钥（197K 候选全部失败）。

派生算法
--------
- 扫 ~/.../app_data/net/kvcomm/key_<code>_*.statistic 文件名
- 对每个 (code, wxid) 候选：
    xor_key = code & 0xFF
    aes_key = MD5(str(code) + cleaned_wxid).hex()[:16]   # ASCII 字符串
- 用 V2 _t.dat 文件 [0xF:0x1F] 16 字节做模板验证：派生出的 aes_key 把
  密文 AES-128-ECB 解出图像 magic（JPEG / PNG / GIF / WebP / wxgf）即视为命中
- 为防短 magic 偶然命中，要求多个不同模板都通过验证才视为成功
- 命中后写回 config.json 的 image_aes_key / image_xor_key 字段，
  monitor_web.py 启动时自动加载，图片消息显示内联预览

致谢
----
派生算法源自 @hicccc77 在 issue #23 的评论，参考实现位于
https://github.com/hicccc77/WeFlow （CC BY-NC-SA 4.0）。本模块是独立的
Python 实现，未复制其 TypeScript 源码；函数边界与变量命名沿用算法的自然
结构（regex 模式 / MD5 调用顺序 / magic 字节表等不可避免地相同）。

用法
----
  python find_image_key_macos.py
"""
import glob
import hashlib
import json
import os
import platform
import re
import sys

from Crypto.Cipher import AES

# V2 .dat 文件 magic（与 decode_image.py 中 V2_MAGIC_FULL 一致）
V2_MAGIC = bytes.fromhex("070856320807")

# kvcomm 文件名格式：key_<code>_<其他段>.statistic
# code 必须紧跟在 "key_" 之后（不能是 "key_reportnow_..." 这种带前缀的）
_KVCOMM_FILENAME_RE = re.compile(r"^key_(\d+)_.+\.statistic$", re.IGNORECASE)

# AES 解密结果允许的图像 magic
_IMAGE_MAGICS = (
    b"\xff\xd8\xff",      # JPEG
    b"\x89\x50\x4e\x47",  # PNG
    b"GIF",               # GIF
    b"RIFF",              # WebP container（首块只能看前 16B，全检需 [8:12]==b"WEBP"）
    b"wxgf",              # 微信 HEVC GIF / Live Photo
)


def normalize_wxid(account_id):
    """归一化账号 ID。

    - wxid_<seg> 形式：保留 wxid_<seg>，丢弃后续下划线分段
    - <base>_<4 alnum> 形式：丢弃 _<4 alnum> 后缀（macOS 路径目录名常见）
    - 其他：原样返回
    """
    aid = (account_id or "").strip()
    if not aid:
        return ""
    if aid.lower().startswith("wxid_"):
        m = re.match(r"^(wxid_[^_]+)", aid, re.IGNORECASE)
        return m.group(1) if m else aid
    m = re.match(r"^(.+)_([a-zA-Z0-9]{4})$", aid)
    return m.group(1) if m else aid


def derive_image_keys(code, wxid):
    """从 (code, wxid) 派生 (xor_key, aes_key_ascii)。

    aes_key_ascii 是 16 字符 hex 字符串；调用方按 ASCII 编码取前 16 字节作为
    AES-128 密钥。本函数不做 wxid 归一化（由调用方枚举原值与归一化值）。
    """
    xor_key = int(code) & 0xFF
    aes_key = hashlib.md5(f"{code}{wxid}".encode("utf-8")).hexdigest()[:16]
    return xor_key, aes_key


def derive_kvcomm_dir_candidates(db_dir):
    """从 db_dir 推算所有可能的 kvcomm 缓存目录（按优先级排序）。

    微信 4.x 在不同版本 / 安装方式下 kvcomm 路径不固定，需要枚举多个候选。
    返回的列表里至少有一项被 os.path.isdir 确认存在时才算可用。
    """
    parts = db_dir.rstrip(os.sep).split(os.sep)
    candidates = []
    if "xwechat_files" in parts:
        idx = parts.index("xwechat_files")
        documents_root = os.sep.join(parts[:idx])
        # 1) 与 xwechat_files 兄弟目录的 app_data
        candidates.append(os.path.join(documents_root, "app_data", "net", "kvcomm"))
        # 2) 旧版可能放 xwechat 子目录
        candidates.append(os.path.join(documents_root, "xwechat", "net", "kvcomm"))
        # 3) 容器内 Application Support 路径（部分版本）
        if idx >= 1:
            container_root = os.sep.join(parts[:idx - 1])  # Documents 之上
            candidates.append(os.path.join(
                container_root, "Library", "Application Support",
                "com.tencent.xinWeChat", "xwechat", "net", "kvcomm"))
            candidates.append(os.path.join(
                container_root, "Library", "Application Support",
                "com.tencent.xinWeChat", "net", "kvcomm"))
    # 4) 兜底：HOME 下默认沙盒路径
    home = os.path.expanduser("~")
    candidates.append(os.path.join(
        home, "Library", "Containers", "com.tencent.xinWeChat", "Data",
        "Documents", "app_data", "net", "kvcomm"))
    # 去重，保留顺序
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


def find_v2_template_ciphertexts(attach_dir, max_templates=3, max_files=64):
    """在 attach_dir 下找 V2 .dat 文件的模板密文（[0xF:0x1F] 16 字节）。

    优先 _t.dat（缩略图小、读得快），找不到再降级用任意 .dat。
    返回最多 max_templates 个**不同**的密文，用于交叉验证防止短 magic 偶然命中。
    """
    if not attach_dir or not os.path.isdir(attach_dir):
        return []

    def _scan(suffix):
        # 出口条件只看是否凑够 max_templates 个**不同**密文；不因为
        # examined 达到 max_files 提前退出 —— 否则若前 64 个文件都是同一
        # 张图的副本，结果只有 1 个 template，交叉验证就退化成单模板。
        out, seen = [], set()
        examined = 0
        for root, _, files in os.walk(attach_dir):
            for f in files:
                if not f.endswith(suffix):
                    continue
                examined += 1
                try:
                    with open(os.path.join(root, f), "rb") as fp:
                        data = fp.read(0x20)
                except OSError:
                    continue
                if len(data) >= 0x1F and data[:6] == V2_MAGIC:
                    ct = data[0xF:0x1F]
                    if ct not in seen:
                        seen.add(ct)
                        out.append(ct)
                        if len(out) >= max_templates:
                            return out
                # 兜底：扫了 max_files 个文件还凑不齐 max_templates 个不同的，
                # 提前停止以免在巨型 attach 目录里跑很久（只在 out 不空时才能停）
                if examined >= max_files and out:
                    return out
        return out

    return _scan("_t.dat") or _scan(".dat")


def verify_aes_key(aes_key_ascii, template_ct):
    """AES-128-ECB 解 template_ct（16 字节），检查头部是否是图像 magic。"""
    if not aes_key_ascii or not template_ct or len(template_ct) != 16:
        return False
    key_bytes = aes_key_ascii.encode("ascii", errors="ignore")[:16]
    if len(key_bytes) < 16:
        return False
    try:
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        decrypted = cipher.decrypt(template_ct)
    except (ValueError, KeyError):
        return False
    return any(decrypted.startswith(m) for m in _IMAGE_MAGICS)


def verify_aes_key_against_all(aes_key_ascii, templates):
    """在多个模板上交叉验证 aes_key。全部通过才算命中（防短 magic 偶然碰撞）。"""
    if not templates:
        return False
    return all(verify_aes_key(aes_key_ascii, ct) for ct in templates)


def find_image_key_macos(db_dir):
    """在 macOS 上派生并交叉验证 V2 图片密钥。

    Returns:
        (xor_key, aes_key_ascii) on success；失败返回 None 并打印诊断信息。
    """
    kvcomm_dir = find_existing_kvcomm_dir(db_dir)
    if not kvcomm_dir:
        print(f"[!] 找不到 kvcomm 缓存目录，已尝试以下候选:", flush=True)
        for c in derive_kvcomm_dir_candidates(db_dir):
            print(f"      {c}", flush=True)
        print("    通常意味着微信尚未生成密钥缓存，请先在微信中查看 1-2 张图片",
              flush=True)
        return None
    print(f"[+] 使用 kvcomm 目录: {kvcomm_dir}", flush=True)

    codes = collect_kvcomm_codes(kvcomm_dir)
    if not codes:
        print(f"[!] kvcomm 目录无 key_*.statistic 文件: {kvcomm_dir}", flush=True)
        return None
    print(f"[+] 找到 {len(codes)} 个 code 候选", flush=True)

    wxid_candidates = collect_wxid_candidates(db_dir)
    if not wxid_candidates:
        print(f"[!] 无法从 db_dir 提取 wxid: {db_dir}", flush=True)
        return None
    print(f"[+] wxid 候选: {wxid_candidates}", flush=True)

    base_dir = os.path.dirname(db_dir)  # 去掉 db_storage
    attach_dir = os.path.join(base_dir, "msg", "attach")
    templates = find_v2_template_ciphertexts(attach_dir)
    if not templates:
        print(f"[!] 在 {attach_dir} 下找不到 V2 模板文件", flush=True)
        print("    请先在微信中查看 1-2 张图片，让微信生成 V2 .dat 文件",
              flush=True)
        return None
    print(f"[+] 找到 {len(templates)} 个不同模板用于交叉验证", flush=True)

    # 穷举顺序：wxid 外、code 内。这样多账号系统下当前账号的所有 code 优先尝试。
    for wxid in wxid_candidates:
        for code in codes:
            xor_key, aes_key = derive_image_keys(code, wxid)
            if verify_aes_key_against_all(aes_key, templates):
                print()
                print("[✓] 验证成功（所有模板均通过）:", flush=True)
                print(f"    code     = {code}", flush=True)
                print(f"    wxid     = {wxid}", flush=True)
                print(f"    xor_key  = 0x{xor_key:02x}", flush=True)
                print(f"    aes_key  = {aes_key}", flush=True)
                return xor_key, aes_key

    print()
    print("[!] 所有 (wxid × code) 组合都未通过交叉验证", flush=True)
    print("    可能原因：微信版本变更了派生算法 / 缓存已失效 / 模板文件损坏",
          flush=True)
    return None


def _save_config_atomic(config_path, config):
    """原子写 config.json：tmp + os.replace 防止中断留下半截文件。

    若 json.dump 或 os.replace 抛错，向上抛出（让 main 给出 stacktrace
    而不是默默写坏 config）；同时清理可能残留的 .tmp 文件。
    """
    tmp_path = config_path + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, config_path)
    finally:
        # 失败路径上 .tmp 可能残留；成功路径上 os.replace 已经把 tmp 移走了
        if os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def main(config_path=None):
    """CLI 入口。`config_path` 默认是脚本同目录下的 config.json，
    暴露此参数主要为方便单元测试注入隔离的临时配置。"""
    if platform.system().lower() != "darwin":
        print("此脚本只在 macOS 上工作。其他平台请用 find_image_key.py（内存扫描）。",
              file=sys.stderr, flush=True)
        sys.exit(1)

    if config_path is None:
        config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
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
    print(f"[*] db_dir = {db_dir}", flush=True)

    # 短路：如果已有 image_aes_key 且仍能在所有模板上验证通过，直接退出
    # （沿用 find_image_key.py 的 UX 约定，避免无谓重写 config.json）
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
    _save_config_atomic(config_path, config)
    print()
    print(f"[+] 已写入 {config_path}", flush=True)
    print("    下次启动 monitor_web.py 时会自动加载新密钥，图片消息显示内联预览",
          flush=True)


if __name__ == "__main__":
    main()
