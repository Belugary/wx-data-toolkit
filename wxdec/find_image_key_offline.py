"""跨平台离线图片 AES key 派生（无需读运行进程）。

通过微信在磁盘上的目录命名约定派生出 V2 .dat 图片解密所需的
(xor_key, aes_key)。不依赖任何 OS 特定 API —— 纯文件系统 + 密码学运算。

派生算法
--------
- xor_key = uin & 0xFF
- aes_key = MD5(str(uin) + cleaned_wxid).hex()[:16]   # ASCII 字符串
- 用 V2 _t.dat 文件 [0xF:0x1F] 16 字节做模板验证：派生出的 aes_key 把
  密文 AES-128-ECB 解出图像 magic（JPEG / PNG / GIF / WebP / wxgf）即视为命中
- 为防短 magic 偶然命中，要求多个不同模板都通过验证才视为成功

wxid 后缀候选搜索
------------------
关键洞察（@H3CoF6, issue #68）：wxid 目录后 4 位 hex == md5(str(uin))[:4]。

流程：从 V2 .dat 末字节投票反推 xor_key（假设 JPG EOI = 0xD9）→
枚举 (uin & 0xff == xor_key) 的 2^24 个候选 → md5 前缀匹配
得 ~256 个 uin 候选 → AES 模板验证唯一定位。

用法
----
  python -m wxdec.find_image_key_offline          # 读 config.json, 自动派生
  python -m wxdec.find_image_key_offline --help    # 查看选项
"""
import hashlib
import json
import multiprocessing
import os
import queue as _queue
import re
import sys
import time
from collections import Counter

from Crypto.Cipher import AES

# ──────────────────────────────────────────────────────── constants ──── #

V2_MAGIC = bytes.fromhex("070856320807")

IMAGE_MAGICS = (
    b"\xff\xd8\xff",      # JPEG
    b"\x89\x50\x4e\x47",  # PNG
    b"GIF",               # GIF
    b"RIFF",              # WebP container
    b"wxgf",              # 微信 HEVC GIF / Live Photo
)

# md5 hex 后缀只可能是 [0-9a-f]
_WXID_HEX_SUFFIX_RE = re.compile(r"^(.+)_([0-9a-fA-F]{4})$")

# ────────────────────────────────────────────────── core derivation ──── #


def normalize_wxid(account_id):
    """归一化账号 ID。

    - wxid_<seg> 形式：保留 wxid_<seg>，丢弃后续下划线分段
    - <base>_<4 alnum> 形式：丢弃 _<4 alnum> 后缀
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
    AES-128 密钥。
    """
    xor_key = int(code) & 0xFF
    aes_key = hashlib.md5(f"{code}{wxid}".encode("utf-8")).hexdigest()[:16]
    return xor_key, aes_key


# ──────────────────────────────────────────────────── verification ──── #


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
    return any(decrypted.startswith(m) for m in IMAGE_MAGICS)


def verify_aes_key_against_all(aes_key_ascii, templates):
    """在多个模板上交叉验证 aes_key。全部通过才算命中。"""
    if not templates:
        return False
    return all(verify_aes_key(aes_key_ascii, ct) for ct in templates)


# ──────────────────────────────────────────────── template / xor_key ──── #


def find_v2_template_ciphertexts(attach_dir, max_templates=3, max_files=64):
    """在 attach_dir 下找 V2 .dat 文件的模板密文（[0xF:0x1F] 16 字节）。

    优先 _t.dat（缩略图小、读得快），找不到再降级用任意 .dat。
    返回最多 max_templates 个**不同**的密文，用于交叉验证。
    """
    if not attach_dir or not os.path.isdir(attach_dir):
        return []

    def _scan(suffix):
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
                if examined >= max_files and out:
                    return out
        return out

    return _scan("_t.dat") or _scan(".dat")


def derive_xor_key_from_v2_dat(attach_dir, sample=10, min_samples=3):
    """扫多个 V2 .dat 末字节投票反推 xor_key（假设 JPG EOI = 0xD9）。

    Returns:
        (xor_key, votes, total) 或 None（样本不足 / 找不到 V2 .dat）。
    """
    if not attach_dir or not os.path.isdir(attach_dir):
        return None
    last_bytes = []
    for root, _, files in os.walk(attach_dir):
        for f in files:
            if not f.endswith(".dat"):
                continue
            path = os.path.join(root, f)
            try:
                if os.path.getsize(path) < 0x20:
                    continue
                with open(path, "rb") as fp:
                    head = fp.read(6)
                    if head != V2_MAGIC:
                        continue
                    fp.seek(-1, 2)
                    last = fp.read(1)[0]
                last_bytes.append(last ^ 0xD9)
                if len(last_bytes) >= sample:
                    break
            except OSError:
                continue
        if len(last_bytes) >= sample:
            break
    if len(last_bytes) < min_samples:
        return None
    top, votes = Counter(last_bytes).most_common(1)[0]
    return top, votes, len(last_bytes)


# ──────────────────────────────────────────── wxid parsing (portable) ──── #


def extract_wxid_parts(db_dir):
    """从 db_dir 提取 (wxid_full, wxid_base, suffix)。

    db_dir 形如 .../<wxid>_<4hex>/db_storage。
    返回 ('your_wxid_a1b2', 'your_wxid', 'a1b2') 或 None。
    """
    parent = os.path.basename(os.path.dirname(db_dir.rstrip(os.sep)))
    if not parent:
        return None
    m = _WXID_HEX_SUFFIX_RE.match(parent)
    if not m:
        return None
    return parent, m.group(1), m.group(2).lower()


# ──────────────────────────────────────────────── brute-force engine ──── #


def _aes_template_match(aes_bytes, ciphertext):
    """worker 进程内: AES-128-ECB 解 ciphertext 并检查图像 magic。"""
    try:
        decrypted = AES.new(aes_bytes, AES.MODE_ECB).decrypt(ciphertext)
    except (ValueError, KeyError):
        return False
    return any(decrypted.startswith(m) for m in IMAGE_MAGICS)


def bruteforce_uin_candidates(xor_key, wxid_suffix):
    """枚举 0~2^32 中 (uin & 0xff == xor_key) 且 md5(str(uin))[:4] == suffix 的 uin。

    单进程 + hex 比较版本，主要用作算法金标准（测试）与 fallback。
    """
    target = wxid_suffix.lower()
    out = []
    for uin in range(xor_key, 2 ** 32, 256):
        if hashlib.md5(str(uin).encode()).hexdigest()[:4] == target:
            out.append(uin)
    return out


def _bruteforce_worker_chunk(start, end, xor_key, suffix_bytes, wxid_bytes,
                              templates, result_queue):
    """worker: 扫候选区间, 命中推入 queue 即返回。"""
    for i in range(start, end):
        uin = (i << 8) | xor_key
        uin_bytes = str(uin).encode("ascii")
        if hashlib.md5(uin_bytes).digest()[:2] == suffix_bytes:
            aes_hex = hashlib.md5(uin_bytes + wxid_bytes).hexdigest()[:16]
            aes_bytes = aes_hex.encode("ascii")
            if all(_aes_template_match(aes_bytes, ct) for ct in templates):
                result_queue.put((uin, aes_hex))
                return


def bruteforce_with_aes_parallel(xor_key, suffix_hex, wxid_norm, templates,
                                  workers=None, timeout=60):
    """多进程枚举 UIN 空间 + AES 模板验证。

    Returns:
        (uin, aes_key_hex) 或 None
    """
    suffix_bytes = bytes.fromhex(suffix_hex)
    wxid_bytes = wxid_norm.encode("ascii")
    if workers is None:
        workers = max(1, multiprocessing.cpu_count())
    total = 1 << 24
    chunk = total // workers

    queue = multiprocessing.Queue()
    procs = []
    for i in range(workers):
        start_i = i * chunk
        end_i = (i + 1) * chunk if i != workers - 1 else total
        p = multiprocessing.Process(
            target=_bruteforce_worker_chunk,
            args=(start_i, end_i, xor_key, suffix_bytes, wxid_bytes,
                  templates, queue),
            daemon=True,
        )
        p.start()
        procs.append(p)

    found = None
    deadline = time.time() + timeout
    try:
        while any(p.is_alive() for p in procs) and time.time() < deadline:
            try:
                found = queue.get(timeout=0.1)
                break
            except _queue.Empty:
                continue
        if not found:
            try:
                found = queue.get_nowait()
            except _queue.Empty:
                pass
    finally:
        for p in procs:
            if p.is_alive():
                p.terminate()
        for p in procs:
            p.join(timeout=1)
    return found


# ──────────────────────────────────────────── high-level entry points ──── #


def bruteforce_image_key(db_dir, attach_dir, templates):
    """从 wxid 后缀候选搜索 uin，返回 (xor_key, aes_key) 或 None。

    调用方需提前收集好 templates（find_v2_template_ciphertexts）。
    """
    parts = extract_wxid_parts(db_dir)
    if not parts:
        print("[!] wxid 路径不含 _<4 hex> 后缀，无法应用离线枚举", flush=True)
        return None
    wxid_full, wxid_norm, suffix = parts
    print(f"[+] wxid_full={wxid_full}, suffix={suffix}", flush=True)

    xres = derive_xor_key_from_v2_dat(attach_dir)
    if not xres:
        print("[!] V2 .dat 样本不足 (需 >= 3 个), 无法投票反推 xor_key",
              flush=True)
        print("    请先在微信中再看 2-3 张图片，让缩略图缓存到本地后重试",
              flush=True)
        return None
    xor_key, votes, total = xres
    if votes == total:
        print(f"[+] xor_key=0x{xor_key:02x} ({votes}/{total} 一致, 假设 JPG)",
              flush=True)
    else:
        print(f"[!] xor_key 投票分歧 {votes}/{total}, 取多数 0x{xor_key:02x} "
              f"(可能 attach 不全是 JPG)", flush=True)

    workers = max(1, multiprocessing.cpu_count())
    print(f"[*] 多进程枚举 (workers={workers}, 预计 ~1-2 秒)...",
          flush=True)

    wxid_tries = [wxid_norm]
    if wxid_full != wxid_norm:
        wxid_tries.append(wxid_full)

    t0 = time.time()
    for wxid_try in wxid_tries:
        result = bruteforce_with_aes_parallel(
            xor_key, suffix, wxid_try, templates, workers=workers
        )
        if result:
            uin, aes_key = result
            elapsed = time.time() - t0
            print()
            print(f"[OK] 离线枚举成功 (耗时 {elapsed:.1f}s):", flush=True)
            print(f"    uin      = {uin}", flush=True)
            print(f"    wxid     = {wxid_try}", flush=True)
            print(f"    xor_key  = 0x{xor_key:02x}", flush=True)
            print(f"    aes_key  = {aes_key}", flush=True)
            return xor_key, aes_key

    elapsed = time.time() - t0
    print(f"[!] 所有 uin 候选都未通过 AES 验证 (耗时 {elapsed:.1f}s)",
          flush=True)
    return None


def find_image_key_offline(db_dir):
    """跨平台离线派生图片密钥。

    Returns:
        (xor_key, aes_key_ascii) on success; None on failure.
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
    return bruteforce_image_key(db_dir, attach_dir, templates)


# ──────────────────────────────────────────────────────── utilities ──── #


def save_config_atomic(config_path, config):
    """原子写 config.json：tmp + os.replace 防止中断留下半截文件。"""
    tmp_path = config_path + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, config_path)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


# ──────────────────────────────────────────────────────────── CLI ──── #


def main(config_path=None):
    """跨平台 CLI 入口。读 config.json → 离线派生 → 写回密钥。"""
    if config_path is None:
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
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

    result = find_image_key_offline(db_dir)
    if result is None:
        sys.exit(1)

    xor_key, aes_key = result
    config["image_aes_key"] = aes_key
    config["image_xor_key"] = xor_key
    save_config_atomic(config_path, config)
    print()
    print(f"[+] 已写入 {config_path}", flush=True)


if __name__ == "__main__":
    main()
