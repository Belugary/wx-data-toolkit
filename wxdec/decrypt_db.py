"""
WeChat 4.0 数据库解密器

使用从进程内存提取的per-DB enc_key解密SQLCipher 4加密的数据库
参数: SQLCipher 4, AES-256-CBC, HMAC-SHA512, reserve=80, page_size=4096
密钥来源: all_keys.json (由find_all_keys.py从内存提取)
"""
import argparse, hashlib, struct, os, sys, json, time
import hmac as hmac_mod
from Crypto.Cipher import AES

import functools
print = functools.partial(print, flush=True)

PAGE_SZ = 4096
KEY_SZ = 32
SALT_SZ = 16
IV_SZ = 16
HMAC_SZ = 64
RESERVE_SZ = 80  # IV(16) + HMAC(64)
SQLITE_HDR = b'SQLite format 3\x00'
WAL_HEADER_SZ = 32
WAL_FRAME_HEADER_SZ = 24

from wxdec.config import load_config
from wxdec.key_utils import get_key_info, strip_key_metadata
_cfg = load_config()
DB_DIR = _cfg["db_dir"]
OUT_DIR = _cfg["decrypted_dir"]
KEYS_FILE = _cfg["keys_file"]


def derive_mac_key(enc_key, salt):
    """从enc_key派生HMAC密钥"""
    mac_salt = bytes(b ^ 0x3a for b in salt)
    return hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=KEY_SZ)


def decrypt_page(enc_key, page_data, pgno):
    """解密单个页面，输出4096字节的标准SQLite页面"""
    iv = page_data[PAGE_SZ - RESERVE_SZ : PAGE_SZ - RESERVE_SZ + IV_SZ]

    if pgno == 1:
        encrypted = page_data[SALT_SZ : PAGE_SZ - RESERVE_SZ]
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        page = bytearray(SQLITE_HDR + decrypted + b'\x00' * RESERVE_SZ)
        # 保留 reserve=80, B-tree 基于 usable_size=4016 构建
        return bytes(page)
    else:
        encrypted = page_data[:PAGE_SZ - RESERVE_SZ]
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        return decrypted + b'\x00' * RESERVE_SZ


def full_decrypt(db_path, out_path, enc_key):
    """全量解密 .db 文件到 out_path（不做 HMAC 校验，纯热路径）。

    与 decrypt_database() 的区别：
    - 跳过 page 1 HMAC 校验，假设 enc_key 已在 daemon/调用方启动时验过；
    - 不打印进度日志；
    - 返回 (total_pages, elapsed_ms) 给上层做延迟测量。

    daemon 路径（monitor_web 等）应使用本函数；批量 CLI（main()）走
    decrypt_database() 以获得完整 HMAC 校验和进度输出。
    """
    t0 = time.perf_counter()
    file_size = os.path.getsize(db_path)
    total_pages = file_size // PAGE_SZ

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(db_path, 'rb') as fin, open(out_path, 'wb') as fout:
        for pgno in range(1, total_pages + 1):
            page = fin.read(PAGE_SZ)
            if len(page) < PAGE_SZ:
                if len(page) > 0:
                    page = page + b'\x00' * (PAGE_SZ - len(page))
                else:
                    break
            fout.write(decrypt_page(enc_key, page, pgno))

    ms = (time.perf_counter() - t0) * 1000
    return total_pages, ms


def decrypt_wal_full(wal_path, out_path, enc_key):
    """解密 WAL 当前有效 frame，patch 到已解密的 DB 副本。

    WAL 是预分配固定大小（4MB），包含当前有效 frame 和上一轮遗留的旧 frame。
    通过 WAL header 中的 salt 值区分：只有 frame header 的 salt 匹配 WAL header 的才是有效 frame。

    out_path 以 'r+b' 原地 patch：异常发生时已写入的 page 落盘但后续未写，产物
    会停在"部分 patch"状态。这不需要手动回滚 —— 下一次 full_decrypt() / 调用方
    重跑会以 'wb' truncate 重写整个 .db，半 patch 状态自愈。

    返回: (patched_pages, elapsed_ms)
    """
    t0 = time.perf_counter()

    if not os.path.exists(wal_path):
        return 0, 0

    wal_size = os.path.getsize(wal_path)
    if wal_size <= WAL_HEADER_SZ:
        return 0, 0

    frame_size = WAL_FRAME_HEADER_SZ + PAGE_SZ  # 24 + 4096 = 4120
    patched = 0

    with open(wal_path, 'rb') as wf, open(out_path, 'r+b') as df:
        # 读 WAL header，获取当前 salt 值
        wal_hdr = wf.read(WAL_HEADER_SZ)
        wal_salt1 = struct.unpack('>I', wal_hdr[16:20])[0]
        wal_salt2 = struct.unpack('>I', wal_hdr[20:24])[0]

        while wf.tell() + frame_size <= wal_size:
            fh = wf.read(WAL_FRAME_HEADER_SZ)
            if len(fh) < WAL_FRAME_HEADER_SZ:
                break
            pgno = struct.unpack('>I', fh[0:4])[0]
            frame_salt1 = struct.unpack('>I', fh[8:12])[0]
            frame_salt2 = struct.unpack('>I', fh[12:16])[0]

            ep = wf.read(PAGE_SZ)
            if len(ep) < PAGE_SZ:
                break

            # 校验: pgno 有效 且 salt 匹配当前 WAL 周期
            if pgno == 0 or pgno > 1000000:
                continue
            if frame_salt1 != wal_salt1 or frame_salt2 != wal_salt2:
                continue  # 旧周期遗留的 frame，跳过

            dec = decrypt_page(enc_key, ep, pgno)
            df.seek((pgno - 1) * PAGE_SZ)
            df.write(dec)
            patched += 1

    ms = (time.perf_counter() - t0) * 1000
    return patched, ms


def decrypt_database(db_path, out_path, enc_key):
    """解密整个数据库文件"""
    file_size = os.path.getsize(db_path)
    total_pages = file_size // PAGE_SZ

    if file_size % PAGE_SZ != 0:
        print(f"  [WARN] 文件大小 {file_size} 不是 {PAGE_SZ} 的倍数")
        total_pages += 1

    with open(db_path, 'rb') as fin:
        page1 = fin.read(PAGE_SZ)

    if len(page1) < PAGE_SZ:
        print(f"  [ERROR] 文件太小")
        return False

    # 提取salt并派生mac_key, 验证page 1
    salt = page1[:SALT_SZ]
    mac_key = derive_mac_key(enc_key, salt)
    p1_hmac_data = page1[SALT_SZ : PAGE_SZ - RESERVE_SZ + IV_SZ]
    p1_stored_hmac = page1[PAGE_SZ - HMAC_SZ : PAGE_SZ]
    hm = hmac_mod.new(mac_key, p1_hmac_data, hashlib.sha512)
    hm.update(struct.pack('<I', 1))
    if hm.digest() != p1_stored_hmac:
        print(f"  [ERROR] Page 1 HMAC验证失败! salt: {salt.hex()}")
        return False

    print(f"  HMAC OK, {total_pages} pages")

    # 解密所有页面
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(db_path, 'rb') as fin, open(out_path, 'wb') as fout:
        for pgno in range(1, total_pages + 1):
            page = fin.read(PAGE_SZ)
            if len(page) < PAGE_SZ:
                if len(page) > 0:
                    page = page + b'\x00' * (PAGE_SZ - len(page))
                else:
                    break

            decrypted = decrypt_page(enc_key, page, pgno)
            fout.write(decrypted)

            if pgno == 1:
                if decrypted[:16] != SQLITE_HDR:
                    print(f"  [WARN] 解密后header不匹配!")

            if pgno % 10000 == 0:
                print(f"  进度: {pgno}/{total_pages} ({100*pgno/total_pages:.1f}%)")

    return True


def main(argv=None):
    """批量解密微信 4.x 加密数据库。

    退出码:
      0 — 全部 DB 解密成功;若启用 --with-wal,所有 WAL 也合并成功
      1 — 至少一个 DB 解密失败(或 SKIP / SQLite 校验失败)
      2 — 所有 DB 解密成功但启用 --with-wal 时部分 WAL 合并失败
    """
    parser = argparse.ArgumentParser(
        prog="decrypt_db",
        description="批量解密微信 4.x 加密数据库到明文目录",
    )
    parser.add_argument(
        "--with-wal",
        action="store_true",
        help="解密后把 WAL 合并进明文 DB(获得当天最新消息)。默认不合并以保持向后兼容。",
    )
    parser.add_argument(
        "--db-dir",
        default=None,
        help=f"加密 DB 根目录,覆盖 config.json 的 db_dir(默认: {DB_DIR})",
    )
    parser.add_argument(
        "--keys-file",
        default=None,
        help=f"密钥 JSON 路径,覆盖 config.json 的 keys_file(默认: {KEYS_FILE})",
    )
    parser.add_argument(
        "--out-dir",
        default=None,
        help=f"明文输出根目录,覆盖 config.json 的 decrypted_dir(默认: {OUT_DIR})",
    )
    args = parser.parse_args(argv)

    db_dir = args.db_dir or DB_DIR
    keys_file = args.keys_file or KEYS_FILE
    out_dir = args.out_dir or OUT_DIR
    with_wal = args.with_wal

    print("=" * 60)
    print("  WeChat 4.0 数据库解密器")
    print("=" * 60)

    if not with_wal:
        print(
            "[NOTE] 未启用 --with-wal,WAL 缓冲中的最新消息不会进入产物;"
            "若需当天最新数据请加 --with-wal",
            file=sys.stderr,
        )

    # 校验 db_dir 存在(否则 os.walk 会静默返回空,exit 0,
    # 让用户误以为"全部成功"但其实根本没扫到 .db)
    if not os.path.isdir(db_dir):
        print(f"[ERROR] DB 目录不存在或不可访问: {db_dir}", file=sys.stderr)
        sys.exit(1)

    # 加载密钥
    if not os.path.exists(keys_file):
        print(f"[ERROR] 密钥文件不存在: {keys_file}")
        print("请先运行 find_all_keys.py")
        sys.exit(1)

    with open(keys_file, encoding="utf-8") as f:
        keys = json.load(f)

    keys = strip_key_metadata(keys)
    print(f"\n加载 {len(keys)} 个数据库密钥")
    print(f"输出目录: {out_dir}")
    os.makedirs(out_dir, exist_ok=True)

    # 收集所有DB文件
    db_files = []
    for root, dirs, files in os.walk(db_dir):
        for f in files:
            if f.endswith('.db') and not f.endswith('-wal') and not f.endswith('-shm'):
                path = os.path.join(root, f)
                rel = os.path.relpath(path, db_dir)
                sz = os.path.getsize(path)
                db_files.append((rel, path, sz))

    db_files.sort(key=lambda x: x[2])  # 从小到大

    print(f"找到 {len(db_files)} 个数据库文件\n")

    success = 0
    failed = 0
    wal_merged = 0
    wal_failed = 0
    total_bytes = 0

    for rel, path, sz in db_files:
        key_info = get_key_info(keys, rel)
        if not key_info:
            print(f"SKIP: {rel} (无密钥)")
            failed += 1
            continue

        enc_key = bytes.fromhex(key_info["enc_key"])
        out_path = os.path.join(out_dir, rel)

        print(f"解密: {rel} ({sz/1024/1024:.1f}MB) ...", end=" ")

        ok = decrypt_database(path, out_path, enc_key)
        if not ok:
            failed += 1
            continue

        # SQLite验证
        try:
            import sqlite3
            conn = sqlite3.connect(out_path)
            tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            conn.close()
            table_names = [t[0] for t in tables]
            print(f"  OK! 表: {', '.join(table_names[:5])}", end="")
            if len(table_names) > 5:
                print(f" ...共{len(table_names)}个", end="")
            print()
            success += 1
            total_bytes += sz
        except Exception as e:
            print(f"  [WARN] SQLite验证失败: {e}")
            failed += 1
            continue

        # WAL 合并(opt-in)
        if with_wal:
            wal_path = path + "-wal"
            if not os.path.exists(wal_path):
                continue
            try:
                patched, ms = decrypt_wal_full(wal_path, out_path, enc_key)
                if patched > 0:
                    print(f"  WAL: 合并 {patched} pages ({ms:.0f}ms)")
                wal_merged += 1
            except Exception as e:
                print(
                    f"[WARN] {rel}: DB 解密成功,WAL 合并失败: {e}",
                    file=sys.stderr,
                )
                print(
                    "       该 DB 当天最新消息可能缺失",
                    file=sys.stderr,
                )
                wal_failed += 1

    print(f"\n{'='*60}")
    print(f"结果: {success} 成功, {failed} 失败, 共 {len(db_files)} 个")
    if with_wal:
        print(f"WAL: {wal_merged} 合并, {wal_failed} 失败")
    print(f"解密数据量: {total_bytes/1024/1024/1024:.1f}GB")
    print(f"解密文件在: {out_dir}")

    if failed > 0:
        sys.exit(1)
    if wal_failed > 0:
        sys.exit(2)


if __name__ == '__main__':
    main()
