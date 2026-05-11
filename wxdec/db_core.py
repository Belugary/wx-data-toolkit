"""
Database decryption, caching, and configuration loading.

This is the foundation module — no project dependencies except wxdec.config
and wxdec.key_utils.
"""

import os
import sys
import json
import re
import struct
import sqlite3
import tempfile
import hashlib
import atexit
import pathlib
import threading
from Crypto.Cipher import AES
from wxdec.config import load_config
from wxdec.key_utils import get_key_info, key_path_variants, strip_key_metadata

# ============ Crypto constants ============
PAGE_SZ = 4096
KEY_SZ = 32
SALT_SZ = 16
RESERVE_SZ = 80
SQLITE_HDR = b'SQLite format 3\x00'
WAL_HEADER_SZ = 32
WAL_FRAME_HEADER_SZ = 24

# SCRIPT_DIR 是纯路径计算 (无 I/O), 被 voice_transcriptions.json 等 cache 路径
# 复用. 保留 eager 求值; config / keys 文件的实际读取走下方 _State, lazy.
SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ============ Decryption functions ============

def decrypt_page(enc_key, page_data, pgno):
    iv = page_data[PAGE_SZ - RESERVE_SZ : PAGE_SZ - RESERVE_SZ + 16]
    if pgno == 1:
        encrypted = page_data[SALT_SZ : PAGE_SZ - RESERVE_SZ]
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        return bytes(bytearray(SQLITE_HDR + decrypted + b'\x00' * RESERVE_SZ))
    else:
        encrypted = page_data[: PAGE_SZ - RESERVE_SZ]
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        return decrypted + b'\x00' * RESERVE_SZ


def full_decrypt(db_path, out_path, enc_key):
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
    return total_pages


def decrypt_wal(wal_path, out_path, enc_key):
    if not os.path.exists(wal_path):
        return 0
    wal_size = os.path.getsize(wal_path)
    if wal_size <= WAL_HEADER_SZ:
        return 0
    frame_size = WAL_FRAME_HEADER_SZ + PAGE_SZ
    patched = 0
    with open(wal_path, 'rb') as wf, open(out_path, 'r+b') as df:
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
            if pgno == 0 or pgno > 1000000:
                continue
            if frame_salt1 != wal_salt1 or frame_salt2 != wal_salt2:
                continue
            dec = decrypt_page(enc_key, ep, pgno)
            df.seek((pgno - 1) * PAGE_SZ)
            df.write(dec)
            patched += 1
    return patched


# ============ DB Cache ============

class DBCache:
    """缓存解密后的 DB，通过 mtime 检测变化。使用固定文件名，重启后可复用。"""

    CACHE_DIR = os.path.join(tempfile.gettempdir(), "wechat_mcp_cache")
    MTIME_FILE = os.path.join(tempfile.gettempdir(), "wechat_mcp_cache", "_mtimes.json")

    def __init__(self, db_dir, all_keys):
        # db_dir / all_keys 显式注入,不再依赖 module-level globals,这样:
        #  - 单元测试可以构造孤立的 DBCache 实例
        #  - 未来支持多账号时同一进程可并存多个 cache
        self._db_dir = db_dir
        self._all_keys = all_keys
        self._cache = {}  # rel_key -> (db_mtime, wal_mtime, tmp_path)
        os.makedirs(self.CACHE_DIR, exist_ok=True)
        self._load_persistent_cache()

    def _cache_path(self, rel_key):
        """rel_key -> 固定的缓存文件路径"""
        h = hashlib.md5(rel_key.encode()).hexdigest()[:12]
        return os.path.join(self.CACHE_DIR, f"{h}.db")

    def _load_persistent_cache(self):
        """启动时从磁盘恢复缓存映射，验证 mtime 后复用"""
        if not os.path.exists(self.MTIME_FILE):
            return
        try:
            with open(self.MTIME_FILE, encoding="utf-8") as f:
                saved = json.load(f)
        except (json.JSONDecodeError, OSError):
            return
        reused = 0
        for rel_key, info in saved.items():
            tmp_path = info["path"]
            if not os.path.exists(tmp_path):
                continue
            rel_path = rel_key.replace('\\', os.sep)
            db_path = os.path.join(self._db_dir, rel_path)
            wal_path = db_path + "-wal"
            try:
                db_mtime = os.path.getmtime(db_path)
                wal_mtime = os.path.getmtime(wal_path) if os.path.exists(wal_path) else 0
            except OSError:
                continue
            if db_mtime == info["db_mt"] and wal_mtime == info["wal_mt"]:
                self._cache[rel_key] = (db_mtime, wal_mtime, tmp_path)
                reused += 1
        if reused:
            print(f"[DBCache] reused {reused} cached decrypted DBs from previous run", flush=True)

    def _save_persistent_cache(self):
        """持久化缓存映射到磁盘"""
        data = {}
        for rel_key, (db_mt, wal_mt, path) in self._cache.items():
            data[rel_key] = {"db_mt": db_mt, "wal_mt": wal_mt, "path": path}
        try:
            with open(self.MTIME_FILE, 'w', encoding="utf-8") as f:
                json.dump(data, f)
        except OSError:
            pass

    def get(self, rel_key):
        key_info = get_key_info(self._all_keys, rel_key)
        if not key_info:
            return None
        rel_path = rel_key.replace('\\', '/').replace('/', os.sep)
        db_path = os.path.join(self._db_dir, rel_path)
        wal_path = db_path + "-wal"
        if not os.path.exists(db_path):
            return None

        try:
            db_mtime = os.path.getmtime(db_path)
            wal_mtime = os.path.getmtime(wal_path) if os.path.exists(wal_path) else 0
        except OSError:
            return None

        if rel_key in self._cache:
            c_db_mt, c_wal_mt, c_path = self._cache[rel_key]
            if c_db_mt == db_mtime and c_wal_mt == wal_mtime and os.path.exists(c_path):
                return c_path

        tmp_path = self._cache_path(rel_key)
        enc_key = bytes.fromhex(key_info["enc_key"])
        full_decrypt(db_path, tmp_path, enc_key)
        if os.path.exists(wal_path):
            decrypt_wal(wal_path, tmp_path, enc_key)
        self._cache[rel_key] = (db_mtime, wal_mtime, tmp_path)
        self._save_persistent_cache()
        return tmp_path

    def cleanup(self):
        """正常退出时保存缓存映射（不删文件，下次启动可复用）"""
        self._save_persistent_cache()


# ============ Lazy module state ============
# 把所有 module-level I/O (config 读取 / 凭据文件 / 临时目录创建 / atexit 注册)
# 都收进 _State, 第一次访问 _cache / _cfg / DB_DIR 等 lazy 名字时才触发. 这样:
#  - 测试 / 工具脚本如果只需要纯 helper (decrypt_page, open_db_readonly),
#    不会被 config 加载链绑架, 缺 config.json 的环境也能 import 这个模块
#  - 错误延迟到第一次实际使用, call site 更清晰
#  - 单元测试可以直接构造 DBCache(db_dir=..., all_keys={}), 不必整套环境

_state = None
_init_lock = threading.Lock()


class _State:
    """Lazy-built singleton holding config, keys, and the decryption cache."""

    def __init__(self):
        self.cfg = load_config()
        self.db_dir = self.cfg["db_dir"]
        self.keys_file = self.cfg["keys_file"]
        self.decrypted_dir = self.cfg["decrypted_dir"]
        self.wechat_base_dir = self.cfg["wechat_base_dir"]
        self.decoded_image_dir = self.cfg["decoded_image_dir"]
        with open(self.keys_file, encoding="utf-8") as f:
            self.all_keys = strip_key_metadata(json.load(f))
        # 消息 DB 的 rel_keys
        # 用 message_\d+\.db$ 匹配，自然排除 message_resource.db / message_fts_*.db
        self.msg_db_keys = sorted([
            k for k in self.all_keys
            if any(v.startswith("message/") for v in key_path_variants(k))
            and any(re.search(r"message_\d+\.db$", v) for v in key_path_variants(k))
        ])
        self.cache = DBCache(db_dir=self.db_dir, all_keys=self.all_keys)
        atexit.register(self.cache.cleanup)


def _ensure_state():
    global _state
    if _state is not None:
        return _state
    with _init_lock:
        if _state is None:
            _state = _State()
    return _state


# Module-level 名字 → _State 属性的映射. 现有调用方代码 (from db_core import
# _cache / DB_DIR / ...) 完全不动, 通过 PEP 562 __getattr__ 透明 lazy-resolve.
_LAZY_ATTRS = {
    "_cfg": "cfg",
    "_cache": "cache",
    "ALL_KEYS": "all_keys",
    "MSG_DB_KEYS": "msg_db_keys",
    "DB_DIR": "db_dir",
    "KEYS_FILE": "keys_file",
    "DECRYPTED_DIR": "decrypted_dir",
    "WECHAT_BASE_DIR": "wechat_base_dir",
    "DECODED_IMAGE_DIR": "decoded_image_dir",
}


def __getattr__(name):
    # PEP 562: 仅当 module dict 里找不到 name 时 Python 才调这个 hook.
    # 故 SCRIPT_DIR / 函数 / 类 / 常量直接命中 module dict, 不走这里.
    if name in _LAZY_ATTRS:
        return getattr(_ensure_state(), _LAZY_ATTRS[name])
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# ============ Connection helper ============

def open_db_readonly(path):
    """以 read-only + immutable 模式打开 sqlite 文件。

    本项目里通过 sqlite3 访问的 DB 都是解密后的临时缓存 (DBCache._cache_path)
    或离线解密产物 (DECRYPTED_DIR) — 都是我们自己写完后只读的快照,告诉
    sqlite immutable=1 可以让它跳过 WAL/locking 簿记 (轻微性能提升), 并防御
    性地阻止任何意外写入. 路径里可能含空格 / unicode, 用 pathlib.as_uri() 做
    正确的 percent-encoding, 避免裸 f-string 拼接出非法 URI.

    调用方仍需自己 close (建议用 contextlib.closing).
    """
    uri = pathlib.Path(path).as_uri() + "?mode=ro&immutable=1"
    return sqlite3.connect(uri, uri=True)
