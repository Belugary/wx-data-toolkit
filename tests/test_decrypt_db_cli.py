"""decrypt_db.main() CLI behavior tests — `--with-wal` flag, overrides, exit codes.

不依赖真实加密 DB:用 mock 隔离 decrypt_database / decrypt_wal_full,
测试 main() 的编排逻辑(flag 解析、WAL 调用条件、exit code、stderr 提示)。

decrypt_wal_full 在边界场景(WAL 缺失/为空)的真实行为单独覆盖,
不走 mock 路径。
"""
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch, MagicMock

from wxdec import decrypt_db


class _MainHarness:
    """构造一个最小的 keys.json + 加密 db 占位文件,用于跑 decrypt_db.main(argv)。

    decrypt_database / decrypt_wal_full 用 mock 替换;占位 .db 文件只用于
    让 os.walk 能扫到,不会被真实解密。
    """

    def __init__(self, tmp_dir, db_files=("session/session.db",)):
        self.tmp = tmp_dir
        self.db_dir = os.path.join(tmp_dir, "db")
        self.out_dir = os.path.join(tmp_dir, "out")
        self.keys_file = os.path.join(tmp_dir, "keys.json")
        for rel in db_files:
            p = os.path.join(self.db_dir, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(b"\x00" * 4096)
        keys = {
            rel.replace("/", os.sep): {"enc_key": "00" * 32}
            for rel in db_files
        }
        with open(self.keys_file, "w") as f:
            json.dump(keys, f)

    def make_wal(self, rel):
        wal = os.path.join(self.db_dir, rel) + "-wal"
        with open(wal, "wb") as f:
            f.write(b"\x00" * 64)
        return wal

    def argv_base(self):
        return [
            "--db-dir", self.db_dir,
            "--keys-file", self.keys_file,
            "--out-dir", self.out_dir,
        ]


def _fake_decrypt_database_ok(db_path, out_path, enc_key):
    """假 decrypt_database:产出一个空的真 SQLite 文件,让 main() 的 sqlite3
    校验段(SELECT name FROM sqlite_master)能跑通且返回 0 个表。"""
    import sqlite3 as _sq
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    conn = _sq.connect(out_path)
    conn.close()
    return True


def _fake_decrypt_database_fail(db_path, out_path, enc_key):
    return False


class WithWalFlagTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.h = _MainHarness(self._tmp.name)

    def _run(self, argv, db_side_effect=_fake_decrypt_database_ok,
             wal_result=(5, 1.5), wal_raises=None):
        wal_mock = MagicMock()
        if wal_raises:
            wal_mock.side_effect = wal_raises
        else:
            wal_mock.return_value = wal_result

        stderr = io.StringIO()
        stdout = io.StringIO()
        exit_code = None
        with patch.object(decrypt_db, "decrypt_database", side_effect=db_side_effect) as m_db, \
             patch.object(decrypt_db, "decrypt_wal_full", wal_mock) as m_wal, \
             redirect_stderr(stderr), redirect_stdout(stdout):
            try:
                decrypt_db.main(argv)
            except SystemExit as e:
                exit_code = e.code
        return {
            "exit": exit_code,
            "stderr": stderr.getvalue(),
            "stdout": stdout.getvalue(),
            "db_calls": m_db.mock_calls,
            "wal_calls": wal_mock.mock_calls,
        }

    def test_default_no_wal_skips_wal_decrypt(self):
        res = self._run(self.h.argv_base())
        self.assertEqual(
            len(res["wal_calls"]), 0,
            "without --with-wal, decrypt_wal_full must not be called",
        )

    def test_default_no_wal_emits_stderr_hint(self):
        res = self._run(self.h.argv_base())
        self.assertIn("--with-wal", res["stderr"])

    def test_with_wal_flag_invokes_wal_decrypt(self):
        self.h.make_wal("session/session.db")
        res = self._run(self.h.argv_base() + ["--with-wal"])
        self.assertEqual(
            len(res["wal_calls"]), 1,
            "with --with-wal and existing wal file, decrypt_wal_full called once",
        )

    def test_with_wal_no_wal_file_skips_call(self):
        # No make_wal — file absent
        res = self._run(self.h.argv_base() + ["--with-wal"])
        self.assertEqual(
            len(res["wal_calls"]), 0,
            "no .db-wal file → skip wal call (no error)",
        )

    def test_wal_failure_warns_and_exits_2(self):
        self.h.make_wal("session/session.db")
        res = self._run(
            self.h.argv_base() + ["--with-wal"],
            wal_raises=RuntimeError("synthetic wal corruption"),
        )
        self.assertIn("WAL 合并失败", res["stderr"])
        self.assertIn("当天最新消息可能缺失", res["stderr"])
        self.assertEqual(res["exit"], 2, "all DB OK but WAL fail → exit 2")

    def test_db_failure_exits_1(self):
        res = self._run(
            self.h.argv_base(),
            db_side_effect=_fake_decrypt_database_fail,
        )
        self.assertEqual(res["exit"], 1, "DB decrypt fail → exit 1")

    def test_skip_missing_credential_does_not_fail(self):
        """无凭据的 db (e.g. migrate/unspportmsg.db) 应被 SKIP, 不算 failed,
        汇总单独显示 '跳过(无凭据)', 且不影响 exit code。"""
        # harness 已建有凭据的 session.db; 再造一个没凭据的 db 模拟迁移残留
        extra = os.path.join(self.h.db_dir, "migrate", "unspportmsg.db")
        os.makedirs(os.path.dirname(extra), exist_ok=True)
        with open(extra, "wb") as f:
            f.write(b"\x00" * 4096)

        res = self._run(self.h.argv_base())
        self.assertIsNone(
            res["exit"],
            f"SKIP-only run should NOT exit 1, got {res['exit']}\nstdout:\n{res['stdout']}",
        )
        self.assertIn("SKIP: migrate/unspportmsg.db (无凭据)", res["stdout"])
        self.assertIn("跳过(无凭据)", res["stdout"])
        self.assertNotIn(
            "1 失败", res["stdout"],
            "SKIP must not be reported as a failure in summary",
        )

    def test_all_success_no_explicit_exit(self):
        self.h.make_wal("session/session.db")
        res = self._run(self.h.argv_base() + ["--with-wal"])
        # 所有 DB OK + 所有 WAL OK → main 正常返回(无 sys.exit)
        self.assertIsNone(res["exit"])

    def test_with_wal_does_not_emit_stderr_hint(self):
        """启用 --with-wal 时不应再给提示。"""
        res = self._run(self.h.argv_base() + ["--with-wal"])
        # stderr 里可能有别的(测试工具自身)但不应包含"未启用 --with-wal"
        self.assertNotIn("未启用 --with-wal", res["stderr"])

    def _seed_residuals(self, rel):
        """在 out_dir 预置 -shm/-wal,模拟 sqlite3 验证连接的副作用。"""
        out_db = os.path.join(self.h.out_dir, rel)
        os.makedirs(os.path.dirname(out_db), exist_ok=True)
        for suffix in ("-shm", "-wal"):
            with open(out_db + suffix, "wb") as f:
                f.write(b"stale")
        return out_db

    def test_residuals_cleaned_after_with_wal(self):
        """--with-wal 路径走完后应清理 -shm/-wal 残留。"""
        out_db = self._seed_residuals("session/session.db")
        self.h.make_wal("session/session.db")
        self._run(self.h.argv_base() + ["--with-wal"])
        self.assertFalse(os.path.exists(out_db + "-shm"))
        self.assertFalse(os.path.exists(out_db + "-wal"))

    def test_residuals_cleaned_without_with_wal(self):
        """默认路径(无 --with-wal)也应清理残留,因为 sqlite3 验证仍会跑。"""
        out_db = self._seed_residuals("session/session.db")
        self._run(self.h.argv_base())
        self.assertFalse(os.path.exists(out_db + "-shm"))
        self.assertFalse(os.path.exists(out_db + "-wal"))


class CliOverrideTests(unittest.TestCase):
    """--db-dir / --keys-file / --out-dir 覆盖模块级 config 默认值。"""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.h = _MainHarness(self._tmp.name)

    def test_db_dir_override_walks_provided_path(self):
        seen = []

        def capture(db_path, out_path, enc_key):
            seen.append(db_path)
            return _fake_decrypt_database_ok(db_path, out_path, enc_key)

        with patch.object(decrypt_db, "decrypt_database", side_effect=capture), \
             patch.object(decrypt_db, "decrypt_wal_full", MagicMock()), \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            try:
                decrypt_db.main(self.h.argv_base())
            except SystemExit:
                pass

        self.assertTrue(seen, "decrypt_database should be called at least once")
        for p in seen:
            self.assertTrue(
                p.startswith(self.h.db_dir),
                f"{p} should be under provided --db-dir {self.h.db_dir}",
            )

    def test_out_dir_override_routes_writes(self):
        with patch.object(decrypt_db, "decrypt_database", side_effect=_fake_decrypt_database_ok), \
             patch.object(decrypt_db, "decrypt_wal_full", MagicMock()), \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            try:
                decrypt_db.main(self.h.argv_base())
            except SystemExit:
                pass

        produced = os.path.join(self.h.out_dir, "session", "session.db")
        self.assertTrue(
            os.path.exists(produced),
            f"output should land under --out-dir at {produced}",
        )

    def test_db_dir_nonexistent_exits_1(self):
        """--db-dir 指向不存在的目录应该 exit 1 + stderr 报错,而不是静默 exit 0
        (os.walk 对不存在的目录会默默返回空 iterator)。"""
        argv = [
            "--db-dir", "/nonexistent/path/that/does/not/exist",
            "--keys-file", self.h.keys_file,
            "--out-dir", self.h.out_dir,
        ]
        stderr = io.StringIO()
        exit_code = None
        with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
            try:
                decrypt_db.main(argv)
            except SystemExit as e:
                exit_code = e.code
        self.assertEqual(exit_code, 1)
        self.assertIn("DB 目录不存在", stderr.getvalue())


class WalCoreFunctionTests(unittest.TestCase):
    """decrypt_wal_full 在边界场景的真实行为(无加密、纯文件操作)。"""

    def test_no_wal_file_returns_zero_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            wal = os.path.join(tmp, "missing.db-wal")
            out = os.path.join(tmp, "out.db")
            open(out, "wb").close()
            patched, ms = decrypt_db.decrypt_wal_full(wal, out, b"\x00" * 32)
            self.assertEqual(patched, 0)
            self.assertEqual(ms, 0)

    def test_empty_wal_file_returns_zero_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            wal = os.path.join(tmp, "empty.db-wal")
            out = os.path.join(tmp, "out.db")
            open(wal, "wb").close()
            open(out, "wb").close()
            patched, ms = decrypt_db.decrypt_wal_full(wal, out, b"\x00" * 32)
            self.assertEqual(patched, 0)
            self.assertEqual(ms, 0)

    def test_header_only_wal_returns_zero_zero(self):
        """WAL 只有 header(无 frame)应该返回 (0, _) 而不是抛异常。"""
        with tempfile.TemporaryDirectory() as tmp:
            wal = os.path.join(tmp, "header_only.db-wal")
            out = os.path.join(tmp, "out.db")
            with open(wal, "wb") as f:
                f.write(b"\x00" * decrypt_db.WAL_HEADER_SZ)
            open(out, "wb").close()
            patched, ms = decrypt_db.decrypt_wal_full(wal, out, b"\x00" * 32)
            self.assertEqual(patched, 0)


if __name__ == "__main__":
    unittest.main()
