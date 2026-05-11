"""验证 db_core 的 lazy init 契约: import 模块本身和纯 helper 不触发 config
加载, 只有访问 _cache / DB_DIR / ALL_KEYS 等 lazy 名字时才触发. 用子进程隔离
状态, 避免被同进程其他测试已经 init 过的 _state 干扰.
"""
import os
import subprocess
import sys
import textwrap
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run_subprocess(snippet):
    """在子进程跑 snippet, 返回 (stdout, stderr, returncode)."""
    code = textwrap.dedent(snippet)
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=15,
        cwd=PROJECT_ROOT,
    )
    return result.stdout, result.stderr, result.returncode


class DBCoreLazyContractTests(unittest.TestCase):
    def test_module_import_alone_does_not_trigger_init(self):
        # `import wxdec.db_core` 本身不应读 config / 凭据 / 创建 cache
        stdout, stderr, rc = _run_subprocess(f"""
            import sys
            sys.path.insert(0, {PROJECT_ROOT!r})
            import wxdec.db_core as db
            print('STATE_NONE:', db._state is None)
        """)
        self.assertEqual(rc, 0, f"stdout={stdout}\nstderr={stderr}")
        self.assertIn("STATE_NONE: True", stdout)

    def test_pure_helpers_importable_without_init(self):
        # 常量 / 解密函数 / open_db_readonly / DBCache 类定义都是纯的,
        # 导入它们不应触发 lazy state.
        stdout, stderr, rc = _run_subprocess(f"""
            import sys
            sys.path.insert(0, {PROJECT_ROOT!r})
            from wxdec.db_core import (
                PAGE_SZ, KEY_SZ, SQLITE_HDR,
                decrypt_page, full_decrypt, decrypt_wal,
                open_db_readonly, DBCache, SCRIPT_DIR,
            )
            import wxdec.db_core as db
            print('STATE_NONE:', db._state is None)
            print('PAGE_SZ:', PAGE_SZ)
        """)
        self.assertEqual(rc, 0, f"stdout={stdout}\nstderr={stderr}")
        self.assertIn("STATE_NONE: True", stdout)
        self.assertIn("PAGE_SZ: 4096", stdout)

    def test_accessing_lazy_attr_triggers_init(self):
        # 第一次访问 _cache 必须触发 _State 构造; 之后 _state 不再为 None.
        stdout, stderr, rc = _run_subprocess(f"""
            import sys
            sys.path.insert(0, {PROJECT_ROOT!r})
            import wxdec.db_core as db
            assert db._state is None
            _ = db._cache  # 触发 lazy init
            print('STATE_INITIALIZED:', db._state is not None)
            # 二次访问拿到同一个 cache 实例 (singleton 语义)
            print('SAME_INSTANCE:', db._cache is db._state.cache)
        """)
        self.assertEqual(rc, 0, f"stdout={stdout}\nstderr={stderr}")
        self.assertIn("STATE_INITIALIZED: True", stdout)
        self.assertIn("SAME_INSTANCE: True", stdout)

    def test_dbcache_constructible_without_globals(self):
        # DBCache 不再依赖 module globals, 测试可以独立构造一个空实例.
        # 用空 all_keys + 不存在的 db_dir, 验证不会爆 KeyError / NameError.
        stdout, stderr, rc = _run_subprocess(f"""
            import sys
            sys.path.insert(0, {PROJECT_ROOT!r})
            from wxdec.db_core import DBCache
            cache = DBCache(db_dir='/nonexistent', all_keys={{}})
            # all_keys 空 → get 找不到 key, 返回 None
            print('GET_RESULT:', cache.get('contact/contact.db'))
        """)
        self.assertEqual(rc, 0, f"stdout={stdout}\nstderr={stderr}")
        self.assertIn("GET_RESULT: None", stdout)

    def test_unknown_attr_still_raises_attribute_error(self):
        # __getattr__ 仅对 _LAZY_ATTRS 介入, 其他名字按 Python 默认抛
        # AttributeError — 防止 hook 把不该 lazy 的名字也吞掉.
        stdout, stderr, rc = _run_subprocess(f"""
            import sys
            sys.path.insert(0, {PROJECT_ROOT!r})
            import wxdec.db_core as db
            try:
                _ = db.NOT_A_REAL_ATTR
                print('NO_ERROR')
            except AttributeError as e:
                print('ATTRIBUTE_ERROR:', 'NOT_A_REAL_ATTR' in str(e))
        """)
        self.assertEqual(rc, 0, f"stdout={stdout}\nstderr={stderr}")
        self.assertIn("ATTRIBUTE_ERROR: True", stdout)


if __name__ == "__main__":
    unittest.main()
