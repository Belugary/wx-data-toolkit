"""Unit tests for wxdec.export_plan.

Covers commit-3 invariants from plan v5 DoD:
  - Filename + collision (`__<username>` suffix)
  - Index version matrix: missing / v3 / older (backup) / future (raise)
  - Atomic write
  - `.partial.<pid>` cleanup: dead-pid AND mtime>ttl both required
  - CSV BOM + blacklist / whitelist
  - `--users` char validation + multi-match error
  - Stats fan-out on real tmp sqlite (per-shard sum)
"""

import csv
import json
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import wxdec.contact as contact
import wxdec.export_plan as ep


# ============ Filename helpers ============

class TestExportFilename(unittest.TestCase):

    def test_default_no_username(self):
        self.assertEqual(ep.export_filename("张三"), "张三_export.json")

    def test_collision_appends_username(self):
        self.assertEqual(
            ep.export_filename("张三", username="wxid_a"),
            "张三__wxid_a_export.json",
        )

    def test_unsafe_chars_replaced(self):
        # Windows/POSIX-illegal characters get replaced with `_`.
        self.assertEqual(ep.export_filename("a/b\\c:d"), "a_b_c_d_export.json")

    def test_empty_display_falls_back_to_unknown(self):
        self.assertEqual(ep.export_filename(""), "unknown_export.json")


# ============ Index version matrix ============

class TestIndexLoadVersionMatrix(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_missing_file_returns_empty_v3(self):
        idx, warnings = ep.load_index(self.tmpdir)
        self.assertEqual(idx["schema_version"], 3)
        self.assertEqual(idx["users"], {})
        self.assertEqual(warnings, [])

    def test_v3_loaded_intact(self):
        path = os.path.join(self.tmpdir, ep.EXPORT_INDEX_FILE)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "schema_version": 3,
                "created_at": "2026-01-01T00:00:00Z",
                "last_run_at": "2026-01-01T00:00:00Z",
                "users": {"wxid_a": {"filename": "张三_export.json"}},
            }, f)
        idx, warnings = ep.load_index(self.tmpdir)
        self.assertEqual(idx["users"]["wxid_a"]["filename"], "张三_export.json")
        self.assertEqual(warnings, [])

    def test_older_version_backs_up_and_resets(self):
        path = os.path.join(self.tmpdir, ep.EXPORT_INDEX_FILE)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"schema_version": 1, "users": {}}, f)
        idx, warnings = ep.load_index(self.tmpdir)
        self.assertEqual(idx["schema_version"], 3)
        self.assertEqual(idx["users"], {})
        self.assertTrue(os.path.exists(f"{path}.v1.bak"))
        self.assertTrue(any("v1.bak" in w for w in warnings))

    def test_missing_version_treated_as_old(self):
        path = os.path.join(self.tmpdir, ep.EXPORT_INDEX_FILE)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"users": {"wxid_x": {"filename": "x.json"}}}, f)
        idx, warnings = ep.load_index(self.tmpdir)
        # Missing version → backed up, fresh empty index
        self.assertEqual(idx["users"], {})
        self.assertTrue(warnings)

    def test_future_version_raises(self):
        path = os.path.join(self.tmpdir, ep.EXPORT_INDEX_FILE)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"schema_version": 99, "users": {}}, f)
        with self.assertRaises(RuntimeError):
            ep.load_index(self.tmpdir)

    def test_corrupt_json_backs_up(self):
        path = os.path.join(self.tmpdir, ep.EXPORT_INDEX_FILE)
        with open(path, "w") as f:
            f.write("{not valid json")
        idx, warnings = ep.load_index(self.tmpdir)
        self.assertEqual(idx["users"], {})
        self.assertTrue(os.path.exists(f"{path}.corrupt.bak"))
        self.assertTrue(any("损坏" in w for w in warnings))


class TestIndexWriteAtomic(unittest.TestCase):

    def test_write_and_reload_roundtrip(self):
        tmpdir = tempfile.mkdtemp()
        idx = ep._empty_index()
        idx["users"]["wxid_a"] = {"filename": "张三_export.json"}
        ep.write_index_atomic(tmpdir, idx)
        path = os.path.join(tmpdir, ep.EXPORT_INDEX_FILE)
        self.assertTrue(os.path.exists(path))
        # No leftover .tmp
        self.assertFalse(os.path.exists(f"{path}.tmp"))
        reloaded, _ = ep.load_index(tmpdir)
        self.assertEqual(reloaded["users"]["wxid_a"]["filename"], "张三_export.json")


# ============ Filename resolution + collision ============

class TestResolveExportPath(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.idx = ep._empty_index()

    def test_first_export_uses_plain_filename(self):
        path, msgs = ep.resolve_export_path(self.tmpdir, "wxid_a", "张三", self.idx)
        self.assertEqual(os.path.basename(path), "张三_export.json")
        self.assertEqual(msgs, [])
        # Index updated
        self.assertEqual(self.idx["users"]["wxid_a"]["filename"], "张三_export.json")

    def test_collision_with_other_user_appends_username_suffix(self):
        # First user takes the plain filename
        ep.resolve_export_path(self.tmpdir, "wxid_a", "张三", self.idx)
        # Second user with same display name → collision suffix
        path, _ = ep.resolve_export_path(self.tmpdir, "wxid_b", "张三", self.idx)
        self.assertEqual(os.path.basename(path), "张三__wxid_b_export.json")

    def test_remark_change_renames_old_file(self):
        # Initial: wxid_a writes 张三_export.json
        path1, _ = ep.resolve_export_path(self.tmpdir, "wxid_a", "张三", self.idx)
        Path(path1).write_text("dummy", encoding="utf-8")
        # Display name changes to 张三-同事
        path2, msgs = ep.resolve_export_path(self.tmpdir, "wxid_a", "张三-同事", self.idx)
        self.assertEqual(os.path.basename(path2), "张三-同事_export.json")
        self.assertTrue(os.path.exists(path2))
        self.assertFalse(os.path.exists(path1))
        self.assertTrue(any("renamed" in m for m in msgs))


# ============ .partial cleanup ============

class TestCleanupOrphanPartials(unittest.TestCase):

    def test_dead_pid_old_file_removed(self):
        tmpdir = tempfile.mkdtemp()
        # PID 99999 unlikely to be live; mtime set to 2h ago
        p = os.path.join(tmpdir, "x.json.partial.99999")
        Path(p).write_text("", encoding="utf-8")
        old = time.time() - 7200
        os.utime(p, (old, old))
        removed = ep.cleanup_orphan_partials(tmpdir, ttl_seconds=3600)
        self.assertEqual(removed, [p])

    def test_live_pid_skipped_regardless_of_mtime(self):
        tmpdir = tempfile.mkdtemp()
        # Current process PID is alive
        live_pid = os.getpid()
        p = os.path.join(tmpdir, f"x.json.partial.{live_pid}")
        Path(p).write_text("", encoding="utf-8")
        old = time.time() - 7200
        os.utime(p, (old, old))
        removed = ep.cleanup_orphan_partials(tmpdir, ttl_seconds=3600)
        self.assertEqual(removed, [])
        self.assertTrue(os.path.exists(p))

    def test_recent_file_skipped_regardless_of_pid(self):
        tmpdir = tempfile.mkdtemp()
        p = os.path.join(tmpdir, "x.json.partial.99998")
        Path(p).write_text("", encoding="utf-8")
        # Fresh mtime (just created)
        removed = ep.cleanup_orphan_partials(tmpdir, ttl_seconds=3600)
        self.assertEqual(removed, [])
        self.assertTrue(os.path.exists(p))


# ============ CSV plan IO ============

class TestPlanCSV(unittest.TestCase):

    def _path(self):
        return os.path.join(tempfile.mkdtemp(), "plan.csv")

    def _rows(self):
        return [
            {"index": 0, "username": "wxid_a", "chat_name": "张三",
             "chat_type": "single", "message_count": 100,
             "first_time": "", "last_time": "", "body_bytes": 0,
             "attachment_estimated_bytes": 0, "attachment_scanned_bytes": 0,
             "size_status": "estimate_only"},
            {"index": 1, "username": "gh_pub", "chat_name": "公众号",
             "chat_type": "pub", "message_count": 50,
             "first_time": "", "last_time": "", "body_bytes": 0,
             "attachment_estimated_bytes": 0, "attachment_scanned_bytes": 0,
             "size_status": "estimate_only"},
        ]

    def test_writes_utf8_bom(self):
        p = self._path()
        ep.write_plan_csv(self._rows(), p, plan_mode=ep.PLAN_MODE_BLACKLIST)
        with open(p, "rb") as f:
            self.assertEqual(f.read(3), b"\xef\xbb\xbf")

    def test_blacklist_default_export_one(self):
        p = self._path()
        ep.write_plan_csv(self._rows(), p, plan_mode=ep.PLAN_MODE_BLACKLIST)
        with open(p, encoding="utf-8-sig") as f:
            rows = list(csv.DictReader(f))
        # wxid_a default 1, gh_pub pre-filled 0
        self.assertEqual(rows[0]["export"], "1")
        self.assertEqual(rows[1]["export"], "0")

    def test_whitelist_default_export_zero(self):
        p = self._path()
        ep.write_plan_csv(self._rows(), p, plan_mode=ep.PLAN_MODE_WHITELIST)
        with open(p, encoding="utf-8-sig") as f:
            rows = list(csv.DictReader(f))
        self.assertEqual(rows[0]["export"], "0")
        self.assertEqual(rows[1]["export"], "0")

    def test_load_blacklist_includes_unless_zero(self):
        p = self._path()
        ep.write_plan_csv(self._rows(), p, plan_mode=ep.PLAN_MODE_BLACKLIST)
        selected, _ = ep.load_plan_csv(p, plan_mode=ep.PLAN_MODE_BLACKLIST)
        # wxid_a kept (default 1), gh_pub skipped (pre-filled 0)
        self.assertEqual(selected, {"wxid_a"})

    def test_load_whitelist_only_ones(self):
        p = self._path()
        # Write whitelist (default 0)
        ep.write_plan_csv(self._rows(), p, plan_mode=ep.PLAN_MODE_WHITELIST)
        selected, _ = ep.load_plan_csv(p, plan_mode=ep.PLAN_MODE_WHITELIST)
        self.assertEqual(selected, set())
        # Now mark wxid_a as 1
        with open(p, encoding="utf-8-sig") as f:
            text = f.read()
        text = text.replace(",wxid_a,", "_xxx", 1)  # marker
        # Easier: rewrite manually
        with open(p, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(ep.PLAN_CSV_FIELDS))
            w.writeheader()
            for i, row in enumerate(self._rows()):
                out = dict(row)
                out["export"] = "1" if i == 0 else "0"
                w.writerow(out)
        selected, _ = ep.load_plan_csv(p, plan_mode=ep.PLAN_MODE_WHITELIST)
        self.assertEqual(selected, {"wxid_a"})

    def test_load_rejects_duplicate_username(self):
        p = self._path()
        with open(p, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["export", "username"])
            w.writeheader()
            w.writerow({"export": "1", "username": "wxid_a"})
            w.writerow({"export": "1", "username": "wxid_a"})
        with self.assertRaises(ValueError):
            ep.load_plan_csv(p, plan_mode=ep.PLAN_MODE_BLACKLIST)

    def test_load_rejects_empty_username(self):
        p = self._path()
        with open(p, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["export", "username"])
            w.writeheader()
            w.writerow({"export": "1", "username": ""})
        with self.assertRaises(ValueError):
            ep.load_plan_csv(p, plan_mode=ep.PLAN_MODE_BLACKLIST)


# ============ --users validation + resolution ============

class TestValidateUserArgChars(unittest.TestCase):

    def test_accepts_wxid_form(self):
        ep.validate_user_arg_chars("wxid_abc123")

    def test_accepts_early_self_alias(self):
        # 29% of R3 实测 session.db usernames look like this
        ep.validate_user_arg_chars("EarlyAlias_Foo")
        ep.validate_user_arg_chars("LegacyAlias12345")

    def test_accepts_chatroom_suffixes(self):
        ep.validate_user_arg_chars("12345@chatroom")
        ep.validate_user_arg_chars("67890@openim")

    def test_accepts_chinese_remark(self):
        ep.validate_user_arg_chars("张三")
        ep.validate_user_arg_chars("公司同事-小李")

    def test_rejects_path_traversal(self):
        with self.assertRaises(ep.UserArgError):
            ep.validate_user_arg_chars("../etc/passwd")
        with self.assertRaises(ep.UserArgError):
            ep.validate_user_arg_chars("/tmp/x")

    def test_rejects_control_chars(self):
        with self.assertRaises(ep.UserArgError):
            ep.validate_user_arg_chars("a\nb")
        with self.assertRaises(ep.UserArgError):
            ep.validate_user_arg_chars("a\x00b")

    def test_rejects_sql_meta(self):
        with self.assertRaises(ep.UserArgError):
            ep.validate_user_arg_chars("a;DROP TABLE x")


class TestResolveUserArgs(unittest.TestCase):

    def setUp(self):
        contact._invalidate_contact_caches()
        self._orig_get_path = contact._get_contact_db_path
        contact._get_contact_db_path = lambda: '/tmp/fake-contact.db'

    def tearDown(self):
        contact._get_contact_db_path = self._orig_get_path
        contact._invalidate_contact_caches()

    def test_username_in_session_resolved_directly(self):
        contact._contact_full = []
        with patch.object(ep, '_find_msg_tables_for_user', return_value=[]):
            resolved, _ = ep.resolve_user_args(
                ["wxid_a"], all_session_usernames={"wxid_a"}
            )
        self.assertEqual(resolved, ["wxid_a"])

    def test_username_with_shards_resolved_directly(self):
        contact._contact_full = []
        with patch.object(ep, '_find_msg_tables_for_user',
                          side_effect=lambda u: [{'db_path': '/x', 'table_name': 't'}] if u == "LegacyAlias12345" else []):
            resolved, _ = ep.resolve_user_args(
                ["LegacyAlias12345"], all_session_usernames=set()
            )
        self.assertEqual(resolved, ["LegacyAlias12345"])

    def test_remark_unique_match_resolved(self):
        contact._contact_full = [
            {"username": "wxid_a", "remark": "张三", "nick_name": "Alice"},
            {"username": "wxid_b", "remark": "", "nick_name": "Bob"},
        ]
        with patch.object(ep, '_find_msg_tables_for_user', return_value=[]):
            resolved, warnings = ep.resolve_user_args(
                ["张三"], all_session_usernames=set()
            )
        self.assertEqual(resolved, ["wxid_a"])
        self.assertTrue(any("张三" in w and "wxid_a" in w for w in warnings))

    def test_remark_multi_match_raises(self):
        # Two contacts with same remark — must error, not silently pick first
        contact._contact_full = [
            {"username": "wxid_a", "remark": "张三", "nick_name": "Alice"},
            {"username": "wxid_b", "remark": "张三", "nick_name": "Bob"},
        ]
        with patch.object(ep, '_find_msg_tables_for_user', return_value=[]):
            with self.assertRaises(ep.UserArgError) as cm:
                ep.resolve_user_args(["张三"], all_session_usernames=set())
        # Error message must list the ambiguous candidates
        self.assertIn("wxid_a", str(cm.exception))
        self.assertIn("wxid_b", str(cm.exception))

    def test_unknown_arg_recorded_as_warning_not_resolved(self):
        contact._contact_full = []
        with patch.object(ep, '_find_msg_tables_for_user', return_value=[]):
            resolved, warnings = ep.resolve_user_args(
                ["never_seen"], all_session_usernames=set()
            )
        self.assertEqual(resolved, [])
        self.assertTrue(any("无法解析" in w for w in warnings))


# ============ Plan stats fan-out ============

def _build_msg_db_shard(rows):
    """rows = [(local_id, local_type, create_time, real_sender_id, message_content)].
    Returns path of a tmp sqlite DB with a single Msg_<md5('wxid_test')> table.
    """
    import hashlib as _h
    table_name = f"Msg_{_h.md5('wxid_test'.encode()).hexdigest()}"
    path = Path(tempfile.mkdtemp()) / "message_x.db"
    with sqlite3.connect(path) as conn:
        conn.execute(
            f"CREATE TABLE [{table_name}] (local_id INTEGER, local_type INTEGER, "
            f"create_time INTEGER, real_sender_id INTEGER, message_content TEXT)"
        )
        conn.executemany(
            f"INSERT INTO [{table_name}] (local_id, local_type, create_time, "
            f"real_sender_id, message_content) VALUES (?, ?, ?, ?, ?)",
            rows,
        )
    return str(path), table_name


class TestCollectPlanStats(unittest.TestCase):

    def test_fan_out_sums_across_shards(self):
        path1, table_name = _build_msg_db_shard([
            (1, 1, 1700000000, 0, "hello"),
            (2, 1, 1700000100, 0, "world"),
        ])
        path2, _ = _build_msg_db_shard([
            (1, 1, 1699000000, 0, "old1"),
            (2, 1, 1699000100, 0, "old2"),
            (3, 1, 1699000200, 0, "old3"),
        ])

        shards = [
            {"db_path": path1, "table_name": table_name},
            {"db_path": path2, "table_name": table_name},
        ]
        with patch.object(ep, '_find_msg_tables_for_user', return_value=shards):
            stats = ep.collect_plan_stats(["wxid_test"], size_mode=ep.SIZE_MODE_ESTIMATE)
        s = stats["wxid_test"]
        self.assertEqual(s["message_count"], 5)
        self.assertEqual(s["first_ct"], 1699000000)
        self.assertEqual(s["last_ct"], 1700000100)
        # body_bytes = len("hello"+"world"+"old1"+"old2"+"old3") = 5+5+4+4+4 = 22
        self.assertEqual(s["body_bytes"], 22)
        self.assertEqual(s["size_status"], ep.SIZE_STATUS_ESTIMATE_ONLY)

    def test_no_shards_returns_no_messages_status(self):
        with patch.object(ep, '_find_msg_tables_for_user', return_value=[]):
            stats = ep.collect_plan_stats(["wxid_none"], size_mode=ep.SIZE_MODE_ESTIMATE)
        self.assertEqual(stats["wxid_none"]["size_status"], ep.SIZE_STATUS_NO_MESSAGES)
        self.assertEqual(stats["wxid_none"]["message_count"], 0)

    def test_date_range_filter(self):
        path, table_name = _build_msg_db_shard([
            (1, 1, 1700000000, 0, "a"),
            (2, 1, 1700100000, 0, "b"),
            (3, 1, 1700200000, 0, "c"),
        ])
        with patch.object(ep, '_find_msg_tables_for_user',
                          return_value=[{"db_path": path, "table_name": table_name}]):
            stats = ep.collect_plan_stats(
                ["wxid_test"],
                start_ts=1700050000, end_ts=1700150000,
                size_mode=ep.SIZE_MODE_ESTIMATE,
            )
        # Only msg 2 in range
        self.assertEqual(stats["wxid_test"]["message_count"], 1)
        self.assertEqual(stats["wxid_test"]["body_bytes"], 1)  # "b"


# ============ Lock path ============

class TestLockPath(unittest.TestCase):

    def test_lock_lives_outside_output_dir(self):
        tmpdir = tempfile.mkdtemp()
        lock_path = ep.lock_path_for(tmpdir)
        self.assertFalse(lock_path.startswith(tmpdir))
        # Should be under system tmp
        self.assertTrue(lock_path.startswith(tempfile.gettempdir()))

    def test_same_output_dir_same_lock(self):
        tmpdir = tempfile.mkdtemp()
        self.assertEqual(ep.lock_path_for(tmpdir), ep.lock_path_for(tmpdir))

    def test_different_output_dir_different_lock(self):
        t1 = tempfile.mkdtemp()
        t2 = tempfile.mkdtemp()
        self.assertNotEqual(ep.lock_path_for(t1), ep.lock_path_for(t2))


if __name__ == "__main__":
    unittest.main()
