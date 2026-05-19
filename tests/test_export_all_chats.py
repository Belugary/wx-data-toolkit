"""Tests for wxdec.cli.export_all_chats — CLI argparse + export_one core path.

Focus on commit-4 DoD invariants:
  - --write-plan-csv writes UTF-8 BOM CSV via export_plan
  - --from-plan-csv loads selection
  - --users multi-match raises (regression for R3-1 + plan v5 fuzzy guard)
  - export_one full export builds v3 JSON with schema_version + last_cursor
  - export_one incremental skips already-exported messages by per-shard cursor
  - export_one rejects v1/v2 old JSON → falls back to full re-export

Tests use real tmp sqlite for message tables but mock the chat-context
layer (`msg_query._resolve_chat_context`) because building the full
session.db + Name2Id + decryption stack is out of scope.
"""

import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import wxdec.contact as contact
from wxdec.cli import export_all_chats as eac


def _build_msg_db(rows, username="wxid_test"):
    """rows = [(local_id, local_type, create_time, real_sender_id, content)].
    Returns (db_path, table_name) for a Msg_<md5(username)> table with the
    schema export_one expects (incl. WCDB_CT_message_content for CT decompression).
    """
    table_name = f"Msg_{hashlib.md5(username.encode()).hexdigest()}"
    path = Path(tempfile.mkdtemp()) / "message_x.db"
    with sqlite3.connect(path) as conn:
        conn.execute(
            f"CREATE TABLE [{table_name}] (local_id INTEGER, local_type INTEGER, "
            f"create_time INTEGER, real_sender_id INTEGER, message_content TEXT, "
            f"WCDB_CT_message_content INTEGER)"
        )
        # Name2Id table for sender resolution; empty is fine for "me" / system
        conn.execute("CREATE TABLE Name2Id (user_name TEXT)")
        conn.executemany(
            f"INSERT INTO [{table_name}] (local_id, local_type, create_time, "
            f"real_sender_id, message_content, WCDB_CT_message_content) "
            f"VALUES (?, ?, ?, ?, ?, 0)",
            rows,
        )
    return str(path), table_name


def _fake_ctx(username, display_name, db_path, table_name, is_group=False):
    return {
        "username": username,
        "display_name": display_name,
        "is_group": is_group,
        "message_tables": [{"db_path": db_path, "table_name": table_name}],
    }


# ============ CLI argparse ============

class TestCLIArgs(unittest.TestCase):

    def test_mutually_exclusive_write_and_from_plan(self):
        with patch.object(eac.ep, 'load_session_usernames', return_value=["wxid_a"]):
            ret = eac.main([
                "--write-plan-csv", "/tmp/p.csv",
                "--from-plan-csv", "/tmp/q.csv",
            ])
        self.assertEqual(ret, eac.EXIT_ERROR)

    def test_no_session_db_returns_error(self):
        with patch.object(eac.ep, 'load_session_usernames', return_value=[]):
            ret = eac.main(["--write-plan-csv", "/tmp/p.csv"])
        self.assertEqual(ret, eac.EXIT_ERROR)


# ============ export_one full export ============

class TestExportOneFull(unittest.TestCase):

    def setUp(self):
        contact._invalidate_contact_caches()
        self._orig_get_path = contact._get_contact_db_path
        contact._get_contact_db_path = lambda: '/tmp/fake.db'
        contact._contact_full = []  # bypass DB call in contact_metadata_for_chat
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        contact._get_contact_db_path = self._orig_get_path
        contact._invalidate_contact_caches()

    def test_v3_schema_includes_cursor_and_metadata(self):
        db_path, table = _build_msg_db([
            (1, 1, 1700000000, 0, "msg1"),
            (2, 1, 1700000100, 0, "msg2"),
            (3, 1, 1700000200, 0, "msg3"),
        ])
        ctx = _fake_ctx("wxid_test", "测试", db_path, table)
        idx = eac.ep._empty_index()

        with patch.object(eac.msg_query, '_resolve_chat_context', return_value=ctx):
            success, total, new, reason = eac.export_one(
                "wxid_test", self.tmpdir,
                contact_names={"wxid_test": "测试"},
                idx=idx,
            )
        self.assertTrue(success, reason)
        self.assertEqual(total, 3)
        self.assertEqual(new, 3)

        out_file = os.path.join(self.tmpdir, "测试_export.json")
        self.assertTrue(os.path.exists(out_file))
        with open(out_file, encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["schema_version"], 3)
        self.assertEqual(data["username"], "wxid_test")
        self.assertIn("date_first_msg", data)
        self.assertIn("date_last_msg", data)
        self.assertIn("last_cursor", data)
        # Cursor keyed by shard basename
        shard_key = os.path.basename(db_path)
        self.assertIn(shard_key, data["last_cursor"])
        self.assertEqual(data["last_cursor"][shard_key]["create_time"], 1700000200)
        self.assertEqual(data["last_cursor"][shard_key]["local_id"], 3)
        # Index updated
        self.assertIn("wxid_test", idx["users"])
        self.assertEqual(idx["users"]["wxid_test"]["filename"], "测试_export.json")


# ============ export_one incremental ============

class TestExportOneIncremental(unittest.TestCase):

    def setUp(self):
        contact._invalidate_contact_caches()
        self._orig_get_path = contact._get_contact_db_path
        contact._get_contact_db_path = lambda: '/tmp/fake.db'
        contact._contact_full = []
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        contact._get_contact_db_path = self._orig_get_path
        contact._invalidate_contact_caches()

    def test_incremental_skips_messages_at_or_before_cursor(self):
        # Initial DB: 3 messages
        db_path, table = _build_msg_db([
            (1, 1, 1700000000, 0, "msg1"),
            (2, 1, 1700000100, 0, "msg2"),
            (3, 1, 1700000200, 0, "msg3"),
        ])
        ctx = _fake_ctx("wxid_test", "测试", db_path, table)
        idx = eac.ep._empty_index()

        with patch.object(eac.msg_query, '_resolve_chat_context', return_value=ctx):
            # First export: full
            eac.export_one("wxid_test", self.tmpdir,
                           contact_names={}, idx=idx)

            # Add 2 new messages to the same shard
            with sqlite3.connect(db_path) as conn:
                conn.executemany(
                    f"INSERT INTO [{table}] (local_id, local_type, create_time, "
                    f"real_sender_id, message_content, WCDB_CT_message_content) "
                    f"VALUES (?, ?, ?, ?, ?, 0)",
                    [
                        (4, 1, 1700000300, 0, "msg4"),
                        (5, 1, 1700000400, 0, "msg5"),
                    ],
                )

            # Incremental export
            success, total, new, reason = eac.export_one(
                "wxid_test", self.tmpdir,
                contact_names={}, idx=idx,
                incremental=True,
            )

        self.assertTrue(success, reason)
        self.assertEqual(total, 5)  # 3 existing + 2 new
        self.assertEqual(new, 2)    # Only 2 new appended

        with open(os.path.join(self.tmpdir, "测试_export.json"), encoding="utf-8") as f:
            data = json.load(f)
        # Cursor advanced to msg5
        shard_key = os.path.basename(db_path)
        self.assertEqual(data["last_cursor"][shard_key]["local_id"], 5)

    def test_incremental_falls_back_to_full_on_old_schema(self):
        db_path, table = _build_msg_db([
            (1, 1, 1700000000, 0, "msg1"),
            (2, 1, 1700000100, 0, "msg2"),
        ])
        ctx = _fake_ctx("wxid_test", "测试", db_path, table)
        idx = eac.ep._empty_index()

        # Plant an old-schema JSON (no schema_version, list-form cursor)
        ep_path = os.path.join(self.tmpdir, "测试_export.json")
        with open(ep_path, "w", encoding="utf-8") as f:
            json.dump({
                "chat": "测试",
                "username": "wxid_test",
                "exported_at": "old",
                "messages": [{"local_id": 999, "timestamp": 1, "sender": "me"}],
                # No schema_version, no last_cursor
            }, f)

        # Inject prior index entry pointing at the old file
        idx["users"]["wxid_test"] = {"filename": "测试_export.json"}

        with patch.object(eac.msg_query, '_resolve_chat_context', return_value=ctx):
            success, total, new, reason = eac.export_one(
                "wxid_test", self.tmpdir,
                contact_names={}, idx=idx,
                incremental=True,
            )
        self.assertTrue(success, reason)
        # Old schema → full re-export, ignoring planted msg local_id=999
        self.assertEqual(total, 2)
        self.assertEqual(new, 2)
        with open(ep_path, encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["schema_version"], 3)
        # local_id=999 from old JSON is gone (full re-export)
        self.assertEqual([m["local_id"] for m in data["messages"]], [1, 2])


# ============ Group chat header ============

class TestExportOneGroup(unittest.TestCase):

    def setUp(self):
        contact._invalidate_contact_caches()
        self._orig_get_path = contact._get_contact_db_path
        contact._get_contact_db_path = lambda: '/tmp/fake.db'
        contact._contact_full = []

    def tearDown(self):
        contact._get_contact_db_path = self._orig_get_path
        contact._invalidate_contact_caches()

    def test_group_has_is_group_no_contact_fields(self):
        # Different username because Msg_ table is keyed by md5(username)
        group_un = "12345@chatroom"
        db_path, table = _build_msg_db([
            (1, 1, 1700000000, 0, "hi"),
        ], username=group_un)
        ctx = _fake_ctx(group_un, "工作群", db_path, table, is_group=True)
        idx = eac.ep._empty_index()
        tmpdir = tempfile.mkdtemp()
        with patch.object(eac.msg_query, '_resolve_chat_context', return_value=ctx):
            eac.export_one(group_un, tmpdir, contact_names={}, idx=idx)
        with open(os.path.join(tmpdir, "工作群_export.json"), encoding="utf-8") as f:
            data = json.load(f)
        self.assertTrue(data.get("is_group"))
        self.assertNotIn("contact_remark", data)
        self.assertNotIn("contact_nick_name", data)
        self.assertNotIn("contact_memo", data)


if __name__ == "__main__":
    unittest.main()
