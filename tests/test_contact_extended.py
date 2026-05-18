"""Unit test for wxdec.contact.load_contacts_extended.

The legacy `_load_contacts_from` returns `{username: display}` and a flat
list — sufficient for the project's MCP server / web viewer. The extended
loader adds `alias` (微信号) plus structural `is_group` / `is_pub` flags
needed by downstream consumers (daily summarizers, multi-account
browsers).
"""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from wxdec.contact import load_contacts_extended


def _build_contact_db(rows):
    """rows = list of (username, nick_name, alias, remark)"""
    tmp = Path(tempfile.mkdtemp()) / "contact.db"
    with sqlite3.connect(tmp) as conn:
        conn.execute(
            "CREATE TABLE contact (username TEXT, nick_name TEXT, "
            "alias TEXT, remark TEXT)"
        )
        conn.executemany(
            "INSERT INTO contact (username, nick_name, alias, remark) "
            "VALUES (?, ?, ?, ?)",
            rows,
        )
    return tmp


class TestLoadContactsExtended(unittest.TestCase):

    def test_basic_personal_contact(self):
        db = _build_contact_db([
            ("alice_wxid", "Alice", "alice123", "我的好友 Alice"),
        ])
        out = load_contacts_extended(db)
        self.assertEqual(out["alice_wxid"], {
            "display": "我的好友 Alice",     # remark wins
            "nick": "Alice",
            "alias": "alice123",
            "remark": "我的好友 Alice",
            "is_group": False,
            "is_pub": False,
        })

    def test_display_priority_remark_then_nick_then_username(self):
        db = _build_contact_db([
            ("a", "NickA", "", "RemarkA"),     # remark wins
            ("b", "NickB", "", ""),            # nick wins
            ("c", "", "", ""),                 # username falls through
        ])
        out = load_contacts_extended(db)
        self.assertEqual(out["a"]["display"], "RemarkA")
        self.assertEqual(out["b"]["display"], "NickB")
        self.assertEqual(out["c"]["display"], "c")

    def test_group_flag(self):
        db = _build_contact_db([
            ("12345@chatroom", "某群", "", ""),
            ("alice_wxid", "Alice", "", ""),
        ])
        out = load_contacts_extended(db)
        self.assertTrue(out["12345@chatroom"]["is_group"])
        self.assertFalse(out["alice_wxid"]["is_group"])

    def test_public_account_flag(self):
        db = _build_contact_db([
            ("gh_someaccount", "某公众号", "gh_alias", ""),
            ("alice_wxid", "Alice", "", ""),
        ])
        out = load_contacts_extended(db)
        self.assertTrue(out["gh_someaccount"]["is_pub"])
        self.assertFalse(out["alice_wxid"]["is_pub"])

    def test_null_fields_become_empty_strings(self):
        # Real WeChat contact.db rows often have NULL nick/alias/remark.
        # Loader must coerce to "" so downstream string ops are safe.
        db = _build_contact_db([
            ("alice_wxid", None, None, None),
        ])
        out = load_contacts_extended(db)
        self.assertEqual(out["alice_wxid"]["nick"], "")
        self.assertEqual(out["alice_wxid"]["alias"], "")
        self.assertEqual(out["alice_wxid"]["remark"], "")
        # display falls through to username when remark+nick are both empty
        self.assertEqual(out["alice_wxid"]["display"], "alice_wxid")

    def test_empty_username_rows_skipped(self):
        db = _build_contact_db([
            ("alice_wxid", "Alice", "", ""),
            ("", "ghost", "", ""),
            (None, "null_ghost", "", ""),
        ])
        out = load_contacts_extended(db)
        self.assertEqual(set(out.keys()), {"alice_wxid"})


if __name__ == "__main__":
    unittest.main()
