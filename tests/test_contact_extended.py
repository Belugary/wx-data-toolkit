"""Unit tests for wxdec.contact.

Covers:
  - `load_contacts_extended`: legacy 4-column schema → dict-of-dicts with
    derived `is_group` / `is_pub` flags.
  - `_load_contacts_from`: PRAGMA-sniffed 3-to-6 column schema covering
    optional `alias` / `description` / `phone*` columns across WeChat
    client versions.
  - `get_contact_tag_names_by_username`: reverse index from
    {label_id: {members}} to {username: [tag_names]}.
"""

import sqlite3
import tempfile
import unittest
from pathlib import Path

import wxdec.contact as contact
from wxdec.contact import (
    _load_contacts_from,
    get_contact_tag_names_by_username,
    load_contacts_extended,
)


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


def _build_contact_db_minimal(rows):
    """Older WeChat schema: only username/nick_name/remark, no alias/phone/description.

    rows = list of (username, nick_name, remark)
    """
    tmp = Path(tempfile.mkdtemp()) / "contact.db"
    with sqlite3.connect(tmp) as conn:
        conn.execute(
            "CREATE TABLE contact (username TEXT, nick_name TEXT, remark TEXT)"
        )
        conn.executemany(
            "INSERT INTO contact (username, nick_name, remark) VALUES (?, ?, ?)",
            rows,
        )
    return tmp


def _build_contact_db_full(rows, phone_col='phone_number'):
    """Newer schema with all optional columns present.

    rows = list of (username, nick_name, remark, alias, description, phone)
    """
    tmp = Path(tempfile.mkdtemp()) / "contact.db"
    with sqlite3.connect(tmp) as conn:
        conn.execute(
            f"CREATE TABLE contact (username TEXT, nick_name TEXT, remark TEXT, "
            f"alias TEXT, description TEXT, {phone_col} TEXT)"
        )
        conn.executemany(
            f"INSERT INTO contact (username, nick_name, remark, alias, "
            f"description, {phone_col}) VALUES (?, ?, ?, ?, ?, ?)",
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


class TestLoadContactsFromColumnSniff(unittest.TestCase):
    """PRAGMA table_info sniffing for optional alias/description/phone columns.

    Some WeChat client versions omit `description` and `phone_number`
    entirely; loader must coerce missing columns to "" without raising,
    so the same code path works against 3.x and 4.x dumps.
    """

    def setUp(self):
        contact._invalidate_contact_caches()

    def test_minimal_schema_missing_columns_become_empty(self):
        db = _build_contact_db_minimal([
            ("alice_wxid", "Alice", "我的好友 Alice"),
        ])
        _names, full = _load_contacts_from(db)
        self.assertEqual(len(full), 1)
        row = full[0]
        self.assertEqual(row['username'], 'alice_wxid')
        self.assertEqual(row['nick_name'], 'Alice')
        self.assertEqual(row['remark'], '我的好友 Alice')
        self.assertEqual(row['alias'], '')
        self.assertEqual(row['description'], '')
        self.assertEqual(row['phone'], '')

    def test_full_schema_all_columns_populated(self):
        db = _build_contact_db_full([
            ("alice_wxid", "Alice", "好友 Alice", "alice123",
             "重要客户", "13800000000"),
        ])
        _names, full = _load_contacts_from(db)
        row = full[0]
        self.assertEqual(row['alias'], 'alice123')
        self.assertEqual(row['description'], '重要客户')
        self.assertEqual(row['phone'], '13800000000')

    def test_alt_phone_column_mobile(self):
        # Some client versions name the column `mobile` instead of `phone_number`.
        db = _build_contact_db_full([
            ("bob_wxid", "Bob", "", "bob_alias", "", "13900000000"),
        ], phone_col='mobile')
        _names, full = _load_contacts_from(db)
        self.assertEqual(full[0]['phone'], '13900000000')

    def test_null_text_fields_coerced_to_empty(self):
        db = _build_contact_db_full([
            ("alice_wxid", None, None, None, None, None),
        ])
        _names, full = _load_contacts_from(db)
        row = full[0]
        self.assertEqual(row['nick_name'], '')
        self.assertEqual(row['alias'], '')
        self.assertEqual(row['description'], '')
        self.assertEqual(row['phone'], '')


class TestGetContactTagNamesByUsername(unittest.TestCase):
    """Reverse index from {label_id: {members}} to {username: [tag_names]}.

    The production loader (`_load_contact_tags`) reads contact.db; this
    test bypasses DB by pre-populating the module-level cache and
    monkey-patching `_get_contact_db_path` to return a non-None sentinel
    (so the loader's early-return on missing path doesn't trigger).
    """

    def setUp(self):
        contact._invalidate_contact_caches()
        self._orig_get_path = contact._get_contact_db_path
        contact._get_contact_db_path = lambda: '/tmp/fake-contact.db'  # sentinel

    def tearDown(self):
        contact._get_contact_db_path = self._orig_get_path
        contact._invalidate_contact_caches()

    def test_reverse_index_basic(self):
        contact._contact_tags = {
            101: {'name': '同事', 'sort_order': 1, 'members': [
                {'username': 'wxid_a', 'display_name': 'A'},
                {'username': 'wxid_b', 'display_name': 'B'},
            ]},
            102: {'name': '家人', 'sort_order': 2, 'members': [
                {'username': 'wxid_a', 'display_name': 'A'},
            ]},
        }
        out = get_contact_tag_names_by_username()
        self.assertEqual(set(out['wxid_a']), {'同事', '家人'})
        self.assertEqual(out['wxid_b'], ['同事'])
        self.assertNotIn('wxid_c', out)

    def test_empty_when_no_tags(self):
        contact._contact_tags = {}
        self.assertEqual(get_contact_tag_names_by_username(), {})

    def test_skips_empty_tag_names_and_usernames(self):
        contact._contact_tags = {
            201: {'name': '', 'members': [{'username': 'wxid_x'}]},     # empty tag name
            202: {'name': 'tagY', 'members': [{'username': ''}, {}]},   # empty/missing username
            203: {'name': 'tagZ', 'members': [{'username': 'wxid_z'}]},
        }
        out = get_contact_tag_names_by_username()
        self.assertEqual(out, {'wxid_z': ['tagZ']})


if __name__ == "__main__":
    unittest.main()
