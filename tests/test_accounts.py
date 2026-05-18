"""Unit tests for wxdec.accounts.detect_accounts.

Builds a synthetic decrypted_dir tree (contact.db + message_N.db) and
verifies the self-wxid identification algorithm against scenarios that
mimic real-data quirks documented in the source module:

  - Naive "any status=2 = self" produces 100+ false positives (friend
    messages can carry status=2). Cliff filter must trim them.
  - Group + public-account chats must be SKIPPED (only PRIVATE chats
    count). A group with self=heavy sender shouldn't double-count.
  - System pseudo-wxids (filehelper, weixin, ...) must be excluded.
  - Multi-account dumps: when two real selves have similar message
    counts, BOTH should survive the cliff (≥ 50% of predecessor).
"""

import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path

from wxdec.accounts import AccountInfo, detect_accounts


def _md5(s):
    return hashlib.md5(s.encode()).hexdigest()


def _build_decrypted_dir(contacts, msg_db_rows):
    """contacts: list of (username, nick_name, alias, local_type, description)
    msg_db_rows: list of (db_index, name2id_rows, msg_tables)
      name2id_rows: list of (rowid, user_name)
      msg_tables: list of (chat_username, [(real_sender_id, status, create_time)])

    Returns Path to root of the synthetic decrypted_dir.
    """
    root = Path(tempfile.mkdtemp())
    (root / "contact").mkdir()
    (root / "message").mkdir()

    contact_db = root / "contact" / "contact.db"
    with sqlite3.connect(contact_db) as conn:
        conn.execute(
            "CREATE TABLE contact (username TEXT, nick_name TEXT, "
            "alias TEXT, remark TEXT, local_type INTEGER, description TEXT)"
        )
        for username, nick, alias, ltype, desc in contacts:
            conn.execute(
                "INSERT INTO contact (username, nick_name, alias, remark, "
                "local_type, description) VALUES (?, ?, ?, ?, ?, ?)",
                (username, nick, alias, "", ltype, desc),
            )

    for db_index, name2id_rows, msg_tables in msg_db_rows:
        db_path = root / "message" / f"message_{db_index}.db"
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "CREATE TABLE Name2Id (rowid INTEGER PRIMARY KEY, user_name TEXT)"
            )
            for rowid, uname in name2id_rows:
                conn.execute(
                    "INSERT INTO Name2Id (rowid, user_name) VALUES (?, ?)",
                    (rowid, uname),
                )
            for chat_username, rows in msg_tables:
                tbl = f"Msg_{_md5(chat_username)}"
                conn.execute(
                    f"CREATE TABLE [{tbl}] (real_sender_id INTEGER, "
                    f"status INTEGER, create_time INTEGER)"
                )
                for sender_id, status, ct in rows:
                    conn.execute(
                        f"INSERT INTO [{tbl}] (real_sender_id, status, "
                        f"create_time) VALUES (?, ?, ?)",
                        (sender_id, status, ct),
                    )
    return root


class TestDetectAccounts(unittest.TestCase):

    def test_canonical_single_account(self):
        root = _build_decrypted_dir(
            contacts=[
                ("me_wxid", "我", "my_alias", 0, ""),
                ("alice_wxid", "Alice", "", 0, ""),
                ("bob_wxid", "Bob", "", 0, ""),
            ],
            msg_db_rows=[
                (0,
                 [(1, "me_wxid"), (2, "alice_wxid"), (3, "bob_wxid")],
                 [
                     # alice chat — I sent 100, alice sent 50
                     ("alice_wxid", [(1, 2, 100)] * 100
                                    + [(2, 2, 100)] * 50),
                     # bob chat — I sent 80, bob sent 40
                     ("bob_wxid", [(1, 2, 100)] * 80
                                  + [(3, 2, 100)] * 40),
                 ]),
            ],
        )
        out = detect_accounts(root)
        self.assertEqual(len(out), 1)
        self.assertIsInstance(out[0], AccountInfo)
        self.assertEqual(out[0].wxid, "me_wxid")
        self.assertEqual(out[0].nickname, "我")
        self.assertEqual(out[0].alias, "my_alias")
        # friends = local_type=0 minus gh_*/groups = 3 (all rows)
        self.assertEqual(out[0].friend_count, 3)

    def test_cliff_filter_trims_friend_false_positives(self):
        # Self sends 200 messages with status=2. Friend has 1 row with
        # status=2 (real data quirk). Cliff filter (50% ratio) drops friend.
        root = _build_decrypted_dir(
            contacts=[
                ("me_wxid", "Me", "", 0, ""),
                ("noisy_friend", "Friend", "", 0, ""),
            ],
            msg_db_rows=[
                (0,
                 [(1, "me_wxid"), (2, "noisy_friend")],
                 [
                     ("noisy_friend", [(1, 2, 100)] * 200 + [(2, 2, 100)]),
                 ]),
            ],
        )
        out = detect_accounts(root)
        self.assertEqual([a.wxid for a in out], ["me_wxid"])

    def test_multi_account_dump_both_survive(self):
        # Two real selves with similar counts (100 vs 80) — both should
        # survive the 50% cliff.
        root = _build_decrypted_dir(
            contacts=[
                ("self_a", "A", "", 0, ""),
                ("self_b", "B", "", 0, ""),
                ("alice_wxid", "Alice", "", 0, ""),
            ],
            msg_db_rows=[
                (0,
                 [(1, "self_a"), (2, "self_b"), (3, "alice_wxid")],
                 [
                     ("alice_wxid", [(1, 2, 100)] * 100
                                    + [(2, 2, 100)] * 80
                                    + [(3, 2, 100)] * 10),
                 ]),
            ],
        )
        out = detect_accounts(root)
        wxids = [a.wxid for a in out]
        # Both selves survive; alice (10 << 80*0.5=40) gets clipped.
        self.assertEqual(wxids, ["self_a", "self_b"])

    def test_group_chats_excluded(self):
        # Self sends 5 messages in private (low). A friend sends 200 in
        # a group (would dominate if groups were counted). Expected: self
        # wins because only the private chat counts.
        group_user = "12345678@chatroom"
        root = _build_decrypted_dir(
            contacts=[
                ("me_wxid", "Me", "", 0, ""),
                ("alice_wxid", "Alice", "", 0, ""),
                (group_user, "Group", "", 0, ""),
            ],
            msg_db_rows=[
                (0,
                 [(1, "me_wxid"), (2, "alice_wxid")],
                 [
                     ("alice_wxid", [(1, 2, 100)] * 5),
                     (group_user, [(2, 2, 100)] * 200),
                 ]),
            ],
        )
        out = detect_accounts(root)
        self.assertEqual([a.wxid for a in out], ["me_wxid"])

    def test_public_account_chats_excluded(self):
        # Same idea — gh_* chats must be excluded from candidate pool.
        pub = "gh_pubaccount"
        root = _build_decrypted_dir(
            contacts=[
                ("me_wxid", "Me", "", 0, ""),
                (pub, "PubAcct", "", 0, ""),
            ],
            msg_db_rows=[
                (0,
                 [(1, "me_wxid"), (2, pub)],
                 [
                     (pub, [(1, 2, 100)] * 5),  # would count without filter
                 ]),
            ],
        )
        out = detect_accounts(root)
        # No private chats → no candidates
        self.assertEqual(out, [])

    def test_system_pseudo_wxids_excluded(self):
        # If filehelper appears as a sender in a private chat, it must NOT
        # be a candidate.
        root = _build_decrypted_dir(
            contacts=[
                ("filehelper", "文件传输助手", "", 0, ""),
                ("alice_wxid", "Alice", "", 0, ""),
            ],
            msg_db_rows=[
                (0,
                 [(1, "filehelper"), (2, "alice_wxid")],
                 [
                     ("alice_wxid", [(1, 2, 100)] * 50),
                 ]),
            ],
        )
        out = detect_accounts(root)
        self.assertEqual(out, [])

    def test_aggregate_stats_across_dbs(self):
        # Verify cross-DB aggregation for self counts AND msg time-range.
        root = _build_decrypted_dir(
            contacts=[
                ("me_wxid", "Me", "", 0, ""),
                ("alice_wxid", "Alice", "", 0, ""),
            ],
            msg_db_rows=[
                (0,
                 [(1, "me_wxid"), (2, "alice_wxid")],
                 [("alice_wxid", [(1, 2, 1000)] * 50)]),
                (1,
                 [(1, "alice_wxid"), (5, "me_wxid")],
                 [("alice_wxid", [(5, 2, 2000)] * 50)]),
            ],
        )
        out = detect_accounts(root)
        self.assertEqual(out[0].wxid, "me_wxid")
        self.assertEqual(out[0].msg_first_ts, 1000)
        self.assertEqual(out[0].msg_last_ts, 2000)
        self.assertEqual(out[0].total_msg_count, 100)

    def test_empty_dir(self):
        root = Path(tempfile.mkdtemp())
        (root / "contact").mkdir()
        (root / "message").mkdir()
        self.assertEqual(detect_accounts(root), [])

    def test_missing_name2id_table_tolerated(self):
        # A message_N.db file present but lacking the Name2Id table
        # (corrupt / partial dump) must NOT crash; the scanner should
        # skip that DB and aggregate the rest.
        root = _build_decrypted_dir(
            contacts=[
                ("me_wxid", "Me", "", 0, ""),
                ("alice_wxid", "Alice", "", 0, ""),
            ],
            msg_db_rows=[
                (0,
                 [(1, "me_wxid"), (2, "alice_wxid")],
                 [("alice_wxid", [(1, 2, 100)] * 50)]),
            ],
        )
        # Add a malformed DB alongside the good one
        bad = root / "message" / "message_99.db"
        with sqlite3.connect(bad) as conn:
            conn.execute("CREATE TABLE unrelated (x INTEGER)")
        out = detect_accounts(root)
        self.assertEqual([a.wxid for a in out], ["me_wxid"])


if __name__ == "__main__":
    unittest.main()
