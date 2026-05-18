"""Self-wxid (account) discovery from a decrypted WeChat data dir.

Critical primitive for any downstream that needs to know "whose perspective
am I rendering" — daily summarizers, multi-account dump browsers,
analytics. Naive approaches (e.g. "rowid 1 in Name2Id is self") break on
real data; the algorithm here is validated against a 6.4M-msg corpus where
`status=2` is NOT exclusively self-sent (friends' read messages can carry
status=2 too, producing 195+ false positives).

Public API:
    AccountInfo dataclass
    detect_accounts(decrypted_dir) -> list[AccountInfo]

For a 1-decrypted_dir-1-account install (canonical), returns a 1-element
list. Multi-account dumps return multiple candidates; downstream setup
wizards present them for user pick.
"""

from __future__ import annotations

import hashlib
import sqlite3
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import List

# WeChat's system slot wxids — would be false-positives if any internal
# row tagged them status=2.
_NON_USER_WXIDS = frozenset({
    "notifymessage", "filehelper", "weixin", "newsapp",
    "fmessage", "qqmail", "tmessage", "qmessage",
})

# A wxid is dropped from the candidate pool if its count drops below this
# fraction of its predecessor in the ranked list. 0.5 = 2x cliff.
_SELF_CANDIDATE_CLIFF_RATIO = 0.5


@dataclass
class AccountInfo:
    """One detected self-account, with descriptive metadata.

    `friend_count` / `group_count` / `total_msg_count` /
    `msg_first_ts` / `msg_last_ts` are DUMP-WIDE rather than per-wxid
    (since contact.db has one combined contact list); when multiple
    candidates appear, treat them as "this dump's totals" rather than
    "this account's private friend list".
    """
    wxid: str
    nickname: str = ""
    alias: str = ""
    description: str = ""
    msg_first_ts: int = 0
    msg_last_ts: int = 0
    friend_count: int = 0
    group_count: int = 0
    total_msg_count: int = 0


def detect_accounts(decrypted_dir):
    """Discover candidate self-wxid(s) in `decrypted_dir`, sorted by
    self-message count descending.

    Algorithm:

      1. For every Msg_* table that is a PRIVATE chat (excludes
         @chatroom groups and gh_* public accounts), count messages
         with `status=2` grouped by real_sender_id, resolve rowids to
         wxids per-DB, aggregate across DBs.
      2. Group + public chats are skipped because their status=2
         semantics differ — in groups, members' messages frequently
         carry status=2 with no self-relationship.
      3. Cliff filter: rank wxids by count; include only the leading
         contiguous run where each next-rank count is >= 50% of its
         predecessor. Friend false-positives (33 vs self's 269k →
         0.01% ratio) get clipped; multi-account dumps where two
         real selves have similar counts both survive.
      4. Skip gh_*, *@chatroom, and WeChat system pseudo-wxids
         (`filehelper` / `weixin` etc.).
    """
    decrypted_dir = Path(decrypted_dir)
    contact_db = decrypted_dir / "contact" / "contact.db"
    md5_to_kind = _build_chat_kind_index(contact_db)

    candidates = _find_self_candidates(decrypted_dir, md5_to_kind)
    if not candidates:
        return []

    friend_count, group_count = _count_friends_groups(contact_db)
    msg_first_ts, msg_last_ts, total = _aggregate_msg_stats(decrypted_dir)

    return [
        _build_account_info(
            wxid, contact_db,
            friend_count, group_count,
            msg_first_ts, msg_last_ts, total,
        )
        for wxid in candidates
    ]


def _build_chat_kind_index(contact_db):
    """{md5(username): 'public' | 'group' | 'private'} for every contact."""
    out = {}
    if not contact_db.exists():
        return out
    with sqlite3.connect(contact_db) as conn:
        try:
            rows = conn.execute(
                "SELECT username FROM contact "
                "WHERE username IS NOT NULL AND username != ''"
            ).fetchall()
        except sqlite3.Error:
            return out
    for (username,) in rows:
        if username.startswith("gh_"):
            kind = "public"
        elif username.endswith("@chatroom"):
            kind = "group"
        else:
            kind = "private"
        out[hashlib.md5(username.encode()).hexdigest()] = kind
    return out


def _find_self_candidates(decrypted_dir, md5_to_kind):
    """Return wxids ranked by `status=2` count in PRIVATE chats only,
    after the cliff filter trims the long tail of friend false-positives.
    """
    counter = Counter()
    for db_path in sorted(decrypted_dir.glob("message/message_[0-9]*.db")):
        with sqlite3.connect(db_path) as conn:
            try:
                id_to_wxid = {
                    rowid: wxid
                    for rowid, wxid in conn.execute(
                        "SELECT rowid, user_name FROM Name2Id"
                    )
                }
            except sqlite3.Error:
                continue
            try:
                tables = [
                    r[0] for r in conn.execute(
                        "SELECT name FROM sqlite_master "
                        "WHERE type='table' AND name LIKE 'Msg_%'"
                    )
                ]
            except sqlite3.Error:
                continue
            for tbl in tables:
                chat_md5 = tbl[len("Msg_"):]
                if md5_to_kind.get(chat_md5) != "private":
                    continue
                try:
                    rows = conn.execute(
                        f"SELECT real_sender_id, COUNT(*) FROM [{tbl}] "
                        f"WHERE status=2 GROUP BY real_sender_id"
                    ).fetchall()
                except sqlite3.Error:
                    continue
                for sid, n in rows:
                    wxid = id_to_wxid.get(sid)
                    if wxid is None:
                        continue
                    if (
                        wxid.startswith("gh_")
                        or "@" in wxid
                        or wxid in _NON_USER_WXIDS
                    ):
                        continue
                    counter[wxid] += n

    return _apply_cliff_filter(counter.most_common())


def _apply_cliff_filter(ranked):
    """Take the leading run of candidates whose count is >= ratio *
    predecessor. Returns the list of surviving wxids in rank order.
    """
    if not ranked:
        return []
    survivors = [ranked[0][0]]
    for i in range(1, len(ranked)):
        if ranked[i][1] >= ranked[i - 1][1] * _SELF_CANDIDATE_CLIFF_RATIO:
            survivors.append(ranked[i][0])
        else:
            break
    return survivors


def _count_friends_groups(contact_db):
    """Friends = contact.local_type=0 minus public accounts and groups.
    Groups = contact rows with @chatroom username.
    """
    if not contact_db.exists():
        return (0, 0)
    with sqlite3.connect(contact_db) as conn:
        try:
            friends = conn.execute(
                "SELECT COUNT(*) FROM contact "
                "WHERE local_type=0 "
                "  AND username NOT LIKE 'gh_%' "
                "  AND username NOT LIKE '%@chatroom'"
            ).fetchone()[0]
            groups = conn.execute(
                "SELECT COUNT(*) FROM contact "
                "WHERE username LIKE '%@chatroom'"
            ).fetchone()[0]
        except sqlite3.Error:
            return (0, 0)
    return (int(friends), int(groups))


def _aggregate_msg_stats(decrypted_dir):
    """(msg_first_ts, msg_last_ts, total_count) across every Msg_* table.
    """
    mn = None
    mx = 0
    total = 0
    for db_path in sorted(decrypted_dir.glob("message/message_[0-9]*.db")):
        with sqlite3.connect(db_path) as conn:
            try:
                tables = [
                    r[0] for r in conn.execute(
                        "SELECT name FROM sqlite_master "
                        "WHERE type='table' AND name LIKE 'Msg_%'"
                    )
                ]
            except sqlite3.Error:
                continue
            for tbl in tables:
                try:
                    row = conn.execute(
                        f"SELECT MIN(create_time), MAX(create_time), "
                        f"COUNT(*) FROM [{tbl}]"
                    ).fetchone()
                except sqlite3.Error:
                    continue
                first, last, count = row
                if first is None or count == 0:
                    continue
                mn = first if mn is None else min(mn, first)
                mx = max(mx, last)
                total += count
    return (mn or 0, mx, total)


def _build_account_info(wxid, contact_db,
                        friend_count, group_count,
                        msg_first_ts, msg_last_ts, total_msg_count):
    nickname = ""
    alias = ""
    description = ""
    if contact_db.exists():
        with sqlite3.connect(contact_db) as conn:
            try:
                row = conn.execute(
                    "SELECT nick_name, alias, description FROM contact "
                    "WHERE username = ?",
                    (wxid,),
                ).fetchone()
            except sqlite3.Error:
                row = None
            if row:
                nickname = row[0] or ""
                alias = row[1] or ""
                description = row[2] or ""
    return AccountInfo(
        wxid=wxid,
        nickname=nickname,
        alias=alias,
        description=description,
        msg_first_ts=msg_first_ts,
        msg_last_ts=msg_last_ts,
        friend_count=friend_count,
        group_count=group_count,
        total_msg_count=total_msg_count,
    )
