"""WeChat Moments (朋友圈 / SNS) DB parser.

Reads `sns/sns.db` after decryption and yields structured Moment records.
Pairs with `sns_isaac.py` (media decryption) — this module handles the
metadata side: post text, location, link cards, video-channel reposts,
media list, privacy flag.

Public API:
    Moment dataclass — one post
    parse_moment_xml(xml_text) -> Moment | None
    iter_moments(sns_db_path, user_name=None,
                 start_ts=None, end_ts=None,
                 include_cover=False) -> Iterator[Moment]

Schema (validated against real sns.db):
  - SnsTimeLine(tid INTEGER PK DESC, user_name TEXT, content TEXT,
                pack_info_buf TEXT)
  - `content` is a TimelineObject XML stored in any of: raw XML, hex
    string, base64 string, or zstd-compressed bytes. Detection is by
    header / character set since the column is declared TEXT.
  - createTime is a unix epoch in UTC (the SNS protocol speaks UTC,
    not WeChat's usual local time).
  - type == 7 is the user's cover/background image, not a real post.

XML quirks (bare `&` in URLs, raw `<` / `>` in text nodes from
2013-2017 era posts, control chars) are pre-sanitized before parsing.
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import sqlite3
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, List, Optional

import zstandard as zstd

from wxdec.msg_parse import FinderFeed, parse_finder_feed

_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/=]+$")

_INVALID_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_CDATA_BLOCK_RE = re.compile(r"<!\[CDATA\[.*?\]\]>", re.DOTALL)
_BARE_AMP_RE = re.compile(r"&(?!(amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);)")
_TEXT_ONLY_NODES = ("content", "title", "description", "nickname",
                    "contentDesc", "appname", "sourceName", "sourcename",
                    "poiName", "displayName", "feeddesc")
_TEXT_NODE_RE = re.compile(
    r"(<(" + "|".join(_TEXT_ONLY_NODES) + r")\b[^>]*>)(.*?)(</\2>)",
    re.DOTALL,
)

_WECHAT_UPGRADE_HOST = "support.weixin.qq.com"


# ── Dataclasses ──────────────────────────────────────────────────────────────


@dataclass
class MediaItem:
    """One image / video within a Moment.

    `type` codes from the TimelineObject schema:
      - 2 = image
      - 6 = video
      - 7 = album cover image (filtered out at Moment level via type==7)
    `video_duration` is in seconds, populated only for video items.
    """
    type: int
    description: str = ""
    video_duration: int = 0


@dataclass
class LinkCard:
    """Embedded link share inside a Moment (公众号 article / web URL)."""
    title: str
    url: str
    description: str = ""


@dataclass
class Moment:
    """One Moment (朋友圈) post.

    `created_ts` is the UTC unix epoch from <createTime>. Caller applies
    any local-time day-window filter.

    `type` is the ContentObject contentStyle / type code. Type=7 (cover/
    background image) is filtered by iter_moments() unless include_cover
    is True; pure-text / image-only posts get type=1 / 2 etc.

    `is_private` is True when <private>=1 (post visible only to self).
    """
    created_ts: int
    user_name: str
    type: int
    content_desc: str = ""
    location: str = ""
    is_private: bool = False
    finder: Optional[FinderFeed] = None
    link: Optional[LinkCard] = None
    media: List[MediaItem] = field(default_factory=list)


# ── DB iteration ─────────────────────────────────────────────────────────────


def iter_moments(sns_db_path, user_name=None,
                 start_ts=None, end_ts=None,
                 include_cover=False):
    """Yield Moments from `sns/sns.db`.

    `user_name` — restrict to a single author wxid. None reads all
    posters (typically self + friends; self-only is the common case).
    `start_ts`, `end_ts` — half-open UTC epoch filter applied AFTER
    parsing each row (the createTime field is in the XML, not the SQL
    columns; we can't push the filter into SQLite).
    `include_cover` — when False (default) drops type=7 cover-image
    posts; they're per-user album backgrounds, not real posts.

    Returns an empty iterator if sns.db is missing or has no
    SnsTimeLine table (e.g. user hasn't synced Moments yet).
    """
    sns_db_path = Path(sns_db_path)
    if not sns_db_path.exists():
        return
    with sqlite3.connect(sns_db_path) as conn:
        if user_name is None:
            sql = "SELECT user_name, content FROM SnsTimeLine"
            params = ()
        else:
            sql = "SELECT user_name, content FROM SnsTimeLine WHERE user_name = ?"
            params = (user_name,)
        try:
            rows = conn.execute(sql, params).fetchall()
        except sqlite3.OperationalError:
            return

    for db_user, raw_content in rows:
        xml_text = _decode_blob_to_xml(raw_content)
        moment = parse_moment_xml(xml_text, user_name=db_user)
        if moment is None:
            continue
        if not include_cover and moment.type == 7:
            continue
        if start_ts is not None and moment.created_ts < start_ts:
            continue
        if end_ts is not None and moment.created_ts >= end_ts:
            continue
        yield moment


# ── XML decoding (content column has 4 possible encodings) ───────────────────


def _decode_blob_to_xml(value):
    """Decode SnsTimeLine.content to UTF-8 XML.

    Detection order: bytes (zstd-or-raw) → already-XML → hex → base64.
    """
    if value is None:
        return ""

    if isinstance(value, bytes):
        raw = _try_zstd_decompress(value)
        return html.unescape(raw.decode("utf-8", errors="ignore").strip())

    text = str(value).strip()
    if not text:
        return ""
    if text.lstrip().startswith("<"):
        return html.unescape(text)

    compact = "".join(text.split())
    if len(compact) >= 16 and len(compact) % 2 == 0 and _HEX_RE.match(compact):
        try:
            return _decode_blob_to_xml(bytes.fromhex(compact))
        except ValueError:
            pass
    if len(compact) >= 24 and len(compact) % 4 == 0 and _BASE64_RE.match(compact):
        try:
            return _decode_blob_to_xml(base64.b64decode(compact, validate=True))
        except (ValueError, binascii.Error):
            pass
    return html.unescape(text)


def _try_zstd_decompress(raw):
    if not raw.startswith(_ZSTD_MAGIC):
        return raw
    try:
        return zstd.ZstdDecompressor().decompress(raw)
    except Exception:
        return raw


def _sanitize_xml(xml_text):
    """Fix WeChat's pseudo-XML: bare & in URLs, raw < > in user-text fields,
    and stray control characters that ElementTree refuses."""
    s = _INVALID_CTRL_RE.sub("", xml_text)
    parts = []
    last = 0
    for m in _CDATA_BLOCK_RE.finditer(s):
        head = s[last:m.start()]
        parts.append(_BARE_AMP_RE.sub("&amp;", head))
        parts.append(m.group(0))
        last = m.end()
    parts.append(_BARE_AMP_RE.sub("&amp;", s[last:]))
    out = "".join(parts)

    def _esc(m):
        open_tag, _, text, close_tag = m.group(1), m.group(2), m.group(3), m.group(4)
        return open_tag + text.replace("<", "&lt;").replace(">", "&gt;") + close_tag

    return _TEXT_NODE_RE.sub(_esc, out)


# ── XML field extraction ─────────────────────────────────────────────────────


def parse_moment_xml(xml_text, user_name=""):
    """Parse a TimelineObject XML into a Moment, or None on malformed XML.

    Returns None for truncated rows (sns.db can contain partial rows
    from interrupted syncs) — caller drops silently.

    `user_name` is the author wxid from the DB row (SnsTimeLine.user_name);
    threaded through since it's not always present inside the XML.
    """
    if not xml_text or not xml_text.strip():
        return None
    try:
        root = ET.fromstring(_sanitize_xml(xml_text))
    except ET.ParseError:
        return None

    tl = root if root.tag == "TimelineObject" else root.find(".//TimelineObject")
    if tl is None:
        return None

    moment = Moment(
        created_ts=_safe_int(_findtext(tl, "createTime")),
        user_name=user_name or _findtext(tl, "username"),
        type=_safe_int(_findtext(tl, ".//ContentObject/contentStyle")
                       or _findtext(tl, ".//ContentObject/type")),
        content_desc=_findtext(tl, "contentDesc"),
        is_private=_findtext(tl, ".//private") == "1",
    )

    loc_el = tl.find(".//location")
    if loc_el is not None:
        attrs = loc_el.attrib
        moment.location = (
            (attrs.get("poiName") or "").strip()
            or (attrs.get("poiAddressName") or "").strip()
            or (attrs.get("city") or "").strip()
        )

    co_el = tl.find(".//ContentObject")
    finder_el = co_el.find("finderFeed") if co_el is not None else None
    moment.finder = parse_finder_feed(finder_el)

    # Link share: 43% of real Moments are 公众号 article / web shares with
    # title + contentUrl + description on the ContentObject. Skip when:
    #   (a) finder is present (URL is then a finder deeplink, not an article)
    #   (b) URL is the WeChat upgrade-prompt placeholder (~7% of URLs —
    #       typically Sight short-video posts on older app versions where
    #       the link can't render and the title is the meaningless 'Sight'
    #       / '微信小视频').
    if co_el is not None and moment.finder is None:
        link_title = _findtext(co_el, "title")
        link_url = _findtext(co_el, "contentUrl")
        link_desc = _findtext(co_el, "description")
        if (link_title and link_url
                and _WECHAT_UPGRADE_HOST not in link_url):
            moment.link = LinkCard(
                title=link_title,
                url=link_url,
                description=link_desc,
            )

    for m_el in tl.findall(".//mediaList/media"):
        moment.media.append(MediaItem(
            type=_safe_int(_findtext(m_el, "type")),
            description=_findtext(m_el, "description"),
            video_duration=_safe_int(_findtext(m_el, "videoDuration")),
        ))

    return moment


def _findtext(elem, path):
    if elem is None:
        return ""
    el = elem.find(path)
    if el is None or el.text is None:
        return ""
    return el.text.strip()


def _safe_int(v):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return 0
