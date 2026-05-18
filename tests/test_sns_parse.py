"""Unit tests for wxdec.sns_parse.

Coverage:
  - _decode_blob_to_xml: bytes (zstd + raw), already-XML, hex, base64
  - _sanitize_xml: bare & in URLs, raw < > in text fields, ctrl chars
  - parse_moment_xml: type extraction, contentDesc, location attrs,
                      ContentObject link-card vs finder, mediaList
  - iter_moments: full pipeline against synthetic sns.db; type=7 cover
                  filter, ts window filter, user_name filter, missing
                  table tolerance
"""

import base64
import sqlite3
import tempfile
import unittest
from pathlib import Path

import zstandard as zstd

from wxdec import sns_parse
from wxdec.sns_parse import (
    LinkCard,
    MediaItem,
    Moment,
    _decode_blob_to_xml,
    _sanitize_xml,
    iter_moments,
    parse_moment_xml,
)


# Synthetic TimelineObject for tests
def _timeline_xml(create_time=1700000000, content_desc="今天天气真好",
                  poi="成都市",
                  type_code=1, with_link=False, with_finder=False,
                  media=None, is_private=False):
    media_xml = ""
    for m in (media or []):
        media_xml += (f"<media><type>{m[0]}</type>"
                      f"<description>{m[1]}</description>"
                      f"<videoDuration>{m[2]}</videoDuration></media>")
    media_list = f"<mediaList>{media_xml}</mediaList>" if media_xml else ""

    link_xml = ""
    if with_link:
        link_xml = (
            "<title>一篇文章</title>"
            "<contentUrl>https://mp.weixin.qq.com/s/abc</contentUrl>"
            "<description>文章描述</description>"
        )
    finder_xml = ""
    if with_finder:
        finder_xml = (
            "<finderFeed>"
            "<nickname>某视频号</nickname>"
            "<feedType>4</feedType>"
            "<liveId>0</liveId>"
            "<mediaCount>1</mediaCount>"
            "<mediaList><media><mediaType>4</mediaType>"
            "<videoPlayDuration>30</videoPlayDuration></media></mediaList>"
            "</finderFeed>"
        )

    loc_xml = f'<location poiName="{poi}"/>' if poi else ""
    private_xml = "<private>1</private>" if is_private else ""

    return f"""<TimelineObject>
        <createTime>{create_time}</createTime>
        <contentDesc>{content_desc}</contentDesc>
        {private_xml}
        <location {f'poiName="{poi}"' if poi else ''}/>
        <ContentObject>
            <contentStyle>{type_code}</contentStyle>
            {link_xml}
            {finder_xml}
            {media_list}
        </ContentObject>
    </TimelineObject>"""


# ── _decode_blob_to_xml ──────────────────────────────────────────────────────


class TestDecodeBlob(unittest.TestCase):

    def test_none(self):
        self.assertEqual(_decode_blob_to_xml(None), "")

    def test_already_xml_string(self):
        s = "<root>hi</root>"
        self.assertEqual(_decode_blob_to_xml(s), s)

    def test_html_entities_unescaped(self):
        # & in URL is escaped by WeChat sometimes; decoder unescapes.
        self.assertEqual(_decode_blob_to_xml("<x>a&amp;b</x>"), "<x>a&b</x>")

    def test_hex_string(self):
        original = "<root>hello</root>"
        hex_str = original.encode().hex()
        self.assertEqual(_decode_blob_to_xml(hex_str), original)

    def test_base64_string(self):
        original = "<root>moments</root>"
        b64 = base64.b64encode(original.encode()).decode()
        self.assertEqual(_decode_blob_to_xml(b64), original)

    def test_zstd_bytes(self):
        original = b"<root>compressed</root>" * 5
        compressed = zstd.ZstdCompressor().compress(original)
        out = _decode_blob_to_xml(compressed)
        self.assertEqual(out, original.decode())

    def test_raw_bytes_not_zstd(self):
        # Raw UTF-8 bytes without zstd magic → decoded as text
        self.assertEqual(_decode_blob_to_xml(b"<root>raw</root>"),
                         "<root>raw</root>")


# ── _sanitize_xml ────────────────────────────────────────────────────────────


class TestSanitize(unittest.TestCase):

    def test_bare_amp_in_url_escaped(self):
        s = '<a href="https://x.com/path?a=1&b=2">x</a>'
        out = _sanitize_xml(s)
        self.assertIn("&amp;b=2", out)

    def test_existing_entities_preserved(self):
        s = "<x>&amp;&lt;&gt;</x>"
        self.assertEqual(_sanitize_xml(s), s)

    def test_raw_lt_gt_in_text_field_escaped(self):
        s = "<contentDesc>x < y > z</contentDesc>"
        out = _sanitize_xml(s)
        self.assertIn("x &lt; y &gt; z", out)

    def test_control_chars_stripped(self):
        s = "<x>a\x00b\x07c</x>"
        self.assertEqual(_sanitize_xml(s), "<x>abc</x>")

    def test_amp_inside_cdata_preserved(self):
        # Bare `&` outside CDATA must be escaped (XML legality), but `&`
        # inside CDATA is data and MUST pass through untouched. The
        # implementation splits on CDATA blocks to enforce this — guard
        # against a refactor that drops the block-boundary handling.
        s = ('<root>'
             '<a href="http://x?p=1&q=2">x</a>'
             '<note><![CDATA[raw a&b=c <foo> stays]]></note>'
             '</root>')
        out = _sanitize_xml(s)
        # bare & escaped outside CDATA
        self.assertIn("p=1&amp;q=2", out)
        # CDATA content unchanged (& and < not escaped within CDATA)
        self.assertIn("<![CDATA[raw a&b=c <foo> stays]]>", out)


# ── parse_moment_xml ─────────────────────────────────────────────────────────


class TestParseMomentXml(unittest.TestCase):

    def test_basic_text_post(self):
        m = parse_moment_xml(_timeline_xml(), user_name="alice")
        self.assertIsInstance(m, Moment)
        self.assertEqual(m.user_name, "alice")
        self.assertEqual(m.content_desc, "今天天气真好")
        self.assertEqual(m.location, "成都市")
        self.assertEqual(m.created_ts, 1700000000)
        self.assertEqual(m.type, 1)
        self.assertFalse(m.is_private)

    def test_private_flag(self):
        m = parse_moment_xml(_timeline_xml(is_private=True))
        self.assertTrue(m.is_private)

    def test_with_link_card(self):
        m = parse_moment_xml(_timeline_xml(with_link=True))
        self.assertIsInstance(m.link, LinkCard)
        self.assertEqual(m.link.title, "一篇文章")
        self.assertEqual(m.link.url, "https://mp.weixin.qq.com/s/abc")
        self.assertIsNone(m.finder)

    def test_with_finder_suppresses_link(self):
        # When finder is present, link extraction is skipped (URL is a
        # finder deeplink, not a real article).
        m = parse_moment_xml(_timeline_xml(with_link=True, with_finder=True))
        self.assertIsNotNone(m.finder)
        self.assertIsNone(m.link)

    def test_with_media(self):
        m = parse_moment_xml(_timeline_xml(media=[
            (2, "image1.jpg", 0),
            (2, "image2.jpg", 0),
            (6, "video.mp4", 45),
        ]))
        self.assertEqual(len(m.media), 3)
        self.assertEqual(m.media[2].type, 6)
        self.assertEqual(m.media[2].video_duration, 45)

    def test_malformed_xml(self):
        self.assertIsNone(parse_moment_xml("<broken"))

    def test_empty(self):
        self.assertIsNone(parse_moment_xml(""))
        self.assertIsNone(parse_moment_xml("   "))

    def test_location_fallback_poiaddressname(self):
        # When poiName is absent, fall back to poiAddressName.
        xml = """<TimelineObject>
            <createTime>1700000000</createTime>
            <contentDesc>x</contentDesc>
            <location poiAddressName="某某商圈"/>
            <ContentObject><contentStyle>1</contentStyle></ContentObject>
        </TimelineObject>"""
        m = parse_moment_xml(xml)
        self.assertEqual(m.location, "某某商圈")

    def test_location_fallback_city(self):
        # When poiName and poiAddressName are both absent, fall back to city.
        xml = """<TimelineObject>
            <createTime>1700000000</createTime>
            <contentDesc>x</contentDesc>
            <location city="成都"/>
            <ContentObject><contentStyle>1</contentStyle></ContentObject>
        </TimelineObject>"""
        m = parse_moment_xml(xml)
        self.assertEqual(m.location, "成都")

    def test_location_priority_poiname_wins(self):
        # All three present → poiName wins.
        xml = """<TimelineObject>
            <createTime>1700000000</createTime>
            <contentDesc>x</contentDesc>
            <location poiName="venue" poiAddressName="addr" city="city"/>
            <ContentObject><contentStyle>1</contentStyle></ContentObject>
        </TimelineObject>"""
        m = parse_moment_xml(xml)
        self.assertEqual(m.location, "venue")


# ── iter_moments ─────────────────────────────────────────────────────────────


class TestIterMoments(unittest.TestCase):

    def _build_db(self, rows):
        """rows = [(user_name, content_xml_string), ...]"""
        tmp = Path(tempfile.mkdtemp()) / "sns.db"
        with sqlite3.connect(tmp) as conn:
            conn.execute(
                "CREATE TABLE SnsTimeLine "
                "(tid INTEGER PRIMARY KEY, user_name TEXT, content TEXT, "
                " pack_info_buf TEXT)"
            )
            conn.executemany(
                "INSERT INTO SnsTimeLine (user_name, content) VALUES (?, ?)",
                rows,
            )
        return tmp

    def test_missing_db_returns_empty(self):
        out = list(iter_moments("/nonexistent/path/sns.db"))
        self.assertEqual(out, [])

    def test_basic_iteration(self):
        db = self._build_db([
            ("alice", _timeline_xml(create_time=1700000000,
                                    content_desc="post 1")),
            ("alice", _timeline_xml(create_time=1700000100,
                                    content_desc="post 2")),
        ])
        out = list(iter_moments(db))
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0].content_desc, "post 1")

    def test_type_7_cover_filtered_by_default(self):
        db = self._build_db([
            ("alice", _timeline_xml(content_desc="real post", type_code=1)),
            ("alice", _timeline_xml(content_desc="cover image", type_code=7)),
        ])
        out = list(iter_moments(db))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].content_desc, "real post")

    def test_type_7_included_when_requested(self):
        db = self._build_db([
            ("alice", _timeline_xml(content_desc="cover", type_code=7)),
        ])
        out = list(iter_moments(db, include_cover=True))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].type, 7)

    def test_user_name_filter(self):
        db = self._build_db([
            ("alice", _timeline_xml(content_desc="from alice")),
            ("bob", _timeline_xml(content_desc="from bob")),
        ])
        out = list(iter_moments(db, user_name="alice"))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].user_name, "alice")

    def test_ts_window_filter(self):
        db = self._build_db([
            ("alice", _timeline_xml(create_time=1000)),
            ("alice", _timeline_xml(create_time=2000)),
            ("alice", _timeline_xml(create_time=3000)),
        ])
        out = list(iter_moments(db, start_ts=1500, end_ts=2500))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].created_ts, 2000)

    def test_missing_table_tolerated(self):
        tmp = Path(tempfile.mkdtemp()) / "empty_sns.db"
        with sqlite3.connect(tmp) as conn:
            conn.execute("CREATE TABLE unrelated (x INTEGER)")
        self.assertEqual(list(iter_moments(tmp)), [])


if __name__ == "__main__":
    unittest.main()
