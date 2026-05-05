"""decrypt_sns video path — XML parsing + URL fixup + post-level seed plumbing.

Covers (no network):
  - parse_timeline_xml extracts <enc key="..."/> as `videoEncKey`
  - missing <enc> -> empty videoEncKey
  - _fix_sns_url(is_video=True): token / idx must come first; /150 not rewritten
  - _fix_sns_url(is_video=False): regression on existing image behaviour
  - query_sns plumbs videoEncKey through to post dicts (in-memory sqlite fixture)
"""
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wxdec.cli.decrypt_sns import (
    _fix_sns_url,
    parse_timeline_xml,
    query_interactions,
    query_sns,
)


# Synthetic XML — no real PII. Mirrors the WeChat 4.x SnsTimeLine.content shape:
# <enc key="..."/> sits inside ContentObject, alongside mediaList.
_XML_VIDEO_POST = """<TimelineObject>
  <id>1234567890</id>
  <username>fake_user_xyz</username>
  <createTime>1700000000</createTime>
  <contentDesc>video post for tests</contentDesc>
  <location latitude="31.230000" longitude="121.470000" city="Shanghai" poiName="Test POI" poiAddressName="123 Fake Rd" country="CN" poiScale="1" />
  <ContentObject>
    <contentStyle>15</contentStyle>
    <mediaList>
      <media>
        <id>9999</id>
        <type>6</type>
        <sub_type>0</sub_type>
        <description>video alt text</description>
        <url type="6" md5="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" videomd5="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" key="0">https://cdn.example/video</url>
        <thumb type="6" md5="cccccccccccccccccccccccccccccccc">https://cdn.example/thumb</thumb>
        <size width="1080" height="1920" totalSize="8388608" />
        <videoDuration>15.7</videoDuration>
        <enc key="2105122989" />
      </media>
    </mediaList>
    <enc key="2105122989" type="1"/>
  </ContentObject>
</TimelineObject>
"""

_XML_IMAGE_POST = """<TimelineObject>
  <id>2222222222</id>
  <username>fake_user_xyz</username>
  <createTime>1700000100</createTime>
  <contentDesc>image post for tests</contentDesc>
  <ContentObject>
    <contentStyle>1</contentStyle>
    <mediaList>
      <media>
        <id>1111</id>
        <type>2</type>
        <url type="2" md5="dddddddddddddddddddddddddddddddd" key="14970291265290127678">https://cdn.example/img</url>
      </media>
    </mediaList>
  </ContentObject>
</TimelineObject>
"""

_XML_PRIVATE_POST = """<TimelineObject>
  <id>3333333333</id>
  <username>fake_user_xyz</username>
  <createTime>1700000200</createTime>
  <contentDesc>secret</contentDesc>
  <private>1</private>
  <ContentObject>
    <contentStyle>1</contentStyle>
    <mediaList/>
  </ContentObject>
</TimelineObject>
"""

_XML_FINDER_POST = """<TimelineObject>
  <id>4444444444</id>
  <username>fake_user_xyz</username>
  <createTime>1700000300</createTime>
  <contentDesc>shared a video</contentDesc>
  <ContentObject>
    <contentStyle>15</contentStyle>
    <mediaList/>
    <finderFeed>
      <objectId>obj_abc123</objectId>
      <objectNonceId>nonce_xyz</objectNonceId>
      <feedType>4</feedType>
      <username>finder_creator_xyz</username>
      <nickname>Creator Name</nickname>
      <avatar>https://avatar/x</avatar>
      <desc>video description</desc>
      <liveId>0</liveId>
      <mediaCount>1</mediaCount>
      <mediaList>
        <media>
          <mediaType>4</mediaType>
          <url>https://finder.cdn/video</url>
          <thumbUrl>https://finder.cdn/thumb</thumbUrl>
          <coverUrl>https://finder.cdn/cover</coverUrl>
          <fullCoverUrl>https://finder.cdn/cover_full</fullCoverUrl>
          <width>720</width>
          <height>1280</height>
          <videoPlayDuration>684</videoPlayDuration>
        </media>
      </mediaList>
    </finderFeed>
  </ContentObject>
</TimelineObject>
"""


class TestVideoEncKeyExtraction(unittest.TestCase):
    def test_video_post_extracts_enc_key(self):
        out = parse_timeline_xml(_XML_VIDEO_POST)
        self.assertEqual(out["videoEncKey"], "2105122989")
        self.assertEqual(out["type"], 15)
        self.assertEqual(len(out["media"]), 1)
        self.assertEqual(out["media"][0]["type"], 6)
        # url.key on the media itself remains "0" — parser must NOT confuse the two
        self.assertEqual(out["media"][0]["urlAttrs"]["key"], "0")
        self.assertEqual(
            out["media"][0]["urlAttrs"]["videomd5"],
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )

    def test_image_post_has_empty_video_enc_key(self):
        out = parse_timeline_xml(_XML_IMAGE_POST)
        self.assertEqual(out["videoEncKey"], "")
        # image url.key still flows through urlAttrs unchanged
        self.assertEqual(
            out["media"][0]["urlAttrs"]["key"],
            "14970291265290127678",
        )

    def test_empty_xml(self):
        out = parse_timeline_xml("")
        self.assertEqual(out["videoEncKey"], "")

    def test_enc_with_whitespace(self):
        # Leading/trailing whitespace in the attribute should be stripped
        xml = _XML_VIDEO_POST.replace('key="2105122989"', 'key=" 2105122989 "')
        out = parse_timeline_xml(xml)
        self.assertEqual(out["videoEncKey"], "2105122989")


class TestFixSnsUrlVideo(unittest.TestCase):
    def test_video_token_goes_first(self):
        # Video URLs put token=... &idx=1 right after `?`, BEFORE existing params.
        url = "https://example.com/video.mp4?param=foo"
        out = _fix_sns_url(url, "abc123", is_video=True)
        self.assertEqual(out, "https://example.com/video.mp4?token=abc123&idx=1&param=foo")

    def test_video_no_existing_query(self):
        url = "https://example.com/video.mp4"
        out = _fix_sns_url(url, "abc123", is_video=True)
        self.assertEqual(out, "https://example.com/video.mp4?token=abc123&idx=1")

    def test_video_does_not_rewrite_150(self):
        # /150 rewrite is image-specific; video paths must be preserved verbatim.
        url = "https://example.com/video/150"
        out = _fix_sns_url(url, "abc123", is_video=True)
        self.assertIn("/video/150", out)
        self.assertNotIn("/video/0", out)

    def test_video_keeps_existing_token(self):
        url = "https://example.com/video.mp4?token=preset"
        out = _fix_sns_url(url, "abc123", is_video=True)
        self.assertEqual(out, "https://example.com/video.mp4?token=preset")

    def test_image_behavior_unchanged(self):
        # Regression: image path still rewrites /150 -> /0 and appends token at the tail.
        url = "https://example.com/image/150"
        out = _fix_sns_url(url, "abc123")
        self.assertEqual(out, "https://example.com/image/0?token=abc123&idx=1")

    def test_http_to_https(self):
        out = _fix_sns_url("http://example.com/video.mp4", "abc123", is_video=True)
        self.assertTrue(out.startswith("https://"))


def _make_sns_db(xmls: list[tuple[int, str, str]],
                 interactions: list[tuple] = None) -> str:
    """Build a temp sqlite with SnsTimeLine + SnsMessage_tmp3 schema.

    interactions rows: (type, feed_id, from_username, from_nickname, content,
                        create_time, comment_id, comment64_id)
    """
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "CREATE TABLE SnsTimeLine (tid INTEGER PRIMARY KEY, user_name TEXT, content TEXT)"
        )
        conn.execute(
            "CREATE TABLE SnsMessage_tmp3 ("
            "  local_id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  type INTEGER, feed_id INTEGER,"
            "  from_username TEXT, from_nickname TEXT,"
            "  to_username TEXT, content TEXT,"
            "  create_time INTEGER, comment_id INTEGER, comment64_id INTEGER,"
            "  del_status INTEGER DEFAULT 0)"
        )
        conn.executemany(
            "INSERT INTO SnsTimeLine (tid, user_name, content) VALUES (?, ?, ?)",
            xmls,
        )
        if interactions:
            conn.executemany(
                "INSERT INTO SnsMessage_tmp3 "
                "(type, feed_id, from_username, from_nickname, content, "
                " create_time, comment_id, comment64_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                interactions,
            )
        conn.commit()
    finally:
        conn.close()
    return path


class TestQuerySnsVideoEncKey(unittest.TestCase):
    """End-to-end (no network): SnsTimeLine row -> parsed post dict carries videoEncKey."""

    def test_video_post_carries_enc_key(self):
        db_path = _make_sns_db([
            (1, "fake_user_xyz", _XML_VIDEO_POST),
            (2, "fake_user_xyz", _XML_IMAGE_POST),
        ])
        try:
            posts = query_sns(
                db_path, user="fake_user_xyz",
                start_ts=0, end_ts=0, include_cover=False, limit=None,
            )
            self.assertEqual(len(posts), 2)
            by_tid = {p["tid"]: p for p in posts}
            self.assertEqual(by_tid[1]["videoEncKey"], "2105122989")
            self.assertEqual(by_tid[2]["videoEncKey"], "")
        finally:
            Path(db_path).unlink(missing_ok=True)


class TestLocationCapture(unittest.TestCase):
    """location is XML attributes (not children); ensure all variants captured."""

    def test_full_location_attributes(self):
        out = parse_timeline_xml(_XML_VIDEO_POST)
        self.assertEqual(out["location"], "Test POI")  # poiName preferred
        detail = out["locationDetail"]
        self.assertEqual(detail["poiName"], "Test POI")
        self.assertEqual(detail["city"], "Shanghai")
        self.assertEqual(detail["country"], "CN")
        self.assertEqual(detail["latitude"], "31.230000")
        self.assertEqual(detail["longitude"], "121.470000")
        self.assertEqual(detail["poiAddressName"], "123 Fake Rd")

    def test_location_missing(self):
        out = parse_timeline_xml(_XML_IMAGE_POST)
        self.assertEqual(out["location"], "")
        self.assertEqual(out["locationDetail"], {})

    def test_location_zero_values_filtered(self):
        # 经纬度是 0/0.000000 应该被 strip 掉, 不算"有位置"
        xml = _XML_IMAGE_POST.replace(
            "<contentStyle>1</contentStyle>",
            '<contentStyle>1</contentStyle>\n<location latitude="0.000000" longitude="0" city="" />'
        )
        out = parse_timeline_xml(xml)
        self.assertEqual(out["locationDetail"], {})

    def test_location_falls_back_to_city(self):
        # 没 poiName 但有 city: location 字段应该退化到 city
        xml = _XML_IMAGE_POST.replace(
            "<ContentObject>",
            '<location latitude="31.230000" longitude="121.470000" city="Shanghai" />\n<ContentObject>'
        )
        out = parse_timeline_xml(xml)
        self.assertEqual(out["location"], "Shanghai")
        self.assertEqual(out["locationDetail"]["city"], "Shanghai")
        self.assertNotIn("poiName", out["locationDetail"])


class TestMediaMetadataCapture(unittest.TestCase):
    """size / videoDuration / description 全部抓取。"""

    def test_video_media_metadata(self):
        out = parse_timeline_xml(_XML_VIDEO_POST)
        m = out["media"][0]
        self.assertEqual(m["description"], "video alt text")
        self.assertEqual(m["subType"], "0")
        self.assertEqual(m["videoDuration"], "15.7")
        self.assertEqual(m["size"]["width"], "1080")
        self.assertEqual(m["size"]["height"], "1920")
        self.assertEqual(m["size"]["totalSize"], "8388608")

    def test_image_media_metadata_missing_optional(self):
        out = parse_timeline_xml(_XML_IMAGE_POST)
        m = out["media"][0]
        # 字段存在但默认空, 不会 KeyError
        self.assertEqual(m["videoDuration"], "")
        self.assertEqual(m["description"], "")
        self.assertEqual(m["size"], {})


class TestQueryInteractions(unittest.TestCase):
    """SnsMessage_tmp3 -> {feed_id: {likes, comments}}"""

    def test_likes_and_comments_separated_by_type(self):
        # type=1 like, type=2 comment
        interactions = [
            (1, 100, "wxid_alice", "Alice", "", 1700000010, 1, 0),
            (2, 100, "wxid_bob", "Bob", "nice!", 1700000020, 2, 0),
            (1, 100, "wxid_carol", "Carol", "", 1700000030, 3, 0),
            (2, 200, "wxid_dave", "Dave", "lol", 1700000050, 4, 0),
        ]
        db = _make_sns_db([], interactions)
        try:
            ix = query_interactions(db)
            self.assertEqual(set(ix.keys()), {100, 200})
            self.assertEqual(len(ix[100]["likes"]), 2)
            self.assertEqual(len(ix[100]["comments"]), 1)
            self.assertEqual(ix[100]["comments"][0]["content"], "nice!")
            self.assertEqual(ix[100]["comments"][0]["fromUsername"], "wxid_bob")
            self.assertEqual(ix[100]["likes"][0]["fromUsername"], "wxid_alice")
            self.assertIn("createTimeIso", ix[100]["likes"][0])
        finally:
            Path(db).unlink(missing_ok=True)

    def test_filter_by_post_tids(self):
        interactions = [
            (1, 100, "wxid_a", "A", "", 1, 1, 0),
            (1, 200, "wxid_b", "B", "", 2, 2, 0),
        ]
        db = _make_sns_db([], interactions)
        try:
            ix = query_interactions(db, post_tids=[100])
            self.assertEqual(set(ix.keys()), {100})
        finally:
            Path(db).unlink(missing_ok=True)

    def test_soft_deleted_interactions_filtered(self):
        # del_status != 0 = 对方撤回, 微信本地不真删, 我们过滤掉
        interactions = [
            (1, 100, "wxid_alive", "Alive", "", 1, 1, 0, 0),  # 保留
            (2, 100, "wxid_recall", "Recalled", "撤回的评论", 2, 2, 0, 1),  # 过滤
            (1, 100, "wxid_alsoalive", "AlsoAlive", "", 3, 3, 0, 0),  # 保留
        ]
        # _make_sns_db 当前签名只填 8 列, 这里直接手写包含 del_status 的插入
        import sqlite3, tempfile
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        c = sqlite3.connect(path)
        try:
            c.execute(
                "CREATE TABLE SnsMessage_tmp3 ("
                "  local_id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "  type INTEGER, feed_id INTEGER,"
                "  from_username TEXT, from_nickname TEXT,"
                "  content TEXT, create_time INTEGER,"
                "  comment_id INTEGER, comment64_id INTEGER,"
                "  del_status INTEGER)"
            )
            c.executemany(
                "INSERT INTO SnsMessage_tmp3 (type, feed_id, from_username, "
                "from_nickname, content, create_time, comment_id, comment64_id, "
                "del_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                interactions,
            )
            c.commit()
        finally:
            c.close()
        try:
            ix = query_interactions(path)
            self.assertEqual(len(ix[100]["likes"]), 2)  # 软删的 comment 不算
            self.assertEqual(len(ix[100]["comments"]), 0)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_missing_table_returns_empty(self):
        # 老版本 sns.db 可能没 SnsMessage_tmp3
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE SnsTimeLine (tid INTEGER, user_name TEXT, content TEXT)")
        conn.commit()
        conn.close()
        try:
            self.assertEqual(query_interactions(path), {})
        finally:
            Path(path).unlink(missing_ok=True)


class TestQuerySnsWithInteractions(unittest.TestCase):
    """query_sns 把 likes/comments 注入到 post dict。"""

    def test_with_interactions_false_skips_query(self):
        # `with_interactions=False` 应该完全跳过 SnsMessage_tmp3 查询;
        # 即便 likes/comments 在 db 里存在, post dict 也只看到空数组
        db = _make_sns_db(
            [(1, "fake_user_xyz", _XML_IMAGE_POST)],
            interactions=[(1, 1, "wxid_a", "A", "", 1, 1, 0)],
        )
        try:
            posts = query_sns(db, user="fake_user_xyz",
                              start_ts=0, end_ts=0, include_cover=False,
                              limit=None, with_interactions=False)
            self.assertEqual(len(posts), 1)
            self.assertEqual(posts[0]["likes"], [])
            self.assertEqual(posts[0]["comments"], [])
        finally:
            Path(db).unlink(missing_ok=True)

    def test_post_carries_likes_and_comments(self):
        db = _make_sns_db(
            [(1, "fake_user_xyz", _XML_VIDEO_POST),
             (2, "fake_user_xyz", _XML_IMAGE_POST)],
            interactions=[
                (1, 1, "wxid_a", "Alice", "", 1700000010, 1, 0),
                (2, 1, "wxid_b", "Bob", "great", 1700000020, 2, 0),
                # tid=2 没有任何互动 (检查空数组 default)
            ],
        )
        try:
            posts = query_sns(db, user="fake_user_xyz",
                              start_ts=0, end_ts=0, include_cover=False, limit=None)
            by_tid = {p["tid"]: p for p in posts}
            self.assertEqual(len(by_tid[1]["likes"]), 1)
            self.assertEqual(len(by_tid[1]["comments"]), 1)
            self.assertEqual(by_tid[1]["comments"][0]["content"], "great")
            self.assertEqual(by_tid[2]["likes"], [])
            self.assertEqual(by_tid[2]["comments"], [])
        finally:
            Path(db).unlink(missing_ok=True)


class TestPrivateAndFinder(unittest.TestCase):
    """isPrivate boolean + finderFeed (视频号转发) 字段。"""

    def test_private_post(self):
        out = parse_timeline_xml(_XML_PRIVATE_POST)
        self.assertTrue(out["isPrivate"])
        self.assertEqual(out["finderFeed"], {})

    def test_public_post_default(self):
        out = parse_timeline_xml(_XML_IMAGE_POST)
        self.assertFalse(out["isPrivate"])

    def test_finder_feed_full_extraction(self):
        out = parse_timeline_xml(_XML_FINDER_POST)
        ff = out["finderFeed"]
        self.assertEqual(ff["objectId"], "obj_abc123")
        self.assertEqual(ff["username"], "finder_creator_xyz")
        self.assertEqual(ff["nickname"], "Creator Name")
        self.assertEqual(ff["desc"], "video description")
        self.assertEqual(ff["feedType"], 4)
        self.assertEqual(ff["mediaCount"], 1)
        self.assertEqual(len(ff["media"]), 1)
        m = ff["media"][0]
        self.assertEqual(m["mediaType"], 4)
        self.assertEqual(m["url"], "https://finder.cdn/video")
        self.assertEqual(m["coverUrl"], "https://finder.cdn/cover")
        self.assertEqual(m["fullCoverUrl"], "https://finder.cdn/cover_full")
        self.assertEqual(m["videoPlayDuration"], 684)
        self.assertEqual(m["width"], 720)

    def test_no_finder_feed_returns_empty_dict(self):
        out = parse_timeline_xml(_XML_VIDEO_POST)
        self.assertEqual(out["finderFeed"], {})

    def test_query_sns_propagates_new_fields(self):
        db = _make_sns_db([
            (1, "fake_user_xyz", _XML_PRIVATE_POST),
            (2, "fake_user_xyz", _XML_FINDER_POST),
            (3, "fake_user_xyz", _XML_IMAGE_POST),
        ])
        try:
            posts = query_sns(db, user="fake_user_xyz",
                              start_ts=0, end_ts=0, include_cover=False, limit=None)
            by_tid = {p["tid"]: p for p in posts}
            self.assertTrue(by_tid[1]["isPrivate"])
            self.assertEqual(by_tid[1]["finderFeed"], {})
            self.assertFalse(by_tid[2]["isPrivate"])
            self.assertEqual(by_tid[2]["finderFeed"]["objectId"], "obj_abc123")
            self.assertFalse(by_tid[3]["isPrivate"])
            self.assertEqual(by_tid[3]["finderFeed"], {})
        finally:
            Path(db).unlink(missing_ok=True)


class TestEarlyEraXmlRescue(unittest.TestCase):
    """老版本 (2013-2017) 微信在 contentDesc / title 里允许 raw < > 字符。

    形如 <title>[xx]<杞菊雪梨饮></title> 或 <content>呸!<o>_<o</content>。
    sanitize 必须把这些 text-only 节点内的 raw < > escape 掉, 否则 ET 把
    <杞菊雪梨饮> 当成未闭合标签炸。
    """

    def test_title_with_raw_brackets_parses(self):
        # 老版本微信用户在 title 写过带尖括号的字面文本 (书名号 / 颜文字), 没转义
        xml = (
            "<TimelineObject><id>1</id><username>x</username>"
            "<createTime>1400000000</createTime>"
            "<ContentObject>"
            "<contentStyle>3</contentStyle>"
            "<title>book review: <Title With Brackets></title>"
            "<contentUrl>https://x</contentUrl>"
            "<mediaList/>"
            "</ContentObject></TimelineObject>"
        )
        out = parse_timeline_xml(xml)
        self.assertNotIn("_parseError", out)
        self.assertIn("Title With Brackets", out["title"])
        self.assertEqual(out["createTime"], 1400000000)

    def test_content_with_emoticon_brackets(self):
        # 颜文字在 contentDesc 里也常见
        xml = (
            "<TimelineObject><id>2</id><username>x</username>"
            "<createTime>1400000100</createTime>"
            "<contentDesc>hi <o>_<o smile</contentDesc>"
            "<ContentObject><contentStyle>1</contentStyle><mediaList/></ContentObject>"
            "</TimelineObject>"
        )
        out = parse_timeline_xml(xml)
        self.assertNotIn("_parseError", out)
        self.assertEqual(out["contentDesc"], "hi <o>_<o smile")

    def test_irreparable_xml_returns_parse_error(self):
        # sanitize 也救不回来的: out 保留默认空字段 + _parseError 标记
        broken = "<not-closed-root><createTime>1400000200</createTime>"
        out = parse_timeline_xml(broken)
        self.assertIn("_parseError", out)
        # 默认值不变 (没有自动 regex 抢救)
        self.assertEqual(out["createTime"], 0)
        self.assertEqual(out["contentDesc"], "")


if __name__ == "__main__":
    unittest.main()
