"""decrypt_media_for_posts 过滤条件回归。

历史 bug:type∈{1,2} 白名单漏了 type=0 但 attrs 完整的公众号封面图
(mmbiz.qpic.cn,与 type=2 加密机制完全相同)。

新语义:走解密路径的充分必要条件 = urlAttrs 同时含非零 key + 非空 token。
md5 缺失允许(公众号封面常见此情况),内部按 key 兜底命名。
type 字段不再是过滤条件;视频(type=6)单独走 _download_video_one。
"""
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wxdec.cli import decrypt_sns


def _post_with_media(*media_items, video_enc_key: str = ""):
    return {"tid": -1, "media": list(media_items), "videoEncKey": video_enc_key}


def _media(mtype, *, key="abc", token="tok", md5="m1", url="https://x"):
    return {
        "type": mtype,
        "url": url,
        "urlAttrs": {"key": key, "token": token, "md5": md5},
    }


class TestMediaFilter(unittest.TestCase):

    def setUp(self):
        # mock 实际下载,只验证哪些 media 被尝试
        self.attempts = []

        def fake_download(url, token, key, md5, out_dir, **kw):
            self.attempts.append({"url": url, "key": key, "md5": md5})
            return None, "skip-test"

        self._patcher = patch.object(
            decrypt_sns, "_download_and_decrypt_one", side_effect=fake_download
        )
        self._patcher.start()

    def tearDown(self):
        self._patcher.stop()

    def test_type_2_with_attrs_attempted(self):
        """普通图片 type=2 + 完整 attrs → 进流程。"""
        decrypt_sns.decrypt_media_for_posts(
            [_post_with_media(_media(2))], "/tmp/x"
        )
        self.assertEqual(len(self.attempts), 1)

    def test_type_0_mmbiz_cover_attempted(self):
        """关键回归:type=0 但 attrs 完整(公众号封面)也要进流程。"""
        decrypt_sns.decrypt_media_for_posts(
            [_post_with_media(_media(0, url="https://mmbiz.qpic.cn/x"))], "/tmp/x"
        )
        self.assertEqual(len(self.attempts), 1)

    def test_type_6_video_routes_to_video_downloader(self):
        """视频走 _download_video_one, 不走图片解密路径。"""
        with patch.object(decrypt_sns, "_download_video_one",
                          return_value=(None, "skip-test")) as mock_v:
            decrypt_sns.decrypt_media_for_posts(
                [_post_with_media({
                    "type": 6,
                    "url": "http://szzjwxsns.video.qq.com/snsvideodownload",
                    "urlAttrs": {"videomd5": "abc123", "md5": "ignored", "key": "0"},
                }, video_enc_key="999")], "/tmp/x"
            )
            self.assertEqual(self.attempts, [])  # 图片下载器不应被调用
            self.assertEqual(mock_v.call_count, 1)
            # _download_video_one(url, token, key, vmd5, out_dir) - vmd5 在 args[3]
            self.assertEqual(mock_v.call_args.args[3], "abc123")

    def test_type_6_video_missing_videomd5_falls_back_to_md5(self):
        """没 videomd5 时退到 md5 命名。"""
        with patch.object(decrypt_sns, "_download_video_one",
                          return_value=(None, "skip-test")) as mock_v:
            decrypt_sns.decrypt_media_for_posts(
                [_post_with_media({
                    "type": 6,
                    "url": "http://x",
                    "urlAttrs": {"md5": "fallback_md5"},
                }, video_enc_key="999")], "/tmp/x"
            )
            self.assertEqual(mock_v.call_count, 1)
            self.assertEqual(mock_v.call_args.args[3], "fallback_md5")

    def test_type_0_finder_video_no_attrs_skipped(self):
        """视频号视频引用 type=0, attrs={} → 跳过, 留给 video task。"""
        decrypt_sns.decrypt_media_for_posts(
            [_post_with_media({
                "type": 0,
                "url": "http://wxapp.tc.qq.com/stodownload?encfilekey=X",
                "urlAttrs": {},
            })], "/tmp/x"
        )
        self.assertEqual(self.attempts, [])

    def test_zero_key_skipped(self):
        """attrs.key='0' 的(小红书外链 thumb 等)→ 跳过。"""
        decrypt_sns.decrypt_media_for_posts(
            [_post_with_media(_media(2, key="0"))], "/tmp/x"
        )
        self.assertEqual(self.attempts, [])

    def test_missing_md5_still_attempted(self):
        """md5 缺失(公众号封面常见)→ 进流程, 内部按 key 命名兜底。"""
        decrypt_sns.decrypt_media_for_posts(
            [_post_with_media(_media(2, md5=""))], "/tmp/x"
        )
        self.assertEqual(len(self.attempts), 1)

    def test_missing_token_skipped(self):
        decrypt_sns.decrypt_media_for_posts(
            [_post_with_media(_media(2, token=""))], "/tmp/x"
        )
        self.assertEqual(self.attempts, [])

    def test_mixed_post_filters_correctly(self):
        """同一帖子里有合规 + 不合规 media,只下载合规的。"""
        decrypt_sns.decrypt_media_for_posts(
            [_post_with_media(
                _media(2),                                       # ✓
                _media(0, url="https://mmbiz.qpic.cn/c"),         # ✓ 公众号封面
                {"type": 6, "urlAttrs": {}},                     # ✗ 视频 attrs 空
                _media(2, key="0"),                              # ✗ 占位 key
            )],
            "/tmp/x",
        )
        self.assertEqual(len(self.attempts), 2)


if __name__ == "__main__":
    unittest.main()
