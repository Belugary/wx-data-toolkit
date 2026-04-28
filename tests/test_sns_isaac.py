"""sns_isaac.py — ISAAC-64 keystream + 朋友圈媒体 XOR 解密的回归测试。

覆盖:
  1. 4 组 WASM-equivalent ground-truth keystream(算法核心正确性)
  2. 边界 size(0 / 1 / 7 / 8 / 2047 / 2048 / 2049, 跨块拼接对不上就死)
  3. roundtrip(加密->解密还原, 跨块大数据)
  4. 种子格式: 空 / 0 / 十六进制 0x 前缀 / 非法字符串(应 stderr 警告并降级)
  5. decrypt_video_in_place 安全语义: seed 错时**不破坏原文件**
"""
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wxdec.sns_isaac import (
    Isaac64,
    SNS_VIDEO_HEAD_SIZE,
    decrypt_image_bytes,
    decrypt_video_in_place,
    detect_image_kind,
    detect_mp4,
)


class TestIsaac64Vectors(unittest.TestCase):
    """ground-truth keystream 来自 WeFlow WASM 实测; 算法跑偏一字节就过不了。"""

    VECTORS = [
        ("0", 16, "9d39247e33776d412af7398005aaa5c7"),
        ("1234567890", 64,
         "2cc68a3743edb02432fd0572d6b8f876dcf26c701e0471af2aaa5a3dae61001c"
         "88d386e73eaa9b7223dfb3218156492de363a90bb5ca76762c56dec25513724e"),
        ("9876543210", 64,
         "b6fd235fa47589bb8a598097cf0e417d06e10e90805a7008af7561ab683d2a61"
         "ea5df27327c5f0e767aadfe60873366d922f44273687df34b4b6a9318c92cb4b"),
        ("14970291265290127678", 32,
         "9bbc5f3928eef2952cd8183503b556c83c29e7131d43fb9ce9d2c20563ee9010"),
    ]

    def test_wasm_equivalent_keystream(self):
        for seed, size, expect in self.VECTORS:
            with self.subTest(seed=seed, size=size):
                got = Isaac64(seed).generate_keystream(size).hex()
                self.assertEqual(got, expect)


class TestKeystreamBoundaries(unittest.TestCase):
    """跨块、零长、非 8 倍数等边界。一块 = 256 个 u64 = 2048 字节。"""

    def test_zero_size(self):
        self.assertEqual(Isaac64("123").generate_keystream(0), b"")

    def test_negative_size(self):
        self.assertEqual(Isaac64("123").generate_keystream(-1), b"")

    def test_unaligned_sizes(self):
        # 任意小尺寸都应该是 prefix-of-aligned-output
        full = Isaac64("123").generate_keystream(64)
        for n in (1, 3, 7, 8, 9, 15, 16, 33):
            with self.subTest(n=n):
                self.assertEqual(Isaac64("123").generate_keystream(n), full[:n])

    def test_block_boundary(self):
        # 跨块: 2047/2048/2049 都应跟 4096 字节流的对应前缀一致
        long = Isaac64("777").generate_keystream(4096)
        for n in (2047, 2048, 2049, 3000):
            with self.subTest(n=n):
                self.assertEqual(Isaac64("777").generate_keystream(n), long[:n])

    def test_video_head_size_one_call(self):
        # 视频解密走 131072 = 64 * 2048 字节, 整数块, 不应踩边界
        ks = Isaac64("42").generate_keystream(SNS_VIDEO_HEAD_SIZE)
        self.assertEqual(len(ks), SNS_VIDEO_HEAD_SIZE)


class TestRoundtrip(unittest.TestCase):
    """encrypt -> decrypt 必须完全还原。能撞出大多数块边界 / 状态机 bug。"""

    def _roundtrip(self, plaintext: bytes, seed: str):
        ks = Isaac64(seed).generate_keystream(len(plaintext))
        ciphertext = bytes(p ^ k for p, k in zip(plaintext, ks))
        recovered = decrypt_image_bytes(ciphertext, seed)
        self.assertEqual(recovered, plaintext)

    def test_short_text(self):
        self._roundtrip(b"Hello, WeChat Moments!", "999")

    def test_jpeg_like(self):
        self._roundtrip(b"\xff\xd8\xff\xe0\x00\x10JFIF" + os.urandom(2000), "0xabc123")

    def test_cross_blocks(self):
        # 跨 5 个块, 每块 2048 字节
        self._roundtrip(os.urandom(10000), "555")

    def test_video_head(self):
        # 撑到完整视频头大小
        self._roundtrip(os.urandom(SNS_VIDEO_HEAD_SIZE), "424242")


class TestSeedFormats(unittest.TestCase):
    def test_empty_and_zero_equivalent(self):
        a = Isaac64("").generate_keystream(16)
        b = Isaac64("0").generate_keystream(16)
        self.assertEqual(a, b)

    def test_hex_prefix(self):
        # int(s, 0) 支持 0x 前缀, "0x499602D2" 应该 = "1234567890"
        a = Isaac64("0x499602D2").generate_keystream(16)
        b = Isaac64("1234567890").generate_keystream(16)
        self.assertEqual(a, b)

    def test_non_numeric_seed_warns_and_degrades(self):
        # 非法字符串应该 stderr 警告 + 降级到 0
        buf = StringIO()
        with redirect_stderr(buf):
            ks = Isaac64("abc").generate_keystream(16)
        self.assertIn("不是合法", buf.getvalue())
        self.assertEqual(ks, Isaac64("0").generate_keystream(16))

    def test_large_seed_truncation(self):
        # > 64 位的种子应被截断到低 64 位
        u64_max = (1 << 64) - 1
        a = Isaac64(str(u64_max + 1)).generate_keystream(16)  # truncates to 0
        b = Isaac64("0").generate_keystream(16)
        self.assertEqual(a, b)


class TestImageDecrypt(unittest.TestCase):
    def test_empty_payload_returns_empty(self):
        self.assertEqual(decrypt_image_bytes(b"", "123"), b"")

    def test_empty_key_returns_payload(self):
        self.assertEqual(decrypt_image_bytes(b"abc", ""), b"abc")

    def test_detect_image_kind(self):
        self.assertEqual(detect_image_kind(b"\xff\xd8\xff\xe0xxxx"), "jpeg")
        self.assertEqual(detect_image_kind(b"\x89PNG\r\n\x1a\nxxx"), "png")
        self.assertIsNone(detect_image_kind(b"random bytes"))


class TestVideoSafety(unittest.TestCase):
    """P1 修复: seed 错误时不应破坏原文件。"""

    def test_wrong_seed_leaves_file_intact(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".mp4") as f:
            payload = b"\x00" * 200000  # 200KB 全零, ftyp 必败
            f.write(payload)
            tmp = Path(f.name)
        try:
            before = tmp.read_bytes()
            ok = decrypt_video_in_place(tmp, "999999")  # seed 错
            after = tmp.read_bytes()
            self.assertFalse(ok)
            self.assertEqual(before, after, "失败时不应回写")
        finally:
            tmp.unlink(missing_ok=True)

    def test_already_plaintext_no_change(self):
        # ftyp 已经是明文: 直接 short-circuit, 不解密、不修改
        with tempfile.NamedTemporaryFile(delete=False, suffix=".mp4") as f:
            payload = b"\x00\x00\x00\x20ftypisom" + b"\x00" * 200
            f.write(payload)
            tmp = Path(f.name)
        try:
            before = tmp.read_bytes()
            ok = decrypt_video_in_place(tmp, "anykey")
            after = tmp.read_bytes()
            self.assertFalse(ok)
            self.assertEqual(before, after)
        finally:
            tmp.unlink(missing_ok=True)

    def test_empty_key_returns_false(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".mp4") as f:
            f.write(b"x" * 100)
            tmp = Path(f.name)
        try:
            self.assertFalse(decrypt_video_in_place(tmp, ""))
            self.assertFalse(decrypt_video_in_place(tmp, "  "))
        finally:
            tmp.unlink(missing_ok=True)


class TestDetectMp4(unittest.TestCase):
    def test_detect_mp4(self):
        self.assertTrue(detect_mp4(b"\x00\x00\x00\x20ftypisom"))
        self.assertFalse(detect_mp4(b"\x00\x00\x00\x20xxxxisom"))
        self.assertFalse(detect_mp4(b"short"))


if __name__ == "__main__":
    unittest.main()
