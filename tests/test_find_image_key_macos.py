"""单元测试：find_image_key_macos 派生算法 + 端到端 smoke。

不依赖真实微信数据；用 tempdir + 合成密文构造测试。
"""
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from Crypto.Cipher import AES

from wxdec import find_image_key_macos as fkm


class NormalizeWxidTests(unittest.TestCase):
    def test_wxid_with_extra_segments_keeps_only_first(self):
        # wxid_<seg> 形式只保留第一段下划线之内的内容
        self.assertEqual(fkm.normalize_wxid("wxid_abc123_extra_more"), "wxid_abc123")

    def test_wxid_no_extra_segments(self):
        self.assertEqual(fkm.normalize_wxid("wxid_abc123"), "wxid_abc123")

    def test_account_with_4char_alnum_suffix_stripped(self):
        # macOS 路径常见：your_wxid_a1b2c3 → your_wxid
        self.assertEqual(fkm.normalize_wxid("your_wxid_a1b2c3"), "your_wxid")

    def test_account_without_recognizable_suffix_returned_asis(self):
        self.assertEqual(fkm.normalize_wxid("simple"), "simple")
        self.assertEqual(fkm.normalize_wxid("foo_bar_baz"), "foo_bar_baz")  # baz 是 3 char

    def test_empty_or_none_returns_empty(self):
        self.assertEqual(fkm.normalize_wxid(""), "")
        self.assertEqual(fkm.normalize_wxid(None), "")
        self.assertEqual(fkm.normalize_wxid("   "), "")


class DeriveImageKeysTests(unittest.TestCase):
    def test_xor_is_low_byte_of_code(self):
        xor, _ = fkm.derive_image_keys(0x12345678, "anything")
        self.assertEqual(xor, 0x78)

    def test_xor_handles_small_codes(self):
        self.assertEqual(fkm.derive_image_keys(0xFF, "x")[0], 0xFF)
        self.assertEqual(fkm.derive_image_keys(0x00, "x")[0], 0x00)

    def test_aes_is_md5_hex_truncated_to_16(self):
        # Golden value：来自 POC 在真实微信数据上的验证（issue #23 解的就是这一对）
        xor, aes = fkm.derive_image_keys(18709375, "your_wxid")
        self.assertEqual(xor, 0x7F)
        self.assertEqual(aes, "b73bd4126969d30f")

    def test_aes_does_not_normalize_wxid_internally(self):
        # 归一化由调用方负责；不同 wxid 字符串产出不同 key
        _, aes_full = fkm.derive_image_keys(18709375, "your_wxid_a1b2c3")
        _, aes_norm = fkm.derive_image_keys(18709375, "your_wxid")
        self.assertNotEqual(aes_full, aes_norm)


class DeriveKvcommDirCandidatesTests(unittest.TestCase):
    def test_canonical_macos_path_is_first_candidate(self):
        db_dir = (
            "/Users/x/Library/Containers/com.tencent.xinWeChat/Data/Documents/"
            "xwechat_files/wxid_abc/db_storage"
        )
        candidates = fkm.derive_kvcomm_dir_candidates(db_dir)
        self.assertGreater(len(candidates), 0)
        expected_primary = (
            "/Users/x/Library/Containers/com.tencent.xinWeChat/Data/Documents/"
            "app_data/net/kvcomm"
        )
        self.assertEqual(candidates[0], expected_primary)

    def test_returns_multiple_candidates(self):
        # 多候选是 Round 1 review 的关键修复点：跨版本路径覆盖
        db_dir = (
            "/Users/x/Library/Containers/com.tencent.xinWeChat/Data/Documents/"
            "xwechat_files/wxid_abc/db_storage"
        )
        candidates = fkm.derive_kvcomm_dir_candidates(db_dir)
        self.assertGreaterEqual(len(candidates), 3,
                                "应返回多个候选路径以覆盖不同微信版本布局")

    def test_no_xwechat_files_still_returns_home_fallback(self):
        # 即使无法从 db_dir 推算，也至少返回 HOME 默认路径作兜底
        candidates = fkm.derive_kvcomm_dir_candidates("/random/path")
        self.assertGreaterEqual(len(candidates), 1)
        self.assertTrue(any("Containers/com.tencent.xinWeChat" in c
                            for c in candidates))

    def test_candidates_are_unique(self):
        db_dir = "/x/y/Documents/xwechat_files/wxid_abc/db_storage"
        candidates = fkm.derive_kvcomm_dir_candidates(db_dir)
        self.assertEqual(len(candidates), len(set(candidates)))


class FindExistingKvcommDirTests(unittest.TestCase):
    def test_returns_first_existing_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            # 构造合法 db_dir 路径，在第一个候选位置创建实际目录
            base = os.path.join(tmp, "Documents", "xwechat_files", "wxid_x")
            db_dir = os.path.join(base, "db_storage")
            os.makedirs(db_dir)
            kvcomm = os.path.join(tmp, "Documents", "app_data", "net", "kvcomm")
            os.makedirs(kvcomm)

            self.assertEqual(fkm.find_existing_kvcomm_dir(db_dir), kvcomm)

    def test_returns_none_when_no_candidate_exists(self):
        # 即使 HOME fallback 候选也不存在时，应返回 None。
        # 隔离测试不能依赖宿主机有/无微信安装；patch expanduser 指向 tmp。
        with tempfile.TemporaryDirectory() as fake_home:
            with patch("os.path.expanduser", return_value=fake_home):
                self.assertIsNone(fkm.find_existing_kvcomm_dir("/nonexistent/x/y/z"))


class CollectKvcommCodesTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.kvdir = self._tmp.name

    def _touch(self, name):
        with open(os.path.join(self.kvdir, name), "w") as f:
            f.write("")

    def test_extracts_code_from_filename(self):
        self._touch("key_18709375_4066645761_1_1777096531_137785059_3600_input.statistic")
        self._touch("key_99999999_yyy_zzz.statistic")
        self.assertEqual(fkm.collect_kvcomm_codes(self.kvdir), [18709375, 99999999])

    def test_ignores_files_with_non_numeric_first_segment(self):
        self._touch("key_reportnow_18709375_xxx.statistic")
        self._touch("key_abc_def.statistic")
        self._touch("config.ini")
        self._touch("monitordata_x")
        self.assertEqual(fkm.collect_kvcomm_codes(self.kvdir), [])

    def test_dedupes_same_code_across_files(self):
        self._touch("key_42_a.statistic")
        self._touch("key_42_b.statistic")
        self.assertEqual(fkm.collect_kvcomm_codes(self.kvdir), [42])

    def test_missing_dir_returns_empty(self):
        self.assertEqual(fkm.collect_kvcomm_codes("/nonexistent/xxx"), [])

    def test_none_dir_returns_empty(self):
        self.assertEqual(fkm.collect_kvcomm_codes(None), [])


class CollectWxidCandidatesTests(unittest.TestCase):
    def test_returns_raw_and_normalized_when_different(self):
        db_dir = "/x/Documents/xwechat_files/your_wxid_a1b2c3/db_storage"
        self.assertEqual(fkm.collect_wxid_candidates(db_dir),
                         ["your_wxid_a1b2c3", "your_wxid"])

    def test_returns_one_when_normalize_is_identity(self):
        db_dir = "/x/Documents/xwechat_files/wxid_abc/db_storage"
        self.assertEqual(fkm.collect_wxid_candidates(db_dir), ["wxid_abc"])

    def test_no_xwechat_files_returns_empty(self):
        self.assertEqual(fkm.collect_wxid_candidates("/random/path"), [])

    def test_xwechat_files_at_end_returns_empty(self):
        self.assertEqual(fkm.collect_wxid_candidates("/x/xwechat_files"), [])


class VerifyAesKeyTests(unittest.TestCase):
    KEY = "b73bd4126969d30f"

    def _encrypt(self, plaintext_16):
        return AES.new(self.KEY.encode("ascii"), AES.MODE_ECB).encrypt(plaintext_16)

    def test_jpeg_magic_passes(self):
        ct = self._encrypt(b"\xff\xd8\xff\xe0" + b"\x00" * 12)
        self.assertTrue(fkm.verify_aes_key(self.KEY, ct))

    def test_png_magic_passes(self):
        ct = self._encrypt(b"\x89PNG\r\n\x1a\n" + b"\x00" * 8)
        self.assertTrue(fkm.verify_aes_key(self.KEY, ct))

    def test_gif_magic_passes(self):
        ct = self._encrypt(b"GIF89a" + b"\x00" * 10)
        self.assertTrue(fkm.verify_aes_key(self.KEY, ct))

    def test_wxgf_magic_passes(self):
        ct = self._encrypt(b"wxgf" + b"\x00" * 12)
        self.assertTrue(fkm.verify_aes_key(self.KEY, ct))

    def test_random_data_fails(self):
        self.assertFalse(fkm.verify_aes_key(self.KEY, bytes(range(16))))

    def test_wrong_length_template_fails(self):
        self.assertFalse(fkm.verify_aes_key(self.KEY, b"short"))
        self.assertFalse(fkm.verify_aes_key(self.KEY, b""))

    def test_short_aes_key_fails(self):
        self.assertFalse(fkm.verify_aes_key("short", b"\x00" * 16))

    def test_empty_aes_key_fails(self):
        self.assertFalse(fkm.verify_aes_key("", b"\x00" * 16))


class VerifyAesKeyAgainstAllTests(unittest.TestCase):
    """交叉验证：必须所有模板都通过才算命中（防短 magic 偶然碰撞）。"""

    KEY = "b73bd4126969d30f"

    def _encrypt(self, plaintext_16):
        return AES.new(self.KEY.encode("ascii"), AES.MODE_ECB).encrypt(plaintext_16)

    def test_all_templates_pass(self):
        ct1 = self._encrypt(b"\xff\xd8\xff\xe0" + b"\x00" * 12)
        ct2 = self._encrypt(b"\x89PNG\r\n\x1a\n" + b"\x00" * 8)
        self.assertTrue(fkm.verify_aes_key_against_all(self.KEY, [ct1, ct2]))

    def test_one_template_fails_overall_fails(self):
        ct1 = self._encrypt(b"\xff\xd8\xff\xe0" + b"\x00" * 12)  # passes
        ct2 = bytes(range(16))                                    # random, fails
        self.assertFalse(fkm.verify_aes_key_against_all(self.KEY, [ct1, ct2]))

    def test_empty_template_list_returns_false(self):
        # 没模板就不能验证；不视为通过（防"零样本=自动通过"陷阱）
        self.assertFalse(fkm.verify_aes_key_against_all(self.KEY, []))


class FindV2TemplateCiphertextsTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = self._tmp.name

    def _build_v2_dat(self, name, ciphertext_16, subdir=""):
        target_dir = os.path.join(self.dir, subdir) if subdir else self.dir
        os.makedirs(target_dir, exist_ok=True)
        path = os.path.join(target_dir, name)
        with open(path, "wb") as f:
            f.write(fkm.V2_MAGIC + b"\x00" * 9 + ciphertext_16 + b"\x00\x00")
        return path

    def test_finds_one_template_in_v2_thumb(self):
        ct = bytes(range(0xF, 0x1F))
        self._build_v2_dat("abc_t.dat", ct)
        result = fkm.find_v2_template_ciphertexts(self.dir)
        self.assertEqual(result, [ct])

    def test_finds_multiple_distinct_templates(self):
        cts = [bytes([i] * 16) for i in (0x11, 0x22, 0x33)]
        for i, ct in enumerate(cts):
            self._build_v2_dat(f"chat{i}_t.dat", ct, subdir=f"chat{i}")
        result = fkm.find_v2_template_ciphertexts(self.dir, max_templates=3)
        self.assertEqual(set(result), set(cts))

    def test_dedupes_identical_templates(self):
        ct = b"\x42" * 16
        self._build_v2_dat("a_t.dat", ct, subdir="a")
        self._build_v2_dat("b_t.dat", ct, subdir="b")
        result = fkm.find_v2_template_ciphertexts(self.dir)
        self.assertEqual(result, [ct])

    def test_falls_back_to_any_dat_if_no_thumb(self):
        ct = b"\x33" * 16
        self._build_v2_dat("only_full.dat", ct)
        self.assertEqual(fkm.find_v2_template_ciphertexts(self.dir), [ct])

    def test_skips_non_v2_files(self):
        path = os.path.join(self.dir, "abc_t.dat")
        with open(path, "wb") as f:
            f.write(b"\x00" * 100)
        self.assertEqual(fkm.find_v2_template_ciphertexts(self.dir), [])

    def test_empty_dir_returns_empty(self):
        self.assertEqual(fkm.find_v2_template_ciphertexts(self.dir), [])

    def test_missing_dir_returns_empty(self):
        self.assertEqual(fkm.find_v2_template_ciphertexts("/nonexistent"), [])

    def test_walks_into_subdirs(self):
        ct = b"\x44" * 16
        self._build_v2_dat("x_t.dat", ct, subdir="sub/deeper")
        self.assertEqual(fkm.find_v2_template_ciphertexts(self.dir), [ct])

    def test_respects_max_templates(self):
        cts = [bytes([i] * 16) for i in range(10)]
        for i, ct in enumerate(cts):
            self._build_v2_dat(f"x{i}_t.dat", ct, subdir=f"d{i}")
        result = fkm.find_v2_template_ciphertexts(self.dir, max_templates=2)
        self.assertEqual(len(result), 2)


class FindImageKeyMacosIntegrationTests(unittest.TestCase):
    """端到端集成：合成 kvcomm 文件 + 合成 V2 模板 → 期望派生出已知 key。"""

    def _build_test_env(self, tmpdir, code, wxid_raw, num_templates=2):
        """构造测试环境，返回 (db_dir, expected_xor, expected_aes)。"""
        wxid_norm = fkm.normalize_wxid(wxid_raw)
        base = os.path.join(tmpdir, "Documents", "xwechat_files", wxid_raw)
        db_dir = os.path.join(base, "db_storage")
        os.makedirs(db_dir)

        kvcomm = os.path.join(tmpdir, "Documents", "app_data", "net", "kvcomm")
        os.makedirs(kvcomm)
        with open(os.path.join(kvcomm, f"key_{code}_x.statistic"), "w") as f:
            f.write("")

        xor_expected, aes_expected = fkm.derive_image_keys(code, wxid_norm)
        # 多个模板用不同的 plaintext 加密（仍是图像 magic 开头但内容不同）
        plaintexts = [
            b"\xff\xd8\xff\xe0" + b"\x00" * 12,           # JPEG
            b"\x89PNG\r\n\x1a\n" + b"\x00" * 8,           # PNG
            b"GIF89a" + b"\x01\x02" + b"\x00" * 8,        # GIF
        ]
        for i in range(num_templates):
            pt = plaintexts[i % len(plaintexts)]
            ct = AES.new(aes_expected.encode("ascii"), AES.MODE_ECB).encrypt(pt)
            attach = os.path.join(base, "msg", "attach", f"chat{i}")
            os.makedirs(attach)
            with open(os.path.join(attach, f"img{i}_t.dat"), "wb") as f:
                f.write(fkm.V2_MAGIC + b"\x00" * 9 + ct + b"\x00\x00")
        return db_dir, xor_expected, aes_expected

    def test_full_flow_succeeds_with_normalized_wxid(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_dir, xor_exp, aes_exp = self._build_test_env(
                tmp, code=18709375, wxid_raw="your_wxid_a1b2c3", num_templates=3)
            result = fkm.find_image_key_macos(db_dir)
            self.assertIsNotNone(result, "派生应该成功")
            self.assertEqual(result, (xor_exp, aes_exp))

    def test_returns_none_when_no_kvcomm_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = os.path.join(tmp, "Documents", "xwechat_files", "wxid_x")
            db_dir = os.path.join(base, "db_storage")
            os.makedirs(db_dir)
            self.assertIsNone(fkm.find_image_key_macos(db_dir))

    def test_returns_none_when_no_v2_template(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = os.path.join(tmp, "Documents", "xwechat_files", "wxid_x")
            db_dir = os.path.join(base, "db_storage")
            os.makedirs(db_dir)
            kvcomm = os.path.join(tmp, "Documents", "app_data", "net", "kvcomm")
            os.makedirs(kvcomm)
            with open(os.path.join(kvcomm, "key_42_x.statistic"), "w") as f:
                f.write("")
            self.assertIsNone(fkm.find_image_key_macos(db_dir))

    def test_returns_none_when_no_combination_verifies(self):
        # 有 code 也有 V2 .dat，但密文是随机的，没有任何 key 能解出
        with tempfile.TemporaryDirectory() as tmp:
            base = os.path.join(tmp, "Documents", "xwechat_files", "wxid_x")
            db_dir = os.path.join(base, "db_storage")
            os.makedirs(db_dir)
            kvcomm = os.path.join(tmp, "Documents", "app_data", "net", "kvcomm")
            os.makedirs(kvcomm)
            with open(os.path.join(kvcomm, "key_42_x.statistic"), "w") as f:
                f.write("")
            attach = os.path.join(base, "msg", "attach", "x")
            os.makedirs(attach)
            with open(os.path.join(attach, "x_t.dat"), "wb") as f:
                f.write(fkm.V2_MAGIC + b"\x00" * 9 + b"\xde\xad\xbe\xef" * 4 + b"\x00\x00")
            self.assertIsNone(fkm.find_image_key_macos(db_dir))

    def test_empty_db_dir_returns_none_without_crash(self):
        # 防御：空字符串、不合理路径不应抛异常。
        # patch expanduser 让 HOME fallback 也指向不存在的路径，避免
        # 测试在装了真实微信的开发机上意外深入到 wxid 缺失分支。
        with tempfile.TemporaryDirectory() as fake_home:
            with patch("os.path.expanduser", return_value=fake_home):
                self.assertIsNone(fkm.find_image_key_macos(""))


class MainShortCircuitTests(unittest.TestCase):
    """main() 短路：已有 image_aes_key 仍然有效时，不应重新派生 / 不应改写 config。"""

    def test_existing_valid_key_skips_derivation(self):
        with tempfile.TemporaryDirectory() as tmp:
            wxid = "wxid_abc"
            base = os.path.join(tmp, "Documents", "xwechat_files", wxid)
            db_dir = os.path.join(base, "db_storage")
            os.makedirs(db_dir)

            # kvcomm 里放个 code，证明若真去派生也能算出 key
            kvcomm = os.path.join(tmp, "Documents", "app_data", "net", "kvcomm")
            os.makedirs(kvcomm)
            code = 42
            with open(os.path.join(kvcomm, f"key_{code}_x.statistic"), "w") as f:
                f.write("")

            # 用真实派生的 key 加密 V2 模板，使现有 key 在该模板上能验证通过
            xor_exp, aes_exp = fkm.derive_image_keys(code, wxid)
            jpeg_pt = b"\xff\xd8\xff\xe0" + b"\x00" * 12
            ct = AES.new(aes_exp.encode("ascii"), AES.MODE_ECB).encrypt(jpeg_pt)
            attach = os.path.join(base, "msg", "attach", "x")
            os.makedirs(attach)
            with open(os.path.join(attach, "test_t.dat"), "wb") as f:
                f.write(fkm.V2_MAGIC + b"\x00" * 9 + ct + b"\x00\x00")

            # 写入"已有有效 key"的 config
            cfg_path = os.path.join(tmp, "config.json")
            cfg_initial = {
                "db_dir": db_dir,
                "image_aes_key": aes_exp,
                "image_xor_key": xor_exp,
                "extra_field": "must_be_preserved",  # 证明 main 不会重写
            }
            with open(cfg_path, "w", encoding="utf-8") as f:
                json.dump(cfg_initial, f)
            mtime_before = os.path.getmtime(cfg_path)

            # 关键：patch find_image_key_macos 让它若被误调用立刻可见
            with patch.object(fkm, "find_image_key_macos") as mock_derive:
                fkm.main(config_path=cfg_path)

            mock_derive.assert_not_called()  # 短路应直接 return，不进派生
            # config.json 不应被重写
            self.assertEqual(os.path.getmtime(cfg_path), mtime_before)
            with open(cfg_path, encoding="utf-8") as f:
                self.assertEqual(json.load(f), cfg_initial)

    def test_existing_invalid_key_falls_through_to_derivation(self):
        with tempfile.TemporaryDirectory() as tmp:
            wxid = "wxid_abc"
            base = os.path.join(tmp, "Documents", "xwechat_files", wxid)
            db_dir = os.path.join(base, "db_storage")
            os.makedirs(db_dir)

            kvcomm = os.path.join(tmp, "Documents", "app_data", "net", "kvcomm")
            os.makedirs(kvcomm)
            code = 42
            with open(os.path.join(kvcomm, f"key_{code}_x.statistic"), "w") as f:
                f.write("")

            xor_exp, aes_exp = fkm.derive_image_keys(code, wxid)
            jpeg_pt = b"\xff\xd8\xff\xe0" + b"\x00" * 12
            ct = AES.new(aes_exp.encode("ascii"), AES.MODE_ECB).encrypt(jpeg_pt)
            attach = os.path.join(base, "msg", "attach", "x")
            os.makedirs(attach)
            with open(os.path.join(attach, "test_t.dat"), "wb") as f:
                f.write(fkm.V2_MAGIC + b"\x00" * 9 + ct + b"\x00\x00")

            cfg_path = os.path.join(tmp, "config.json")
            cfg_initial = {
                "db_dir": db_dir,
                "image_aes_key": "deadbeefdeadbeef",  # 故意写一个错的
            }
            with open(cfg_path, "w", encoding="utf-8") as f:
                json.dump(cfg_initial, f)

            fkm.main(config_path=cfg_path)

            # 短路应失败，进入派生路径，配置应被改写为正确的 key
            with open(cfg_path, encoding="utf-8") as f:
                cfg_after = json.load(f)
            self.assertEqual(cfg_after["image_aes_key"], aes_exp)
            self.assertEqual(cfg_after["image_xor_key"], xor_exp)


class SaveConfigAtomicTests(unittest.TestCase):
    """原子写测试：os.replace 保证 config.json 不会被半截覆盖。"""

    def test_roundtrip_writes_pretty_utf8(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = os.path.join(tmp, "config.json")
            cfg = {"db_dir": "/x", "image_aes_key": "中文测试key"}
            fkm._save_config_atomic(cfg_path, cfg)
            with open(cfg_path, encoding="utf-8") as f:
                self.assertEqual(json.load(f), cfg)
            # ensure_ascii=False：中文应直接落盘，不被转义
            with open(cfg_path, "rb") as f:
                self.assertIn("中文测试key".encode("utf-8"), f.read())

    def test_failed_replace_leaves_original_intact(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = os.path.join(tmp, "config.json")
            with open(cfg_path, "w", encoding="utf-8") as f:
                json.dump({"original": True}, f)
            with patch.object(os, "replace",
                              side_effect=OSError("disk full during rename")):
                with self.assertRaises(OSError):
                    fkm._save_config_atomic(cfg_path, {"new": True})
            # 原文件应保持不变
            with open(cfg_path, encoding="utf-8") as f:
                self.assertEqual(json.load(f), {"original": True})


if __name__ == "__main__":
    unittest.main()
