"""Unit tests for wxdec.msg_parse — structured XML → dataclass parsers.

All inputs are synthetic XML constructed in the test, mirroring the real
WeChat payload shapes documented in the source module. No PII or real
chat data lands here.

Coverage:
  - parse_voip:  direction, subtype dispatch (已接通 / 中途中断 / 未接通),
                 fallback_ts vs inviteid64, multi-root <voipmsg> slicing
  - parse_name_card:  full row, missing nickname, sign==certinfo de-dup
  - parse_location:   poi+label, coord-only, placeholder poiname, missing-all
  - parse_redpack:    标准 红包 from nativeurl, 群收款 amount, missing wcpayinfo
  - parse_transfer + pair_transfers:  paysubtype label, transcationid grouping,
                                      pst=3 single-field rejection
  - parse_finder_feed:  full feed, missing nickname, subtype gating
"""

import unittest

from wxdec.msg_parse import (
    FinderFeed,
    Location,
    NameCard,
    Redpack,
    TransferInfo,
    VoipRecord,
    pair_transfers,
    parse_finder_feed,
    parse_location,
    parse_name_card,
    parse_redpack,
    parse_transfer,
    parse_voip,
)


# ── VoIP ─────────────────────────────────────────────────────────────────────


def _voip_xml(msg_text, inviteid64=None):
    invite_line = (f"<inviteid64>{inviteid64}</inviteid64>"
                   if inviteid64 is not None else "")
    return f"""<voipmsg>
        <VoIPBubbleMsg>
            <room_type>1</room_type>
            <msg>{msg_text}</msg>
            {invite_line}
        </VoIPBubbleMsg>
    </voipmsg>"""


class TestParseVoip(unittest.TestCase):

    def test_completed_call_me_caller(self):
        xml = _voip_xml("通话时长 3:21", inviteid64=1_700_000_000_000)
        r = parse_voip(xml, fallback_ts=1_700_000_200, sender_id=42, self_id=42)
        self.assertIsInstance(r, VoipRecord)
        self.assertTrue(r.is_me_caller)
        self.assertEqual(r.sub_type, "已接通")
        self.assertEqual(r.duration, "3:21")
        self.assertIsNone(r.status)
        self.assertEqual(r.start_ts, 1_700_000_000)  # inviteid64 / 1000
        self.assertEqual(r.end_ts, 1_700_000_200)    # fallback_ts

    def test_interrupted_call_with_duration(self):
        xml = _voip_xml("通话中断 0:05")
        r = parse_voip(xml, fallback_ts=1234567890, sender_id=1, self_id=2)
        self.assertEqual(r.sub_type, "中途中断")
        self.assertEqual(r.duration, "0:05")
        self.assertEqual(r.end_ts, 1234567890)
        self.assertFalse(r.is_me_caller)

    def test_bare_interrupt(self):
        xml = _voip_xml("通话中断")
        r = parse_voip(xml, fallback_ts=99, sender_id=1, self_id=1)
        self.assertEqual(r.sub_type, "中途中断")
        self.assertIsNone(r.duration)
        self.assertEqual(r.status, "通话中断")
        self.assertIsNone(r.end_ts)

    def test_canceled_partner_caller(self):
        # partner cancels → "已取消" (partner-side render), sender = partner
        xml = _voip_xml("对方已取消")
        r = parse_voip(xml, fallback_ts=1, sender_id=99, self_id=42)
        self.assertEqual(r.sub_type, "未接通")
        self.assertEqual(r.status, "对方已取消")
        self.assertFalse(r.is_me_caller)
        self.assertIsNone(r.end_ts)

    def test_other_device_pickup(self):
        xml = _voip_xml("已在其它设备接听")
        r = parse_voip(xml, fallback_ts=1, sender_id=1, self_id=1)
        self.assertEqual(r.sub_type, "已接通")
        self.assertEqual(r.status, "已在其它设备接听")
        self.assertIsNone(r.duration)

    def test_inviteid64_missing_falls_back(self):
        xml = _voip_xml("通话时长 1:00")  # no inviteid64
        r = parse_voip(xml, fallback_ts=555, sender_id=1, self_id=1)
        self.assertEqual(r.start_ts, 555)
        self.assertEqual(r.end_ts, 555)

    def test_multi_root_sibling_after_voipmsg(self):
        # WeChat sometimes appends sibling elements after </voipmsg>.
        # Strict XML rejects multi-root; parse_voip must slice cleanly.
        xml = (_voip_xml("通话时长 0:30", inviteid64=1700000000000)
               + "<voipinvitemsg><foo/></voipinvitemsg>")
        r = parse_voip(xml, fallback_ts=1, sender_id=1, self_id=1)
        self.assertIsNotNone(r)
        self.assertEqual(r.duration, "0:30")

    def test_empty_and_unrelated(self):
        self.assertIsNone(parse_voip("", 0, 0, 0))
        self.assertIsNone(parse_voip("<other>x</other>", 0, 0, 0))

    def test_malformed_xml(self):
        self.assertIsNone(parse_voip("<voipmsg>broken", 0, 0, 0))

    def test_inviteid64_zero_falls_back(self):
        # Implementation guards `inviteid64 > 0`; explicit "0" must take
        # the same fallback path as a missing tag.
        xml = _voip_xml("通话时长 1:00", inviteid64=0)
        r = parse_voip(xml, fallback_ts=777, sender_id=1, self_id=1)
        self.assertEqual(r.start_ts, 777)
        self.assertEqual(r.inviteid64, 0)


# ── Name card ────────────────────────────────────────────────────────────────


class TestParseNameCard(unittest.TestCase):

    def test_full_personal_card(self):
        xml = (
            '<msg nickname="Alice" alias="alice123" '
            'sign="hello world" province="Sichuan" sex="2"/>'
        )
        r = parse_name_card(xml)
        self.assertIsInstance(r, NameCard)
        self.assertEqual(r.nickname, "Alice")
        self.assertEqual(r.alias, "alice123")
        self.assertEqual(r.sign, "hello world")
        self.assertEqual(r.province, "Sichuan")
        self.assertEqual(r.certinfo, "")

    def test_business_card_with_certinfo(self):
        xml = (
            '<msg nickname="某宏观研究" certinfo="加密 | 美股 | 黄金 | 宏观" '
            'sign="加密 | 美股 | 黄金 | 宏观"/>'
        )
        r = parse_name_card(xml)
        self.assertEqual(r.certinfo, "加密 | 美股 | 黄金 | 宏观")
        # sign equal to certinfo → suppressed
        self.assertEqual(r.sign, "")

    def test_missing_nickname_returns_none(self):
        self.assertIsNone(parse_name_card('<msg alias="x"/>'))

    def test_malformed(self):
        self.assertIsNone(parse_name_card("<broken"))


# ── Location ─────────────────────────────────────────────────────────────────


class TestParseLocation(unittest.TestCase):

    def test_poi_with_category(self):
        xml = (
            '<msg><location poiname="和猫住TNR动物医院" '
            'label="四川省成都市武侯区xxx" '
            'poiCategoryTips="医疗保健:诊所" '
            'poiBusinessHour="09:00-21:00" '
            'x="104.06" y="30.67" cityname="成都市"/></msg>'
        )
        r = parse_location(xml)
        self.assertIsInstance(r, Location)
        self.assertEqual(r.venue, "和猫住TNR动物医院")
        self.assertEqual(r.category, "医疗保健:诊所")
        self.assertEqual(r.address, "四川省成都市武侯区xxx")
        self.assertEqual(r.hours, "09:00-21:00")

    def test_placeholder_poiname_falls_through_to_label(self):
        xml = '<msg><location poiname="[位置]" label="some address" x="1" y="2"/></msg>'
        r = parse_location(xml)
        self.assertEqual(r.venue, "some address")
        # `address` field is populated whenever `label != poiname` (after
        # placeholder clearing). Caller may dedupe against venue if it
        # wants to suppress the duplicate.
        self.assertEqual(r.address, "some address")

    def test_coord_only(self):
        xml = '<msg><location x="104.06" y="30.67"/></msg>'
        r = parse_location(xml)
        self.assertEqual(r.venue, "")
        self.assertEqual(r.x, "104.06")
        self.assertEqual(r.y, "30.67")

    def test_completely_empty_returns_none(self):
        # no poi, no label, no coords
        self.assertIsNone(parse_location('<msg><location/></msg>'))

    def test_price_zero_preserved_for_caller_decision(self):
        xml = ('<msg><location poiname="X" label="Y" '
               'poiPriceTips="0.0"/></msg>')
        r = parse_location(xml)
        # parser preserves raw; caller decides suppression
        self.assertEqual(r.price, "0.0")


# ── Redpack ──────────────────────────────────────────────────────────────────


def _redpack_appmsg(scene="微信红包", sender_title="恭喜发财，大吉大利",
                    sender_wxid="alice_wxid", senderdes=""):
    # Real WeChat XML escapes `&` to `&amp;` (DB serialization). Bare `&`
    # would cause ElementTree to reject the document.
    nativeurl = (f"wxpay://c2cbizmessagehandler/hongbao/receivehongbao?"
                 f"sendusername={sender_wxid}&amp;signature=xxx") if sender_wxid else ""
    return f"""<msg><appmsg><type>2001</type>
        <wcpayinfo>
            <scenetext>{scene}</scenetext>
            <sendertitle>{sender_title}</sendertitle>
            <nativeurl>{nativeurl}</nativeurl>
            <senderdes>{senderdes}</senderdes>
        </wcpayinfo></appmsg></msg>"""


class TestParseRedpack(unittest.TestCase):

    def test_standard_redpack(self):
        r = parse_redpack(_redpack_appmsg())
        self.assertIsInstance(r, Redpack)
        self.assertEqual(r.scene, "微信红包")
        self.assertEqual(r.sender_wxid, "alice_wxid")
        self.assertEqual(r.sender_title, "恭喜发财，大吉大利")
        self.assertEqual(r.amount_per_person, "")

    def test_group_collection_extracts_amount(self):
        xml = _redpack_appmsg(scene="群收款", senderdes="每人需支付138.34元")
        r = parse_redpack(xml)
        self.assertEqual(r.scene, "群收款")
        self.assertEqual(r.amount_per_person, "138.34")

    def test_missing_nativeurl_sender_empty(self):
        xml = _redpack_appmsg(sender_wxid="")
        r = parse_redpack(xml)
        self.assertEqual(r.sender_wxid, "")
        # Caller fallback: row-level sender_id == self_id

    def test_missing_wcpayinfo(self):
        xml = "<msg><appmsg><type>2001</type></appmsg></msg>"
        self.assertIsNone(parse_redpack(xml))


# ── Transfer + pairing ───────────────────────────────────────────────────────


def _transfer_appmsg(paysubtype, *, feedesc="¥888.00", pay_memo="",
                     transcationid="tid_001",
                     payer="", receiver=""):
    return f"""<msg><appmsg><type>2000</type>
        <wcpayinfo>
            <paysubtype>{paysubtype}</paysubtype>
            <feedesc>{feedesc}</feedesc>
            <pay_memo>{pay_memo}</pay_memo>
            <transcationid>{transcationid}</transcationid>
            <payer_username>{payer}</payer_username>
            <receiver_username>{receiver}</receiver_username>
        </wcpayinfo></appmsg></msg>"""


class TestParseTransfer(unittest.TestCase):

    def test_initiation_pst_1(self):
        r = parse_transfer(_transfer_appmsg("1", payer="me_wxid", receiver="dad_wxid"))
        self.assertIsInstance(r, TransferInfo)
        self.assertEqual(r.paysubtype_label, "发起转账")
        self.assertEqual(r.fee_desc, "¥888.00")
        self.assertEqual(r.payer_username, "me_wxid")

    def test_pst_8_also_initiation(self):
        # The label table was historically wrong (8 mapped to "已领取");
        # locked in correct mapping.
        r = parse_transfer(_transfer_appmsg("8"))
        self.assertEqual(r.paysubtype_label, "发起转账")

    def test_pst_9_refund(self):
        r = parse_transfer(_transfer_appmsg("9"))
        self.assertEqual(r.paysubtype_label, "已退还")

    def test_unknown_pst_keeps_raw(self):
        r = parse_transfer(_transfer_appmsg("42"))
        self.assertIn("42", r.paysubtype_label)
        self.assertIn("未知", r.paysubtype_label)

    def test_missing_wcpayinfo(self):
        xml = "<msg><appmsg><type>2000</type></appmsg></msg>"
        self.assertIsNone(parse_transfer(xml))

    def test_camelcase_field_variants_tolerated(self):
        # WeChat 4.x version variants: feeDesc / paymemo / transcationId
        # alongside the snake_case forms. `_pick()` falls through alternates.
        xml = """<msg><appmsg><type>2000</type>
            <wcpayinfo>
                <paysubtype>1</paysubtype>
                <feeDesc>¥123.45</feeDesc>
                <paymemo>合并支付</paymemo>
                <transcationId>TID_CAMEL</transcationId>
            </wcpayinfo></appmsg></msg>"""
        r = parse_transfer(xml)
        self.assertEqual(r.fee_desc, "¥123.45")
        self.assertEqual(r.pay_memo, "合并支付")
        self.assertEqual(r.transcationid, "TID_CAMEL")


class TestPairTransfers(unittest.TestCase):

    def test_pair_aggregates_across_rows(self):
        # tid=T1: initiation row has payer+receiver; ack row (pst=3) has only
        # one side. Pairing should fill direction from the initiation row.
        rows = [
            parse_transfer(_transfer_appmsg("1", transcationid="T1",
                                            payer="me", receiver="dad")),
            parse_transfer(_transfer_appmsg("3", transcationid="T1",
                                            payer="", receiver="me")),
        ]
        out = pair_transfers(rows)
        self.assertEqual(out["T1"], ("me", "dad"))

    def test_pst_3_single_field_rejected(self):
        # pst=3 with only one of payer/receiver populated is the FLIPPED
        # variant (14% of pst=3 rows) — must NOT influence direction.
        rows = [
            parse_transfer(_transfer_appmsg("3", transcationid="T2",
                                            payer="", receiver="wrong_party")),
        ]
        out = pair_transfers(rows)
        self.assertEqual(out, {})

    def test_pst_3_with_both_fields_trusted(self):
        rows = [
            parse_transfer(_transfer_appmsg("3", transcationid="T3",
                                            payer="alice", receiver="bob")),
        ]
        out = pair_transfers(rows)
        self.assertEqual(out["T3"], ("alice", "bob"))

    def test_empty_transcationid_skipped(self):
        rows = [
            parse_transfer(_transfer_appmsg("1", transcationid="",
                                            payer="a", receiver="b")),
        ]
        self.assertEqual(pair_transfers(rows), {})


# ── Finder feed ──────────────────────────────────────────────────────────────


def _finder_xml(nickname="某视频号", desc="今天的视频内容", feed_type=4,
                live_id=0, media_count=1, media_type=4, biz_nickname=""):
    return f"""<finderFeed>
        <nickname>{nickname}</nickname>
        <bizNickname>{biz_nickname}</bizNickname>
        <desc>{desc}</desc>
        <feedType>{feed_type}</feedType>
        <liveId>{live_id}</liveId>
        <mediaCount>{media_count}</mediaCount>
        <authIconType>1</authIconType>
        <mediaList>
            <media>
                <mediaType>{media_type}</mediaType>
                <videoPlayDuration>62</videoPlayDuration>
            </media>
        </mediaList>
    </finderFeed>"""


class TestParseFinderFeed(unittest.TestCase):

    def test_standard_video_post(self):
        r = parse_finder_feed(_finder_xml())
        self.assertIsInstance(r, FinderFeed)
        self.assertEqual(r.nickname, "某视频号")
        self.assertEqual(r.video_play_duration, 62)
        self.assertEqual(r.subtype, "视频")

    def test_unknown_shape_subtype_none(self):
        # liveId != 0 — live replay shape, not the validated single-video
        # combo. subtype must be None so callers see a visible signal.
        r = parse_finder_feed(_finder_xml(live_id=12345))
        self.assertIsNone(r.subtype)

    def test_missing_nickname_returns_none(self):
        xml = "<finderFeed><desc>x</desc></finderFeed>"
        self.assertIsNone(parse_finder_feed(xml))

    def test_accepts_none_element(self):
        self.assertIsNone(parse_finder_feed(None))


if __name__ == "__main__":
    unittest.main()
