"""Structured message parsers — XML → dataclass, no DB / no display deps.

Complement to `msg_format.py` (which renders single-line label strings for
chat history display). These parsers return structured records, suitable
for programmatic consumers (downstream summarizers, diary tools, search
indexes) that need fields rather than pre-rendered prose.

All inputs are XML strings (or already-parsed appmsg elements). Caller
supplies any context needed (self_id, sender_id, is_group) so this module
stays free of DB / contact lookups.

Coverage in this module:
  - VoIP (base_type=50)        → VoipRecord
  - Name card (base_type=42)   → NameCard
  - Location (base_type=48)    → Location
  - Red packet (app_type=2001) → Redpack
  - Transfer (app_type=2000)   → TransferInfo  +  pair_transfers()
  - Video-channel (app_type=51 finderFeed) → FinderFeed

Empirical validation references in each docstring cite row counts from
the upstream downstream (rwd_lite/wechat.py) where these parsers were
originally written and verified against a 6.4M-msg real-data corpus.

Relationship with `msg_format.py` (known overlap, not yet consolidated):
  - `msg_format._extract_transfer_info` ≈ `parse_transfer`
  - `msg_format._format_voip_message_text` ≈ string render over `parse_voip`
  - `msg_format._format_namecard_text` ≈ string render over `parse_name_card`
  - `msg_format._collapse_text` ≈ `_collapse`

msg_format serves the existing MCP / web-viewer string-label ABI (stable
production consumers); msg_parse serves structured-output consumers
(summarizers, search indexes, downstream apps). When adding a new parser
here, do NOT also add a copy in msg_format — if a string renderer is
later needed, layer it on top of the dataclass returned here. Eventual
goal: msg_format becomes a thin renderer over msg_parse and the
duplication disappears.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

# ── XML helpers ──────────────────────────────────────────────────────────────


def _parse_xml(text):
    if not text:
        return None
    try:
        return ET.fromstring(text.lstrip("﻿").strip())
    except ET.ParseError:
        return None


def _txt(elem, child_tag):
    if elem is None:
        return ""
    return (elem.findtext(child_tag) or "").strip()


def _attr(elem, name):
    if elem is None:
        return ""
    return (elem.get(name) or "").strip()


def _safe_int(s, default=0):
    try:
        return int((s or "").strip())
    except (ValueError, AttributeError, TypeError):
        return default


# ── VoIP (base_type=50) ──────────────────────────────────────────────────────

_VOIP_SLICE = re.compile(r"<voipmsg\b.*?</voipmsg>", re.DOTALL)
_VOIP_DURATION = re.compile(r"通话时长\s+(.+)")
_VOIP_INTERRUPT_NUM = re.compile(r"通话中断\s+\d")
_VOIP_INTERRUPT_DUR = re.compile(r"通话中断\s+(.+)")


@dataclass
class VoipRecord:
    """Structured VoIP (call) record.

    `is_me_caller` — direction. In 1v1 chats `real_sender_id == self_id`
    iff I dialed. (Group VoIP rows do not occur in real data.)

    `sub_type` ∈ {"已接通", "中途中断", "未接通"}.
    `duration` is the raw suffix from `通话时长 X` or `通话中断 X` rows
    (e.g. "3:21"); None when the call had no completed duration.
    `status` is the raw <msg> text for non-duration rows (取消 / 忙线 /
    未应答 / ...); None when carried by `duration` already.

    `start_ts` is `inviteid64 / 1000` (the moment of dialing). When
    inviteid64 is missing, falls back to `fallback_ts`. `end_ts` is the
    DB row's create_time (status-message landing time) for completed
    or interrupted calls; None for missed/canceled.
    """
    is_me_caller: bool
    sub_type: str
    start_ts: int
    end_ts: Optional[int] = None
    duration: Optional[str] = None
    status: Optional[str] = None
    raw_msg: str = ""
    inviteid64: int = 0


def parse_voip(xml_text, fallback_ts, sender_id, self_id):
    """Parse a base_type=50 voipmsg payload into VoipRecord, or None on
    malformed XML.

    Subtype dispatch:
      - 已接通: msg starts with "通话时长 "  OR  msg == "已在其它设备接听"
      - 中途中断: msg matches "通话中断 N"  OR  msg == "通话中断" (no number)
      - 未接通: everything else (取消 / 拒绝 / 未应答 / 忙线 / ...)

    Validated across 1466 real rows by upstream downstream (rwd_lite):
    every <msg> text aligns cleanly with sender_id under the
    `is_me_caller = (sender_id == self_id)` rule (e.g. "对方已取消"
    appears 194/195 with sender=对方=caller; "已取消" 73/73 with
    sender=我=caller).

    `fallback_ts` is the DB row's create_time (status-message landing,
    ≈ call END / state-change time).

    WeChat sometimes appends sibling top-level elements after `</voipmsg>`
    (voipinvitemsg / voipextinfo / voiplocalinfo). Strict XML rejects
    multiple roots — we slice to just the first `<voipmsg>...</voipmsg>`.
    """
    if not xml_text or "<voip" not in xml_text:
        return None
    m = _VOIP_SLICE.search(xml_text)
    sliced = m.group(0) if m else xml_text
    root = _parse_xml(sliced)
    if root is None:
        return None

    msg_text = (root.findtext(".//msg") or "").strip()
    inviteid64_ms = _safe_int(root.findtext(".//inviteid64") or "", 0)
    start_ts = inviteid64_ms // 1000 if inviteid64_ms > 0 else fallback_ts
    is_me_caller = (sender_id == self_id)

    duration = None
    status = None
    end_ts = None

    if msg_text.startswith("通话时长"):
        sub_type = "已接通"
        m = _VOIP_DURATION.match(msg_text)
        duration = m.group(1).strip() if m else None
        end_ts = fallback_ts
    elif _VOIP_INTERRUPT_NUM.match(msg_text):
        sub_type = "中途中断"
        m = _VOIP_INTERRUPT_DUR.match(msg_text)
        duration = m.group(1).strip() if m else None
        end_ts = fallback_ts
    elif msg_text == "通话中断":
        sub_type = "中途中断"
        status = msg_text
    elif msg_text == "已在其它设备接听":
        sub_type = "已接通"
        status = msg_text
    else:
        sub_type = "未接通"
        status = msg_text or "未知状态"

    return VoipRecord(
        is_me_caller=is_me_caller,
        sub_type=sub_type,
        start_ts=start_ts,
        end_ts=end_ts,
        duration=duration,
        status=status,
        raw_msg=msg_text,
        inviteid64=inviteid64_ms,
    )


# ── Name card (base_type=42) ─────────────────────────────────────────────────


@dataclass
class NameCard:
    """Structured name-card share.

    Verified across 3,285 real rows (0 parse errors). High-signal field
    for shared 公众号 / biz cards is `certinfo` — Personal contacts don't
    populate it. `city` is intentionally NOT extracted (65% of cities
    are country markers like '中国大陆' / '中国' / 'China' — too noisy);
    `province` is the geographic field worth surfacing.
    """
    nickname: str
    alias: str = ""           # 微信号 (58% populated)
    certinfo: str = ""        # 认证 (53% populated)
    sign: str = ""            # 个性签名 (29% populated)
    province: str = ""        # 地区 (85% populated)


def parse_name_card(xml_text):
    """Parse a base_type=42 name-card share. Returns None on malformed XML
    or missing nickname.

    Intentionally NOT extracted (low signal / system metadata):
    bigheadimgurl / smallheadimgurl / brandIconUrl, v3_xxx encrypted
    username, fullpy / shortpy (pinyin), imagestatus / scene / certflag /
    brandFlags / regionCode, antispamticket / brandSubscriptConfigUrl /
    brandHomeUrl / biznamecardinfo, sex (0/1/2).
    """
    root = _parse_xml(xml_text)
    if root is None:
        return None
    nickname = _attr(root, "nickname")
    if not nickname:
        return None
    certinfo = _attr(root, "certinfo")
    sign = _attr(root, "sign")
    # 公众号 cards often set sign == certinfo; the duplicate carries no
    # extra signal so callers can suppress, but we preserve the raw fields.
    return NameCard(
        nickname=nickname,
        alias=_attr(root, "alias"),
        certinfo=certinfo,
        sign=sign if sign != certinfo else "",
        province=_attr(root, "province"),
    )


# ── Location (base_type=48) ──────────────────────────────────────────────────

_LOC_PLACEHOLDER_NAMES = frozenset({"[位置]", "[Location]"})


@dataclass
class Location:
    """Structured location share.

    Verified across 1,411 real rows (0 parse errors). `poiname` and
    `label` are BOTH populated in ~97% of rows and DIFFERENT in 99.93%
    of those (poiname=venue, label=address) — surface both.
    `category` (poiCategoryTips, ~50% populated) is high diary signal:
    '医疗保健:诊所', '美食:火锅' — often more useful than opaque venue
    names.

    Coord-only rows (1.2%, missing poi/label): `x` and `y` populated,
    venue empty. Caller renders as bare `[位置] x,y`.
    """
    venue: str              # poiname > label
    category: str = ""      # poiCategoryTips
    address: str = ""       # label when != poiname
    hours: str = ""         # poiBusinessHour
    price: str = ""         # poiPriceTips (suppressed for "0" / "0.0" / "0.00")
    x: str = ""
    y: str = ""


def parse_location(xml_text):
    """Parse a base_type=48 location share. Returns None on malformed XML
    or when both venue AND coordinates are missing (true empty row).

    `poiname` ∈ {'[位置]', '[Location]'} is the placeholder WeChat shows
    when the user shared a coord without picking a POI from the list
    (~3% of rows) — treated as missing so caller falls through to label
    or coords.

    `price` values "0" / "0.0" / "0.00" (no price data) returned as-is;
    caller decides whether to render them.
    """
    root = _parse_xml(xml_text)
    if root is None:
        return None
    loc = root if root.tag == "location" else root.find(".//location")
    if loc is None:
        return None

    poiname = _attr(loc, "poiname")
    if poiname in _LOC_PLACEHOLDER_NAMES:
        poiname = ""
    label = _attr(loc, "label")
    x = _attr(loc, "x")
    y = _attr(loc, "y")

    venue = poiname or label
    if not venue and not (x and y):
        return None

    return Location(
        venue=venue,
        category=_attr(loc, "poiCategoryTips"),
        address=label if (label and label != poiname) else "",
        hours=_attr(loc, "poiBusinessHour"),
        price=_attr(loc, "poiPriceTips"),
        x=x,
        y=y,
    )


# ── Red packet (app_type=2001) ───────────────────────────────────────────────

_REDPACK_SENDUSERNAME = re.compile(r"sendusername=([^&]+)")
_REDPACK_AMOUNT = re.compile(r"(\d+(?:\.\d+)?)\s*元")


@dataclass
class Redpack:
    """Structured red packet record.

    Verified across 7,748 real rows. `scene` distribution:
      - '微信红包' 98.81% — standard p2p / group red packet
      - '群收款'   1.03%  — group AA payment request
      - '活动账单' 0.14%  — event bill split
      - 'WeChat利是' 0.01% — Hong Kong red packet

    `amount` is INTENTIONALLY absent (privacy) for standard 红包; only
    群收款 / 活动账单 carry per-person amount in <senderdes>.

    `sender_wxid` is parsed from `<nativeurl>` URL params (sendusername=,
    97% populated). When absent, the caller can fall back to the row-level
    sender (sender_id == self_id) — `sender_wxid` will be the empty
    string in that case, signaling "fall back to row context".

    Lifecycle pairing is NOT supported for redpacks (vs transfers):
    `payer_username` / `receiver_username` are NEVER populated, and
    `paysubtype` is 89.6% empty / only '0' otherwise (useless for state).
    """
    scene: str
    sender_wxid: str = ""
    sender_title: str = ""       # user's greeting/label ('恭喜发财，大吉大利')
    amount_per_person: str = ""  # only for 群收款 / 活动账单, e.g. '138.34'


def parse_redpack(xml_text_or_appmsg):
    """Parse an app_type=2001 red packet. Accepts either the full message
    XML or an already-parsed `<appmsg>` Element.

    Returns None on malformed XML or missing `<wcpayinfo>`.
    """
    if isinstance(xml_text_or_appmsg, ET.Element):
        appmsg = xml_text_or_appmsg
    else:
        root = _parse_xml(xml_text_or_appmsg)
        if root is None:
            return None
        appmsg = root.find(".//appmsg")
        if appmsg is None:
            return None

    wcpay = appmsg.find(".//wcpayinfo")
    if wcpay is None:
        return None

    scene = _txt(wcpay, "scenetext")
    sender_title = _txt(wcpay, "sendertitle")
    nativeurl = _txt(wcpay, "nativeurl")

    sender_wxid = ""
    m = _REDPACK_SENDUSERNAME.search(nativeurl)
    if m:
        sender_wxid = m.group(1)

    amount = ""
    if scene in ("群收款", "活动账单"):
        m = _REDPACK_AMOUNT.search(_txt(wcpay, "senderdes"))
        if m:
            amount = m.group(1)

    return Redpack(
        scene=scene,
        sender_wxid=sender_wxid,
        sender_title=sender_title,
        amount_per_person=amount,
    )


# ── Transfer (app_type=2000) ─────────────────────────────────────────────────

# paysubtype label table — verified empirically against a 1495-row corpus.
# An earlier version (ported from upstream wxdec's older format helpers)
# labeled 8 as "已领取"; that was wrong — pst=8 pairs with pst=3 in 159
# cases (newer-version initiation, replacing pst=1). pst=9 also appears,
# paired with pst=4 (newer-version refund).
#   1, 8 — initiation (sender-side row; paired with 3)
#   3    — receipt acknowledgement (recipient-side row; sender_id flipped)
#   4, 9 — refund (paired together in newer versions)
#   5    — 24h auto-expire refund
#   7    — pending, awaiting receipt
TRANSFER_PAYSUBTYPE_LABEL = {
    "1": "发起转账",
    "8": "发起转账",
    "3": "已收款",
    "4": "已退还",
    "9": "已退还",
    "5": "过期已退还",
    "7": "待领取",
}

# Per-paysubtype trust rules for XML payer/receiver fields, verified
# empirically against a 1248-row corpus:
#   - 1, 8, 4, 5, 7, 9: fields describe transfer direction faithfully
#     when populated; trust unconditionally
#   - 3 (receipt-ack): ~14% of rows have FLIPPED `receiver_username`
#     (points at the message recipient = original sender, not original
#     receiver). The flipped rows are exactly those with only ONE of
#     payer/receiver populated; rows with BOTH fields are always
#     consistent. So accept pst=3 only when both fields are present.
_TRANSFER_DIRECTIONAL_PAYSUBTYPES = frozenset({"1", "8", "4", "5", "7", "9"})


@dataclass
class TransferInfo:
    """Structured transfer (微信转账) record extracted from one DB row.

    A single logical transfer spawns multiple DB rows (initiation,
    receipt-ack, refund, etc.) all sharing the same `transcationid`.
    Direction fields (`payer_username`, `receiver_username`) are
    sparsely populated per row — the initiation row often has them,
    lifecycle rows often don't. Use `pair_transfers()` to aggregate
    direction across a transcationid group.
    """
    paysubtype: str
    paysubtype_label: str
    fee_desc: str = ""
    pay_memo: str = ""
    transcationid: str = ""
    payer_username: str = ""
    receiver_username: str = ""


def _collapse(text):
    if not text:
        return ""
    return re.sub(r"\s+", " ", text).strip()


def parse_transfer(xml_text_or_appmsg):
    """Parse an app_type=2000 transfer. Accepts either the full message
    XML or an already-parsed `<appmsg>` Element. Returns None when
    `<wcpayinfo>` is absent.

    Field-name lookup tolerates WeChat 4.x version variants:
    feedesc/feeDesc, pay_memo/paymemo, transcationid/transcationId.
    """
    if isinstance(xml_text_or_appmsg, ET.Element):
        appmsg = xml_text_or_appmsg
    else:
        root = _parse_xml(xml_text_or_appmsg)
        if root is None:
            return None
        appmsg = root.find(".//appmsg")
        if appmsg is None:
            return None

    info_el = appmsg.find("wcpayinfo")
    if info_el is None:
        return None

    def _pick(*tags):
        for t in tags:
            v = _collapse(info_el.findtext(t) or "")
            if v:
                return v
        return ""

    paysubtype = _pick("paysubtype")
    label = TRANSFER_PAYSUBTYPE_LABEL.get(
        paysubtype,
        f"未知(paysubtype={paysubtype})" if paysubtype else "",
    )
    return TransferInfo(
        paysubtype=paysubtype,
        paysubtype_label=label,
        fee_desc=_pick("feedesc", "feeDesc"),
        pay_memo=_pick("pay_memo", "paymemo"),
        transcationid=_pick("transcationid", "transcationId"),
        payer_username=_pick("payer_username"),
        receiver_username=_pick("receiver_username"),
    )


def pair_transfers(infos):
    """Aggregate (payer, receiver) per transcationid across a chat's transfer
    rows. Returns `{transcationid: (payer_wxid, receiver_wxid)}`.

    Probe shows only ~10-15% of transfer rows have BOTH payer/receiver
    populated, but ANY row in a transcationid group with a non-empty
    field gives ground-truth direction for ALL rows in that group.

    Trust rules (see `_TRANSFER_DIRECTIONAL_PAYSUBTYPES` comment for why):
      - Trust paysubtypes {1, 8, 4, 5, 7, 9} unconditionally when present.
      - Trust paysubtype=3 only when BOTH payer and receiver are
        populated (single-field pst=3 rows are flipped 14% of the time).
      - Skip everything else.

    First non-empty value per field wins, so initiation-row direction
    takes precedence over later lifecycle rows.
    """
    out = {}
    for info in infos:
        tid = info.transcationid
        if not tid:
            continue
        pst = info.paysubtype
        payer = info.payer_username
        receiver = info.receiver_username
        if pst in _TRANSFER_DIRECTIONAL_PAYSUBTYPES:
            pass  # trust unconditionally
        elif pst == "3" and payer and receiver:
            pass
        else:
            continue
        cur_p, cur_r = out.get(tid, ("", ""))
        out[tid] = (cur_p or payer, cur_r or receiver)
    return out


# ── Finder feed (app_type=51, also embedded in Moments ContentObject) ────────


@dataclass
class FinderFeed:
    """Structured 视频号 finderFeed record.

    Shared between two contexts:
      - app_type=51 in chat messages (forwarded to private / group chat)
      - ContentObject/finderFeed in SnsTimeLine (forwarded to Moments)

    Empirical scan of 1268 real rows found 100% in the
    (feedType=4, liveId=0, mediaCount=1, mediaType=4) bucket — i.e.
    single-video. Other shapes (图文 / 直播 / 直播回放) were absent in
    that corpus.

    `subtype` is "视频" only for the empirically validated combo above;
    other dimension combinations return subtype=None as a visible signal
    that a new shape needs categorization.
    """
    nickname: str
    desc: str = ""
    biz_nickname: str = ""
    feed_type: int = 0
    live_id: int = 0
    media_count: int = 0
    media_type: int = 0
    video_play_duration: int = 0
    auth_icon_type: int = 0

    @property
    def subtype(self):
        if (self.feed_type == 4
                and self.live_id == 0
                and self.media_count == 1
                and self.media_type == 4):
            return "视频"
        return None


def parse_finder_feed(elem_or_xml):
    """Parse a `<finderFeed>` element (or XML text containing one) into a
    FinderFeed record. Returns None when the element is missing or has no
    nickname (caller renders bare `[视频号转发]` as fallback).
    """
    if isinstance(elem_or_xml, ET.Element):
        finder_el = (elem_or_xml if elem_or_xml.tag == "finderFeed"
                     else elem_or_xml.find(".//finderFeed"))
    elif elem_or_xml is None:
        return None
    else:
        root = _parse_xml(elem_or_xml)
        if root is None:
            return None
        finder_el = (root if root.tag == "finderFeed"
                     else root.find(".//finderFeed"))
    if finder_el is None:
        return None
    nickname = _txt(finder_el, "nickname")
    if not nickname:
        return None
    media_el = finder_el.find(".//mediaList/media")
    return FinderFeed(
        nickname=nickname,
        desc=_txt(finder_el, "desc"),
        biz_nickname=_txt(finder_el, "bizNickname"),
        feed_type=_safe_int(_txt(finder_el, "feedType")),
        live_id=_safe_int(_txt(finder_el, "liveId")),
        media_count=_safe_int(_txt(finder_el, "mediaCount")),
        media_type=(_safe_int(_txt(media_el, "mediaType"))
                    if media_el is not None else 0),
        video_play_duration=(_safe_int(_txt(media_el, "videoPlayDuration"))
                             if media_el is not None else 0),
        auth_icon_type=_safe_int(_txt(finder_el, "authIconType")),
    )
