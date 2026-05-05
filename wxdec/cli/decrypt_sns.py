"""
朋友圈 (SNS / Moments) 解析 CLI

读取已导出的 sns.db, 按 wxid + 日期范围筛选朋友圈条目, 输出 JSON 或可读文本。
本脚本只处理"已导出的标准 SQLite 文件"; 加密库的导出走项目现有的 `decrypt_db.py` 流程。

朋友圈数据流:
  1. SELECT tid, user_name, content FROM SnsTimeLine
  2. content 可能是: 纯 XML / hex 字符串 / base64 字符串 / zstd 压缩字节
  3. 解码为 UTF-8 XML 后, 提取 TimelineObject 的关键字段(createTime / contentDesc / media / 等)
  4. 按用户 wxid 与时间范围过滤, 输出
  5. (可选 --decrypt-media)拉 CDN URL + 用 sns_isaac XOR 还原 + 落盘 <md5>.<ext>

朋友圈 XML 解析独立重写, 参考来源:
  - LifeArchiveProject/WeChatDataAnalysis (XML 多层编码、伪 XML 净化、TimelineObject 字段)

媒体下载 + 还原在 --decrypt-media 模式下进行, 协议参考:
  - https://github.com/teest114514/chatlog_alpha (URL fix 规则: /150→/0, ?token&idx=1)
  - https://github.com/hicccc77/WeFlow (CDN 必须 `User-Agent: MicroMessenger Client`)
ISAAC-64 keystream 生成由 sns_isaac.py 提供; 本脚本不依赖 WASM, 纯 Python clean-room。

未实现 (留待后续):
  - 公众号文章封面拉取
  - 视频号转发的视频内容获取(本项目仅采集 finderFeed metadata)
"""
import argparse
import base64
import glob
import html
import json
import os
import re
import sqlite3
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Optional

import functools
print = functools.partial(print, flush=True)

from wxdec.config import load_config


_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/=]+$")

# 净化伪 XML 用的正则
_INVALID_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_CDATA_BLOCK_RE = re.compile(r"<!\[CDATA\[.*?\]\]>", re.DOTALL)
_BARE_AMP_RE = re.compile(r"&(?!(amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);)")

# 老版本微信 (2013-2017) 在 contentDesc / title / description / content / nickname
# 等纯文本节点内允许用户输入字面量 < > (例如颜文字、书名号), 没做 XML escape,
# 导致 ET 把它们当未闭合标签 -> "mismatched tag" 或 "not well-formed"。
# 这里识别已知 text-only 节点的内部, 把 raw < > 转义掉; 合法 XML 路径不受影响。
_TEXT_ONLY_NODES = ("content", "title", "description", "nickname",
                    "contentDesc", "appname", "sourceName", "sourcename",
                    "poiName", "displayName", "feeddesc")
_TEXT_NODE_RE = re.compile(
    r"(<(" + "|".join(_TEXT_ONLY_NODES) + r")\b[^>]*>)(.*?)(</\2>)",
    re.DOTALL,
)


def _escape_lt_gt_in_text_nodes(xml_text: str) -> str:
    """对 _TEXT_ONLY_NODES 列举的元素内部, 把 raw < > 转成 &lt; &gt;。

    & 已由调用方先做过 _BARE_AMP_RE 处理, 这里不再 escape & (避免破坏已正确
    转义的 &amp;)。
    """
    def repl(m: re.Match) -> str:
        open_tag, _, text, close_tag = m.group(1), m.group(2), m.group(3), m.group(4)
        text = text.replace("<", "&lt;").replace(">", "&gt;")
        return open_tag + text + close_tag

    return _TEXT_NODE_RE.sub(repl, xml_text)


def _try_zstd_decompress(raw: bytes) -> bytes:
    """若 raw 以 zstd magic 开头, 返回解压结果; 否则原样返回。

    zstandard 库可选: 没装时遇到压缩数据会跳过 (返回原 raw, 后续解析会失败)。
    """
    if not raw.startswith(_ZSTD_MAGIC):
        return raw
    try:
        import zstandard as zstd  # type: ignore
        return zstd.ZstdDecompressor().decompress(raw)
    except ImportError:
        print("[!] 检测到 zstd 压缩内容, 但未安装 zstandard 库; pip install zstandard", file=sys.stderr)
        return raw


def _decode_blob_to_xml(value: Any) -> str:
    """把 SnsTimeLine.content 字段解码为 UTF-8 XML 字符串。

    支持的输入形式 (按检测顺序):
      1. bytes: 直接解(zstd 解压 -> utf-8)
      2. str 且看起来像 XML: 直接 unescape 返回
      3. 全十六进制字符串: 先 hex 解码 -> 走 bytes 路径
      4. 全 base64 字符串: 先 base64 解码 -> 走 bytes 路径
    """
    if value is None:
        return ""

    if isinstance(value, bytes):
        raw = _try_zstd_decompress(value)
        return html.unescape(raw.decode("utf-8", errors="ignore").strip())

    text = str(value).strip()
    if not text:
        return ""

    # 已经像 XML
    if text.lstrip().startswith("<"):
        return html.unescape(text)

    # 尝试 hex
    compact = "".join(text.split())
    if len(compact) >= 16 and len(compact) % 2 == 0 and _HEX_RE.match(compact):
        try:
            return _decode_blob_to_xml(bytes.fromhex(compact))
        except ValueError:
            pass

    # 尝试 base64
    if len(compact) >= 24 and len(compact) % 4 == 0 and _BASE64_RE.match(compact):
        try:
            return _decode_blob_to_xml(base64.b64decode(compact, validate=True))
        except (ValueError, base64.binascii.Error):
            pass

    # 啥也不是, 原样返回 (可能是已损坏数据)
    return html.unescape(text)


def _sanitize_xml(xml_text: str) -> str:
    """修复微信"伪 XML": URL 里 bare & 没转义会让 ElementTree 炸。

    策略:
      1. 去除非法控制字符
      2. 保留 CDATA 块原样, 对 CDATA 外 bare & 转成 &amp;
      3. 老版本(2013-2017)用户在 content/title 等纯文本字段里写过 raw < > 字符
         (颜文字 "<o>_<o"、书名号 "<杞菊雪梨饮>"), 在这些已知 text-only 节点
         内部把 < > 转义。
    """
    s = _INVALID_CTRL_RE.sub("", xml_text)

    parts: list[str] = []
    last = 0
    for m in _CDATA_BLOCK_RE.finditer(s):
        head = s[last:m.start()]
        parts.append(_BARE_AMP_RE.sub("&amp;", head))
        parts.append(m.group(0))
        last = m.end()
    parts.append(_BARE_AMP_RE.sub("&amp;", s[last:]))
    out = "".join(parts)
    out = _escape_lt_gt_in_text_nodes(out)
    return out


def _safe_int(v: Any) -> int:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return 0


def _findtext(root: ET.Element, path: str) -> str:
    el = root.find(path)
    if el is None or el.text is None:
        return ""
    return el.text.strip()


def parse_timeline_xml(xml_text: str, fallback_username: str = "") -> dict[str, Any]:
    """把朋友圈 XML 解析成结构化 dict。

    返回字段(尽量覆盖常用): username, createTime, contentDesc, location,
    sourceName, type, title, contentUrl, media[]
    """
    out: dict[str, Any] = {
        "username": fallback_username,
        "createTime": 0,
        "contentDesc": "",
        # 兼容字段: poiName 优先, 否则空。完整位置信息在 locationDetail。
        "location": "",
        # 完整位置: poiName / poiAddress / poiAddressName / city / country
        # / latitude / longitude / poiClassifyId / poiScale。空字典 = 该帖无位置。
        "locationDetail": {},
        "sourceName": "",
        "type": 0,
        "title": "",
        "contentUrl": "",
        "media": [],
        # 视频(media.type=6)的 ISAAC seed: 来自 <enc key="..."/> 而不是 <url key="0"/>。
        # 通常 post 级别 + 各 media 内重复, 这里取最近一个。WeFlow extractVideoKey 同源。
        "videoEncKey": "",
        # 私密帖(只自己可见)
        "isPrivate": False,
        # 视频号转发: ContentObject 内 <finderFeed> 节点。空字典 = 非视频号转发。
        # 字段: objectId / username / nickname / desc / feedType / mediaCount /
        # media[] (mediaType / url / thumbUrl / coverUrl / width / height / videoPlayDuration)。
        # url 是视频号 CDN, 协议不同于朋友圈媒体, 本项目不解密只采集 metadata。
        "finderFeed": {},
    }

    if not xml_text.strip():
        return out

    try:
        root = ET.fromstring(_sanitize_xml(xml_text))
    except ET.ParseError as e:
        out["_parseError"] = f"{e}"
        return out

    # 规范化到 TimelineObject 节点: ET 的 .// 不匹配 root 自身, 所以两种结构都得兼容
    tl = root if root.tag == "TimelineObject" else root.find(".//TimelineObject")
    if tl is None:
        out["_parseError"] = "no TimelineObject element"
        return out

    out["username"] = _findtext(tl, "username") or fallback_username
    out["createTime"] = _safe_int(_findtext(tl, "createTime"))
    out["contentDesc"] = _findtext(tl, "contentDesc")

    # location: 微信存的是 attribute 而不是 child element。之前用 _findtext 永远抓空。
    # poiName / poiAddress 等只有用户主动选择 poi 时填充; 仅经纬度发的帖子只有 lat/lon/city。
    loc_el = tl.find(".//location")
    if loc_el is not None:
        loc_attrs = dict(loc_el.attrib)
        # 过滤无意义零值, 只保留实际填充的字段
        out["locationDetail"] = {
            k: v for k, v in loc_attrs.items()
            if v and v not in ("0", "0.0", "0.000000")
        }
        # 兼容字段: poiName 最具可读性, 没有就退化到 city, 都没有就空字符串
        out["location"] = (
            loc_attrs.get("poiName")
            or loc_attrs.get("poiAddressName")
            or loc_attrs.get("city")
            or ""
        ).strip()

    for tag in ("appname", "sourceName", "sourcename"):
        v = _findtext(tl, f".//{tag}")
        if v:
            out["sourceName"] = v
            break

    out["type"] = _safe_int(_findtext(tl, ".//ContentObject/contentStyle")
                            or _findtext(tl, ".//ContentObject/type"))
    out["title"] = _findtext(tl, ".//ContentObject/title")
    out["contentUrl"] = _findtext(tl, ".//ContentObject/contentUrl")
    out["isPrivate"] = _findtext(tl, ".//private") == "1"

    # 视频号转发: <ContentObject>/<finderFeed>。url 是视频号 CDN, 不解密只采集 metadata。
    finder_el = tl.find(".//ContentObject/finderFeed")
    if finder_el is not None:
        finder_media = []
        for fm in finder_el.findall(".//mediaList/media"):
            finder_media.append({
                "mediaType": _safe_int(_findtext(fm, "mediaType")),
                "url": _findtext(fm, "url"),
                "thumbUrl": _findtext(fm, "thumbUrl"),
                "coverUrl": _findtext(fm, "coverUrl"),
                "fullCoverUrl": _findtext(fm, "fullCoverUrl"),
                "width": _safe_int(_findtext(fm, "width")),
                "height": _safe_int(_findtext(fm, "height")),
                "videoPlayDuration": _safe_int(_findtext(fm, "videoPlayDuration")),
            })
        out["finderFeed"] = {
            "objectId": _findtext(finder_el, "objectId"),
            "objectNonceId": _findtext(finder_el, "objectNonceId"),
            "feedType": _safe_int(_findtext(finder_el, "feedType")),
            "username": _findtext(finder_el, "username"),
            "nickname": _findtext(finder_el, "nickname"),
            "avatar": _findtext(finder_el, "avatar"),
            "desc": _findtext(finder_el, "desc"),
            "liveId": _findtext(finder_el, "liveId"),
            "mediaCount": _safe_int(_findtext(finder_el, "mediaCount")),
            "media": finder_media,
        }

    # <enc key="..."/> 同时存在于 ContentObject 顶层 + 各 <media> 内部, 通常一致。
    # find(".//enc") 取深度优先第一个; 视频还原走 post-level 这一个值。
    enc_el = tl.find(".//enc")
    if enc_el is not None:
        out["videoEncKey"] = (enc_el.attrib.get("key") or "").strip()

    media: list[dict[str, Any]] = []
    for m in tl.findall(".//mediaList/media"):
        url_el = m.find("url")
        thumb_el = m.find("thumb")
        size_el = m.find("size")
        media.append({
            "type": _safe_int(_findtext(m, "type")),
            "id": _findtext(m, "id"),
            "subType": _findtext(m, "sub_type"),
            "description": _findtext(m, "description"),
            "url": (url_el.text.strip() if url_el is not None and url_el.text else ""),
            "urlAttrs": dict(url_el.attrib) if url_el is not None else {},
            "thumb": (thumb_el.text.strip() if thumb_el is not None and thumb_el.text else ""),
            "thumbAttrs": dict(thumb_el.attrib) if thumb_el is not None else {},
            # 像素尺寸 + 字节大小; 缺失或为空字典表示该媒体无 size 节点
            "size": dict(size_el.attrib) if size_el is not None else {},
            # 视频时长(秒, 文本)。图片帖子也有这个 child 但通常为空。
            "videoDuration": _findtext(m, "videoDuration"),
        })
    out["media"] = media

    return out


def resolve_sns_db(decrypted_dir: str, override: Optional[str]) -> str:
    """定位已导出的 sns.db 文件路径。

    优先级:
      1. override (--db 参数) 显式指定
      2. {decrypted_dir}/sns/sns.db
      3. {decrypted_dir}/sns/*.db (取首个)
      4. {decrypted_dir}/**/sns*.db (兜底搜索)
    """
    if override:
        if not os.path.isfile(override):
            raise FileNotFoundError(f"指定的 sns.db 不存在: {override}")
        return override

    candidate = os.path.join(decrypted_dir, "sns", "sns.db")
    if os.path.isfile(candidate):
        return candidate

    matches = sorted(glob.glob(os.path.join(decrypted_dir, "sns", "*.db")))
    if matches:
        return matches[0]

    matches = sorted(glob.glob(os.path.join(decrypted_dir, "**", "sns*.db"), recursive=True))
    if matches:
        return matches[0]

    raise FileNotFoundError(
        f"在 {decrypted_dir} 下找不到朋友圈数据库; "
        f"请先运行 `python main.py decrypt` 导出, 或用 --db 显式指定路径"
    )


def _parse_date_utc(s: str) -> int:
    """YYYY-MM-DD -> 该日 00:00:00 UTC 的 unix 秒。"""
    dt = datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def query_interactions(
    db_path: str, post_tids: Optional[list[int]] = None
) -> dict[int, dict[str, list]]:
    """从 SnsMessage_tmp3 拉点赞 / 评论, 按 feed_id (= SnsTimeLine.tid) 聚合。

    SnsMessage_tmp3.type 语义:
      type=1 -> 点赞: content 通常为空, 互动方在 from_username/from_nickname/create_time
      type=2 -> 评论: content 是评论文本; 其余同上, 加 comment_id 用于回复关系

    SnsMessage_tmp3 表对 self 帖子专用 (to_username = self), 不区分别人帖子的互动。
    `post_tids` 给定时仅 IN 过滤; 否则全表读 (sns.db 通常 < 10K 行)。

    返回: {feed_id: {"likes": [...], "comments": [...]}}
    每个 like / comment dict 字段: from / nickname / time(int) / timeIso(str)。
    评论额外有 content / commentId / commentId64。
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        if post_tids:
            placeholders = ",".join("?" for _ in post_tids)
            sql = (
                "SELECT type, feed_id, from_username, from_nickname, content, "
                "create_time, comment_id, comment64_id "
                f"FROM SnsMessage_tmp3 WHERE feed_id IN ({placeholders}) "
                "ORDER BY create_time"
            )
            params: list[Any] = list(post_tids)
        else:
            sql = (
                "SELECT type, feed_id, from_username, from_nickname, content, "
                "create_time, comment_id, comment64_id "
                "FROM SnsMessage_tmp3 ORDER BY create_time"
            )
            params = []
        rows = conn.execute(sql, params).fetchall()
    except sqlite3.OperationalError:
        # SnsMessage_tmp3 不存在 (老版本 sns.db)。视为零互动而非报错。
        return {}
    finally:
        conn.close()

    out: dict[int, dict[str, list]] = {}
    for r in rows:
        feed_id = r["feed_id"]
        bucket = out.setdefault(feed_id, {"likes": [], "comments": []})
        ct = r["create_time"] or 0
        ct_iso = (
            datetime.fromtimestamp(ct, tz=timezone.utc).isoformat()
            if ct else ""
        )
        base = {
            "from": r["from_username"] or "",
            "nickname": r["from_nickname"] or "",
            "time": ct,
            "timeIso": ct_iso,
        }
        if r["type"] == 1:  # like
            bucket["likes"].append(base)
        elif r["type"] == 2:  # comment
            bucket["comments"].append({
                **base,
                "content": r["content"] or "",
                "commentId": r["comment_id"] or 0,
                "commentId64": r["comment64_id"] or 0,
            })
        # 其它 type 暂时观察, 不入桶
    return out


def query_sns(
    db_path: str,
    *,
    user: Optional[str],
    start_ts: int,
    end_ts: int,
    include_cover: bool,
    limit: Optional[int],
) -> list[dict[str, Any]]:
    """从 sns.db 拉数据 + 按 wxid 过滤(SQL) + 按日期过滤(parsed XML)。

    日期过滤必须在 XML 解析之后做, 因为 createTime 不在 SQL 列里。
    互动 (likes/comments) 来自 SnsMessage_tmp3, 按 tid 关联。
    """
    sql = "SELECT tid, user_name, content FROM SnsTimeLine"
    params: list[Any] = []
    if user:
        sql += " WHERE user_name = ?"
        params.append(user)
    sql += " ORDER BY tid DESC"

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(sql, params).fetchall()
    finally:
        conn.close()

    interactions = query_interactions(db_path)

    posts: list[dict[str, Any]] = []
    for r in rows:
        tid = r["tid"]
        username = r["user_name"] or ""
        content = r["content"]

        xml_text = _decode_blob_to_xml(content)
        parsed = parse_timeline_xml(xml_text, fallback_username=username)

        # type=7 是朋友圈封面背景图; 默认排除
        if not include_cover and parsed["type"] == 7:
            continue

        ct = parsed["createTime"]
        if start_ts and ct and ct < start_ts:
            continue
        if end_ts and ct and ct >= end_ts:
            continue

        ix = interactions.get(tid, {"likes": [], "comments": []})
        post = {
            "tid": tid,
            "username": parsed["username"] or username,
            "createTime": ct,
            "createTimeIso": (
                datetime.fromtimestamp(ct, tz=timezone.utc).isoformat()
                if ct else ""
            ),
            "contentDesc": parsed["contentDesc"],
            "location": parsed["location"],
            "locationDetail": parsed["locationDetail"],
            "sourceName": parsed["sourceName"],
            "type": parsed["type"],
            "title": parsed["title"],
            "contentUrl": parsed["contentUrl"],
            "media": parsed["media"],
            "videoEncKey": parsed["videoEncKey"],
            "isPrivate": parsed["isPrivate"],
            "finderFeed": parsed["finderFeed"],
            "likes": ix["likes"],
            "comments": ix["comments"],
        }
        if "_parseError" in parsed:
            post["_parseError"] = parsed["_parseError"]

        posts.append(post)
        if limit is not None and len(posts) >= limit:
            break

    return posts


def _infer_self_wxid_from_path(db_dir: str) -> Optional[str]:
    """从 db_dir 路径反推一个候选名: .../xwechat_files/<dir_name>/db_storage。

    注意 dir_name 不一定是真实 wxid: 微信 4.x 在 macOS 下目录名常带 4 字符
    hex 后缀, 例如目录 `your_wxid_a1b2` 但表里的 wxid 是 `your_wxid`。这里
    只给候选, 是否真实存在要由 _resolve_self_wxid 用 sns.db 验证。
    """
    parent = os.path.dirname(db_dir.rstrip(os.sep))
    if not parent:
        return None
    name = os.path.basename(parent)
    if name and name not in ("xwechat_files", "your_wxid"):
        return name
    return None


def _resolve_self_wxid(db_path: str, candidate: Optional[str]) -> Optional[str]:
    """用 sns.db 里实际存在的 user_name 验证候选 wxid; 不匹配时尝试前缀回退。

    回退规则: 候选 `your_wxid_a1b2` 时, 若表中存在 `your_wxid` 则返回 `your_wxid`。
    都不行就返回 None, 由调用方决定是否降级为"查全部"。
    """
    if not candidate:
        return None
    try:
        conn = sqlite3.connect(db_path)
        users = {r[0] for r in conn.execute(
            "SELECT DISTINCT user_name FROM SnsTimeLine WHERE user_name IS NOT NULL"
        ) if r[0]}
        conn.close()
    except sqlite3.Error:
        return candidate

    if candidate in users:
        return candidate
    for u in users:
        if u and candidate.startswith(u + "_"):
            return u
    return None


# ---------- media download + decrypt (--decrypt-media 模式) ----------

# WeChat CDN(szmmsns.qpic.cn)拒绝非 MicroMessenger UA, 即便带正确 token。
# 浏览器 / curl 默认 UA 一律 400。来源: WeFlow snsService.ts。
_SNS_UA = "MicroMessenger Client"
_DEFAULT_TIMEOUT = 30
_DEFAULT_MAX_BYTES = 20 * 1024 * 1024
# 视频默认 100MB 上限: 给足缓冲避免大视频被截断。
_DEFAULT_VIDEO_MAX_BYTES = 100 * 1024 * 1024


def _fix_sns_url(raw_url: str, token: str, *, is_video: bool = False) -> str:
    """规范化 SNS CDN URL 以便能拿到全图原始字节。

    图片(默认):
      - http -> https(腾讯 CDN 已强制 TLS)
      - 路径以 /150 结尾(thumb 缩略图, referer-locked)→ 改 /0(全图)
      - query 加 ?token=<token>&idx=1(CDN 签名)

    视频(is_video=True): 不替换 /150 段(视频 URL 路径形态不同), 且 token / idx
    放在 query 最前面 (CDN 对参数顺序敏感)。

    来源: chatlog_alpha(图片)+ WeFlow snsService.ts.fixSnsUrl(视频)
    """
    if not raw_url:
        return raw_url
    fixed = raw_url.replace("http://", "https://", 1)
    if not is_video:
        if fixed.endswith("/150"):
            fixed = fixed[:-4] + "/0"
        elif fixed.endswith("/150/"):
            fixed = fixed[:-5] + "/0"
    if token and "token=" not in fixed:
        if is_video:
            # 视频: token / idx 必须在最前
            base, _, existing = fixed.partition("?")
            tail = f"&{existing}" if existing else ""
            fixed = f"{base}?token={token}&idx=1{tail}"
        else:
            sep = "&" if "?" in fixed else "?"
            fixed = f"{fixed}{sep}token={token}&idx=1"
    return fixed


def _detect_image_ext(data: bytes) -> Optional[str]:
    """Return file extension based on magic bytes; None if unknown.

    Mirrors sns_isaac.detect_image_kind but returns the on-disk ext rather
    than the format name.
    """
    if not data or len(data) < 8:
        return None
    if data[:3] == b"\xff\xd8\xff":
        return "jpg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if data[:4] == b"RIFF" and len(data) >= 12 and data[8:12] == b"WEBP":
        return "webp"
    if data[:2] == b"BM":
        return "bmp"
    return None


def _download_and_decrypt_one(
    raw_url: str,
    token: str,
    key: str,
    md5: str,
    out_dir: str,
    *,
    timeout: int = _DEFAULT_TIMEOUT,
    max_size: int = _DEFAULT_MAX_BYTES,
) -> tuple[Optional[str], str]:
    """下载一张 SNS 图、用 ISAAC-64 keystream XOR 解密、落盘 <out_dir>/<md5>.<ext>。

    命名取 urlAttrs.md5(每张图独立, 全局去重); key 是同一帖子内多张图共享的
    ISAAC seed, 不能用于命名。同一张图被多次发送 → md5 一致 → 只存一份。

    幂等: out_dir 下已有 <md5>.* 时直接返回该路径(状态 "skip-existing")。
    安全: 写 <md5>.<ext>.part, 解密 + magic 校验通过后 rename, 失败不污染目标。

    Returns (saved_path_or_none, status_string)。状态字符串前缀:
      ok / skip-* / error-*
    """
    if not raw_url:
        return None, "skip-no-url"
    if not key or str(key) in ("0", ""):
        return None, "skip-no-key"
    if not md5:
        return None, "skip-no-md5"

    # idempotency: any existing <md5>.* counts as "already done".
    existing = glob.glob(os.path.join(out_dir, f"{md5}.*"))
    existing = [p for p in existing if not p.endswith(".part")]
    if existing:
        return existing[0], "skip-existing"

    fixed_url = _fix_sns_url(raw_url, token)
    req = urllib.request.Request(
        fixed_url,
        headers={"User-Agent": _SNS_UA, "Accept": "*/*", "Connection": "keep-alive"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            x_enc = resp.headers.get("X-Enc", "").strip()
            cl = resp.headers.get("Content-Length")
            if cl and int(cl) > max_size:
                return None, "error-too-big"
            payload = resp.read(max_size + 1)
            if len(payload) > max_size:
                return None, "error-too-big"
    except urllib.error.HTTPError as e:
        return None, f"error-http-{e.code}"
    except urllib.error.URLError as e:
        return None, f"error-url"

    if x_enc == "1":
        # In-process XOR decrypt; sns_isaac is a pure-Python module, no WASM.
        from wxdec.sns_isaac import decrypt_image_bytes
        try:
            data = decrypt_image_bytes(payload, key)
        except Exception as e:
            print(f"[!] decrypt failed for key={key}: {e}", file=sys.stderr)
            return None, "error-decrypt"
    else:
        # No X-Enc header → either CDN returned a non-encrypted variant or this
        # url isn't an encrypted resource at all. Try as-is; magic check below
        # is the final gate.
        data = payload

    ext = _detect_image_ext(data)
    if not ext:
        return None, "error-bad-magic"

    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{md5}.{ext}")
    tmp_path = out_path + ".part"
    with open(tmp_path, "wb") as f:
        f.write(data)
    os.replace(tmp_path, out_path)
    return out_path, "ok"


def _download_video_one(
    raw_url: str,
    token: str,
    key: str,
    md5: str,
    out_dir: str,
    *,
    timeout: int = _DEFAULT_TIMEOUT,
    max_size: int = _DEFAULT_VIDEO_MAX_BYTES,
) -> tuple[Optional[str], str]:
    """下载朋友圈视频、用 ISAAC-64 keystream XOR 前 128KB 还原, 落盘 <md5>.mp4。

    与图片版本的关键差异:
      - seed 来自 post 级别的 <enc key="..."/>(图片用 media 级 url.key)
      - 只 XOR 前 SNS_VIDEO_HEAD_SIZE 字节, 余下原样
      - 必须 ftyp 校验通过才落盘(seed 错时彻底不写文件)
      - URL token 在 query 最前面(CDN 对参数顺序敏感)

    幂等: out_dir 下已有 <md5>.mp4 直接 skip-existing。
    安全: <md5>.mp4.part 临时落盘 → 解密 + ftyp 校验通过 → rename。
    """
    if not raw_url:
        return None, "skip-no-url"
    if not key or str(key) in ("0", ""):
        return None, "skip-no-key"
    if not md5:
        return None, "skip-no-md5"

    out_path = os.path.join(out_dir, f"{md5}.mp4")
    if os.path.isfile(out_path):
        return out_path, "skip-existing"

    fixed_url = _fix_sns_url(raw_url, token, is_video=True)
    req = urllib.request.Request(
        fixed_url,
        headers={"User-Agent": _SNS_UA, "Accept": "*/*", "Connection": "keep-alive"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            cl = resp.headers.get("Content-Length")
            if cl and int(cl) > max_size:
                return None, "error-too-big"
            payload = resp.read(max_size + 1)
            if len(payload) > max_size:
                return None, "error-too-big"
    except urllib.error.HTTPError as e:
        return None, f"error-http-{e.code}"
    except urllib.error.URLError:
        return None, "error-url"

    from wxdec.sns_isaac import decrypt_video_bytes, detect_mp4

    if detect_mp4(payload[:8]):
        # 服务端罕见地直接给明文(看到 X-Enc 缺失或服务端策略变更), 不重复 XOR
        plain = payload
    else:
        plain = decrypt_video_bytes(payload, key)
        if plain is None:
            return None, "error-bad-magic"

    os.makedirs(out_dir, exist_ok=True)
    tmp_path = out_path + ".part"
    with open(tmp_path, "wb") as f:
        f.write(plain)
    os.replace(tmp_path, out_path)
    return out_path, "ok"


def decrypt_media_for_posts(posts: list, out_dir: str) -> dict:
    """按帖子遍历 media 项, 下载 + 还原 + 落盘, mutate `media` dict 加 `localPath`。

    支持: 图片(media.type ∈ {1, 2})+ 视频(media.type == 6)。
    视频用 post 级别的 <enc key="..."/> 作为 ISAAC seed; 图片用 media url.key。

    out_dir 下产物:
      - 图片 <md5>.<jpg|png|gif|webp|bmp>(全局去重 by md5)
      - 视频 <videomd5>.mp4(同样按 videomd5 全局去重)
    """
    counts: dict[str, int] = {}
    saved = errors = total = 0

    for post in posts:
        post_video_key = str(post.get("videoEncKey") or "")
        for m in post.get("media", []):
            mtype = m.get("type")
            attrs = m.get("urlAttrs", {}) or {}
            url = m.get("url") or ""
            token = str(attrs.get("token", ""))

            if mtype in (1, 2):
                key = str(attrs.get("key", ""))
                md5 = str(attrs.get("md5", ""))
                total += 1
                saved_path, status = _download_and_decrypt_one(url, token, key, md5, out_dir)
            elif mtype == 6:
                md5 = str(attrs.get("videomd5", "") or attrs.get("md5", ""))
                total += 1
                saved_path, status = _download_video_one(url, token, post_video_key, md5, out_dir)
            else:
                continue

            counts[status] = counts.get(status, 0) + 1
            if saved_path:
                m["localPath"] = saved_path
            if status == "ok":
                saved += 1
            elif status.startswith("error"):
                errors += 1

    skipped = total - saved - errors
    print(
        f"[+] SNS 媒体: 共 {total} 项, 还原 {saved}, 跳过 {skipped}, 失败 {errors}",
        file=sys.stderr,
    )
    if counts:
        detail = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        print(f"    分项: {detail}", file=sys.stderr)
    return {"total": total, "saved": saved, "skipped": skipped, "errors": errors,
            "detail": counts}


def _build_argparser(path_hint: Optional[str], default_decrypted_dir: str) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="decrypt_sns.py",
        description="按 wxid + 日期筛选朋友圈, 输出 JSON。需要先 `python main.py decrypt` 把 sns.db 导出。",
    )
    p.add_argument(
        "--db",
        help=f"已导出的 sns.db 路径(默认在 {default_decrypted_dir}/sns/ 下查找)",
    )
    p.add_argument(
        "--user",
        default=None,
        help=(
            f"按发布者 wxid 过滤; 不传则自动从 sns.db 解析当前账号 "
            f"(路径候选: {path_hint or '(未识别)'})。用 --all-users 查所有人。"
        ),
    )
    p.add_argument("--all-users", action="store_true", help="查所有人, 覆盖自动推断")
    p.add_argument("--date", help="单日(等价于 --start=DATE --end=DATE+1, 单位 UTC), 形如 2024-06-15")
    p.add_argument("--start", help="起始日期(含, UTC), 形如 2024-06-15")
    p.add_argument("--end", help="结束日期(不含, UTC), 形如 2024-06-16")
    p.add_argument("--limit", type=int, default=None, help="最多输出条数")
    p.add_argument("--include-cover", action="store_true", help="包含 type=7 封面背景图(默认排除)")
    p.add_argument(
        "--decrypt-media",
        action="store_true",
        help="拉 CDN URL + 用 sns_isaac XOR 还原原图, 落盘 <image-out-dir>/<key>.<ext>",
    )
    p.add_argument(
        "--image-out-dir",
        default=None,
        help="还原后图片落盘目录(默认 <decoded_image_dir>/sns/)",
    )
    p.add_argument("-o", "--output", help="JSON 输出文件路径(默认 stdout)")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    cfg = load_config()
    db_dir = cfg.get("db_dir", "")
    decrypted_dir = cfg.get("decrypted_dir", "decrypted")
    path_hint = _infer_self_wxid_from_path(db_dir)

    args = _build_argparser(path_hint, decrypted_dir).parse_args(argv)

    # 时间窗口
    if args.date and (args.start or args.end):
        print("[!] --date 与 --start/--end 不能同时使用", file=sys.stderr)
        return 2
    if args.date:
        start_ts = _parse_date_utc(args.date)
        end_ts = start_ts + 86400
    else:
        start_ts = _parse_date_utc(args.start) if args.start else 0
        end_ts = _parse_date_utc(args.end) if args.end else 0

    # 定位 sns.db
    db_path = resolve_sns_db(decrypted_dir, args.db)
    print(f"[*] 读取: {db_path}", file=sys.stderr)

    # 解析发布者过滤(--user 显式 > --all-users > 路径候选 + sns.db 验证)
    if args.all_users:
        user: Optional[str] = None
    elif args.user:
        user = args.user
    else:
        user = _resolve_self_wxid(db_path, path_hint)
        if user:
            note = "" if user == path_hint else f" (路径候选 {path_hint!r}, 前缀回退)"
            print(f"[*] 自动识别当前账号: {user}{note}", file=sys.stderr)
        else:
            print(
                f"[!] 路径候选 {path_hint!r} 未在数据库中匹配, 降级为查询所有人; "
                f"用 --user <wxid> 手动指定可缩小范围",
                file=sys.stderr,
            )

    if user:
        print(f"[*] 发布者过滤: {user}", file=sys.stderr)
    else:
        print(f"[*] 不限发布者", file=sys.stderr)
    if start_ts or end_ts:
        start_label = (
            datetime.fromtimestamp(start_ts, tz=timezone.utc).strftime("%Y-%m-%d")
            if start_ts else "-∞"
        )
        end_label = (
            datetime.fromtimestamp(end_ts, tz=timezone.utc).strftime("%Y-%m-%d")
            if end_ts else "+∞"
        )
        print(f"[*] 时间窗(UTC): [{start_label}, {end_label})", file=sys.stderr)

    posts = query_sns(
        db_path,
        user=user,
        start_ts=start_ts,
        end_ts=end_ts,
        include_cover=args.include_cover,
        limit=args.limit,
    )

    if args.decrypt_media:
        decoded_image_dir = cfg.get("decoded_image_dir") or "decoded_images"
        decoded_image_dir = os.path.expanduser(decoded_image_dir)
        out_dir = args.image_out_dir or os.path.join(decoded_image_dir, "sns")
        out_dir = os.path.expanduser(out_dir)
        print(f"[*] 还原 SNS 媒体到: {out_dir}", file=sys.stderr)
        decrypt_media_for_posts(posts, out_dir)

    payload = json.dumps(posts, ensure_ascii=False, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(payload)
        print(f"[+] 写入 {len(posts)} 条到 {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(payload + "\n")

    print(f"[+] 命中 {len(posts)} 条", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
