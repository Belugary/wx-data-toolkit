"""
朋友圈 (SNS / Moments) 解析 CLI

读取已解密的 sns.db, 按 wxid + 日期范围筛选朋友圈条目, 输出 JSON 或可读文本。
本脚本只处理"解密后的 SQLite 文件"; 加密库的解密走项目现有的 `decrypt_db.py` 流程。

朋友圈数据流:
  1. SELECT tid, user_name, content FROM SnsTimeLine
  2. content 可能是: 纯 XML / hex 字符串 / base64 字符串 / zstd 压缩字节
  3. 解码为 UTF-8 XML 后, 提取 TimelineObject 的关键字段(createTime / contentDesc / media / 等)
  4. 按用户 wxid 与时间范围过滤, 输出

朋友圈 XML 解析独立重写, 参考来源:
  - LifeArchiveProject/WeChatDataAnalysis (XML 多层编码、伪 XML 净化、TimelineObject 字段)

媒体 ISAAC-64 keystream + XOR 解密在 sns_isaac.py 单独实现; 本脚本只输出
带 url/key/token 的元数据 JSON, 解密由调用方按需触发(参见 sns_isaac.py)。

未实现 (留待后续):
  - 把 sns_isaac 集成进来做 --decrypt-media 批量下载
  - 视频与公众号文章封面拉取
  - 评论 / 点赞列表展开
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

    策略: 保留 CDATA 块原样, 只对 CDATA 之外的 bare & 转成 &amp;。
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
    return "".join(parts)


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
        "location": "",
        "sourceName": "",
        "type": 0,
        "title": "",
        "contentUrl": "",
        "media": [],
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
    out["location"] = _findtext(tl, ".//location/poiName") or _findtext(tl, ".//location")

    for tag in ("appname", "sourceName", "sourcename"):
        v = _findtext(tl, f".//{tag}")
        if v:
            out["sourceName"] = v
            break

    out["type"] = _safe_int(_findtext(tl, ".//ContentObject/contentStyle")
                            or _findtext(tl, ".//ContentObject/type"))
    out["title"] = _findtext(tl, ".//ContentObject/title")
    out["contentUrl"] = _findtext(tl, ".//ContentObject/contentUrl")

    media: list[dict[str, Any]] = []
    for m in tl.findall(".//mediaList/media"):
        url_el = m.find("url")
        thumb_el = m.find("thumb")
        media.append({
            "type": _safe_int(_findtext(m, "type")),
            "id": _findtext(m, "id"),
            "url": (url_el.text.strip() if url_el is not None and url_el.text else ""),
            "urlAttrs": dict(url_el.attrib) if url_el is not None else {},
            "thumb": (thumb_el.text.strip() if thumb_el is not None and thumb_el.text else ""),
            "thumbAttrs": dict(thumb_el.attrib) if thumb_el is not None else {},
        })
    out["media"] = media

    return out


def resolve_sns_db(decrypted_dir: str, override: Optional[str]) -> str:
    """定位已解密的 sns.db 文件路径。

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
        f"请先运行 `python main.py decrypt` 解密, 或用 --db 显式指定路径"
    )


def _parse_date_utc(s: str) -> int:
    """YYYY-MM-DD -> 该日 00:00:00 UTC 的 unix 秒。"""
    dt = datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


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
            "sourceName": parsed["sourceName"],
            "type": parsed["type"],
            "title": parsed["title"],
            "contentUrl": parsed["contentUrl"],
            "media": parsed["media"],
        }
        if "_parseError" in parsed:
            post["_parseError"] = parsed["_parseError"]

        posts.append(post)
        if limit is not None and len(posts) >= limit:
            break

    return posts


def _infer_self_wxid_from_path(db_dir: str) -> Optional[str]:
    """从 db_dir 路径反推一个候选名: .../xwechat_files/<dir_name>/db_storage。

    注意 dir_name 不一定是真实 wxid: 微信 4.x 在 macOS 下目录名常带后缀,
    例如目录 `A_Hare_626a` 但表里的 wxid 是 `A_Hare`。这里只给候选, 是否真实
    存在要由 _resolve_self_wxid 用 sns.db 验证。
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

    回退规则: 候选 `A_Hare_626a` 时, 若表中存在 `A_Hare` 则返回 `A_Hare`。
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


def _build_argparser(path_hint: Optional[str], default_decrypted_dir: str) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="decrypt_sns.py",
        description="按 wxid + 日期筛选朋友圈, 输出 JSON。需要先 `python main.py decrypt` 把 sns.db 解密出来。",
    )
    p.add_argument(
        "--db",
        help=f"已解密的 sns.db 路径(默认在 {default_decrypted_dir}/sns/ 下查找)",
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
