"""
Message formatting — pure functions, no project dependencies.

All state (like contact name dicts) is passed as parameters.
"""

import os
import re
import sqlite3
import hashlib
import xml.etree.ElementTree as ET
from datetime import datetime
import zstandard as zstd

# ============ Constants ============

_XML_UNSAFE_RE = re.compile(r'<!DOCTYPE|<!ENTITY', re.IGNORECASE)
_XML_PARSE_MAX_LEN = 20000

# 合并转发消息（含 recorditem 内嵌 XML）在 dataitem 数量多时显著超过默认 20K 上限，
# 实测真实 outer XML 可达 ~500KB。caller 可通过 max_len 参数为 type=19 类大消息放宽限制。
_RECORD_XML_PARSE_MAX_LEN = 500_000

# 大附件 md5 校验时的安全上限：超过此 size 直接拒绝校验（避免 MCP 进程
# 在 100MB+ 视频/附件上一次性 read() 整文件爆内存或长时间阻塞）。
_MD5_VERIFY_MAX_SIZE = 500 * 1024 * 1024  # 500 MB
_MD5_CHUNK_SIZE = 64 * 1024  # 64 KB

_zstd_dctx = zstd.ZstdDecompressor()

_RECORD_MAX_ITEMS = 50
_RECORD_MAX_LINE_LEN = 200

# 合并转发 dataitem 的 datatype → wechat 缓存子目录映射。仅这 4 类有真本地
# binary 文件；其他 datatype（链接/名片/小程序/视频号 等）只有 metadata。
_RECORD_BINARY_SUBDIR = {'8': 'F', '2': 'Img', '5': 'V', '4': 'A'}

# datatype → 中文标签，散在多处使用：渲染合并卡片 / decode_record_item 的
# 错误提示 / 单元测试。统一在模块顶部维护避免漂移。
_RECORD_DATATYPE_LABEL = {
    '1': '文本', '2': '图片', '3': '名片', '4': '语音',
    '5': '视频', '6': '链接', '7': '位置', '8': '文件',
    '17': '聊天记录', '19': '小程序', '22': '视频号',
    '23': '视频号直播', '29': '音乐', '36': '小程序/H5',
    '37': '表情包',
}

# 微信转账 (appmsg type=2000, <wcpayinfo>) paysubtype 含义。
# 微信官方无公开文档，此表来自社区抓包归纳。1/3/4 在所有已知版本一致；
# 5/7/8 在不同版本存在变体（"过期已退还"在某些抓包里也归为 4），所以遇到
# 未识别值时降级显示原始数字，方便用户自行核对。
_TRANSFER_PAYSUBTYPE_LABEL = {
    '1': '发起转账',     # 发送方记录：等待对方收钱
    '3': '已收款',       # 双向：发送方看到"对方已收"，接收方看到"已收钱"
    '4': '已退还',       # 主动退还或被退还
    '5': '过期已退还',    # 24h 未收，自动退还（发送方记录）
    '7': '待领取',       # 已发起未接收
    '8': '已领取',       # 部分版本：转账被领取（接收方记录）
}

# 微信引用回复（appmsg type=57, <refermsg>）内层 <type> 的标签映射。
# refermsg/<type> 用的是顶层 base_type 数字（跟 format_msg_type 重合），
# 但语义不同：format_msg_type 给"消息类型 chip"，这里给"被引用消息的一行摘要"，
# 不展开 cdn url / aeskey / md5 等二进制元数据（直接截断 XML 字符串当摘要是
# 现状的 bug，5.66% 的引用回复消息因此渲染成乱码——见 issue #44 #45）。
_REFER_INNER_TYPE_LABEL = {
    '1': '文本',         # 特殊：直接展开 content
    '3': '图片',
    '34': '语音',
    '42': '名片',
    '43': '视频',
    '47': '动画表情',
    '48': '位置',
    '49': '链接/卡片',   # 特殊：嵌套 appmsg，进一步解 inner type
    '50': '通话',
}

# refer_type=49 时 content 是嵌套 <msg><appmsg>...，inner appmsg/<type> → 标签。
# 跟合并转发 _RECORD_DATATYPE_LABEL 的数字含义不同（datatype 是 recorditem 的私有
# schema），独立维护。
_INNER_APPMSG_TYPE_LABEL = {
    '5': '链接', '6': '文件', '8': '动画表情卡',
    '19': '聊天记录', '33': '小程序', '36': '小程序',
    '51': '视频号', '57': '引用消息',
    '2000': '转账', '2001': '红包',
}


# ============ Functions ============

def format_msg_type(t):
    base_type, _ = _split_msg_type(t)
    return {
        1: '文本', 3: '图片', 34: '语音', 42: '名片',
        43: '视频', 47: '表情', 48: '位置', 49: '链接/文件',
        50: '通话', 10000: '系统', 10002: '撤回',
    }.get(base_type, f'type={t}')


def _split_msg_type(t):
    try:
        t = int(t)
    except (TypeError, ValueError):
        return 0, 0
    # WeChat packs the base type into the low 32 bits and app subtype into the high 32 bits.
    if t > 0xFFFFFFFF:
        return t & 0xFFFFFFFF, t >> 32
    return t, 0


def _decompress_content(content, ct):
    """解压 zstd 压缩的消息内容"""
    if ct and ct == 4 and isinstance(content, bytes):
        try:
            return _zstd_dctx.decompress(content).decode('utf-8', errors='replace')
        except Exception:
            return None
    if isinstance(content, bytes):
        try:
            return content.decode('utf-8', errors='replace')
        except Exception:
            return None
    return content


def _parse_message_content(content, local_type, is_group):
    """解析消息内容，返回 (sender_id, text)。

    群消息 content 形如 'wxid_xxx:\n<xml...>'；某些 type=19 合并转发也会
    写成 'wxid_xxx:<?xml...' 或 'wxid_xxx:<msg...' 不带换行——剥离逻辑两种都要处理。
    """
    if content is None:
        return '', ''
    if isinstance(content, bytes):
        return '', '(二进制内容)'

    sender = ''
    text = content
    if is_group:
        if ':\n' in content:
            sender, text = content.split(':\n', 1)
        else:
            # 'sender:<?xml...' / 'sender:<msg...' 等无换行 case
            m = re.match(r'^([A-Za-z0-9_\-@.]+):(<\?xml|<msg|<msglist|<voipmsg|<sysmsg)', content)
            if m:
                sender = m.group(1)
                text = content[len(sender) + 1:]

    return sender, text


def _collapse_text(text):
    if not text:
        return ''
    return re.sub(r'\s+', ' ', text).strip()


def _load_name2id_maps(conn):
    id_to_username = {}
    try:
        rows = conn.execute("SELECT rowid, user_name FROM Name2Id").fetchall()
    except sqlite3.Error:
        return id_to_username

    for rowid, user_name in rows:
        if not user_name:
            continue
        id_to_username[rowid] = user_name
    return id_to_username


def _display_name_for_username(username, names, get_self_username_func):
    if not username:
        return ''
    if username == get_self_username_func():
        return 'me'
    return names.get(username, username)


def _resolve_sender_label(real_sender_id, sender_from_content, is_group, chat_username, chat_display_name, names, id_to_username, get_self_username_func=None):
    # For backward compat: if get_self_username_func not provided, use a lazy import
    if get_self_username_func is None:
        from wxdec.contact import _get_self_username
        get_self_username_func = _get_self_username

    sender_username = id_to_username.get(real_sender_id, '')

    if is_group:
        if sender_username and sender_username != chat_username:
            return _display_name_for_username(sender_username, names, get_self_username_func)
        if sender_from_content:
            return _display_name_for_username(sender_from_content, names, get_self_username_func)
        return ''

    if sender_username == chat_username:
        return chat_display_name
    if sender_username:
        return _display_name_for_username(sender_username, names, get_self_username_func)
    return ''


def _resolve_quote_sender_label(ref_user, ref_display_name, is_group, chat_username, chat_display_name, names, get_self_username_func=None):
    # For backward compat: if get_self_username_func not provided, use a lazy import
    if get_self_username_func is None:
        from wxdec.contact import _get_self_username
        get_self_username_func = _get_self_username

    if is_group:
        if ref_user:
            return _display_name_for_username(ref_user, names, get_self_username_func)
        return ref_display_name or ''

    self_username = get_self_username_func()
    if ref_user:
        if ref_user == chat_username:
            return chat_display_name
        if self_username and ref_user == self_username:
            return 'me'
        return names.get(ref_user, ref_display_name or ref_user)
    if ref_display_name:
        if ref_display_name == chat_display_name:
            return chat_display_name
        self_display_name = names.get(self_username, self_username) if self_username else ''
        if self_display_name and ref_display_name == self_display_name:
            return 'me'
        return ref_display_name
    return ''


def _safe_basename(name):
    """对 user-derived filename（从消息 XML 来，不可信）做严格 sanitize。

    Reject 而不是 normalize：哪怕 os.path.basename 把 '../foo' 剥成 'foo' 是
    safe 的，意图依然可疑，应该显式失败让用户看到。
    """
    if not name:
        return ''
    if '\x00' in name:
        return ''
    if os.path.isabs(name):
        return ''
    # 任何 path separator 或 .. component 直接拒（不做 normalize）
    parts = name.replace('\\', '/').split('/')
    if any(p in ('', '.', '..') for p in parts) and len(parts) > 1:
        return ''
    if len(parts) > 1:
        return ''
    if name in ('.', '..'):
        return ''
    return name


def _path_under_root(path, root):
    """resolve realpath 后确认仍在 root 下（防 symlink 跳出）。"""
    try:
        real_path = os.path.realpath(path)
        real_root = os.path.realpath(root)
    except OSError:
        return False
    return real_path == real_root or real_path.startswith(real_root + os.sep)


def _md5_file_chunked(path, max_size=_MD5_VERIFY_MAX_SIZE):
    """流式分块计算文件 md5，避免大文件一次读完爆内存。

    超过 max_size 直接拒绝（DoS 防御 + 大附件 md5 校验现实意义不大）。
    返回 (md5_hex, error)；成功时 error 为 None。
    """
    try:
        size = os.path.getsize(path)
    except OSError as e:
        return None, f"无法读取文件 size: {e}"
    if size > max_size:
        return None, f"文件 size {size:,} 超过 md5 校验上限 {max_size:,}（防 DoS）"
    h = hashlib.md5()
    try:
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(_MD5_CHUNK_SIZE)
                if not chunk:
                    break
                h.update(chunk)
    except OSError as e:
        return None, f"读取文件失败: {e}"
    return h.hexdigest().lower(), None


def _parse_xml_root(content, max_len=_XML_PARSE_MAX_LEN):
    if not content or len(content) > max_len or _XML_UNSAFE_RE.search(content):
        return None

    try:
        return ET.fromstring(content)
    except ET.ParseError:
        return None


def _parse_int(value, fallback=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def _parse_app_message_outer(content):
    """Parse outer appmsg XML，对 type=19 合并卡片自动放宽到 _RECORD_XML_PARSE_MAX_LEN。

    所有解析 outer appmsg 的 caller（get_chat_history 渲染 / decode_file_message /
    decode_record_item）共用此 helper，避免同一条大消息在不同 caller 上行为不一致。
    Substring 短路保证非 type=19 的大 appmsg 不付出 500K parse 代价。"""
    root = _parse_xml_root(content)
    if root is None and content and len(content) <= _RECORD_XML_PARSE_MAX_LEN:
        if '<type>19</type>' in content:
            root = _parse_xml_root(content, max_len=_RECORD_XML_PARSE_MAX_LEN)
    return root


def _format_app_message_text(content, local_type, is_group, chat_username, chat_display_name, names):
    if not content or '<appmsg' not in content:
        return None

    _, sub_type = _split_msg_type(local_type)
    root = _parse_app_message_outer(content)
    if root is None:
        return None

    appmsg = root.find('.//appmsg')
    if appmsg is None:
        return None

    title = _collapse_text(appmsg.findtext('title') or '')
    app_type_text = (appmsg.findtext('type') or '').strip()
    app_type = _parse_int(app_type_text, _parse_int(sub_type, 0))

    if app_type == 57:
        return _format_refer_message_text(
            appmsg, is_group, chat_username, chat_display_name, names
        )

    if app_type == 19:
        return _format_record_message_text(appmsg, title)

    if app_type == 2000:
        return _format_transfer_message_text(appmsg, title)

    if app_type == 6:
        return f"[文件] {title}" if title else "[文件]"
    if app_type == 5:
        return f"[链接] {title}" if title else "[链接]"
    if app_type in (33, 36, 44):
        return f"[小程序] {title}" if title else "[小程序]"
    if title:
        return f"[链接/文件] {title}"
    return "[链接/文件]"


def _format_record_dataitem(item):
    """格式化合并记录中的单个 dataitem，返回展示文本。"""
    datatype = (item.get('datatype') or '').strip()

    if datatype == '1':
        return _collapse_text(item.findtext('datadesc') or '') or '[文本]'
    if datatype in ('2', '3', '4', '5', '7', '23', '37'):
        return f"[{_RECORD_DATATYPE_LABEL[datatype]}]"
    if datatype in ('6', '36'):
        link_title = _collapse_text(item.findtext('datatitle') or '')
        label = _RECORD_DATATYPE_LABEL[datatype]
        return f"[{label}] {link_title}" if link_title else f"[{label}]"
    if datatype == '8':
        file_title = _collapse_text(item.findtext('datatitle') or '')
        return f"[文件] {file_title}" if file_title else '[文件]'
    if datatype == '17':
        nested_title = _collapse_text(item.findtext('datatitle') or '')
        return f"[聊天记录] {nested_title}" if nested_title else '[聊天记录]'
    if datatype == '19':
        # 小程序：appbranditem/sourcedisplayname 是直接子代，不需要 .// 递归
        app_name = _collapse_text(item.findtext('appbranditem/sourcedisplayname') or '')
        item_title = _collapse_text(item.findtext('datatitle') or '')
        label = item_title or app_name or '小程序'
        return f"[小程序] {label}"
    if datatype == '22':
        feed_desc = _collapse_text(item.findtext('finderFeed/desc') or '')
        return f"[视频号] {feed_desc[:80]}" if feed_desc else '[视频号]'
    if datatype == '29':
        song = _collapse_text(item.findtext('datatitle') or '')
        artist = _collapse_text(item.findtext('datadesc') or '')
        if song and artist:
            return f"[音乐] {song} - {artist}"
        return f"[音乐] {song}" if song else '[音乐]'

    desc = _collapse_text(item.findtext('datadesc') or '')
    title_text = _collapse_text(item.findtext('datatitle') or '')
    fallback = desc or title_text
    return fallback if fallback else f"[未知类型 {datatype}]"


def _format_record_message_text(appmsg, title):
    """解析合并转发的聊天记录卡片（appmsg type=19, recorditem）。"""
    fallback_title = title or '聊天记录'
    record_node = appmsg.find('recorditem')
    if record_node is None or not record_node.text:
        return f"[聊天记录] {fallback_title}（待加载）"

    inner = _parse_xml_root(record_node.text, max_len=_RECORD_XML_PARSE_MAX_LEN)
    if inner is None:
        return f"[聊天记录] {fallback_title}"

    record_title = _collapse_text(inner.findtext('title') or '') or fallback_title
    is_chatroom = (inner.findtext('isChatRoom') or '').strip() == '1'
    datalist = inner.find('datalist')
    items = list(datalist.findall('dataitem')) if datalist is not None else []
    if not items:
        suffix = "（群聊转发，待加载）" if is_chatroom else "（待加载）"
        return f"[聊天记录] {record_title}{suffix}"

    header = f"[聊天记录] {record_title}"
    if is_chatroom:
        header += "（群聊转发）"
    header += f"，共 {len(items)} 条"

    lines = [header + ":"]
    for idx, item in enumerate(items[:_RECORD_MAX_ITEMS]):
        sender = _collapse_text(item.findtext('sourcename') or '')
        when = _collapse_text(item.findtext('sourcetime') or '')
        content = _format_record_dataitem(item)

        if len(content) > _RECORD_MAX_LINE_LEN:
            content = content[:_RECORD_MAX_LINE_LEN] + '…'

        # 0-based index 让用户能用 decode_record_item(chat, local_id, item_index) 引用
        prefix_parts = [f"[{idx}]"] + [p for p in (when, sender) if p]
        prefix = ' '.join(prefix_parts)
        lines.append(f"  {prefix}: {content}")

    if len(items) > _RECORD_MAX_ITEMS:
        lines.append(f"  …（还有 {len(items) - _RECORD_MAX_ITEMS} 条未显示）")

    return "\n".join(lines)


def _extract_refer_info(appmsg):
    """从 appmsg type=57 解出 refermsg 各字段，返回 dict 或 None。

    refermsg/<content> 是 escape 后的字符串，内层 type 决定其 schema:
      type=1 (纯文本) / 3 (img cdn) / 34 (voicemsg) / 47 (emoji)
      / 49 (嵌套 appmsg) / ...

    refer_content 保留原始字符串（不 collapse），让 _summarize_refer_content
    按 type 进一步处理（type=49 还要再解一层 XML）。其他字段过 _collapse_text
    清掉换行/前后空白。
    """
    refer = appmsg.find('refermsg')
    if refer is None:
        return None

    return {
        'reply_text': _collapse_text(appmsg.findtext('title') or ''),
        'refer_type': _collapse_text(refer.findtext('type') or ''),
        'refer_svrid': _collapse_text(refer.findtext('svrid') or ''),
        'refer_fromusr': _collapse_text(refer.findtext('fromusr') or ''),
        'refer_chatusr': _collapse_text(refer.findtext('chatusr') or ''),
        'refer_displayname': _collapse_text(refer.findtext('displayname') or ''),
        'refer_content': refer.findtext('content') or '',
        'refer_createtime': _collapse_text(refer.findtext('createtime') or ''),
    }


def _summarize_refer_content(refer_type, content, max_len=160):
    """把被引用消息的 content 摘要成一行可读文本。

    分支规则：
      type=1 (文本): 取原文，截断到 max_len
      type=3/34/43/47/...: 给标签兜底，不展开 cdn url / aeskey / md5
      type=49 (嵌套 appmsg): 解一层 inner appmsg/type + title，给"[链接] xxx"
      未识别 type: 给 [type=N] 兜底，方便用户自查

    max_len 只对 type=1 文本生效；标签型摘要本身就短。
    """
    refer_type = (refer_type or '').strip()

    if not content:
        label = _REFER_INNER_TYPE_LABEL.get(refer_type)
        if label:
            return f'[{label}]'
        return f'[type={refer_type}]' if refer_type else '[引用消息]'

    if refer_type == '1':
        text = _collapse_text(content)
        return text[:max_len] + '…' if len(text) > max_len else text

    if refer_type == '49':
        # 嵌套 appmsg：content 是来源不可信的微信侧 payload，走 _parse_xml_root
        # 经 _XML_UNSAFE_RE 过滤 DOCTYPE/ENTITY 防 XXE 注入。
        inner_root = _parse_xml_root(content)
        if inner_root is None:
            return '[卡片]'
        inner_appmsg = inner_root.find('.//appmsg')
        if inner_appmsg is None:
            return '[卡片]'
        inner_type = _collapse_text(inner_appmsg.findtext('type') or '')
        inner_title = _collapse_text(inner_appmsg.findtext('title') or '')
        label = _INNER_APPMSG_TYPE_LABEL.get(
            inner_type, f'卡片 type={inner_type}' if inner_type else '卡片'
        )
        return f'[{label}] {inner_title}' if inner_title else f'[{label}]'

    label = _REFER_INNER_TYPE_LABEL.get(refer_type)
    if label:
        return f'[{label}]'
    return f'[type={refer_type}]'


def _format_refer_message_text(appmsg, is_group, chat_username, chat_display_name, names):
    """渲染微信引用回复（appmsg type=57）的两行展示文本，给 history / monitor_web 共用。

    格式:
      <用户的回复正文>
        ↳ 回复 <对方>: <被引用消息摘要>

    fallback:
      1) refermsg 缺失 → 退回到外层 title 兜底
      2) refer_content 空 → summary 给"[refer_type 标签]"或"[引用消息]"
      3) sender 解析不出来 → "回复:" 不带名字
    """
    info = _extract_refer_info(appmsg)
    if info is None:
        title = _collapse_text(appmsg.findtext('title') or '')
        return title or '[引用消息]'

    summary = _summarize_refer_content(info['refer_type'], info['refer_content'])
    sender_label = _resolve_quote_sender_label(
        info['refer_fromusr'], info['refer_displayname'],
        is_group, chat_username, chat_display_name, names
    )

    quote_text = info['reply_text'] or '[引用消息]'
    prefix = f'回复 {sender_label}: ' if sender_label else '回复: '
    quote_text += f'\n  ↳ {prefix}{summary}'
    return quote_text


def _extract_transfer_info(appmsg):
    """从 appmsg type=2000 解出 wcpayinfo 各字段，返回 dict 或 None。

    字段大小写在不同微信版本间漂移（见过 feedesc/feeDesc, pay_memo/paymemo），
    用 lower-case 兜底。所有值用 _collapse_text 清掉换行/前后空白。
    """
    info = appmsg.find('wcpayinfo')
    if info is None:
        return None

    def _pick(*tags):
        for t in tags:
            v = _collapse_text(info.findtext(t) or '')
            if v:
                return v
        return ''

    paysubtype = _pick('paysubtype')
    return {
        'paysubtype': paysubtype,
        'paysubtype_label': _TRANSFER_PAYSUBTYPE_LABEL.get(
            paysubtype, f'未知(paysubtype={paysubtype})' if paysubtype else ''
        ),
        # feedesc 通常是 "￥0.01" 风格的展示串（全角 ￥）；feedescxml 是富文本变体
        'fee_desc': _pick('feedesc', 'feeDesc'),
        'pay_memo': _pick('pay_memo', 'paymemo'),
        # 三种交易号：transcationid 是微信支付侧（注意拼写是 transc 不是 trans），
        # transferid 是微信内部转账 id，paymsgid 偶见于旧版本
        'transcation_id': _pick('transcationid', 'transcationId'),
        'transfer_id': _pick('transferid', 'transferId'),
        'pay_msg_id': _pick('paymsgid', 'payMsgId'),
        'begin_transfer_time': _pick('begintransfertime', 'beginTransferTime'),
        'invalid_time': _pick('invalidtime', 'invalidTime'),
        'effective_date': _pick('effectivedate', 'effectiveDate'),
        'payer_username': _pick('payer_username', 'payerUsername'),
        'receiver_username': _pick('receiver_username', 'receiverUsername'),
    }


def _format_transfer_message_text(appmsg, title):
    """渲染微信转账（appmsg type=2000）一行展示文本，给 history / monitor_web 共用。

    fallback 顺序：
      1) wcpayinfo 缺失 → 只显示 title 兜底，避免吞数据
      2) paysubtype 未知 → 显示原始数字让用户自查
      3) 没有 fee_desc → 至少给个方向标签
    """
    info = _extract_transfer_info(appmsg)
    if not info:
        return f"[转账] {title}" if title else "[转账]"

    label = info['paysubtype_label'] or '转账'
    parts = [f"[转账·{label}]"] if label != '转账' else ["[转账]"]
    if info['fee_desc']:
        parts.append(info['fee_desc'])
    if info['pay_memo']:
        parts.append(f"备注: {info['pay_memo']}")
    return ' '.join(parts)


def _format_voip_message_text(content):
    if not content or '<voip' not in content:
        return None

    root = _parse_xml_root(content)
    if root is None:
        return "[通话]"

    raw_text = _collapse_text(root.findtext('.//msg') or '')
    if not raw_text:
        return "[通话]"

    status_map = {
        'Canceled': '已取消',
        'Line busy': '对方忙线',
        'Already answered elsewhere': '已在其他设备接听',
        'Declined on other device': '已在其他设备拒接',
        'Call canceled by caller': '主叫已取消',
        'Call not answered': '未接听',
        "Call wasn't answered": '未接听',
    }

    if raw_text.startswith('Duration:'):
        duration = raw_text.split(':', 1)[1].strip()
        return f"[通话] 通话时长 {duration}" if duration else "[通话]"

    return f"[通话] {status_map.get(raw_text, raw_text)}"


def _format_message_text(local_id, local_type, content, is_group, chat_username, chat_display_name, names, create_time=0):
    sender_from_content, text = _parse_message_content(content, local_type, is_group)
    base_type, _ = _split_msg_type(local_type)

    # 同一 chat 的消息可能跨 message_N.db 分片，导致 local_id 跨分片冲突。
    # 把 create_time 一起注入到输出，让 decode_file_message / decode_record_item
    # 能用 (local_id, create_time) 唯一定位 row。
    def _id_suffix():
        return f"(local_id={local_id}, ts={create_time})" if create_time else f"(local_id={local_id})"

    if base_type == 3:
        text = f"[图片] {_id_suffix()}"
    elif base_type == 47:
        text = "[表情]"
    elif base_type == 50:
        text = _format_voip_message_text(text) or "[通话]"
    elif base_type == 49:
        formatted = _format_app_message_text(
            text, local_type, is_group, chat_username, chat_display_name, names
        ) or "[链接/文件]"
        if formatted.startswith('[文件]'):
            formatted = f"{formatted} {_id_suffix()}"
        elif formatted.startswith('[聊天记录]'):
            # 多行：把 ID 后缀放在 header 末尾，":" 之前
            if '\n' in formatted:
                first_line, rest = formatted.split('\n', 1)
                first_line_no_colon = first_line.rstrip(':').rstrip()
                formatted = f"{first_line_no_colon} {_id_suffix()}:\n{rest}"
            else:
                formatted = f"{formatted} {_id_suffix()}"
        text = formatted
    elif base_type != 1:
        type_label = format_msg_type(local_type)
        text = f"[{type_label}] {text}" if text else f"[{type_label}]"

    return sender_from_content, text
