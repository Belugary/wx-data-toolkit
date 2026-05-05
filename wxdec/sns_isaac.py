"""
ISAAC-64 keystream + 朋友圈媒体 XOR 解密。

ISAAC (Indirection, Shift, Accumulate, Add, Count) 是 Robert J. Jenkins, Jr. 1996 年
公开的 PRNG (https://burtleburtle.net/bob/rand/isaacafa.html), 算法本身在公有领域。
微信视频号 / 朋友圈使用 WeFlow 的 `WxIsaac64`(WASM 实现)作为 keystream 生成器,
**它跟标准 ISAAC-64 有一个字节的差异**: PHI 常数尾字节是 0x13 而不是标准的 0x15。

本实现据 [nobiyou/wx_channel](https://github.com/nobiyou/wx_channel) (MIT) 的
`pkg/util/isaac64.go` 移植到 Python, 输出与 WeFlow WASM 完全一致(self-test 用
WASM 实测 keystream 作为 ground truth, 4/4 通过)。

注: WeChatDataAnalysis 仓库的 `isaac64.py` 用了标准 ISAAC-64 的 PHI 常数 0x...C15,
作者自己注释 "may not perfectly match WxIsaac64" — 它确实不能解真实加密数据。

朋友圈媒体规则(微信 4.x):
  - 图片: 整文件 XOR keystream
  - 视频: 仅前 131072 字节(64 个完整 ISAAC 块)XOR, 余下原样, 解密后 offset 4 应是 b'ftyp'

视频 128KB 这个常数没有官方文档, 据 wx_channel + WeFlow WASM 实测推导。
若日后微信调整加密范围, 视频解密会失败但原文件不会被破坏(decrypt_video_in_place
解密后先校验 ftyp, 校验通过才回写)。

种子格式: XML 中 `<url>` / `<enc>` 标签的 attr `key="14970291265290127678"`,
        十进制数字字符串 -> int(s, 0) -> 64-bit 截断 -> 仅填到 randrsl[0]。

Keystream 字节序: 反向消费 randrsl(从 [255] 到 [0]), 每个 u64 用 big-endian 8 字节序列化。
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Optional

import functools
print = functools.partial(print, flush=True)


_U64 = 0xFFFFFFFFFFFFFFFF
# WeFlow WxIsaac64 用的 PHI 常数尾字节是 0x13, 不是 ISAAC-64 标准的 0x15!
# 这是它跟标准 ISAAC-64 的关键差异, 也是 WeChatDataAnalysis Python fallback
# "may not perfectly match WxIsaac64" 的根因。来源: nobiyou/wx_channel (MIT)
# pkg/util/isaac64.go 的实测代码与 WeFlow WASM 行为一致。
_GOLDEN = 0x9E3779B97F4A7C13


def _u64(x: int) -> int:
    return x & _U64


class Isaac64:
    """ISAAC-64 PRNG。

    种子接口与 WxIsaac64 / WeChatDataAnalysis 兼容: 接受字符串(数字 / 0x 前缀均可),
    内部按十进制 / hex 转 int, 截断到 64 位, 仅填到 randrsl[0]。

    生成 keystream 用 generate_keystream(n_bytes); 默认 be_swap32 编码。
    """

    __slots__ = ("mm", "aa", "bb", "cc", "randrsl", "randcnt")

    def __init__(self, seed):
        s = str(seed).strip()
        if not s:
            seed_val = 0
        else:
            try:
                seed_val = int(s, 0)
            except ValueError:
                # 静默降级到 0 会让 Isaac64("abc") 与 Isaac64("0") 产生同一 keystream,
                # 调试时极易掩盖 seed 取错的真因(比如从 XML 复制时多了个空白字符)。
                # 给一行 stderr 警告, 不抛异常以保留 caller 兼容性。
                print(f"[!] sns_isaac: seed {s!r} 不是合法 int / hex, 降级到 0; keystream 将无意义",
                      file=sys.stderr)
                seed_val = 0

        self.mm = [0] * 256
        self.aa = 0
        self.bb = 0
        self.cc = 0
        self.randrsl = [0] * 256
        self.randrsl[0] = _u64(seed_val)
        self.randcnt = 0
        self._reseed_init()

    # 内部: 8 轮 mix(操作 8 个寄存器 a..h)。返回更新后的 8 元组。
    @staticmethod
    def _mix(a, b, c, d, e, f, g, h):
        a = _u64(a - e); f ^= h >> 9;            h = _u64(h + a)
        b = _u64(b - f); g ^= _u64(a << 9);      a = _u64(a + b)
        c = _u64(c - g); h ^= b >> 23;           b = _u64(b + c)
        d = _u64(d - h); a ^= _u64(c << 15);     c = _u64(c + d)
        e = _u64(e - a); b ^= d >> 14;           d = _u64(d + e)
        f = _u64(f - b); c ^= _u64(e << 20);     e = _u64(e + f)
        g = _u64(g - c); d ^= f >> 17;           f = _u64(f + g)
        h = _u64(h - d); e ^= _u64(g << 14);     g = _u64(g + h)
        return _u64(a), _u64(b), _u64(c), _u64(d), _u64(e), _u64(f), _u64(g), _u64(h)

    def _reseed_init(self):
        # 初始化 mm[]: flag=True 路径(种子初始化, vs reseed 是 flag=False)。
        a = b = c = d = e = f = g = h = _GOLDEN

        # 阶段 A: 种子前的 4 轮纯 mix
        for _ in range(4):
            a, b, c, d, e, f, g, h = self._mix(a, b, c, d, e, f, g, h)

        # 阶段 B: 把 randrsl[] 注入, 第一次填 mm[]
        for i in range(0, 256, 8):
            a = _u64(a + self.randrsl[i + 0]); b = _u64(b + self.randrsl[i + 1])
            c = _u64(c + self.randrsl[i + 2]); d = _u64(d + self.randrsl[i + 3])
            e = _u64(e + self.randrsl[i + 4]); f = _u64(f + self.randrsl[i + 5])
            g = _u64(g + self.randrsl[i + 6]); h = _u64(h + self.randrsl[i + 7])
            a, b, c, d, e, f, g, h = self._mix(a, b, c, d, e, f, g, h)
            self.mm[i + 0] = a; self.mm[i + 1] = b
            self.mm[i + 2] = c; self.mm[i + 3] = d
            self.mm[i + 4] = e; self.mm[i + 5] = f
            self.mm[i + 6] = g; self.mm[i + 7] = h

        # 阶段 C: 二次混合 (使 mm 中的 entropy 充分扩散)
        for i in range(0, 256, 8):
            a = _u64(a + self.mm[i + 0]); b = _u64(b + self.mm[i + 1])
            c = _u64(c + self.mm[i + 2]); d = _u64(d + self.mm[i + 3])
            e = _u64(e + self.mm[i + 4]); f = _u64(f + self.mm[i + 5])
            g = _u64(g + self.mm[i + 6]); h = _u64(h + self.mm[i + 7])
            a, b, c, d, e, f, g, h = self._mix(a, b, c, d, e, f, g, h)
            self.mm[i + 0] = a; self.mm[i + 1] = b
            self.mm[i + 2] = c; self.mm[i + 3] = d
            self.mm[i + 4] = e; self.mm[i + 5] = f
            self.mm[i + 6] = g; self.mm[i + 7] = h

        # 第一个块产出, 标记 randrsl 已填满供反向消费
        self._gen_block()
        self.randcnt = 256

    def _gen_block(self):
        """生成 256 个 u64 输出到 randrsl[], 同时更新 mm/aa/bb/cc。"""
        self.cc = _u64(self.cc + 1)
        self.bb = _u64(self.bb + self.cc)
        mm = self.mm
        aa = self.aa
        bb = self.bb
        for i in range(256):
            x = mm[i]
            mod = i & 3
            if mod == 0:
                aa = _u64(aa ^ (_u64(aa << 21) ^ _U64))  # ~(aa<<21)
            elif mod == 1:
                aa = _u64(aa ^ (aa >> 5))
            elif mod == 2:
                aa = _u64(aa ^ _u64(aa << 12))
            else:
                aa = _u64(aa ^ (aa >> 33))
            aa = _u64(mm[(i + 128) & 255] + aa)
            y = _u64(mm[(x >> 3) & 255] + aa + bb)
            mm[i] = y
            bb = _u64(mm[(y >> 11) & 255] + x)
            self.randrsl[i] = bb
        self.aa = aa
        self.bb = bb

    def _next_u64(self) -> int:
        """从 randrsl 反向取 u64(255 -> 0); 取空再生成下一块。"""
        if self.randcnt == 0:
            self._gen_block()
            self.randcnt = 256
        self.randcnt -= 1
        return self.randrsl[self.randcnt]

    def generate_keystream(self, n_bytes: int) -> bytes:
        """每个 u64 输出按 big-endian 8 字节序列化, 直接拼接。

        wx_channel 的 Go 实现用 "LE 字节然后整体反转" 写法, 等价于 BE。
        """
        if n_bytes <= 0:
            return b""
        blocks = (n_bytes + 7) // 8
        out = bytearray(blocks * 8)
        for i in range(blocks):
            v = self._next_u64()
            out[i * 8 : i * 8 + 8] = v.to_bytes(8, "big")
        return bytes(out[:n_bytes])


# ---------- 媒体解密 ----------

def decrypt_image_bytes(payload: bytes, key: str) -> bytes:
    """全文件 XOR; payload 为空或 key 为空则原样返回。"""
    if not payload or not str(key or "").strip():
        return payload
    ks = Isaac64(key).generate_keystream(len(payload))
    out = bytearray(payload)
    for i in range(min(len(out), len(ks))):
        out[i] ^= ks[i]
    return bytes(out)


# 视频前 128KB 加密, 余下不动。
SNS_VIDEO_HEAD_SIZE = 131072

# 常见图片/视频 magic, 用来校验解密是否成功
_MAGIC = {
    b"\xff\xd8\xff": "jpeg",
    b"\x89PNG\r\n\x1a\n": "png",
    b"GIF87a": "gif",
    b"GIF89a": "gif",
    b"RIFF": "webp",  # 真实 webp 还要看 offset 8 的 WEBP, 这里仅粗筛
}


def detect_image_kind(buf: bytes) -> Optional[str]:
    for magic, kind in _MAGIC.items():
        if buf.startswith(magic):
            return kind
    return None


def detect_mp4(buf: bytes) -> bool:
    """前 12 字节包含 ftyp 即视为 mp4 容器。"""
    return len(buf) >= 8 and buf[4:8] == b"ftyp"


def decrypt_video_bytes(payload: bytes, key: str) -> Optional[bytes]:
    """前 SNS_VIDEO_HEAD_SIZE 字节 XOR; ftyp 校验通过返回完整明文, 否则 None。

    与 decrypt_image_bytes 的差异: 视频只 XOR 前 128KB, 余下原样; 且必须 ftyp 校验
    通过才接受输出。校验失败一律返回 None — 包括三种情况, 调用方需用 detect_mp4
    检查 payload 头自行区分:
      - seed 错(payload 是密文但 key 不对)
      - 已经是明文(payload 起手就是 ftyp; 不重复 XOR)
      - 文件损坏 / 截断
    """
    if not str(key or "").strip():
        return None
    if not payload or len(payload) < 8:
        return None
    if detect_mp4(payload[:8]):
        return None  # already plaintext; caller can detect this via detect_mp4 itself

    n = min(SNS_VIDEO_HEAD_SIZE, len(payload))
    head = bytearray(payload[:n])
    ks = Isaac64(key).generate_keystream(n)
    for i in range(n):
        head[i] ^= ks[i]

    if not detect_mp4(bytes(head[:8])):
        return None

    return bytes(head) + payload[n:]


def decrypt_video_in_place(path: Path, key: str) -> bool:
    """读 path -> 内存解密 -> ftyp 校验通过才回写; 失败时原文件保持不变。

    薄壳: 实际解密由 decrypt_video_bytes 完成, 这里仅负责 IO。
    seed 错 / 已是明文 / 文件损坏 都返回 False。
    """
    if not str(key or "").strip():
        return False
    if path.stat().st_size <= 8:
        return False

    with path.open("rb") as f:
        payload = f.read()

    plain = decrypt_video_bytes(payload, key)
    if plain is None:
        return False

    # 大小不变(只 XOR 前 128KB, 余下原样)— 用 r+b 覆写, 不需 truncate。
    with path.open("r+b") as f:
        f.write(plain)
        f.flush()
    return True


# ---------- self-test ----------

# 测试向量来自 WeFlow WASM (权威实现, 通过 Node 桥接生成)。
# clean-room 重写必须输出完全一致才能保证解密真实数据正确。
_VECTORS = [
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


def run_self_test() -> int:
    ok = 0
    fail = 0
    for seed, size, expect_hex in _VECTORS:
        got = Isaac64(seed).generate_keystream(size).hex()
        if got == expect_hex:
            ok += 1
            print(f"  OK   seed={seed!r:>30s} size={size:4d}")
        else:
            fail += 1
            print(f"  FAIL seed={seed!r:>30s} size={size:4d}", file=sys.stderr)
            print(f"       got  = {got}", file=sys.stderr)
            print(f"       want = {expect_hex}", file=sys.stderr)
    print(f"[+] {ok} ok, {fail} fail (out of {len(_VECTORS)})")
    return 0 if fail == 0 else 1


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="sns_isaac.py",
        description="ISAAC-64 keystream + 朋友圈媒体 XOR 解密 (clean-room).",
    )
    sub = p.add_subparsers(dest="cmd", required=False)

    sub.add_parser("self-test", help="跑测试向量, 验证算法实现正确")

    p_img = sub.add_parser("decrypt-image", help="解密单张朋友圈图片")
    p_img.add_argument("input", help="加密的图片字节文件")
    p_img.add_argument("key", help="ISAAC seed (XML 里 url 上的 key 属性)")
    p_img.add_argument("-o", "--output", required=True, help="输出明文图片路径")

    p_vid = sub.add_parser("decrypt-video", help="原地解密朋友圈视频前 128KB")
    p_vid.add_argument("path", help="加密的 mp4 文件 (会被原地修改, 建议先 cp 备份)")
    p_vid.add_argument("key", help="ISAAC seed")

    args = p.parse_args(argv)

    if args.cmd is None or args.cmd == "self-test":
        return run_self_test()

    if args.cmd == "decrypt-image":
        with open(args.input, "rb") as f:
            payload = f.read()
        plain = decrypt_image_bytes(payload, args.key)
        kind = detect_image_kind(plain)
        with open(args.output, "wb") as f:
            f.write(plain)
        if kind:
            print(f"[+] 解密成功 ({kind}) -> {args.output}")
            return 0
        print(f"[!] 解密后未识别图片 magic; 写入 {args.output} 但可能格式不对", file=sys.stderr)
        return 2

    if args.cmd == "decrypt-video":
        ok = decrypt_video_in_place(Path(args.path), args.key)
        if ok:
            print(f"[+] 解密成功 (ftyp 校验通过) -> {args.path}")
            return 0
        print(f"[!] 解密失败或文件已是明文", file=sys.stderr)
        return 2

    return 1


if __name__ == "__main__":
    sys.exit(main())
