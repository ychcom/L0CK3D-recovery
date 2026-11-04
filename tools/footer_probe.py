#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
读取 C3RB3R (.L0CK3D) 文件尾部 588 字节记录并解析字段（正确版：带 chunk 地址映射）。

ext260.tsv 列：ino, file_off, btrfs_logical, ext_offset, length, ?, generation

文件尾布局（相对尾部起点）：
  0    48  AES-256-CBC 包裹的 file-key32 + nonce8 + nonce8
  48   524 RSA 公钥包裹记录 + 标记区
  568  4   本会话标记 (session marker)
  572  1   文件模式: 0x24 全文件 / 0x25 分段 / 0x26 前 1MiB
  573  1   分段参数
  574  1   crypto 模式: 0x20 真加密 / 0x21 诱饵
  575  1   保留 0
  576  4   保留
  580  8   原始文件大小 (little-endian, uint64)
"""
import sys, struct, os, re, subprocess

DEV = "/dev/loop1"
EXT = "/root/ext260.tsv"

def load_chunks():
    p = subprocess.run(["btrfs", "inspect-internal", "dump-tree", "-t", "3", DEV],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    out = p.stdout.decode("utf-8", "replace")
    res, cur = [], None
    for line in out.split("\n"):
        m = re.search(r"CHUNK_ITEM (\d+)", line)
        if m:
            cur = {"logical": int(m.group(1)), "len": None, "phys": None, "type": ""}
            res.append(cur); continue
        if cur is None: continue
        if cur["len"] is None:
            m = re.search(r"length (\d+)", line)
            if m: cur["len"] = int(m.group(1))
        m = re.search(r"type (\w+)", line)
        if m: cur["type"] = m.group(1)
        if cur["phys"] is None:
            m = re.search(r"stripe 0 devid \d+ offset (\d+)", line)
            if m: cur["phys"] = int(m.group(1))
    return [c for c in res if c["len"] and c["phys"] is not None]

CH = load_chunks()
sys.stderr.write("chunks %d\n" % len(CH))

def l2p(logical):
    for c in CH:
        if c["logical"] <= logical < c["logical"] + c["len"]:
            return c["phys"] + (logical - c["logical"])
    return None

def load_extents(inodes):
    out = {}
    with open(EXT) as f:
        for line in f:
            c = line.rstrip("\r\n").split("\t")
            if len(c) < 7: continue
            if c[0] not in inodes: continue
            try:
                out.setdefault(c[0], []).append(
                    (int(c[1]), int(c[2]), int(c[3]), int(c[4]), int(c[6])))
            except ValueError:
                pass
    return out

FH = open(DEV, "rb")

def read_fo(items, size, start, n):
    """从文件逻辑偏移 start 读 n 字节（跨 extent 分块）"""
    buf = b""
    pos = start
    while len(buf) < n:
        it = None
        for x in items:
            if x[0] <= pos < x[0] + x[3]:
                it = x; break
        if it is None:
            buf += b"\x00"; pos += 1; continue
        delta = pos - it[0]
        # 本 extent 内可读长度
        avail = it[3] - delta
        want = min(n - len(buf), avail)
        if it[1] < 0:            # inline
            buf += b"\x00" * want; pos += want; continue
        ph = l2p(it[1] + it[2] + delta)
        if ph is None:
            buf += b"\x00" * want; pos += want; continue
        FH.seek(ph)
        buf += FH.read(want)
        pos += want
    return buf

def main():
    inodes = set(sys.argv[1].split(","))
    labels = {}
    sizes = {}
    labfile = sys.argv[2] if len(sys.argv) > 2 else None
    if labfile and os.path.exists(labfile):
        for line in open(labfile, encoding="utf-8", errors="replace"):
            q = line.rstrip("\n").split("\t")
            if len(q) >= 2: labels[q[0]] = q[-1]
            if len(q) >= 3 and q[1].isdigit(): sizes[q[0]] = int(q[1])

    # size 表补充：ino -> size（从 ino260.tsv，若存在）
    if os.path.exists("/root/ino260.tsv"):
        for line in open("/root/ino260.tsv", encoding="utf-8", errors="replace"):
            c = line.rstrip("\n").split("\t")
            if len(c) >= 5 and c[0] in inodes:
                sizes[c[1]] = int(c[3])

    ext = load_extents(inodes)
    print("ino\tsize\tmarker\tmode\tparam\tcrypto\treserved\tfooter_orig\tcheck\tlabel")
    for ino in sorted(inodes, key=lambda x: int(x)):
        items = ext.get(ino) or []
        size = sizes.get(ino)
        if not items or size is None:
            print("%s\t-\tNO_DATA items=%d size=%s keys=%s\t\t\t\t\t%s" % (
                ino, len(items), size,
                sorted(sizes.keys())[:3], labels.get(ino, "")))
            continue
        if size < 588:
            print("%s\t%d\tTOO_SMALL\t\t\t\t\t\t\t%s" % (ino, size, labels.get(ino, "")))
            continue
        blob = read_fo(items, size, size - 588, 588)
        marker = blob[568:572].hex()
        mode = blob[572]; param = blob[573]; crypto = blob[574]
        rsv = blob[575]
        orig = struct.unpack_from("<Q", blob, 580)[0]
        ok = "OK" if orig == size - 588 else "MISMATCH(exp %d)" % (size - 588)
        MODE = {0x24: "全文件", 0x25: "分段", 0x26: "前1MiB"}.get(mode, "?")
        print("%s\t%d\t%s\t0x%02X(%s)\t%d\t0x%02X\t%d\t%d\t%s\t%s" % (
            ino, size, marker, mode, MODE, param, crypto, rsv, orig, ok,
            labels.get(ino, "")))
        print("   keyblob48=%s" % blob[0:48].hex())

if __name__ == "__main__":
    main()
