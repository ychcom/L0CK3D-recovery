#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
尝试从旧 extent 的"未引用剩余空间"中读取文件缺失区间的数据。
原理：btrfs extent_data 只引用 (ext_off, length) 这一段，
      原 extent 中 offset > ext_off+length 的部分可能仍在磁盘上未被覆写。

用法: read_gap.py "<logical> <ext_off> <want_ext_start> <want_len> <out_name>"
"""
import sys, os, re, subprocess, bisect

DEV = "/dev/loop1"

def load_chunks():
    p = subprocess.run(["btrfs", "inspect-internal", "dump-tree", "-t", "3", DEV],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    out = p.stdout.decode("utf-8", "replace")
    res, cur = [], None
    for line in out.split("\n"):
        m = re.search(r"CHUNK_ITEM (\d+)", line)
        if m:
            cur = {"logical": int(m.group(1)), "len": None, "phys": None}
            res.append(cur); continue
        if cur is None: continue
        if cur["len"] is None:
            m = re.search(r"length (\d+)", line)
            if m: cur["len"] = int(m.group(1))
        if cur["phys"] is None:
            m = re.search(r"stripe 0 devid \d+ offset (\d+)", line)
            if m: cur["phys"] = int(m.group(1))
    res = [c for c in res if c["len"] and c["phys"] is not None]
    res.sort(key=lambda c: c["logical"])
    return res

CH = load_chunks()
LO = [c["logical"] for c in CH]

def l2p(logical):
    i = bisect.bisect_right(LO, logical) - 1
    if i >= 0:
        c = CH[i]
        if c["logical"] <= logical < c["logical"] + c["len"]:
            return c["phys"] + (logical - c["logical"])
    return None

def main():
    logical = int(sys.argv[1])
    want_start = int(sys.argv[2])     # extent 内起始偏移
    want_len = int(sys.argv[3])
    outname = sys.argv[4]
    ph = l2p(logical + want_start)
    sys.stderr.write("logical=%d +%d -> phys=%s\n" % (logical, want_start, ph))
    if ph is None:
        sys.stderr.write("NOMAP\n"); return
    with open(DEV, "rb") as f:
        f.seek(ph)
        d = f.read(want_len)
    out = "/root/gap_%s.bin" % outname
    open(out, "wb").write(d)
    sys.stderr.write("wrote %s %d bytes\n" % (out, len(d)))
    sys.stderr.write("head32=%s\n" % d[:32].hex())
    sys.stderr.write("tail32=%s\n" % d[-32:].hex())

if __name__ == "__main__":
    main()
