#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
批量扫描 .L0CK3D 文件尾部记录，统计加密模式分布。
输出: ino\tsize\tmarker\tmode\tparam\tcrypto\tfooter_orig\tcheck\tpath
"""
import sys, struct, os, re, subprocess, collections

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
            cur = {"logical": int(m.group(1)), "len": None, "phys": None}
            res.append(cur); continue
        if cur is None: continue
        if cur["len"] is None:
            m = re.search(r"length (\d+)", line)
            if m: cur["len"] = int(m.group(1))
        if cur["phys"] is None:
            m = re.search(r"stripe 0 devid \d+ offset (\d+)", line)
            if m: cur["phys"] = int(m.group(1))
    return [c for c in res if c["len"] and c["phys"] is not None]

CH = load_chunks()
sys.stderr.write("chunks %d\n" % len(CH))
# 排序加速二分查找
CH.sort(key=lambda c: c["logical"])
import bisect
LO = [c["logical"] for c in CH]

def l2p(logical):
    i = bisect.bisect_right(LO, logical) - 1
    if i >= 0:
        c = CH[i]
        if c["logical"] <= logical < c["logical"] + c["len"]:
            return c["phys"] + (logical - c["logical"])
    return None

def load_extents(inodes):
    out = {}
    with open(EXT) as f:
        for line in f:
            c = line.rstrip("\r\n").split("\t")
            if len(c) < 7 or c[0] not in inodes: continue
            try:
                out.setdefault(c[0], []).append(
                    (int(c[1]), int(c[2]), int(c[3]), int(c[4])))
            except ValueError:
                pass
    return out

FH = open(DEV, "rb")

def read_fo(items, start, n):
    buf = b""; pos = start
    while len(buf) < n:
        it = None
        for x in items:
            if x[0] <= pos < x[0] + x[3]: it = x; break
        if it is None or it[1] < 0:
            buf += b"\x00" * (n - len(buf)); break
        delta = pos - it[0]
        want = min(n - len(buf), it[3] - delta)
        ph = l2p(it[1] + it[2] + delta)
        if ph is None:
            buf += b"\x00" * want; pos += want; continue
        FH.seek(ph); buf += FH.read(want); pos += want
    return buf

def main():
    lst = sys.argv[1]           # ino\tsize\tpath
    targets = []
    for line in open(lst, encoding="utf-8", errors="replace"):
        q = line.rstrip("\n").split("\t")
        if len(q) >= 3 and q[1].isdigit():
            targets.append((q[0], int(q[1]), q[2]))
    inodes = {t[0] for t in targets}
    ext = load_extents(inodes)
    sys.stderr.write("targets %d, ext inodes %d\n" % (len(targets), len(ext)))

    out = open("/root/footer_scan.tsv", "w", encoding="utf-8")
    out.write("ino\tsize\tmarker\tmode\tparam\tcrypto\tfooter_orig\tcheck\tpath\n")
    st = collections.Counter(); nost = collections.Counter()
    for ino, size, path in targets:
        items = ext.get(ino) or []
        if not items or size < 588:
            out.write("%s\t%d\t-\t-\t-\t-\t-\tNO_DATA\t%s\n" % (ino, size, path))
            nost["NO_DATA"] += 1
            continue
        blob = read_fo(items, size - 588, 588)
        marker = blob[568:572].hex(); mode = blob[572]
        param = blob[573]; crypto = blob[574]
        orig = struct.unpack_from("<Q", blob, 580)[0]
        ok = "OK" if orig == size - 588 else "MISMATCH"
        out.write("%s\t%d\t%s\t0x%02X\t%d\t0x%02X\t%d\t%s\t%s\n" % (
            ino, size, marker, mode, param, crypto, orig, ok, path))
        st[(mode, crypto, ok)] += 1
    out.close()
    print("=== 模式分布 (mode, crypto, check) ===")
    for k, v in st.most_common():
        print("  0x%02X  0x%02X  %-8s  %d" % (k[0], k[1], k[2], v))
    for k, v in nost.most_common():
        print("  %s  %d" % (k, v))
    print("总计:", sum(st.values()) + sum(nost.values()))

if __name__ == "__main__":
    main()
