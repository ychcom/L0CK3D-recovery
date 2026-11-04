#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
利用 btrfs CoW 旧 extent 重建文件完整原文（crt106 思路的精简实现）。

原理：extent_data 三元组 (file_off, logical, ext_off, length, total, gen)。
  - 旧 extent（gen < NEWGEN）的起点 logical 对应文件偏移 S = file_off - ext_off
  - 文件偏移 [S, S+total) 的原文可能都存在于磁盘 extent 内 [0, total)
  - 同区间多个旧 extent 时取 gen 最大的（最新原文版本）

用法: rebuild.py ino1,ino2,...  -> /root/rb_out/<ino>.bin
"""
import sys, os, re, subprocess, bisect, collections

DEV = "/dev/loop1"
EXT = "/root/ext260.tsv"
NEWGEN = 4450000
OUTD = "/root/rb_out"
os.makedirs(OUTD, exist_ok=True)

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
sys.stderr.write("chunks %d\n" % len(CH))

def l2p(logical):
    i = bisect.bisect_right(LO, logical) - 1
    if i >= 0:
        c = CH[i]
        if c["logical"] <= logical < c["logical"] + c["len"]:
            return c["phys"] + (logical - c["logical"])
    return None

FH = open(DEV, "rb")

def load_old_extents(inodes):
    """ino -> [(S, total, logical, gen)] 按 S 升序"""
    out = collections.defaultdict(list)
    for line in open(EXT):
        c = line.rstrip("\r\n").split("\t")
        if len(c) < 7 or c[0] not in inodes: continue
        try:
            fo = int(c[1]); logi = int(c[2]); eo = int(c[3])
            ln = int(c[4]); tot = int(c[5]); gen = int(c[6])
        except ValueError:
            continue
        if gen < NEWGEN:
            out[c[0]].append((fo - eo, tot, logi, gen))
    for k in out:
        out[k].sort(key=lambda x: (x[0], -x[3]))
    return out

def read_phys(phys, n):
    FH.seek(phys); return FH.read(n)

def rebuild(ino, orig, path):
    """重建 [0, orig)，返回 (bytes, covered_ratio)。未覆盖区填 0。"""
    es = EXT_EXT.get(ino, [])
    if not es: return None, 0.0
    out = bytearray(orig)
    pos = 0
    covered = 0
    while pos < orig:
        best = None
        for (S, tot, logi, gen) in es:
            if S <= pos < S + tot:
                if best is None or gen > best[3]:
                    best = (S, tot, logi, gen)
        if best is None:
            break
        S, tot, logi, gen = best
        end = min(S + tot, orig)
        # 分块读，处理跨 chunk
        cur = pos
        while cur < end:
            want = min(1 << 20, end - cur)
            # extent 内偏移 = cur - S
            ph = l2p(logi + (cur - S))
            if ph is None:
                cur += want; continue
            # 限制在当前 chunk 边界内
            data = read_phys(ph, want)
            out[cur:cur+len(data)] = data
            cur += len(data)
        covered += end - pos
        pos = end
    return bytes(out), covered / orig

EXT_EXT = {}

def main():
    inodes = set(sys.argv[1].split(","))
    global EXT_EXT
    EXT_EXT = load_old_extents(inodes)
    # footer_scan.tsv 拿 orig
    info = {}
    for line in open("/root/footer_scan.tsv", encoding="utf-8", errors="replace"):
        q = line.rstrip("\n").split("\t")
        if len(q) >= 9 and q[7] == "OK":
            info[q[0]] = (int(q[6]), q[8])
    for ino in inodes:
        if ino not in info:
            print("%s\tNO_FOOTER" % ino); continue
        orig, path = info[ino]
        data, ratio = rebuild(ino, orig, path)
        if data is None:
            print("%s\tNO_OLD_EXT\t%s" % (ino, path)); continue
        open(os.path.join(OUTD, "%s.bin" % ino), "wb").write(data)
        print("%s\tratio=%.4f\t%d\t%s" % (ino, ratio, orig, path))

if __name__ == "__main__":
    main()
