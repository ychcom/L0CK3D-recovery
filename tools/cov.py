#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
评估每个 .L0CK3D 文件能否被"旧代际 extent"完整覆盖（=> 可 100% 无损恢复）。
旧 extent: generation < NEWGEN（加密时的代际）。
覆盖区间 = [file_off - ext_off, file_off - ext_off + total_size)
"""
import sys, collections

EXT = "/root/ext260.tsv"
NEWGEN = 4450000
SCAN = "/root/footer_scan.tsv"

def main():
    # footer 提供 orig 和 mode
    info = {}
    for line in open(SCAN, encoding="utf-8", errors="replace"):
        q = line.rstrip("\n").split("\t")
        if len(q) >= 9 and q[7] == "OK":
            info[q[0]] = dict(size=int(q[1]), mode=q[3], param=int(q[4]),
                              orig=int(q[6]), path=q[8])
    inodes = set(info)

    ext = collections.defaultdict(list)
    for line in open(EXT):
        c = line.rstrip("\r\n").split("\t")
        if len(c) < 7 or c[0] not in inodes: continue
        try:
            fo = int(c[1]); logi = int(c[2]); eo = int(c[3])
            ln = int(c[4]); tot = int(c[5]); gen = int(c[6])
        except ValueError:
            continue
        if gen < NEWGEN:                     # 旧代际
            s = fo - eo
            ext[c[0]].append((s, s + tot))

    fully = part = none = 0
    out = open("/root/coverage.tsv", "w", encoding="utf-8")
    out.write("ino\torig\tmode\ttotal_size\tcovered\tratio\tfully\tpath\n")
    for ino, inf in info.items():
        orig = inf["orig"]
        ivs = ext.get(ino, [])
        if not ivs:
            out.write("%s\t%d\t%s\t0\t0\t0\tNO_EXT\t%s\n" % (ino, orig, inf["mode"], inf["path"]))
            none += 1; continue
        # 合并区间
        ivs.sort()
        merged = []
        for s, e in ivs:
            if merged and s <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], e)
            else:
                merged.append([s, e])
        # 与 [0, orig) 的覆盖
        covered = 0
        for s, e in merged:
            covered += max(0, min(e, orig) - max(s, 0))
        ratio = covered / orig if orig else 0
        full = 1 if covered >= orig else 0
        if full: fully += 1
        elif covered > 0: part += 1
        else: none += 1
        out.write("%s\t%d\t%s\t%d\t%d\t%.4f\t%d\t%s\n" % (
            ino, orig, inf["mode"], orig, covered, ratio, full, inf["path"]))
    out.close()
    print("完整覆盖(100%%): %d, 部分覆盖: %d, 无覆盖: %d, 总计 %d" % (fully, part, none, len(info)))

if __name__ == "__main__":
    main()
