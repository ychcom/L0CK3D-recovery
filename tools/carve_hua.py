#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VM 内运行：在源盘指定物理范围扫描 OLE2 复合文档魔数（xls/doc 旧格式），
对每个命中做结构校验并导出候选文件，写 manifest。
用法: python3 carve_hua.py <start> <end> <outdir>
安全: O_RDONLY 只读。
"""
import os
import sys
import struct

DEV = "/dev/loop1"
MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
MAXCAND = 131072          # 每候选最多导出 128KB（目标文件最大 86KB）
CHUNK = 64 << 20

start = int(sys.argv[1])
end = int(sys.argv[2])
outdir = sys.argv[3]
os.makedirs(outdir, exist_ok=True)

fd = os.open(DEV, os.O_RDONLY)
hits = []
pos = start
while pos < end:
    n = min(CHUNK, end - pos)
    data = os.read(fd, n)
    if not data:
        break
    off = 0
    while True:
        i = data.find(MAGIC, off)
        if i < 0:
            break
        hits.append(pos + i)
        off = i + 1
    pos += len(data)
    print("scanned %.1f%% hits=%d" % ((pos - start) * 100.0 / (end - start), len(hits)), flush=True)

print("SCAN_DONE hits=%d" % len(hits), flush=True)

man = open(os.path.join(outdir, "manifest.tsv"), "w")
man.write("idx\tabspos\tshift_ok\tminishift\tminor_ver\tdll_ver\tfirst_sec\n")
ok = 0
for k, h in enumerate(hits):
    os.lseek(fd, h, 0)
    head = os.read(fd, 512)
    if len(head) < 512:
        continue
    shift = struct.unpack_from("<H", head, 30)[0]
    minishift = struct.unpack_from("<H", head, 32)[0]
    minor, dll = struct.unpack_from("<HH", head, 24)
    first_sec = struct.unpack_from("<I", head, 48)[0] if False else 0
    # 合理的 OLE2: sector shift 9(512B) 或 12(4096B)，mini shift 6
    okshift = shift in (9, 12) and minishift == 6
    if not okshift:
        man.write("%d\t%d\t0\t%d\t%d\t%d\t0\n" % (k, h, minishift, minor, dll))
        continue
    os.lseek(fd, h, 0)
    blob = os.read(fd, MAXCAND)
    fn = os.path.join(outdir, "carve_%05d.bin" % k)
    with open(fn, "wb") as f:
        f.write(blob)
    man.write("%d\t%d\t1\t%d\t%d\t%d\t%d\n" % (k, h, minishift, minor, dll, len(blob)))
    ok += 1
man.close()
os.close(fd)
print("CARVE_DONE valid=%d total_hits=%d" % (ok, len(hits)), flush=True)
