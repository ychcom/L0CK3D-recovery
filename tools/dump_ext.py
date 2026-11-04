#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VM 内运行：对子卷做**一次** dump-tree，把全部 EXTENT_DATA 落成 TSV，供后续所有批次复用。
（restore.py 原本每批都重新 dump 一次，Share 子卷单次约 20-60 分钟，多批次会重复浪费。）

用法: python3 dump_ext.py <subvol_id> <out.tsv>
输出: oid \t fileoff \t diskbyte \t dataoff \t itemlen \t extlen \t generation
      （inline extent 记 diskbyte=-1）
安全: 只读 dump-tree，不写源盘。
"""
import re
import sys
import subprocess

DEV = "/dev/loop1"
SID = int(sys.argv[1])
OUT = sys.argv[2]

re_item = re.compile(r"item\s+\d+\s+key\s+\((\d+)\s+(EXTENT_DATA)\s+(\d+)\)")
re_disk = re.compile(r"extent data disk byte (\d+) nr (\d+)")
re_doff = re.compile(r"extent data offset (\d+) nr (\d+)")
re_inline = re.compile(r"inline extent data size (\d+)")
re_gen = re.compile(r"^\s+generation (\d+)")

p = subprocess.Popen(
    ["btrfs", "inspect-internal", "dump-tree", "-t", str(SID), DEV],
    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    text=True, errors="replace", bufsize=1 << 20,
)

cur = None
cgen = 0
cdisk = None
cextlen = 0
n = 0
with open(OUT, "w") as fo:
    for line in p.stdout:
        m = re_item.search(line)
        if m:
            cur = (int(m.group(1)), int(m.group(3)))
            cgen = 0
            cdisk = None
            cextlen = 0
            continue
        g = re_gen.search(line)
        if g:
            cgen = int(g.group(1))
            continue
        if cur is None:
            continue
        oid, foff = cur
        m1 = re_disk.search(line)
        if m1:
            cdisk = int(m1.group(1))
            cextlen = int(m1.group(2))
            continue
        m2 = re_doff.search(line)
        if m2:
            doff = int(m2.group(1))
            ilen = int(m2.group(2))
            if cdisk is None:
                continue
            fo.write("%d\t%d\t%d\t%d\t%d\t%d\t%d\n" % (oid, foff, cdisk, doff, ilen, cextlen, cgen))
            n += 1
            continue
        if re_inline.search(line):
            fo.write("%d\t%d\t%d\t%d\t%d\t%d\t%d\n" % (oid, foff, -1, 0, 0, 0, cgen))
            n += 1
p.stdout.close()
p.wait()
sys.stderr.write("dump_ext subvol=%d wrote %d extent items to %s\n" % (SID, n, OUT))
