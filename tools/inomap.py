#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
路径 -> inode 号映射（只读，运行在 Alpine VM 内）

复用 diskinv.py 的解析逻辑，额外输出 inode 号，供 fetchx.py 按物理偏移取字节。

用法: python3 inomap.py <subvol_id> <out.tsv>
输出: path \t inode \t type(F|D) \t size \t mtime \t locked
"""
import re
import sys
import subprocess

DEV = "/dev/loop1"
ROOT_DIRID = 256

SID = int(sys.argv[1])
OUT = sys.argv[2]

re_item = re.compile(r"item\s+\d+\s+key\s+\((\d+)\s+(\w+)\s+(\d+)\)")
re_loc = re.compile(r"location key \((\d+) INODE_ITEM 0\)")
re_name = re.compile(r"^\s*name:\s*(.*)$")
re_size = re.compile(r"\bsize\s+(\d+)")
re_mode = re.compile(r"\bmode\s+(\d+)")
re_mtime = re.compile(r"^\s*mtime\s+(\d+)")
re_type = re.compile(r"type\s+(\S+)")
LOCK = re.compile(r"\.(L0CK3D|LOCK3D)$", re.I)
re_oct = re.compile(r"\\([0-7]{3})")


def unescape(name):
    if "\\" not in name:
        return name
    try:
        bs = re_oct.sub(lambda m: chr(int(m.group(1), 8)), name)
        return bs.encode("latin-1", "replace").decode("utf-8", "replace")
    except Exception:
        return name


children = {}
inode = {}

cur_kind = None
cur_ino = None
parent_ino = None
pending = None

p = subprocess.Popen(
    ["btrfs", "inspect-internal", "dump-tree", "-t", str(SID), DEV],
    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    text=True, errors="replace", bufsize=1 << 20,
)

n = 0
for line in p.stdout:
    n += 1
    m = re_item.search(line)
    if m:
        oid, typ = int(m.group(1)), m.group(2)
        cur_ino = None
        cur_kind = None
        parent_ino = None
        pending = None
        if typ == "INODE_ITEM":
            cur_ino = oid
            cur_kind = "inode"
            if oid not in inode:
                inode[oid] = [0, 0, 0]
        elif typ in ("DIR_ITEM", "DIR_INDEX"):
            cur_kind = "dir"
            parent_ino = oid
        continue

    if cur_kind == "inode" and cur_ino is not None:
        m2 = re_size.search(line)
        if m2:
            inode[cur_ino][0] = int(m2.group(1))
        m3 = re_mode.search(line)
        if m3:
            inode[cur_ino][2] = int(m3.group(1))
        m4 = re_mtime.search(line)
        if m4:
            inode[cur_ino][1] = int(m4.group(1))
        continue

    if cur_kind == "dir" and parent_ino is not None:
        m2 = re_loc.search(line)
        if m2:
            cino = int(m2.group(1))
            t = re_type.search(line)
            if t:
                tv = t.group(1)
                ft = "D" if (tv in ("DIR", "2") or "DIR" in tv) else "F"
            else:
                ft = "?"
            pending = (cino, ft)
            continue
        m3 = re_name.search(line)
        if m3 and pending:
            cino, ft = pending
            name = unescape(m3.group(1).rstrip("\r\n"))
            d = children.setdefault(parent_ino, {})
            if cino not in d or d[cino][0] is None:
                d[cino] = (name, ft)
            pending = None
        continue

p.stdout.close()
p.wait()
sys.stderr.write("parsed %d lines, %d inodes, %d dirs\n" % (n, len(inode), len(children)))

for pid, d in children.items():
    for cino, (name, ft) in d.items():
        if ft == "?":
            md = inode.get(cino, [0, 0, 0])[2]
            d[cino] = (name, "D" if (md & 0o170000) == 0o040000 else "F")

out = open(OUT, "w", encoding="utf-8", errors="replace")
seen = set()
stack = [(ROOT_DIRID, "")]
info = inode.get(ROOT_DIRID, [0, 0, 0])
out.write("/\t%d\tD\t%d\t%d\t0\n" % (ROOT_DIRID, info[0], info[1]))
cnt = 0
while stack:
    ino, path = stack.pop()
    if ino in seen:
        continue
    seen.add(ino)
    for cino, (name, ft) in sorted(children.get(ino, {}).items(), key=lambda x: x[1][0] or ""):
        if name is None:
            continue
        cp = path + "/" + name
        inf = inode.get(cino, [0, 0, 0])
        out.write("%s\t%d\t%s\t%d\t%d\t%d\n" % (
            cp, cino, ft if ft != "?" else "F", inf[0], inf[1], 1 if LOCK.search(name) else 0))
        cnt += 1
        if ft == "D":
            stack.append((cino, cp))
out.close()
sys.stderr.write("wrote %d entries to %s\n" % (cnt, OUT))
