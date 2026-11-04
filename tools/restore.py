#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
C3RB3R 端到端还原器（S1：btrfs CoW 算术反演，全程只读）

原理
  btrfs 写时复制 + extent 未拆分 -> 被勒索软件覆盖丢弃的「原文明文段」仍然 allocated，
  原文还在原物理位置。加密段的原文逻辑地址可由相邻存活的旧 item 纯算术推出：
      P_pre  = 前一个旧 item 的 (diskbyte + dataoff + itemlen)
      P_post = 后一个旧 item 的 (diskbyte + dataoff) - L
      P_pre == P_post  -> 双向校验通过（BOTH）
  未加密段（generation < NEWGEN）直接按 item 读出即为原文。
  输出长度 = marker 记录的原件大小（= 密文大小 - 588），尾记录自然被裁掉。

用法: python3 restore.py <subvol_id> <restore_list.tsv> <outdir>
  restore_list.tsv: name<TAB>inode<TAB>csize<TAB>origsize<TAB>rel
产出: <outdir>/<name>.bin  还原出的原文件
      <outdir>/manifest.tsv / segments.tsv  审计信息

安全: 设备以 O_RDONLY 打开；不写源盘、不 mount、不做 balance/defrag/repair。
"""
import os
import re
import sys
import json
import struct
import hashlib
import subprocess

DEV = "/dev/loop1"
SID = int(sys.argv[1])
LIST = sys.argv[2]
OUTD = sys.argv[3]
# 可选参数 4：上传基址（如 http://192.0.2.68:8124）。提供时，每个文件还原完立刻
# 流式上传并删除本地副本，使 VM 磁盘占用保持在单文件量级（大文件必用）。
UPBASE = sys.argv[4].rstrip("/") if len(sys.argv) > 4 and sys.argv[4] else None
UPHOST = UPPORT = None
if UPBASE:
    from urllib.parse import urlparse
    _u = urlparse(UPBASE)
    UPHOST, UPPORT = _u.hostname, (_u.port or 80)
# 大于该值则流式直传（VM 内存盘仅 ~989MB，大文件落盘必爆）
DISK_LIMIT = int(os.environ.get("DISK_LIMIT", "256")) * 1048576


class StreamOut(object):
    """小文件：落盘 -> upload2 上传 -> 删除本地；
       大文件：边组装边 HTTP PUT（Content-Length 预置为原件大小），全程不落盘。"""

    def __init__(self, name, orig, path):
        self.name, self.orig, self.path = name, orig, path
        self.mode = "http" if (UPBASE and orig > DISK_LIMIT) else "disk"
        self.head = b""
        self.tail = b""
        self.n = 0
        if self.mode == "http":
            import http.client
            self.conn = http.client.HTTPConnection(UPHOST, UPPORT, timeout=1800)
            self.conn.putrequest("PUT", "/%s.bin" % name,
                                 skip_host=False, skip_accept_encoding=True)
            self.conn.putheader("Host", UPHOST if not UPPORT else "%s:%d" % (UPHOST, UPPORT))
            self.conn.putheader("Content-Length", str(orig))
            self.conn.endheaders()
            self.f = None
        else:
            self.conn = None
            self.f = open(path, "wb")

    def write(self, b):
        if not b:
            return
        if self.n < 16:
            self.head = (self.head + b)[:16]
        self.tail = (self.tail + b)[-65536:]
        self.n += len(b)
        if self.mode == "http":
            self.conn.send(b)
        else:
            self.f.write(b)

    def close(self):
        """幂等：可能被多次调用（收尾处重复 close 不应报错或重复上传）"""
        if getattr(self, "closed", False):
            return self.ok
        self.closed = True
        if self.mode == "http":
            r = self.conn.getresponse()
            r.read()
            self.conn.close()
            sys.stderr.write("STREAM %s %d/%d status=%s\n"
                             % (self.name, self.n, self.orig, r.status))
            self.ok = (r.status < 400)
            return self.ok
        self.f.close()
        self.ok = upload(self.name, self.path)
        return self.ok
# 攻击窗口 generation 下界（旧块实测 gen≈2227xx / 813894；攻击写入实测 gen=4452375）
# 可用环境变量 NEWGEN 覆盖（用于救援“攻击前数月写入、gen 已越过 4,000,000”的文件）
NEWGEN = int(os.environ.get("NEWGEN", "4000000"))

targets = []
for line in open(LIST, encoding="utf-8", errors="replace"):
    c = line.rstrip("\r\n").split("\t")
    if len(c) < 4 or not c[1].isdigit():      # 跳过空行与表头
        continue
    targets.append(dict(name=c[0], ino=int(c[1]), csize=int(c[2]),
                        orig=int(c[3]), rel=c[4] if len(c) > 4 else ""))
sys.stderr.write("targets %d\n" % len(targets))
os.makedirs(OUTD, exist_ok=True)
T = {t["ino"]: t for t in targets}


def load_chunks():
    p = subprocess.run(["btrfs", "inspect-internal", "dump-tree", "-t", "3", DEV],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    out = p.stdout.decode("utf-8", "replace")
    res = []
    cur = None
    for line in out.split("\n"):
        m = re.search(r"CHUNK_ITEM (\d+)", line)
        if m:
            cur = {"logical": int(m.group(1)), "len": None, "phys": None, "type": ""}
            res.append(cur)
            continue
        if cur is None:
            continue
        if cur["len"] is None:
            m = re.search(r"length (\d+)", line)
            if m:
                cur["len"] = int(m.group(1))
        m = re.search(r"type (\w+)", line)
        if m:
            cur["type"] = m.group(1)
        if cur["phys"] is None:
            m = re.search(r"stripe 0 devid \d+ offset (\d+)", line)
            if m:
                cur["phys"] = int(m.group(1))
    return [c for c in res if c["len"] and c["phys"] is not None]


CH = load_chunks()
sys.stderr.write("chunks %d\n" % len(CH))


def l2p(logical):
    for c in CH:
        if c["logical"] <= logical < c["logical"] + c["len"]:
            return c["phys"] + (logical - c["logical"])
    return None


re_item = re.compile(r"item\s+\d+\s+key\s+\((\d+)\s+(EXTENT_DATA)\s+(\d+)\)")
re_disk = re.compile(r"extent data disk byte (\d+) nr (\d+)")
re_doff = re.compile(r"extent data offset (\d+) nr (\d+)")
re_inline = re.compile(r"inline extent data size (\d+)")
re_gen = re.compile(r"^\s+generation (\d+)")

extents = {}
EXTFILE = os.environ.get("EXTFILE")     # 复用已 dump 好的 extent 表，避免每批重复 dump
if EXTFILE:
    with open(EXTFILE) as fe:
        for line in fe:
            c = line.rstrip("\r\n").split("\t")
            if len(c) < 7:
                continue
            oid = int(c[0])
            if oid not in T:
                continue
            extents.setdefault(oid, []).append(
                (int(c[1]), int(c[2]), int(c[3]), int(c[4]), int(c[5]), int(c[6])))
    sys.stderr.write("loaded extents from %s: %d inodes\n" % (EXTFILE, len(extents)))
else:
    cur = None
    cgen = 0
    cdisk = None
    cextlen = 0
    p = subprocess.Popen(
        ["btrfs", "inspect-internal", "dump-tree", "-t", str(SID), DEV],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, errors="replace", bufsize=1 << 20,
    )
    for line in p.stdout:
        m = re_item.search(line)
        if m:
            oid = int(m.group(1))
            cur = (oid, int(m.group(3))) if oid in T else None
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
            extents.setdefault(oid, []).append((foff, cdisk, doff, ilen, cextlen, cgen))
            continue
        if re_inline.search(line):
            extents.setdefault(oid, []).append((foff, -1, 0, 0, 0, cgen))
    p.stdout.close()
    p.wait()
    sys.stderr.write("got extents for %d inodes\n" % len(extents))

fh = open(DEV, "rb")


def anchor(items, s, e):
    """返回 (pre, post)：加密段 [s,e) 原文逻辑地址的两种独立推算"""
    L = e - s
    pre = post = None
    for it in items:
        foff, disk, doff, ilen, extlen, gen = it
        if gen >= NEWGEN or disk < 0:
            continue
        if foff + ilen == s:
            pre = disk + doff + ilen
        if foff == e:
            post = disk + doff - L
    return pre, post


def self_copy_addr(items, s, orig):
    """
    末端兜底：btrfs 的 EXTENT_DATA 要求 fileoff 与 extent 内偏移同为 4096 对齐，
    因此勒索软件在文件末尾追加 588B 尾记录时，btrfs 会把「最后一个不足 1 块的原文尾巴」
    一并复制进新 extent。也就是说，若某 item 是最后一个且 (orig - fileoff) < 4096，
    该 item 的前 (orig - fileoff) 字节就是原文副本，可直接自读，无需锚点。
    """
    # 仅对「文件至少 1 块、末端不足 1 块」的情形启用；极小文件（<4096）不启用，
    # 那种文件本身就是全加密，自读只会取回密文。
    if orig < 4096 or orig - s >= 4096 or orig - s <= 0:
        return None
    for it in items:
        foff, disk, doff, ilen, extlen, gen = it
        if foff == s and disk >= 0:
            if max(x[0] for x in items) == foff:      # 必须是最后一个 item
                # item 必须还装得下 588B 尾记录，否则它本身就是纯密文段
                if ilen > (orig - s) + 588:
                    return disk + doff
    return None


def runs_of(items):
    """把连续同类的 item 合并成 run（加密段可能被拆成多个 item）"""
    items = sorted(items, key=lambda x: x[0])
    runs = []
    for it in items:
        foff, disk, doff, ilen, extlen, gen = it
        if ilen <= 0:
            continue
        kind = "C" if gen >= NEWGEN else "P"
        if runs and runs[-1]["kind"] == kind and runs[-1]["e"] == foff:
            runs[-1]["e"] = foff + ilen
        else:
            runs.append(dict(kind=kind, s=foff, e=foff + ilen))
    return runs


def upload(name, path):
    """还原完即流式上传，成功后删除本地副本，避免 VM 磁盘被占满"""
    if not UPBASE:
        return True
    try:
        import subprocess
        r = subprocess.run(["python3", "/root/upload2.py", path,
                            "%s/%s.bin" % (UPBASE, name)],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=1800)
        ok = (r.returncode == 0)
        sys.stderr.write("UP %s %s\n" % (name, "OK" if ok else "FAIL:" + r.stdout.decode()[-200:]))
        if ok:
            try:
                os.remove(path)
            except Exception:
                pass
        return ok
    except Exception as e:
        sys.stderr.write("UP %s EXC %s\n" % (name, e))
        return False


def fill_zero(fo, h, n):
    """分块写零，避免 b'\\x00' * n 一次性分配 GB 级内存（VM 内存盘仅 ~989MB）"""
    blk = b"\x00" * (1 << 20)
    while n > 0:
        k = blk if n >= len(blk) else blk[:n]
        fo.write(k)
        h.update(k)
        n -= len(k)


def read_seg(fh, phys, L, fo, h):
    """分块读源段并写出，避免 fh.read(L) 把整段（可达数 GB）一次性读入内存"""
    fh.seek(phys)
    left = L
    while left > 0:
        data = fh.read(min(1 << 20, left))
        if not data:
            fill_zero(fo, h, left)
            break
        fo.write(data)
        h.update(data)
        left -= len(data)


MAGICS = [
    (b"\xff\xd8\xff", "JPEG"), (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"GIF87a", "GIF"), (b"GIF89a", "GIF"), (b"%PDF", "PDF"),
    (b"PK\x03\x04", "ZIP"), (b"Rar!", "RAR"), (b"RIFF", "RIFF"),
    (b"\x1a\x45\xdf\xa3", "MKV"), (b"ID3", "MP3"), (b"BM", "BMP"),
    (b"II*\x00", "TIFF"), (b"MM\x00*", "TIFF"), (b"OggS", "OGG"),
    (b"\x00\x00\x00\x18ftyp", "MP4"), (b"\x00\x00\x00\x20ftyp", "MP4"),
]


def sniff(head, path):
    for sig, nm in MAGICS:
        if head.startswith(sig):
            return nm
    if len(head) >= 8 and head[4:8] == b"ftyp":
        return "MP4"
    return "UNKNOWN"


def struct_ok(kind, head, tail):
    """容器级首尾结构自检（无备份时唯一的正确性旁证），直接吃内存中的首尾字节"""
    head = head or b""
    tail = tail or b""
    if kind == "JPEG":
        return "OK" if (head[:3] == b"\xff\xd8\xff" and b"\xff\xd9" in tail) else "BAD"
    if kind == "MP4":
        return "OK" if head[4:8] == b"ftyp" else "BAD"
    if kind == "PNG":
        return "OK" if b"IEND" in tail else "BAD"
    if kind == "PDF":
        return "OK" if (head[:4] == b"%PDF" and b"%%EOF" in tail) else "BAD"
    return "NA"


man = open(os.path.join(OUTD, "manifest.tsv"), "w", encoding="utf-8")
man.write("name\tinode\trel\torig\tcsize\tgot\tsha256\tgap_bytes\t"
          "n_cipher_seg\tcipher_bytes_restored\tcipher_bytes_missing\tconf\t"
          "trailer_u32\thead16\ttail16\tmagic\tstruct\n")
segf = open(os.path.join(OUTD, "segments.tsv"), "w", encoding="utf-8")
segf.write("name\tkind\tfileoff\tlen\tsrc_logical\tconf\tnote\n")

for t in targets:
    ino = t["ino"]
    items = extents.get(ino, [])
    orig = t["orig"]
    out_path = os.path.join(OUTD, t["name"] + ".bin")
    fo = StreamOut(t["name"], orig, out_path)
    h = hashlib.sha256()
    pos = 0
    gap = 0
    n_cip = 0
    cip_ok = 0
    cip_miss = 0
    confs = []

    # 尾记录 marker 交叉校验（读密文最后 16B）
    trailer = ""
    try:
        last = max(items, key=lambda x: x[0])
        L = last[3]
        if L >= 16 and last[1] >= 0:
            ph = l2p(last[1] + last[2] + max(0, L - 16))
            if ph is not None:
                fh.seek(ph)
                b16 = fh.read(16)
                trailer = ",".join(str(x) for x in struct.unpack("<4I", b16))
    except Exception:
        pass

    for run in runs_of(items):
        s, e = run["s"], run["e"]
        if e <= pos:
            continue
        if s > orig:
            break
        if s > pos:                      # 空洞
            n = min(s, orig) - pos
            fill_zero(fo, h, n)
            gap += n
            pos = s
            if pos >= orig:
                break
        e = min(e, orig)
        L = e - s
        if run["kind"] == "P":
            it = None
            for x in items:
                if x[0] <= s and x[0] + x[3] > s:
                    it = x
            if it is None or it[1] < 0:
                fill_zero(fo, h, L)
                gap += L
                segf.write("%s\tP\t%d\t%d\t-1\tNONE\tinline/hole\n" % (t["name"], s, L))
            else:
                phys = l2p(it[1] + it[2] + (s - it[0]))
                if phys is None:
                    fill_zero(fo, h, L)
                    gap += L
                    segf.write("%s\tP\t%d\t%d\t-1\tNOMAP\tchunk map miss\n" % (t["name"], s, L))
                else:
                    read_seg(fh, phys, L, fo, h)
                    segf.write("%s\tP\t%d\t%d\t%d\tDIRECT\tplain read\n"
                               % (t["name"], s, L, it[1] + it[2] + (s - it[0])))
        else:
            n_cip += 1
            pre, post = anchor(items, s, e)
            if pre is not None and post is not None:
                conf, P = ("BOTH", pre) if pre == post else ("CONFLICT", post)
            elif pre is not None:
                conf, P = "PRE", pre
            elif post is not None:
                conf, P = "POST", post
            else:
                sa = self_copy_addr(items, s, orig)
                if sa is not None:
                    conf, P = "SELF", sa
                else:
                    conf, P = "NO_ANCHOR", None
            confs.append(conf)
            if P is None:
                fill_zero(fo, h, L)
                cip_miss += L
                segf.write("%s\tC\t%d\t%d\t-1\tNO_ANCHOR\tzero-filled\n" % (t["name"], s, L))
            else:
                phys = l2p(P)
                if phys is None:
                    fill_zero(fo, h, L)
                    cip_miss += L
                    segf.write("%s\tC\t%d\t%d\t%d\t%s\tNOMAP\n" % (t["name"], s, L, P, conf))
                else:
                    read_seg(fh, phys, L, fo, h)
                    cip_ok += L
                    segf.write("%s\tC\t%d\t%d\t%d\t%s\trestored\n" % (t["name"], s, L, P, conf))
        pos = e
        if pos >= orig:
            break
    if pos < orig:
        n = orig - pos
        fill_zero(fo, h, n)
        gap += n
        pos = orig
    fo.close()

    conf = "BOTH" if confs and all(c == "BOTH" for c in confs) else (
        "MIXED" if confs else "NO_CIPHER")
    if "NO_ANCHOR" in confs:
        conf = "NO_ANCHOR"
    if "CONFLICT" in confs:
        conf = "CONFLICT"

    head16 = fo.head[:16].hex()
    tail16 = fo.tail[-16:].hex()
    mtype = sniff(fo.head[:16], out_path)
    sok = struct_ok(mtype, fo.head[:16], fo.tail)

    man.write("%s\t%d\t%s\t%d\t%d\t%d\t%s\t%d\t%d\t%d\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n" % (
        t["name"], ino, t["rel"], orig, t["csize"], pos, h.hexdigest(), gap,
        n_cip, cip_ok, cip_miss, conf, trailer, head16, tail16, mtype, sok))
    sys.stderr.write("%s ino=%d orig=%d got=%d cipher=%d/%d conf=%s struct=%s sha=%s\n"
                     % (t["name"], ino, orig, pos, cip_ok, cip_ok + cip_miss,
                        conf, sok, h.hexdigest()[:16]))
    up_ok = fo.close()
    if not up_ok:
        sys.stderr.write("UPLOAD_FAIL %s\n" % t["name"])

man.close()
segf.close()
fh.close()
sys.stderr.write("DONE %d\n" % len(targets))
