#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
流式上传（避免一次性 read() 整个大文件导致内存耗尽）。

用法: python3 upload2.py <本地文件> <URL>
以 256KB 分块 PUT，Content-Length 由 os.path.getsize 提供。
"""
import os
import sys
import http.client
from urllib.parse import urlparse

path = sys.argv[1]
url = sys.argv[2]
n = os.path.getsize(path)
u = urlparse(url)
host = u.hostname
port = u.port or 80

conn = http.client.HTTPConnection(host, port, timeout=600)
conn.putrequest("PUT", u.path or "/", skip_host=False, skip_accept_encoding=True)
conn.putheader("Host", host if not u.port else "%s:%d" % (host, port))
conn.putheader("Content-Length", str(n))
conn.endheaders()

sent = 0
with open(path, "rb") as f:
    while True:
        b = f.read(262144)
        if not b:
            break
        conn.send(b)
        sent += len(b)
r = conn.getresponse()
r.read()
conn.close()
print("sent %s %d/%d status=%s" % (os.path.basename(path), sent, n, r.status), flush=True)
sys.exit(0 if r.status < 400 else 1)
