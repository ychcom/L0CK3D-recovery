#!/usr/bin/env python3
# 简易上传接收服务：虚拟机 -> 本机
# 仅监听回环地址，仅用于可信内网的临时传输，无鉴权，用完即停
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

SAVE_DIR = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("SAVE_DIR", "./vmout")
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8124
os.makedirs(SAVE_DIR, exist_ok=True)


class H(BaseHTTPRequestHandler):
    def do_PUT(self):
        n = int(self.headers.get('Content-Length', 0))
        name = os.path.basename(self.path.strip('/')) or 'upload.bin'
        with open(os.path.join(SAVE_DIR, name), 'wb') as f:
            left = n
            while left > 0:
                b = self.rfile.read(min(65536, left))
                if not b:
                    break
                f.write(b)
                left -= len(b)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')
        print('saved %s (%d bytes)' % (name, n), flush=True)

    def do_POST(self):
        self.do_PUT()

    def log_message(self, *a):
        pass


print('upload server on %d -> %s' % (PORT, SAVE_DIR), flush=True)
HTTPServer(('127.0.0.1', PORT), H).serve_forever()
