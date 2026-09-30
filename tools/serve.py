#!/usr/bin/env python3
"""Serve the site locally for testing.

  python3 tools/serve.py            # http://127.0.0.1:8002
  PORT=9000 python3 tools/serve.py

Writes generated test pages into the repo root, which is gitignored.
"""
import functools
import http.server
import os
import socketserver

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = int(os.environ.get("PORT", "8002"))


class Handler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def log_message(self, fmt, *a):
        pass


if __name__ == "__main__":
    socketserver.TCPServer.allow_reuse_address = True
    handler = functools.partial(Handler, directory=ROOT)
    with socketserver.TCPServer(("0.0.0.0", PORT), handler) as httpd:
        print("serving %s on http://127.0.0.1:%d" % (ROOT, PORT), flush=True)
        httpd.serve_forever()
