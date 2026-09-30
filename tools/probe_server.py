#!/usr/bin/env python3
"""Serve the draft and log viewport probe reports from the PS5.

Two jobs:
  1. static files from the draft dir
  2. GET/POST /__probe -> append a timestamped line to probe.log

Run:  python3 probe_server.py [port] [draftdir]
"""
import http.server
import json
import os
import sys
import datetime

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8002
ROOT = sys.argv[2] if len(sys.argv) > 2 else os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(ROOT, "probe.log")

INTERESTING = [
    "innerWidth", "innerHeight", "clientWidth", "clientHeight",
    "outerWidth", "outerHeight", "dpr", "screenW", "screenH",
    "availW", "availH", "colorDepth", "vvW", "vvH", "vvScale",
    "touch", "maxTouch", "onLine", "ua", "colorScheme",
]


class H(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=ROOT, **kw)

    def _record(self, raw):
        from urllib.parse import parse_qs
        q = parse_qs(raw)
        d = {k: v[0] for k, v in q.items()}
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG, "a") as f:
            f.write("\n===== %s =====\n" % ts)
            for k in INTERESTING:
                if k in d:
                    f.write("  %-18s %s\n" % (k, d[k]))
            f.write("  %-18s %s\n" % ("raw", raw))
        print("PROBE @ %s -> %s" % (ts, json.dumps(d, sort_keys=True)), flush=True)

    def do_GET(self):
        if self.path.split("?")[0] == "/__probe":
            raw = self.path.split("?", 1)[1] if "?" in self.path else ""
            self._record(raw)
            self.send_response(204)
            self.end_headers()
            return
        super().do_GET()

    def do_POST(self):
        if self.path.split("?")[0] == "/__probe":
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n).decode("utf-8", "replace")
            self._record(raw)
            self.send_response(204)
            self.end_headers()
            return
        self.send_error(405)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print("probe server on :%d serving %s" % (PORT, ROOT), flush=True)
    http.server.ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
