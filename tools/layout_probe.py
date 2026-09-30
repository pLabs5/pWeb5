#!/usr/bin/env python3
"""Render draft/index.html headless at several sizes and dump layout metrics.

Chromium can screenshot but we need numbers, so inject a measuring script into
a copy of the page and read the results back out of the DOM.
"""
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(ROOT, "index.html")).read()

PROBE = """
<script>
setTimeout(function () {
  var de = document.documentElement;
  function box(sel) {
    var el = document.querySelector(sel);
    if (!el) return null;
    var r = el.getBoundingClientRect();
    return { w: Math.round(r.width), h: Math.round(r.height),
             top: Math.round(r.top), left: Math.round(r.left) };
  }
  var widest = 0, widestSel = "";
  document.querySelectorAll("#main *").forEach(function (el) {
    var r = el.getBoundingClientRect();
    if (r.width > widest) {
      widest = r.width;
      widestSel = el.className || el.tagName;
    }
  });
  var out = {
    viewport: window.innerWidth + "x" + window.innerHeight,
    rootFontPx: getComputedStyle(de).fontSize,
    main: box("#main"),
    bar: box(".bar"),
    rowhead: box(".rowhead"),
    secStages: box("#secStages"),
    secSession: box("#secSession"),
    secQueue: box("#secQueue"),
    secLog: box("#secLog"),
    log: box("#log"),
    note: box(".note"),
    docScrollH: de.scrollHeight,
    bodyScrollH: document.body.scrollHeight,
    vOverflow: de.scrollHeight > window.innerHeight,
    hOverflow: de.scrollWidth > window.innerWidth,
    widestChild: Math.round(widest),
    widestSel: String(widestSel).slice(0, 30),
    visibleScreen: ["boot","main","done","measure"].filter(function (id) {
      return !document.getElementById(id).classList.contains("hidden");
    }).join(","),
    collapsed: ["secStages","secSession","secQueue","secLog"].filter(function (id) {
      return document.getElementById(id).classList.contains("collapsed");
    }).join(",")
  };
  var p = document.createElement("pre");
  p.id = "LAYOUTJSON";
  p.textContent = JSON.stringify(out);
  document.body.appendChild(p);
}, 4000);
</script>
"""


def run(w, h):
    html = SRC.replace("</body>", PROBE + "</body>")
    fd, path = tempfile.mkstemp(suffix=".html", dir=tempfile.gettempdir())
    os.write(fd, html.encode())
    os.close(fd)
    cmd = [
        "nix", "shell", "nixpkgs#chromium", "-c", "chromium",
        "--headless", "--no-sandbox", "--disable-gpu", "--hide-scrollbars",
        "--force-device-scale-factor=1",
        "--window-size=%d,%d" % (w, h),
        "--virtual-time-budget=6000", "--dump-dom",
        "file://" + path,
    ]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=240).stdout
    finally:
        os.unlink(path)
    m = re.search(r'LAYOUTJSON">(.*?)</pre>', out, re.S)
    if not m:
        return None
    import html as htm
    import json
    return json.loads(htm.unescape(m.group(1)))


if __name__ == "__main__":
    sizes = [(480, 360), (480, 820), (360, 640), (640, 360), (1024, 768), (1920, 1080)]
    if len(sys.argv) > 1:
        sizes = [tuple(int(v) for v in a.split("x")) for a in sys.argv[1:]]
    for (w, h) in sizes:
        r = run(w, h)
        print("=" * 62)
        if not r:
            print("%dx%d  NO DATA" % (w, h))
            continue
        print("viewport %-10s rootfont %-7s visible:%s collapsed:[%s]" % (
            r["viewport"], r["rootFontPx"], r["visibleScreen"], r["collapsed"]))
        for k in ("main","secStages","secSession","secQueue","secLog","log","note"):
            b = r.get(k)
            print("   %-8s %s" % (k, b and "w=%-4d h=%-4d top=%-4d left=%d" % (
                b["w"], b["h"], b["top"], b["left"])))
        print("   docScrollH=%-5d vOverflow=%-5s hOverflow=%-5s widest=%d (%s)" % (
            r["docScrollH"], r["vOverflow"], r["hOverflow"],
            r["widestChild"], r["widestSel"]))
