#!/usr/bin/env python3
"""End-to-end checks of the UI over HTTP (so fetch/manifest works).

  python3 tools/serve.py &            # or: python3 tools/probe_server.py
  python3 tools/func_test.py run     # expect a successful run
  python3 tools/func_test.py fail    # expect the WebKit-failure path

Polls until the UI reaches a terminal state rather than guessing a delay:
with --virtual-time-budget, virtual time pauses while manifest.txt is actually
being fetched, which pushes the payload timers past any fixed timeout.

Env: ORIGIN (default http://127.0.0.1:8002), MODE, BUDGET.
"""
import html as htm
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ORIGIN = os.environ.get("ORIGIN", "http://127.0.0.1:8002")
MODE = sys.argv[1] if len(sys.argv) > 1 else "run"
BUDGET = sys.argv[2] if len(sys.argv) > 2 else "200000"
QUERY = "?fail=1&fw=13.20" if MODE == "fail" else "?fw=13.20"
URL = ORIGIN + "/_functest.html" + QUERY

PROBE = """
<script>
var MODE_IS_FAIL = %s;
var waited = 0;
(function poll() {
  var done = document.getElementById("done");
  var anyFail = document.querySelector(".step.fail");
  if ((done && !done.classList.contains("hidden")) || anyFail || waited > 120000) {
    emit(); return;
  }
  waited += 200;
  setTimeout(poll, 200);
})();
function emit() {
  function vis(id) { return !document.getElementById(id).classList.contains("hidden"); }
  function txt(id) { var e = document.getElementById(id); return e ? e.textContent.trim() : null; }
  function col(id) { return document.getElementById(id).classList.contains("collapsed"); }
  var out = {
    waitedMs: waited,
    bootVisible: vis("boot"),
    mainVisible: vis("main"),
    doneVisible: vis("done"),
    doneTitle: txt("doneTitle"),
    doneSummaryLen: (txt("doneSummary") || "").length,
    fwBadge: txt("fwBadge"),
    kSource: txt("kSource"),
    kPayload: txt("kPayload"),
    kPort: txt("kPort"),
    kView: txt("kView"),
    kTime: txt("kTime"),
    pct: txt("pctLabel"),
    now: txt("nowLabel"),
    sumStages: txt("sumStages"),
    sumSession: txt("sumSession"),
    srcBadge: txt("srcBadge"),
    logCount: txt("logCount"),
    logLines: document.querySelectorAll("#log .line").length,
    collapsed: { stages: col("secStages"), session: col("secSession"),
                 queue: col("secQueue"), log: col("secLog") },
    collapsedStages: col("secStages"),
    collapsedSession: col("secSession"),
    collapsedQueue: col("secQueue"),
    collapsedLog: col("secLog"),
    toggleGlyphs: [].map.call(document.querySelectorAll(".tg"), function (b) {
      return b.textContent; }).join(","),
    payloadRows: document.querySelectorAll("#plist li").length,
    payloadStates: [].map.call(document.querySelectorAll("#plist em"), function (e) {
      return e.textContent.trim(); }),
    barClass: document.getElementById("barFill").className,
    ledClass: document.getElementById("led").className
  };
  var p = document.createElement("pre");
  p.id = "FUNCJSON";
  p.textContent = JSON.stringify(out);
  document.body.appendChild(p);

  /* exercise the "view run" button: it should dismiss the verdict and reveal
     the finished run underneath */
  if (MODE_IS_FAIL) { emitPost(); return; }
  document.getElementById("viewRun").click();
  setTimeout(emitPost, 300);
}
function emitPost() {
  function vis(id) { return !document.getElementById(id).classList.contains("hidden"); }
  var p = document.createElement("pre");
  p.id = "POSTJSON";
  p.textContent = JSON.stringify({
    doneVisible: vis("done"),
    mainVisible: vis("main"),
    logLines: document.querySelectorAll("#log .line").length,
    collapsedAny: ["secStages","secSession","secQueue","secLog"].some(function (id) {
      return document.getElementById(id).classList.contains("collapsed"); })
  });
  document.body.appendChild(p);
}
</script>
"""

page = (open(os.path.join(ROOT, "index.html")).read()
        .replace("</body>", (PROBE % ("true" if MODE == "fail" else "false")) + "</body>"))
open(os.path.join(ROOT, "_functest.html"), "w").write(page)

cmd = ["nix", "shell", "nixpkgs#chromium", "-c", "chromium",
       "--headless", "--no-sandbox", "--disable-gpu", "--hide-scrollbars",
       "--window-size=1024,768", "--virtual-time-budget=" + BUDGET, "--dump-dom", URL]
try:
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=1500).stdout
except subprocess.TimeoutExpired:
    print("chromium timed out")
    sys.exit(2)

m = re.search(r'FUNCJSON">(.*?)</pre>', out, re.S)
if not m:
    print("NO DATA - page never reached a terminal state (dom bytes: %d)" % len(out))
    sys.exit(1)

d = json.loads(htm.unescape(m.group(1)))
for k, v in d.items():
    print("%-14s %s" % (k, v))

post = re.search(r'POSTJSON">(.*?)</pre>', out, re.S)
postd = json.loads(htm.unescape(post.group(1))) if post else None
if postd:
    print("--- after clicking [ view run ] ---")
    for k, v in postd.items():
        print("%-14s %s" % (k, v))

fails = []
if d["bootVisible"]:
    fails.append("boot still visible")
if not d["mainVisible"]:
    fails.append("main never shown")
if not d["doneVisible"]:
    fails.append("never reached done screen")
if not d["doneSummaryLen"] >= 40:
    fails.append("done summary empty")
if d["logCount"] != str(d["logLines"]):
    fails.append("log counter desynced")

# sections must NOT be collapsed just because the run finished. On a failure the
# queue/session legitimately stay collapsed, since the manifest never resolved.
WANT_GLYPHS = "–,–,–,–" if MODE == "run" else "–,+,+,–"
if d["toggleGlyphs"] != WANT_GLYPHS:
    fails.append("unexpected section state: glyphs=%r want %r"
                 % (d["toggleGlyphs"], WANT_GLYPHS))

if MODE == "run":
    if d["doneTitle"] != "JAILBROKEN":   fails.append("title=%r" % d["doneTitle"])
    if d["payloadRows"] < 2:             fails.append("payload queue not populated")
    if any(s != "sent" for s in d["payloadStates"]):
        fails.append("payloads not all sent: %s" % d["payloadStates"])
    if d["logLines"] < 20:               fails.append("too few log lines: %d" % d["logLines"])
    if d["kPort"] == "not listening":    fails.append("elfldr port never updated")
    if d["barClass"] != "ok":            fails.append("progress bar not ok")
    if d["ledClass"] != "led ok":        fails.append("led=%r" % d["ledClass"])
    if d["pct"] != "100%":               fails.append("pct=%r" % d["pct"])
    if d["sumStages"] != "4/4":          fails.append("sumStages=%r" % d["sumStages"])
    if d["collapsedQueue"] or d["collapsedSession"]:
        fails.append("queue/session still collapsed after a successful run")
    if not postd:
        fails.append("no post-click state captured")
    else:
        if postd["doneVisible"]:    fails.append("verdict not dismissed by [ view run ]")
        if not postd["mainVisible"]: fails.append("main not revealed by [ view run ]")
        if postd["collapsedAny"]:   fails.append("sections collapsed after [ view run ]")
else:
    if d["doneTitle"] != "FAILED":       fails.append("title=%r" % d["doneTitle"])
    if d["barClass"] != "err":           fails.append("bar=%r" % d["barClass"])
    if d["ledClass"] != "led err":       fails.append("led=%r" % d["ledClass"])
    if d["pct"] == "100%":               fails.append("pct should not be 100%")
    if d["logLines"] < 5:                fails.append("too few log lines: %d" % d["logLines"])

print()
if fails:
    print("FAIL[%s]: " % MODE + "; ".join(fails))
    sys.exit(1)
print("PASS[%s]: terminal state reached, sections stay expanded, %d log lines"
      % (MODE, d["logLines"]))
