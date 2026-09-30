/* Mock driver for the Jailbreak Store UI.
 *
 * Real mode contract (next step): the exploit iframe runs the patched Relapse
 * chain and posts {type:"wkal", kind:"log"|"autoload", ok, bytes, why}.
 * This file only consumes that contract. Without ?real=1 it replays a scripted
 * run so the UI can be reviewed on a PC first.
 */
"use strict";

var $ = function (id) { return document.getElementById(id); };

var STAGES = [
  { el: "stage-1", txt: "s1", name: "webkit" },
  { el: "stage-2", txt: "s2", name: "kernel" },
  { el: "stage-3", txt: "s3", name: "elfldr" },
  { el: "stage-4", txt: "s4", name: "autoload" }
];

var t0 = Date.now();
var timer = null;
var logLines = 0;
var stageDone = 0;
var stageOnce = [];
var sentCount = 0;
var runStats = { errors: 0, warnings: 0, bytes: 0 };

/* firmware */
var isPS5 = navigator.userAgent.indexOf("PlayStation 5") !== -1;
var m = /PlayStation 5\/(\d+\.\d+)/.exec(navigator.userAgent);
var fw = m ? m[1] : "";
var q = new URLSearchParams(location.search);
if (q.get("fw")) fw = q.get("fw");

function viewport() {
  return window.innerWidth + "x" + window.innerHeight +
    (window.devicePixelRatio && window.devicePixelRatio !== 1
      ? " @" + window.devicePixelRatio + "x" : "");
}

/* ---------- collapsible sections ---------- */
var userToggled = {};

function setCollapsed(secId, collapsed) {
  var sec = $(secId);
  if (!sec) return;
  sec.classList.toggle("collapsed", !!collapsed);
  var btn = sec.querySelector(".tg");
  if (btn) btn.textContent = collapsed ? "+" : "–";
}

function toggleSec(secId, force) {
  var sec = $(secId);
  if (!sec) return;
  var next = force === undefined ? !sec.classList.contains("collapsed") : !!force;
  setCollapsed(secId, next);
  if (!q.get("measure")) userToggled[secId] = next;
}

/* progress-driven collapsing, unless the viewer took manual control */
function autoCollapse(secId, collapsed) {
  if (userToggled[secId] !== undefined) return;
  setCollapsed(secId, collapsed);
}

function initEnv() {
  if (!isPS5 && !q.get("fw")) fw = "13.20";

  $("bootStatus").innerHTML = isPS5
    ? "ps5 " + (fw || "?") + " detected<span class=cur>_</span>"
    : "preview — no ps5 ua<span class=cur>_</span>";
  $("fwBadge").textContent = "FW " + (fw || "--");
  $("kView").textContent = viewport();
  $("kPayload").textContent = "--";
  $("kSource").textContent = "--";
  $("kTime").textContent = "0.0s";
  $("led").className = "led run";

  log("webview " + viewport() + (isPS5 ? "" : " (preview)"), "sys");
  log("ua " + navigator.userAgent, "sys");
  log("fw " + fw + (useFullKstuff(fw)
    ? " <= 10.01, full kstuff supported"
    : " > 10.01, full kstuff unsupported, default kstuff-lite"), "sys");
  log("document " + document.documentElement.scrollWidth + "x" +
      document.documentElement.scrollHeight, "sys");
}

/* log */
function stamp() {
  var d = new Date();
  function p(n) { return (n < 10 ? "0" : "") + n; }
  return p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
}

function log(msg, type) {
  var el = document.createElement("div");
  el.className = "line " + (type || "log");
  var ts = document.createElement("span"); ts.className = "ts"; ts.textContent = stamp();
  var tx = document.createElement("span"); tx.className = "tx"; tx.textContent = msg;
  el.appendChild(ts); el.appendChild(tx);
  var box = $("log");
  var atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 24;
  box.appendChild(el);
  if (atBottom) box.scrollTop = box.scrollHeight;

  logLines++;
  $("logCount").textContent = logLines;
  if (type === "error") runStats.errors++;
  if (type === "warning") runStats.warnings++;
}

/* steps */
var LABELS = { waiting:"wait", running:"run", done:"ok", rejected:"fail", listening:"ok" };

function stage(i, state, msg) {
  var s = STAGES[i];
  if (!s) return;
  $(s.el).className = "step" + (state ? " " + state : "");
  $(s.txt).textContent = LABELS[msg] || msg || "wait";

  if (state === "done") {
    /* count each stage at most once, even if finish() sweeps stragglers */
    if (!stageOnce[i]) {
      stageOnce[i] = true;
      stageDone++;
      $("sumStages").textContent = stageDone + "/" + STAGES.length;
      setProgress(stageDone / STAGES.length * 100, null);
      log("stage " + (i + 1) + "/" + STAGES.length + " " + s.name +
          " ok — " + (msg || ""), "success");
    }
  } else if (state === "fail") {
    $("sumStages").textContent = stageDone + "/" + STAGES.length;
    setProgress(stageDone / STAGES.length * 100, "err");
    log("stage " + (i + 1) + "/" + STAGES.length + " " + s.name +
        " FAILED — " + (msg || ""), "error");
  }
}

function setNow(text) { $("nowLabel").textContent = text; }

function setProgress(pct, cls) {
  var p = Math.max(0, Math.min(100, pct));
  var bar = $("barFill");
  bar.style.width = p + "%";
  bar.className = cls || "";
  $("pctLabel").textContent = Math.round(p) + "%";
}

/* payload list, built from the resolved manifest */
var payloadEls = [];

function renderPayloads(entries) {
  var ul = $("plist");
  ul.innerHTML = "";
  payloadEls = entries.map(function (e) {
    var li = document.createElement("li");
    var dot = document.createElement("i");
    var name = document.createElement("span"); name.className = "pname"; name.textContent = e.name;
    var st = document.createElement("em"); st.textContent = "queued";
    li.appendChild(dot); li.appendChild(name); li.appendChild(st);
    ul.appendChild(li);
    return { li: li, st: st, name: e.name };
  });
  $("kPayload").textContent = entries.map(function (e) { return e.name; }).join(", ");
  autoCollapse("secQueue", false);
}

function setPayload(i, state, label) {
  var p = payloadEls[i];
  if (!p) return;
  p.li.className = state || "";
  p.st.textContent = label;
}

/* clock */
function tick() {
  $("kTime").textContent = ((Date.now() - t0) / 1000).toFixed(1) + "s";
}
function startClock() { if (!timer) timer = setInterval(tick, 100); }
function stopClock() { if (timer) { clearInterval(timer); timer = null; } }

/* flow */
function begin() {
  $("boot").classList.add("hidden");
  $("done").classList.add("hidden");
  $("measure").classList.add("hidden");
  $("main").classList.remove("hidden");
  $("log").innerHTML = "";
  $("doneSummary").textContent = "";
  logLines = 0; stageDone = 0; sentCount = 0;
  stageOnce = [];
  runStats = { errors: 0, warnings: 0, bytes: 0 };
  userToggled = {};
  payloadEls = [];

  setProgress(0, null);
  setNow("starting");
  t0 = Date.now();
  for (var i = 0; i < STAGES.length; i++) stage(i, "", "waiting");
  $("sumStages").textContent = "0/" + STAGES.length;
  $("kPort").textContent = "not listening";
  $("kPort").className = "";
  $("srcBadge").textContent = "resolving";
  $("sumSession").textContent = "resolving";
  $("kSource").textContent = "--";
  $("kPayload").textContent = "--";
  $("logCount").textContent = "0";
  $("led").className = "led run";

  /* start collapsed: the queue is unknown until the manifest resolves, and the
     session block has nothing but placeholders until elfldr comes up. Keeps
     short popup windows uncrowded during the early phase. */
  setCollapsed("secQueue", true);
  setCollapsed("secSession", true);
  setCollapsed("secStages", false);
  setCollapsed("secLog", false);

  startClock();
  log("run started", "info");
}

function finish(ok, why) {
  stopClock();
  if (ok) {
    for (var i = 0; i < STAGES.length; i++) {
      if ($(STAGES[i].el).className.indexOf("done") === -1) stage(i, "done", "done");
    }
    setProgress(100, "ok");
    setNow("complete");
  } else {
    setNow("failed");
  }
  $("led").className = "led " + (ok ? "ok" : "err");

  /* Sections are left as-is on finish: the run is the interesting part, so
     stages/queue/session/log stay expanded and readable. (The verdict screen
     covers this view; "view run" dismisses it.) */
  $("sumSession").textContent = ok ? "complete" : "failed";

  $("done").className = "screen center" + (ok ? "" : " error");
  $("doneTitle").textContent = ok ? "JAILBROKEN" : "FAILED";
  $("doneSub").textContent = ok
    ? (sentCount + " payload(s) delivered — close this window")
    : (why || "chain did not complete");

  var names = payloadEls.map(function (p) { return p.name; });
  $("doneSummary").textContent =
    "firmware   " + (fw || "?") + "\n" +
    "viewport   " + viewport() + "\n" +
    "manifest   " + ($("kSource").textContent) + "\n" +
    "payloads   " + (names.length ? names.join(" -> ") : "none") + "\n" +
    "elfldr     " + ($("kPort").textContent) + "\n" +
    "transferred " + runStats.bytes.toLocaleString() + " bytes\n" +
    "elapsed    " + ((Date.now() - t0) / 1000).toFixed(1) + "s\n" +
    "log lines  " + logLines + " (" + runStats.warnings + " warn, " +
      runStats.errors + " err)";

  log(ok ? "run complete" : "run failed: " + (why || "unknown"), ok ? "success" : "error");
}

/* mock run */
var SCRIPT = [
  [900,  0, "sys", "reading firmware banner"],
  [1400, 1, "active", "running"],
  [1900, 0, "info", "webkit: probing for JSC pool fingerprint"],
  [2600, 1, "done", "ARW ready"],
  [3000, 2, "active", "running"],
  [3600, 0, "info", "kexp: staging kexp_2026_05_25.bin"],
  [4300, 0, "sys", "JSC leak: 3 fingerprints, 12 pool entries"],
  [5200, 0, "info", "releasing 3 spray objects"],
  [6400, 2, "active", "aio_multi_wait uaf race"],
  [7100, 0, "warning", "one retry needed (race lost)"],
  [8400, 0, "info", "kernel r/w object acquired at 0xffff8..."],
  [9200, 2, "done", "kernel r/w established"],
  [9800, 3, "active", "waiting for :9021"],
  [10500, 0, "sys", "sysopen /dev/elfldr 0x2f"],
  [11200, 0, "success", "elfldr listening on 127.0.0.1:9021"],
  [11800, 4, "active", "reading manifest"]
];

var SIZES = { "kstuff-lite.elf": 1737080, "kstuff.elf": 4690760, "etahen.elf": 4690760 };

function runMock() {
  /* Manifest resolution happens post-exploit, so show it at the same point. */
  setTimeout(function () {
    log("fetching manifest.txt", "info");
    resolveManifest({ fw: fw, remote: true })
      .then(function (r) {
        renderPayloads(r.entries);
        $("srcBadge").textContent = r.source;
        $("kSource").textContent = r.source;
        $("sumSession").textContent = r.source;
        autoCollapse("secSession", false);   /* now there is something to show */
        log("manifest: " + r.entries.length + " entries, source=" + r.source +
            (r.reason ? " (" + r.reason + ")" : ""), "sys");
        log("queue: " + r.entries.map(function (e) { return e.name; }).join(" -> "), "info");

        var at = 12900;
        r.entries.forEach(function (e, i) {
          var sz = SIZES[e.name] || 0;
          setTimeout(function () {
            setPayload(i, "warming", "sending…");
            setNow("sending " + e.name);
            log("GET " + e.url, "info");
            log(e.name + (sz ? " — " + sz.toLocaleString() + " bytes" : ""), "info");
          }, at);
          setTimeout(function () {
            setPayload(i, "sent", "sent");
            sentCount++;
            runStats.bytes += sz;
            log(e.name + " -> elfldr :9021 accepted", "success");
            if (i === 0) setTimeout(function () {
              log("patching app.db + shellui trophy IsServerAvailable", "info");
              log("SceLncUtil getAppStatus 0x80940004 (expected, offline)", "sys");
            }, 300);
          }, at + 700);
          at += 1500;
        });

        var warnAt = at + 300;
        setTimeout(function () {
          log("elfldr :9020 unavailable, falling back to :9021", "warning");
        }, warnAt);
        setTimeout(function () {
          log("autostart skipped: no private elfldr :9020", "warning");
          log("boot-time autostart unavailable on this firmware", "warning");
          setNow("finishing");
          finish(true);
        }, warnAt + 400);
      })
      .catch(function (err) {
        log("manifest fetch failed: " + err, "error");
        stage(3, "fail", "manifest unavailable");
        finish(false, "Could not resolve the payload manifest.");
      });
  }, 11800);

  SCRIPT.forEach(function (s) {
    setTimeout(function () {
      if (s[1] >= 1 && s[1] <= 4) stage(s[1] - 1, s[2], s[3]);
      else log(s[3], s[2]);
    }, s[0]);
  });

  setTimeout(function () {
    $("kPort").textContent = "127.0.0.1:9021";
    $("kPort").className = "ok";
    $("sumSession").textContent = "elfldr :9021";
    stage(2, "done", "listening");   /* index 2 = elfldr; autoload is index 3 */
  }, 11200);
}

function runMockFail() {
  setTimeout(function () { stage(0, "active", "running"); }, 1200);
  setTimeout(function () { log("webkit: probing for JSC pool fingerprint", "info"); }, 1700);
  setTimeout(function () { log("JSC leak: 2 fingerprints (expected 3)", "warning"); }, 2400);
  setTimeout(function () { log("no usable pool object, aborting", "info"); }, 3800);
  setTimeout(function () {
    stage(0, "fail", "rejected");
    log("WebKit exploit failed: fingerprint mismatch", "error");
    log("Reload the page and try again — this happens sometimes.", "info");
    finish(false, "WebKit exploit failed. Reload and retry.");
  }, 5200);
}

/* real mode */
function runReal() {
  log("loading exploit chain from src/main.js", "info");
  setNow("loading chain");
  $("exploit").src = "src/main.js?autoload=payload.elf";
}

function onMessage(e) {
  var d = e.data;
  if (!d || d.type !== "wkal") return;
  if (d.kind === "log") {
    log(d.text || "…", d.level || "info");
  } else if (d.kind === "autoload") {
    if (d.ok) {
      stage(3, "done", "autoload sent");
      finish(true);
    } else {
      stage(3, "fail", "failed");
      finish(false, d.why);
    }
  }
}

/* ---------- viewport probe (?measure=1) ---------- */
function pad(k, v) {
  k = String(k);
  while (k.length < 27) k += " ";
  return k + v;
}

function measureReport() {
  var vv = window.visualViewport;
  var sc = window.screen || {};
  var de = document.documentElement;
  var rows = [
    pad("innerWidth  x innerHeight", window.innerWidth + " x " + window.innerHeight),
    pad("clientWidth x clientHeight", de.clientWidth + " x " + de.clientHeight),
    pad("outerWidth  x outerHeight", window.outerWidth + " x " + window.outerHeight),
    pad("devicePixelRatio", String(window.devicePixelRatio)),
    pad("screen.width x height", sc.width + " x " + sc.height),
    pad("availWidth  x availHeight", sc.availWidth + " x " + sc.availHeight),
    pad("visualViewport w x h", vv ? (vv.width + " x " + vv.height) : "n/a"),
    pad("visualViewport scale", vv ? String(vv.scale) : "n/a"),
    pad("colorDepth", sc.colorDepth ? sc.colorDepth + "bit" : "n/a"),
    pad("maxTouchPoints", String(navigator.maxTouchPoints || 0)),
    pad("onLine", String(!!navigator.onLine)),
    pad("fw (from UA)", fw || "n/a"),
    pad("isPS5", String(isPS5))
  ];
  var w = window.innerWidth;
  rows.push("", pad("layout bucket",
    w < 380 ? "phone (<380)" :
    w < 560 ? "small popup (<560)" :
    w < 900 ? "medium popup (<900)" : "wide (>=900)"));
  return rows.join("\n");
}

function showMeasure() {
  $("boot").classList.add("hidden");
  $("main").classList.add("hidden");
  $("done").classList.add("hidden");
  $("measure").classList.remove("hidden");
  $("mOut").textContent = measureReport();
  if (navigator.clipboard) navigator.clipboard.writeText(measureReport()).catch(function () {});
  /* also report to the host so nothing has to be read off the screen */
  try {
    new Image().src = "__probe?" + encodeURIComponent(measureReport());
  } catch (e) {}
}

/* wire */
function start() {
  if (q.get("measure") === "1") { showMeasure(); return; }
  $("measure").classList.add("hidden");
  begin();
  if (q.get("real") === "1") runReal();
  else if (q.get("fail") === "1") runMockFail();
  else runMock();
}

function init() {
  initEnv();
  window.addEventListener("message", onMessage);

  /* manual collapse toggles */
  [].forEach.call(document.querySelectorAll(".tg"), function (btn) {
    btn.addEventListener("click", function () {
      toggleSec(btn.getAttribute("data-tg"));
    });
  });

  $("copyLog").addEventListener("click", function () {
    var text = [].map.call($("log").childNodes, function (n) {
      return n.querySelector(".ts").textContent + "  " + n.querySelector(".tx").textContent;
    }).join("\n");
    if (navigator.clipboard) navigator.clipboard.writeText(text);
    log("log copied to clipboard", "info");
  });

  $("toggleLog").addEventListener("click", function () {
    var box = $("log");
    var hidden = box.style.display === "none";
    box.style.display = hidden ? "" : "none";
    this.textContent = hidden ? "hide" : "show";
  });

  $("again").addEventListener("click", start);
  $("viewRun").addEventListener("click", function () {
    /* dismiss the verdict so the finished run (log, queue, stages) is visible */
    $("done").classList.add("hidden");
    $("main").classList.remove("hidden");
    var box = $("log");
    box.scrollTop = box.scrollHeight;
    log("viewing completed run", "info");
  });
  window.addEventListener("resize", function () {
    if (q.get("measure") === "1" && !$("measure").classList.contains("hidden")) showMeasure();
    else if (fw) $("kView").textContent = viewport();
  });
  setTimeout(start, q.get("measure") === "1" ? 0 : 800);
}

init();
