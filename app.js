/* UI driver for the Jailbreak Store.
 *
 * This file owns no exploit logic. It defines the two globals that the
 * upstream chain reports through - window.writeLog and window.jb - and turns
 * their output into the stage list, progress bar and log. The chain itself is
 * the unmodified Relapse 09f10f5 code under src/, called by src/boot.js.
 *
 * Run it with no arguments on a PS5. On a desktop browser it refuses, because
 * there is no WebKit to exploit and no console to send payloads to.
 */
"use strict";

var $ = function (id) { return document.getElementById(id); };

var STAGES = [
  { el: "stage-1", txt: "s1", name: "webkit" },
  { el: "stage-2", txt: "s2", name: "rop worker" },
  { el: "stage-3", txt: "s3", name: "kernel" },
  { el: "stage-4", txt: "s4", name: "elfldr" },
  { el: "stage-5", txt: "s5", name: "autoload" }
];

/* Where each upstream reporter's output belongs. The chain emits its own
 * tag strings, so rather than patching it we map the tags onto stages. */
var TAG_STAGE = {
  "WebKit": 0,
  "Attempt": 0,
  "Retry": 0,
  "leak_addr": 0,
  "host_addr": 0,
  "holder_addr": 0,
  "fake_addr": 0,
  "view_vector": 0,
  "function_addr": 0,
  "executable_addr": 0,
  "native_function": 0,
  "native_constructor": 0,
  "Worker": 1,
  "Worker chain": 1,
  "Kernel": 2,
  "oid": 2,
  "oid steering": 2,
  "oid_churn": 2,
  "Process": 2,
  "Pipes": 2,
  "Privileges": 2,
  "aio_info_addr": 2,
  "ucred_addr": 2,
  "kernel rw": 2,
  "Cleanup": 2,
  "kexp": 3,
  "Autoload": 4
};

/* Stage completion is driven off exact log lines the chain prints, not off
 * the progress tags. Tags are free text and their details vary, so matching
 * on them marks stages done at the wrong time - "Offsets: 13.20 loaded"
 * contains "loaded" but obviously does not mean the WebKit stage finished. */
var MILESTONES = [
  { line: "ARW ready",                     stage: 0, label: "ready" },
  { line: "Worker chain: ready",           stage: 1, label: "ready" },
  { line: "privileges ready",              stage: 2, label: "ready" },
  { line: "elfldr is listening on 9021",  stage: 3, label: "listening" },
  { line: "elfldr is listening on port 9021", stage: 3, label: "listening" }
];


/* The payload chain, in the order the unmodified kexp.js sends it. */
var PAYLOADS = [
  { name: "kstuff.elf", label: "kstuff-lite 1.11B", size: 1737080 },
  { name: "shadowmountplus.elf", label: "shadowmountplus", size: 2449672 },
  { name: "etaHEN.elf", label: "etaHEN (Oct 1)", size: 4690760 }
];

var t0 = Date.now();
var timer = null;
var logLines = 0;
var stageDone = 0;
var stageOnce = [];
var sentCount = 0;
var runStats = { errors: 0, warnings: 0, bytes: 0 };

/* ---------- console + firmware detection ----------
 *
 * The vendored src/firmware.js hard-rejects unless the UA contains the literal
 * "PlayStation 5" and matches /PlayStation 5\/(\d+\.\d+)/, and its version must
 * appear in a fixed 32-entry list. Real consoles do not all match that: the UA
 * format varies by region and firmware, and any version outside the list is
 * refused outright. So the globals it publishes are superseded here rather than
 * editing the vendored file. app.js is a classic script and boot.js is a module,
 * so this runs before boot() reads window.fw_str / window.firmware.
 */
var q = new URLSearchParams(location.search);

/* Offsets are named with a two-digit minor, so a UA that reports "13.2" has to
 * become "13.20" or offsets/13.2.js is requested and 404s. */
function normalizeFw(v) {
  var m = /^(\d+)\.(\d+)$/.exec(String(v || ""));
  if (!m) return String(v || "");
  return m[1] + "." + (m[2].length < 2 ? m[2] + "0" : m[2]);
}

/* Deliberately loose: matches "PlayStation 5/13.20", "PS5/13.20", and variants
 * with other text between the product name and the number. */
var UA_FW = /(?:playstation\s*5|ps5)[^0-9]{0,12}(\d+\.\d+)/i;
var UA_CONSOLE = /playstation|ps5|ps4/i;

function detectFw() {
  var override = q.get("fw");
  if (override) return { fw: normalizeFw(override), source: "?fw=", console: true };

  var m = UA_FW.exec(navigator.userAgent);
  if (m) return { fw: normalizeFw(m[1]), source: "user agent", console: true };

  /* No version in the UA, but the UA still looks like a console. Do not refuse:
     let the chain try, and fail on the missing offsets file with a message that
     says which firmware it was looking for. */
  if (UA_CONSOLE.test(navigator.userAgent))
    return { fw: "", source: "user agent, no version", console: true };

  return { fw: "", source: "none", console: false };
}

var det = detectFw();
var fw = det.fw;
var fwSource = det.source;
var isPS5 = det.console;

/* Take over from src/firmware.js. The supported-version list is intentionally
   not enforced: offsets only exist for the versions upstream shipped, so an
   unlisted version will fail at offsets/<fw>.js, which reports the real
   reason. Refusing up front would also reject a console whose UA simply did not
   parse. */
window.fw_str = fw;
window.firmware = {
  rejection() {
    if (fw) return null;
    return q.get("fw")
      ? "FW " + q.get("fw") + " is not a known version"
      : "could not read the firmware version from the user agent - " +
        "append ?fw=13.20 to set it explicitly";
  },
  overridden: true,
};

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
    ? (fw
        ? "ps5 " + fw + " detected (" + fwSource + ")<span class=cur>_</span>"
        : "ps5 detected, firmware unknown — add ?fw=13.20<span class=cur>_</span>")
    : "preview — no ps5 user agent<span class=cur>_</span>";
  $("fwBadge").textContent = "FW " + (fw || "--");
  $("kView").textContent = viewport();
  $("kPayload").textContent = "--";
  $("kSource").textContent = "--";
  $("kTime").textContent = "0.0s";
  $("led").className = "led run";

  log("webview " + viewport() + (isPS5 ? "" : " (preview)"), "sys");
  log("ua " + navigator.userAgent, "sys");
  log("fw " + (fw || "unknown") + " from " + fwSource, isPS5 && !fw ? "warning" : "sys");
  if (isPS5 && !fw)
    log("no version parsed; append ?fw=<version> to select offsets manually", "warning");
  if (fw)
    log("kstuff: " + (useFullKstuff(fw)
      ? "<= 10.01, full kstuff supported"
      : "> 10.01, full kstuff unsupported, default kstuff-lite"), "sys");
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

/* ------------------------------------------------------------------ *
 * The bridge. Everything under src/ reports through these two globals,
 * which is exactly what upstream Relapse's site.js did - the chain has
 * no idea the UI exists.
 * ------------------------------------------------------------------ */
var rawLogLines = [];
var runTerminal = false;

window.writeLog = function (message, type, replace) {
  rawLogLines.push(String(message));
  /* webkit.js's retry loop is uncapped, so once we have given up on the chain
   * it can keep emitting for a while. Stop rendering those, or the log grows
   * under a verdict that has already been reached. */
  if (runTerminal) return;
  log(message, type === "success" ? "success" : type === "error" ? "error" : type);
};

window.jb = {
  logLines: rawLogLines,
  payloadsDone: false,
  mark: function (name, detail) {
    var text = detail == null || detail === "" ? String(name)
             : String(name) + ": " + String(detail);
    var isFail = /Failed|failed/.test(String(name));
    window.writeLog(text, isFail ? "error" : "info");

    /* Progress tags only ever mark a stage as the current one. Completion is
     * handled by the milestone watcher, because tag details are free text. */
    var idx = TAG_STAGE[name];
    if (idx === undefined || stageOnce[idx]) return;
    if (name === "Offsets" || name === "Autoload") return;
    stage(idx, "running", String(detail || "").split(" ")[0] || "run");
  }
};


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
  runTerminal = true;
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

  /* The installer only works once elfldr is actually listening, so it is tied
     to a successful run. On a failed run it stays hidden rather than offering a
     button that cannot work. */
  $("offer").classList.toggle("hidden", !ok);
  if (ok) {
    $("install").disabled = false;
    $("install").textContent = "APPLY TO PS STORE";
    $("offerNote").textContent =
      "reboots nothing on its own — a PS5 reboot is needed for the tile to change";
  }

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
/* ---------- the real run ----------
 *
 * src/boot.js is the only caller of the chain. It is an ES module, so it loads
 * after the classic scripts under src/ have put their globals in place. The
 * promise it returns settles when the payload chain reports back. */
function showPayloadQueue() {
  renderPayloads(PAYLOADS.map(function (p) {
    return { name: p.label, url: "payloads/" + p.name, size: p.size };
  }));
  $("srcBadge").textContent = PAYLOADS.length + " queued";
  $("sumSession").textContent = "queued";
  autoCollapse("secQueue", false);
  $("kPayload").textContent = PAYLOADS.length + " payloads";
  $("kSource").textContent = "bundled";
}

function watchMilestones() {
  var hit = MILESTONES.map(function () { return false; });
  var timer = setInterval(function () {
    var all = true;
    for (var i = 0; i < MILESTONES.length; i++) {
      if (hit[i]) continue;
      all = false;
      var m = MILESTONES[i];
      if (rawLogLines.some(function (l) { return l.indexOf(m.line) !== -1; })) {
        hit[i] = true;
        stage(m.stage, "done", m.label);
      }
    }
    if (all) clearInterval(timer);
  }, 100);
}

function watchPayloadProgress() {
  /* The chain logs "<name> sent" as each one lands on elfldr. */
  var sent = {};
  var timer = setInterval(function () {
    for (var i = 0; i < PAYLOADS.length; i++) {
      var short = PAYLOADS[i].name.replace(".elf", "");
      if (sent[i]) continue;
      var hit = rawLogLines.some(function (l) {
        return l.indexOf(short + ".elf sent") !== -1 ||
               l.indexOf(short.replace(".elf", "") + " sent") !== -1;
      });
      if (hit) {
        sent[i] = true;
        sentCount++;
        setPayload(i, "sent", "sent");
        runStats.bytes += PAYLOADS[i].size;
        log(PAYLOADS[i].label + " -> elfldr :9021 accepted", "success");
        stage(4, "running", sentCount + "/" + PAYLOADS.length);
      }
    }
    if (sentCount === PAYLOADS.length) {
      clearInterval(timer);
      stage(4, "done", "sent");
      log("all payloads delivered to elfldr :9021", "success");
    }
  }, 120);
}

function runChain() {
  log("loading exploit chain from src/boot.js", "info");
  setNow("loading chain");
  showPayloadQueue();
  watchMilestones();
  watchPayloadProgress();

  import("./src/boot.js")
    .then(function (boot) { return boot.boot(); })
    .then(function () {
      stage(3, "done", "listening");
      $("kPort").textContent = "127.0.0.1:9021";
      $("kPort").className = "ok";
      $("sumSession").textContent = "elfldr :9021";
      finish(true);
    })
    .catch(function (err) {
      var why = err && err.message ? err.message : String(err);
      log(why, "error");
      for (var i = 0; i < STAGES.length; i++) {
        if (!stageOnce[i]) stage(i, "fail", "not reached");
      }
      finish(false, why);
    });
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

  if (!isPS5) {
    /* There is no WebKit to exploit off-console, so the chain would fail in a
       confusing way. Say so plainly instead. */
    document.body.classList.add("unsupported");
    $("bootStatus").textContent = "this site only runs on a PlayStation 5";
    $("bootStatus").classList.add("err");
    $("led").className = "led err";
    $("goWrap").classList.add("hidden");
    $("goNote").classList.add("hidden");
    return;
  }

  /* The chain sprays the moment it runs, so it takes a deliberate click rather
     than firing on load. ?auto=1 skips the gate - the headless chain probe
     and the on-console retest both use it. */
  if (q.get("auto") === "1") { launch(); return; }
  $("go").addEventListener("click", launch);
}

function launch() {
  $("goWrap").classList.add("hidden");
  $("goNote").classList.add("hidden");
  begin();
  runChain();
}

/* ---------- the PS Store installer offer ---------- */
/* Delivers payloads/JailbreakStore.elf to elfldr, which rewrites the MMS
 * databases: it renames NPXS40047 and repoints its DEEPLINK_URI at this page.
 * The console needs a reboot afterwards for the tile to change.
 *
 * This is a plain no-cors POST rather than the syscall socket kexp.js uses. The
 * chain's p/chain handles live inside the ROP worker and are not reachable from
 * here without editing vendored main.js. Browsers treat http://127.0.0.1 as
 * potentially trustworthy so the mixed-content rule does not apply, but that
 * exemption is not guaranteed on the PS5's WebView - if this reports a failure
 * on hardware, send the ELF from a PC instead. */
function installStoreHijack() {
  var btn = $("install");
  var note = $("offerNote");
  btn.disabled = true;
  btn.textContent = "SENDING...";
  note.textContent = "transferring JailbreakStore.elf to elfldr :9021";

  fetch("payloads/JailbreakStore.elf")
    .then(function (r) {
      if (!r.ok) throw new Error("download HTTP " + r.status);
      return r.arrayBuffer();
    })
    .then(function (buf) {
      note.textContent = "sending " + buf.byteLength.toLocaleString() + " bytes";
      return fetch("http://127.0.0.1:9021/", {
        method: "POST",
        mode: "no-cors",
        headers: { "Content-Type": "application/octet-stream" },
        body: buf
      });
    })
    .then(function () {
      btn.textContent = "APPLIED";
      note.textContent = "reboot the PS5 - the tile becomes \"Jailbreak Store\" and opens this page";
      log("JailbreakStore.elf sent to elfldr :9021", "success");
      log("PS Store tile repointed; a PS5 reboot is required", "info");
    })
    .catch(function (err) {
      var why = err && err.message ? err.message : String(err);
      btn.disabled = false;
      btn.textContent = "RETRY";
      note.textContent = "send failed: " + why + " - send the ELF from a PC instead";
      log("store install failed: " + why, "error");
    });
}

function init() {
  initEnv();

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

  $("again").addEventListener("click", launch);
  $("install").addEventListener("click", installStoreHijack);
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
