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
 * tag strings, so rather than patching it we map the tags onto stages.
 *
 * Stages 0 and 1 (WebKit, ROP worker) are tagged by our own boot.js and
 * main.js, plus core.js's placement attempts. Stages 2 and 3 are tagged by
 * KAR0218's chain through window.__rep - it replaced the older chain, which used
 * the "oid"/"oid steering"/"Cleanup" style tags, so both sets are kept.
 *
 * Every tag the chain can emit has to be here. It reaches this table via
 * window.__rep (see below), and withDeadline wraps all of main(), so a tag left
 * out just means the stage list stops naming phases partway through a run.
 * FAIL and STOP are deliberately absent: those are terminal, and the run throws
 * rather than progressing. */
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
  /* Kar0218's driver: everything from START to DONE is inside run(), which is
   * the kernel stage; only the kexp/elfldr handoff is stage 3. */
  "START": 2,
  "BOOT": 2,
  "KASLR": 2,
  "PIN": 2,
  "UNPIN": 2,
  "PARK": 2,
  "FAST": 2,
  "KREAD": 2,
  "PROC": 2,
  "PIPE": 2,
  "ESC": 2,
  "VERIFY": 2,
  "DEFUSE": 2,
  "RESCUE": 2,
  "DONE": 2,
  "KEXP": 3,
  "ELFLDR": 3,
  "Autoload": 4
};

/* Stage completion is driven off exact log lines the chain prints, not off
 * the progress tags. Tags are free text and their details vary, so matching
 * on them marks stages done at the wrong time - "Offsets: 13.20 loaded"
 * contains "loaded" but obviously does not mean the WebKit stage finished. */
var MILESTONES = [
  { line: "ARW ready",                     stage: 0, label: "ready" },
  { line: "Worker chain: ready",           stage: 1, label: "ready" },
  /* Stage 2 is "kernel rw and root". The chain used to end this stage with a
   * "privileges ready" line; KAR0218's version reports ESC with the uid/sandbox
   * transition instead, which is a stronger claim: root and out of sandbox are
   * both confirmed by reading them back, not assumed. Match on that. */
  { line: "ROOT, OUT OF SANDBOX",          stage: 2, label: "ready" },
  { line: "privileges ready",              stage: 2, label: "ready" },
  { line: "elfldr is listening on 9021",  stage: 3, label: "listening" },
  { line: "elfldr is listening on port 9021", stage: 3, label: "listening" }
];


/* The payload list is no longer hardcoded here. It comes from the manifest at
 * runtime - see showPayloadQueue()/syncPayloadQueue(). Kept only as the
 * fallback boot.js uses if neither manifest can be read. */
var FALLBACK_PAYLOADS = [
  { name: "kstuff.elf", label: "kstuff-lite 1.11B", size: 1737080 },
  { name: "shadowmountplus.elf", label: "shadowmountplus", size: 2449672 },
  { name: "etaHEN.elf", label: "etaHEN", size: 4690760 }
];

var t0 = Date.now();
var timer = null;
var logLines = 0;
var stageDone = 0;
var stageOnce = [];
var sentCount = 0;
var runStats = { errors: 0, warnings: 0, bytes: 0 };

/* ---------- payload queue ----------
 *
 * The rows here are whatever the run is currently able to say about each payload.
 * Who fills them changed: this page's own payload list used to be the whole
 * story, and now it is one entry (dispatcher.elf) plus whatever the dispatcher
 * reports behind it, read back from its console-side log by boot.js.
 */
/* True once the dispatcher owns the queue and its log is the authority. The
 * page's own "entry sent" watcher stands down then, or it would count
 * dispatcher.elf as a delivered plugin on top of the dispatcher's own count. */
var dispatchOwned = false;
/* How many payloads the dispatcher said it intends to send, once it has said so.
 * Zero until then, which is why the manifest count boot.js reads up front is
 * still what fills the queue initially. */
var dispatchPlan = 0;
var dispatchFailures = [];
/* Why the dispatcher's log could not be read, if it could not be. Non-empty
 * means the queue is back to being this page's own guess, and the verdict says
 * so rather than claiming the plugins loaded. */
var dispatchUnavailable = "";
/* Bytes seen going out per payload, so a retried payload is counted once. */
var dispatchBytes = {};

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
  log("webview " + viewport() + (isPS5 ? "" : " (preview)"), "sys");
  log("ua " + navigator.userAgent, "sys");
  log("fw " + (fw || "unknown") + " from " + fwSource, isPS5 && !fw ? "warning" : "sys");
  if (isPS5 && !fw)
    log("no version parsed; append ?fw=<version> to select offsets manually", "warning");
  /* Which kstuff build loads is the manifest's decision now, not something
   * worth guessing at from the firmware here - boot.js logs what it sent. */
  log("document " + document.documentElement.scrollWidth + "x" +
      document.documentElement.scrollHeight, "sys");
}

/* log. Each line is one flush div of plain text, marker first, exactly like
 * the reference console in /tmp/opencode/Relapse-Exploit (writeLog there
 * prints "[+] message"). The old per-line timestamp column pushed every
 * message into a fixed-gap flex row, which read as "indented and spaced
 * apart" - drop it and let the message sit flush at the left edge. */
function logMarker(type) {
  return type === "error" ? "-"
       : type === "warning" ? "!"
       : type === "info" || type === "success" ? "+"
       : "*";
}

var logQueue = [];
var logFlushTimer = null;
/* A run dumps whole stages in the same frame (the payload tail especially),
 * which scrolls the log faster than it can be read. Pace bursts at one line
 * per interval so the log keeps up with the on-screen popups instead of
 * racing past them. Idle lines still land immediately. */
var LOG_STEP_MS = 100;

function renderLogLine(entry) {
  var el = document.createElement("div");
  var msg = String(entry.msg);
  /* The chain prints "payloads loaded" the moment its own handoff to elfldr
   * lands, before boot.js has sent a single manifest entry. On a fresh run
   * that reads as a lie in the log, so correct the display text only; the
   * raw log keeps the literal for anything that matches on it. */
  if (msg === "Kernel: payloads loaded") msg = "Kernel: elfldr ready, plugins load next";
  /* Collapse every run of whitespace so a stray newline can never open blank
   * rows or shove a line right, no matter what white-space policy a cached
   * stylesheet leaves on the element. */
  msg = msg.replace(/\s+/g, " ").trim();
  el.className = "line " + (entry.level || "log");
  el.textContent = "[" + logMarker(entry.level) + "] " + msg;
  var box = $("log");
  var atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 24;
  box.appendChild(el);
  if (atBottom) box.scrollTop = box.scrollHeight;

  logLines++;
  $("logCount").textContent = logLines;
  if (entry.level === "error") runStats.errors++;
  if (entry.level === "warning") runStats.warnings++;
}

function flushLogQueue() {
  logFlushTimer = null;
  while (logQueue.length) {
    var entry = logQueue.shift();
    renderLogLine(entry);
    if (logQueue.length) {
      logFlushTimer = setTimeout(flushLogQueue, LOG_STEP_MS);
      return;
    }
  }
}

function log(msg, type) {
  logQueue.push({ msg: String(msg), level: type || "log" });
  if (logFlushTimer !== null) return;
  renderLogLine(logQueue.shift());
  if (logQueue.length) logFlushTimer = setTimeout(flushLogQueue, LOG_STEP_MS);
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
  /* The chain can keep emitting after a stage has been given up on - a slow
   * placement retry, or a kernel round trip that eventually lands. Keep
   * collecting the raw lines, since the verdict reasons about them, but stop
   * rendering, or the log grows under a verdict that has already been reached. */
  if (runTerminal) return;
  /* An unrecognised level would land as a bare class name with no rule behind
   * it, so map the ones the site uses onto the styles that exist. */
  var level =
    type === "success" || type === "error" || type === "warning" || type === "info" || type === "sys"
      ? type
      : "info";
  log(message, level);
};

/* Progress tags only ever mark a stage as the current one. Completion is
 * handled by the milestone watcher, because tag details are free text. */
function markStage(name, detail) {
  var idx = TAG_STAGE[name];
  if (idx === undefined || stageOnce[idx]) return;
  if (name === "Offsets" || name === "Autoload") return;
  stage(idx, "running", String(detail || "").split(" ")[0] || "run");
}

window.jb = {
  logLines: rawLogLines,
  payloadsDone: false,
  /* Set by boot.js before it hands dispatcher.elf over, once the dispatcher log
   * on the console is the signal for whether the plugins loaded. See
   * waitForPayloads() in src/boot.js. */
  dispatcherArmed: false,
  dispatcherWatch: null,
  mark: function (name, detail) {
    var text = detail == null || detail === "" ? String(name)
             : String(name) + ": " + String(detail);
    var isFail = /Failed|failed/.test(String(name));
    window.writeLog(text, isFail ? "error" : "info");
    markStage(name, detail);
  },
  /* The dispatcher runs on the console, past the last thing this page used to
   * watch. It writes every line it emits to /data/autoldr/dispatcher.log, and
   * boot.js reads that file back over the same exploit primitive the payload
   * arrived on and reports it here. So the queue, the counts and the verdict
   * come from the dispatcher's own log rather than from this page's guess at
   * what it was doing. Set by boot.js; see watchDispatcherLog(). */
  dispatch: function (event) {
    handleDispatch(event);
  }
};

/* The exploit chain reports through report(tag, detail), not through
 * jb.mark(). Its log line reaches the page separately, via main.js's log()
 * callback, so this must only drive the stage list - logging again here would
 * print every phase twice. Without this hook the chain's tags never reach
 * TAG_STAGE at all and the stage list sits on its first phase for the whole
 * kernel run. */
window.__rep = function (tag, detail) {
  markStage(tag, detail);
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

/* The dispatcher's queue arrives one entry at a time as it works through the
 * manifest, so it is appended to rather than rendered in one go the way the
 * page's own single-entry list was. Keyed by name because the dispatcher reports
 * each payload under the same name in every line it logs about it. */
function appendPayload(name) {
  for (var i = 0; i < payloadEls.length; i++)
    if (payloadEls[i].name === name) return i;

  var li = document.createElement("li");
  var dot = document.createElement("i");
  var label = document.createElement("span"); label.className = "pname"; label.textContent = name;
  var st = document.createElement("em"); st.textContent = "queued";
  li.appendChild(dot); li.appendChild(label); li.appendChild(st);
  $("plist").appendChild(li);
  payloadEls.push({ li: li, st: st, name: name });
  autoCollapse("secQueue", false);
  return payloadEls.length - 1;
}

/* ---------- dispatcher events ----------
 *
 * boot.js tails /data/autoldr/dispatcher.log on the console and reports what it
 * finds there. These are its events. The dispatcher runs past the last thing
 * this page used to be able to watch, so once these start arriving they are the
 * authority on the payload queue and on whether the run worked.
 */
function handleDispatch(event) {
  if (!event) return;
  var i, total;

  switch (event.kind) {
  case "log":
    /* The dispatcher's own output, shown verbatim so it can be matched against
     * the log on the console line for line. */
    log(event.line, event.level === "error" ? "error"
        : event.level === "warning" ? "warning" : "info");
    break;

  case "plan":
    dispatchOwned = true;
    dispatchPlan = event.count;
    /* The dispatcher's own count replaces the manifest count boot.js read up
     * front, which was only ever a guess made before anything was readable. */
    $("kPayload").textContent = event.count + " plugins";
    break;

  case "entry":
    dispatchOwned = true;
    i = appendPayload(event.name);
    setPayload(i, "", event.index + "/" + event.total + (event.local ? " - console-local" : ""));
    $("srcBadge").textContent = payloadEls.length + " queued";
    break;

  case "state":
    dispatchOwned = true;
    i = appendPayload(event.name);
    total = dispatchPlan || payloadEls.length;
    if (event.state === "sending") {
      /* Counted once per payload: the dispatcher logs this line again on a
       * retry, and a retried payload is not another few MB over the wire. */
      if (dispatchBytes[event.name] == null) {
        dispatchBytes[event.name] = event.bytes || 0;
        runStats.bytes += dispatchBytes[event.name];
      }
      setPayload(i, "running", "sending " + dispatchBytes[event.name] + " bytes");
      stage(4, "running", sentCount + "/" + total);
    } else if (event.state === "dryrun") {
      setPayload(i, "", event.bytes + " bytes - would send, nothing sent");
    } else if (event.state === "sent") {
      sentCount++;
      setPayload(i, "sent", "sent");
      stage(4, "running", sentCount + "/" + total);
    }
    break;

  case "done":
    dispatchOwned = true;
    dispatchFailures = event.failures || [];
    stage(4, event.ok ? "done" : "fail",
          sentCount + "/" + (dispatchPlan || payloadEls.length) +
          (event.ok ? "" : " - " + dispatchFailures.length + " failed"));
    break;

  case "watchEnd":
    if (!event.result || event.result.unavailable)
      dispatchUnavailable = (event.result && event.result.why) || "";
    break;

  case "unavailable":
    dispatchUnavailable = event.why || "";
    break;
  }
}

/* clock */
function tick() {
  $("kTime").textContent = ((Date.now() - t0) / 1000).toFixed(1) + "s";
}
function startClock() { if (!timer) timer = setInterval(tick, 100); }
function stopClock() { if (timer) { clearInterval(timer); timer = null; } }

/* The build tag belongs to the boot screen: it answers "which bundle is this?"
 * before anything runs, and is in the way once the run is what matters. */
function setBver(show) {
  $("bver").style.display = show ? "" : "none";
}

/* flow */
function begin() {
  $("boot").classList.add("hidden");
  $("done").classList.add("hidden");
  $("measure").classList.add("hidden");
  $("main").classList.remove("hidden");
  setBver(false);
  $("log").innerHTML = "";
  $("doneSummary").textContent = "";
  logLines = 0; stageDone = 0; sentCount = 0;
  stageOnce = [];
  runStats = { errors: 0, warnings: 0, bytes: 0 };
  userToggled = {};
  payloadEls = [];
  /* Per-run view state for the payload queue. dispatchOwned says whether the
   * dispatcher (rather than this page) owns it - see watchPayloadProgress(). */
  dispatchOwned = false;
  dispatchPlan = 0;
  dispatchFailures = [];
  dispatchUnavailable = "";
  dispatchBytes = {};

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
  /* the queue is unknown until the manifest resolves, and the
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

  /* Sections are left as-is on finish: the run is the interesting part, so
     stages/queue/session/log stay expanded and readable. (The verdict screen
     covers this view; "view run" dismisses it.) */
  $("sumSession").textContent = ok ? "complete" : "failed";

  /* The verdict covers the run, and "view run" is what brings it back, so the
     run view is hidden and the window scrolled back to the top. Without this
     the verdict lands below a full screen of log and you have to scroll to
     find it. */
  $("main").classList.add("hidden");
  window.scrollTo(0, 0);

  $("done").className = "screen center" + (ok ? "" : " error");
  $("doneTitle").textContent = ok ? "JAILBROKEN" : "FAILED";
  /* JAILBROKEN says elfldr is up and the dispatcher took the payload. It does
   * not on its own say the plugins loaded - only the dispatcher's log says
   * that - so when the log could not be read the sentence says so rather than
   * leaving the claim unqualified. */
  var unverified = ok && !!dispatchUnavailable;
  $("doneSub").textContent = ok
    ? (unverified
        ? "dispatcher delivered, but its log could not be read — plugin load unconfirmed"
        : sentCount + " plugin(s) delivered — close this window")
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
    "plugins    " + (names.length ? names.join(" -> ") : "none") + "\n" +
    "elfldr     " + ($("kPort").textContent) + "\n" +
    "transferred " + runStats.bytes.toLocaleString() + " bytes\n" +
    "elapsed    " + ((Date.now() - t0) / 1000).toFixed(1) + "s\n" +
    "log lines  " + logLines + " (" + runStats.warnings + " warn, " +
      runStats.errors + " err)" +
    /* The dispatcher's own account of what went wrong. A payload the dispatcher
     * could not deliver looks exactly like a healthy one from out here without
     * this, which is the whole reason the log is read. */
    (dispatchFailures.length
      ? "\nfailed     " + dispatchFailures.join(" | ")
      : "");

  log(ok ? "run complete" : "run failed: " + (why || "unknown"), ok ? "success" : "error");
}

/* mock run */
/* ---------- the real run ----------
 *
 * src/boot.js is the only caller of the chain. It is an ES module, so it loads
 * after the classic scripts under src/ have put their globals in place. The
 * promise it returns settles when the payload chain reports back. */
/* The one payload the page sends is not known until boot.js gets past the
 * kernel stage. This starts as a placeholder and is replaced the moment the
 * real entry exists; see syncPayloadQueue(). What the dispatcher does behind
 * that one entry arrives as events from boot.js; see handleDispatch(). */
var payloadEntries = [];

function syncPayloadQueue() {
  var entries = (window.jb && window.jb.payloadEntries) || [];
  if (!entries.length) return false;
  payloadEntries = entries;
  renderPayloads(entries.map(function (e) {
    return { name: e.name, url: e.url, size: e.size || 0, local: !!e.local };
  }));
  /* One payload goes out from here, but it dispatches the rest of the chain, so
   * the badge counts the plugins the dispatcher will send rather than the one
   * this page sends. */
  var planned = window.jb && window.jb.plannedPayloads;
  $("srcBadge").textContent = payloadEntries.length + " queued";
  $("kPayload").textContent = (planned || payloadEntries.length) + " plugins";
  $("kSource").textContent = "dispatcher.elf";
  return true;
}

function showPayloadQueue() {
  /* The console's own manifest only becomes readable after the kernel stage,
   * so up front this is an honest placeholder rather than a guess. */
  renderPayloads([{ name: "resolving manifest", url: "", size: 0 }]);
  $("srcBadge").textContent = "resolving";
  $("sumSession").textContent = "queued";
  autoCollapse("secQueue", false);
  $("kPayload").textContent = "resolving";
  $("kSource").textContent = "manifest";

  var timer = setInterval(function () {
    if (syncPayloadQueue()) clearInterval(timer);
  }, 150);
  setTimeout(function () { clearInterval(timer); }, 120000);
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
  /* boot.js logs "<name> sent" once dispatcher.elf has been handed to elfldr.
   * That is a handoff, not a loaded plugin, so it stands down as soon as the
   * dispatcher's own log starts reporting (dispatchOwned) - otherwise it would
   * count dispatcher.elf as a delivered plugin on top of the dispatcher's count
   * and put two entries in the queue for one payload. */
  var sent = {};
  var timer = setInterval(function () {
    if (dispatchOwned) { clearInterval(timer); return; }
    if (!payloadEntries.length) return;
    for (var i = 0; i < payloadEntries.length; i++) {
      if (sent[i]) continue;
      var name = payloadEntries[i].name;
      if (rawLogLines.some(function (l) { return l.indexOf(name + " sent") !== -1; })) {
        sent[i] = true;
        sentCount++;
        setPayload(i, "sent", "sent");
        runStats.bytes += payloadEntries[i].size || 0;
        log(name + " -> elfldr :9021 accepted", "success");
        stage(4, "running", sentCount + "/" + payloadEntries.length);
        if (i === payloadEntries.length - 1)
          log("dispatcher.elf now sends the rest of the chain itself - " +
              "reporting it from /data/autoldr/dispatcher.log", "info");
      }
    }
    if (sentCount === payloadEntries.length) {
      clearInterval(timer);
      stage(4, "done", "sent");
      log("dispatcher.elf delivered to elfldr :9021", "success");
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
  setBver(false);
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
    $("goWrap").classList.add("hidden");
    $("goNote").classList.add("hidden");
    return;
  }

  /* The chain sprays the moment it runs, so it takes a deliberate click rather
     than firing on load. ?auto=1 skips the gate - the headless chain probe
     and the on-console retest both use it. */
  if (q.get("auto") === "1") { launch(); return; }

  /* Not auto-run instantly: the exploit sprays the moment launch() fires,
   * so leave a visible countdown on the boot screen. A tap on JAILBREAK
   * skips the wait for someone who is in a hurry. */
  var remaining = 10;
  $("goNote").textContent = "auto-starts in " + remaining + "s - tap JAILBREAK to start now";
  var countdown = setInterval(function () {
    remaining--;
    if (remaining <= 0) {
      clearInterval(countdown);
      launch();
    } else {
      $("goNote").textContent = "auto-starts in " + remaining + "s - tap JAILBREAK to start now";
    }
  }, 1000);
  $("go").addEventListener("click", function () {
    clearInterval(countdown);
    launch();
  });
}

var hasLaunched = false;
function launch() {
  if (hasLaunched) return;
  hasLaunched = true;
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
      return n.textContent;
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
    window.scrollTo(0, 0);
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
