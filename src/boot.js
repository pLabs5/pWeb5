/* Boot for the Jailbreak Store.
 *
 * This replaces Relapse's own src/site.js and is the ONLY place that decides
 * how the exploit chain gets called. The chain itself is KAR0218's reworked
 * Relapse (src/core.js, src/utils/mem.js, src/relapse_exploit.js, src/rop.js,
 * src/kexp.js), which reports through the two globals upstream site.js
 * also defined:
 *
 *   window.writeLog(message, type)   free-form log line
 *   window.jb.mark(tag, detail)      progress marker
 *
 * Both are wired to the UI by app.js, so the exploit's own output feeds the
 * log and drives the stage list without any of it being aware of the UI.
 *
 * What stays ours, and why: upstream Relapse and KAR0218 both hardcode the
 * plugin list and its order inside their own loaders, and drive them from a
 * remote keypress - which cannot happen inside the PS5 WebView. Here the
 * manifest decides both which payloads load and in what order, and the load runs
 * directly against the ROP handles main.js publishes. See "Payload loading"
 * below. Their chain exposes those handles exactly the same way, so none of this
 * needed changing to take their exploit.
 *
 * Nothing under src/ is edited to serve the UI or the manifest. Vendored chain
 * files differ from KAR0218 only where they had to: import paths, plus the fake
 * cell's promotion path in mem.js. Keep it that way - re-syncing from upstream
 * should be a diff, not a rewrite.
 */

import { establishPrimitive, fakeCellReleased, CORE_INSTANCE } from "./core.js";
import { installWindowP, pairStatus, memCoreInstance, readInto } from "./utils/mem.js";

/* core.js is module state, and mem.js imports it separately to promote the
 * fake cell. If those two imports ever resolve to different URLs, ES modules
 * load two separate instances: establishPrimitive() runs on one while mem.js
 * inspects the other, and promotion fails with a useless "pair was NOT
 * promoted". Both sides import it without a ?v= so the URLs match, and this
 * assertion turns any future skew into a loud failure instead of a silent
 * one. Upstream carries the same guard against their aio.html. */
if (CORE_INSTANCE !== memCoreInstance)
  throw new Error(
    "core.js module skew: boot.js and utils/mem.js loaded different instances",
  );

/* main.js appends offsets/<fw>.js with a plain <script> tag while it is being
 * parsed, and upstream site.js calls straight into the exploit without waiting
 * for it. That is a real race: the offset globals can still be undefined when
 * the WebKit stage asks for them. Wait for them instead of hoping. */
function waitForOffsets(timeoutMs = 15000) {
  const haveOffsets = () =>
    typeof OFFSET_wk_host_constructor_candidates !== "undefined" &&
    typeof OFFSET_wk_memset_import !== "undefined" &&
    typeof wk_gadgetmap !== "undefined" &&
    typeof syscall_map !== "undefined";

  if (haveOffsets()) return Promise.resolve();

  return new Promise((resolve, reject) => {
    const started = Date.now();
    const timer = setInterval(() => {
      if (haveOffsets()) {
        clearInterval(timer);
        resolve();
      } else if (Date.now() - started > timeoutMs) {
        clearInterval(timer);
        reject(
          new Error(
            "offsets/" + (window.fw_str || "unknown") + ".js never loaded, " +
              "so this firmware has no exploit offsets",
          ),
        );
      }
    }, 25);
  });
}

function getWebKitBase() {
  const ctor = globalThis.__ps5NativeCtor;
  if (
    typeof ctor !== "number" ||
    typeof OFFSET_wk_host_constructor_candidates === "undefined"
  )
    throw new Error("WebKit base inputs are unavailable");

  for (const offset of OFFSET_wk_host_constructor_candidates) {
    const base = ctor - offset;
    if (base >= 0x800000000 && base < 0x900000000 && base % 0x4000 === 0)
      return base;
  }
  throw new Error("WebKit base not found");
}

/* core.js's establishPrimitive() does have a reject path now - it caps itself
 * at maxAttempts and rejects with "gave up after N attempts" - but the cap is
 * per placement attempt, and a run where every attempt times out slowly can
 * still outlast the page's patience. This stays as the outer bound so a stalled
 * WebKit stage still reaches a verdict instead of sitting at 0/5 forever. */
function withDeadline(promise, ms, what, detail) {
  let timer;
  return Promise.race([
    promise.finally(() => clearTimeout(timer)),
    new Promise((_, reject) => {
      timer = setTimeout(() => {
        /* `detail` is deferred to the moment the deadline actually fires and is
         * only appended if it yields something, so a stage that never reported a
         * phase does not claim it stalled in "unknown". */
        const phase = detail ? detail() : null;
        const where = phase ? ", stalled after: " + phase : "";
        reject(
          new Error(
            what + " did not complete in " + Math.round(ms / 1000) + "s" + where,
          ),
        );
      }, ms);
    }),
  ]);
}

/* Runs the WebKit bug until it yields a userland read/write primitive, then
 * installs it.
 *
 * core.js's establishPrimitive takes an options object rather than a bare
 * callback, and placement retries itself up to maxAttempts, so this no longer
 * needs to hand it a single event handler. The onEvent hook still forwards
 * every line to the page log: core.js reports its placement retries there and
 * they are the only way to tell "still trying" from "stuck".
 *
 * installWindowP then promotes the fake cell into the real read/write pair.
 * That promotion can fail, and on failure mem.js either leaves window.p
 * withdrawn or reports pairStatus.error. Upstream checks pairStatus.promoted
 * and refuses to continue; so does this, because a primitive that never
 * promoted will fail somewhere much less legible a few stages later. */
async function getPrimitive(timeoutMs) {
  const carrier = await withDeadline(
    establishPrimitive({
      /* Placement retries itself. 24 is upstream's figure: enough to ride out
       * a run where the heap is in a bad shape, without letting a genuinely
       * dead firmware sit here for many minutes. */
      maxAttempts: 24,
      onEvent(tag, detail, attempt) {
        window.writeLog(
          (typeof attempt === "number" ? "[" + attempt + "] " : "") + tag +
            (detail ? " " + detail : ""),
          "info",
        );
      },
      beforeCriticalLoad() {
        /* core.js lays out this page's own DOM immediately before the critical
         * WebKit load, and placement is sensitive to what is sitting on the
         * heap there. Touching layout is what gives it a reason to be there.
         * Upstream pokes their #console; ours is the #log pane. */
        try {
          $("log").offsetWidth;
        } catch (e) {}
      },
    }),
    timeoutMs,
    "the WebKit exploit",
  );

  installWindowP(carrier, {
    onEvent(tag, detail) {
      window.writeLog(tag + " " + detail, "info");
    },
  });

  if (!pairStatus.promoted)
    throw new Error(
      "the primitive pair was not promoted: " + (pairStatus.error || "unknown"),
    );

  const primitive = globalThis.p;
  if (!primitive || typeof primitive.read8 !== "function")
    throw new Error("Memory primitive unavailable");

  window.writeLog(
    "primitive up (fakeCellReleased=" + fakeCellReleased() + ")",
    "success",
  );
  return primitive;
}
/* ------------------------------------------------------------------ *
 * Payload loading
 *
 * The chain's kexp.js brings elfldr up and then stops - it exports only
 * runKexp, and has no idea a payload list exists. That is deliberate: upstream
 * Relapse and KAR0218 both hardcode the plugin list and its order inside their
 * own loaders.
 *
 * The page used to make that list the fourth stage of the chain: parse
 * manifest.txt here, map each plugin into ROP memory, and stream it to elfldr
 * one socket at a time. It tied the rest of the jailbreak to this page staying
 * alive, and it had no way to know whether a payload had actually taken - the
 * UI's "accepted" state was our own "sent" log line coming back to be polled.
 *
 * So the page now has one job after kexp: hand elfldr a single payload,
 * dispatcher.elf, which resolves the manifest and sends everything else itself
 * over the console's own sockets. See dispatcher/main.c. manifest.txt is read
 * by that payload now, not by this page.
 * ------------------------------------------------------------------ */

const FS = {
  READ: 0x003,
  WRITE: 0x004,
  OPEN: 0x005,
  CLOSE: 0x006,
  SOCKET: 0x061,
  CONNECT: 0x062,
  MKDIR: 0x088,
  MMAP: 0x1dd,
};
const PROT_RW = 0x3;
const MAP_PRIVATE_ANON = 0x1002;
const ELFDR_PORT = 9021;
const CHUNK = 0x10000;
const O_RDONLY = 0;
const MKDIR_ANY = 0x1ff;

/* The network path, matching kexp's mapElf. */
async function mapElfFromUrl(url, p, chain) {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) throw new Error(url + " returned HTTP " + response.status);
  const elf = new Uint8Array(await response.arrayBuffer());
  if (elf.length < 0x1000) throw new Error(url + " is too small to be an ELF");

  const size = (elf.length + 0x3fff) & ~0x3fff;
  const mapped = await chain.syscall(FS.MMAP, 0, size, PROT_RW, MAP_PRIVATE_ANON, -1, 0);
  if (mapped.low >>> 0 === 0xffffffff || mapped.low < 0x10000)
    throw new Error("mmap failed for " + url);

  const dwords = elf.length & ~3;
  for (let offset = 0; offset < dwords; offset += 4) p.write4(mapped.add32(offset), readU32(elf, offset));
  for (let offset = dwords; offset < elf.length; offset++) p.write1(mapped.add32(offset), elf[offset]);
  if (p.read4(mapped) >>> 0 !== 0x464c457f) throw new Error(url + " copy failed");
  return { base: mapped, size: elf.length };
}

function readU32(bytes, offset) {
  return (
    (bytes[offset] |
      (bytes[offset + 1] << 8) |
      (bytes[offset + 2] << 16) |
      (bytes[offset + 3] << 24)) >>>
    0
  );
}

async function connectToElfldr(p, chain) {
  const address = p.malloc(16, 1);
  p.write8(address, { hi: 0, low: 0 });
  p.write8(address.add32(8), { hi: 0, low: 0 });
  p.write4(address, 0x3d230210); // AF_INET, 127.0.0.1:9021
  p.write4(address.add32(4), 0x0100007f);

  for (let attempt = 0; attempt < 40; attempt++) {
    const fd = (await chain.syscall(FS.SOCKET, 2, 1, 0)).low | 0;
    if (fd >= 0) {
      if (((await chain.syscall(FS.CONNECT, fd, address, 16)).low | 0) === 0) return fd;
      await chain.syscall(FS.CLOSE, fd);
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error("elfldr is not listening on port 9021");
}

async function sendMapped(name, payload, p, chain) {
  const fd = await connectToElfldr(p, chain);
  try {
    for (let offset = 0; offset < payload.size; ) {
      const length = Math.min(CHUNK, payload.size - offset);
      const written = (await chain.syscall(FS.WRITE, fd, payload.base.add32(offset), length)).low | 0;
      if (written <= 0) throw new Error(name + " socket write failed");
      offset += written;
    }
  } finally {
    await chain.syscall(FS.CLOSE, fd);
  }
}

/* ------------------------------------------------------------------ *
 * Watching the dispatcher
 *
 * The dispatcher's own output goes to a file on the console, not back to the
 * page: /data/autoldr/dispatcher.log. It has nowhere else to put it, because the
 * WebView it was handed to cannot be written to from the other side.
 *
 * That file is also the answer to "what is it actually loading", because it is
 * the dispatcher's own account of the run rather than this page's guess at one.
 * The page can read it: it still holds the read/write primitive and the ROP
 * chain from the kernel stage, and open(2)/read(2) are syscalls like any other.
 * So the page watches the log over the same primitive the payload arrived on.
 * No second listener, no extra port, and nothing for the dispatcher to know
 * about - which matters, because payloads/dispatcher.elf is a committed binary
 * and there is no SDK here to rebuild it.
 *
 * The one thing the dispatcher needs from outside is the directory. Its logmsg()
 * opens the log for append and does nothing when that fails, so on a console
 * with no /data/autoldr/ the file is never created and there is nothing to
 * watch. Creating it here, over the same syscalls, is why the committed
 * dispatcher works unchanged.
 * ------------------------------------------------------------------ */

const LOCAL_ROOT = "/data/autoldr";
const DISPATCHER_LOG = LOCAL_ROOT + "/dispatcher.log";
const LOG_READ_CHUNK = 0x4000;
const LOG_MAX_BYTES = 0x20000;
const LOG_POLL_MS = 600;
/* The dispatcher logs its first line the moment it starts, so a run that has
 * produced nothing by now is not going to. Short enough not to leave the page
 * hanging on a console we cannot read. */
const LOG_UNSEEN_GRACE_MS = 8000;

/* The dispatcher's log is plain text with no levels in it - it is a file on the
 * console, written for whoever opens it later. These are what turn it into the
 * levels the page renders. Anything unrecognised stays "info", so a line the
 * dispatcher grows later still shows up instead of being dropped or misfiled.
 *
 * This list is deliberately anchored on the reason a line is written, not on the
 * subsystem that wrote it: "elfldr:" covers both a wait that resolves (warning)
 * and a listener that never appears (error), and only one of those ends a run.
 * dispatcher/main.c is the authority on the wording - if a line moves there, it
 * moves here. */
const DISPATCH_ERRORS = [
  /dispatch failed/,
  /cannot fetch /,
  /cannot read /,
  /cannot create request/,
  /request failed for /,
  /returned status /,
  /elfldr: nothing on :\d+/,
  /elfldr: socket:/,
  /cannot reach elfldr/,
  /* the write error carries the payload name in front of it, so it cannot be
   * matched on a prefix the way the rest of these are */
  /write failed at \d+\/\d+/,
  /only \d+ bytes, too small/,
  /but not an ELF/,
  /manifest produced no entries/,
  /cloud manifest unavailable/,
  /* every sce* bring-up step, which is what a jailbroken-but-no-network
   * console reports and used to reach this page as nothing at all */
  /\bsce\w+ failed\b/,
  /must be an http, https or local: target/,
  /local target must /,
  /too many entries/,
];
const DISPATCH_WARNINGS = [
  /not accepting yet/,
  /firmware version unavailable/,
  /not BCD, unrecognised/,
];

/* "[2/3] etahen.elf <- payloads/etaHEN.elf (console-local)" */
const DISPATCH_ENTRY = /^\[(\d+)\/(\d+)\] (.+?) <- (\S+?)( \(console-local\))?$/;
/* "dispatcher: 3 payload(s), dispatching" */
const DISPATCH_PLAN = /^dispatcher: (\d+) payload\(s\)/;
/* "etahen.elf: sending 4690760 bytes to elfldr :9021" */
const DISPATCH_SENDING = /^(\S+): sending (\d+) bytes to elfldr :\d+$/;
const DISPATCH_WOULD_SEND = /^(\S+): (\d+) bytes, would send to elfldr :\d+$/;
const DISPATCH_SENT = /^(\S+): sent$/;
const DISPATCH_DONE = /^dispatcher: done$/;

function dispatchLevel(line) {
  if (DISPATCH_ERRORS.some((re) => re.test(line))) return "error";
  if (DISPATCH_WARNINGS.some((re) => re.test(line))) return "warning";
  return "info";
}

/* elfldr's readback is echoed into the log verbatim, so the file can hold bytes
 * that are not text - a control character would move the line on screen and a
 * lone newline would split one log row into several. Collapse anything outside
 * printable ASCII, and runs of it, to single spaces. */
function cleanDispatchLine(raw) {
  return String(raw).replace(/[^\x20-\x7e]+/g, " ").replace(/\s+/g, " ").trim();
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/* A syscall the offsets file has no entry for comes back as undefined, and
 * pushing that onto the ROP chain throws a TypeError from inside mem.write8
 * rather than saying which syscall is missing. offsets/13.00.js ships a
 * truncated map, so say it here instead. */
function missingSyscalls(chain, names) {
  return names.filter((n) => !chain.syscalls[n]);
}

async function ensureLocalRoot(p, chain) {
  const slot = p.malloc(LOCAL_ROOT.length + 1);
  p.writestr(slot, LOCAL_ROOT);
  /* EEXIST is the normal answer - the directory is already there whenever the
   * console owner keeps a manifest in it - so only the failure is worth
   * reporting, and the caller decides what that means. */
  return (await chain.syscall(FS.MKDIR, slot, MKDIR_ANY, 0)).low | 0;
}

/* Read a whole file off the console into a Uint8Array. `slot` and `buf` are
 * console-side allocations the caller owns, passed back in so a polling loop
 * does not leak a fresh buffer on every tick.
 *
 * Returns null when the file cannot be opened, which is the normal state for a
 * console nobody has dropped a manifest on yet. */
async function readConsoleFile(chain, path, slot, buf, maxBytes) {
  const fd = (await chain.syscall(FS.OPEN, slot, O_RDONLY, 0)).low | 0;
  if (fd < 0) return null;

  const out = new Uint8Array(maxBytes);
  let total = 0;
  try {
    for (;;) {
      const want = Math.min(LOG_READ_CHUNK, maxBytes - total);
      if (want <= 0) break;
      const got = (await chain.syscall(FS.READ, fd, buf, want)).low | 0;
      if (got <= 0) break;
      readInto(out.subarray(total, total + got), buf, got);
      total += got;
    }
  } finally {
    await chain.syscall(FS.CLOSE, fd);
  }
  return out.subarray(0, total);
}

/* Everything the log already holds belongs to an earlier run. Tailing from its
 * current end is what makes the watcher report THIS run's dispatch instead of
 * replaying the last one, which is why loadPayloads() takes the offset before
 * the handoff rather than starting at zero. */
async function dispatcherLogOffset(p, chain) {
  const missing = missingSyscalls(chain, [FS.OPEN, FS.READ, FS.CLOSE]);
  if (missing.length)
    throw new Error(
      "these offsets have no syscall for " + missing.map((n) => "0x" + n.toString(16)).join(", ") +
        ", so the page cannot read the console's disk",
    );

  const rc = await ensureLocalRoot(p, chain);
  if (rc !== 0 && rc !== -17)
    /* -17 is EEXIST. Anything else means the directory is not there and the
     * dispatcher will not be able to write its log at all. */
    window.writeLog("could not create " + LOCAL_ROOT + " (errno " + rc + ")", "warning");

  const slot = p.malloc(DISPATCHER_LOG.length + 1, 1);
  p.writestr(slot, DISPATCHER_LOG);
  const buf = p.malloc(LOG_READ_CHUNK, 1);
  const existing = await readConsoleFile(chain, DISPATCHER_LOG, slot, buf, LOG_MAX_BYTES);
  return existing ? existing.length : 0;
}

/* Reads the dispatcher's log until it says it is finished, and reports every
 * line as it lands. Resolves with the run's own verdict, so boot() can hold the
 * final screen until the chain is genuinely over rather than until the handoff
 * that started it.
 *
 * `unavailable` comes back true when the log could never be read at all, which
 * is the one case where the page has to fall back to reporting the handoff and
 * nothing more. */
async function watchDispatcherLog(p, chain, from, deadlineMs) {
  const started = Date.now();
  const failures = [];
  let finished = false;
  let sawAny = false;
  let truncated = false;
  let lastLine = "";

  const result = { ok: false, why: "", unavailable: true };

  let slot, buf;
  try {
    slot = p.malloc(DISPATCHER_LOG.length + 1, 1);
    p.writestr(slot, DISPATCHER_LOG);
    buf = p.malloc(LOG_READ_CHUNK, 1);
  } catch (e) {
    result.why = "could not set up the dispatcher log reader (" + e.message + ")";
    window.jb.dispatch({ kind: "unavailable", why: result.why });
    return result;
  }

  const report = (line) => {
    const level = dispatchLevel(line);
    if (level === "error") failures.push(line);
    window.jb.dispatch({ kind: "log", line: line, level: level });

    let m;
    if ((m = DISPATCH_ENTRY.exec(line))) {
      window.jb.dispatch({
        kind: "entry",
        index: Number(m[1]),
        total: Number(m[2]),
        name: m[3],
        target: m[4],
        local: !!m[5],
      });
      return;
    }
    if ((m = DISPATCH_PLAN.exec(line))) {
      window.jb.dispatch({ kind: "plan", count: Number(m[1]) });
      return;
    }
    if ((m = DISPATCH_SENDING.exec(line))) {
      window.jb.dispatch({ kind: "state", name: m[1], state: "sending", bytes: Number(m[2]) });
      return;
    }
    if ((m = DISPATCH_WOULD_SEND.exec(line))) {
      window.jb.dispatch({ kind: "state", name: m[1], state: "dryrun", bytes: Number(m[2]) });
      return;
    }
    if ((m = DISPATCH_SENT.exec(line))) {
      window.jb.dispatch({ kind: "state", name: m[1], state: "sent" });
      return;
    }
    if (DISPATCH_DONE.test(line)) {
      finished = true;
      window.jb.dispatch({ kind: "done", ok: failures.length === 0, failures: failures.slice() });
    }
  };

  let seen = from;
  let carry = "";

  for (;;) {
    let bytes = null;
    try {
      bytes = await readConsoleFile(chain, DISPATCHER_LOG, slot, buf, LOG_MAX_BYTES);
    } catch (e) {
      window.writeLog("dispatcher log read failed: " + e.message, "warning");
    }

    if (bytes && bytes.length) {
      result.unavailable = false;
      sawAny = true;

      /* Someone truncated or replaced the log under us. Start again from the
       * top rather than sitting at an offset past the end and reporting
       * nothing for the rest of the run. */
      if (bytes.length < seen) {
        seen = 0;
        carry = "";
      }

      if (bytes.length >= LOG_MAX_BYTES && !truncated) {
        truncated = true;
        window.writeLog(
          "dispatcher log is at " + LOG_MAX_BYTES + " bytes, so its oldest lines are not shown",
          "warning",
        );
      }

      if (bytes.length > seen) {
        carry += new TextDecoder().decode(bytes.subarray(seen, bytes.length));
        const lines = carry.split("\n");
        /* The last element is whatever followed the final newline, which is a
         * line still being written. Hold it until the rest of it lands. */
        carry = lines.pop();
        for (const raw of lines) {
          const line = cleanDispatchLine(raw);
          if (!line) continue;
          lastLine = line;
          report(line);
        }
        seen = bytes.length;
      }
    }

    if (finished || failures.length) break;

    /* Nothing at all after this long means the log is not coming, and waiting
     * out the full deadline to learn that only makes the page sit there. Either
     * the file cannot be read or the dispatcher cannot write it, and neither is
     * something retrying fixes - the caller reports the run as unverified
     * rather than as a failure, because the chain itself may well be fine. */
    if (!sawAny && Date.now() - started > LOG_UNSEEN_GRACE_MS) {
      result.why = "the dispatcher wrote nothing to its log in " +
        Math.round(LOG_UNSEEN_GRACE_MS / 1000) + "s, so what it loaded cannot be confirmed";
      break;
    }

    if (Date.now() - started > deadlineMs) {
      result.why = "the dispatcher never finished - last thing it logged: " + lastLine;
      break;
    }
    await sleep(LOG_POLL_MS);
  }

  if (failures.length) {
    result.ok = false;
    result.why = failures[failures.length - 1];
  } else if (finished) {
    result.ok = true;
  }

  if (!result.unavailable) window.jb.dispatch({ kind: "watchEnd", result: result });
  return result;
}

/* The one payload this page sends. Everything the manifest names is dispatched
 * by it, natively, so closing this page no longer strands the chain. */
const DISPATCHER_URL = "payloads/dispatcher.elf";
const DISPATCHER_NAME = "dispatcher.elf";

/* How many entries the manifest names, plus kstuff if the manifest did not
 * name one - the same rule the dispatcher applies. Best effort: this is for the
 * UI's plugin count, and failing to read the manifest here says nothing about
 * whether the dispatcher can read it on the console. */
/* Counts the payloads the dispatcher intends to send. The console-local
 * manifest wins - that is the one the dispatcher reads, so site- and
 * page-side guesses have to defer to it. Only when it is missing or
 * unreadable does the count fall back to the site file. */
function countManifestLines(text) {
  let named = 0, kstuff = false;
  for (const raw of String(text).split("\n")) {
    const line = raw.replace(/#.*$/, "").trim();
    if (!line) continue;
    const eq = line.indexOf("=");
    const name = (eq < 0 ? line : line.slice(0, eq)).trim();
    if (!name) continue;
    named++;
    if (/kstuff/i.test(name)) kstuff = true;
  }
  return named + (kstuff ? 0 : 1);
}

async function countPlannedPayloads(p, chain) {
  try {
    const loaded = await readConsoleFileBytes(p, chain, LOCAL_MANIFEST, LOG_MAX_BYTES);
    if (loaded) return countManifestLines(new TextDecoder().decode(loaded));
  } catch (e) {
    /* A CSP/SYSCALL gap on an offsets build means the console filesystem is
     * opaque - fall through to the site manifest, which is the old
     * behaviour, rather than refusing to report anything. */
  }
  try {
    const response = await fetchWithTimeout("manifest.txt", 30000);
    if (!response.ok) return 0;
    return countManifestLines(await response.text());
  } catch (e) {
    return 0;
  }
}

/* The dispatcher's HTTPS cannot be relied on (a sandboxed console network
 * drops it), so the WebView - which is already online - fetches the payloads
 * and streams them onto disk under /data/autoldr/payloads. The local manifest
 * is then rewritten around local: targets. Returns only when every remote
 * entry was staged, so the on-disk manifest is consistent or untouched. */
async function stageConsoleManifest(p, chain) {
  const origin = /^https?:/.test(window.location.origin || "")
    ? window.location.origin
    : "https://pweb5.pages.dev";

  let text;
  try {
    const loaded = await readConsoleFileBytes(p, chain, LOCAL_MANIFEST, LOG_MAX_BYTES);
    text = loaded ? new TextDecoder().decode(loaded) : null;
  } catch (e) {
    text = null;
  }
  if (!text) {
    const response = await fetchWithTimeout("manifest.txt", 30000);
    if (!response.ok) throw new Error("site manifest fetch failed: HTTP " + response.status);
    text = await response.text();
  }

  // A commented-out kstuff line is not a kstuff line.
  const activeLines = text.split("\n").map((l) => l.replace(/#.*$/, "").trim());
  const kstuffNamed = activeLines.some((l) => l !== "" && /kstuff/i.test(l));
  /* A missing kstuff line means the dispatcher will pick one itself; mirror
   * the same pick here so a wrong build does not quietly load. */
  const modern = !!window.fw_str && window.fw_str !== "" &&
    !(parseFloat(window.fw_str) <= 10.01);
  if (!kstuffNamed) text += (text.trim() ? "\n" : "") +
    (modern
      ? "kstuff-lite.elf=payloads/kstuff-lite-1.11B.elf\n"
      : "kstuff.elf=payloads/kstuff.elf\n");

  const lines = text.split("\n");
  const out = [];
  let staged = 0, rewritten = 0;

  for (const raw of lines) {
    const stripped = raw.replace(/#.*$/, "").trim();
    if (!stripped) { out.push(raw); continue; }
    const eq = stripped.indexOf("=");
    const name = (eq < 0 ? stripped : stripped.slice(0, eq)).trim();
    const target = (eq < 0 ? "payloads/" + name : stripped.slice(eq + 1)).trim();
    if (/^local:/i.test(target)) { out.push(raw); continue; }

    /* Bare names and the explicit payloads/ form resolve the same way the
     * dispatcher treats them: under the site's payloads/ directory. */
    const url = /^https?:\/\//i.test(target) ? target
      : /^\/\//.test(target) ? "https:" + target
      : origin + "/" + (/^payloads\//.test(target) ? target : "payloads/" + target);

    const bin = url.split("?")[0].split("/").pop();
    window.writeLog("staging " + name + " -> " + LOCAL_PAYLOADS_DIR + "/" + bin, "info");
    try {
      const response = await fetchWithTimeout(url, 30000);
      if (!response.ok) throw new Error("HTTP " + response.status);
      const elf = new Uint8Array(await response.arrayBuffer());
      if (elf.length < 4 || elf[0] !== 0x7f || elf[1] !== 0x45 || elf[2] !== 0x4c || elf[3] !== 0x46)
        throw new Error("not an ELF (a CDN error page?)");
      await ensureDir(p, chain, LOCAL_PAYLOADS_DIR);
      await writeConsoleFile(p, chain, LOCAL_PAYLOADS_DIR + "/" + bin, elf);
      out.push(name + "=local:" + LOCAL_PAYLOADS_DIR + "/" + bin);
      staged++;
      rewritten++;
    } catch (e) {
      /* Do not leave a half-staged manifest: the local file would shrink
       * boot-time flexibility and any entry we could not stage is one the
       * dispatcher would need HTTPS for anyway. */
      window.writeLog("could not stage " + name + " (" + e.message + "); the dispatcher will try its own network", "warning");
      return;
    }
  }

  out.unshift("# rewritten by the staging page with local: targets; the", "# originals' bytes are under /data/autoldr/payloads.");
  await ensureDir(p, chain, LOCAL_ROOT);
  await writeConsoleFile(p, chain, LOCAL_MANIFEST, new TextEncoder().encode(out.join("\n") + "\n"));
  window.writeLog("staged " + staged + " payload(s) onto the console; the dispatcher will load them from disk", "success");
}

async function loadPayloads(p, chain, watchMs) {
  const entry = { name: DISPATCHER_NAME, url: DISPATCHER_URL };

  window.writeLog("loading " + DISPATCHER_URL + " - the rest of the chain is dispatched natively", "info");
  /* app.js reads both of these to draw its progress view. The dispatcher owns
   * the per-payload pauses now, so there is one entry and no inter-entry delay. */
  window.jb.payloadEntries = [entry];
  window.jb.nextDelay = 0;
  /* What the dispatcher intends to send, read from manifest.txt here purely so
   * the UI can count it before the dispatcher has said anything. The dispatcher
   * reads the manifest itself, and its own log replaces this count the moment
   * it reports the plan. */
  window.jb.plannedPayloads = await countPlannedPayloads(p, chain);
  /* Set before the handoff, not after: waitForPayloads() uses this to know the
   * log is the signal, so it must be true by the time the "sent" line it would
   * otherwise fall back on appears. */
  window.jb.dispatcherArmed = true;

  /* Stage the payloads through the WebView before the dispatcher starts,
   * because the console-side HTTPS is unreliable; if this fails we still
   * send dispatcher.elf - the failure modes down there cannot be worse
   * for it than the ones the dispatcher already reports. */
  try {
    await stageConsoleManifest(p, chain);
  } catch (e) {
    window.writeLog("payload staging skipped: " + e.message, "warning");
  }

  const payload = await mapElfFromUrl(entry.url, p, chain);
  entry.size = payload.size;

  /* Taken before the send, not after. The dispatcher starts writing the moment
   * elfldr loads it, so the end of the log has to be noted while it still only
   * holds earlier runs - otherwise this run's lines are indistinguishable from
   * the last one's. */
  let from = 0;
  try {
    from = await dispatcherLogOffset(p, chain);
  } catch (e) {
    window.writeLog(
      "cannot read " + DISPATCHER_LOG + " (" + e.message + ") - this page cannot report what the dispatcher loads",
      "warning",
    );
    window.jb.dispatch({ kind: "unavailable", why: e.message });
  }

  await sendMapped(entry.name, payload, p, chain);
  window.jb.mark("plugin", entry.name + " sent");

  /* Started here rather than inside the send, and not before it: the ROP chain
   * carries one caller at a time, so a log poll racing sendMapped's socket
   * writes would corrupt both. */
  window.jb.dispatcherWatch = watchDispatcherLog(p, chain, from, watchMs);
  return [entry];
}

function fetchWithTimeout(url, ms, init) {
  return Promise.race([
    fetch(url, init || { cache: "no-store" }),
    new Promise((_, reject) => setTimeout(() => reject(new Error(url + " timed out at the WebView")), ms)),
  ]);
}

/* Resolves once the dispatcher says it is finished, which is the only thing that
 * means the plugins actually loaded. It used to settle on the "<name> sent"
 * line instead, which is just the handoff - a run whose plugins all failed
 * still produced that line, and the verdict said JAILBROKEN.
 *
 * The dispatcher's log is that signal (see watchDispatcherLog). If it cannot be
 * read at all the page is back to knowing only that the handoff happened, so the
 * old line stays as a fallback rather than the run sitting out its whole
 * timeout. */
function waitForPayloads(timeoutMs) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let timer = null;

    const done = (ok, why) => {
      if (settled) return;
      settled = true;
      window.jb.payloadsDone = true;
      if (timer) clearInterval(timer);
      ok ? resolve() : reject(new Error(why));
    };

    timer = setInterval(() => {
      const watch = window.jb.dispatcherWatch;
      if (watch) {
        clearInterval(timer);
        timer = null;
      watch.then(
        (r) => {
          /* An unreadable log is not a failed run - it is an unverified one. The
           * handoff did land, so the chain worked; there is just nothing here
           * that can say what happened behind it, and finish() says exactly
           * that instead of claiming the plugins loaded. A log we could read but
           * which reported a failure is a real failure, and rejects. */
          if (r.unavailable) done(true, r.why);
          else done(r.ok, r.why);
        },
        (e) => done(false, (e && e.message) || String(e)),
      );
        return;
      }
      if (window.jb.dispatcherArmed) return;

      const lines = window.jb.logLines || [];
      /* The chain reports a failed kexp handoff in its own words now
       * ("elfldr is not confirmed up" / "kexp threw"), and main.js logs the
       * case where the kernel stage finished without elfldr. Any of those means
       * there is no listener to send plugins to. */
      if (lines.some((l) =>
            /elfldr is not listening/.test(l) ||
            /elfldr is not confirmed up/.test(l) ||
            /elfldr did not confirm up/.test(l) ||
            /^ELFLDR kexp threw/.test(l)))
        done(false, "elfldr is not listening on port 9021");
      else {
        const entries = window.jb.payloadEntries;
        if (entries && entries.length && lines.some((l) => l.indexOf(entries[entries.length - 1].name + " sent") >= 0))
          done(true, "");
      }
    }, 100);

    setTimeout(() => done(false, "plugin chain did not finish in time"), timeoutMs);
  });
}

/* The last kernel-stage line the chain reported, so a timeout can name the
 * phase it stalled in instead of just failing.
 *
 * The older chain tagged this stage "Kernel: ...". KAR0218's uses short stage
 * tags instead, so match those too - otherwise a kernel timeout could not say
 * where it got stuck, which was the entire reason this function exists.
 *
 * The separator is a single space, not ": ": relapse_exploit.js report()
 * builds its line as tag + " " + detail, and main.js hands report() straight to
 * window.writeLog, which stores the message verbatim. Expecting ": " here meant
 * no line ever matched and every timeout reported "unknown".
 *
 * Every tag the chain emits is listed, because withDeadline wraps all of
 * main() and the whole driver lives inside it - START is the first line of the
 * run and DONE the last, so a stall anywhere in between still has to be
 * nameable. Keeping the list complete is the point; harness.js asserts that no
 * tag the chain can emit is missing here. */
const KERNEL_STAGE_TAGS =
  /^(?:Kernel:|BOOT|DEFUSE|DONE|ELFLDR|ESC|FAIL|FAST|KASLR|KEXP|KREAD|PARK|PIN|PIPE|PROC|RESCUE|START|STOP|UNPIN|VERIFY) (.+)$/;

function lastKernelPhase() {
  const lines = window.jb.logLines || [];
  for (let i = lines.length - 1; i >= 0; i--) {
    const m = KERNEL_STAGE_TAGS.exec(lines[i]);
    if (m) return m[1] + ": " + m[2];
  }
  return "unknown";
}

export async function boot() {
  const rejection = window.firmware.rejection();
  if (rejection) throw new Error(rejection);

  /* The WebKit stage normally lands in seconds, but it retries internally and
   * a slow attempt on real hardware is not unusual, so keep this generous.
   * ?webkitTimeout= lets it be shortened for testing off-console. */
  const override = new URLSearchParams(location.search).get("webkitTimeout");
  const webkitTimeout = override ? Number(override) * 1000 : 300000;
  const payloadTimeout = Number(
    new URLSearchParams(location.search).get("payloadTimeout") || 300,
  ) * 1000;
  /* The kernel stage walks every armed AIO group and clears it, and each step
   * is a kernel round trip through the ROP primitive. It has no bound of its
   * own, so on a bad run it can sit on "checking aio groups" indefinitely and
   * the page never reaches a verdict, which is what left the console unable to
   * finish a reboot. Bound the stage from out here; relapse_exploit.js is left
   * alone. The phase is read back from the log so a timeout says where it got
   * stuck rather than just failing.
   * ?kernelTimeout=N overrides it in seconds. A successful run sat on
   * "checking aio groups" for minutes, so the default is well past that; the
   * bound is for runs that never come back at all. */
  const kernelTimeout = Number(
    new URLSearchParams(location.search).get("kernelTimeout") || 600,
  ) * 1000;

  window.writeLog("Agent: " + navigator.userAgent, "info");
  window.writeLog("Firmware: " + window.fw_str, "info");

  await waitForOffsets();
  window.jb.mark("Offsets", window.fw_str + " loaded");

  const primitive = await getPrimitive(webkitTimeout);
  window.writeLog("ARW ready", "success");
  window.jb.mark("WebKit", "base 0x" + getWebKitBase().toString(16));

  /* main() runs prepareRop and then the kernel exploit, which ends by handing
   * off to kexp so elfldr comes up on 9021. The payload list is NOT driven by
   * an R2 press: the manifest decides what loads and in what order, so the load
   * is driven from here against the same ROP handles main.js publishes.
   *
   * The wait is armed BEFORE main() so the first payload line cannot be missed. */
  await withDeadline(main(primitive), kernelTimeout, "the kernel stage", () => {
    const phase = lastKernelPhase();
    return phase === "unknown" ? null : phase;
  });

  if (!window.jb.chain || !window.jb.p)
    throw new Error("the kernel stage did not publish its ROP handles");

  /* No elfldr means nothing can receive the plugins. main() logs that case and
   * records it here, so stop rather than stream payloads at a closed port and
   * report it as a plugin failure. */
  if (!window.jb.elfldr) {
    window.jb.payloadsDone = true;
    window.jb.mark("Autoload", "elfldr never confirmed up on port 9021");
    throw new Error(
      "the kernel stage finished but elfldr is not listening on port 9021, " +
        "so there is nowhere to send the plugins",
    );
  }

  await loadPayloads(window.jb.p, window.jb.chain, payloadTimeout);
  return waitForPayloads(payloadTimeout);
}
