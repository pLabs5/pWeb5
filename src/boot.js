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
import { installWindowP, pairStatus, memCoreInstance } from "./utils/mem.js";

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
  WRITE: 0x004,
  CLOSE: 0x006,
  SOCKET: 0x061,
  CONNECT: 0x062,
  MMAP: 0x1dd,
};
const PROT_RW = 0x3;
const MAP_PRIVATE_ANON = 0x1002;
const ELFDR_PORT = 9021;
const CHUNK = 0x10000;

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

/* The one payload this page sends. Everything the manifest names is dispatched
 * by it, natively, so closing this page no longer strands the chain. */
const DISPATCHER_URL = "payloads/dispatcher.elf";
const DISPATCHER_NAME = "dispatcher.elf";

/* How many entries the manifest names, plus kstuff if the manifest did not
 * name one - the same rule the dispatcher applies. Best effort: this is for the
 * UI's plugin count, and failing to read the manifest here says nothing about
 * whether the dispatcher can read it on the console. */
async function countPlannedPayloads() {
  try {
    const response = await fetch("manifest.txt", { cache: "no-store" });
    if (!response.ok) return 0;
    let named = 0, kstuff = false;
    for (const raw of String(await response.text()).split("\n")) {
      const line = raw.replace(/#.*$/, "").trim();
      if (!line) continue;
      const eq = line.indexOf("=");
      const name = (eq < 0 ? line : line.slice(0, eq)).trim();
      if (!name) continue;
      named++;
      if (/kstuff/i.test(name)) kstuff = true;
    }
    return named + (kstuff ? 0 : 1);
  } catch (e) {
    return 0;
  }
}

async function loadPayloads(p, chain) {
  const entry = { name: DISPATCHER_NAME, url: DISPATCHER_URL };

  window.writeLog("loading " + DISPATCHER_URL + " - the rest of the chain is dispatched natively", "info");
  /* app.js reads both of these to draw its progress view. The dispatcher owns
   * the per-payload pauses now, so there is one entry and no inter-entry delay. */
  window.jb.payloadEntries = [entry];
  window.jb.nextDelay = 0;
  /* What the dispatcher intends to send, read from manifest.txt here purely so
   * the UI can count it. The dispatcher reads the manifest itself and this page
   * has no say in what actually loads, so a mismatch here is cosmetic - it is
   * the dispatcher's own log that says what it did. */
  window.jb.plannedPayloads = await countPlannedPayloads();

  const payload = await mapElfFromUrl(entry.url, p, chain);
  entry.size = payload.size;
  await sendMapped(entry.name, payload, p, chain);
  window.jb.mark("plugin", entry.name + " sent");
  return [entry];
}

/* Resolves once the dispatcher has been handed to elfldr. That is the last
 * thing this page can observe: it means elfldr took the payload, not that the
 * plugins behind it loaded. Those are reported by the dispatcher itself, in
 * /data/autodr/dispatcher.log on the console. */
function waitForPayloads(timeoutMs) {
  return new Promise((resolve, reject) => {
    const done = (ok, why) => {
      window.jb.payloadsDone = true;
      clearInterval(timer);
      ok ? resolve() : reject(new Error(why));
    };

    const timer = setInterval(() => {
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
          done(true);
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
    new URLSearchParams(location.search).get("payloadTimeout") || 120,
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
  const payloads = waitForPayloads(payloadTimeout).catch((e) => {
    window.jb.mark("Autoload", e.message);
    return e;
  });

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

  await loadPayloads(window.jb.p, window.jb.chain);
  return payloads;
}
