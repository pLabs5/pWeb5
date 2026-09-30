/* Boot for the Jailbreak Store.
 *
 * This replaces Relapse's own src/site.js and is the ONLY place that decides
 * how the exploit chain gets called. Every file under src/ is the upstream
 * 09f10f5 code, unmodified, and does its own reporting through the two globals
 * that upstream site.js also defined:
 *
 *   window.writeLog(message, type)   free-form log line
 *   window.jb.mark(tag, detail)      progress marker
 *
 * Both are wired to the UI by app.js, so the exploit's own output feeds the
 * log and drives the stage list without any of it being aware of the UI.
 *
 * The payload step is where this differs from upstream in substance rather
 * than in mechanism. Relapse waits for an R2 keypress, which cannot happen
 * inside the PS5 WebView, and the list behind that keypress is hardcoded in
 * kexp.js. Here the manifest decides both which payloads load and in what
 * order, and the load runs directly against the ROP handles main.js
 * publishes. See "Payload loading" below.
 */

import { establishPrimitive } from "./webkit.js";
import { installWindowP } from "./utils/mem.js";

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

/* establishPrimitive() returns new Promise((resolve) => {...}) - there is no
 * reject path, and webkit.js's retry() has no attempt cap, so a WebKit exploit
 * that never lands leaves the promise pending forever. The page would sit at
 * 0/5 with the log growing and never reach a verdict. Upstream gets away with
 * that because a human just reloads; here it means a UI that lies about being
 * stuck. Bound it from the outside instead of editing webkit.js. */
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

async function getPrimitive(timeoutMs) {
  const primitive = installWindowP(
    await withDeadline(
      establishPrimitive(window.jb.mark),
      timeoutMs,
      "the WebKit exploit",
    ),
  );
  if (!primitive || typeof primitive.read8 !== "function")
    throw new Error("Memory primitive unavailable");
  return primitive;
}
/* ------------------------------------------------------------------ *
 * Payload loading
 *
 * kexp.js can already send an ELF that is mapped in ROP memory, but its
 * mapElf/sendElf pair is private to that module and loadOptionalPayloads
 * hardcodes the payload list and its ordering. The manifest is what should
 * decide both, so the loading is done here instead, against the handles
 * main.js publishes on window.jb. kexp.js itself is left untouched.
 *
 * A payload is loaded straight into ROP memory and streamed to elfldr from
 * there, so a payload that lives on the console costs the same as one fetched
 * over HTTP: the bytes never pass through the page.
 * ------------------------------------------------------------------ */

const FS = {
  WRITE: 0x004,
  CLOSE: 0x006,
  SOCKET: 0x061,
  CONNECT: 0x062,
  MMAP: 0x1dd,
};
const O_RDONLY = 0x0000;
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

function parseManifest(text) {
  const entries = [];
  for (const raw of String(text).split("\n")) {
    /* Strip a trailing comment as well as whole-line ones: a target left with
     * " # ..." appended would be opened as a literal path and simply fail. */
    const line = raw.replace(/#.*$/, "").trim();
    if (!line) continue;
    const eq = line.indexOf("=");
    if (eq < 0) entries.push({ name: line, url: "payloads/" + line });
    else entries.push({ name: line.slice(0, eq).trim(), url: line.slice(eq + 1).trim() });
  }
  return entries;
}

/* Remote only for now. A console-local manifest was tried and pulled: it
 * needed a 16MB mapping per candidate, twice, before any payload loaded, which
 * was enough to wedge the exploit on console. See the README. */
async function resolveEntries() {
  try {
    const response = await fetch("manifest.txt", { cache: "no-store" });
    if (response.ok) {
      const parsed = parseManifest(await response.text());
      if (parsed.length) {
        window.writeLog("manifest: manifest.txt (site)", "info");
        return parsed;
      }
    }
  } catch (e) {
    /* fall through to the default below */
  }
  /* Must mirror the order in manifest.txt: kstuff first, then etaHEN on its own,
   * then shadowmountplus last. Reordering here reintroduces the panic. */
  window.writeLog("manifest: unavailable, using the built-in fallback", "warning");
  return [
    { name: "kstuff-lite.elf", url: "payloads/kstuff-lite-1.11B.elf" },
    { name: "etahen.elf", url: "payloads/etaHEN-Oct1.elf" },
    { name: "shadowmountplus.elf", url: "payloads/shadowmountplus.elf" },
  ];
}

/* Send every entry in manifest order, waiting between them. etaHEN starts its
 * FTP server the moment it lands and shadowmountplus remounts /system_ex, so
 * the two must not be in flight at the same time - that combination is what
 * panicked the console. ?payloadDelay=N overrides the gap in seconds. */
async function loadPayloads(p, chain) {
  const entries = await resolveEntries();
  const query = new URLSearchParams(location.search);
  const delay = Number(query.get("payloadDelay") || 5) * 1000;

  window.writeLog("loading " + entries.length + " payload(s) from the manifest", "info");
  window.jb.payloadEntries = entries;

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    const source = "payloads/" + entry.url.replace(/^payloads\//, "");
    window.writeLog("[" + (i + 1) + "/" + entries.length + "] fetching " + entry.name, "info");
    const payload = await mapElfFromUrl(source, p, chain);
    window.writeLog("[" + (i + 1) + "/" + entries.length + "] mapped " + entry.name + " (" + payload.size + " bytes)", "info");
    await sendMapped(entry.name, payload, p, chain);
    window.jb.mark("payload", entry.name + " sent");
    window.writeLog(entry.name + " sent", "success");
    if (i < entries.length - 1 && delay > 0) {
      window.writeLog("waiting " + delay / 1000 + "s before the next payload", "info");
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }
  return entries;
}

/* Resolves once the payload chain has finished. The manifest decides what is
 * last, so completion is "the final entry reported", not any fixed name. */
function waitForPayloads(timeoutMs) {
  return new Promise((resolve, reject) => {
    const done = (ok, why) => {
      window.jb.payloadsDone = true;
      clearInterval(timer);
      ok ? resolve() : reject(new Error(why));
    };

    const timer = setInterval(() => {
      const lines = window.jb.logLines || [];
      if (lines.some((l) => /elfldr is not listening/.test(l)))
        done(false, "elfldr is not listening on port 9021");
      else {
        const entries = window.jb.payloadEntries;
        if (entries && entries.length && lines.some((l) => l.indexOf(entries[entries.length - 1].name + " sent") >= 0))
          done(true);
      }
    }, 100);

    setTimeout(() => done(false, "payload chain did not finish in time"), timeoutMs);
  });
}

/* The last "Kernel: ..." line the exploit reported, so a timeout can name the
 * phase it stalled in. */
function lastKernelPhase() {
  const lines = window.jb.logLines || [];
  for (let i = lines.length - 1; i >= 0; i--) {
    const m = /^Kernel: (.+)$/.exec(lines[i]);
    if (m) return m[1];
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

  /* main() runs prepareRop + the kernel exploit and then registers the R2
   * listener, which is what used to hand the payload list to kexp.js. We do
   * not press R2: the manifest decides the payload list and its order, and
   * kexp's copy is hardcoded, so the load is driven from here instead. The
   * wait is armed first so the first payload line is not missed. */
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

  await loadPayloads(window.jb.p, window.jb.chain);
  return payloads;
}
