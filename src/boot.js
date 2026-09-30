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
function withDeadline(promise, ms, what) {
  let timer;
  return Promise.race([
    promise.finally(() => clearTimeout(timer)),
    new Promise((_, reject) => {
      timer = setTimeout(
        () => reject(new Error(what + " did not complete in " + Math.round(ms / 1000) + "s")),
        ms,
      );
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
  READ: 0x003,
  WRITE: 0x004,
  OPEN: 0x005,
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
const LOCAL_ROOT = "/data/autoldr";

/* A path has to exist as a NUL-terminated string in ROP memory before it can
 * be handed to the kernel, and the primitive only writes 1-8 bytes at a time. */
function writeCString(p, address, text) {
  for (let i = 0; i < text.length; i++) p.write1(address.add32(i), text.charCodeAt(i) & 0xff);
  p.write1(address.add32(text.length), 0);
  return address;
}

function low(result) {
  if (result === null || result === undefined) return -1;
  return typeof result === "object" && result.low !== undefined ? result.low | 0 : result | 0;
}

/* Map a file that is already on the console. Same {base, size} shape the
 * sender wants, so local and remote payloads are interchangeable. */
async function mapElfFromDisk(path, p, chain) {
  const pathAddr = writeCString(p, p.malloc(path.length + 1, 1), path);

  const fd = low(await chain.syscall(FS.OPEN, pathAddr, O_RDONLY, 0));
  if (fd < 0) throw new Error("cannot open " + path + " on the console");

  try {
    /* Read to EOF in chunks straight into one mapping. Reserving a fixed
     * ceiling keeps this to a single mmap; nothing is copied into JS. */
    const capacity = 0x1000000; // 16 MiB ceiling per payload
    const base = await chain.syscall(FS.MMAP, 0, capacity, PROT_RW, MAP_PRIVATE_ANON, -1, 0);
    if (low(base) <= 0x10000) throw new Error("mmap failed for " + path);

    let total = 0;
    for (;;) {
      const want = Math.min(CHUNK, capacity - total);
      if (want <= 0) break;
      const got = low(await chain.syscall(FS.READ, fd, base.add32(total), want));
      if (got <= 0) break;
      total += got;
    }
    if (total < 0x1000) throw new Error(path + " is too small to be an ELF");
    if (p.read4(base) >>> 0 !== 0x464c457f) throw new Error(path + " is not an ELF");
    return { base: base, size: total };
  } finally {
    await chain.syscall(FS.CLOSE, fd);
  }
}

/* The network path, matching kexp's mapElf. */
async function mapElfFromUrl(url, p, chain) {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) throw new Error(url + " returned HTTP " + response.status);
  const elf = new Uint8Array(await response.arrayBuffer());
  if (elf.length < 0x1000) throw new Error(url + " is too small to be an ELF");

  const size = (elf.length + 0x3fff) & ~0x3fff;
  const mapped = await chain.syscall(FS.MMAP, 0, size, PROT_RW, MAP_PRIVATE_ANON, -1, 0);
  if (low(mapped) <= 0x10000) throw new Error("mmap failed for " + url);

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
    const fd = low(await chain.syscall(FS.SOCKET, 2, 1, 0));
    if (fd >= 0) {
      if (low(await chain.syscall(FS.CONNECT, fd, address, 16)) === 0) return fd;
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
      const written = low(await chain.syscall(FS.WRITE, fd, payload.base.add32(offset), length));
      if (written <= 0) throw new Error(name + " socket write failed");
      offset += written;
    }
  } finally {
    await chain.syscall(FS.CLOSE, fd);
  }
}

/* Read the console-side manifest. Only meaningful after the kernel stage,
 * because before it the page has no filesystem access at all. */
async function readLocalManifest(p, chain) {
  const candidates = [LOCAL_ROOT + "/manifest.txt", LOCAL_ROOT];
  for (const path of candidates) {
    try {
      const payload = await mapElfFromDisk(path, p, chain);
      let text = "";
      for (let i = 0; i < payload.size; i++) text += String.fromCharCode(p.read8(payload.base.add32(i)) & 0xff);
      if (text.trim()) return text;
    } catch (e) {
      /* not there, or unreadable: fall through to the next candidate */
    }
  }
  return null;
}

function parseManifest(text) {
  const entries = [];
  for (const raw of String(text).split("\n")) {
    /* Strip a trailing comment as well as whole-line ones: a target left with
     * " # ..." appended would be opened as a literal path and simply fail. */
    const line = raw.replace(/#.*$/, "").trim();
    if (!line) continue;
    const eq = line.indexOf("=");
    if (eq < 0) entries.push({ name: line, url: "payloads/" + line, local: false });
    else {
      const name = line.slice(0, eq).trim();
      const target = line.slice(eq + 1).trim();
      entries.push({
        name: name,
        url: target,
        local: target.startsWith("/"),
      });
    }
  }
  return entries;
}

/* Resolution order: the console's own manifest, then the one served by the
 * site, then the built-in default. A target beginning with "/" is a path on
 * the console; anything else is fetched from the site. */
async function resolveEntries(p, chain) {
  if (p && chain) {
    const local = await readLocalManifest(p, chain);
    const parsed = local ? parseManifest(local) : [];
    if (parsed.length) {
      window.writeLog("manifest: " + LOCAL_ROOT + "/manifest.txt", "info");
      return parsed;
    }
  }
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
  return [
    { name: "kstuff.elf", url: "payloads/kstuff.elf", local: false },
    { name: "shadowmountplus.elf", url: "payloads/shadowmountplus.elf", local: false },
    { name: "etaHEN.elf", url: "payloads/etaHEN.elf", local: false },
  ];
}

/* Send every entry in manifest order, waiting between them. etaHEN starts its
 * FTP server the moment it lands and shadowmountplus remounts /system_ex, so
 * the two must not be in flight at the same time - that combination is what
 * panicked the console. ?payloadDelay=N overrides the gap in seconds. */
async function loadPayloads(p, chain) {
  const entries = await resolveEntries(p, chain);
  const query = new URLSearchParams(location.search);
  const delay = Number(query.get("payloadDelay") || 5) * 1000;

  window.writeLog("loading " + entries.length + " payload(s) from the manifest", "info");
  window.jb.payloadEntries = entries;

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    const source = entry.local ? entry.url : "payloads/" + entry.url.replace(/^payloads\//, "");
    const payload = entry.local
      ? await mapElfFromDisk(source, p, chain)
      : await mapElfFromUrl(source, p, chain);
    await sendMapped(entry.name, payload, p, chain);
    window.jb.mark("payload", entry.name + " sent");
    window.writeLog(entry.name + " sent", "success");
    if (i < entries.length - 1 && delay > 0)
      await new Promise((resolve) => setTimeout(resolve, delay));
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

  await main(primitive);

  if (!window.jb.chain || !window.jb.p)
    throw new Error("the kernel stage did not publish its ROP handles");

  await loadPayloads(window.jb.p, window.jb.chain);
  return payloads;
}
