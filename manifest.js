/* Manifest resolution for the Jailbreak Store autoloader.
 *
 * Two sources, in priority order:
 *   1. Local  : /data/autoldr  — plain text, one "name=url" per line.
 *               Read after the kernel stage, when syscalls are available.
 *   2. Remote : manifest.txt at the site origin — same format. Used when the
 *               local file is missing or unreadable.
 *   3. Built-in default, chosen by firmware.
 *
 * Format is deliberately boring so a typo degrades to the default rather than
 * breaking the run. Blank lines and lines starting with # are ignored.
 *
 *   # name=url
 *   kstuff-lite.elf=payloads/kstuff-lite-1.11.elf
 *   etahen.elf=payloads/etaHEN.elf
 *
 * A bare "name" with no "=" also works and is resolved to payloads/<name>.
 */

/* Firmware at or below this gets full kstuff, which still supports them.
   Above it, only kstuff-lite runs, because full kstuff's offsets stop at 10.01.
   Keep this in sync with the README if that ceiling ever moves. */
var FULL_KSTUFF_MAX_FW = "10.01";

/* Ordered because they are sent in sequence: kstuff patches the kernel and
   remounts, etaHEN needs the result of that to come up. */
var DEFAULT_LITE = ["kstuff-lite.elf", "etahen.elf"];
var DEFAULT_FULL = ["kstuff.elf", "etahen.elf"];

function compareFw(a, b) {
  var pa = String(a).split("."), pb = String(b).split(".");
  for (var i = 0; i < 2; i++) {
    var na = parseInt(pa[i], 10), nb = parseInt(pb[i], 10);
    if (isNaN(na)) na = 0;
    if (isNaN(nb)) nb = 0;
    if (na !== nb) return na < nb ? -1 : 1;
  }
  return 0;
}

function useFullKstuff(fw) {
  if (!fw) return false;
  return compareFw(fw, FULL_KSTUFF_MAX_FW) <= 0;
}

function defaultPayloads(fw) {
  return useFullKstuff(fw) ? DEFAULT_FULL.slice() : DEFAULT_LITE.slice();
}

function resolveUrl(name, url, base) {
  if (/^https?:\/\//i.test(url)) return url;
  if (url.charAt(0) === "/") return (base || "") + url;
  return (base || "") + "payloads/" + url;
}

/* Parse manifest text. Returns an array of {name, url, label}. */
function parseManifest(text, base) {
  var out = [];
  if (!text) return out;
  var lines = String(text).split(/\r?\n/);
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim();
    if (!line || line.charAt(0) === "#") continue;

    var name, url;
    var eq = line.indexOf("=");
    if (eq === -1) {
      name = line;
      url = line;
    } else {
      name = line.slice(0, eq).trim();
      url = line.slice(eq + 1).trim();
    }
    if (!name) continue;
    if (!url) url = name;

    out.push({ name: name, url: resolveUrl(name, url, base), label: name });
  }
  return out;
}

/* Strip a manifest down to something we can hand to the autoloader.
   The chain only needs a list of files to fetch relative to itself, so keep
   both the bare name and the resolved absolute URL. */
function toAutoloadList(entries, origin) {
  return entries.map(function (e) {
    return { name: e.name, url: e.url, label: e.label, relative: e.url };
  });
}

/* Read a file from the PS5 filesystem. Only callable after the kernel stage:
   before that the page is an ordinary web page with no filesystem access.
   `chain.syscall(op, ...args)` is the ROP syscall interface. */
function readPs5File(chain, path, maxLen) {
  var SYS_OPEN = 0x005, SYS_READ = 0x003, SYS_CLOSE = 0x006;
  var O_RDONLY = 0x0000;

  var fd = chain.syscallSync(SYS_OPEN, path, O_RDONLY, 0);
  if (fd === null || fd === undefined) return null;
  if (fd.low !== undefined) {
    if (fd.low < 0) return null;      // negative errno: file is not there
    fd = fd.low;
  }
  if (fd < 0) return null;

  var p = chain.p;
  var buf = p.malloc(maxLen || 8192, 1);
  var got = chain.syscallSync(SYS_READ, fd, buf, maxLen || 8192);
  if (got === null || got === undefined) return null;
  if (got.low !== undefined) got = got.low;
  if (got <= 0) return null;

  chain.syscallSync(SYS_CLOSE, fd);

  /* Copy out of the primitive's memory into a JS string. */
  var bytes = new Uint8Array(got);
  for (var i = 0; i < got; i++) bytes[i] = p.read8(buf.add32(i)) & 0xff;
  return decodeUtf8(bytes.subarray(0, got));
}

function decodeUtf8(bytes) {
  if (typeof TextDecoder !== "undefined") return new TextDecoder("utf-8").decode(bytes);
  var s = "";
  for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return s;
}

/* Fetch the remote manifest. Same-origin by default so no CORS surprises. */
function fetchRemoteManifest(url) {
  return fetch(url || "manifest.txt", { cache: "no-store" })
    .then(function (r) { return r.ok ? r.text() : null; })
    .catch(function () { return null; });
}

/* Decide the payload list. Call after the kernel stage.
   fw:  detected firmware string, e.g. "13.20"
   chain:  {p, syscallSync} once the exploit has run
   origin: absolute origin of the site, for resolving relative URLs
   Returns {entries, source, reason}. */
function resolveManifest(opts) {
  opts = opts || {};
  var fw = opts.fw || "";
  var origin = opts.origin || "";
  var fallback = defaultPayloads(fw);
  var def = { entries: fallback.map(function (n) {
      return { name: n, url: resolveUrl(n, n, origin), label: n };
    }), source: "default", reason: null };

  /* Local file wins if present. */
  if (opts.chain) {
    var text = null;
    try {
      text = readPs5File(opts.chain, "/data/autoldr", 8192);
    } catch (e) {
      text = null;                       // no syscalls, or open failed
    }
    if (text) {
      var local = parseManifest(text, origin);
      if (local.length) return { entries: local, source: "local", reason: "/data/autoldr" };
      def.reason = "local file empty, using default";
    } else {
      def.reason = "no /data/autoldr";
    }
  }

  /* Then the network copy. */
  if (opts.remote !== false && typeof fetch === "function") {
    return fetchRemoteManifest(opts.manifestUrl)
      .then(function (text) {
        if (text) {
          var remote = parseManifest(text, origin);
          if (remote.length) return { entries: remote, source: "remote", reason: opts.manifestUrl || "manifest.txt" };
          def.reason = "remote manifest empty, using default";
        }
        return def;
      })
      .catch(function () { return def; });
  }

  return Promise.resolve(def);
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    compareFw: compareFw,
    useFullKstuff: useFullKstuff,
    defaultPayloads: defaultPayloads,
    parseManifest: parseManifest,
    resolveManifest: resolveManifest,
    FULL_KSTUFF_MAX_FW: FULL_KSTUFF_MAX_FW
  };
}
