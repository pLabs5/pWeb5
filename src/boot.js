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
 * The only thing that differs from upstream is the payload step. Relapse waits
 * for an R2 keypress, which cannot happen inside the PS5 WebView, so the
 * payload chain would never run. Rather than edit main.js we synthesise the
 * exact event it listens for.
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

/* main.js registers this listener after the kernel stage succeeds:
 *
 *   function onKey(event) {
 *     if (event.key !== "F8" || event.code !== "Unidentified") return;
 *     window.removeEventListener("keydown", onKey, true);
 *     onPress();
 *   }
 *
 * F8 / "Unidentified" is what the DualSense R2 pad reports through the WebKit
 * key handler. There is no key handler in the WebView, so dispatch the same
 * event ourselves and the unmodified listener runs the payload chain. */
export function pressR2() {
  const event = new KeyboardEvent("keydown", {
    key: "F8",
    code: "Unidentified",
    bubbles: true,
    cancelable: true,
  });
  return window.dispatchEvent(event);
}

/* Resolves once the payload chain has finished, by watching the log lines the
 * unmodified kexp.js emits. Returns a timeout error rather than hanging if the
 * chain never reports back. */
function waitForPayloads(timeoutMs) {
  return new Promise((resolve, reject) => {
    const done = (ok, why) => {
      window.jb.payloadsDone = true;
      clearInterval(timer);
      ok ? resolve() : reject(new Error(why));
    };

    const timer = setInterval(() => {
      const lines = window.jb.logLines || [];
      if (lines.some((l) => /etaHEN\.elf sent/.test(l))) done(true);
      else if (lines.some((l) => /elfldr is not listening/.test(l)))
        done(false, "elfldr is not listening on port 9021");
    }, 100);

    setTimeout(
      () => done(false, "payload chain did not finish in time"),
      timeoutMs,
    );
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
   * listener. It resolves before any payload is sent, so the wait for payloads
   * is armed before main() to avoid missing the first log line. */
  const payloads = waitForPayloads(payloadTimeout).catch((e) => {
    window.jb.mark("Autoload", e.message);
    return e;
  });

  await main(primitive);

  pressR2();
  return payloads;
}
