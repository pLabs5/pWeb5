/* Devtools harness for the Jailbreak Store — run the full log flow in a
 * desktop browser without a PS5, through the exact same bridge the chain
 * reports through (window.writeLog / window.jb). Paste into the DevTools
 * console on the live page:
 *
 *   __jbTest.desktop()          full run, paced like the console (100ms/line)
 *   __jbTest.desktop(0)         instant burst, no pacing
 *   __jbTest.inspect()          dump every DOM line's class + text
 *   __jbTest.levels()           one message per level class
 *
 * Everything goes through window.writeLog, so the markers, the level
 * classes on the .line elements, the whitespace sanitizer, the "payloads
 * loaded" display rewrite and the copy-log output are all the real thing.
 */
(function () {
  "use strict";
  var sleep = function (ms) { return new Promise(function (res) { setTimeout(res, ms); }); };
  var wasWhy = function (msg, type) { window.writeLog(msg, type); };

  /* The payload-loading sequence mirrors boot.js: fetch, sent, accepted,
   * then boot.js's watcher emits "waiting Ns before the next payload". */
  async function payloadQueue(stepMs) {
    var w = function (m, t) { wasWhy(m, t); return sleep(stepMs); };
    await w("[1/3] fetching kstuff-lite.elf", "info");
    await w("payload: kstuff-lite.elf sent", "info");
    await w("kstuff-lite.elf -> elfldr :9021 accepted", "info");
    await w("waiting 5s before the next payload", "info");
    await w("[2/3] fetching etahen.elf", "info");
    await w("payload: etahen.elf sent", "info");
    await w("etahen.elf -> elfldr :9021 accepted", "info");
    await w("waiting 5s before the next payload", "info");
    await w("[3/3] fetching shadowmountplus.elf", "info");
    await w("payload: shadowmountplus.elf sent", "info");
    await w("shadowmountplus.elf -> elfldr :9021 accepted", "info");
  }

  /* The kernel block uses the exact strings/level kinds the vendored exploit
   * emits. Bare reports default to writeLog's whitelist -> info ('+' marker);
   * aio/ucred pass explicit "info"; writeLog also rewrites the display text
   * of "payloads loaded". A naked "log" type is included so the width of the
   * + / * mapping can be seen side by side. */
  async function kernelBlock(stepMs) {
    var w = function (m) { wasWhy(m); return sleep(stepMs); };
    window.jb.mark("Worker chain", "ready"); await sleep(stepMs);
    wasWhy("stage 2/5 rop worker ok -- ready", "info"); await sleep(stepMs);
    await w("Kernel: Starting kernel exploit");
    await w("Kernel: base 0x8004000000");
    await w("Kernel: read and write ready");
    window.writeLog("aio_info_addr: 0x8023433410", "info"); await sleep(stepMs);
    window.writeLog("ucred_addr: 0x802270b100", "info"); await sleep(stepMs);
    await w("Kernel: fast read and write ready");
    await w("Kernel: checking aio groups");
    await w("Kernel: checking privileges");
    await w("Kernel: privileges ready");
    await w("kexp: elfldr returned 0x0");
    /* the message source logs this; the UI should render the honest rewrite */
    await w("Kernel: payloads loaded");
  }

  var result = {
    desktop: async function (stepMs) {
      stepMs = stepMs == null ? 100 : stepMs;
      if (window.jb && window.jb.logLines && window.jb.logLines.length) {
        window.writeLog("injected __jbTest", "sys");
      }
      await kernelBlock(stepMs);
      await payloadQueue(stepMs);
      window.writeLog("run complete", "success");
      window.writeLog("__jbTest done", "sys");
    },
    /* dump the DOM's actual line classes + text, so spacing/markers can be
       verified against what the CSS applies, not just what is printed */
    inspect: function () {
      var box = document.getElementById("log");
      return [].slice.call(box ? box.children : []).map(function (n, i) {
        return i + ": [" + n.className + "] " + n.textContent;
      }).join("\n");
    },
    levels: function () {
      ["info", "success", "warning", "error", "sys", "log", "mystery"].forEach(function (lvl) {
        window.writeLog("level \"" + lvl + "\"", lvl);
      });
      window.writeLog("end of levels", "sys");
    },
  };
  window.__jbTest = result;
  if (window.console) console.log("__jbTest installed: desktop() / inspect() / levels()");
})();