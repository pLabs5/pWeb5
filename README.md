# ps5-jailbreak-store

A PS5 WebKit autoloader. It runs the Relapse exploit chain inside the console's
own browser engine, reports progress as the chain runs, and pushes the
jailbreak payloads to the console's elfldr.

The page is a single static site with no build step and no dependencies, meant
to be hosted on Cloudflare Pages and opened by hijacking the Jailbreak Store
tile's deeplink so it runs inside the PS5 WebKit sandbox.

## how the chain is wired

Everything under `src/` is the upstream Relapse `09f10f5` code. It is not
rewritten, wrapped or shimmed. The only local addition is `src/boot.js`, which
takes the place of Relapse's own `src/site.js` and is the only thing that
decides how the chain is called.

Upstream already separates the chain from its presentation: the exploit files
report through two globals that `site.js` defines, and never touch the DOM.
Those globals are defined by `app.js` instead, which turns their output into
the stage list, the progress bar and the log:

| global | defined in | used by |
|--------|-----------|---------|
| `window.writeLog(message, type)` | `app.js` | every file under `src/` |
| `window.jb.mark(tag, detail)` | `app.js` | `webkit.js`, `main.js`, `boot.js` |

So the chain is unaware the UI exists, which is why replacing the presentation
did not require touching it.

### load order

`index.html` loads the chain in upstream order, and the split between classic
scripts and modules is load-bearing — `main.js`, `rop.js` and `syscalls.js`
all put globals in place for the ES modules that follow:

```html
<script src="src/firmware.js"></script>        <!-- window.fw_str, window.firmware -->
<script src="src/main.js"></script>            <!-- main(); appends offsets/<fw>.js -->
<script src="src/rop.js"></script>             <!-- global rop / worker_rop classes -->
<script src="src/utils/syscalls.js"></script>  <!-- global SYS_* constants -->
<script src="app.js"></script>                 <!-- defines writeLog + window.jb -->
<script type="module" src="src/boot.js"></script>
```

`boot.js` is a module, so it runs after all of the above are in place.

## stages

| # | stage | what it covers |
|---|-------|----------------|
| 1 | webkit | `establishPrimitive` — the ARW primitive |
| 2 | rop worker | worker stack discovery and the ROP chain |
| 3 | kernel | `runKernelExploit` — kernel rw, process, pipes, privileges |
| 4 | elfldr | `launchShellcode` — kexp loads, elfldr listens on :9021 |
| 5 | autoload | the payload chain, sent to elfldr in order |

Stage completion is driven off exact log lines the chain prints, not off its
progress tags, because tag details are free text. An earlier version matched on
tags and marked stage 1 done the moment it saw `Offsets: 13.20 loaded`.

Sections still collapse on their own: the payload queue and session panel stay
closed until there is something real to show, and nothing is collapsed when the
run finishes, so the finished state stays readable.

## payloads

`src/kexp.js` sends these by name, in this order, to `127.0.0.1:9021`:

| name fetched | shipped as |
|---|---|
| `kstuff.elf` | `kstuff-lite 1.11B` bytes |
| `shadowmountplus.elf` | upstream `09f10f5` build |
| `etaHEN.elf` | the Oct 1 etaHEN build |

`kstuff.elf` is the filename the unmodified `kexp.js` fetches, so the
kstuff-lite 1.11B bytes are served under that name. The honest filename is kept
alongside it as `kstuff-lite-1.11B.elf`.

### `manifest.txt` and `manifest.js` are not on the send path

They document the payload plan and the firmware split, and they record the
expiry date, but nothing reads them at runtime: the actual sends come from
`kexp.js`'s own hardcoded list. Making the manifest drive the sends would mean
editing `kexp.js`, which is exactly what this project is avoiding. They are
kept as the record of intent until that decision is made.

### etaHEN expires on 1 October

`payloads/etaHEN-Oct1.elf` stops working on 1 October. When that happens the
send still succeeds, so the failure looks like a successful send followed by
nothing happening. Pull the new build from the etaHEN Discord and replace the
file *and* the `manifest.txt` line with a filename that records the new expiry
date. The filename is the only place that date is recorded.

## local changes to upstream

Exactly one, and it is a real bug:

- `fix: aio_multiwait timeout landed in tv_sec, not tv_usec` — see the commit
  message. `struct timeval` is `{i64 tv_sec; i64 tv_usec}` and both timeval
  buffers in `relapse_exploit.js` are `alloc(16)`, but the value was written at
  offset 0. So `waitTimeoutUs = 10000` asked for a 10000 **second** wait
  instead of 10ms. `aio_multiwait` is the only blocking AIO call in the chain,
  so a reclaim batch whose requests never completed stalled the ROP worker for
  ~2.8h and `main.js` then gave up with *"the rop worker never answered in
  20s"*, leaving the console wedged until a reload.

The pristine import is tagged `vendor/relapse-09f10f5` and was verified
byte-identical to upstream `09f10f5`, so `git diff vendor/relapse-09f10f5`
always shows exactly what was changed locally.

### known upstream hang, contained but not fixed

`webkit.js`'s `establishPrimitive` returns `new Promise((resolve) => ...)`. It
has no reject path, and `retry()` has no attempt cap, so a WebKit exploit that
never lands leaves the promise pending forever — upstream tolerates that because
a human just reloads. Rather than edit `webkit.js`, `boot.js` bounds it from the
outside and fails the run instead.

## development

```bash
python3 tools/serve.py                 # http://127.0.0.1:8002
```

The site refuses to run anywhere that is not a PS5, so the UI cannot be
reviewed by just opening it on a desktop. To exercise the real chain off
console, spoof the user-agent. The chain then genuinely runs and fails in the
WebKit stage, which is enough to prove the wiring, the offsets load and the
failure path:

```bash
chromium --headless --no-sandbox \
  --user-agent="Mozilla/5.0 (PlayStation 5/13.20) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15" \
  --virtual-time-budget=20000 --dump-dom \
  'http://127.0.0.1:8002/?webkitTimeout=6'
```

| flag | effect |
|------|--------|
| `?measure=1` | show the WebView viewport report |
| `?webkitTimeout=N` | fail the WebKit stage after N seconds (default 300) |
| `?payloadTimeout=N` | fail the payload stage after N seconds (default 120) |

`tools/layout_probe.py` still reports layout metrics at several viewports and
does not need a PS5.

## notes

- The PS5 WebView reports its dimensions at runtime via `?measure=1`; the
  layout is fluid and does not hardcode a viewport.
- Deployed to Cloudflare Pages with Rocket Loader and HTML/CSS/JS minification
  disabled, so the exploit code is not rewritten in transit.
