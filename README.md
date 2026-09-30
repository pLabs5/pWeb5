# ps5-jailbreak-store

A PS5 WebKit autoloader served straight to the console's own browser engine. It
runs the exploit chain in-page, reports progress as it happens, and pushes the
jailbreak payloads to the console's elfldr.

The page is a single static site with no build step and no dependencies. It is
designed to be hosted on Cloudflare Pages and opened by hijacking the Jailbreak
Store tile's deeplink, so the page runs inside the PS5 WebKit sandbox.

## interface

- **stages** - the four chain steps (webkit probe, spray, kernel, elfldr/autoload)
- **session** - detected firmware, WebView viewport, elfldr port
- **payload queue** - the payloads resolved from the manifest, and their state
- **log** - full timestamped run log

Sections collapse and expand on their own as the run progresses: the queue stays
closed until the manifest resolves, the session panel stays closed until there is
a real value to show, and nothing is collapsed when the run finishes so the
finished state stays readable. Every header can be clicked to override the
automatic behaviour.

Query flags:

| flag | effect |
|------|--------|
| `?fw=13.20` | pretend the console reports that firmware |
| `?fail=1` | force the WebKit-failure path instead of running the chain |
| `?real=1` | load `src/main.js` and drive it for real instead of simulating |
| `?measure=1` | show the WebView viewport report |

## manifests

Payloads are resolved in this order:

1. a local `/data/autoldr` manifest on the console
2. `manifest.txt` fetched from the site
3. a firmware-based built-in default

`manifest.txt` is a comma-separated list of `name=url` pairs, sent in order. The
default entries pick `kstuff-lite` for firmware newer than `10.01`, and full
`kstuff` below that.

## development

```bash
python3 tools/serve.py                 # http://127.0.0.1:8002
python3 tools/func_test.py run         # success path, headless chromium
python3 tools/func_test.py fail        # failure path
python3 tools/layout_probe.py          # layout metrics at several viewports
```

`func_test.py` and `layout_probe.py` drive headless chromium. Both poll for a
terminal state instead of sleeping a fixed amount, because Chromium's virtual
time pauses during the real `manifest.txt` fetch and pushes the payload timers
past any guessed timeout.

`?real=1` and the real Relapse chain are not wired up yet; the default run is a
simulation, and the progress/log/UI layers are the parts that are finished.
