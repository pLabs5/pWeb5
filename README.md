# ps5-jailbreak-store

A PS5 WebKit autoloader. It runs the Relapse exploit chain inside the console's
own browser engine, reports progress as the chain runs, and pushes the jailbreak
payloads to the console's elfldr.

Live at **https://ps5-jailbreak-store.foxinwntr.workers.dev**

## starting a run

Nothing happens on load. Press **JAILBREAK** and the button removes itself —
the WebKit stage sprays the moment it starts and there is no undo.

## firmware detection

The site reads the firmware from the user agent and loads the matching
offsets. If yours does not parse — some consoles report a different format —
append the version by hand:

```
https://ps5-jailbreak-store.foxinwntr.workers.dev/?fw=13.20
```

A version that has no offsets file fails with a message naming the version it
wanted, rather than refusing to start.

## stages

| # | stage | what it covers |
|---|-------|----------------|
| 1 | webkit | the ARW primitive |
| 2 | rop worker | worker stack discovery and the ROP chain |
| 3 | kernel | kernel rw, process, pipes, privileges |
| 4 | elfldr | kexp loads, elfldr listens on :9021 |
| 5 | autoload | the payload chain, sent to elfldr in order |

## payloads

`src/kexp.js` sends these, in this order, to `127.0.0.1:9021`:

| fetched as | actually is |
|---|---|
| `kstuff.elf` | kstuff-lite 1.11B |
| `shadowmountplus.elf` | shadowmountplus |
| `etaHEN.elf` | the Oct 1 etaHEN build |

### etaHEN expires on 1 October

`payloads/etaHEN-Oct1.elf` stops working on 1 October. The send still succeeds
afterwards, so it looks like a successful run followed by nothing happening.
Pull the new build from the etaHEN Discord and replace the file.

### shadowmountplus can block etaHEN

Worth knowing before you rely on a run. `loadOptionalPayloads` fetches and maps
all three payloads before sending any of them, and has no error handling. So:

- if `shadowmountplus.elf` fails to download, **kstuff never loads either**
- it is sent between kstuff and etaHEN, so if it fails to send, **etaHEN is
  never sent** — and the run still reports success

It is also unlikely to work on 13.20 with kstuff-lite, since it wants full
kstuff. This is the one payload whose behaviour on console is unverified.

## the PS Store installer

After a successful run the verdict screen offers to send
`JailbreakStore.elf` to elfldr. That renames the `NPXS40047` tile to *Jailbreak
Store* and repoints it at this site, so tapping it starts the exploit. Optional,
and only offered on a successful run. A PS5 reboot is needed afterwards.

It writes a deeplink pointer and the title/icon names. It deletes nothing and
the app content is untouched, so removing the `DEEPLINK_URI` row puts the real
store back.

The button is a plain `no-cors` POST to `127.0.0.1:9021` rather than the syscall
socket the exploit payloads use, because the chain's handles live inside the ROP
web worker and are not reachable from page script. That works in a normal
browser, but the loopback mixed-content exemption is **not confirmed on the
PS5's WebView**. If the button reports a failure, send the ELF from a PC:

```bash
python3 tools/send_elf.py payloads/JailbreakStore.elf <ps5-ip> 9021
```

## known issues

- **The webkit stage can hang.** Upstream `webkit.js` has no reject path and no
  cap on its retries, so a WebKit exploit that never lands leaves the run
  pending forever. The site bounds it from the outside and fails the run instead
  of hanging silently.
- **The kernel stage can hang.** `defuseAioGroups()` walks every armed AIO group
  and clears it, and each group costs a lookup, two reads, and up to three
  write-and-verify attempts through the ROP primitive. It has no bound of its
  own, so a run that goes wrong can sit on `Kernel: checking aio groups` with the
  page never reaching a verdict, which leaves the console unable to finish
  rebooting. The site bounds the stage and reports the phase it stalled in.
- **Offsets are per-firmware.** `offsets/` is stock Relapse `09f10f5` and must
  stay; a version with no offset file cannot run.
- Everything under `src/` is stock Relapse `09f10f5` except `main.js`, which
  publishes the ROP handles and `boot.js`, which owns the manifest and timeouts.
  `relapse_exploit.js`, `webkit.js`, `rop.js`, and `kexp.js` are byte-for-byte
  against the tag `vendor/relapse-09f10f5`. An earlier one-line fix to an
  `aio_multiwait` timeout was reverted: upstream waits 10ms via `tv_usec`, and
  writing the value as `tv_sec` instead turned a rare 2.8h stall into a stall on
  the normal path.
- The payload list and spacing come from `manifest.txt`; `src/kexp.js`'s own
  hardcoded list is unused.

## query flags

| flag | effect |
|------|--------|
| `?fw=13.20` | force the firmware version |
| `?auto=1` | skip the start gate |
| `?measure=1` | show the WebView viewport report |
| `?webkitTimeout=N` | fail the webkit stage after N seconds (default 300) |
| `?kernelTimeout=N` | fail the kernel stage after N seconds (default 240) |
| `?payloadTimeout=N` | fail the payload stage after N seconds (default 120) |
| `?payloadDelay=N` | seconds between payloads from the manifest (default 5) |

## running and deploying

```bash
python3 tools/serve.py     # http://127.0.0.1:8002
./tools/build.sh           # assemble dist/
wrangler deploy            # publish dist/
```

To exercise the real chain off console, spoof the user agent — the site only
offers the run on something that looks like a PS5:

```bash
chromium --headless --no-sandbox \
  --user-agent="Mozilla/5.0 (PlayStation 5/13.20) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15" \
  --virtual-time-budget=20000 --dump-dom \
  'http://127.0.0.1:8002/?auto=1&webkitTimeout=6'
# force the kernel deadline to a short value to see the timeout path
  'http://127.0.0.1:8002/?auto=1&webkitTimeout=300&kernelTimeout=3'
```

The chain then genuinely runs and fails in the WebKit stage, which is enough to
prove the wiring, the offsets load and the failure path.
