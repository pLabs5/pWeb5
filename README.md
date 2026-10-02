# pWeb5

A PS5 jailbreak autoloader that runs in the console's own browser. It executes
the exploit chain in the page, shows you what it is doing while it does it, and
pushes the homebrew payloads to the console once the chain is up.

Live at **https://pweb5.pages.dev**

The exploit chain is [KAR0218's rework of Relapse](https://github.com/KAR0218/KAR0218.github.io/tree/main/ps5/relapse),
which is built on [Relapse](https://github.com/RedPeaSolutions/Relapse-Exploit)
and verifies each step instead of assuming it worked. Firmware **7.00 through
13.60**.

## running it

Open **https://pweb5.pages.dev** in the console's browser and press
**JAILBREAK**.

Nothing happens on load — the button is there on purpose. The chain sprays
memory the moment it starts and there is no undo, so it waits for a deliberate
click.

You need the console on the internet and a browser pointed at that address.
Nothing is downloaded or unpacked on a PC first; the page fetches the payloads
and streams them to the console itself.

The **JAILBREAK** button only appears to something the site recognises as a
PlayStation 5. Opened on a desktop it just says so, because there is no WebKit
there to exploit and no console to send anything to.

## what happens

Five stages, in order:

| # | stage | what it covers |
|---|-------|----------------|
| 1 | webkit | the ARW primitive |
| 2 | rop worker | worker stack discovery and the ROP chain |
| 3 | kernel | kernel rw, process, pipes, privileges |
| 4 | elfldr | kexp loads, elfldr listens on :9021 |
| 5 | autoload | the plugin chain, sent to elfldr in order |

Each one ticks off as it completes and the log below shows the chain's own
output. At the end you get a verdict — **JAILBROKEN** or **FAILED** — with a
summary: firmware, viewport, which manifest was used, which plugins were sent,
how many bytes moved, and how long it took. **view run** puts the full log back.

If a stage stalls, the page gives up on it rather than sitting there forever, and
says which phase it stalled in.

Stage 4 is a hard gate. elfldr has to actually confirm it is listening on 9021
before any plugin is sent, so a run that got root but no elfldr reports that
plainly instead of streaming payloads at a closed port and calling it a plugin
failure.

### the run checks its own work

This is the part that differs from the original chain. It does not assume a step
worked:

- The WebKit primitive retries its own placement, up to 24 attempts, and says
  which attempt it is on.
- The fake memory cell is promoted into a real read/write pair, and **that
  promotion is verified**. If it fails, its rollback is verified too — and if
  the rollback cannot be confirmed, `window.p` is withdrawn rather than left
  published mis-aimed.
- The kernel stage confirms its own output: arbitrary kernel read is read back,
  your process is found in `allproc`, and root and out-of-sandbox are checked by
  reading your uid and sandbox flag *after* writing them, not assumed from the
  write succeeding.
- The master/victim pipe pair is created and both ends are verified as ours.
- The walk counter is checked to make sure it does not move on its own, and a
  walk that does is stopped instead of being trusted.
- Failed steps are retried rather than carried forward.

A step that cannot be made to work reports `NO-GO` or `STOP` with the reason and
stops the run. You get a failed run with an explanation instead of a run that
reports success on a half-built primitive.

## what you get

The plugin list is not hardcoded in the page — it comes from `manifest.txt`,
which also decides the order:

| plugin | what it is |
|--------|------------|
| kstuff-lite | the kernel payload everything else needs |
| etaHEN | the homebrew installer environment |
| shadowmountplus | remounts `/system_ex`, so more can be written to it |

Which kstuff build loads is your firmware's decision, not yours: full kstuff up
to and including 10.01, kstuff-lite above that.

There is a **5 second gap between plugins**, and it matters. etaHEN starts its
FTP server the moment it lands and shadowmountplus remounts `/system_ex`;
sending them close together panics the console. Each one is fetched, streamed to
elfldr, and confirmed before the next starts.

### etaHEN has stopped working

`payloads/etaHEN.elf` is time-limited and the bundled build **expired on
1 October 2026**.

This does not fail loudly. The send still succeeds, so it looks like a
successful run followed by nothing happening. If etaHEN is what you came for,
you need a newer build dropped into the plugin list — see below.

## using your own plugins

You do not need to edit anything on the site. Put a manifest on the console at:

```
/data/autoldr/manifest.txt
```

and it **replaces** the site's list entirely — your plugins, your order:

```
# /data/autoldr/manifest.txt
ProsperoMgr.elf=local:/data/autoldr/plugins/ProsperoMgr.elf
etahen.elf=payloads/etaHEN.elf
```

Nothing from the site list loads once yours exists, so name anything you still
want. Format is one `name=target` per line; `#` starts a comment and blank lines
are skipped. A bare `name` with no `=` means `payloads/<name>`.

A target is one of three things:

| target | where it comes from |
|--------|---------------------|
| `payloads/<file>` | a file on this site |
| `//host/path` or `https://host/path` | anywhere else, if that host allows it |
| `local:/data/autoldr/<file>` | a file already on the console |

A remote host has to send `Access-Control-Allow-Origin` or the fetch fails and
the run reports which URL would not load. That is why GitHub release assets do
not work as a target but `raw.githubusercontent.com` does. Any other scheme is
rejected and fails the run, rather than being fetched as a path on this site.

`kstuff` is the exception — it always loads first, because it is what makes the
rest work, and you do not have to name it. Name `kstuff.elf` or
`kstuff-lite.elf` yourself and that one is used instead of the firmware pick, so
you can pin a build.

**Be honest about the risk here:** only `/data/autoldr/` is reachable with a
`local:` target, `..` is rejected, and the file has to be on the console before
the run starts. But a console-local manifest and `local:` plugins are new, and
neither has been run on real hardware. The site's own manifest works; treat your
own as untested.

## making the Store tile your launcher

After a successful run the verdict screen offers **APPLY TO PS STORE**. That
sends `JailbreakStore.elf` to elfldr, which renames the PS Store tile
(`NPXS40047`) to *Jailbreak Store* and repoints it at this site — so from then
on you tap the tile instead of finding a URL.

It changes nothing about the app itself and deletes no rows, so you can undo it
by removing the `DEEPLINK_URI` entry from the tile's metadata and putting the
real store back. **A PS5 reboot is needed** either way for the tile to change.

If the button reports a failure, the ELF can be sent from a PC instead:

```bash
python3 tools/send_elf.py payloads/JailbreakStore.elf <ps5-ip> 9021
```

## firmware

The version is read from the browser's user agent. If yours does not parse —
the format varies by region and firmware — set it yourself:

```
https://pweb5.pages.dev/?fw=13.20
```

Offsets only exist for versions the upstream chain shipped, so an unsupported
firmware fails with a message naming the version it wanted rather than just
refusing. Two-digit minors are normalised, so `13.2` and `13.20` are the same.

## query flags

| flag | effect |
|------|--------|
| `?fw=13.20` | set the firmware version by hand |
| `?auto=1` | skip the start button |
| `?measure=1` | show the WebView viewport report |
| `?webkitTimeout=N` | give up on the webkit stage after N seconds (default 300) |
| `?kernelTimeout=N` | give up on the kernel stage after N seconds (default 600) |
| `?payloadTimeout=N` | give up on the plugin stage after N seconds (default 120) |
| `?payloadDelay=N` | seconds between plugins (default 5) |

Lowering a timeout does not make the chain faster, it only makes the page stop
waiting. The defaults are generous on purpose — the kernel stage can legitimately
sit on `checking aio groups` for minutes on a good run.

## if it goes wrong

**The webkit stage hangs.** Placement retries up to 24 times, but the cap is
per attempt, so a run where every attempt times out slowly would still leave the
run pending. The page bounds the whole stage and fails the run instead of hanging
silently. The log tells you which attempt it was on.

**The kernel stage hangs.** It walks every armed AIO group and clears it, one
kernel round trip at a time. On a bad run this used to sit forever and leave the
console unable to finish a reboot. It is bounded now, and the failure names the
phase it got stuck in.

**`offsets/<version>.js never loaded`.** That firmware has no exploit offsets.
Nothing about this site will fix it.

**A plugin fails to load.** The run stops and names the file. Whatever was sent
before it stays sent — plugins are delivered one at a time, in order.

**It only works on a subset of firmware.** Offsets are per-version and cover
7.00–13.60. There is no fallback for a version outside that.

## licence

**GPLv3.** Full text in [`LICENSE`](LICENSE).

pWeb5 is free software: you can use, study, share and modify it. If you
redistribute it, or ship a modified version, you have to pass the same licence on
and make your source available.

The exploit chain under `src/` is KAR0218's rework of Relapse, adapted here (see
the top of [`src/boot.js`](src/boot.js) for exactly what changed). The bundled
plugin binaries under `payloads/` are third-party builds and keep their own
terms — they are redistributed, not relicensed.
