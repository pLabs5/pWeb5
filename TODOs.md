# TODOs

## Goal: make the autoloader properly offline

Today the console still needs working DNS and a reachable site for the one
payload it cannot do without. The page loads from a hostname, the manifest is
fetched from the site origin, and the firmware-to-kstuff pick is hardcoded to a
site-relative `payloads/...` URL — including in local-manifest mode, where it is
the only entry we force on top of the console owner's list. Both picks are in
`src/boot.js`: the build table at `KSTUFF` (`src/boot.js:417`) and the force-on-top
at `src/boot.js:464`.

Which file that resolves to depends on firmware: full `payloads/kstuff.elf` up to
and including 10.01, `payloads/kstuff-lite-1.11B.elf` above that
(`src/boot.js:435`).

So an offline console is a manual fixup today, not a supported state. You can
get there by naming the payload yourself:

```
kstuff.elf=local:/data/autoldr/kstuff.elf
```

but that requires the owner to know which build their firmware needs and to
place the right file at the right path by hand. The loader already knows the
firmware-to-build mapping. It should be the one deciding.

What "offline" has to mean, in order:

1. **The site is reachable by IP, not by name.** `fetch("manifest.txt")` and
   the `payloads/...` URLs are all origin-relative, and `tools/serve.py` already
   binds `0.0.0.0`, so self-hosting over the LAN works with no DNS at all. The
   console only resolves names because the default deployment is Cloudflare.
   Decide: LAN-only self-host, keep the public one as a convenience, or both.

2. **The kstuff pick comes off the console's own disk by default.** Read it
   from `/data/autoldr/` when it is there, and only fall back to the site copy
   when it is not. A local manifest that names kstuff still overrides both.
   Until this lands, no amount of local: entries in the manifest makes the run
   offline, because the forced entry is still a network fetch.

3. **The manifest resolves without the network.** The local file already
   replaces the site one, and is read first. This is mostly done — it needs a
   real console to confirm the read path, which is untested.

4. **Nothing in the default list needs a name to resolve.** Every entry in
   `manifest.txt` is site-relative. Once (1) and (2) are done, the whole chain
   from page load to payloads is IP-and-disk only.

### Later, not required for offline

- **nanoDNS, for keeping the console off PlayStation's servers.** A DNS proxy
  payload (`drakmor/nanoDNS`, config at `/data/nanodns/nanodns.ini`) that
  overrides domains from a config file instead of editing `/etc/hosts`, which
  lives on the read-only system image. Note the chicken-and-egg: it can only be
  sent once elfldr is already listening on 9021, and switching the console's
  primary DNS to `127.0.0.1` with nothing bound there kills all name
  resolution, including the site itself. It is independent of items 1-4, so it
  does not gate offline loading.
- **Serve remote payloads over LAN without CORS games.** Point a domain at your
  own box and serve with `ACAO: *`, or just use `local:` and skip the problem.
- **Self-update from the console's own disk**, so a new build replaces the old
  one without a browser round-trip.

### Not done, and not claimed

Nothing in this file has been tested on a PS5. The local read path, the
firmware-to-kstuff mapping, and the whole `local:` path are verified only
against a fake syscall chain.
