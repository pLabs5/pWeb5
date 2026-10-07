# pWeb5

a ps5 jailbreak autoloader using a webpage
> Live at **https://pweb5.pages.dev**
> firmwares 7.00 through 13.60

The exploit chain is [KAR0218's rework of Relapse](https://github.com/KAR0218/KAR0218.github.io/tree/main/ps5/relapse), which itself is built on [Relapse](https://github.com/ntfargo/Relapse-Exploit) and verifies each step instead of assuming it worked. Firmware ***7.00 through 13.60***.

> [!WARNING]
> This repo/website hosts a kernel exploit meant for Playstation 5 devices. By using this as a kernel exploit you accept the possible damages caused to your device.

> [!NOTE]
> I am not responsible for any damages or consequences directly caused   by this software, including but not limited to console system software corruption, data loss, or anything else arising from its use.

## running it

in order to run it initally, you need your PS5's IP address, then:

```sh
wrkdir=$(mktemp -d)
git clone https://github.com/pLabs5/pWeb5 "$wrkdir"
cd "$wrkdir/pWeb5"
make fakedns PS5iP=<playstationsIP>
```

`make fakedns` compiles `tools/fakedns/fakedns.c` and launches it with `sudo`, because binding to UDP port 53 needs root.

you should see something like this when running:
```
[fakedns] local IP: <computersIP>                    <- the IP you'll set on the PS5
[fakedns] PS5 IP:   <playstationsIP>
[fakedns] manuals.playstation.com -> pweb5.pages.dev (172.66.44.146)
[fakedns] firewall: udp/53 permitted                 <- applied automatically, since we're root
[fakedns] blocked substrings: playstation / sonyentertainmentnetwork / scea
[fakedns] will relay everything else to 8.8.8.8:53
```

what it does with DNS requests from the PS5:

- any name containing `manuals.playstation` is sent to **pweb5.pages.dev**, so the Users Guide opens the exploit
- names mentioning `playstation`, `sonyentertainmentnetwork` or `scea` get **NXDOMAIN**, cutting the console off from PlayStation/Sony services so it can't phone home mid-exploit
<I STOPPED HERE, NEED TO FINISH EDITING AFTER DONE>
- everything else is relayed untouched to `8.8.8.8`, so normal internet still works.

then take your PS5 online and point it at this computer as its DNS resolver, under: `settings -> network -> settings -> set up internet connection`, click the options button, select `advanced options`, and set `DNS server` to the **local IP** fakedns printed.

after confirming the options you will probably get a `could not connect to the internet` error, this is ***GOOD.*** after the error message appears click `ok` and navigate to the PS5 Users Guide.

the page should load, wait 10 seconds and the exploit will start and payloads will be sent. once jailbroken set the DNS server of the PS5 back to your router/automatic so normal online features return. 

## what you get

the main part of the page is sending `dispatcher.elf`, that payload reads either the local manifest at `/data/pLabs5/pWeb5/manifest.txt` or the remote `manifest.txt`. after reading / parsing the manifest it fetches the payload from the correct source, either the `payloads/` folder in the repo, the local `/data/pLabs5/pWeb5/plugins/` folder on the console, or from a website. 
the default manifest,txt loads plugins in the following order:
| plugin | what it is |
|--------|------------|
|kstuff/kstuff-lite| the kernel payload most things need 
|etaHEN | the homebrew enabler
|shadowmountplus | remounts `/system_ex` and manages game dumps

the version of kstuff that gets used is dependant on your FW, not up to you, ill probably change that at some point
there is a roughly 5 second delay between each plugin (a `wait=N` key in the manifest sets its own pause; `wait=0` makes it instant), this is to prevent plugins from interferring with eachother.
`dispatcher.elf` writes everything it does to `/data/pLabs5/pWeb5/dispatcher.log`

### etaHEN has stopped working

the current beta of etaHEN, located in the repo at `payloads/etaHEN.elf` has 'expired' if your consoles date/ time is up-to-date, it won't load properly, but you can get around it expiring by setting a time/date before **october 1st, 2026** 
i am currently waiting for the next beta to drop in the `PKG-Zone` discord, once it does i'll update it, for now, just set your date+time back a month or so

## using your own plugins

pWeb5 supports using your own plugins, to do so, create the manifest at:
```
/data/pLabs5/pWeb5/manifest.txt
```
creating that file causes `dispatcher.elf` to read *your* manifest instead of the sites `manifest.txt`

format / options for manifest.txt (without the leading `<lineNumber>:`)
```
1: # /data/pLabs5/pWeb5/manifest.txt < this is a comment
2: ProsperoMgr.elf=local:/data/pLabs5/pWeb5/plugins/ProsperoMgr.elf
3: etahen.elf=payloads/etaHEN.elf 
```
- line 1: just a comment, isn't read by the dispatcher
- line 2: loads ProsperoMgr.elf from `/data/pLabs5/pWeb5/plugins/` on the console
- line 3: loads etaHEN.elf from: `pweb5.pages.dev/payloads/etaHEN.elf`  

`kstuff` is the **ONLY** exception — it always loads first, because it is what makes the rest work, and you do not have to name it. Name `kstuff.elf` or `kstuff-lite.elf` yourself and that one is used instead of the firmware pick, so you can pin a build.

## making the Store tile your launcher

after a successful run, the verdict screen shows the **APPLY TO PS STORE** button. that sends `payloads/JailbreakStore.elf` to elfldr, which renames the PS Store tile (`NPXS40047`) to *Jailbreak Store*, changes the logo to the old playstation logo, and repoints it at `https://pweb5.pages.dev` — so from then on you tap the store instead of using fakedns every time.

> [!NOTE]
> for the change(s) to apply to the PS store, you need to reboot


## query flags

| flag | effect |
|------|--------|
| `?fw=13.20` | set the firmware version by hand | 
| `?auto=1` | skip the start button | 
| `?measure=1` | show the WebView viewport report |
| `?webkitTimeout=N` | give up on the webkit stage after N seconds (default 300) |
| `?kernelTimeout=N` | give up on the kernel stage after N seconds (default 600) |
| `?payloadTimeout=N` | give up on the plugin stage after N seconds (default 120) |

<!-- 
remove query flags and instead make them config options in:
/data/pLabs5/pWeb5/config.ini
-->

## if it goes wrong

**The webkit stage hangs:** 
- *Controller stops working/ nothing happens when using it:*
	- it's very possible the webkit primitive stage hung, in this case, simply hold the power button for 10 seconds to force a poweroff
- *PS5 still responds but webpage no-longer loads after a `this page is not responding. stop loading it?` popup appears*
	- the webkit primitive stage hung, simply hold the power button for 10 seconds to force a poweroff

**The kernel stage hangs:** 

- *`offsets/<fwVersion>,js never loaded`*
	- that FW version very likely doesn't have support, or the PS5 had trouble loading the `offsets/<version>.js` file

**A plugin fails to load:** 
- *`local plugin failed`*
	- a few things could have gone wrong, you may have defined the wrong path to a local plugin, or the local plugin wasn't for the PS5
- *`remote plugin failed`*
	- its most likely that it failed to get the plugin from the internet for whatever reason, check your router settings

## licence

**AGPLv3.** Full text in [`LICENSE`](LICENSE).

  pWeb5 is free software: you can use, study, share and modify it. if you
  redistribute it, or ship a modified version, you have to pass the same licence on and make your source available.

the exploit chain that is used is KAR0218's rework of relapse, adapted to work here. the included plugin binaries under `payloads/` are third-party builds and keep their own terms. 


## legal

I, foxinwinter/pLabs5, as well as its contributers, are not affiliated with, associated with, sponsored by, endorsed by or otherwise established with Sony Interactive Entertainment, Playstation, or any of their
other companies or works unless explictly stated otherwise.
*Just because a explict mention above isn't present does **NOT** mean otherwise.*

All software is provided "as is", without warranty of **ANY** kind, express
or implied. Use all software at your own risk.

You are solely responsible for complying with terms of service of all programs, as well as any applicable law. 
