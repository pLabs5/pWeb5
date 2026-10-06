#!/usr/bin/env bash
# Assemble the deployable site into dist/.
#
# Only these paths are served. Building a clean directory keeps .git, tools/
# and the repo metadata off a public URL, and makes it obvious that everything
# under payloads/ is published.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=dist
rm -rf "$OUT"
mkdir -p "$OUT"

# The dispatcher is the only payload this site builds, and the page has to be
# able to fetch it, so it lands in payloads/ before the copy below. Building it
# here rather than by hand keeps payloads/dispatcher.elf from going stale
# against dispatcher/main.c. Without an SDK the site still builds - the elf is
# just left as whatever was last built.
if [ -n "${PS5_PAYLOAD_SDK:-}" ]; then
  echo "building dispatcher.elf"
  make -C dispatcher
  install -m 644 dispatcher/dispatcher.elf payloads/dispatcher.elf
elif [ ! -f payloads/dispatcher.elf ]; then
  echo "warning: PS5_PAYLOAD_SDK is unset and payloads/dispatcher.elf is missing." >&2
  echo "         the site will build but the chain will stop after elfldr." >&2
fi

# LICENSE ships with the deploy: AGPLv3 section 4/6 requires conveying the
# licence and copyright notice with both source and object forms, and section 13
# wants the source reachable from wherever the site is served.
cp index.html style.css app.js manifest.txt _headers LICENSE "$OUT/"
cp -r src offsets payloads fonts "$OUT/"

# Unmistakable per-deploy tag, fixed to the bottom-left corner: the console
# cannot open a URL easily, so the label proves which bundle is running.
# The checked-in index.html stays clean; only dist/ gets the tag.
SHA=$(git rev-parse --short HEAD 2>/dev/null || echo dev)
sed -i "s#<span class=\"bver\" id=\"bver\"></span>#<span class=\"bver\" id=\"bver\">${SHA}</span>#" "$OUT/index.html"

echo "dist/ contents:"
find "$OUT" -type f | sort | sed 's/^/  /'
echo
echo "total: $(du -sh "$OUT" | cut -f1)"
