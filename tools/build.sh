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

cp index.html style.css app.js manifest.txt _headers probe.html "$OUT/"
cp tools/devtools_mock.js "$OUT/devtools_mock.js"
cp -r src offsets payloads fonts "$OUT/"

# Unmistakable per-deploy tag on the JAILBREAK button: the console cannot
# open a URL easily, so the label itself proves which bundle is running.
# The checked-in index.html stays clean; only dist/ gets the tag.
SHA=$(git rev-parse --short HEAD 2>/dev/null || echo dev)
sed -i 's#<button id="go" class="go" type="button">JAILBREAK</button>#<button id="go" class="go" type="button">JAILBREAK<sub class="bver">'"$SHA"'</sub></button>#' "$OUT/index.html"

echo "dist/ contents:"
find "$OUT" -type f | sort | sed 's/^/  /'
echo
echo "total: $(du -sh "$OUT" | cut -f1)"
