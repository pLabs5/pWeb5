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

cp index.html style.css app.js manifest.txt _headers "$OUT/"
cp -r src offsets payloads fonts "$OUT/"

echo "dist/ contents:"
find "$OUT" -type f | sort | sed 's/^/  /'
echo
echo "total: $(du -sh "$OUT" | cut -f1)"
