#!/usr/bin/env bash
# Host tests for the dispatcher's manifest parsing and kstuff selection.
# No console required: the harness stubs firmware and HTTPS.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

ROOT="$TMP/autodr"
HTTP="$TMP/http"
mkdir -p "$ROOT/payloads" "$HTTP/payloads"

BIN="$TMP/harness"
cc -std=gnu11 -Wall -Wextra -Wno-unused-parameter -O1 -g \
   -DLOCAL_ROOT="\"$ROOT\"" -DCLOUD_BASE='"http://localtest"' \
   -o "$BIN" tests/harness.c || exit 1

fails=0
run() { # name, expects...  (manifest on stdin when $MANIFEST=1)
  local name="$1"; shift
  local out="$TMP/out.$name"
  # Most cases only care about the resolved plan, and a fetch of a payload that
  # was never planted would just fail the run. Those set NO_FETCH=1; the cases
  # that check the size/magic guards leave it unset so the fetch really happens.
  local -a dry=(DISPATCHER_DRYRUN=1)
  [ "${NO_FETCH:-0}" = 1 ] && dry+=("DISPATCHER_PLAN_ONLY=1")
  env -i PATH="$PATH" TEST_FW="${FW:-0x12000000}" \
      TEST_HTTP_ROOT="$HTTP" "${dry[@]}" \
      "$BIN" >"$out" 2>&1
  cat "$out"
}

check() { # description, pattern, output-file
  if grep -qF "$2" "$3"; then
    echo "  ok   $1"
  else
    echo "  FAIL $1"
    echo "       expected to find: $2"
    fails=$((fails + 1))
  fi
}

refute() { # description, pattern, output-file
  if grep -qF "$2" "$3"; then
    echo "  FAIL $1"
    echo "       did not expect: $2"
    fails=$((fails + 1))
  else
    echo "  ok   $1"
  fi
}

echo "local manifest wins, kstuff forced first, order preserved"
cat >"$ROOT/manifest.txt" <<'EOF'
# a comment line

ethaproject.etaHEN
shadowmountplus.elf=http://example.test/remote.bin
EOF
FW=0x12000000 NO_FETCH=1 run local >/dev/null
check "kstuff first"        "[1/3] kstuff-lite.elf <- http://localtest/payloads/kstuff-lite-1.11B.elf" "$TMP/out.local"
check "bare name resolves"  "[2/3] ethaproject.etaHEN <- http://localtest/payloads/ethaproject.etaHEN" "$TMP/out.local"
check "absolute url kept"   "[3/3] shadowmountplus.elf <- http://example.test/remote.bin" "$TMP/out.local"

echo "firmware boundary decides full vs lite kstuff"
# Own manifest, so the plan is kstuff + one entry.
printf 'placeholder.elf\n' >"$ROOT/manifest.txt"
FW=0x10010000 NO_FETCH=1 run fw101 >/dev/null
check "10.01 gets full kstuff"  "[1/2] kstuff.elf <- http://localtest/payloads/kstuff.elf" "$TMP/out.fw101"
FW=0x10020000 NO_FETCH=1 run fw102 >/dev/null
check "10.02 gets lite kstuff"  "[1/2] kstuff-lite.elf <- http://localtest/payloads/kstuff-lite-1.11B.elf" "$TMP/out.fw102"
FW=0x12000000 NO_FETCH=1 run fwok >/dev/null
check "12.00 gets lite kstuff"  "[1/2] kstuff-lite.elf <- http://localtest/payloads/kstuff-lite-1.11B.elf" "$TMP/out.fwok"

echo "an explicitly named kstuff wins over firmware detection"
cat >"$ROOT/manifest.txt" <<'EOF'
kstuff-lite-1.11B.elf
EOF
FW=0x10010000 NO_FETCH=1 run named >/dev/null
check "named kstuff honoured" "[1/1] kstuff-lite-1.11B.elf <- http://localtest/payloads/kstuff-lite-1.11B.elf" "$TMP/out.named"

echo "local: targets are confined to the local root"
cat >"$ROOT/manifest.txt" <<'EOF'
traverse=local:../../etc/passwd
outside=local:/etc/passwd
good=local:MANIFEST_PLACEHOLDER/payload.bin
EOF
sed -i "s#MANIFEST_PLACEHOLDER#$ROOT#" "$ROOT/manifest.txt"
printf 'ELF-ish' >"$ROOT/payload.bin"
NO_FETCH=1 run local2 >/dev/null
check "traversal refused"   "must be under $ROOT/" "$TMP/out.local2"
check "outside root refused" "must be under $ROOT/" "$TMP/out.local2"
check "valid local accepted" "good <- $ROOT/payload.bin (console-local)" "$TMP/out.local2"
refute "traversal not dispatched" "traverse <-" "$TMP/out.local2"

echo "trailing comments are stripped, not treated as part of the path"
cat >"$ROOT/manifest.txt" <<'EOF'
thing.elf=other.elf # inline note
EOF
NO_FETCH=1 run comment >/dev/null
check "comment stripped" "[2/2] thing.elf <- http://localtest/payloads/other.elf" "$TMP/out.comment"

echo "an explicit payloads/ prefix does not stack"
cat >"$ROOT/manifest.txt" <<'EOF'
etahen.elf=payloads/etaHEN.elf
bare.elf
EOF
NO_FETCH=1 run prefix >/dev/null
check "prefixed target resolves once" "[2/3] etahen.elf <- http://localtest/payloads/etaHEN.elf" "$TMP/out.prefix"
check "bare target resolves once"    "[3/3] bare.elf <- http://localtest/payloads/bare.elf" "$TMP/out.prefix"
refute "no payloads/payloads"  "payloads/payloads/" "$TMP/out.prefix"

echo "firmware is reported as BCD, not as a raw byte"
printf 'placeholder.elf\n' >"$ROOT/manifest.txt"
FW=0x12000000 NO_FETCH=1 run bcd12 >/dev/null
check "12.00 reads as 12.00" "firmware 12.00 (0x12000000)" "$TMP/out.bcd12"
FW=0x09000000 NO_FETCH=1 run bcd9 >/dev/null
check "09.00 reads as 9.00" "firmware 9.00 (0x09000000)" "$TMP/out.bcd9"
FW=0x135b0000 NO_FETCH=1 run badbcd >/dev/null
check "non-BCD is not guessed" "0x135b0000 (not BCD, unrecognised)" "$TMP/out.badbcd"

echo "cloud fallback when there is no local manifest"
rm -f "$ROOT/manifest.txt"
cat >"$HTTP/manifest.txt" <<'EOF'
cloudone.elf
EOF
NO_FETCH=1 run cloud >/dev/null
check "fetched cloud manifest" "using cloud manifest" "$TMP/out.cloud"
check "cloud bare name"       "[2/2] cloudone.elf <- http://localtest/payloads/cloudone.elf" "$TMP/out.cloud"

echo "a payload that comes back as HTML is not sent to elfldr"
# The live site answers an unknown path under payloads/ with the SPA's
# index.html and a 200, so a missing payload looks like a successful fetch.
# Only the ELF magic check catches it, so it has to.
#
# kstuff is always sent first, so it has to be fetchable here too or the run
# stops before reaching the payload under test.
cat >"$ROOT/manifest.txt" <<'EOF'
kstuff-lite.elf=payloads/kstuff-lite-1.11B.elf
missing.elf
EOF
printf '\177ELF' >"$HTTP/payloads/kstuff-lite-1.11B.elf"
dd if=/dev/zero bs=4096 count=1 >>"$HTTP/payloads/kstuff-lite-1.11B.elf" 2>/dev/null
# The real site's fallback is its whole index.html, comfortably over the 4KB
# floor, so a short one-liner would be caught by the size check instead and
# would not prove the magic check does its job.
{ printf '<!DOCTYPE html><title>Jailbreak Store</title>'; \
  dd if=/dev/zero bs=1024 count=8 2>/dev/null | tr '\0' 'x'; } \
  >"$HTTP/payloads/missing.elf"
run htmlpage >/dev/null
check "html rejected, not sent" "not an ELF (a CDN error page?)" "$TMP/out.htmlpage"
refute "no false 'sent' line"  "missing.elf: sending" "$TMP/out.htmlpage"
refute "chain stops there"      "shadowmountplus" "$TMP/out.htmlpage"
rm -f "$HTTP/payloads/missing.elf"

echo "a truncated payload is rejected too"
head -c 200 /dev/zero >"$HTTP/payloads/tiny.elf"
cat >"$ROOT/manifest.txt" <<'EOF'
kstuff-lite.elf=payloads/kstuff-lite-1.11B.elf
tiny.elf
EOF
run tiny >/dev/null
check "too small rejected" "too small to be an ELF" "$TMP/out.tiny"
refute "not sent"          "tiny.elf: sending" "$TMP/out.tiny"
rm -f "$HTTP/payloads/tiny.elf" "$HTTP/payloads/kstuff-lite-1.11B.elf"

echo
if [ "$fails" -eq 0 ]; then
  echo "all dispatcher tests passed"
else
  echo "$fails check(s) failed"
fi
exit $((fails > 0))
