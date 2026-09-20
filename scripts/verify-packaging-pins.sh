#!/bin/sh
# verify-packaging-pins.sh — every URL + SHA-256 pinned under
# packaging/ must match the release's own checksums.txt, so a stale
# or mistyped pin fails CI instead of shipping a broken install.
# Usage: sh scripts/verify-packaging-pins.sh [TAG]  (default v0.2.0)
set -eu
TAG="${1:-v0.2.0}"
VER="$(printf '%s' "$TAG" | sed 's/^v//')"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM
R="$(cd "$(dirname "$0")/.." && pwd)"
cd "$WORK"
if ! curl -sSL --fail -o checksums.txt \
  "https://github.com/pauljones0/findbtc/releases/download/$TAG/checksums.txt"; then
  echo "FAIL: cannot fetch checksums.txt for $TAG" >&2
  exit 1
fi
fail=0
check() { # file, asset-name; the release checksums.txt is truth.
  want="$(awk -v n="$2" '$2 == n { print $1; exit }' checksums.txt)"
  if [ -z "$want" ]; then
    echo "FAIL: $2 not in $TAG checksums.txt" >&2
    fail=1
    return
  fi
  if ! grep -qF "$2" "$1"; then
    echo "FAIL: $1 does not reference $2" >&2
    fail=1
  fi
  if ! grep -qiF "$want" "$1"; then
    echo "FAIL: $1 lacks $TAG sha $want for $2" >&2
    fail=1
  fi
}
CASK="$R/packaging/homebrew/Casks/findbtc.rb"
SCOOP="$R/packaging/scoop/findbtc.json"
WIN="$R/packaging/winget/pauljones0.findbtc.installer.yaml"
for f in "$CASK" "$SCOOP" "$WIN"; do
  [ -f "$f" ] || { echo "FAIL: missing $f" >&2; fail=1; }
done
[ "$fail" -eq 1 ] && exit 1
# Brew cask: 4 tarballs (mac intel/arm, linux intel/arm).
check "$CASK" "findbtc_${VER}_darwin_amd64.tar.gz"
check "$CASK" "findbtc_${VER}_darwin_arm64.tar.gz"
check "$CASK" "findbtc_${VER}_linux_amd64.tar.gz"
check "$CASK" "findbtc_${VER}_linux_arm64.tar.gz"
# Scoop + winget: 2 zips (windows amd64/arm64).
check "$SCOOP" "findbtc_${VER}_windows_amd64.zip"
check "$SCOOP" "findbtc_${VER}_windows_arm64.zip"
check "$WIN" "findbtc_${VER}_windows_amd64.zip"
check "$WIN" "findbtc_${VER}_windows_arm64.zip"
# Version strings agree with the tag (winget --manifest requires all
# three manifests to agree, so all three are checked).
grep -qF "\"${VER}\"" "$CASK" || { echo "FAIL: cask version" >&2; fail=1; }
grep -qF "\"version\": \"${VER}\"" "$SCOOP" || { echo "FAIL: scoop version" >&2; fail=1; }
for m in "$R/packaging/winget/pauljones0.findbtc.yaml" "$WIN" \
  "$R/packaging/winget/pauljones0.findbtc.locale.en-US.yaml"; do
  grep -qF "PackageVersion: ${VER}" "$m" || { echo "FAIL: winget version in $m" >&2; fail=1; }
done
# Scoop autoupdate templates must render to live URLs: substitute
# the tag version per Scoop semantics ($version, never the
# digits-only $cleanVersion) and fetch. Any unexpanded $ fails.
if grep -qF '$cleanVersion' "$SCOOP"; then
  echo "FAIL: scoop template uses digits-only \$cleanVersion" >&2
  fail=1
fi
grep -o '"url": *"[^"]*"' "$SCOOP" | grep '\$' | while IFS= read -r tpl; do
  rendered="$(printf '%s' "$tpl" | sed "s/\$version/$VER/g")"
  case "$rendered" in
    *'$'*) echo "FAIL: unexpanded variable in $tpl" >&2; exit 1;;
  esac
  url="$(printf '%s' "$rendered" | sed 's/"url": *"//; s/"$//')"
  if ! curl -sSL --fail -o /dev/null "$url"; then
    echo "FAIL: autoupdate URL dead: $url" >&2
    exit 1
  fi
done || fail=1
if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "OK: all packaging pins match $TAG checksums.txt"
