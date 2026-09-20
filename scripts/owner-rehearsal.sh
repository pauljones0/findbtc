#!/usr/bin/env bash
# owner-rehearsal.sh — cold owner-facing end-to-end recovery rehearsal.
#
# Proves the documented advice -> scan -> case-log -> report ->
# what-next path against synthetic disposable media with the frozen
# CLI, offline. Pattern mirrors scripts/password-handoff.sh: the
# README's fenced rehearsal block runs verbatim, then the matrix
# asserts the transcript and artifacts.
#
# Usage: owner-rehearsal.sh REPO WORKPARENT
#   FINDBTC   findbtc binary (default: findbtc)
#   PYTHON    python interpreter (default: python3)
#
# Matrix (see .agents/plans/2026-09-20-g41-rehearsal-matrix.md):
# hostile-but-valid filenames reach native argv byte-exact; decoy
# stays clean; locked/missing targets warn loudly with NOT SCANNED
# case-log records; default output leaks no fixture secret (with
# positive carve controls); media bytes are unchanged afterwards.
set -euo pipefail

REPO=${1:?usage: owner-rehearsal.sh REPO WORKPARENT}
WORKPARENT=${2:?usage: owner-rehearsal.sh REPO WORKPARENT}
FINDBTC=${FINDBTC:-findbtc}
PYTHON=${PYTHON:-python3}
case "$PYTHON" in
*/*) ;;
*) PYTHON=$(command -v "$PYTHON") || { echo "python interpreter not found: $PYTHON" >&2; exit 1; } ;;
esac

mkdir -p "$WORKPARENT"
WORK=$(mktemp -d "$WORKPARENT/rehearsal.XXXXXX")
echo "workdir: $WORK"
cd "$WORK"

"$PYTHON" "$REPO/scripts/gen-rehearsal-media.py" "$WORK" > media.list
test -s media.list
cp "$REPO/testdata/password-handoff/eth-pbkdf2.json" media/
# shellcheck disable=SC1091
. media/secrets.env
PASSWORD=$(grep -o 'RiverStone2019' "$REPO/testdata/password-handoff/passwords.txt" | head -n 1)
test -n "$PASSWORD"

# The README block invokes bare `findbtc`: stage that name.
case "$FINDBTC" in
*/*) ln -s "$FINDBTC" ./findbtc ;;
*) FINDBTC=$(command -v "$FINDBTC") || { echo "findbtc not found" >&2; exit 1; }; ln -s "$FINDBTC" ./findbtc ;;
esac
export PATH=$WORK:$PATH

if command -v sha256sum >/dev/null 2>&1; then
	SHA=sha256sum
else
	SHA="shasum -a 256"
fi
(cd media && $SHA -- *) > media.sha256
test -s media.sha256

# Snapshot first: hashing must read every byte, and the locked file
# below becomes unreadable on purpose (restored before the final
# check — the assert is byte-unchanged, not mode-unchanged).
if [ "$(id -u)" = 0 ]; then
	echo "running as root: locked.bin stays readable, skipping unreadable-file asserts"
	AS_ROOT=1
else
	AS_ROOT=0
	chmod 000 media/locked.bin
fi

# The README rehearsal block, verbatim, in doc order.
awk '/<!-- owner-rehearsal:start -->/{flag=1;next}/<!-- owner-rehearsal:end -->/{flag=0}flag' "$REPO/README.md" \
	| awk '/^```sh$/{flag=1;next}/^```$/{flag=0}flag' > commands.list
test -s commands.list
TRANSCRIPT=$WORK/transcript.log
: > "$TRANSCRIPT"
n=0
while IFS= read -r line; do
	case "$line" in
		''|'#'*) continue ;;
	esac
	case "$line" in
		*\\)
			echo "multi-line doc command unsupported: $line" >&2
			exit 1 ;;
	esac
	n=$((n + 1))
	echo "+ $line"
	echo "+ $line" >> "$TRANSCRIPT"
	sh -c "$line" >> "$TRANSCRIPT" 2>&1 < /dev/null
done < commands.list
echo "ran $n README commands verbatim"

fail=0
expect() {
	if grep -qF "$1" "$TRANSCRIPT"; then
		echo "PASS: $2"
	else
		echo "FAIL: $2 (missing: $1)" >&2
		fail=1
	fi
}
expect_absent() {
	if grep -qF "$1" "$2"; then
		echo "FAIL: $3 (leaked: $1 in $2)" >&2
		fail=1
	else
		echo "PASS: $3"
	fi
}

# README path: advise routes, batch scans clean, report guides.
expect 'Recommended: findbtc' 'advise prints a recommendation'
expect '[COMPLETE]' 'batch completed'
expect 'Triage:' 'report summarizes detections'
expect 'Hits by target:' 'report groups by target'
expect 'Coverage:' 'report states coverage'
expect 'Next steps:' 'report gives next steps'
expect 'docs/WHAT_NEXT.md' 'report points at what-next'
expect '(bestblock)' 'report names the marker needle'
expect '(tprv)' 'report names the extended-key needle'
expect ': OK media/owner.img' 'verify-case-log confirms the clean batch'

# Hostile-but-valid filenames: exact bytes reach native argv and
# come back in the JSON target field byte-identical.
for target in 'media/spaced name.img' "media/dollar\$'quote.img" 'media/line
break.img' 'media/café.img'; do
	if "$WORK/findbtc" -json "$target" > hostile.jsonl 2>hostile.stderr; then
		echo "PASS: scanned $(printf %s "$target" | head -c 40)"
	else
		echo "FAIL: scan of hostile name failed: $target" >&2
		fail=1
		continue
	fi
	TARGET="$target" "$PYTHON" -c "
import json, os, sys
want = os.environ['TARGET']
hits = [json.loads(l) for l in open('hostile.jsonl') if l.strip()]
assert hits, 'no hits for %r' % want
bad = [h['target'] for h in hits if h['target'] != want]
if bad:
    print('target mismatch: %r' % bad)
    sys.exit(1)
"
	if [ $? -ne 0 ]; then
		echo "FAIL: JSON target not byte-exact for: $target" >&2
		fail=1
	else
		echo "PASS: byte-exact target for hostile name"
	fi
	grep -q 'COMPLETE' hostile.stderr || { echo "FAIL: no COMPLETE for: $target" >&2; fail=1; }
done

# Decoy: clean means clean — empty hits with full coverage.
if "$WORK/findbtc" -json media/decoy.bin > decoy.jsonl 2>decoy.stderr; then
	echo "PASS: decoy exit 0"
else
	echo "FAIL: decoy scan exit $?" >&2
	fail=1
fi
test ! -s decoy.jsonl || { echo "FAIL: decoy produced hits" >&2; fail=1; }
grep -q 'COMPLETE' decoy.stderr || { echo "FAIL: decoy never completed" >&2; fail=1; }
grep -q 'WARNING' decoy.stderr && { echo "FAIL: decoy warned" >&2; fail=1; } || echo "PASS: decoy clean, no warning"

# Partial batch: locked/missing targets warn loudly but exit 0.
set +e
"$WORK/findbtc" -json -case-log partial.case.jsonl media/owner.img media/locked.bin media/gone.img media/cut.img > partial.hits.jsonl 2>partial.stderr
code=$?
set -e
if [ "$AS_ROOT" = 1 ]; then
	test "$code" = 0 || { echo "FAIL: root batch exit $code" >&2; fail=1; }
else
	test "$code" = 0 || { echo "FAIL: partial batch exit $code, want 0" >&2; fail=1; }
	grep -q 'WARNING' partial.stderr || { echo "FAIL: partial batch never warned" >&2; fail=1; }
fi
grep -q 'COMPLETE' partial.stderr || { echo "FAIL: partial batch never completed" >&2; fail=1; }
"$WORK/findbtc" -verify-case-log partial.case.jsonl > verify.out 2>&1
grep -q "NOT SCANNED .*gone.img" verify.out || { echo "FAIL: missing target lacks NOT SCANNED" >&2; fail=1; }
if [ "$AS_ROOT" = 0 ]; then
	grep -q "NOT SCANNED .*locked.bin" verify.out || { echo "FAIL: locked target lacks NOT SCANNED" >&2; fail=1; }
fi
echo "PASS: partial batch + case-log verification"

# A lone missing root fails the run loudly (exit 1).
set +e
"$WORK/findbtc" media/gone.img >missing.out 2>missing.stderr
code=$?
set -e
test "$code" = 1 || { echo "FAIL: missing root exit $code, want 1" >&2; fail=1; }
grep -qi 'cannot\|missing\|no such' missing.stderr || { echo "FAIL: missing root silent" >&2; fail=1; }
echo "PASS: missing root exits 1 loudly"

# Encrypted fixture: crack material out, password stays in.
"$WORK/findbtc" -hashes media/eth-pbkdf2.json > hashes.out 2>hashes.stderr
test -s hashes.out || { echo "FAIL: -hashes empty" >&2; fail=1; }
echo "PASS: -hashes extracts crack material"
"$WORK/findbtc" -tokenlist media/owner.img -tokenlist-out tokens.txt >/dev/null 2>&1
test -s tokens.txt || { echo "FAIL: -tokenlist empty" >&2; fail=1; }
echo "PASS: -tokenlist runs on owner media"

# No fixture secret in default outputs (transcript, hits, report,
# hashes); positive controls prove the bytes were really there.
"$WORK/findbtc" -report hits.jsonl > report.out 2>&1
for f in transcript.log hits.jsonl report.out hashes.out; do
	expect_absent "$REH_TPRV" "$f" "tprv absent from default $f"
	expect_absent "$REH_MNEMONIC" "$f" "mnemonic absent from default $f"
	expect_absent "$PASSWORD" "$f" "keystore password absent from default $f"
done
grep -qF "$REH_TPRV" carve/hit-*.bin 2>/dev/null || { echo "FAIL: carve lacks tprv (vacuous no-leak?)" >&2; fail=1; }
grep -qF "$REH_MNEMONIC" carve/hit-*.bin 2>/dev/null || { echo "FAIL: carve lacks mnemonic (vacuous no-leak?)" >&2; fail=1; }
echo "PASS: positive carve controls hold the secrets"

# Media bytes unchanged by every run above.
if [ "$AS_ROOT" = 0 ]; then
	chmod 644 media/locked.bin
fi
(cd media && $SHA -c ../media.sha256) || { echo "FAIL: media mutated" >&2; fail=1; }
echo "PASS: media unchanged"

if [ "$fail" != 0 ]; then
	echo "REHEARSAL FAILED" >&2
	exit 1
fi
echo "REHEARSAL PASSED"
