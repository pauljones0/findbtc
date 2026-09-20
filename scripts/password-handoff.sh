#!/usr/bin/env bash
# password-handoff.sh — prove the Goal 33 password handoff against real tools.
#
# Runs every ```sh command in docs/PASSWORD_RECOVERY.md verbatim in a scratch
# workdir seeded with testdata/password-handoff/, then asserts each tool
# actually cracked its corpus hash and the doc's version stamp matches the
# tools that ran. CI (job `password-handoff`) calls this; run it locally
# with the same arguments for the same proof.
#
# Convention: ```sh blocks hold runnable commands ONLY (one per line, no
# line continuations, `#` comments skipped). Sample output lives in
# ```text blocks, which this script never executes.
#
# Hermeticity: every run cracks from scratch in its fresh workdir and
# leaves caller/toolchain state alone. Both pots are run-local via the
# documented flags in each doc command (--potfile-path=hashcat.pot,
# --pot=john.pot) — never the exe-adjacent or global pots, which this
# script neither deletes nor writes. The CWD holds only state-excluded
# links (see below), so even the defaults would land here; the flags
# make run-locality explicit instead of incidental. A replayed run
# fails the live-crack counts below on purpose.
#
# Usage:
#   password-handoff.sh REPO WORKPARENT
# Env:
#   FINDBTC   findbtc binary (default: findbtc on PATH)
#   JOHN      john binary (default: john on PATH)
#   HASHCAT   hashcat binary (default: hashcat on PATH)
#   BTCR_DIR  BTCRecover checkout dir (required; btcrecover.py + package)
#   PYTHON    python interpreter (default: python3)
set -euo pipefail

REPO=${1:?usage: password-handoff.sh REPO WORKPARENT}
WORKPARENT=${2:?usage: password-handoff.sh REPO WORKPARENT}
FINDBTC=${FINDBTC:-findbtc}
JOHN=${JOHN:-john}
HASHCAT=${HASHCAT:-hashcat}
BTCR_DIR=${BTCR_DIR:?set BTCR_DIR to a BTCRecover checkout}
PYTHON=${PYTHON:-python3}
DOC=$REPO/docs/PASSWORD_RECOVERY.md

# Never rm -rf a caller-supplied path: an accidental WORK value (a
# checkout, $HOME) must not be deletable by this script. The parent is
# only ever created; each run happens in a fresh owned subdirectory
# of it, printed here for post-mortem (transcript.log lives inside).
mkdir -p "$WORKPARENT"
WORK=$(mktemp -d "$WORKPARENT/handoff.XXXXXX")
echo "workdir: $WORK"
cd "$WORK"
# All tool state stays in the workdir: both pots via the doc's
# --potfile-path/--pot flags, conf via CWD links staged below,
# kernel caches under $WORK (see Hermeticity above).
export HOME=$WORK
export PATH=$WORK:$PATH
# Tools run under their doc names. When the binary already has that name
# its directory goes on PATH untouched; only a differently-named binary
# (e.g. a -o fbt build) gets a workdir symlink, which is safe for the
# tools that need it (findbtc has no exe-relative files). John's
# CWD-relative run files are staged separately below.
# Pin uv's interpreter selection to the ambient python3 while the
# workdir is still empty: when $PYTHON is a uv wrapper it gets symlinked
# below as `python3`, and any uv discovery consulting PATH would re-exec
# that wrapper forever (observed runaway: ~950 nested uv probes). Only
# uv reads UV_PYTHON, so plain-python runs ignore this harmlessly.
if command -v python3 >/dev/null 2>&1; then
	export UV_PYTHON
	UV_PYTHON=$(command -v python3)
fi
link_tool() {
	p=$1
	case "$p" in
		*/*) ;;
		*) p=$(command -v "$p") ;;
	esac
	if [ "$(basename "$p")" = "$2" ]; then
		export PATH=$(cd "$(dirname "$p")" && pwd -P):$PATH
	else
		ln -s "$p" "./$2"
	fi
}
link_tool "$FINDBTC" findbtc
link_tool "$HASHCAT" hashcat
# The doc invokes bare `python3`: when $PYTHON is a wrapper (local uv) or
# a versioned interpreter, it takes that name in the workdir. (Plain
# `python3` with pip-installed deps — the CI shape — needs no mapping.)
if [ "$(basename "$PYTHON")" != "python3" ]; then
	ln -s "$PYTHON" ./python3
fi
# John resolves its home from argv[0]: invoked as a bare name (as the
# doc commands do) it takes run files AND session state from the CWD
# (jumbo path.c path_init; there is no $JOHN override — an exported
# $JOHN is silently ignored). So the run directory's entries are linked
# into the workdir EXCEPT prior session state: a leftover pot would
# turn the run into a replay ("No password hashes left to crack", no
# Session completed) instead of a live crack. The fresh workdir plus
# the live-crack counts below keep every run honest.
JOHN_BIN=$JOHN
case "$JOHN_BIN" in
	*/*) ;;
	*) JOHN_BIN=$(command -v "$JOHN_BIN") ;;
esac
JOHN_DIR=$(cd "$(dirname "$JOHN_BIN")" && pwd -P)
if [ ! -f "$JOHN_DIR/john.conf" ]; then
	echo "john run dir lacks john.conf: $JOHN_DIR" >&2
	exit 1
fi
for f in "$JOHN_DIR"/*; do
	case "$(basename "$f")" in
		*.pot*|*.log*|*.rec) continue ;;
	esac
	ln -s "$f" . 2>/dev/null || true
done
export PATH=$JOHN_DIR:$PATH
# btcrecover.py imports the sibling `btcrecover` package and
# compatibility_check: link those too, or the script shadows its own
# package (ImportError) now that it runs outside its checkout.
ln -s "$BTCR_DIR/btcrecover.py" ./btcrecover.py
ln -s "$BTCR_DIR/btcrecover" ./btcrecover
ln -s "$BTCR_DIR/compatibility_check.py" ./compatibility_check.py
export PYTHONPATH=$BTCR_DIR
cp "$REPO"/testdata/password-handoff/* .

# The committed corpus must equal fresh generator output: fixtures stay
# reviewable in git while remaining reproducible from the script.
"$PYTHON" "$REPO/scripts/gen-password-corpus.py" --check

# Every ```sh line in the doc, verbatim, in doc order. Any nonzero exit
# fails the run (set -e + pipefail); blank lines and `#` comments skip.
TRANSCRIPT=$WORK/transcript.log
: > "$TRANSCRIPT"
awk '/^```sh$/{flag=1;next}/^```$/{flag=0}flag' "$DOC" > commands.list
test -s commands.list
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
	# Commands get /dev/null stdin: without it the first tool that
	# polls stdin (hashcat, john) eats the rest of commands.list.
	sh -c "$line" >> "$TRANSCRIPT" 2>&1 < /dev/null
done < commands.list
echo "ran $n doc commands verbatim"

# Outcome assertions: the transcript must show every crack, not just
# clean exits — and LIVE cracks, not potfile replays. A warm hashcat
# potfile prints "All hashes found as potfile entries" with no Status
# block, so count the per-run completion markers: 3 hashcat cracks, 3
# john cracks, 2 BTCRecover finds (passwordlist + tokenlist runs).
fail=0
expect() {
	if grep -qF "$1" "$TRANSCRIPT"; then
		echo "PASS: $2"
	else
		echo "FAIL: $2 (missing: $1)" >&2
		fail=1
	fi
}
expect_count() {
	local n
	n=$(grep -cE "$1" "$TRANSCRIPT" || true)
	if [ "$n" -ge "$2" ]; then
		echo "PASS: $3 ($n)"
	else
		echo "FAIL: $3 (found $n, want >= $2: $1)" >&2
		fail=1
	fi
}
expect 'btcr-test-password' 'bitcoin mkey cracks (hashcat + john)'
expect 'RiverStone2019' 'eth-pbkdf2 cracks (hashcat + john + BTCRecover)'
expect 'tide-harbor-42' 'eth-scrypt cracks (hashcat + john)'
expect "Password found: 'RiverStone2019'" 'BTCRecover tokenlist end-to-end'
expect_count 'Status\.+: Cracked' 3 'hashcat cracked live in all 3 modes'
expect_count 'Session completed' 3 'john cracked live in all 3 runs'
expect_count "Password found: 'RiverStone2019'" 2 'BTCRecover found live in both runs'

# The doc stamp must name the exact tools that ran (stable substrings:
# John's banner suffix varies by CPU, so only the version stem asserts).
JOHN_V=$($JOHN_BIN 2>&1 | grep -o 'John the Ripper [0-9.]*-jumbo-[0-9]*' | head -n 1)
HC_V=$($HASHCAT --version 2>&1 | head -n 1)
BTCR_V=$($PYTHON ./btcrecover.py --version 2>&1 | grep -o 'btcrecover [0-9.]*-[A-Za-z]*' | head -n 1)
BTCR_SHA=$(git -C "$BTCR_DIR" rev-parse --short HEAD)
PY_ETH_V=$($PYTHON -c "import importlib.metadata as m; print(m.version('eth-keyfile'))" 2>/dev/null)
PY_SETUP_V=$($PYTHON -c "import importlib.metadata as m; print(m.version('setuptools'))" 2>/dev/null)
for v in "$JOHN_V" "$HC_V" "$BTCR_V" "$BTCR_SHA"; do
	if [ -n "$v" ] && grep -qF "$v" "$DOC"; then
		echo "PASS: doc stamps $v"
	else
		echo "FAIL: doc stamp lacks: $v" >&2
		fail=1
	fi
done
# Python pins need a non-empty version before the stamp match: an
# empty "eth-keyfile " prefix would spuriously match the doc.
for pair in "eth-keyfile:$PY_ETH_V" "setuptools:$PY_SETUP_V"; do
	name=${pair%%:*}
	ver=${pair#*:}
	if [ -n "$ver" ] && grep -qF "$name $ver" "$DOC"; then
		echo "PASS: doc stamps $name $ver"
	else
		echo "FAIL: doc stamp lacks: $name $ver" >&2
		fail=1
	fi
done

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "password handoff verified: $n commands, all cracks observed"
