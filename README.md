# FindBTC

Scans devices for remnants of bitcoin wallet files. 

The tool can find wallets even if;

- The wallet was deleted, but not overwritten
- The file system is corrupted and inaccessible
- The device has been reformatted
- The wallet has been partially overwritten
- The wallet is inside a .zip or .tar.gz file, including 
  nested in multiple levels of compressed files
- The zip's central directory is lost: single entries are still carved from
  local file headers

It looks for byte traces of legacy wallets (`bestblock`, `defaultkey`,
`keymeta`, `hdseed`, `crypted_key`, ...), modern descriptor wallets
(`walletdescriptor`, `activeblock`), checksum-validated BIP39 seed phrases
(12/15/18/21/24 words), near-miss phrases with missing or mistyped words,
WIF and extended (`xprv`/`xpub`/...) keys with
base58check validation, Ethereum keystore files (validated by structure),
Electrum seeds and wallet files, checksummed output descriptors, SLIP39
shares, lnd channel-database markers, MetaMask vaults,
and the `wallet.dat` file name. Only key and phrase
types are ever printed; the secrets themselves stay out of logs and output.

## Installing

macOS, via the Homebrew tap (no admin needed):

    brew tap pauljones0/findbtc
    brew install pauljones0/findbtc/findbtc

Windows, via Scoop (no admin needed):

    scoop bucket add findbtc https://github.com/pauljones0/scoop-findbtc
    scoop install findbtc

Windows, via winget from the prepared local manifests (community
submission still pending — see [docs/RELEASE.md](docs/RELEASE.md)).
Local-manifest installs are a winget experimental feature, so the
one-time enable step needs elevation; the install itself does not:

    winget settings --enable LocalManifestFiles   # once, elevated
    mkdir findbtc-winget; cd findbtc-winget
    curl -sSL -O https://raw.githubusercontent.com/pauljones0/findbtc/master/packaging/winget/pauljones0.findbtc.yaml
    curl -sSL -O https://raw.githubusercontent.com/pauljones0/findbtc/master/packaging/winget/pauljones0.findbtc.installer.yaml
    curl -sSL -O https://raw.githubusercontent.com/pauljones0/findbtc/master/packaging/winget/pauljones0.findbtc.locale.en-US.yaml
    winget install --manifest . --accept-package-agreements --accept-source-agreements

Every path above is executed verbatim in CI on its own OS
(`install-smoke`: install, version check, synthetic scan), so the
commands you copy are the commands that passed.

Or download a ready-made binary for linux, macOS or Windows
(x86-64 and ARM64) from the
[releases page](https://github.com/pauljones0/findbtc/releases),
then verify its checksum:

    sha256sum -c checksums.txt

Release artifacts also carry Sigstore build-provenance attestations, verifiable
with `gh attestation verify` (see [docs/RELEASE.md](docs/RELEASE.md)).
On Linux, prefer the managed packages over the archives:

    sudo apt install ./findbtc_*_linux_amd64.deb   # Debian/Ubuntu
    sudo dnf install ./findbtc_*_linux_amd64.rpm   # Fedora/RHEL

Container-first labs can run the blessed image instead (digest-pinned
pull + volume-mount scan, see [docs/CONTAINER.md](docs/CONTAINER.md)):

    docker run --rm -v ./evidence:/evidence:ro \
      ghcr.io/pauljones0/findbtc:latest /evidence/disk.img

Since this is potentially sensitive software, you are encouraged to build it
from source instead. That requires a recent Go toolchain, see
https://golang.org/doc/install — CI covers the latest two stable
releases, and `go.mod` floors the language version at 1.24.

    go install github.com/pauljones0/findbtc@latest
    sudo findbtc /dev/sda


## Usage

    findbtc [-s start-offset] [-json] [-extract-dir DIR [-context BYTES]] [-targets FILE] TARGET [TARGET ...]

    # Eg. scan a disk, printing human-readable hits:

    findbtc /dev/sda

    # Eg. machine-readable hits with exact byte offsets:

    findbtc -json /dev/sda > hits.jsonl

    # Eg. carve 1MB around every hit into ./carve/ for forensic follow-up:

    findbtc -extract-dir ./carve /dev/sda

    # Eg. secret hygiene on a repo or laptop (adds non-wallet matchers):

    findbtc -profile=secrets -walk ~/src > secrets.jsonl

    # Eg. scan a piped image (same hits as scanning the file):

    dd if=/dev/sda bs=1M | findbtc -json - > hits.jsonl

    # Eg. scan several images in one run, one hits file out:

    findbtc -json -case-log case.jsonl img1.E01 img2.raw > hits.jsonl
    # or list the targets in a file (one path per line):
    findbtc -json -case-log case.jsonl -targets batch.txt > hits.jsonl

Not sure which mode fits your target? Ask first — it only inspects,
never scans:

    findbtc -advise /dev/sda

Detections print to stdout; logs, progress and the final `[COMPLETE]` line go
to stderr, so `-json` output stays parseable. Exit codes are a contract:

| Code | Meaning |
| ---- | ------- |
| 0 | The run completed and covered its target — hits or not. A `-walk` that scanned at least one file, or a multi-target run that scanned at least one target, exits 0 even when others failed (failures print loudly with a `WARNING`). |
| 1 | Runtime error or zero coverage: the root target could not be read (missing, unreadable, vanished mid-run), or a `-walk` / multi-target run scanned nothing at all. The reason is on stderr. |
| 2 | Bad flags/usage. |
| 3 | Hits found — but only with `-fail-on-hit`, which gates CI and pre-commit hooks (see [docs/SECRETS_PROFILE.md](docs/SECRETS_PROFILE.md)). |

A bad nested archive inside a readable root stays a warning (exit 0):
only the root target can fail the run.

Progress lines print to stderr at most every 10 seconds (never to
stdout, so pipes stay clean). Known-size targets show percent,
throughput, and an ETA once past a 5-second warmup; the ETA follows
the measured average, so it rises when the scan slows rather than
holding a stale low figure. Unknown-size targets show megabytes
scanned:

    [41.27% 12.4MB/s ETA 3m12s]
    [87mb/??mb 9.8MB/s]

Throughput is per-target (a `-walk` line covers the file in flight).
`-resume` announces its position the same way:

    [main] Resuming /dev/sda at byte offset 123456 (continuing at 41%)

The line shape is a versioned
contract: [schema/hits-v1.json](schema/hits-v1.json), documented in
[docs/HITS_SCHEMA.md](docs/HITS_SCHEMA.md). Each carved hit lands in
`hit-NNNNNN.bin` with a `hit-NNNNNN.json` sidecar holding the same detection
plus a classification of the carved bytes (`sqlite`, `bdb`, `gzip`, `zip`,
`text`, `high-entropy`, ...).
Never carve onto the device being scanned.

### Piped input

Raw scans and the secrets profile accept `-` for stdin, so forensic
triage works over pipes the tool could never seek:

    dd if=/dev/sdb bs=4M | findbtc -json - > hits.jsonl
    ssh lab 'dd if=/dev/sda bs=4M' | findbtc -profile=secrets - > secrets.jsonl

Detections are byte-identical to scanning the same bytes from a file:
offsets are pipe offsets (byte 0 is the first byte read), and only
the target label differs (`"target":"stdin"`, echoed in the
human-readable description; case logs record kind `"stdin"` instead
of `"raw"`). `-s` skips leading pipe bytes; `-extract-dir` carves
work as usual.

Pipes cannot be re-read, so the whole stream is spilled to a temp
file before scanning starts (retries and carves re-open it). The
spill lives in the OS temp dir as `findbtc-stdin-*` (`$TMPDIR` on
Unix, `%TMP%` on Windows — point it at a big volume for large
images) and is removed when the scan returns, success or failure —
a crash may leave it behind for manual cleanup. The spill is capped
at 1 TiB as a backstop against runaway pipes; past the cap the scan
fails loudly rather than truncating, and a full temp disk fails
loudly mid-spill. Spill progress notes print to stderr (one line per
GiB) so large pipes stay visibly alive.

One exception to file parity: forensic containers piped in (EnCase
E01 sets, split raw segments) scan as raw bytes — segments cannot
decode from one flat stream. The scan warns loudly when piped input
carries EWF magic; pass the image file itself for a decoded scan.

Modes that need what a pipe cannot give refuse with exit 1 instead of
mis-scanning: `-fs` and `-unallocated-only` (filesystem offsets),
`-walk` (a directory), `-checkpoint`/`-resume` (a journaled path —
a journal naming a deleted temp file could never resume).

### Triage

A scan can produce hundreds of hits. Summarize them offline, without
rescanning:

    findbtc -json /dev/sda > hits.jsonl
    findbtc -report hits.jsonl

The report answers "is there anything here worth pursuing": per-type
counts with duplicates merged, per-hit confidence, encryption flags,
and prioritized next steps, with hits grouped under one section per
target (each with its hit count and byte-offset span). `-report -`
reads from stdin; add `-json` for the machine-readable report. Like the
scanner, the report prints type labels only — never key or seed material.
An empty hits file gets a coverage note instead of a clean bill of
health: "no detections" is only trustworthy when the scan covered its
target (exit 0 with `[COMPLETE]` on stderr). If the hits are yours
and you don't know what to do next, read
[docs/WHAT_NEXT.md](docs/WHAT_NEXT.md) before anything else.

> **SCAM SHIELD.** Fake "recovery services" target people who just
> found wallet traces. Never send your wallet file, keys, seed words,
> or password guesses to anyone — no legitimate tool or person needs
> them. Never pay upfront for "guaranteed" recovery. Work on copies,
> offline. Details in [docs/WHAT_NEXT.md](docs/WHAT_NEXT.md).

### Password recovery

Encrypted hits can carry crack-ready password hashes. Extract them from a
carve or wallet copy (never the scanned device itself):

    findbtc -hashes ./carve/hit-000001.bin

Scans with `-extract-dir` already attach any `hashes` found in each carve
to the detection and its sidecar. When the password is only half
remembered, `-tokenlist` turns the words near a hit into a starting
BTCRecover tokenlist (case mutations included):

    findbtc -tokenlist ./carve/hit-000001.bin -tokenlist-out tokens.txt

See [docs/PASSWORD_RECOVERY.md](docs/PASSWORD_RECOVERY.md) for the
end-to-end runbook (hashcat, John the Ripper, BTCRecover) — every
command there runs verbatim in CI against real tools.

### Near-miss seed phrases

Recovery input is rarely a perfect phrase, so the scanner also reports
near-misses: phrase-length windows with 1–2 unknown words
(`bip39-12-near-miss`, ...), and runs of 12+ valid words with no
validating window (`bip39-unordered`, possibly a phrase in the wrong
order). Near-miss output is positions and counts only, e.g.
`gaps=[3] typo=[14] validating=[1]` — the gap positions, per-gap
typo candidates within edit distance 2, and how many of those validate
the checksum. Overlapping evidence resolves exact first, then unordered
runs, then near-miss windows, so one location never reports twice.
Measured false-positive bar: zero hits on 1MB of random
bytes and on needle-free prose (LICENSE, main.go, fixtures).
README and GOALS name needle labels on purpose, so the repo
self-scan expects hits there and on fixtures.

Owner recovery can print the actual words with `--reveal`, which attaches
them to BIP39 detections (stdout `-json` included) after a loud warning.
Never share, paste, or log `--reveal` output.

One or two words missing or smudged is enumerable offline
(checksum-gated, most-likely first, with typo correction) as a
`-report` follow-up — no new mode:

    findbtc --reveal -json ./carve/hit-000001.bin > near.jsonl
    findbtc -report near.jsonl -complete --reveal -complete-out keys.txt
    findbtc -watch keys.txt -watch-out addrs.csv

Candidates print on the local terminal only; the keys file (watch-only
account keys, never phrases) feeds `-watch` with no copy-paste. Past
two missing words the tool refuses loudly and points at
[BTCRecover](https://github.com/3rdIteration/btcrecover), which also
owns scrambled-phrase reordering. Full recipe and stop rules:
[docs/WHAT_NEXT.md](docs/WHAT_NEXT.md).

### Fragment salvage

When a carve holds database pages, findbtc reassembles them automatically:
Berkeley DB pages order by their page numbers (gaps zero-filled), SQLite
pages validate into page sets grouped into contiguous runs. Each success
writes `hit-NNNNNN.salvage.db` beside the carve, and the sidecar records a
page map with the source offset of every page. Any file can be analyzed
directly:

    findbtc -salvage ./carve/hit-000001.bin -salvage-out wallet.salvage.db

Salvage needs at least two pages of one database; otherwise the window
carve stands. SQLite order is certain only for a single page-1-led run —
otherwise the page map is the deliverable. Pages destroyed by overwrite or
SSD TRIM cannot be recovered by any tool; overflow and freelist pages are
not identified.

Every salvaged image carries a `verdict` in the sidecar (`salvage.verdict`,
with `reasons`): `valid` means the structure predicts the file opens in
the real database tool — try it (`db_verify`/your wallet software for
BDB, `sqlite3 file.db "PRAGMA quick_check"` for SQLite). `suspect` means
a concrete problem was found (missing pages, page-count mismatch,
uncertain order) — treat the image as a lead for manual carving, not a
database, and read `reasons` before spending effort. `-report` counts
suspect salvages separately. Verdicts are structural predictions, checked
against `db_verify` and `quick_check` on the fixture set — not proofs.

### Watch-only triage

Extended public keys derive their addresses locally — no website paste,
no network:

    findbtc -watch ./carve/hit-000003.bin -watch-out addrs.csv

Accepts a carve, a key file, or `hits.jsonl` (whose carves are searched).
Exports 20 addresses per chain (external + change) as CSV or JSON, with
the script type following the key version (`xpub`→P2PKH, `ypub`→P2SH,
`zpub`→bech32, testnet equivalents). Full keys never appear in the
export; private keys are refused. An opt-in `-balance-endpoint` flag
fills balances from your own Esplora node. See
[docs/WATCH_ONLY.md](docs/WATCH_ONLY.md).

### More wallet formats

Beyond Core wallets and BIP39, the scanner validates:

- **Electrum seeds and files.** 12-word new-style seeds checked against
  the Electrum version prefixes (standard/segwit/2fa), and wallet JSON
  via its seed_version plus wallet_type markers. Old-style Electrum
  seeds (different wordlist, weak check) are out of scope.
- **Output descriptors.** Parenthesized descriptors with a valid
  Core checksum. Descriptor text never prints — it can embed private
  keys — only the hit location.
- **SLIP39 shares.** 20-word (128-bit) and 33-word (256-bit) Shamir
  shares with a valid RS1024 checksum, extendable or not. One share
  alone recovers nothing; gather the threshold.
- **Lightning (lnd).** channel.db bucket markers and the channel.backup
  / channel.db file names. The backup file itself is encrypted, so only
  its name is detectable; buckets say a database is near.
- **MetaMask vaults.** Encrypted vault objects (plain or JSON-escaped
  as in browser storage), validated by field shape and decoded
  lengths. Always flagged as needing its password.

Every format above reports labels and offsets only, carries a triage
classification with next steps in `-report`, and holds the same
false-positive bar: silence on 1MB of random bytes and on this repo's
own prose, enforced by per-format tests. Validated seeds outrank the
weaker unordered hint when they overlap, and Electrum windows inside a
longer exact BIP39 phrase defer to it.

### Filesystem-aware recovery

Raw scanning loses filenames and wastes time on live data. For NTFS and
ext volumes, `-fs` inventories live and deleted entries with names and
scans deleted files' content with filenames stamped on every hit, while
`-unallocated-only` skips everything still allocated:

    findbtc -fs ./evidence/sdb1.img -json > fs-hits.jsonl
    findbtc -unallocated-only /dev/sdb1

For full-disk captures, omit `-fs-offset` and the MBR/GPT partition
table is followed automatically (every NTFS/ext/FAT/exFAT partition is scanned);
pass `-fs-offset` only to pin one volume boot sector by hand.
Range scans take `-checkpoint`/`-resume` too: the journal records
`(range_index, offset)`, and resume refuses loudly if the volume's
range list changed since. Reports show
`file=` for attributed hits. SSDs
with TRIM erase freed blocks within seconds — metadata then names files
whose bytes are gone; see [docs/FILESYSTEMS.md](docs/FILESYSTEMS.md).

Unreadable sectors are retried, then skipped and logged with their byte
ranges, so one bad spot never aborts a scan. For long scans, `-checkpoint
FILE` journals progress every 1MB; if the run is interrupted, `-resume`
continues from the journal instead of starting over.

### Directory sweeps

Sweep a live system, laptop, or repo with the same detectors:

    findbtc -walk /home/user -json > sweep.jsonl
    findbtc -report sweep.jsonl

Symlinks are not followed by default, one unreadable file never aborts
the sweep, and each file appends its own case-log record. Repeat
sweeps suppress reviewed findings with `-baseline known.jsonl` (see
[the secrets profile](docs/SECRETS_PROFILE.md)). See the
[runbook](docs/LIVE_SWEEP.md) for policy and live-system notes.

### Forensic casework

EnCase E01 and SMART S01 sets (pass the `.E01`/`.s01`) and split raw
images (`base.001`, …) scan directly, with decoded bytes cross-checked
against the set's stored MD5. EWF2 (`Ex01`/`Lx01`) is refused with a
conversion pointer — see [docs/FORENSICS.md](docs/FORENSICS.md). `-case-log` records source hashes, flags, bad-sector ranges, and
counts per scan; `-verify-case-log` re-hashes the evidence behind the
log so a reviewer can confirm nothing changed; `-dfxml` exports hits
as DFXML 1.1.1 for Autopsy and case pipelines:

    findbtc -json -case-log case.jsonl evidence.E01 > hits.jsonl
    findbtc -verify-case-log case.jsonl
    findbtc -dfxml hits.jsonl > hits.dfxml

Always work from an acquisition behind a write-blocker, never the
original; see [docs/FORENSICS.md](docs/FORENSICS.md) for the end-to-end
workflow. Each release ships with checksums, an SBOM, and SLSA
provenance — see [docs/RELEASE.md](docs/RELEASE.md) to verify a build
before trusting it with evidence.

### Shell completion and man page

The deb/rpm packages install bash, zsh, and fish completions plus a
man page (`man findbtc`), all generated from the real flag table —
every flag is covered by construction. From any other install, print
them straight from the binary:

    findbtc -gen-completion=bash   # or zsh, fish
    findbtc -gen-man | man -l -

The man page's SEE ALSO links the guides no other doc points at
(benchmarks, pipeline ingest, resource bounds), installed under
`/usr/share/doc/findbtc/`.

## License

GPL
