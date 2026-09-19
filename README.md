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

Download a ready-made binary for linux, macOS or Windows (x86-64 and ARM64)
from the [releases page](https://github.com/pauljones0/findbtc/releases), then
verify its checksum:

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

There is no Homebrew tap yet, so macOS users should install from the release
archives.

Since this is potentially sensitive software, you are encouraged to build it
from source instead. That requires a recent Go toolchain, see
https://golang.org/doc/install — CI covers the latest two stable
releases, and `go.mod` floors the language version at 1.24.

    go install github.com/pauljones0/findbtc@latest
    sudo findbtc /dev/sda


## Usage

    findbtc [-s start-offset] [-json] [-extract-dir DIR [-context BYTES]] DEVICE

    # Eg. scan a disk, printing human-readable hits:

    findbtc /dev/sda

    # Eg. machine-readable hits with exact byte offsets:

    findbtc -json /dev/sda > hits.jsonl

    # Eg. carve 1MB around every hit into ./carve/ for forensic follow-up:

    findbtc -extract-dir ./carve /dev/sda

    # Eg. secret hygiene on a repo or laptop (adds non-wallet matchers):

    findbtc -profile=secrets -walk ~/src > secrets.jsonl

Not sure which mode fits your target? Ask first — it only inspects,
never scans:

    findbtc -advise /dev/sda

Detections print to stdout; logs, progress and the final `[COMPLETE]` line go
to stderr, so `-json` output stays parseable. Exit codes are a contract:
0 the run completed (hits or not), 1 runtime error, 2 bad flags/usage,
3 hits found — but only with `-fail-on-hit`, which gates CI and
pre-commit hooks (see [docs/SECRETS_PROFILE.md](docs/SECRETS_PROFILE.md)).
The line shape is a versioned
contract: [schema/hits-v1.json](schema/hits-v1.json), documented in
[docs/HITS_SCHEMA.md](docs/HITS_SCHEMA.md). Each carved hit lands in
`hit-NNNNNN.bin` with a `hit-NNNNNN.json` sidecar holding the same detection
plus a classification of the carved bytes (`sqlite`, `bdb`, `gzip`, `zip`,
`text`, `high-entropy`, ...).
Never carve onto the device being scanned.

### Triage

A scan can produce hundreds of hits. Summarize them offline, without
rescanning:

    findbtc -json /dev/sda > hits.jsonl
    findbtc -report hits.jsonl

The report answers "is there anything here worth pursuing": per-type
counts with duplicates merged, per-hit confidence, encryption flags,
byte-offset spans per target, and prioritized next steps. `-report -`
reads from stdin; add `-json` for the machine-readable report. Like the
scanner, the report prints type labels only — never key or seed material.
If the hits are yours and you don't know what to do next, read
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
to the detection and its sidecar. See
[docs/PASSWORD_RECOVERY.md](docs/PASSWORD_RECOVERY.md) for the end-to-end
runbook (hashcat, John the Ripper, BTCRecover).

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
Never share, paste, or log `--reveal` output. For reordering a scrambled
phrase or brute-forcing several missing words, take the carve to
[BTCRecover](https://github.com/3rdIteration/btcrecover), which searches
permutations and word combinations that a scanner cannot disambiguate.

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
the sweep, and each file appends its own case-log record. See the
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

## License

GPL
