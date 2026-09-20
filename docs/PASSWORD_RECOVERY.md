# Password recovery runbook

findbtc finds encrypted wallets; it never cracks passwords. This runbook
takes you from a hit to a recovery attempt with hashcat, John the Ripper,
or BTCRecover. Everything here works offline.

Every `sh` command below runs verbatim in CI (job `password-handoff`)
against the corpus in `testdata/password-handoff/` — a real cracked
BDB/SQLite mkey pair, two generated Ethereum keystores, a hit-context
file, and `passwords.txt`, the tiny crack list every §3 command tries
(it holds each corpus password between two wrong ones, so a green run
proves the tools really tried and found). Work from a scratch dir with
the corpus copied into it (plus your carves); substitute your own files
for the corpus names — the flags stay the same. Sample output lives in
`text` blocks and never executes.

## 0. Get the tools

You need findbtc plus one cracker. Versions below are the ones this
runbook is verified with (§Verified with); newer ones usually work,
older ones may lack the formats.

- findbtc: build from this repo (see the README), or grab a release
  binary. All `findbtc` commands below assume it is on your PATH.

      go build -o findbtc .

- hashcat with a CPU backend for the small runs here (pocl). The
  verified version is 6.2.6:

      sudo apt-get install hashcat pocl-opencl-icd

  On other systems see the [hashcat homepage](https://hashcat.net)
  plus a CPU OpenCL ICD (pocl) or your GPU vendor's runtime.

- John the Ripper **jumbo** (the distro `john` package is the core
  build without the Bitcoin/Ethereum formats). Build the verified
  release from the Openwall tarball with the repo's GCC fix:

      curl -sL -o john.tar.gz https://www.openwall.com/john/k/john-1.9.0-jumbo-1.tar.gz
      tar xzf john.tar.gz && cd john-1.9.0-jumbo-1
      patch -p0 < /path/to/findbtc/scripts/john-1.9.0-jumbo-1-gcc13-blake2.patch
      cd src && ./configure && make -s -j"$(nproc)"

  then run it from its `run/` directory (see Failure modes).

- BTCRecover from a checkout at the verified commit, with its
  Python deps (the eth-keyfile/setuptools pins matter — see
  §Verified with):

      git clone https://github.com/3rdIteration/btcrecover && cd btcrecover
      git checkout 1457088
      pip install "wallycore>=1.0.0" "protobuf~=5.29.6" "pycryptodome~=3.23.0" "eth-keyfile==0.6.0" "setuptools==80.9.0"

  (`uv run --with ...` with the same pins works too and leaves your
  Python alone.)

## 1. Get the crack material

Scan with carving, or point `-hashes` at a carve or wallet copy (never the
scanned device itself). One line per record, ready to feed a cracker:

```sh
findbtc -hashes core-bdb-mkey.bin
findbtc -hashes eth-pbkdf2.json -json
```

You get (sample output from the corpus):

```text
1 crack-ready hash in core-bdb-mkey.bin
[bitcoin-core-mkey @0] kdf=pbkdf2-hmac-sha512 iters=67908
$bitcoin$64$e6246120c45e390daa6a57476e7fbe4f57d83f79d75f9b4c1db680fe5a846cb8$16$4593aff5639179c7$67908$2$00$2$00
```

- Bitcoin Core: `$bitcoin$64$<key>$16$<salt>$<iters>$2$00$2$00`
  (same bytes bitcoin2john.py emits: last two AES blocks, salt, iterations)
- Ethereum scrypt: `$ethereum$s*<n>*<r>*<p>*<salt>*<ct>*<mac>`
- Ethereum PBKDF2: `$ethereum$p*<c>*<salt>*<ct>*<mac>`

`No crack material found` means the bytes hold no exportable record —
but read stderr before carving wider: keystore-shaped records that fail
strict validation are skipped with the reason (`[hashes] skipped
ethereum-keystore @0: unsupported cipher "aes-256-cbc"`), and presale
wallets are reported as out of scope the same way. No carve fixes an
unsupported cipher or KDF. Only a bare message with no skip lines means
"nothing wallet-shaped here" — then carve a wider context (`-context`)
around the hit and retry. Partial mkey patterns stay silent on purpose:
anything looser than 66 contiguous bytes plus method 0 plus sane
iterations would report noise, and a truncated hash would only waste
crack time.

Crackers want one hash per line with no filenames, one file per mode
(mixing modes in one file aborts the run — see Failure modes). The
`$...$` lines start at column 0, so `grep '^\$'` lifts them out of the
human-readable output:

```sh
findbtc -hashes core-bdb-mkey.bin | grep '^\$' > hashes-bitcoin.txt
findbtc -hashes core-sqlite-mkey.bin | grep '^\$' >> hashes-bitcoin.txt
findbtc -hashes eth-pbkdf2.json | grep '^\$' > hashes-eth-pbkdf2.txt
findbtc -hashes eth-scrypt.json | grep '^\$' > hashes-eth-scrypt.txt
```

## 2. Build a tokenlist from hit context

Tokenlist authoring is BTCRecover's documented hard part, and the carve
around your hit already holds the most likely password parts: nearby
words. `-tokenlist` turns those bytes into a starting tokenlist — one
line per distinct word, case mutations space-separated on the same line
(BTCRecover reads same-line tokens as mutually exclusive, so a word is
never combined with itself):

```sh
findbtc -tokenlist wallet-context.bin -tokenlist-out tokens.txt
```

On the corpus that prints `Wrote 11 token lines (11 base words) to
tokens.txt`, and `tokens.txt` holds one line per nearby word with its
case mutations (excerpt):

```text
# findbtc tokenlist: 11 base words, one line each.
river RIVER River
stone STONE Stone
2019
```

Then trim: delete every line you do not recognize, anchor the words you
are sure about (`^start`, `end$`, `+ required`), and add wildcards for
the parts you half-remember (`%d` a digit, `%1,3d` one-to-three digits).
Each surviving line multiplies the combinations (see Cost estimates),
so ten good lines beat a hundred hopeful ones. `-tokenlist-max N` caps
the output; without it the default is 256 lines, first-seen first.
`-tokenlist` also reads `hits.jsonl` with carves, following the carve
paths like `-watch` does.

## 3a. hashcat

```sh
hashcat -m 11300 --potfile-path=hashcat.pot hashes-bitcoin.txt passwords.txt
hashcat -m 11300 --potfile-path=hashcat.pot --show hashes-bitcoin.txt
hashcat -m 15600 --potfile-path=hashcat.pot hashes-eth-pbkdf2.txt passwords.txt
hashcat -m 15600 --potfile-path=hashcat.pot --show hashes-eth-pbkdf2.txt
hashcat -m 15700 --potfile-path=hashcat.pot --scrypt-tmto 5 hashes-eth-scrypt.txt passwords.txt
hashcat -m 15700 --potfile-path=hashcat.pot --show hashes-eth-scrypt.txt
```

Modes: 11300 Bitcoin Core mkey, 15600 Ethereum PBKDF2, 15700 Ethereum
scrypt. `--potfile-path=hashcat.pot` keeps this recovery's results in
a run-local potfile next to the hashes instead of hashcat's global
one: re-runs in the same directory reuse it, other recoveries are
never touched, and nothing outside the workdir changes. `--show`
reprints cracked passwords from the potfile. Bitcoin
wallets are a slow hash (PBKDF2-HMAC-SHA512, typically 25k–500k
iterations), so start with a small targeted list (old passwords,
variations) before big dictionaries. Success looks like this (corpus
`--show` output — hash, then the password after the colon):

```text
$bitcoin$64$e6246120c45e390daa6a57476e7fbe4f57d83f79d75f9b4c1db680fe5a846cb8$16$4593aff5639179c7$67908$2$00$2$00:btcr-test-password
$bitcoin$64$d57eb66f53d15a0b95cb3514518ef83ce87b743ccafef31e1953a7fef0f88f42$16$11a9673bb6d75428$267488$2$00$2$00:btcr-test-password
```

`--scrypt-tmto 5` caps scrypt's GPU/CPU memory so the run fits modest
hardware; without it hashcat may refuse with `Invalid extra buffer
size` (see Failure modes). Higher numbers use less memory and run
slower; on a big GPU you can drop the flag for speed.

## 3b. John the Ripper (jumbo)

The same strings work; list the matching formats on your build:

```sh
john --list=formats | grep -i -E 'bitcoin|ethereum'
john --format=Bitcoin --pot=john.pot --wordlist=passwords.txt hashes-bitcoin.txt
john --format=Bitcoin --pot=john.pot --show hashes-bitcoin.txt
john --format=ethereum --pot=john.pot --wordlist=passwords.txt hashes-eth-pbkdf2.txt
john --format=ethereum --pot=john.pot --show hashes-eth-pbkdf2.txt
john --format=ethereum --pot=john.pot --wordlist=passwords.txt hashes-eth-scrypt.txt
john --show --pot=john.pot --format=ethereum hashes-eth-scrypt.txt
```

Use `--format=Bitcoin` for Core mkeys and `--format=ethereum` for both
Ethereum KDFs. `--pot=john.pot` keeps this recovery's results in a
run-local potfile next to the hashes — same contract as hashcat's
`--potfile-path` above: re-runs in the same directory reuse it, other
recoveries are never touched. `--show` prints the potfile's passwords.
(The distro `john` package is the core build without these formats —
you need the jumbo build, §Verified with.)

## 3c. BTCRecover (needs the wallet file, not the hash)

BTCRecover reads wallets directly (Bitcoin Core via SQLite natively or
BDB via bsddb3, Ethereum keystores, Electrum, and more) and handles
typo-based guessing, tokenlists, and partial seeds, which hashcat
cannot do. Use it when you have a salvaged wallet file, or only a rough
idea of the password. From your BTCRecover checkout:

```sh
python3 btcrecover.py --wallet eth-pbkdf2.json --passwordlist passwords.txt
python3 btcrecover.py --wallet eth-pbkdf2.json --tokenlist tokens.txt --max-tokens 3
```

The first command tries whole-password candidates; the second combines
up to 3 tokens from the §2 tokenlist in every order (that run finds
`RiverStone2019` from lowercase `river`/`stone` plus `2019` only
because the Capitalized mutations are on those lines). `--max-tokens`
is required: without it BTCRecover tries ever-longer combinations
until you stop it. A found password prints exactly:

```text
Password found: 'RiverStone2019'
```

See the
[BTCRecover tutorial](https://github.com/3rdIteration/btcrecover/blob/master/docs/TUTORIAL.md)
for typo options and seed recovery. If all you have are fragments (no
openable wallet file), stay on the hashcat path with the hashes from
step 1.

## 4. Handle the material like keys

- `hashes.txt`, carves, and sidecars are sensitive: whoever cracks them
  controls the funds, and a cracked Ethereum hash can expose the private
  key directly (ethereum2john.py prints this warning itself). Work on an
  offline machine, encrypt at rest, delete after.
- Never paste hashes, seeds, or keys into websites or "recovery services"
  — legitimate tools never ask for them.

## Failure modes (observed, with fixes)

| Symptom | Cause | Fix |
|---|---|---|
| findbtc: `No crack material found` | no exportable record: nothing wallet-shaped, OR a skipped keystore (see stderr: unsupported cipher/KDF, presale) | read stderr first — a skip reason means carving wider will not help; only a bare message means carve wider (`-context`) and retry |
| findbtc: `No token words found` | context holds no 3+ letter/digit runs | feed a bigger carve, or the `hits.jsonl` with carves |
| hashcat: `Token length exception`, `No hashes loaded` | mixed modes in one file, or a `name:` filename prefix (ethereum2john.py prepends one) | one file per `-m`; strip prefixes (`grep '^\$'` output never has them) |
| hashcat: `All hashes found as potfile entries` on a re-run in the same directory | the hashes were already cracked into the run-local `hashcat.pot` | not an error — `--show` still prints them; delete only that run-local file to re-time from scratch (never another recovery's pot) |
| John: `No password hashes left to crack` on a re-run in the same directory | the hashes were already cracked into the run-local `john.pot` (`--pot` selects the potfile; `--session` only names the session) | not an error — `--show` still prints them; delete only that run-local file to re-time from scratch (never another recovery's pot) |
| hashcat: `Invalid extra buffer size` (scrypt) | scrypt's buffer exceeds device memory at the default tmto | raise `--scrypt-tmto` (5 fits a CPU; higher = less memory, slower). Some old OpenCL stacks (observed: NVIDIA + hashcat 6.2.6 without CUDA) refuse at any tmto — use a CPU backend (pocl) or John |
| John: `No password hashes loaded` | `--format` does not match the hash, or the hash line is truncated | `Bitcoin` for `$bitcoin$`, `ethereum` for `$ethereum$`; re-export |
| John: `fopen: john.conf` | a bare-name `john` resolves its run files from the CWD | run from the jumbo `run/` directory, or copy/symlink its contents next to your hashes |
| John cracks scrypt never, silently | jumbo sizes the scrypt salt with `strlen` (`ethereum_fmt_plug.c`): a salt containing a `0x00` byte truncates and can never match (~12% of random 32-byte salts) | use hashcat for scrypt wallets whose salt hex contains `00` |
| BTCRecover: `not a valid ... wallet` | file is not the detected type, or a BDB Core wallet without bsddb3 installed | check the type (`cipherparams`+`kdfparams` marks an eth keystore); see BTCRecover `INSTALL.md` for bsddb3 |
| BTCRecover runs forever | tokenlist too big for the `--max-tokens` combinatorics | trim lines, anchor (`^`, `$`, `+`), lower `--max-tokens`; see Cost estimates |

## Cost estimates

Work is guesses × KDF cost. Measured reference rates on an i7-7700K
CPU with John 1.9.0-jumbo-1, single thread (`OMP_NUM_THREADS=1`):
~115 passwords/s at 68k Core iterations, ~2100/s at PBKDF2 c=4096,
~2.3/s at scrypt N=262144; default threading roughly doubles that on
4 cores. The corpus runs (hashcat 6.2.6 on pocl CPU, John CPU,
BTCRecover) each finish in seconds to ~2 minutes. Scale from there:

| Attack | Estimate (CPU) | Notes |
|---|---|---|
| Core 250k iters × 10k passwords | ~5 min single-thread | linear in iterations; a discrete GPU runs an order of magnitude or more faster |
| Eth PBKDF2 c=262144 × 10k passwords | ~5 min single-thread | same scaling; GPU helps equally |
| Eth scrypt N=262144 × 10k passwords | ~70 min single-thread | memory-hard: GPUs help less; `--scrypt-tmto` trades RAM for time |
| Tokenlist: L lines, V variants/line, max k tokens | guesses ≈ Σ P(L,i)·Vⁱ | corpus: 11 lines → ~23k guesses, found in 16 s at c=4096. At real c=262144 that is ~64× slower; at 20 lines the same k=3 search is ~190k guesses |
| Real scrypt wallet + 20-line tokenlist | hours to days | trim first; this is where GPU hashcat (rules/masks) or BTCRecover's typo engine earns its keep |

When to stop: billions of guesses on CPU is a GPU-or-never decision —
price a rented GPU against the funds before burning weeks of CPU. If
the KDF parameters are unknown (no complete record exported), no tool
can start; that is a salvage problem (§1), not a cracking problem.

## Limitations

- Only standard records export: Core mkey with method 0, 48-byte encrypted
  key, 8-byte salt; keystores with aes-128-ctr and scrypt / PBKDF2-HMAC-SHA256.
  Anything else is skipped with the reason on stderr (exit stays 0)
  instead of emitting a bogus hash — watch stderr, not just stdout.
  Partial mkey patterns are the exception: anything looser than the
  full 66-byte shape would report noise, so near-misses stay silent.
- Ethereum presale wallets (`encseed`/`bkp` shape) are detected as out of
  scope (a stderr skip line) and not exported.

## Verified with

Every `sh` command above ran green on 2026-09-20 — locally via
`scripts/password-handoff.sh`, the same script CI job
`password-handoff` executes — with:

- John the Ripper 1.9.0-jumbo-1 (CPU build from the openwall release
  tarball plus `scripts/john-1.9.0-jumbo-1-gcc13-blake2.patch`, a
  struct-padding fix for GCC ≥ 13 that changes no hashes; full
  banner suffix varies by CPU)
- hashcat v6.2.6 (pocl CPU backend)
- btcrecover 1.13.0-Cryptoguide @ 1457088 (2026-07-17) on Python 3.12
  with eth-keyfile 0.6.0, setuptools 80.9.0 (eth-keyfile still
  imports pkg_resources, removed from setuptools ≥ 81), and the
  wallycore secp256k1 backend
- findbtc built from this repo at the same commit

`scripts/password-handoff.sh` re-checks the pinned stamps on every
run: the four tool versions above plus the eth-keyfile and setuptools
pins, extracted from the tools themselves — it fails when the doc
drifts from any of them. (The date, Python, pocl, and wallycore lines
are context, not checked.)
