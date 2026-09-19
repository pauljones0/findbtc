# I found traces — what's next?

You ran a scan and got hits. This guide says what each kind of hit
means, what to do next (exact commands), and when to stop. Read the
two boxes first — they protect you from the two most common ways
people lose recoverable wallets.

> **SCAM SHIELD — read this before anything else.**
> You will be targeted. Fake "recovery services" reply to forum
> posts, run ads, and send DMs offering to unlock your wallet.
> Rules that never have exceptions:
>
> - **Never send your wallet file, keys, seed words, or password
>   guesses to anyone.** No legitimate tool or person needs them.
> - **Never type your seed into a website.** Restore only in
>   reputable wallet software, on your own machine, preferably
>   offline.
> - **Never pay upfront for "guaranteed" recovery.** Realistic
>   outcomes are uncertain; guarantees are the scam marker.
> - findbtc itself never needs your secrets: it prints type labels
>   and byte offsets, never key or seed material.

> **WORK ON A COPY, OFFLINE IF YOU CAN.**
> If the wallet matters, stop writing to the source drive now —
> every write can overwrite deleted bytes. Ideally scan a clone or
> image, not the original (`docs/FORENSICS.md`). Keep carves and
> sidecars on encrypted storage, and delete them when done.

## How to read a hit

A hit line names a *trace*, not a wallet:

    Found 'bestblock' at /dev/sda in 4kB block at byte offset 4096

- `'bestblock'` is the needle: which detector fired (see below).
- `/dev/sda` is the target: where the bytes live. `Zipfile #0 ...`
  means inside a compressed file; `file=wallet.dat` (with `-fs`)
  names the filesystem entry.
- The offsets locate the bytes for carving. Only labels and offsets
  ever print — secret bytes stay in the carve files, if any.

Run `-report` on your hits for a summary with next steps per type:

    findbtc -json /dev/sda > hits.jsonl
    findbtc -report hits.jsonl

## 1. Marker hits — traces of a wallet database, no keys yet

Needles like `bestblock`, `defaultkey`, `orderposnext`,
`walletdescriptor`, `activeblock`, `channel.backup`.

**What it means:** a wallet file (or a piece of one) is or was at
that spot. Markers alone spend nothing — they say "dig here".

**Next:** carve around the hit and look at what came with it:

    findbtc -extract-dir ./carve /dev/sda
    findbtc -report hits.jsonl

Open the sidecar (`hit-NNNNNN.json`): it classifies the carved bytes
(`bdb`, `sqlite`, ...). If the carve holds database pages, findbtc
reassembles them automatically into `hit-NNNNNN.salvage.db` — see
"Fragment salvage" in the README. Check the sidecar's `verdict`
first: `valid` is worth opening, `suspect` (with `reasons`) is a
lead, not a database. Then re-scan the carve: nearby
key, seed, or encrypted hits are the actual prize.

**Stop when:** wider carves (`-context`) keep showing markers only,
with no keys, seeds, or encrypted material. Markers without keys
are archaeology, not money.

## 2. Key hits — private key material nearby

Needles like `wif`, `xprv`/`tprv`/..., `xpub`/...

**What it means:** a checksum-validated key encoding sits at that
offset. `wif`/`xprv` shapes control funds; `xpub` shapes are
watch-only (they see addresses but spend nothing).

**Next:** carve it, then handle by type. Never print or paste the
key bytes — work from the carve file:

    findbtc -extract-dir ./carve /dev/sda

- Private key (`wif`, `xprv`, ...): sweep the funds to a fresh
  wallet from an **offline** machine, then discard the exposed key.
  The old key is burned the moment it touched a scanned drive.
- Extended public key (`xpub`, `zpub`, ...): derive its addresses
  locally and check balances without ever exposing a secret:

    findbtc -watch ./carve/hit-000003.bin -watch-out addrs.csv

  See `docs/WATCH_ONLY.md`. Balances come only from your own
  Esplora node (`-balance-endpoint`) — never a random website.

**Stop when:** the key is testnet (`tprv`/`wif-testnet` — worthless
play money) or the carve shows the encoding was a fragment that
fails validation on closer look.

## 3. Seed-phrase hits — recovery words nearby

Needles like `bip39-12`, `bip39-24-near-miss`, `bip39-unordered`,
`electrum-seed`, `slip39-20`.

**What it means:** 12–24 dictionary words in a validating (or
near-validating) arrangement. Exact hits are strong; `near-miss`
has 1–2 wrong/missing words; `unordered` is a word pile that might
be a scrambled phrase — or word salad.

**Next:** carve it. Owner recovery can print the words, on your own
machine only, after a loud warning:

    findbtc -extract-dir ./carve /dev/sda
    findbtc --reveal -json ./carve/hit-000001.bin

Never share, paste, or log `--reveal` output. Restore exact phrases
in reputable wallet software, offline. For near-misses (gaps/typos)
or scrambled phrases, take the carve to
[BTCRecover](https://github.com/3rdIteration/btcrecover), which
searches permutations a scanner cannot disambiguate.

**Stop when:** `unordered` never resolves to a validating window
after trying orders (it was word salad); a single SLIP39 share with
no path to the threshold (one share alone recovers nothing).

## 4. Encrypted hits — the wallet needs its password

Needles like `crypted_key`, `eth-keystore`, `metamask-vault`.

**What it means:** an encrypted wallet or vault. The keys exist but
are locked; without the password (or a crackable one) nothing moves.

**Next:** extract crack-ready hashes from a carve or wallet copy —
never the scanned device itself:

    findbtc -hashes ./carve/hit-000001.bin

Then follow `docs/PASSWORD_RECOVERY.md` (hashcat, John, BTCRecover).
Start with passwords you have actually used; strong unique forgotten
passwords are effectively unrecoverable, and anyone promising
otherwise is selling something (see the scam shield).

**Stop when:** `No crack material found` persists after wider carves
(the record is incomplete), or your realistic password space is
exhausted. Partial records are skipped on purpose — truncated
hashes only waste crack time.

## 5. Secrets-profile hits — leaked credentials, not wallets

Needles like `pem-private-key`, `aws-access-key`, `github-token`
(only with `-profile=secrets`).

**What it means:** a private key block or cloud credential. No
coins directly — but on a shared or stolen machine these are the
attacker's prize.

**Next:** treat any carve as a live secret (encrypted storage,
delete after) and rotate: private keys get replaced and purged
from wherever they leaked; cloud keys get revoked in IAM / at
github.com/settings/tokens with a misuse check. Full checklist:
`docs/SECRETS_PROFILE.md`.

**Stop when:** everything found is revoked/rotated and the leak
source is cleaned. There is no "recover funds" step here — only
containment.

## When to give up (for real)

- The drive was SSD-TRIMmed, fully overwritten, or encrypted with a
  lost key: no tool recovers those bytes, including this one.
- Months of realistic password guesses failed on a strong password.
- Only filename/marker hits remain after wide carves.
- Someone asks for money or secrets to continue: that is the scam,
  not the solution. Walk away.
