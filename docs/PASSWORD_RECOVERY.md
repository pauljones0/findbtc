# Password recovery runbook

findbtc finds encrypted wallets; it never cracks passwords. This runbook
takes you from a hit to a recovery attempt with hashcat, John the Ripper,
or BTCRecover. Everything here works offline.

## 1. Get the crack material

Scan with carving, or point `-hashes` at a carve or wallet copy (never the
scanned device itself):

    findbtc -extract-dir ./carve /dev/sda      # sidecars gain a "hashes" field
    findbtc -hashes ./carve/hit-000001.bin     # or extract from any file
    findbtc -hashes ./carve/hit-000001.bin -json

You get one line per record, ready to feed a cracker:

- Bitcoin Core: `$bitcoin$64$<key>$16$<salt>$<iters>$2$00$2$00`
  (same bytes bitcoin2john.py emits: last two AES blocks, salt, iterations)
- Ethereum scrypt: `$ethereum$s*<n>*<r>*<p>*<salt>*<ct>*<mac>`
- Ethereum PBKDF2: `$ethereum$p*<c>*<salt>*<ct>*<mac>`

`No crack material found` means the bytes hold no complete mkey record
(needs 66 contiguous bytes) or keystore object — carve a wider context
(`-context`) around the hit and retry. Partial records are skipped on
purpose: a truncated hash would only waste crack time.

## 2a. hashcat

Save the `$...$` lines to `hashes.txt` (one per line, no filenames), then:

    hashcat -m 11300 hashes.txt passwords.txt   # Bitcoin Core mkey
    hashcat -m 15600 hashes.txt passwords.txt   # Ethereum PBKDF2
    hashcat -m 15700 hashes.txt passwords.txt   # Ethereum scrypt

Show cracked passwords with `hashcat --show`. Bitcoin wallets are a slow
hash (PBKDF2-HMAC-SHA512, typically 25k–500k iterations), so start with a
small targeted list (old passwords, variations) before big dictionaries.

## 2b. John the Ripper (jumbo)

The same strings work; list the matching formats on your build:

    john --list=formats | grep -i -E 'bitcoin|ethereum'

then run John against a file holding the `$...$` lines with the matching
`--format`.

## 2c. BTCRecover (needs the wallet file, not the hash)

BTCRecover reads Bitcoin Core wallets directly (SQLite natively, BDB via
bsddb3) and also handles typo-based guessing and partial seeds, which
hashcat cannot do. Use it when you have a salvaged `wallet.dat`, or only a
rough idea of the password:

    python btcrecover.py --wallet wallet.dat --passwordlist passwords.txt
    python btcrecover.py --wallet wallet.dat --tokenlist tokens.txt --typos-capslock

See the [BTCRecover tutorial](https://github.com/3rdIteration/btcrecover/blob/master/docs/TUTORIAL.md)
for token files, typo options, and seed recovery. If all you have are
fragments (no openable wallet file), stay on the hashcat path with the
hashes from step 1.

## 3. Handle the material like keys

- `hashes.txt`, carves, and sidecars are sensitive: whoever cracks them
  controls the funds, and a cracked Ethereum hash can expose the private
  key directly. Work on an offline machine, encrypt at rest, delete after.
- Never paste hashes, seeds, or keys into websites or "recovery services"
  — legitimate tools never ask for them.

## Limitations

- Only standard records export: Core mkey with method 0, 48-byte encrypted
  key, 8-byte salt; keystores with aes-128-ctr and scrypt / PBKDF2-HMAC-SHA256.
  Anything else errors with the reason instead of emitting a bogus hash.
- Ethereum presale wallets (`encseed`/`bkp` shape) are detected as out of
  scope and not exported.
