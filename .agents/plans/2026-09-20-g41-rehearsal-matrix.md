# G41 owner-rehearsal acceptance matrix + adversarial review

## Reused pattern (no new framework)

`scripts/password-handoff.sh` + `TestPasswordRecoveryDocCommands`:
a sh harness extracts one doc's ` ```sh ` fences verbatim (awk),
runs each line, and asserts a transcript; a Go wiring test pins
fence shape, lead tools, harness extraction, and the CI job.
G41 adds `scripts/owner-rehearsal.sh` (findbtc-only, offline) plus
one README ` ```sh ` block and one wiring test in the same shape.

## Media (synthetic, generated in workdir; committed corpus copied read-only)

- `media/owner.img`: `bestblock` marker + BIP32 test-vector `tprv`
  + `abandon…about` test mnemonic (all public, unfunded).
- Hostile copies: `spaced name.img`, `dollar$'quote.img`,
  `line\nbreak.img`, `café.img` (marker bytes, exact-name asserts).
- `media/decoy.bin`: printable noise, zero hits expected.
- `media/locked.bin`: chmod 000 (unix, skipped for root).
- `media/gone.img`: listed but never created (portable unreadable).
- `media/eth-pbkdf2.json`: copy of the committed synthetic keystore
  (public test password `RiverStone2019`).
- Truncated `media/cut.img`: valid marker header, cut mid-record.

## Matrix (each row: command, assert)

1. `findbtc -advise media/owner.img` → prints `Recommended:`.
2. Scan each hostile name with `-json` → hits `target` field is
   byte-exact (LF/quote/$/unicode); stderr `[COMPLETE]`; exit 0.
3. Batch scan (owner + decoy + locked + gone + cut) with
   `-case-log case.jsonl` → exit 0 with `WARNING`
   (partial coverage); decoy contributes zero hits.
4. `-verify-case-log case.jsonl` → gone/locked report
   `NOT SCANNED`; owner reports match.
5. `-report hits.jsonl` (default, no `--reveal`) → per-type
   next steps print; `tprv` string, mnemonic word-run, and
   `RiverStone2019` all ABSENT from default stdout + report.
6. Positive controls: carve `hit-*.bin` CONTAINS the `tprv` and
   mnemonic bytes (proves row 5 is not vacuous).
7. `-hashes media/eth-pbkdf2.json` → crack material out, exit 0.
8. `-tokenlist` on the owner carve → exit 0, tokens out.
9. sha256 of every media file identical before/after all runs;
   media list asserted non-empty.
10. README ` ```sh ` block runs verbatim via the harness; lead
    tool allowlist is `findbtc` only; CI `owner-rehearsal` job
    (ubuntu) runs the harness; Go wiring test pins all of it.
11. Windows-gated Go test (where supported): `Advise(C:\)` routes
    `-walk` without running; scan `%SystemRoot%\…\etc\hosts`
    plus its `\\?\`-prefixed form with case-log → exit 0,
    `[COMPLETE]`, coverage honest. UNC (`\\localhost\…`)
    explicitly OUT: no offline SMB fixture; documented, not
    silently skipped.

## Adversarial review (vacuity counters)

- V1 no-leak passes on empty media → row 6 positive controls.
- V2 unchanged-hash on wrong files → row 9 non-empty list.
- V3 tolerant argv parse → row 2 byte-exact JSON compare
  (LF case fails loudly pre-fix, as G40 proved).
- V4 stale `[COMPLETE]` → fresh transcript per run + counts.
- V5 README drift → row 10 wiring test (fence/lead/CI pins).
- V6 Windows hosts flakes → assert completion/coverage only,
  never hit absence; skip (loudly) if unreadable.
- V7 chmod-000 meaningless as root → skip when euid == 0.
- V8 block needs non-findbtc leads → harness rejects; matrix
  keeps `findbtc`-only block, assertions live in the script.
