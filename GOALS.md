# findbtc goal queue

Ranked pain-point goals. Exactly one is the active session goal at a time.
Each goal is complete only when its audit answers YES to: **"did we
completely solve the pain point?"**

## Chain rule (read this when any goal completes)

1. Check every audit box of the active goal, with `gofmt`/`build`/`vet`/`test`
   green (note: on this machine Go needs `GOCACHE`/`GOMODCACHE` pointed at
   writable dirs, e.g. `/tmp/fbt-gocache` and `/tmp/fbt-gomodcache`).
2. Mark the goal `complete` in the status table with the commit hash.
3. Create the next `queued` goal as the new active session goal, using its
   Goal text below as the objective.
4. Continue. Never skip, never run two at once. If blocked, mark `blocked`
   with the reason and stop for the user.

## Status

| # | Goal | Status | Done commit |
|---|------|--------|-------------|
| 1 | Scan triage report | complete | a06a5c8 |
| 2 | Crack-ready export for encrypted wallets | complete | a06a5c8 |
| 3 | Fuzzy / partial BIP39 finder | complete | a06a5c8 |
| 4 | Fragment-aware salvage | complete | a06a5c8 |
| 5 | Watch-only balance triage | complete | a06a5c8 |
| 6 | More wallet formats by demand | complete | a06a5c8 |
| 7 | Filesystem-aware layer | complete | a06a5c8 |
| 8 | Forensics packaging | complete | a06a5c8 |

## Global done criteria (every goal)

- `gofmt -l .` clean; `go build ./...`, `go vet ./...`,
  `go test ./... -count=1` green.
- Committed tests proving the pain is solved (fixtures/golden files, plus an
  independent oracle where feasible — never a test that just repeats the
  implementation's assumption).
- README/docs updated for user-facing changes.
- Privacy: no key/seed material in stdout, logs, or JSON by default. Carved
  `.bin` files are the only place secrets may land, with warnings.
- Offline by default; any network access is opt-in with explicit consent.

## Goal 1 — Scan triage report

**Pain to completely solve:** after a scan, the user stares at raw hits and
cannot answer "is there anything here worth pursuing?" Hope-scans of old
drives and pro triage both die in a pile of undifferentiated detections.

**Completely solved when:**
- [x] One offline step turns `-json` hits into a report: per-type counts,
      deduped hits, per-hit confidence, likely-encrypted flags, byte-offset
      distribution, and a prioritized next-step playbook per wallet type.
- [x] Report works from saved `hits.jsonl` (no rescan) and is documented in
      the README triage workflow.

**Execute:**
1. Report schema + needle→wallet-type classifier + dedupe + JSON writer +
   golden tests on fixture JSONL.
2. CLI `-report hits.jsonl` (human + JSON output) + README.
3. Confidence tuning + per-type playbook text.
4. Optional: disk-map/HTML rendering.

**Non-goals:** balance lookups (Goal 5), cracking (Goal 2), new detectors.

**Verify:** golden test on a fixture `hits.jsonl` covering every detection
kind; dedupe test (same needle+block reported once); gates green.

## Goal 2 — Crack-ready export for encrypted wallets

**Pain to completely solve:** the user found an encrypted wallet but forgot
the password — the highest-volume recovery pain (recovery services report
~70 requests/day). Today they must hand-extract hashes with version-fragile
scripts (`bitcoin2john` fails on wallets newer than it understands).

**Completely solved when:**
- [x] For encrypted hits (`mkey`/`crypted_key`/keystore crypto params),
      findbtc emits a crack-ready hash in a documented,
      BTCRecover/hashcat/John-compatible form, plus KDF metadata and the
      exact follow-up commands.
- [x] Works offline from carved bytes; partial/corrupt records produce a
      clear "not enough material" error instead of a bogus hash.

**Execute:**
1. Parse `mkey` record (salt, iterations, method, encrypted key) from
   carved BDB bytes; golden tests on synthetic wallets old + new.
2. Hash writer in the documented format + self-check (re-derive and compare
   where the password is known in tests only — never log it).
3. Keystore crypto-params export path.
4. Docs: end-to-end password-recovery runbook with BTCRecover.

**Non-goals:** cracking passwords inside findbtc; cloud cracking services.

**Verify:** synthetic `wallet.dat` old and new → hashes byte-identical to an
independent extractor; corrupt-truncation fixtures → clean errors; gates.

## Goal 3 — Fuzzy / partial BIP39 finder

**Pain to completely solve:** findbtc only reports perfect checksum-valid
phrases, but the realistic recovery case is a *nearly*-complete phrase
(1–4 missing words, typos, wrong order). Today those recoverable phrases
are silently missed.

**Completely solved when:**
- [x] 12/15/18/21/24-word windows with up to N unknown/invalid words are
      detected; typo candidates (bounded edit distance) and 12-word
      reorder hints are reported.
- [x] Default output reports positions and gap patterns, never words; an
      explicit `--reveal` exists for owner recovery with loud warnings.
- [x] False-positive rate measured on a noise corpus and documented.

**Execute:**
1. Near-miss window scanner + gap-pattern reporting + fixtures.
2. Typo candidates via bounded edit distance against the wordlist.
3. 12-word reorder hints (checksum-guided, capped work).
4. `--reveal` flag + FP measurement + docs.

**Non-goals:** full-seed brute force (astronomical; scam-adjacent); online
"seed recovery services".

**Verify:** synthetic fragments with missing/typo/shuffled words are found
with correct gap patterns; noise corpus FP rate under the documented bar;
privacy test asserts words appear nowhere in default output; gates.

## Goal 4 — Fragment-aware salvage

**Pain to completely solve:** file carving fails on fragmentation — the #1
carver limitation. findbtc's fixed context window cannot reassemble a
wallet scattered across non-contiguous clusters.

**Completely solved when:**
- [x] BDB page-chain stitching and SQLite page reassembly turn
      multi-fragment fixtures into openable/salvageable databases (or
      validated page sets), falling back to window carve when stitching
      is impossible; the report says what was stitched.
- [x] Carve sidecars record page maps and provenance (which offsets
      contributed).

**Execute:**
1. BDB page-header parser + chain stitching + fixtures.
2. SQLite page reassembly + `sqlite3` open check on fixtures.
3. Stitch-aware carve mode + sidecar page maps.
4. Docs: when salvage can/can't work (TRIM, overwrite).

**Non-goals:** filesystem-level undelete (Goal 7); repairing logically
corrupt records beyond page salvage.

**Verify:** fragmented synthetic BDB/SQLite wallets → salvaged output opens
in independent tools; single-fragment case still works; gates.

## Goal 5 — Watch-only balance triage

**Pain to completely solve:** the user found key material but cannot tell
whether any funds exist — and the obvious move (pasting keys/xpubs into a
website) is both a privacy leak and the #1 phishing pattern.

**Completely solved when:**
- [x] findbtc derives addresses locally from extended public keys (correct
      script type per version, sane gap limit) and exports an address list
      the user can check anywhere.
- [x] Any balance lookup is opt-in via an explicit endpoint flag with
      consent + local-node/Tor docs; the default path makes zero network
      calls (test-enforced).

**Execute:**
1. xpub parse + address derivation (P2PKH/P2SH-P2WPKH/P2WPKH per version;
   evaluate `btcsuite` hdkeychain vs minimal deps).
2. Address-list export (CSV/JSON) from hits or carved xpubs.
3. Optional `--balance-endpoint` plugin + privacy docs.
4. Playbook wiring into the Goal 1 report.

**Non-goals:** private-key derivation (never); built-in explorer API keys;
online-by-default anything.

**Verify:** testnet vectors → expected addresses; default path performs no
network I/O under test; gates.

## Goal 6 — More wallet formats by demand

**Pain to completely solve:** non-Core wallets are invisible: Electrum (own
seed format + files), SLIP39 shares, descriptor checksums, Lightning static
channel backups, browser/mobile vaults.

**Completely solved when:**
- [x] Each shipped format has a validator, FP tests, report classification,
      and a playbook entry. Ship order: Electrum files+seeds → output
      descriptor checksums → SLIP39 → lnd SCB/channel.db → MetaMask vault.

**Execute:** per format: read the spec, add detector + fixtures + noise
corpus FP test, wire classifier/playbook, document.

**Non-goals:** altcoin-of-the-week; closed formats without a spec.

**Verify:** per-format fixtures found, noise FP rate documented, gates.

## Goal 7 — Filesystem-aware layer

**Pain to completely solve:** raw scanning is slow and noisy on big disks,
filenames are lost, and deleted-but-referenced files are missed even though
filesystem metadata still describes them.

**Completely solved when:**
- [x] NTFS MFT and ext inode parsing recover deleted wallet entries with
      names; `--unallocated-only` raw mode skips live data; report shows
      filenames; SSD/TRIM limits documented.

**Execute:**
1. MFT deleted-entry parser + synthetic-image tests.
2. ext inode parser + synthetic-image tests.
3. Unallocated-only scan mode.
4. Report integration + docs.

**Non-goals:** APFS (unless demand proves it); RAID rebuild; Sleuth Kit
clone.

**Verify:** synthetic NTFS/ext images with deleted `wallet.dat` → found by
name; gates.

## Goal 8 — Forensics packaging

**Pain to completely solve:** professional recovery needs a court-ready
workflow: provenance, chain of custody, and image-format support that a raw
scanner does not provide.

**Completely solved when:**
- [x] Case log records source SHA-256, tool version, flags, bad-sector
      ranges, and checkpoint; DFXML/Autopsy-compatible hit export;
      E01/raw/split-image input; write-blocker docs.

**Execute:**
1. Case log + streaming source hash.
2. DFXML export of the Goal 1 report.
3. E01 input support (evaluate libs) + split raw.
4. Docs: forensic workflow end to end.

**Non-goals:** case management; timeline analysis.

**Verify:** sample case export validates against DFXML tooling where
available; tampered source detected via hash; gates.

## Commit policy

Commits and pushes need the user's explicit ask in the session (per Git
safety rules). The chain rule's "done commit" column may read
`a06a5c8` when no commit was requested;
that never blocks picking up the next goal.
