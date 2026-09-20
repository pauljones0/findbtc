# Proposal — 2026-09-20 (Goals 43–45)

Session goal: the next ranked slice after Goals 31–42. Inputs: a
hands-on audit from HEAD (`6ec3a34`) running five realistic owner
flows, a grep of every TODO/known-gap/resume-boundary comment checked
against current behavior, a re-read of the 09-19 brainstorm's pain
notes / parked list / open questions, and the G42 design addendum
(025/026/027) plus the active sibling boundary.

Decisions:

- Rank by owner pain × feasibility, smallest highest-trust slice
  first, chained in dependency order (this slice has no hard deps,
  so smallest-first is the chain).
- The sibling worker owns no-drop bounded scheduling for the
  nested-publication backlog, including the G42 addendum's approved
  `-max-nested-backlog` follow-up. Anything touching publication
  admission, gate scheduling, or congested-run retry semantics is
  rejected below — not parked, rejected as out of this slice's
  lane.
- Demand-gated items stay parked: verified 2026-09-20 via
  `gh repo view` that issues AND discussions are still both
  disabled, so no demand could have arrived through the repo.
  Silence since 09-19 is absence of channel, not absence of
  demand — but scheduling big speculative work on it would be
  scope smuggling either way.
- Old open questions 1 (tap ownership) and 4 (seed-completer
  shape) are resolved by events (G37 shipped
  `pauljones0/homebrew-findbtc` + the Scoop bucket with winget
  manifests staged; G32 shipped the `-report` follow-up). They
  are dropped, not re-asked. Questions 2 and 5 carry forward.

## Flows re-audit (post-31–42)

The five jobs, re-scored:

1. Owner triage — STRONG, one misroute. Advise → scan → case-log
   → report → what-next rehearses green (G41). Remaining hole:
   `-advise` routes by target SHAPE only and misroutes the two
   most valuable follow-up inputs (encrypted wallet copies,
   forensic containers) to raw scans. Goal 43.
2. Forensics sweep — STRONG, two gaps. Batch + range resume
   works (G42, verified by kill test below). Remaining: a
   full-disk `-fs` run over several volumes cannot journal
   (Goal 45), and deleted FAT entries report mangled 8.3 names
   where `fls` recovers the real ones (Goal 44).
3. Password recovery — STRONG (verified against real tools in
   CI, G33/G40). Remaining: nothing in the handoff itself —
   only the advise routing into it (Goal 43).
4. Secret hygiene — STRONG, no new asks. No new secret types
   proposed (standing rule re-asked below, not widened).
5. Deep forensics — ADEQUATE. DFXML-only rationale stands; no
   demand arrived for parked exporters.

## Hands-on audit (2026-09-20, dev binary from HEAD)

Build: `go build -o /tmp/findbtc-audit .`
(`GOCACHE=/tmp/gocache-root`). All commands below ran against it.

- F1 (advise misroute: wallet copy).
  `findbtc -advise testdata/password-handoff/eth-pbkdf2.json`
  → `Recommended: findbtc <path>` with reason "no partition
  table or filesystem found / raw scan covers every byte".
  Observed: an encrypted-wallet copy routes to a raw scan, not
  `-hashes`. The report playbook knows the handoff; the router
  does not.
- F2 (advise misroute: forensic container).
  `printf 'EVF2dummy' > fake.ex01; findbtc -advise fake.ex01`
  → same raw-scan recommendation. Observed: EWF2 magic routes
  to a scan that will refuse with the conversion pointer
  (exit 1). `detector/advise.go` confirms the charter:
  "content is never scanned" — the gap is architectural, and
  the fix is bounded magic sniffing, not scanning.
- F3 (follow-up exit inconsistency, unpinned).
  `-hashes` on keyless input: `No crack material found…` on
  stdout, exit 0. `-salvage` on noise: `No salvageable…
  pages…` on stdout, exit 0. `-watch` on keyless input:
  `[watch] Exiting due to error: no extended public keys…` on
  stderr, exit 1. Observed: `-watch` is the 1-against-4
  outlier on both stream and code; no test pins it (only
  `main.go:1420` names the message). The README exit table
  defines 1 as "runtime error or zero coverage" — readable
  but keyless input is "completed, nothing found".
- F4 (FAT32 just-works: NO bug). A real `mkfs.fat -F 32`
  128 MB volume scans under `-fs` with both auto-seed and
  explicit `-fs-offset 0` (exit 0). An earlier 16 MB "FAT32"
  probe was correctly refused: 32k clusters fall below the
  FAT32 cluster-count threshold, so the refusal named the
  real defect. Partitionless (superfloppy) volumes work —
  `resolveVolumes` tries offset 0 before the partition table.
- F5 (flat-zip scaling, REJECTED as sibling-entangled).
  500-member stored zip: 1023 ms; 2000-member (4×): 7857 ms
  (7.7×) for a 392 KB file. Corroborated in-repo: `bf3c984`
  "Flat many-member zips are O(members²) (per-member ECD
  re-parse)". Rejected: wall time far exceeds CPU time,
  implicating gate/handoff throughput — the sibling's area.
  Revisit after no-drop scheduling lands, with a profile.
- F6 (batch resume flag binding: by design, not proposed).
  Resume with a different `-extract-dir`/`-case-log` than the
  journaled run fails loudly (`batch journal carved into
  "./carve", run asks ""`, exit 1); identical flags resume
  with `batch: skipping … (already complete)`, exit 0. This
  is the G42 run-binding safety rule — strictness here is a
  feature, not friction.
- F7 (`-fs` with no deleted ranges writes no journal:
  correct). Fresh mkfs image + `-checkpoint` → exit 0,
  `[COMPLETE]`, no journal file. Correct: `scanOneVolume`
  returns before the range scanner when there is nothing to
  resume.
- F8 (kill/resume works). 60 MB image, `timeout -s KILL 1`
  killed at the 2 MB journal point; `-resume` announced
  `(continuing at 3%)` and found the planted `bestblock` at
  offset 50000000. Resume-vs-cold agreement held.
- F9 (seed → watch flow green). 11-of-12 smudged-paper recipe
  → 128 checksum-valid completions on the terminal, 384
  watch-only keys (`-complete-out`), 1320 addresses from
  `-watch`, zero seed words in the keys file. (An early
  11-candidate keys file was my probe artifact: piping
  `-complete` through `head` SIGPIPEs the writer. Prefix
  truncation preserves candidate numbering, so no hazard.)
- F10 (unallocated + checkpoint journals merged ranges).
  `-unallocated-only -fs-offset 0 -checkpoint` on the FAT32
  volume → exit 0 with a `ranges`-list journal. This is the
  shipped precedent Goal 45 mirrors.

## TODO / known-gap grep check (each against behavior)

- `detector/zip_scanner.go:67` TODO ("more resilient zip
  reading… partials and corrupted files"): largely SUPERSEDED
  by `zip_recover.go` (local-header carving for
  directory-less archives). Residual (data-descriptor/bit-3
  entries skipped in directory-less recovery) is narrow with
  zero pain evidence — intact archives handle bit 3 via the
  central directory. Park; retire or re-scope the comment
  when carve-resilience demand arrives.
- `detector/fsfat.go:19` ("long-name recovery for deleted
  entries is a known recall gap"): STILL TRUE —
  `fsfat.go:355` assembles LFN runs only `if !deleted`, and
  `fsfat_test.go:318,350,372` pin `?ELETED.BIN`-style names.
  → Goal 44.
- `detector/fsscan.go:110` ("checkpointing is not supported
  across N auto-seeded volumes… pin one volume"): STILL
  TRUE, pinned by `checkpoint_test.go:318` — and now
  inconsistent with the shipped unallocated merged-range
  journal (`main.go:runUnallocated`). → Goal 45.
- `docs/FORENSICS.md` "known resume boundary"
  (directory-less zip fragments ahead of the frontier need
  re-announcement on resume): still true, inherent to the
  recovery design, no demand. Park.
- Consumer-audit nits (no `detector.Version` const — version
  lives in `main.go:21` as `var version`; no CHANGELOG):
  still true, no observed pain. Park as release-prep polish.
- `main.go:327` (batch × `-unallocated-only` + checkpoint
  refuses, exit 2): a G42 composition decision, bigger than
  Goal 45's single-run flattening. Explicit non-goal of 45.
- G42 addendum "approved as follow-up:
  `-max-nested-backlog` flag": sibling territory. Rejected.
- G42 "UNC proof recorded as explicit future work": no
  offline fixture exists (G41), so no verifiable goal can be
  named. Rejected with note, not scheduled.

## Goal 43 — Follow-up routing + exit honesty

Pain: the steps AFTER a scan misroute or misreport. `-advise`
is the tool's router, but its charter ("content is never
scanned", `detector/advise.go:39`) limits it to shape probes,
so the two highest-value follow-up inputs route wrong: an
encrypted wallet copy gets a raw scan instead of `-hashes`
(F1), and an EWF2 container gets a raw scan instead of the
conversion pointer (F2). Separately, `-watch` on readable
but keyless input exits 1 on stderr while `-hashes`,
`-salvage`, `-report`, and `-tokenlist` all report "nothing
found" on stdout with exit 0 (F3) — a script chaining the
documented seed→watch flow reads a clean empty as a failure.
Complete when: (a) `-advise` sniffs bounded magic (first KB
only — never a scan, never a run) and routes EWF/EWF2/S01
images to the documented container path (E01/S01 scan as
today; EWF2 to the libewf conversion pointer, no command),
encrypted-wallet copies (`mkey` record, complete-keystore
shape) to `-hashes`, and extended-public-key files to
`-watch`, with reasons naming the sniffed evidence; (b) the
raw-scan default is preserved on ALL ambiguous input —
advise must never divert a scan-worthy target to a follow-up
(false routing is worse than the raw default); the existing
shape table (dir/volume/partitioned/raw/empty) is unchanged;
(c) `-watch` on readable-but-keyless input prints `No
extended public keys in FILE` on stdout and exits 0, matching
`-hashes`/`-salvage`; unreadable/missing input still exits 1,
and the README exit table gains the follow-up-modes row.
Non-goals: content scanning inside advise (first-KB magic
only); `-salvage`/`-tokenlist`/`-complete` routing without a
named misroute fixture; changing any scan-mode exit.
Verify: routing fixtures (E01/refused-EWF2 magic, mkey bin,
keystore JSON, keys file, ambiguous binary → raw default)
plus the existing 4-fixture routing tests green; exit-matrix
test for watch/hashes/salvage empty-vs-unreadable; FP probe
(random + prose advise to raw); gates.
Rank: FIRST. Smallest scope, highest trust per line: it fixes
the router every new user meets first and the one exit-code
lie left after Goal 31. Zero overlap with the sibling.

## Goal 44 — FAT deleted-entry long-name recovery

Pain: deleted wallet backups on USB sticks, SD cards, and old
externals — exactly where owners keep them (Goal 25's own
pain statement) — report mangled 8.3 names (`?Y-BIT~1.DAT`)
while Sleuth Kit `fls` recovers the real long names from the
surviving LFN slots. findbtc underperforms the oracle it
already cross-checks against, and a forensics report citing
`?`-names for entries `fls` names in full is an avoidable
recall gap the code admits (`fsfat.go:19`).
Complete when: (a) deleted FAT12/16/32 entries whose LFN slot
run survives report the assembled long name (positional
association, checksum-gated where the short name allows —
decide exact gating at goal time; bias: positional + LFN
self-consistency, never a guessed first byte); entries with
no surviving run keep the `?`-prefixed 8.3 form; (b) live
entries are byte-identical (the `if !deleted` extension must
not move the live path — proven by the unchanged live
assertions); (c) the per-format FP bar holds (random + prose
still refuse as non-volumes) and `file=` stamps carry the
recovered names into hits and `-report`.
Non-goals: exFAT deleted-name recovery (separate on-disk
scheme — only if the same fixtures show the same gap);
repairing filesystems; guessing destroyed first bytes.
Verify: FAT12/16/32 fixtures with deleted long-name files
(plus a destroyed-LFN control) with names byte-agreeing with
`fls` via the existing oracle harness (`fsfat_test.go`
`long` field, extended to deleted entries); `?`-pin tests
updated to the new contract; gates.
Rank: SECOND. Code-admitted gap, behavior-pinned, oracle
harness already built — feasibility is proven and the pain
is the owner-backup shape. No sibling overlap (FS readers,
not the publication gate).

## Goal 45 — Multi-volume `-fs` checkpoint

Pain: the standard forensics `-fs` shape — a full-disk image
whose partition table auto-seeds several volumes — cannot
journal: `fsscan.go:110` refuses checkpoint/resume across
auto-seeded volumes, so an interruption restarts EVERY
volume. The workaround (one pinned `-fs-offset` run per
volume) loses the one-run case log and the auto-seed, and
rehearsing it per volume is exactly the loop Goals 38/42
killed for batch scans. The refusal is also now internally
inconsistent: `-unallocated-only` already journals a merged
cross-volume range list in one journal (F10,
`main.go:runUnallocated`).
Complete when: (a) a single `-fs` auto-seed run over N
volumes journals one flattened deleted-entry range list
(range_index, offset) exactly like the unallocated precedent,
with per-range filename ownership spanning volumes; resume
validates the full list (any volume's range list changed →
loud refusal, same rule as today); kill mid-2nd-volume →
resume → byte-identical detections with identical `file=`
stamps vs an uninterrupted cold run; (b) the `fsscan.go:110`
refusal is lifted for the single-run case and its test
becomes a success test; single-volume behavior is
byte-identical (flattened one-volume list journals as
today); (c) case-log records stay per-volume (one record per
scanned volume, as today) and `-verify-case-log` agrees.
Non-goals: batch × `-unallocated-only` checkpoint
(`main.go:327` — a run-binding composition design, future
goal only); `-walk`/`-patch` resume (demand-gated, see open
question 5); changing the range-match refusal rule.
Verify: 2-volume partitioned fixture (FAT32 + ext, deleted
wallet marker in volume 2); kill mid-volume-2 → resume vs
cold byte-identity incl. `file=` stamps; changed-volume
mismatch refusal; zero-deleted-ranges still journals
nothing (F7); gates.
Rank: THIRD (last of slice). Real forensics pain with a
proven in-repo pattern to mirror, but the largest scope of
the three — and it must not land before the sibling's gate
work settles the shared range-resume inheritance tests.

## Parked (no change, with notes)

- EWF2 write path: still conversion-pointer only; no demand.
- New DFXML exporters (CSV/Elastic): no demand; DFXML-only
  rationale stands.
- Live secret verification: NEVER — contradicts the offline
  posture and the G23 shield. `verified` means parses.
- Interactive wizards: still a non-goal pattern (`-advise`
  stays a printer; Goal 43 adds sniffing, not a prompt loop).
- Password cracking inside findbtc: still out; handoff only.
- APFS: still out (TSK covers it).
- Idea 7 (Btrfs/XFS/ZFS): still demand-gated, no demand —
  and the demand channel that could deliver it is still
  closed (verified). Order unchanged: XFS/Btrfs/ZFS, spike
  ZFS deletability before promising.
- Native `git rev-list` walking: demand check still none.
- Zip data-descriptor directory-less skip + the stale
  `zip_scanner.go:67` TODO: narrow, no pain evidence.
- `-walk` / `-patch` resume: real design risk (file-list /
  streaming-attribution journals), no demand signal. Gated
  on open question 5, not scheduled.
- Flat-zip O(members²): measured (F5) but entangled with
  the sibling's gate throughput — revisit after no-drop
  scheduling lands, with a profile, not before.
- `detector.Version` const + CHANGELOG: still absent, still
  painless. Ride-along candidates for a future release-prep
  goal, not a goal.
- Stale-spill cleanup after crashes: tiny; document-only
  unless a user trips on it.
- UNC proof (G42 explicit future work): no offline fixture
  exists — unschedulable until someone names a Windows/SMB
  verification. Not parked demand; blocked verification.

## Open questions for the user

1. Demand channel (3rd ask, now blocking-silent): issues +
   discussions are both still disabled (verified via `gh`
   this session), so every demand-gated item (Idea 7,
   secret types, exporters, walk/patch resume) is decided by
   silence. Enable discussions (low-noise) to give strangers
   a door? Or keep the moat and let demand arrive by email?
2. Secret-type boundaries (2nd ask): still no asks, so no
   new matchers proposed. Confirm the standing rule: named
   victim + corpus evidence before any new secret type?
3. Winget submission: G37 staged validated local manifests
   but filed no community PR (`packaging/winget/`, README
   documents the local-manifest install). File the
   winget-pkgs PR now, or keep staged manifests + docs?
   Needs a human with a Microsoft account; blocks nothing
   in this slice.
4. "24 hour" (3rd ask): still assuming depth signal. If it
   means a scheduled 24h-later follow-up, say so.
5. Resume demand probe: has a long `-walk` or git-history
   (`-patch`) scan ever actually been lost to interruption,
   or is batch + raw + range resume coverage enough? A "yes,
   it hurt" schedules walk/patch resume; silence keeps them
   demand-gated.

## Proposed slice (Goals 43–45)

For approval — implement in rank order, per-goal audits as
before. No hard dependencies between the three; order is
smallest-highest-trust first:

- Goal 43 (follow-up routing + exit honesty): advise sniffs
  bounded magic and stops misrouting wallet copies and
  containers; `-watch` joins the exit-0-on-empty contract.
  Smallest scope, first user touchpoint, zero sibling risk.
- Goal 44 (FAT deleted LFN recovery): closes the
  code-admitted recall gap against the `fls` oracle on the
  owner-backup medium. Precedented harness, medium-small.
- Goal 45 (multi-volume `-fs` checkpoint): full-disk `-fs`
  journals like unallocated already does. Largest of the
  three; land after the sibling's gate work settles shared
  range-resume tests.

Then, only on demand or user answers: walk/patch resume
(Q5), Idea 7 filesystems (Q1), secret types (Q2), zip
scaling revisit (post-sibling profile), winget PR (Q3).
