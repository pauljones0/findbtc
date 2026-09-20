## Goal

Resumable multi-target recovery (GOALS.md Goal 42): a long batch
(`findbtc -checkpoint batch.journal -targets batch.txt ...`, or
positional multi-target) can be interrupted — including by real
SIGKILL under backpressure — and resumed without silently losing
coverage, repeating claims, or trusting changed/missing/reordered
inputs as already scanned. (v2: incorporates Supervisor 022
correctness requirements; direction approved, proceed authorized.)

## Success Criteria

- Kill between targets, then resume: stdout (appended), carve dir,
  and case-log claims are byte-exact vs an uninterrupted cold run
  (modulo case-log timestamps), with skip announcements naming
  each skipped target.
- Kill midway through a later target, then resume: detection-set
  union equals the cold set including a needle straddling the
  journal point; only the documented rewind window may re-report.
- Real SIGKILL under induced backpressure (nested-heavy media +
  large-context carves), at any point: resumed detection union
  equals the cold set; carves are a content-superset within a
  stated count bound; case-log claims verify; coverage completes.
- Changed/truncated/missing inputs rescan or attempt loudly,
  never skip — including same-size mutation with restored
  mtime (caught by digest re-validation); reordered/different
  lists and corrupt journals refuse loudly (exit 1).
- Skip evidence is bound to this journal/run: target
  index+identity, scan options, covered intervals, and output
  artifacts; completion-record-before-manifest and
  manifest-before-ack faults both resolve loudly to skip or
  safe rescan, never a false skip.

## Context And Current Facts

- Batch loop (`main.go` `runMultiTarget`, Goal 38) scans targets
  in order with a shared hits stream, per-target case-log
  records, and `CarveSeqStart` threading; multi+checkpoint
  refuses at `main.go:319`.
- Single raw resume (`main.go:357`): reads `Checkpoint{Path,
  Offset}`, requires path match, `start = cp.Offset`, no
  rewind — a needle straddling the 1MB journal point is
  silently lost (resume seeks exactly, `haveTail=false`).
  Only the announcement line is tested
  (`TestResumePrintsPosition`); no detection-equivalence test.
- Range resume (`detector.go` `ScanRangesWithOptions`, Goal 17)
  is the proven pattern: exact range-list match or loud
  refusal, grid-aligned `rewindOffset` preserving
  `block_offset`, position announcements, already-complete
  short-circuit, kill-simulation fixtures with set-union
  comparison (`detector/checkpoint_test.go`).
- Journal writes (`detector/checkpoint.go`) are atomic
  tmp+rename every 1MB and at target end, from the producer
  side (`scanBlocks`); only the root target journals
  (`detector.go:763`). Nested-archive detections can arrive
  arbitrarily late via the `scanTargets` feedback loop, so a
  reader-frontier journal does not imply delivered output.
- Pipeline stages (`scanZipFiles`, `scanGzipFiles`,
  `detectWallets`) are single sequential goroutines over
  FIFO channels; nested publication order vs forwarding
  must be verified in code before placing a barrier.
- Case-log appends at target finish inside the pipeline
  (`detector.go:721`), so audit record structurally precedes
  any manifest mark main writes after return.
- Verify re-reads from `StartOffset` (`verify.go:91`), so
  resumed partial records verify; zero-byte error records
  carry no digests (Goal 41) and report `NOT SCANNED`.
- Carve names are global `hit-%06d` seq (`detector/carve.go:66`).

## Constraints And Non-goals

- No exact-once durability claim beyond proof. Real-kill
  recovery is proven for the checkpoint path via the
  drain-barrier frontier (below), not assumed.
- v1 supports raw multi-target resume only; `-unallocated-only`
  batch, `-walk`, `-patch`, stdin, `-s` keep explicit
  refusals. UNC needs no part (no fixture).
- Batch checkpoint requires `-case-log` (refuse otherwise):
  skip verification needs stored digests. Single-target
  checkpoint keeps legacy behavior.
- Identity starts at path+size+mtime but skip requires
  digest re-validation of covered bytes (full re-read,
  cost documented); same-size same-mtime swap is
  therefore caught, not trusted.
- Synthetic disposable fixtures only; offline; no real wallets.

## Key Decisions

1. **Extend the journal, don't add a file.** `Checkpoint`
   gains `targets[]` (`path,size,mtime,state,offset`;
   `state=pending|active|complete|failed`) plus bound run
   options (`profile,carveDir,context,json,reveal,
   baseline,caseLog`); presence of `targets` means batch
   journal. Same atomic writer, same `-checkpoint` flag.
   Legacy journals (absent) refuse in batch mode with a
   directional error, keep working single.
2. **Close the raw-resume straddler gap (required).**
   Resume rewinds to the grid at/before offset-overlap by
   reusing `rewindOffset` (exported for main's
   announcement); `-s` never rewinds (only the resume
   path applies it). Bounded rewind re-reports are
   documented, mirroring ranges.
3. **Drain-barrier safe frontier (022-1).** On the
   checkpoint path only, each 1MB journal point and each
   target-end mark first drains the pipeline to
   quiescence: a barrier sentinel traverses the FIFO
   stage chain while `scanBlocks` keeps consuming the
   nested backlog; an atomic publications counter
   proves nothing was published after the barrier, so
   barrier-ack plus empty backlog means every byte at
   or before the frontier is fully delivered. The
   journal then records a *delivered* frontier, and a
   real SIGKILL loses only post-frontier bytes, which
   resume re-covers. Steady-state concurrency is
   unchanged; only journal points pay a drain stall.
4. **Skip rule with bound evidence (022-2, 022-3).**
   Resume skips a target only with ALL of: manifest
   `complete` for this index+path; identity match
   (size+mtime); bound run options identical (else
   refuse); case-log `complete` record for the target
   whose digest re-validates over a fresh re-read of
   the covered bytes; expected carve files present
   (per-target seq range recorded at mark time).
   Kill between case-log append and manifest mark
   resolves via the case-log record plus manifest
   identity (skip, zero dups); kill between manifest
   mark and output ack cannot happen (mark follows
   the drained frontier); anything unproven rescans
   loudly. Torn journal lines, swapped/truncated logs,
   and changed carve destinations refuse or rescan —
   never skip.
5. **Carve continuation by dir-scan, not journaled counts.**
   Resume continues numbering past the max existing
   `hit-*.bin` (announced). Never overwrites, immune to
   stale counts; reuses `CarveSeqStart` threading.
   (Contingent: atomic tmp+rename carve writes if the
   write path allows it trivially, so killed runs leave
   no torn carves.)
6. **Strict list match, loud retries.** Resume requires
   the exact ordered target list or refuses (exit 1).
   Changed/truncated rescans from 0 (loud); missing
   re-attempts (loud `NOT SCANNED` path); failed entries
   always retry; all-skipped exits 0 "already complete"
   (mirrors `TestRangeResumeAlreadyComplete`).
7. **Equivalence standard.** Between-target kill:
   byte-exact (stdout/carves/case-log modulo timestamps).
   Mid-target kill: set-union (G17 `detSet` precedent)
   plus resumed-record `StartOffset` pinned to the
   rewound point (proves no secret rescan) and skip
   announcements naming every skipped target. Real
   SIGKILL: detection union exact; carves
   content-superset within a stated bound (rewind
   window plus at most one torn write).

Rejected: fingerprint-journal zero-dup (new artifact,
marginal gain); blind trust of historical case-log
completes (022-2 forbids); metadata-only identity
(022-3 forbids); clever list reconciliation (refuse
instead); carve names with offsets (breaks pinned
contract); full async ack-plumbing outside the
checkpoint path (barrier achieves the proven frontier
with confined surgery).

## Recommended Approach

1. Detector: `Targets` batch schema + run-options
   binding + validation in `checkpoint.go`;
   batch-aware branch in `writeScanCheckpoint` (new
   `Options.BatchJournal` pointer, single-writer from
   `scanBlocks`); drain-barrier sentinel + ack +
   publications counter + quiescence wait confined to
   journal points; export rewind helper; skip-proof
   reader reusing verify parsing + digest re-check.
2. Main: require `-case-log` with batch checkpoint;
   lift the multi+checkpoint refusal for raw batches;
   build/refresh the manifest in `runMultiTarget`
   (identity stat, transitions, skip/announce/rescan
   rules, all-complete short circuit, dir-scan carve
   continuation); apply rewind to raw resume starts +
   announcements.
3. Docs: update refusal messages, flag help, README/
   man batch passages; document rewind duplicates,
   drain stalls, re-read cost, identity/digest rules,
   and bound options.
4. Fixtures (ranked): raw mid-target kill with
   O-straddler; batch boundary kill (byte-exact);
   batch mid-target kill (set-union); real SIGKILL
   under backpressure vs cold (unix gate test, real
   binary); same-size+mtime-restore mutation,
   truncated, missing, reordered, corrupt table;
   boundary-state injection (manifest/case-log each
   way); refusal cases; baseline+resume numbering;
   secrets-absence in journal/manifest.

## Work Plan

1. Schema + options binding + validation + unit tests
   (round-trip, corrupt table, shape-mismatch errors).
   Depends on: none.
2. Drain-barrier frontier + stage-order verification;
   raw-resume rewind + announcement + mid-target raw
   fixture; update `TestResumePrintsPosition` golden.
   Depends on: 1.
3. Batch manifest lifecycle in `runMultiTarget` +
   boundary byte-exact fixture. Depends on: 1.
4. Mid-target batch, real-SIGKILL gate test, mutation/
   identity/missing/reorder/injection/refusal/baseline
   fixtures. Depends on: 2, 3.
5. Docs + help + man updates; full gate; push; CI read.
   Depends on: 4.

## Validation Plan

- `go test ./detector/ -run 'TestBatch|TestRange|TestResume|TestCheckpoint|TestCaseLog|TestVerify'` — focused suites green.
- `go test . -run 'TestMultiTarget|TestResume|TestBatch|TestRehearsal|TestPassword|TestBatchKill'` — CLI surfaces green.
- `gofmt -l .`, `go vet ./...` clean; full `go test
  ./...` gate green locally or same-source CI green.
- CI `ci` workflow all jobs green (matrix incl.
  Windows, gates, handoff, rehearsal).
- Fixture evidence bar: boundary kill byte-exact
  (diff empty modulo timestamps); mid-target union
  exact incl. straddler; real-kill union exact with
  carve bound; mutation/mismatch exit paths with
  messages asserted; resumed `StartOffset` pinned;
  journal/manifest carry no secret bytes.
- Highest-risk validation: the drain-barrier
  quiescence proof under real SIGKILL (any kill
  point must union) and the skip-proof digest
  re-validation (mutation fixture).

## Risks / Rollback

- Rewind changes single-target resume output (new
  straddler hits + window dups; announcement offset
  shifts to the grid point): intended, golden test
  updated, README example untouched (illustrative).
- Drain stalls add latency at 1MB points on
  checkpoint runs only; non-checkpoint runs
  untouched. Deadlock risk in the barrier loop is
  contained by the finite-publications argument
  plus a loud stall timeout (refuse-safe: journal
  skipped with warning, scan continues — never a
  false frontier).
- Old binaries reading batch journals resume target 1
  from 0 (safe direction: full rescan); new binaries
  refuse legacy journals in batch loudly.
- Rollback: revert the lifted refusal + batch branch;
  schema is additive (`omitempty`), legacy journals
  unaffected.

## Open Questions

None — all material facts verified in the workspace;
022's three correctness requirements are incorporated
above as decisions 3, 4, and the digest rule.
Alternatives ranked: no more consequential concrete
owner pain found in code/ledger review; UNC proof
recorded as explicit future work, not a substitute.

## Addendum 2026-09-20 13:15 Regina — 025/026/027 publication-gate sequence

- 025/026: gate drops + nil error + case-log complete = false
  durable completion (frozen receipt 10/10 vs 3/10). Repaired on
  d183600 with drain-then-error (EOF with skipped>0 returns
  incomplete-coverage error; case-log error; batch failed-never-
  complete) + journal freeze (no frontier journals after a skip is
  counted). Root frozen acceptance TestRootPublicationCoverageCaseLog
  passes on the repaired sources.
- Independent review (needs-changes): falsified barrier-ordering
  for the EOF-deferred zip-recovery flush (flushZipCandidates
  publishes at root EOF, after all mid-root frontiers — a trip
  there concerns pre-frontier bytes; probe: retry certifies
  complete with 0/10 re-covered). Also: no CLI recourse for huge
  archives (-max-nested-backlog flag approved as follow-up),
  -race log-sink race (pre-existing sink, new concurrent call
  site), exact-count determinism, dead pendingFrontier.complete.
  Eager-publish ordering, EOF predicate, deadlock-freedom of the
  current gate, kill window (intact inputs), case-log error choice,
  and batch/range/stdin inheritance all challenged and held.
- 027: same-cap resume replays the same admitted prefix forever
  (cap3: same 3/10 x4 attempts, offset stuck at 1MB, never
  complete — receipt findbtc-same-cap-retry-ebz_8pi2). Cap-raising
  retry is not proof. Requires no-drop bounded scheduling that
  makes progress under unchanged limits; honest error stays as the
  safety floor. Owner analysis: naive blocking publishes deadlock
  via the scanBlocks->stage-input-queue cycle (not just the
  barrier); at least one side of every handoff must stay
  non-blocking. Delegated to isolated workers (design+impl,
  same-cap/flush-poison acceptance, review follow-ups) + shared
  torture proof; integration owner merges, gates, pushes, reads CI.
