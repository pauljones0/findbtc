# G42b no-drop design — covered-set banking + defer-covered admission + flush rewind

## Problem (027)
Same-cap resume replays the same admitted prefix forever: cap3 over a
padded 10-member zip admits the same first-3 ECD burst members every
attempt, drops the same 7, journals the same 1MB point, never
converges. Cap-raising retry is not proof (users cannot change the
constant). Separately, the EOF-deferred zip-recovery flush publishes
at root EOF, after all mid-run frontiers — a trip there concerns
pre-frontier bytes, so no mid-run point is proven (flush-poison:
uncongested retry from the frozen point certifies complete with 0/10
re-covered).

## Design
Checkpointed nested cursor, set-based (robust to publish reorder):

1. Stable member identity. Every nested publish site derives a key
   from (archive identity, member selector): ECD members
   `source.Describe() + "#zip:" + fileIndex`, recovered entries
   `...#zipentry:" + dataOff`, gzip members `...#gzip:" + offset`.
   Keys must be STABLE across resume attempts (same input, different
   start offsets) — verified against Describe() impls before
   implementing; root offsets normalized out if needed.
2. Covered-set banking. scanBlocks banks a member's key when its
   nested read completes (delivered bytes). The set lives in the
   gate (mutex-guarded; publishers + consumer share it), seeds from
   the journal at run start (detector loads CheckpointPath itself),
   and persists on every journal write (uniform with offsets).
   Journal format: Checkpoint.Covered []string (+ BatchTarget.Covered
   for batch). Opaque strings; cross-target contamination inert
   (keys embed source identity). Bound: O(total nested members read).
3. Defer-covered admission. gatePublish checks the covered set
   FIRST: covered members return unpublished WITHOUT consuming a
   gate slot and WITHOUT counting a skip. Only uncovered refusals
   count toward drain-then-error. EOF accounting unchanged (only
   admitted publishes counted — verified at all call sites).
4. Flush-path rewind. A flush-publish refusal sets a deferredSkipped
   flag (flush-specific wrapper); on drain-then-error with the flag
   set, the journal offset rewinds to the run-start offset (no
   mid-run point is proven for deferred bytes). The covered map is
   kept (banked reads are sound). Eager-only trips keep the
   barrier-proven freeze rule (unchanged).
5. Completion: EOF + zero uncovered skips. Converged final attempt
   journals completion; the covered set is dropped there (completion
   subsumes it).

## Why it converges (same-cap cap3, 10 members)
Burst order is ECD order; outstanding is 0 at the burst (1MB drain
consumed everything before it), so attempt 1 deterministically banks
{0,1,2} and errors; attempt 2 defers them, banks {3,4,5}, errors;
{6,7,8}; then {9} with zero skips -> complete. 4 attempts =
ceil(10/3). General: cap>=1 admits >=1 uncovered per attempt
(first publish always admitted), so progress is monotonic and
convergence takes <= #members attempts. Cap 0 still errors with
zero progress (pinned degenerate behavior, unchanged).

## Deliberate contract change: no cross-attempt duplicates
Covered members are never re-read, so concatenated -json outputs
carry each nested hit EXACTLY once (previously: full nested
duplicates on every resume; seam dedup was required reading).
Root-seam re-emission is unchanged (root bytes still rewind).
Kill+resume+pipe is strictly improved; terminal-only killed-run
hits were already documented as lost. Same-day tests move to union
semantics (congested-vs-baseline, kill, torture) with comments.

## Non-goals / residuals
- Cumulative multi-attempt digest (converged entries complete
  without digest -> identity-only skip; sound, weaker).
- Covered-set size cap (O(members) transient journal; completion
  drops it; million-member hostile input noted as residual).
- -max-nested-backlog CLI recourse (approved follow-up after this).
- No pipeline/drain/barrier/gate-cap changes: publish path stays
  non-blocking, so the scanBlocks->stage-queue deadlock cycle is
  never introduced. Zero main.go changes (file-authoritative).

## Acceptance
- TestPubGateSameCapRetryCompletes (in-repo 027 probe).
- TestPubGateFlushSkipRetryRecovers (flush-poison probe).
- Root frozen probes (026 + 027) via overlay against final sources.
- Existing gates green incl. torture (union semantics) + kill tests.
- Adversarial breaker worker on the final diff.

## Addendum — ancestor poisoning (found via torture union 20258 != 22500)
Banking a parent does not imply its children were covered: a
skipped leaf's banked ancestors would defer next run and strand
the leaf forever. Fix: every publish attempt records its parent
link; a refusal poisons the ancestor chain (parentKeyOf type
switch over the three nested target types); filing subtracts
poisoned keys, so the journal only files subtree-complete
members. Filed-covered therefore implies subtree fully
admitted+read (EOF) or discarded (cancel writes nothing), which
makes deferral sound; mid-run filings stay sound by the same
barrier-ordering argument (post-point skips concern other
subtrees). Error paths file the covered snapshot at the frozen
point (else banking dies in memory and retries replay);
deferred-flush trips additionally rewind the offset to run
start. Torture union now exactly 22500/22500, empty
intersection; same-cap converges 3->6->9->10 in 4 attempts.
