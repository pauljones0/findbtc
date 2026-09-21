# Forensic workflow

findbtc scans a copy of the evidence, never the original, and every run
can leave a paper trail a reviewer can re-derive: a case log with
streaming hashes, a verifier for those hashes, and DFXML hit export for
case tools. This page walks the workflow end to end.

## 1. Protect the original: write-blockers

Mount nothing read-write and scan nothing in place. The standard setup:

- Attach the suspect drive through a **hardware write-blocker**
  (Tableau, WiebeTech, or similar) so no host write can reach it.
- Without hardware, use the kernel's protection: add the device with
  `blockdev --setro /dev/sdX`, or mount with `-o ro,noload`, and never
  let a filesystem journal replay against it.
- Acquire to an image on separate media first (`ewfacquire`,
  `ddrescue`, `ftkimager`), then scan the image. findbtc only ever
  reads its input, but the acquisition host can still scribble on an
  unprotected original.

## 2. Acquire and hash

Hash at acquisition time, before findbtc ever sees the bytes:

    sha256sum evidence.E01 evidence.E02 > acquisition.sha256

Keep this file with the case. The case log later attests to what
findbtc read; the acquisition hash attests to what was captured.

## 3. Scan the image

Point findbtc at the image and keep a case log:

    findbtc -json -case-log case.jsonl evidence.E01 > hits.jsonl

Supported inputs, detected automatically:

- **EnCase E01** (pass the `.E01`; `.E02`, … follow) and **SMART S01**
  (pass the `.s01`; `.s02`, … follow). Compressed and stored chunks,
  single- and multi-segment sets. The scan hashes the *decoded* media
  bytes and cross-checks them against the set's stored MD5
  (`ewf.md5_match` in the case log). Layout notes: the S01 volume is
  94 bytes (same leading geometry, `SMART` marker, trailing checksum)
  and its table section carries chunk data inline with absolute file
  offsets — no sectors section; both layouts verified byte-for-byte
  against `ewfexport`.
- **EWF2 (`Ex01`/`Lx01`) is refused, not misread** (`EVF2` magic,
  compressed metadata — a different format family). Convert first
  with libewf and scan the raw output:

      ewfexport -u -t evidence -f raw evidence.Ex01
      findbtc -json evidence.raw > hits.jsonl
- **Split raw** (`base.001`, `base.002`, …): concatenated and scanned
  as one stream; any segment may be named on the command line.
- **Raw** devices and files, as before.
- **Filesystem-guided** (`-fs`, `-unallocated-only`): NTFS/ext
  inventories and range scans; each range appends its own case-log
  record.

Long scans should add `-checkpoint case.checkpoint`: an interrupted
run resumes with `-resume` instead of restarting. The case log records
the checkpoint path and the resume offset.

Range scans (`-fs`, `-unallocated-only`) journal `(range_index,
offset)` the same way. A `-fs` run over several auto-seeded volumes
journals one flattened deleted-entry range list spanning every volume;
resume first checks that full list still matches exactly — a range
list changed in ANY volume refuses loudly rather than silently
skipping bytes, so re-image and start over if the evidence moved. The
resumed range rewinds to its 4kB block grid just before the journal
point, so patterns straddling the interruption still match and the
resumed detection set is identical to an uninterrupted run (the
re-scanned window may re-report hits already printed before the kill
— deduplicate by `(needle, offset)` when merging outputs).

Batch runs (several `TARGET` files with `-checkpoint`) journal a
per-target manifest instead of one offset. Each entry tracks its
target's state — pending, active, complete, failed — plus the
proven byte offset for the in-flight one. A killed batch resumes
with `-resume`: completed targets print `batch: skipping …` and
are never rescanned, the interrupted target resumes from its
journaled offset (rewound to the block grid, same seam rule as
above), and failed targets are retried. Every crash window redoes
work; nothing is ever skipped without journaled proof.

Resume refuses loudly when the journal does not match the run:
a different target list or order, different profile / carve /
JSON / reveal / baseline / case-log options, a legacy or range
journal, or a corrupt file. Every resume decision is authorized
by a versioned content proof, not by metadata: each journal
point files a SHA-256 over the exact bytes read (the root
prefix for whole-file frontiers, the range span for active
range frontiers, the full span for completed ranges and
targets), and the next run re-reads and re-hashes that span on
the same handle it then scans before honoring the offset, the
skip, or any banked member. Anything else — a same-size
replacement, a touched-up timestamp, a changed-middle rewrite,
a remapped device, a swapped EWF/split segment, or a journal
from an older binary that never recorded proofs — rescans from
the start with a warning. (A new journal opened by an old binary
degrades to that binary's own rules — digest re-hash where the
journal carries a digest, metadata otherwise — so upgrade the
binary, not the journal.) Metadata (device, inode, size,
timestamps) is only a cheap rejection tier that skips the
re-read when the bytes obviously moved; a metadata match alone
authorizes nothing, so weak-metadata shapes (Windows in-place
rewrites with restored timestamps, coarse-clock filesystems,
stale NFS attributes) all fail closed at the proof. Banked
nested members additionally carry the archive span they derive
from and are kept only inside verified bytes, so a prefix proof
never blesses members outside it — with one qualification for
gzip: a member's end is unknowable before it reads, so deferral
checks the filed start alone and a hand-shrunk span end is
trusted up to its verified bytes (same trust boundary as the
journal itself: operator-local state, never accept a journal
from an untrusted source). Zip and recovery extents check in
full. Explicit `-s` starts are caller assertions, never proven
bytes: their journals file span proofs a later `-resume`
refuses, rescanning from zero.

The honest price is re-reads: a resume sequentially re-hashes
the bytes it skips (no detection work, usually page-cache hot),
completed-target skips re-hash the full stream, and range
resumes re-verify every completed range. Budget roughly one
extra sequential pass over skipped bytes — measured on this
machine: re-verifying a 256 MiB prefix takes ~2 s (page-cache
hot) against a ~39 s full scan. Two contracts remain
with the operator: quiesce writers during scans. For plain
files scanned with journaling on (`-checkpoint`), a concurrent
write is detected and warned — the run baselines the source at
open and re-checks at root end, and completed skips check
stability before and after the re-hash — but uncheckpointed
plain scans run no pre/post check, and decoded sources (EWF
sets, split spans) carry none either: a mid-scan mutation there
is silent this run, and the next resume's proofs fail closed
and rescan. Exact concurrent guarantees need a snapshot or
write exclusion the tool does not claim,
and re-image evidence whose bytes may have changed on a medium
that cannot be re-read identically (failing media: resume
re-reads fault the same way the scan did, so finish bad-media
scans in one run when possible).

A congested run — more nested archives in flight than the
publication cap admits — drains what it admitted and then fails
honestly with an `incomplete coverage` error instead of clean
completion: the case log records status `error`, the checkpoint
keeps its last skip-free proven point plus the banked members it
already read (completion never journals), and a batch entry lands
in `failed`, never `complete`. Resume retries from the frozen
point and covers only the omitted members — banked ones defer,
so same-cap retries converge (a handful of attempts for a
ten-member burst) and concatenated `-json` outputs carry each
nested hit exactly once, with no cross-attempt duplicates. (A
directory-less recovery trip additionally rewinds the offset to
the run start, since its bytes precede every mid-run point.)
Root-seam re-emission keeps the dedup rule above.

Carves survive kills: every carve file commits atomically (a kill
leaves complete files, never torn bytes), a resumed run continues
carve numbering past the pre-kill files instead of overwriting
them, and staging files from killed runs are reaped on the next
start. Hits re-derived in the rewind seam carve again under new
numbers — deduplicate carved bytes by content hash when merging.

Two loss notes. First, stdout printed before a SIGKILL is gone
with the process: pipe `-json` output to a file
(`-json … > hits.jsonl`) so kill plus resume concatenate to the
full set. Second, zip members recovered from local headers (no
central directory) and discovered before the journal point stay
discovered only when intact archives re-announce them on resume;
genuinely directory-less fragments ahead of the frontier are a
known resume boundary — re-image and run uninterrupted when that
class of evidence matters.

## 4. Read the case log

`-case-log case.jsonl` appends one JSON record per requested target (a
multi-target run appends one record per target, in scan order;
range scans append one per range, as above). A target whose scan
never starts (missing file, unreadable source, refused flag
combination) still leaves one record: status `error`, kind
`unknown`, zero bytes hashed and empty digests — an outcome with
no invented coverage. `-verify-case-log` reports such records as
`NOT SCANNED` without failing; anything hashed still verifies by
hash. Exit 0 therefore vouches for the log's honesty, not for
complete coverage: a log whose records are all `NOT SCANNED`
still exits 0 — count the `complete` records to confirm what
was actually covered:

- `source`: path, kind (`raw`, `ewf`, `split`, `range`), size,
  start offset, checkpoint path.
- `hash`: streaming SHA-256 and MD5 over exactly the bytes read —
  `[start_offset, size)` minus `skipped_ranges` — plus the byte count.
- `skipped_ranges`: unreadable spans that were retried, skipped, and
  excluded from the hash, with the underlying error.
- `detections`: hit count. `flags`: the exact invocation.
  `ewf.stored_md5` / `md5_match`: the E01 cross-check (null when the
  scan did not cover the whole media, e.g. a resume).

## 5. Verify before relying on it

Re-hash the evidence behind the log. Any change since the scan —
tampered source, edited log, newly unreadable bytes — fails:

    findbtc -verify-case-log case.jsonl
    # record 1: OK evidence.E01 (1048576 bytes hashed)

Exit status is nonzero on any mismatch, and each line says which
record failed and how. Run this on the reviewer's machine against
their copy of the evidence; a clean report means the bytes behind
the log are intact.

## 6. Export hits to case tools

`-dfxml` converts saved hits to DFXML 1.1.1 (one `fileobject` per
hit, `byte_run` at the hit offset), which Autopsy and DFXML
pipelines ingest:

    findbtc -dfxml hits.jsonl > hits.dfxml

The output validates against the NIST `dfxml_schema`
(`version="1.1.1"`); seed words are never exported, even from
`--reveal` input. `-report hits.jsonl` stays the human-readable
triage summary.

Stability note: the findbtc XML namespace
(`.../jakewins/findbtc/ns/dfxml#`) deliberately keeps its original
host even though the project moved — namespace identifiers must stay
stable for existing DFXML consumers. It is frozen, not drift.

## 7. Carve with custody

`-extract-dir` carves still write `hit-NNNNNN.bin` plus a JSON
sidecar naming the source and offsets. Keep carves on separate media
from the evidence, and hash them with the case log:

    sha256sum -c acquisition.sha256 && sha256sum carves/* >> case-hashes.txt

## What findbtc does not do

Case management and timeline analysis are out of scope: there is no
case database, no super-timeline, no multi-examiner workflow. The
deliverables are the scan, its hashes, and portable exports —
everything else belongs in the case platform that ingests them.
