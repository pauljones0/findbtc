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

Range scans (`-fs` over one volume, `-unallocated-only`) journal
`(range_index, offset)` the same way. Resume first checks the journal's
range list still matches the volume's exactly — a changed filesystem
refuses loudly rather than silently skipping bytes, so re-image and
start over if the evidence moved. The resumed range rewinds to its 4kB
block grid just before the journal point, so patterns straddling the
interruption still match and the resumed detection set is identical to
an uninterrupted run (the re-scanned window may re-report hits already
printed before the kill — deduplicate by `(needle, offset)` when
merging outputs). One journal holds one range list: checkpointing is
refused across several auto-seeded volumes in one `-fs` run — pin one
volume with `-fs-offset` and journal each volume separately.

## 4. Read the case log

`-case-log case.jsonl` appends one JSON record per scan:

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
