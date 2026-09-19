# Resource bounds vs hostile images

The scanner ingests untrusted bytes. Threat model: a malicious or
pathological image tries to exhaust RAM or hang the scan. Every bound
below is enforced in code (comment next to the constant), and the
worst cases have fixtures in `detector/resource_test.go` with generous
hang-catcher guards.

## Bounds

- **Zip member inflation** (`maxZipMemberBytes`, 1 GiB): honestly
  declared giants are skipped at publish; `inflateCapped` re-checks
  actual bytes at Open so lying headers cannot bypass it (the recovery
  path inflates raw flate, where this is the only enforcement;
  `archive/zip` additionally enforces declared sizes on read).
  Nesting multiplies per level, capped by `maxArchiveDepth` (8).
- **E01/S01 chunks** (`ewfMaxChunkBytes`, 64 MiB): chunk inflation is
  limited to chunk size +1; over-inflating chunks fail loud naming the
  chunk. Tables claiming more chunks than the volume declares fail
  eager parsing. Peak EWF RAM is otherwise ~the largest segment file
  (held during eager parse) — documented, not limited, since honest
  segments are gigabytes.
- **E01/S01 sets** (`ewfMaxSegments`, 99): the extension scheme ends
  there.
- **Gzip members** stream sequentially (no full inflation); depth
  capped by `maxArchiveDepth`. Time scales with inflated bytes.
- **Partition tables**: EBR chains (`maxEBRChain`, 64), GPT entries
  (`maxGPTEntries`, 4096) and array bytes (`maxGPTArray`, 16 MiB).
- **NTFS**: MFT records per volume (`mftRecordCap`, 1M).
- **Whole-file modes**: `-hashes`/`-salvage`/`-watch` inputs
  (`HashScanMaxBytes`/`SalvageMaxBytes`/`WatchScanMaxBytes`, 256 MiB).
- **Pipeline**: 1M pending-target buffer (~16 MiB of pointers), then
  publishers block; per-file sweep failures capped at 32 retained
  (`maxWalkFailures`, count unbounded).

## Non-bounds (accepted)

- Scan time is proportional to (inflated) input bytes; there is no
  wall-clock cap. Hang-catchers in tests assert completion, not speed.
- No process sandboxing; no formal verification (explicit non-goals).
