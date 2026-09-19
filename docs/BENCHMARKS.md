# Throughput benchmarks

Committed benchmarks (`detector/benchmark_test.go`) scan fixed
deterministic fixtures — 32 MiB raw, 8 MiB through a nested zip, 32 MiB
through E01 (mixed compressed/stored chunks) — with a wallet needle per
MiB so detection, not just I/O, is exercised:

    go test ./detector/ -run '^$' -bench 'BenchmarkScan' -benchtime 1x

## Reference table

Machine: 8× Intel i7-7700K @ 4.20 GHz, 31 GB RAM, Linux, Go 1.24.1.
Single 1× runs; MB/s is decoded-media bytes per second.

| Benchmark | Before (MB/s) | After (MB/s) | Speedup |
|---|---|---|---|
| Raw 32 MiB | 0.8–1.1 | 9.6 | ~10× |
| Nested zip 8 MiB | 0.34 | 3.7 | ~11× |
| E01 mixed 32 MiB | 1.25 | 10.5 | ~8× |

The full `go test ./...` suite dropped from ~80 s to ~22 s on the same
machine, an independent confirmation.

## What the profile found (Goal 15)

1. **Near-miss windows (42% of CPU + GC pressure).** Every window
   position allocated a gap list and `fmt.Sprintf` dedup keys, the
   Levenshtein DP allocated per row, and checksum trials allocated per
   attempt. Now: allocation-free gap counting, struct dedup keys built
   after the cheap filters, stack DP buffers, one reused trial buffer.
2. **SLIP39/Electrum windows (9 GB alloc per 32 MB scan).** Word slices
   were allocated per window before validity was known, and Electrum
   re-lowered every token per window. Now: validity-first builds,
   once-per-token lowering, length-gated list lookups.
3. **Gzip pre-filter (15 GB re-inflation per 8 MB nested scan).** Every
   random `0x1f8b` opened the source for a sanity check, and opening a
   zip member inflates it whole. Now: the in-block header bytes must
   show CM=8 with clear reserved bits (exactly what `gzip.NewReader`
   demands) before the source is opened; undecidable tails still take
   the full check.

All three preserve detection semantics: no needle, window, or checksum
rule changed, and the full suite (including overlap/exact-offset
fixtures) stays green.

## Not revisited

The 1 GiB per-member zip inflation cap stays: no streaming member
reader landed (Goal 15 step 3 was conditional on one). Members still
inflate fully into RAM under the cap.
