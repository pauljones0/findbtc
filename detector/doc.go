// Package detector scans bytes for cryptocurrency wallet traces: key
// material, seed phrases, keystores, and wallet-file residue on raw
// devices, forensic images, filesystems, and directory trees.
//
// # Quick start
//
// Scan a path and collect detections with a closure (see
// ExampleScanWithOptions for a runnable version):
//
//	var hits []detector.Detection
//	err := detector.ScanWithOptions(0, path, detector.Options{},
//		func(d detector.Detection) { hits = append(hits, d) },
//		nil) // progress ignored
//
// Entry points by job:
//
//   - Raw bytes, devices, EWF/split images: Scan, ScanWithOptions.
//   - Piped input (dd/ssh): ScanStdinWithOptions spills the stream
//     to a bounded temp file, then scans it like a file.
//   - Filesystem unallocated space: UnallocatedRangesAuto, then
//     ScanRangesWithOptions over the extents.
//   - Deleted files with names (-fs): ScanFS, ScanFSVolumes.
//   - Directory trees (-walk): Walk.
//   - Reports: Summarize, WriteDFXML, ReadDetections.
//
// # Stability tiers
//
// Tier 1 — Stable. The Detection JSON wire format is frozen per
// schema/hits-v1.json: field names, types, and the six required keys
// (description, needle, offset, target, block_offset, match_length)
// never change within v1 — only new optional fields may appear, and
// TestDetectionJSONTagsFrozen fails the build on any drift. The same
// freeze covers the six required Go fields and the Scan /
// ScanWithOptions signatures.
//
// Tier 2 — Evolving. Everything else public may grow but not
// gratuitously break: new Options fields, new Report sections, new
// needle labels, new ProgressInfo/WalkStats counters, and new
// filesystem and partition APIs. Options.Resume and the checkpoint
// journal format are single-version crash recovery, not a
// cross-version or cross-machine protocol. Treat the journal as
// operator-local state: resume verifies content proofs and
// cross-checks filed member spans against the rediscovered
// members' own extents (zip full extent, recovery
// header-through-data, gzip start), and any mismatch re-reads
// loudly — but a gzip member's end is unknowable before it
// reads, so a hand-shrunk gzip span end is trusted up to its
// verified bytes. Never accept a journal from an untrusted
// source; when in doubt, delete it and rescan.
//
// Tier 3 — Internal. Exported only for the CLI, tests, and
// benchmarks: pipeline primitives (Block, TargetReader), exposed magic
// constants (GZIP_HEADER, ZIP_*), and anything else this comment does
// not name. Do not build on these.
//
// # Embedding
//
// Servers route diagnostics through Options.Log (nil writes stderr,
// exactly as the CLI; io.Discard silences) and enforce deadlines
// through Options.Context (nil runs to completion). A cancelled scan
// returns ctx.Err() promptly: detections already delivered stay
// delivered, the checkpoint journal keeps its last completed mark,
// the case log records status "canceled", and no pipeline goroutine
// leaks. Callbacks must return; a blocked callback blocks shutdown.
//
// # Known warts
//
//   - Results stream through callbacks; there is no slice-returning
//     API. The closure above is the pattern.
//   - startOffset comes first in ScanWithOptions for historical
//     reasons.
//   - Single-target resume is caller-driven: ReadCheckpoint, then pass
//     the journal offset back as startOffset (exact, or rewound to
//     the block grid for needles straddling the journal point —
//     the CLI rewinds). The detector verifies the journaled
//     content proof on its own handle before honoring the offset;
//     refused claims restart at zero with a warning. A start that
//     continues no journal point is taken as an explicit caller
//     assertion — except under Options.Resume, which warns and
//     restarts instead. Range scans resume inside the detector
//     via Options.Resume.
//   - Progress callbacks fire often; keep them cheap or pass nil.
//   - Detection.Target for archive members names the member stream
//     ("Zipfile #0 @ byte 0 in [...]"), not a filesystem path.
//   - Detections are candidates keyed by needle label, not proof of a
//     spendable wallet: verify before acting, especially for
//     WIF and seed-phrase hits.
package detector
