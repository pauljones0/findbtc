package detector

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Checkpoint records scan progress so an interrupted scan can resume without
// re-scanning completed bytes. Ranges == nil is a legacy single-target
// journal (Offset is an absolute file offset); otherwise Offset is an
// absolute offset within Ranges[RangeIndex].
type Checkpoint struct {
	Path    string    `json:"path"`
	Offset  int64     `json:"offset"`
	Updated time.Time `json:"updated"`
	// Ranges and RangeIndex appear only on range-scan journals (-fs,
	// -unallocated-only). Absent fields mean a legacy journal.
	Ranges     []FSExtent `json:"ranges,omitempty"`
	RangeIndex int        `json:"range_index,omitempty"`
	// Targets and Run appear only on batch journals (Goal 42):
	// Targets mirrors the ordered input list with per-target
	// state, Run binds the scan options the journaled
	// progress was produced under. len(Targets) > 0 is the
	// batch discriminator; legacy journals omit both.
	Targets []BatchTarget `json:"targets,omitempty"`
	Run     *BatchRun     `json:"run,omitempty"`
	// Covered banks nested targets fully read in congested runs
	// (G42b): each entry is the member's cover key (Describe plus
	// size discriminators) with a |rootext=A-B provenance span
	// naming the absolute stream bytes the member derives from.
	// A retry defers re-publishing banked members, so same-cap
	// attempts converge instead of replaying the same admitted
	// prefix. Completion drops the list (it subsumes it). Opaque
	// to old binaries, whose plain keys never match and re-cover.
	Covered []string `json:"covered,omitempty"`
	// Size and Mtime identify the bytes the journaled progress —
	// including Covered — was produced from. They are cheap
	// human-readable checks only; reuse is authorized by Proof,
	// never by these. Zero/absent on journals from older
	// binaries.
	Size  int64 `json:"size,omitempty"`
	Mtime int64 `json:"mtime,omitempty"`
	// Ident is the kernel-attested run-start identity (device /
	// inode / size / mtime / ctime): the cheap rejection tier in
	// front of Proof. Absent on older journals, which rescan.
	Ident FileIdentity `json:"identity,omitempty"`
	// Proof pins the exact bytes the journaled Offset and
	// Covered were produced from (see proof.go): the frontier is
	// honored only after the span re-reads and hashes equal on
	// the opened handle. Absent on journals from older binaries
	// and on runs that never read a provable prefix (explicit -s
	// skips); both rescan.
	Proof *PrefixProof `json:"proof,omitempty"`
	// RangeProofs pins each completed range of a range-scan
	// journal; resume re-verifies every one before skipping it.
	// Absent on journals from older binaries, which rescan.
	RangeProofs []RangeProof `json:"range_proofs,omitempty"`
}

// Batch target states: pending (never started), active (in flight,
// Offset journals its frontier), complete (fully scanned),
// failed (attempted, error recorded — always retried on resume).
const (
	BatchPending  = "pending"
	BatchActive   = "active"
	BatchComplete = "complete"
	BatchFailed   = "failed"
)

// BatchTarget is one batch entry's journaled state. Size -1 with
// Mtime 0 means identity unknown (target missing when statted);
// unknown identity never matches, so such entries always rescan.
// SHA256 pins the covered bytes for clean full-pass scans (empty
// otherwise): a skip re-hashes before trusting it.
type BatchTarget struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Mtime  int64  `json:"mtime"`
	State  string `json:"state"`
	Offset int64  `json:"offset"`
	SHA256 string `json:"sha256,omitempty"`
	// Covered banks nested targets fully read while this entry
	// ran congested; see Checkpoint.Covered. Main adopts the
	// filed list like Offset/SHA256 and never invents one.
	Covered []string `json:"covered,omitempty"`
	// Ident attests the run-start bytes Offset/Covered describe;
	// see Checkpoint.Ident: the cheap rejection tier only.
	Ident FileIdentity `json:"identity,omitempty"`
	// Proof pins the exact bytes Offset/Covered were produced
	// from; see Checkpoint.Proof. Resume honors filed progress
	// only after this span re-verifies on the opened handle.
	Proof *PrefixProof `json:"proof,omitempty"`
}

// BatchRun binds the run options progress was produced under.
// Resume refuses when any of these differ: different options
// mean different coverage or differently-shaped outputs, and a
// journal must never promise another run's artifacts.
type BatchRun struct {
	Profile  string `json:"profile"`
	CarveDir string `json:"carve_dir"`
	Context  int64  `json:"context"`
	JSON     bool   `json:"json"`
	Reveal   bool   `json:"reveal"`
	Baseline string `json:"baseline"`
	CaseLog  string `json:"case_log"`
}

// IsBatch reports whether cp is a batch journal.
func (cp Checkpoint) IsBatch() bool {
	return len(cp.Targets) > 0
}

// Journal the root target every N blocks (256 x 4kB = 1MB).
const checkpointBlockInterval = 256

// writeCheckpoint atomically records that path is scanned up to offset.
// Journal failures warn; they must never fail the scan itself. ident is
// the RUN-START identity: filing write-time identity would bless stale
// progress when bytes change mid-run, so callers capture it once up
// front and file it at every point. proof pins the bytes read (see
// proof.go); nil files an unprovable point, which resumes rescan.
func writeCheckpoint(log io.Writer, file, path string, offset int64, covered []string, ident FileIdentity, proof *PrefixProof) {
	writeCheckpointData(log, file, Checkpoint{Path: path, Offset: offset, Updated: time.Now().UTC(), Covered: covered, Size: ident.Size, Mtime: ident.MtimeNS / 1e9, Ident: ident, Proof: proof})
}

// writeCheckpointRange atomically records range-scan progress: ranges is
// the full range list (for resume validation), index the range in flight,
// offset the absolute file offset scanned up to within it. proof pins
// the active range's proven span; rangeProofs pins completed ranges.
func writeCheckpointRange(log io.Writer, file, path string, ranges []FSExtent, index int, offset int64, covered []string, ident FileIdentity, proof *PrefixProof, rangeProofs []RangeProof) {
	writeCheckpointData(log, file, Checkpoint{Path: path, Offset: offset, Updated: time.Now().UTC(), Ranges: ranges, RangeIndex: index, Covered: covered, Size: ident.Size, Mtime: ident.MtimeNS / 1e9, Ident: ident, Proof: proof, RangeProofs: rangeProofs})
}

// CheapTierReject is the path-based form of the metadata rejection
// tier for callers without an opened handle (main's resume intent).
// It reports whether filed journal progress is already disproven
// for path; false means NOT-YET-REJECTED, never authorized — the
// detector still verifies the content proof on its own handle
// before honoring anything. Open-then-fstat inside the detector
// re-checks authoritatively.
func CheapTierReject(filed FileIdentity, path string) (reject bool, note string) {
	fi, err := os.Stat(path)
	if err != nil {
		return true, "cannot stat " + path + "; rescanning from the start"
	}
	cur, ok := FileIdentityOf(path)
	pass, note := cheapTierPass(filed, fi, cur, ok, path)
	return !pass, note
}

func writeCheckpointData(log io.Writer, file string, cp Checkpoint) {
	raw, err := json.Marshal(cp)
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(file), ".findbtc-checkpoint-*")
	if err != nil {
		logLinef(log, "[checkpoint] warning: %s\n", err.Error())
		return
	}
	tmpName := tmp.Name()
	_, werr := tmp.Write(append(raw, '\n'))
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Rename(tmpName, file) != nil {
		os.Remove(tmpName)
		logLinef(log, "[checkpoint] warning: cannot write %s\n", file)
	}
}

// ReadCheckpoint loads a journal written by writeCheckpoint.
func ReadCheckpoint(file string) (Checkpoint, error) {
	var cp Checkpoint
	raw, err := os.ReadFile(file)
	if err != nil {
		return cp, err
	}
	if err := json.Unmarshal(raw, &cp); err != nil {
		return cp, fmt.Errorf("bad checkpoint %s: %w", file, err)
	}
	if cp.Path == "" || cp.Offset < 0 || cp.RangeIndex < 0 {
		return cp, fmt.Errorf("bad checkpoint %s: missing path or negative offset", file)
	}
	if cp.Proof != nil && !validPrefixProof(cp.Proof) {
		return cp, fmt.Errorf("bad checkpoint %s: malformed content proof", file)
	}
	for i, r := range cp.Ranges {
		if r.Start < 0 || r.Len <= 0 {
			return cp, fmt.Errorf("bad checkpoint %s: range %d has non-positive geometry", file, i)
		}
	}
	for i, p := range cp.RangeProofs {
		if !validRangeProof(p) {
			return cp, fmt.Errorf("bad checkpoint %s: range proof %d is malformed", file, i)
		}
	}
	if err := validateBatchTargets(file, cp.Targets); err != nil {
		return cp, err
	}
	if len(cp.Targets) > 0 && cp.Run == nil {
		return cp, fmt.Errorf("bad checkpoint %s: batch journal without run options", file)
	}
	return cp, nil
}

// validateBatchTargets checks batch entries: known states, at most
// one active, sane geometry. Size -1 (unknown, missing at stat)
// is allowed; anything lower is corrupt.
func validateBatchTargets(file string, targets []BatchTarget) error {
	active := 0
	for i, t := range targets {
		switch t.State {
		case BatchPending, BatchActive, BatchComplete, BatchFailed:
		default:
			return fmt.Errorf("bad checkpoint %s: target %d has unknown state %q", file, i, t.State)
		}
		if t.State == BatchActive {
			active++
		}
		if t.Path == "" {
			return fmt.Errorf("bad checkpoint %s: target %d has no path", file, i)
		}
		if t.Size < -1 || t.Mtime < 0 || t.Offset < 0 {
			return fmt.Errorf("bad checkpoint %s: target %d has impossible identity", file, i)
		}
		if t.SHA256 != "" && !isHexDigest(t.SHA256) {
			return fmt.Errorf("bad checkpoint %s: target %d has a malformed digest", file, i)
		}
		if t.Proof != nil && !validPrefixProof(t.Proof) {
			return fmt.Errorf("bad checkpoint %s: target %d has a malformed content proof", file, i)
		}
	}
	if active > 1 {
		return fmt.Errorf("bad checkpoint %s: %d active targets, want at most 1", file, active)
	}
	return nil
}

// WriteBatchJournal atomically records the batch manifest cp to
// file. Journal failures warn; they must never fail the scan
// itself — a lost mark only costs rescanned work, never a
// silent skip, because skips need journaled proof.
func WriteBatchJournal(log io.Writer, file string, cp Checkpoint) {
	cp.Updated = time.Now().UTC()
	writeCheckpointData(log, file, cp)
}

// isHexDigest reports whether s is a 64-character lowercase hex
// SHA-256 digest.
func isHexDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if c < '0' || (c > '9' && c < 'a') || c > 'f' {
			return false
		}
	}
	return true
}
