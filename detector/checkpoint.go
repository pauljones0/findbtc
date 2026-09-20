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
	// size discriminators), stable across resume attempts of the
	// same input. A retry defers
	// re-publishing banked members, so same-cap attempts converge
	// instead of replaying the same admitted prefix. Completion
	// drops the list (it subsumes it). Opaque to old binaries.
	Covered []string `json:"covered,omitempty"`
	// Size and Mtime identify the bytes the journaled progress —
	// including Covered — was produced from. A retry seeds
	// covered members only on identity match; replaced bytes
	// re-read everything (a same-path swap keeps member keys but
	// changes their content). Zero/absent on journals from older
	// binaries, which never match and simply re-cover.
	Size  int64 `json:"size,omitempty"`
	Mtime int64 `json:"mtime,omitempty"`
	// Ident is the kernel-attested run-start identity (device /
	// inode / size / mtime / ctime) the Size/Mtime pair alone
	// cannot prove: same-size rewrites with restored mtimes
	// match metadata but change bytes. Matching uses Ident only;
	// Size/Mtime stay as cheap human-readable checks. Absent on
	// older journals, which never match and rescan.
	Ident FileIdentity `json:"identity,omitempty"`
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
	// see Checkpoint.Ident. Resume honors filed progress only on
	// identity match.
	Ident FileIdentity `json:"identity,omitempty"`
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
// front and file it at every point.
func writeCheckpoint(log io.Writer, file, path string, offset int64, covered []string, ident FileIdentity) {
	writeCheckpointData(log, file, Checkpoint{Path: path, Offset: offset, Updated: time.Now().UTC(), Covered: covered, Size: ident.Size, Mtime: ident.MtimeNS / 1e9, Ident: ident})
}

// writeCheckpointRange atomically records range-scan progress: ranges is
// the full range list (for resume validation), index the range in flight,
// offset the absolute file offset scanned up to within it.
func writeCheckpointRange(log io.Writer, file, path string, ranges []FSExtent, index int, offset int64, covered []string, ident FileIdentity) {
	writeCheckpointData(log, file, Checkpoint{Path: path, Offset: offset, Updated: time.Now().UTC(), Ranges: ranges, RangeIndex: index, Covered: covered, Size: ident.Size, Mtime: ident.MtimeNS / 1e9, Ident: ident})
}

// IdentityTrust decides whether filed journal progress (a frontier
// offset, a covered set) may be honored for path. Regular files
// with exact identity match honor both; replaced bytes rescan
// both, with a note for warnings. Non-regular targets (volumes,
// pipes) keep legacy offset trust — no platform can attest their
// bytes, and refusing would end resume for raw media — while
// dropping covered sets, which re-reading re-covers. Missing
// files rescan so the open fails honestly instead of skipping.
// Legacy journals (empty identity) rescan once on upgrade.
func IdentityTrust(filed FileIdentity, path string) (offset, covered bool, note string) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, false, "cannot stat " + path + "; rescanning from the start"
	}
	if !fi.Mode().IsRegular() {
		return true, false, ""
	}
	cur, ok := FileIdentityOf(path)
	if !ok {
		// Regular file on an unattested platform: sound
		// refusal (full rescan), outside the CI matrix.
		return false, false, "no byte identity available for " + path + "; rescanning from the start"
	}
	if filed.Matches(cur) {
		return true, true, ""
	}
	return false, false, "journal identity for " + path + " does not match current bytes; rescanning from the start"
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
	for i, r := range cp.Ranges {
		if r.Start < 0 || r.Len <= 0 {
			return cp, fmt.Errorf("bad checkpoint %s: range %d has non-positive geometry", file, i)
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
