package detector

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// BatchIdentity stats path for manifest identity: size plus unix
// mtime. A missing target reports (-1, 0): unknown identity never
// matches, so such entries always rescan.
func BatchIdentity(path string) (size, mtime int64) {
	fi, err := os.Stat(path)
	if err != nil {
		return -1, 0
	}
	return fi.Size(), fi.ModTime().Unix()
}

// NewBatchManifest builds a fresh all-pending manifest mirroring
// the ordered input list, bound to run.
func NewBatchManifest(targets []string, run BatchRun) *BatchManifest {
	m := &BatchManifest{Run: run}
	for _, t := range targets {
		size, mtime := BatchIdentity(t)
		ident, _ := FileIdentityOf(t)
		m.Targets = append(m.Targets, BatchTarget{Path: t, Size: size, Mtime: mtime, Ident: ident, State: BatchPending})
	}
	return m
}

// MatchBatchManifest validates a loaded batch journal for resume:
// the journal must be a batch journal for exactly this ordered
// target list under exactly this run binding. Identity (size,
// mtime) is not matched here — completed entries skip without
// it, and the active entry's offset is validated at scan time,
// when a fresh stat decides resume-against-offset or rescan.
func MatchBatchManifest(cp Checkpoint, targets []string, run BatchRun) (*BatchManifest, error) {
	if !cp.IsBatch() {
		return nil, fmt.Errorf("checkpoint is not a batch journal; resume it with a single target")
	}
	if len(cp.Targets) != len(targets) {
		return nil, fmt.Errorf("batch journal covers %d targets, run lists %d", len(cp.Targets), len(targets))
	}
	for i := range targets {
		if cp.Targets[i].Path != targets[i] {
			return nil, fmt.Errorf("batch journal target %d is %q, run lists %q", i, cp.Targets[i].Path, targets[i])
		}
	}
	if cp.Run == nil {
		return nil, fmt.Errorf("batch journal has no run options")
	}
	if err := matchBatchRun(*cp.Run, run); err != nil {
		return nil, err
	}
	return &BatchManifest{Targets: cp.Targets, Run: *cp.Run}, nil
}

func matchBatchRun(have, want BatchRun) error {
	switch {
	case have.Profile != want.Profile:
		return fmt.Errorf("batch journal ran under profile %q, run asks %q", have.Profile, want.Profile)
	case have.CarveDir != want.CarveDir:
		return fmt.Errorf("batch journal carved into %q, run asks %q", have.CarveDir, want.CarveDir)
	case have.Context != want.Context:
		return fmt.Errorf("batch journal used carve context %d, run asks %d", have.Context, want.Context)
	case have.JSON != want.JSON:
		return fmt.Errorf("batch journal ran with json=%v, run asks %v", have.JSON, want.JSON)
	case have.Reveal != want.Reveal:
		return fmt.Errorf("batch journal ran with reveal=%v, run asks %v", have.Reveal, want.Reveal)
	case have.Baseline != want.Baseline:
		return fmt.Errorf("batch journal ran under baseline %q, run asks %q", have.Baseline, want.Baseline)
	case have.CaseLog != want.CaseLog:
		return fmt.Errorf("batch journal case-logged to %q, run asks %q", have.CaseLog, want.CaseLog)
	}
	return nil
}

// BatchIdentityMatches reports whether a fresh stat still matches
// the journaled identity: unknown journaled identity (-1, 0)
// never matches, so such entries always rescan. Cheap tier only —
// same-size rewrites with restored mtimes match here and must be
// decided by digest re-hash or exact FileIdentity.
func BatchIdentityMatches(t BatchTarget, size, mtime int64) bool {
	if t.Size < 0 || t.Mtime == 0 {
		return false
	}
	return t.Size == size && t.Mtime == mtime
}

// VerifyBatchDigest re-hashes the first size bytes of path and
// compares against the manifest digest. Any error — unreadable
// file, short read, mismatch — fails safe: the caller rescans,
// never skips.
func VerifyBatchDigest(path string, size int64, want string) error {
	if want == "" {
		return fmt.Errorf("no digest journaled")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.CopyN(h, f, size)
	if err != nil {
		return fmt.Errorf("verify read: %w", err)
	}
	if n != size {
		return fmt.Errorf("verify short: %d of %d bytes", n, size)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("digest mismatch")
	}
	return nil
}

// NextCarveSeq scans dir for carved hit-NNNNNN outputs and returns
// the sequence number after the highest found, so a resumed run
// continues numbering instead of overwriting pre-kill carves with
// different content. A missing or unreadable directory, or one
// with no carves, yields 1; foreign files are ignored, and the
// scan never writes.
func NextCarveSeq(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 1
	}
	max := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "hit-") {
			continue
		}
		rest := strings.TrimPrefix(name, "hit-")
		dot := strings.Index(rest, ".")
		if dot <= 0 {
			continue
		}
		seq, err := strconv.Atoi(rest[:dot])
		if err != nil || seq <= 0 {
			continue
		}
		if seq > max {
			max = seq
		}
	}
	return max + 1
}

// ManifestSnapshot renders m as a journal Checkpoint for atomic
// transition persists: legacy fields carry Offset 0 so an old
// binary, which cannot see Targets, falls back to a full rescan
// of a path-matched target instead of silently skipping bytes.
func ManifestSnapshot(m *BatchManifest) Checkpoint {
	cp := Checkpoint{Targets: append([]BatchTarget(nil), m.Targets...)}
	if len(cp.Targets) > 0 {
		cp.Path = cp.Targets[0].Path
	}
	run := m.Run
	cp.Run = &run
	return cp
}
