package detector

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Directory-tree sweeps (Goal 13). Walk scans every regular file under a
// root with the standard single-file pipeline, so a laptop, live system,
// or repo gets the same detectors as an image.
//
// Policy, explicit:
//   - Symlinks are never followed by default: symlink entries are counted
//     in SkippedSymlinks and left alone, which also makes loops
//     impossible. FollowSymlinks opts in; looped links then fail safe
//     (recorded under Failed, walk continues).
//   - Only regular files are scanned. Directories are descended;
//     anything else (sockets, fifos, devices) counts as SkippedSpecial.
//   - One unreadable file or directory never aborts the walk: the path
//     and error join Failed and the sweep continues.
//   - The carve directory and case-log file are skipped when they sit
//     inside the walked tree, so a sweep never scans its own output.
//   - Checkpointing is refused: a single offset cannot resume a file
//     list. Each file still appends its own case-log record.

// WalkOptions configures Walk.
type WalkOptions struct {
	// Scan configures the per-file pipeline (carving, reveal, case log).
	Scan Options
	// MaxDepth limits depth below root (root is 0); 0 means unlimited.
	MaxDepth int
	// FollowSymlinks scans through symlinked files and descends into
	// symlinked directories. Off by default; loops fail safe per link.
	FollowSymlinks bool
	// Baseline, when non-nil, suppresses findings whose Fingerprint
	// was recorded in a reviewed earlier sweep (see
	// LoadBaselineFingerprints): known hits stay silent while new
	// hits report. Suppressed counts land in
	// WalkStats.SuppressedBaseline, never in the detection stream.
	Baseline map[string]bool
}

// WalkFailure records one path the sweep could not handle.
type WalkFailure struct {
	Path string
	Err  string
}

// WalkStats summarizes a completed sweep.
type WalkStats struct {
	// Files is the count of regular files scanned (including ones whose
	// scan failed partway; see Failed).
	Files int64
	// Detections is the total detection count across all files.
	Detections      int64
	SkippedSymlinks int64
	SkippedSpecial  int64
	SkippedDepth    int64
	SkippedOwn      int64 // carve dir / case log inside the tree
	// Failed holds the first failures (capped); FailedTotal counts all.
	Failed      []WalkFailure
	FailedTotal int64
	// SuppressedBaseline counts findings silenced by the baseline
	// (known hits from an earlier reviewed sweep).
	SuppressedBaseline int64
}

// maxWalkFailures caps retained failure detail; the count is unbounded.
const maxWalkFailures = 32

func (s *WalkStats) fail(path string, err error) {
	s.FailedTotal++
	if len(s.Failed) < maxWalkFailures {
		s.Failed = append(s.Failed, WalkFailure{Path: path, Err: err.Error()})
	}
}

// Walk scans the file or directory tree at root. It returns stats and a
// nil error whenever the sweep itself ran; per-file failures land in
// stats, never in the returned error. A non-nil error means the walk
// could not start (bad root, checkpoint requested) — or that
// wopts.Scan.Context was canceled, in which case stats cover the files
// finished before cancellation and the error is ctx.Err(). Either
// callback may be nil.
func Walk(root string, wopts WalkOptions, onDetection func(Detection), onProgress func(ProgressInfo)) (WalkStats, error) {
	var stats WalkStats
	onDetection, onProgress = withDefaultCallbacks(onDetection, onProgress)
	if wopts.Scan.CheckpointPath != "" {
		return stats, fmt.Errorf("checkpointing is not supported for directory sweeps (a single offset cannot resume a file list)")
	}
	info, err := os.Lstat(root)
	if err != nil {
		return stats, fmt.Errorf("cannot sweep %s: %w", root, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		if !wopts.FollowSymlinks {
			return stats, fmt.Errorf("cannot sweep %s: root is a symlink (opt in with FollowSymlinks to follow it)", root)
		}
		resolved, err := filepath.EvalSymlinks(root)
		if err != nil {
			return stats, fmt.Errorf("cannot sweep %s: %w", root, err)
		}
		root = resolved
		if info, err = os.Stat(root); err != nil {
			return stats, fmt.Errorf("cannot sweep %s: %w", root, err)
		}
	}
	carvePrefix, caseLog := ownOutputPaths(wopts.Scan)
	seqBase := wopts.Scan.CarveSeqStart
	abs, err := filepath.Abs(root)
	if err != nil {
		return stats, fmt.Errorf("cannot resolve %s: %w", root, err)
	}
	w := &walker{
		wopts: wopts, stats: &stats,
		carvePrefix: carvePrefix, caseLog: caseLog,
		onDetection: onDetection, onProgress: onProgress,
		seqBase: &seqBase, root: abs,
	}
	if !info.IsDir() {
		if err := w.scanFile(root); err != nil {
			return stats, err
		}
		return stats, nil
	}
	if wopts.FollowSymlinks {
		// Evaluated anchor for cycle detection.
		if eval, err := filepath.EvalSymlinks(abs); err == nil {
			abs = eval
		}
		w.visited = map[string]bool{abs: true}
	}
	w.root = abs
	if err := w.recurse(abs, 0); err != nil {
		return stats, err
	}
	return stats, nil
}

// ownOutputPaths returns absolute skip rules for the sweep's own outputs:
// the carve dir (prefix) and case-log file (exact), when configured.
func ownOutputPaths(opts Options) (carvePrefix, caseLog string) {
	if opts.CarveDir != "" {
		if abs, err := filepath.Abs(opts.CarveDir); err == nil {
			carvePrefix = abs + string(os.PathSeparator)
		}
	}
	if opts.CaseLogPath != "" {
		if abs, err := filepath.Abs(opts.CaseLogPath); err == nil {
			caseLog = abs
		}
	}
	return carvePrefix, caseLog
}

type walker struct {
	wopts       WalkOptions
	stats       *WalkStats
	onDetection func(Detection)
	onProgress  func(ProgressInfo)
	carvePrefix string
	caseLog     string
	seqBase     *int
	root        string // anchored sweep root for fingerprint relpaths
	// visited holds evaluated dir paths in follow mode for cycle checks.
	visited map[string]bool
}

func (w *walker) isOwnOutput(abs string) bool {
	if w.carvePrefix != "" && (abs == strings.TrimSuffix(w.carvePrefix, string(os.PathSeparator)) || strings.HasPrefix(abs, w.carvePrefix)) {
		return true
	}
	return w.caseLog != "" && abs == w.caseLog
}

func (w *walker) scanFile(path string) error {
	if err := w.wopts.Scan.scanContext().Err(); err != nil {
		return err
	}
	// The pipeline reports an unreadable target as an error, but
	// probe readability first anyway: an unopenable file must land in
	// Failed without counting as scanned, so a sweep never silently
	// claims coverage it did not get.
	if f, err := os.Open(path); err != nil {
		w.stats.fail(path, err)
		return nil
	} else {
		f.Close()
	}
	w.stats.Files++
	fileOpts := w.wopts.Scan
	fileOpts.CarveSeqStart = *w.seqBase
	var n int
	err := ScanWithOptions(0, path, fileOpts, func(d Detection) {
		// Every walk detection carries its baseline key (a future
		// reviewed sweep becomes the suppress-list); matching
		// suppresses known hits while new ones report. The root is
		// absolute, so absolutize a relative scan path for the
		// relpath — display paths stay as walked.
		abs, aerr := filepath.Abs(path)
		if aerr != nil {
			abs = path
		}
		d.Fingerprint = FingerprintFinding(w.root, abs, d.Needle, d.Offset, d.MatchLen)
		if w.wopts.Baseline != nil && d.Fingerprint != "" && w.wopts.Baseline[d.Fingerprint] {
			w.stats.SuppressedBaseline++
			return
		}
		n++
		w.onDetection(d)
	}, w.onProgress)
	*w.seqBase += n
	w.stats.Detections += int64(n)
	if err != nil {
		// Cancellation stops the sweep; anything else is one
		// file's failure among many.
		if cerr := w.wopts.Scan.scanContext().Err(); cerr != nil {
			return cerr
		}
		w.stats.fail(path, err)
	}
	return nil
}

func (w *walker) recurse(abs string, depth int) error {
	if err := w.wopts.Scan.scanContext().Err(); err != nil {
		return err
	}
	entries, err := os.ReadDir(abs)
	if err != nil {
		w.stats.fail(abs, err)
		return nil
	}
	for _, e := range entries {
		if err := w.wopts.Scan.scanContext().Err(); err != nil {
			return err
		}
		child := filepath.Join(abs, e.Name())
		childDepth := depth + 1
		if w.wopts.MaxDepth > 0 && childDepth > w.wopts.MaxDepth {
			w.stats.SkippedDepth++
			continue
		}
		if w.isOwnOutput(child) {
			w.stats.SkippedOwn++
			continue
		}
		mode := e.Type()
		switch {
		case mode.IsDir():
			if err := w.recurse(child, childDepth); err != nil {
				return err
			}
		case mode.IsRegular():
			if err := w.scanFile(child); err != nil {
				return err
			}
		case mode&os.ModeSymlink != 0:
			if err := w.followLink(child, childDepth); err != nil {
				return err
			}
		default:
			// Sockets, fifos, devices: never scanned.
			w.stats.SkippedSpecial++
		}
	}
	return nil
}

// followLink handles one symlink per policy.
func (w *walker) followLink(path string, depth int) error {
	if !w.wopts.FollowSymlinks {
		w.stats.SkippedSymlinks++
		return nil
	}
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		w.stats.fail(path, fmt.Errorf("broken or looped symlink: %w", err))
		return nil
	}
	if w.isOwnOutput(target) {
		w.stats.SkippedOwn++
		return nil
	}
	info, err := os.Stat(target)
	if err != nil {
		w.stats.fail(path, err)
		return nil
	}
	if info.IsDir() {
		if w.visited[target] {
			w.stats.fail(path, fmt.Errorf("symlink cycle: %s already visited", target))
			return nil
		}
		w.visited[target] = true
		return w.recurse(target, depth)
	}
	if info.Mode().IsRegular() {
		return w.scanFile(target)
	}
	w.stats.SkippedSpecial++
	return nil
}
