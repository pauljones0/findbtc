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
// could not start (bad root, checkpoint requested).
func Walk(root string, wopts WalkOptions, onDetection func(Detection), onProgress func(ProgressInfo)) (WalkStats, error) {
	var stats WalkStats
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
	w := &walker{
		wopts: wopts, stats: &stats,
		carvePrefix: carvePrefix, caseLog: caseLog,
		onDetection: onDetection, onProgress: onProgress,
		seqBase: &seqBase,
	}
	if !info.IsDir() {
		w.scanFile(root)
		return stats, nil
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return stats, fmt.Errorf("cannot resolve %s: %w", root, err)
	}
	if wopts.FollowSymlinks {
		// Evaluated anchor for cycle detection.
		if eval, err := filepath.EvalSymlinks(abs); err == nil {
			abs = eval
		}
		w.visited = map[string]bool{abs: true}
	}
	w.recurse(abs, 0)
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
	// visited holds evaluated dir paths in follow mode for cycle checks.
	visited map[string]bool
}

func (w *walker) isOwnOutput(abs string) bool {
	if w.carvePrefix != "" && (abs == strings.TrimSuffix(w.carvePrefix, string(os.PathSeparator)) || strings.HasPrefix(abs, w.carvePrefix)) {
		return true
	}
	return w.caseLog != "" && abs == w.caseLog
}

func (w *walker) scanFile(path string) {
	// The pipeline logs an unreadable target but still reports
	// completion, so probe readability here to keep Failed honest:
	// a sweep must never silently claim coverage it did not get.
	if f, err := os.Open(path); err != nil {
		w.stats.fail(path, err)
		return
	} else {
		f.Close()
	}
	w.stats.Files++
	fileOpts := w.wopts.Scan
	fileOpts.CarveSeqStart = *w.seqBase
	var n int
	err := ScanWithOptions(0, path, fileOpts, func(d Detection) {
		n++
		w.onDetection(d)
	}, w.onProgress)
	*w.seqBase += n
	w.stats.Detections += int64(n)
	if err != nil {
		w.stats.fail(path, err)
	}
}

func (w *walker) recurse(abs string, depth int) {
	entries, err := os.ReadDir(abs)
	if err != nil {
		w.stats.fail(abs, err)
		return
	}
	for _, e := range entries {
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
			w.recurse(child, childDepth)
		case mode.IsRegular():
			w.scanFile(child)
		case mode&os.ModeSymlink != 0:
			w.followLink(child, childDepth)
		default:
			// Sockets, fifos, devices: never scanned.
			w.stats.SkippedSpecial++
		}
	}
}

// followLink handles one symlink per policy.
func (w *walker) followLink(path string, depth int) {
	if !w.wopts.FollowSymlinks {
		w.stats.SkippedSymlinks++
		return
	}
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		w.stats.fail(path, fmt.Errorf("broken or looped symlink: %w", err))
		return
	}
	if w.isOwnOutput(target) {
		w.stats.SkippedOwn++
		return
	}
	info, err := os.Stat(target)
	if err != nil {
		w.stats.fail(path, err)
		return
	}
	if info.IsDir() {
		if w.visited[target] {
			w.stats.fail(path, fmt.Errorf("symlink cycle: %s already visited", target))
			return
		}
		w.visited[target] = true
		w.recurse(target, depth)
		return
	}
	if info.Mode().IsRegular() {
		w.scanFile(target)
		return
	}
	w.stats.SkippedSpecial++
}
