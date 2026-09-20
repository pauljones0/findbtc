package detector

import (
	"context"
	"fmt"
	"io"
	"os"
)

// StdinTargetName labels piped input wherever a target is named:
// detection Target fields, progress lines, and case-log source paths.
// It is stable across runs so piped findings stay comparable; the
// spill file's temp path never appears in detections, progress, or
// case logs (only in a stderr diagnostic naming the spill, so crash
// residue can be found and removed).
const StdinTargetName = "stdin"

// MaxStdinSpillBytes caps the temp file a piped scan spills stdin
// into. Pipes cannot be re-read (retries and carves re-open the
// target), so the whole stream lands on disk before scanning starts;
// the cap keeps a runaway pipe from filling the temp volume. It is a
// backstop, not a target: available temp space is the practical bound
// and a full disk fails the scan loudly mid-spill. A var (not const)
// so tests can lower it without moving a terabyte.
var MaxStdinSpillBytes = int64(1 << 40)

// stdinSpillDir overrides the spill file's parent directory; empty
// means the platform temp dir (os.CreateTemp default, honoring
// TMPDIR). A test hook for asserting spill cleanup.
var stdinSpillDir string

// stdinSpillNoteInterval paces the stderr notes during a spill: one
// line per GiB keeps multi-hundred-gigabyte pipes visibly alive
// without spamming small ones (which log start and finish only).
const stdinSpillNoteInterval = int64(1 << 30)

// stdinScanTarget scans a spilled pipe as a seekable file. Offsets
// are pipe offsets (byte 0 is the first byte read), so detections
// match a file scan of the same bytes exactly; only Target differs.
type stdinScanTarget struct {
	spill string
	start int64
}

func (t *stdinScanTarget) Describe() string   { return StdinTargetName }
func (t *stdinScanTarget) StartOffset() int64 { return t.start }
func (t *stdinScanTarget) Depth() int         { return 0 }
func (t *stdinScanTarget) Size() (int64, error) {
	// FileSize, not Stat: empty inputs must size exactly the way an
	// empty file does (ioctl probe fails → unknown total), so pipe
	// and file progress agree even at zero bytes.
	return FileSize(t.spill)
}
func (t *stdinScanTarget) Open() (TargetReader, error) {
	return os.Open(t.spill)
}

// ScanStdinWithOptions scans a pipe the way ScanWithOptions scans a
// file: the stream is spilled to a bounded temp file first, then the
// standard pipeline (profiles, carves, case log, progress) runs over
// the spill, which is removed when the scan returns. Either callback
// may be nil. startOffset skips leading pipe bytes like -s.
//
// -checkpoint/-resume are refused: a journal naming a deleted temp
// file could never resume, so the failure is loud and up front.
func ScanStdinWithOptions(r io.Reader, startOffset int64, opts Options, onDetection func(Detection), onProgress func(ProgressInfo)) error {
	onDetection, onProgress = withDefaultCallbacks(onDetection, onProgress)
	if opts.CheckpointPath != "" || opts.Resume {
		return fmt.Errorf("cannot scan stdin: -checkpoint and -resume need a stable path; pipes cannot resume")
	}
	if opts.CarveDir != "" {
		if err := os.MkdirAll(opts.CarveDir, 0755); err != nil {
			return fmt.Errorf("cannot create carve directory %s: %w", opts.CarveDir, err)
		}
	}
	// The spill honors cancellation like the pipeline does: a
	// pre-cancelled context never touches the pipe, and a mid-spill
	// cancel stops between reads instead of draining terabytes.
	ctx := opts.scanContext()
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("cannot scan stdin: %w", err)
	}
	spill, err := os.CreateTemp(stdinSpillDir, "findbtc-stdin-*")
	if err != nil {
		return fmt.Errorf("cannot scan stdin: cannot create spill file: %w", err)
	}
	spillName := spill.Name()
	opts.logf("[stdin] spilling pipe to %s (cap %d bytes)\n", spillName, MaxStdinSpillBytes)
	spilled, serr := spillBounded(ctx, spill, r, opts)
	cerr := spill.Close()
	if serr != nil {
		os.Remove(spillName)
		return serr
	}
	if cerr != nil {
		os.Remove(spillName)
		return fmt.Errorf("cannot scan stdin: spill close failed after %d bytes: %w", spilled, cerr)
	}
	opts.logf("[stdin] spilled %d bytes; scanning\n", spilled)
	// A piped EnCase set cannot decode: segments arrive as one flat
	// stream, so EWF magic here means the container itself would
	// scan raw — near-certain false negatives. Warn loudly; the
	// scan still runs over the bytes as given. EWF2 gets its own
	// advice because file scans refuse EWF2 too (libewf converts).
	switch {
	case isEWF2Segment(spillName):
		opts.logf("[stdin] warning: piped input looks like an EnCase EWF2 container; scanning raw bytes — convert with libewf (ewfexport) and scan the raw output\n")
	case isEWFSegment(spillName):
		opts.logf("[stdin] warning: piped input looks like an EnCase (EWF) container; scanning raw bytes — pass the image file to decode it\n")
	}
	defer os.Remove(spillName)
	opts.strictRoot = true
	return runPipeline(&stdinScanTarget{spill: spillName, start: startOffset}, opts, onDetection, onProgress)
}

// spillBounded copies the pipe to dst, stopping loudly past
// MaxStdinSpillBytes. Read, write, and cap failures all report how
// far the spill got so a truncated pipe is never mistaken for a
// short one.
func spillBounded(ctx context.Context, dst *os.File, r io.Reader, opts Options) (int64, error) {
	capErr := func(total int64) error {
		return fmt.Errorf("cannot scan stdin: pipe exceeds the %d-byte spill cap (%d bytes spilled); scan a file instead", MaxStdinSpillBytes, total)
	}
	var total int64
	nextNote := stdinSpillNoteInterval
	buf := make([]byte, 1<<20)
	for {
		// A cancel lands between reads: the in-flight Read still
		// finishes (pipes cannot be un-read), but the spill stops
		// instead of draining the rest of the stream.
		if err := ctx.Err(); err != nil {
			return total, fmt.Errorf("cannot scan stdin: canceled during spill after %d bytes: %w", total, err)
		}
		// Never physically spill past cap+1 (the one probe byte
		// proves overflow); the post-write check below catches a
		// final chunk coalesced with EOF, which never loops again.
		room := MaxStdinSpillBytes + 1 - total
		if room <= 0 {
			return total, capErr(total)
		}
		n, rerr := r.Read(buf[:min(int64(len(buf)), room)])
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return total, fmt.Errorf("cannot scan stdin: spill write failed after %d bytes: %w", total, werr)
			}
			total += int64(n)
			if total > MaxStdinSpillBytes {
				return total, capErr(total)
			}
			if total >= nextNote {
				opts.logf("[stdin] spilled %d bytes\n", total)
				nextNote += stdinSpillNoteInterval
			}
		}
		if rerr == io.EOF {
			return total, nil
		}
		if rerr != nil {
			return total, fmt.Errorf("cannot scan stdin: pipe read failed after %d bytes: %w", total, rerr)
		}
	}
}
