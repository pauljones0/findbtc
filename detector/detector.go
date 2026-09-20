package detector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// A block of data being worked on
type Block struct {
	// Absolute offset of data[0] in the target
	offset int64
	// Buffer holding overlap prefix plus newly read bytes; only data[:length]
	// is valid, the remainder is stale from buffer reuse
	data   []byte
	length int

	// Number of leading bytes re-scanned from the previous block; matches
	// fully inside this prefix were already reported and must be skipped
	overlap int

	// final marks the last block of a target; tokenizers use it to decide
	// whether a trailing word fragment continues in a later block
	final bool

	// Describe how to find this block of data
	location string

	// The target this block came from
	source scanTarget

	// barrier, when non-nil, marks a drain-barrier sentinel: stages
	// forward it untouched (no detection, no EOF accounting, never
	// recycled to the block pool) and detectWallets acknowledges by
	// sending on it once every block ahead of it is delivered.
	barrier chan<- struct{}
}

// Bytes read per scan step; consecutive blocks additionally re-scan a short
// overlap so patterns straddling a boundary are still found.
const blockSize = 4 * 1024

// trimEdgeFragments drops a leading/trailing partial token when block data
// continues past the edge: first/final mark target boundaries. A match using
// bytes past the edge is evaluated whole in the neighboring block instead.
// It returns the trimmed data and the start offset within the input.
func trimEdgeFragments(data []byte, first, final bool, isWordChar func(byte) bool) ([]byte, int) {
	start, end := 0, len(data)
	if !first {
		for start < len(data) && isWordChar(data[start]) {
			start++
		}
	}
	if !final {
		for end > start && isWordChar(data[end-1]) {
			end--
		}
	}
	return data[start:end], start
}

// scanOverlap returns how many trailing bytes of each block are prepended to
// the next one: one less than the longest pattern any stage searches for,
// including the widest seed phrase, keystore, and Goal 6 format spans.
func scanOverlap() int {
	max := bip39MaxSpan + 1
	for _, span := range []int{keystoreMaxSpan, electrumMaxSpan, electrumFileMaxSpan, descriptorMaxSpan, slip39MaxSpan, metamaskMaxSpan, secretsMaxSpan} {
		if span+1 > max {
			max = span + 1
		}
	}
	patterns := append(append([][]byte{}, needles...), ZIP_ECD_HEADER, GZIP_HEADER)
	for _, p := range patterns {
		if len(p) > max {
			max = len(p)
		}
	}
	return max - 1
}

func NewBlock(size int) *Block {
	return &Block{
		offset: 0,
		data:   make([]byte, size),
	}
}

// Describes a detected wallet trace. All fields are comparable so tests can
// use reflect.DeepEqual on detections.
type Detection struct {
	Description string `json:"description"`
	Needle      string `json:"needle"`
	// Offset is the absolute byte offset of the needle within Target.
	Offset int64 `json:"offset"`
	// Target describes the scanned stream holding the hit.
	Target string `json:"target"`
	// BlockOffset is the logical 4kB-block start containing the hit.
	BlockOffset int64 `json:"block_offset"`
	// MatchLen is the byte span of the hit (needle length or phrase span).
	MatchLen int `json:"match_length"`
	// CarvePath is the carved file when carving is enabled, else "".
	CarvePath string `json:"carve_path,omitempty"`
	// Carve classifies the carved bytes; set only when carving succeeded.
	Carve *CarveInfo `json:"carve,omitempty"`
	// Hashes holds crack-ready password material extracted from the carve;
	// set only when carving found usable mkey or keystore records.
	Hashes []CrackHash `json:"hashes,omitempty"`
	// Words holds seed-phrase words for BIP39 hits; set only with Reveal
	// (--reveal), otherwise words never leave the detector.
	Words []string `json:"words,omitempty"`
	// FileName names the filesystem entry holding the hit; set only by
	// filesystem-guided (-fs) scans, never by raw scans.
	FileName string `json:"file_name,omitempty"`
	// Salvage describes reassembled database pages from the carve; set only
	// when salvage wrote a .salvage.db file.
	Salvage *SalvageInfo `json:"salvage,omitempty"`
	// Fingerprint keys the finding for baseline suppression (Goal 29):
	// "v1/<relpath>/<needle>/<line-hash>" on -walk sweeps, which know
	// the tree root, and "v1/history/<commit>/<path>/<needle>/<hash>"
	// on patch (-patch) scans; empty everywhere else.
	Fingerprint string `json:"fingerprint,omitempty"`
	// Commit is the enclosing commit sha for patch (-patch) scans;
	// empty for other modes and for bytes outside any commit.
	Commit string `json:"commit,omitempty"`
	// Path is the enclosing repo-relative file for patch scans;
	// empty for other modes and outside any diff.
	Path string `json:"path,omitempty"`
	// Line is the new-file line number holding the hit on patch
	// scans, set only for added/context lines; 0 otherwise.
	Line int `json:"line,omitempty"`
	// Verified reports that a DER-family PEM body base64-decoded and
	// parsed as a DER SEQUENCE (Goal 30). Structural offline check
	// only — it says the block is well-formed, never that the key
	// works, and no live verification of any kind is performed.
	Verified bool `json:"verified,omitempty"`
}

type ProgressInfo struct {
	// Description of the target currently being scanned
	CurrentTarget string
	// Number of bytes scanned in the current target
	ScannedBytes int64
	// Bytes in the current target
	TotalBytes int64
	// Number of targets remaining to be scanned; this may grow dynamically as new targets
	// are discovered inside existing targets (eg. compressed files)
	UnscannedTargets int
}

type TargetReader interface {
	io.ReaderAt
	io.Reader
	io.Closer
	io.Seeker
}

type scanTarget interface {
	Describe() string
	StartOffset() int64
	Size() (int64, error)
	Open() (TargetReader, error)
	// Depth counts archive nesting: the root target is 0, each archive
	// member adds one. It bounds zip-bomb-style recursion.
	Depth() int
}

// Resource limits against hostile or pathological archives.
const (
	// maxArchiveDepth caps nested archive traversal (zip-in-gzip-in-...).
	// Worst case per level is bounded by the member/chunk caps below, so
	// total archive RAM stays near depth × the largest single inflation.
	maxArchiveDepth = 8
)

// maxZipMemberBytes caps the in-memory inflation of one zip member: the
// publish check skips honestly-declared giants, and member Open re-checks
// actual inflated bytes so a lying declared size cannot bypass it. A var
// (not const) so hostile-input tests can lower it without allocating 1 GiB.
var maxZipMemberBytes = int64(1 << 30)

type fileScanTarget struct {
	path        string
	startOffset int64
}

func (t *fileScanTarget) Describe() string {
	return t.path
}
func (t *fileScanTarget) StartOffset() int64 {
	return t.startOffset
}
func (t *fileScanTarget) Depth() int {
	return 0
}
func (t *fileScanTarget) Size() (int64, error) {
	return FileSize(t.path)
}
func (t *fileScanTarget) Open() (TargetReader, error) {
	f, err := os.Open(t.path)
	if err != nil {
		return nil, err
	}
	return f, nil
}

var EOF *Block = &Block{}

// Options configures ScanWithOptions. The zero value scans without carving.
type Options struct {
	// CarveDir, when non-empty, writes CarveContextBytes around every hit to
	// CarveDir/hit-NNNNNN.bin plus a JSON sidecar. Never point it at the
	// scanned device itself.
	CarveDir string
	// CarveContextBytes carved before and after each hit. Only used with CarveDir.
	CarveContextBytes int64
	// OnBadSector, when non-nil, is called for every byte range skipped
	// after repeated read failures. Skipped ranges are also logged to stderr.
	OnBadSector BadSectorFunc
	// CheckpointPath, when non-empty, journals root-target progress to the
	// file every 1MB and on completion, so an interrupted scan can resume.
	CheckpointPath string
	// Resume continues a range scan (ScanRangesWithOptions) from the
	// CheckpointPath journal instead of starting over. Single-target
	// resume is handled by the caller (read the journal, pass the
	// offset); this flag is ignored outside range scans.
	Resume bool
	// Profile selects the detector set: "" (or "default") runs the
	// wallet matchers only; "secrets" adds the opt-in non-wallet
	// secret matchers (private-key blocks, credential shapes) on
	// top. Any other value fails the scan loudly.
	Profile string
	// rangeCtx carries range-journal state into runPipeline; set by
	// ScanRangesWithOptions, never by callers.
	rangeCtx *rangeJournalCtx
	// BatchJournal, when non-nil, makes proven frontiers journal
	// the batch manifest (targets plus bound run options) with
	// the active entry's offset filled in. Set by batch callers
	// (main's multi-target loop); the detector reads it at
	// journal points but never mutates it.
	BatchJournal *BatchManifest
	// strictRoot makes runPipeline return an error when the root
	// target fails or covers zero bytes (coverage honesty). Only
	// ScanWithOptions and ScanStdinWithOptions set it: range scans
	// keep per-range tolerance, and nested targets always stay
	// warn-and-continue.
	strictRoot bool
	// Reveal, when true, attaches seed-phrase words to BIP39 detections
	// (owner recovery only). Default output never contains words.
	Reveal bool
	// CaseLogPath, when non-empty, appends one JSON record per scan to
	// the file: source identity, streaming SHA-256/MD5 over the bytes
	// actually read, skipped ranges, and the detection count.
	CaseLogPath string
	// CarveSeqStart is the first carve sequence number (hit-NNNNNN).
	// Multi-target callers (the directory walker) thread a shared
	// counter through it so carves never collide; single scans leave 0.
	CarveSeqStart int
	// ToolVersion stamps the case log; main sets it from the build.
	ToolVersion string
	// Flags records the invocation arguments in the case log; main sets
	// it so a reviewer can reproduce the scan exactly.
	Flags []string
	// Log routes library diagnostics (scan progress notes, carve and
	// checkpoint warnings). Nil writes to os.Stderr, exactly as
	// before; set it to route logs anywhere else, or to io.Discard
	// for quiet embedding. Detection output never goes here — it
	// flows through the onDetection callback. The library
	// serializes its own writes through one package-level mutex,
	// so a plain non-goroutine-safe sink (bytes.Buffer) is safe;
	// the caller must still not write to (or read) the sink
	// concurrently from outside the scan.
	Log io.Writer
	// Patch treats the input as a patch series (git log -p) and
	// attributes each root-target hit to commit + repo path (+
	// new-file line for added/context lines), with a history
	// fingerprint for baseline suppression. Detections buffer and
	// deliver after the scan (progress still streams); carve
	// sidecars are re-marshaled with the attribution. Nested
	// archive hits stay unattributed (member-relative offsets).
	Patch bool
	// Context cancels the scan. Nil means context.Background (run to
	// completion). On cancellation ScanWithOptions and friends return
	// promptly with ctx.Err(): detections already delivered stay
	// delivered, the checkpoint journal keeps its last completed
	// mark (no completion record is written), the case log (when
	// enabled) records status "canceled", and no pipeline goroutine
	// is left behind.
	Context context.Context
	// caseRec carries the active recorder from runPipeline to scanBlocks.
	caseRec *caseRecorder
}

// BadSectorFunc reports an unreadable byte range [start, end) in a target.
type BadSectorFunc func(target string, start, end int64, err error)

// Recovery behavior for unreadable offsets on seekable targets: each failed
// block is retried this many times before its range is skipped. Backoff
// between attempts stays short so failing disks are not hammered.
const maxReadAttempts = 3

func readRetryBackoff(attempt int) time.Duration {
	return time.Duration(attempt) * 50 * time.Millisecond
}

// logWriter resolves the diagnostics sink: opts.Log, or os.Stderr
// when nil. Every library diagnostic funnels through here (or the
// logf helpers below), so embedding stays quiet on demand while the
// default output is byte-identical.
func (o Options) logWriter() io.Writer {
	if o.Log != nil {
		return o.Log
	}
	return os.Stderr
}

// logMu serializes every logf/logLinef write. Pipeline stages log
// concurrently (gate warn-once, block processing, drains), and
// Options is copied by value, so the mutex lives here at package
// level — never in Options — as the single serialization point
// for all diagnostics sinks.
var logMu sync.Mutex

// logf writes one diagnostics line to the configured sink.
func (o Options) logf(format string, args ...any) {
	logMu.Lock()
	defer logMu.Unlock()
	fmt.Fprintf(o.logWriter(), format, args...)
}

// logLinef writes to an explicit sink, defaulting nil to os.Stderr,
// for helpers that receive the writer instead of full Options.
func logLinef(w io.Writer, format string, args ...any) {
	if w == nil {
		w = os.Stderr
	}
	logMu.Lock()
	defer logMu.Unlock()
	fmt.Fprintf(w, format, args...)
}

// scanContext resolves the cancellation context: opts.Context, or
// context.Background when nil.
func (o Options) scanContext() context.Context {
	if o.Context != nil {
		return o.Context
	}
	return context.Background()
}

// withDefaultCallbacks replaces nil scan callbacks with no-ops, so
// library callers pass nil for streams they ignore instead of
// remembering empty closures.
func withDefaultCallbacks(onDetection func(Detection), onProgress func(ProgressInfo)) (func(Detection), func(ProgressInfo)) {
	if onDetection == nil {
		onDetection = func(Detection) {}
	}
	if onProgress == nil {
		onProgress = func(ProgressInfo) {}
	}
	return onDetection, onProgress
}

// Scan runs the detection system with default options; see ScanWithOptions.
// Either callback may be nil.
func Scan(startOffset int64, path string, onDetection func(Detection), onProgress func(ProgressInfo)) error {
	return ScanWithOptions(startOffset, path, Options{}, onDetection, onProgress)
}

// Bootstrap and run the detection system, scanning the given path
// for remnants of wallets. Normally, the path given would
// be a raw device file handle, like /dev/sdb or some such; the system
// would then scan every sector of that device. Forensic images are
// accepted too: EnCase E01 sets (pass the .E01) decode transparently,
// and split raw sets (base.001, base.002, ...) concatenate. Either
// callback may be nil.
//
// A root target that cannot be read (or that covers zero bytes of an
// expected size) is an error, never a quiet success; nested targets
// inside it stay warn-and-continue.
func ScanWithOptions(startOffset int64, path string, opts Options, onDetection func(Detection), onProgress func(ProgressInfo)) error {
	onDetection, onProgress = withDefaultCallbacks(onDetection, onProgress)
	// Patch findings buffer for attribution and deliver after the
	// checkpoint journals completion: a crash in between would
	// resume past findings that never reported, so the combination
	// refuses loudly instead of certifying lost coverage.
	if opts.Patch && (opts.CheckpointPath != "" || opts.Resume) {
		return recordAttempt(opts, path, fmt.Errorf("cannot scan patch: -checkpoint and -resume would resume past buffered findings; scan without them"))
	}
	if _, err := os.Stat(path); err != nil {
		return recordAttempt(opts, path, fmt.Errorf("cannot scan %s: %w", path, err))
	}
	if opts.CarveDir != "" {
		if err := os.MkdirAll(opts.CarveDir, 0755); err != nil {
			return recordAttempt(opts, path, fmt.Errorf("cannot create carve directory %s: %w", opts.CarveDir, err))
		}
	}
	target, err := detectScanTarget(path, startOffset)
	if err != nil {
		return recordAttempt(opts, path, err)
	}
	opts.strictRoot = true
	if opts.Patch {
		return scanPatch(target, opts, onDetection, onProgress)
	}
	return runPipeline(target, opts, onDetection, onProgress)
}

// scanPatch runs the pipeline buffering detections, then attributes
// them to patch positions in one forward re-read of the target and
// delivers in scan order. Attribution never fails the scan: a
// re-read failure warns and the findings report with whatever was
// stamped (possibly bare). Cancellation returns promptly with
// ctx.Err() instead: no re-read, no further delivery.
func scanPatch(target scanTarget, opts Options, onDetection func(Detection), onProgress func(ProgressInfo)) error {
	ctx := opts.scanContext()
	var buffered []Detection
	runErr := runPipeline(target, opts, func(d Detection) {
		buffered = append(buffered, d)
	}, onProgress)
	if ctx.Err() != nil {
		if runErr != nil {
			return runErr
		}
		return ctx.Err()
	}
	if len(buffered) > 0 {
		if f, err := target.Open(); err != nil {
			opts.logf("[patch] warning: attribution skipped (cannot re-read %s: %s)\n", target.Describe(), err.Error())
		} else {
			aerr := attributePatch(ctx, f, target.Describe(), buffered, opts.logWriter())
			f.Close()
			if aerr != nil && ctx.Err() != nil {
				if runErr != nil {
					return runErr
				}
				return ctx.Err()
			}
			// Read errors warn inside attributePatch; delivery
			// and sidecars carry whatever was stamped.
			rewritePatchSidecars(buffered, opts.logWriter())
		}
		for _, d := range buffered {
			onDetection(d)
		}
	}
	return runErr
}

// rangeJournalCtx identifies one range within a journaled range scan.
type rangeJournalCtx struct {
	ranges []FSExtent
	index  int
}

// ScanRangesWithOptions scans isolated byte ranges of one file (filesystem
// unallocated extents, deleted-file runs) as sequential pipelines: the
// completion protocol assumes a single root target, so ranges cannot share
// one. Carves near range edges clamp to the range.
//
// With CheckpointPath set, every range journals (range_index, offset) each
// 1MB and on completion. With Resume, the journal's range list must match
// exactly or resume refuses loudly; the resumed range rewinds to its
// block grid at/before offset-overlap so straddling patterns still match.
// Either callback may be nil.
func ScanRangesWithOptions(path string, ranges []FSExtent, opts Options, onDetection func(Detection), onProgress func(ProgressInfo)) error {
	onDetection, onProgress = withDefaultCallbacks(onDetection, onProgress)
	if opts.Patch {
		return recordAttempt(opts, path, fmt.Errorf("cannot scan patch: range scans slice the input, so patch positions would misattribute; scan the whole file instead"))
	}
	if _, err := os.Stat(path); err != nil {
		return recordAttempt(opts, path, fmt.Errorf("cannot scan %s: %w", path, err))
	}
	if opts.CarveDir != "" {
		if err := os.MkdirAll(opts.CarveDir, 0755); err != nil {
			return recordAttempt(opts, path, fmt.Errorf("cannot create carve directory %s: %w", opts.CarveDir, err))
		}
	}
	startIdx := 0
	var startOff int64 = -1
	if opts.Resume {
		if opts.CheckpointPath == "" {
			return recordAttempt(opts, path, fmt.Errorf("resume requires a checkpoint path"))
		}
		idx, off, resume, err := readRangeResume(opts.logWriter(), opts.CheckpointPath, path, ranges)
		if err != nil {
			return recordAttempt(opts, path, err)
		}
		if !resume {
			return nil // journal says the list already completed
		}
		startIdx, startOff = idx, off
		// A missing journal already announced a fresh start inside
		// readRangeResume; only a real journal point gets a
		// resume-position line.
		if off >= 0 {
			opts.logf("[checkpoint] Resuming %s at range %d of %d%s\n",
				path, resumeDisplayIndex(ranges, idx, off)+1, len(ranges), rangeResumePercent(ranges, idx, off))
		}
	}
	for i := startIdx; i < len(ranges); i++ {
		r := ranges[i]
		if r.Len <= 0 {
			continue
		}
		start := r.Start
		if i == startIdx && startOff >= 0 {
			if startOff >= r.Start+r.Len {
				continue // journaled at/past the end: range done
			}
			start = rewindOffset(r.Start, startOff)
		}
		t := &boundedScanTarget{path: path, start: start, length: r.Start + r.Len - start}
		ropts := opts
		ropts.Resume = false
		if opts.CheckpointPath != "" {
			ropts.rangeCtx = &rangeJournalCtx{ranges: ranges, index: i}
		}
		if err := runPipeline(t, ropts, onDetection, onProgress); err != nil {
			return err
		}
	}
	return nil
}

// resumeDisplayIndex names the range where work resumes for a journal
// point: a point exactly on a boundary belongs to the next range with
// nonzero remainder (the scan loop skips the rest), not the finished
// one. A point at the very end of the list names the last range.
func resumeDisplayIndex(ranges []FSExtent, idx int, off int64) int {
	// Same skip condition the scan loop below uses: a range with no
	// remainder contributes nothing, so the ordinal advances past it.
	didx := idx
	for didx < len(ranges) && off >= ranges[didx].Start+ranges[didx].Len {
		didx++
	}
	if didx >= len(ranges) {
		return len(ranges) - 1
	}
	return didx
}

// rangeResumePercent renders " (continuing at NN%)" for a range resume
// point, or "" when the list totals zero bytes (no meaningful
// denominator). Bytes before the journal point count as done.
func rangeResumePercent(ranges []FSExtent, idx int, off int64) string {
	var total, done int64
	for i, r := range ranges {
		if r.Len <= 0 {
			continue
		}
		total += r.Len
		switch {
		case i < idx:
			done += r.Len
		case i == idx && off > r.Start:
			done += off - r.Start
		}
	}
	if total <= 0 || done < 0 || done > total {
		return ""
	}
	return fmt.Sprintf(" (continuing at %d%%)", done*100/total)
}

// rewindOffset backs a resume point to its range's block grid at or before
// offset-overlap, so resumed blocks align with the original grid (keeping
// block_offset identical) while still covering patterns that straddle the
// journal point.
func rewindOffset(rangeStart, offset int64) int64 {
	back := offset - int64(scanOverlap())
	if back <= rangeStart {
		return rangeStart
	}
	return rangeStart + ((back-rangeStart)/blockSize)*blockSize
}

// ResumeRewindOffset is the exported form of rewindOffset for the
// raw single-target resume path in main: resume seeks the rewound
// grid point so straddling patterns still match, while -s keeps
// its exact user offset.
func ResumeRewindOffset(rangeStart, offset int64) int64 {
	return rewindOffset(rangeStart, offset)
}

// readRangeResume loads and validates a range journal: path, exact range
// list, index bounds, offset within the range. It returns the range index
// and offset to continue from; resume=false means the journal records a
// completed list. A missing journal starts over (like single-target
// resume); anything corrupt or mismatched refuses loudly.
func readRangeResume(log io.Writer, file, path string, ranges []FSExtent) (idx int, off int64, resume bool, err error) {
	cp, err := ReadCheckpoint(file)
	if err != nil {
		if os.IsNotExist(err) {
			logLinef(log, "[checkpoint] No checkpoint at %s, starting from the beginning\n", file)
			return 0, -1, true, nil
		}
		return 0, 0, false, err
	}
	if cp.Path != path {
		return 0, 0, false, fmt.Errorf("checkpoint is for %s, not %s: refusing to resume", cp.Path, path)
	}
	if len(cp.Ranges) == 0 {
		return 0, 0, false, fmt.Errorf("checkpoint %s has no range list (single-target journal?): refusing to resume a range scan", file)
	}
	if firstDiff := firstRangeDiff(cp.Ranges, ranges); firstDiff >= 0 {
		return 0, 0, false, fmt.Errorf("checkpoint range list does not match (first difference at range %d): the volume changed; refusing to resume", firstDiff)
	}
	if cp.RangeIndex > len(ranges) {
		return 0, 0, false, fmt.Errorf("checkpoint range index %d beyond %d ranges: refusing to resume", cp.RangeIndex, len(ranges))
	}
	if cp.RangeIndex == len(ranges) {
		return 0, 0, false, nil
	}
	r := ranges[cp.RangeIndex]
	if cp.Offset < r.Start || cp.Offset > r.Start+r.Len {
		return 0, 0, false, fmt.Errorf("checkpoint offset %d outside range %d [%d,%d): refusing to resume",
			cp.Offset, cp.RangeIndex, r.Start, r.Start+r.Len)
	}
	return cp.RangeIndex, cp.Offset, true, nil
}

// pendingFrontier is a journal point: the root offset read so far
// plus, for range scans, the range list and index. Mid-root points
// are written only after a drain proves every byte at or before
// them delivered; the root-end point travels to runPipeline,
// which writes it on clean EOF. digest carries the cumulative
// covered-bytes SHA-256 at the frontier, set only on the
// completion point to pin the whole target for skips; mid-run
// points leave it empty and resume re-covers from the offset.
type pendingFrontier struct {
	desc   string
	offset int64
	ranges []FSExtent
	index  int
	digest string
}

// batchDigest streams the root bytes of one batch scan for the
// manifest digest. Only scanBlocks feeds it, sequentially, so no
// mutex is needed.
type batchDigest struct {
	h hash.Hash
}

func newBatchDigest() *batchDigest {
	return &batchDigest{h: sha256.New()}
}

func (d *batchDigest) write(p []byte) {
	d.h.Write(p)
}

func (d *batchDigest) hex() string {
	return hex.EncodeToString(d.h.Sum(nil))
}

// maxOutstandingPubs caps published-but-unconsumed nested targets
// below the scanTargets channel capacity. Publishers admit through
// the gate instead of blocking on a full channel, so a hostile
// archive (a zip64 directory with millions of members, a target
// dense with local headers) degrades to loud skips instead of
// wedging every stage behind a consumer that cannot run —
// including the mid-root drain, which parks its only consumer on
// a barrier ack. Inputs that complete today with fewer nested
// targets in flight behave exactly as before; only runs that
// would hang now skip, and the run then fails honestly with an
// incomplete-coverage error (never clean completion): the journal
// freezes at its last skip-free proven point so a retry re-covers
// the omitted bytes. A var (not const) so tests can trip the gate
// with small inputs.
var maxOutstandingPubs int64 = 512 * 1024

// pubGate bounds outstanding nested publications. All methods are
// nil-safe: a nil gate admits everything with legacy blocking
// sends, for direct unit-test drivers with no pipeline.
type pubGate struct {
	outstanding atomic.Int64
	skipped     atomic.Int64
	warned      atomic.Bool
	log         io.Writer
}

func newPubGate(log io.Writer) *pubGate {
	return &pubGate{log: log}
}

// tryPublish admits one publication, or refuses past the cap
// (counting the skip and warning once per run).
func (g *pubGate) tryPublish() bool {
	if g == nil {
		return true
	}
	for {
		o := g.outstanding.Load()
		if o >= maxOutstandingPubs {
			g.skipped.Add(1)
			if g.warned.CompareAndSwap(false, true) {
				logLinef(g.log, "[scan] WARNING: nested publication backlog past %d; further archives skip (total reported at end)\n", maxOutstandingPubs)
			}
			return false
		}
		if g.outstanding.CompareAndSwap(o, o+1) {
			return true
		}
	}
}

// forcePublish counts a publication that must run (the seed).
func (g *pubGate) forcePublish() {
	if g == nil {
		return
	}
	g.outstanding.Add(1)
}

// consumed releases one outstanding publication.
func (g *pubGate) consumed() {
	if g == nil {
		return
	}
	g.outstanding.Add(-1)
}

func (g *pubGate) skippedCount() int64 {
	if g == nil {
		return 0
	}
	return g.skipped.Load()
}

// gatePublish sends t unless the gate is full. Admitted sends
// never block: outstanding counts exactly the channel's contents
// (receives are the only removal, each paired with consumed), so
// below the cap the channel always has room.
func gatePublish(g *pubGate, ch chan scanTarget, t scanTarget) bool {
	if !g.tryPublish() {
		return false
	}
	ch <- t
	return true
}

// BatchManifest is the in-memory batch journal. Main owns target
// states and transitions; the detector only fills the active
// entry's proven offset into the FILE it writes, never mutating
// this struct, so ownership stays single-writer on both sides.
type BatchManifest struct {
	Targets []BatchTarget
	Run     BatchRun
}

// journalCtl coordinates proven journaling between scanBlocks and
// runPipeline. Nil means no checkpoint path: no drains, no
// barrier rounds, no completion write — the pipeline behaves
// exactly as if journaling did not exist.
type journalCtl struct {
	// quiet reports pipeline quiescence: every stage queue and
	// the nested backlog observably empty.
	quiet func() bool
	// final carries the root-end frontier to runPipeline, which
	// writes it on clean EOF only: EOF delivery already proves
	// every byte delivered, while error/cancel paths keep the
	// older proven mark instead of certifying doubt. Buffered
	// one: the root ends once, so the send never blocks, and a
	// clean-EOF return always finds it (sent before the EOF).
	final chan *pendingFrontier
	// digest streams the root bytes of a batch scan for the
	// manifest digest. Non-nil only under a batch journal; a
	// completion frontier from a zero start adopts its hex.
	// Truncated or resumed coverage simply never verifies, so a
	// skip falls back to a rescan, never to blind trust.
	digest *batchDigest
}

// writeScanCheckpoint journals root-target progress: a range entry when
// the pipeline runs inside ScanRangesWithOptions, a legacy entry
// otherwise.
// frontierFor builds the journal point for target read up to offset.
func frontierFor(opts Options, target scanTarget, offset int64) *pendingFrontier {
	p := &pendingFrontier{desc: target.Describe(), offset: offset}
	if opts.rangeCtx != nil {
		p.ranges = append([]FSExtent(nil), opts.rangeCtx.ranges...)
		p.index = opts.rangeCtx.index
	}
	return p
}

// writeFrontier journals a proven frontier: a batch manifest entry
// when the pipeline runs under a batch journal, a range entry
// inside ScanRangesWithOptions, a legacy entry otherwise. Batch
// journals always carry Offset 0 in the legacy fields so an old
// binary, which cannot see Targets, falls back to a full rescan
// of a path-matched target instead of silently skipping bytes.
func writeFrontier(opts Options, p *pendingFrontier) {
	log := opts.logWriter()
	if opts.BatchJournal != nil {
		bj := opts.BatchJournal
		tgts := append([]BatchTarget(nil), bj.Targets...)
		for i := range tgts {
			if tgts[i].State == BatchActive {
				tgts[i].Offset = p.offset
				// Only completions carry a digest; mid-run
				// points must not blank one already filed.
				if p.digest != "" {
					tgts[i].SHA256 = p.digest
				}
			}
		}
		cp := Checkpoint{Offset: 0, Targets: tgts}
		if len(tgts) > 0 {
			cp.Path = tgts[0].Path
		} else {
			cp.Path = p.desc
		}
		run := bj.Run
		cp.Run = &run
		WriteBatchJournal(log, opts.CheckpointPath, cp)
		return
	}
	if p.ranges != nil {
		writeCheckpointRange(log, opts.CheckpointPath, p.desc, p.ranges, p.index, p.offset)
		return
	}
	writeCheckpoint(log, opts.CheckpointPath, p.desc, p.offset)
}

// firstRangeDiff returns the first index where two range lists differ, or
// -1 when they match exactly.
func firstRangeDiff(a, b []FSExtent) int {
	if len(a) != len(b) {
		return min(len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			return i
		}
	}
	return -1
}

// runPipeline runs one scan target through the full detection pipeline.
func runPipeline(seed scanTarget, opts Options, onDetection func(Detection), onProgress func(ProgressInfo)) error {
	// The profile gates the detector set for the whole pipeline; an
	// unknown profile fails up front, never mid-scan.
	var secrets bool
	switch opts.Profile {
	case "", "default":
	case "secrets":
		secrets = true
	default:
		return recordAttempt(opts, seed.Describe(), fmt.Errorf("unknown scan profile %q (want \"\" or \"secrets\")", opts.Profile))
	}
	// Shutdown is coordinated through ctx: when the final EOF reaches
	// detectWallets it reports completion, Scan returns, and the deferred
	// cancel below tells every pipeline stage to exit. Channels are never
	// closed while another goroutine may still send on them. The caller's
	// opts.Context (Background when nil) is the parent, so cancelling it
	// stops every stage the same way.
	userCtx := opts.scanContext()
	ctx, cancel := context.WithCancel(userCtx)
	defer cancel()

	var rec *caseRecorder
	if opts.CaseLogPath != "" {
		rec = newCaseRecorder(seed, opts.ToolVersion, opts.Flags, opts.CheckpointPath)
		opts.caseRec = rec
		userDetect := onDetection
		onDetection = func(d Detection) {
			rec.noteDetection()
			userDetect(d)
		}
		userBad := opts.OnBadSector
		opts.OnBadSector = func(target string, start, end int64, err error) {
			rec.noteSkipped(target, start, end, err)
			if userBad != nil {
				userBad(target, start, end, err)
			}
		}
	}

	signals := make(chan error, 10)

	// rootDone carries the root target's outcome from scanBlocks: nil
	// when it was read, the failure otherwise. Buffered so the send
	// never blocks, including after cancellation; only strictRoot
	// pipelines (ScanWithOptions) receive from it.
	rootDone := make(chan error, 1)

	// scanTargets buffers pending nested-archive targets (1M slots ≈
	// 16 MiB of pointers); past that, publishers block rather than grow
	// memory. Depth (maxArchiveDepth) plus per-member caps bound what a
	// hostile archive can queue behind it.
	scanTargets := make(chan scanTarget, 1024*1024)

	emptyBlocks := make(chan *Block, 30)
	zipDetectionQueue := make(chan *Block, 30)
	gzipDetectionQueue := make(chan *Block, 30)
	walletDetectionQueue := make(chan *Block, 30)

	for i := 0; i < 20; i++ {
		emptyBlocks <- &Block{
			offset: 0,
			data:   make([]byte, blockSize+scanOverlap()),
		}
	}

	onComplete := func() {
		signals <- io.EOF
	}

	// 1. Scan target files, breaking them into blocks of data to work with
	// Journal control exists only with a checkpoint path; without
	// one the pipeline behaves exactly as if journaling did not
	// exist (no drains, no barrier rounds, no completion write).
	var jc *journalCtl
	if opts.CheckpointPath != "" {
		jc = &journalCtl{
			quiet: func() bool {
				return len(zipDetectionQueue) == 0 && len(gzipDetectionQueue) == 0 &&
					len(walletDetectionQueue) == 0 && len(scanTargets) == 0
			},
			final: make(chan *pendingFrontier, 1),
		}
		if opts.BatchJournal != nil {
			jc.digest = newBatchDigest()
		}
	}
	gate := newPubGate(opts.logWriter())
	defer func() {
		if n := gate.skippedCount(); n > 0 {
			opts.logf("[scan] WARNING: skipped %d nested archives past the %d publication cap; coverage is incomplete\n", n, maxOutstandingPubs)
		}
	}()
	go scanBlocks(ctx, scanTargets, emptyBlocks, zipDetectionQueue, onProgress, opts, rootDone, jc, gate)

	// 2. Pass blocks to zipfile detection; any files found will be published as new targets
	go scanZipFiles(ctx, zipDetectionQueue, gzipDetectionQueue, scanTargets, opts.logWriter(), gate)

	// 3. Pass blocks to gzip file detection; any files found will be published as new targets
	go scanGzipFiles(ctx, gzipDetectionQueue, walletDetectionQueue, scanTargets, opts.logWriter(), gate)

	// 3. And, finally, pass raw and uncompressed blocks both to wallet detection
	go detectWallets(ctx, walletDetectionQueue, emptyBlocks, onDetection, onComplete, opts, secrets)

	// Publish the seed target to scan
	gate.forcePublish()
	scanTargets <- seed

	// Wait for the system to signal outcome — or for the caller to
	// cancel, which returns promptly with ctx.Err(). Detections
	// already delivered stay delivered; the checkpoint journal keeps
	// its last completed mark (stages exit before writing more).
	select {
	case signal := <-signals:
		if signal == io.EOF && opts.strictRoot {
			// Coverage honesty: a root that failed or covered
			// nothing is an error, not a quiet success. The
			// root outcome precedes EOF through the pipeline,
			// so this receive never blocks.
			if rootErr := <-rootDone; rootErr != nil {
				signal = rootErr
			}
		}
		if signal == io.EOF {
			if n := gate.skippedCount(); n > 0 {
				// Drain-then-error: the pipeline delivered
				// everything admitted, but dropped nested
				// work is omitted coverage, not clean
				// completion. The error keeps the case log
				// (error, never complete), the checkpoint
				// (no completion frontier below), and the
				// batch manifest (failed, never complete)
				// honest; the journal freeze in
				// drainFrontier pins resume to the last
				// skip-free proven point so a retry
				// re-covers the omitted bytes instead of
				// skipping them forever.
				signal = fmt.Errorf("incomplete coverage: skipped %d nested targets past the %d publication cap; retry to recover", n, maxOutstandingPubs)
			}
		}
		if rec != nil {
			status, runErr := "complete", error(nil)
			if signal != io.EOF {
				status, runErr = "error", signal
			}
			if err := appendCaseLog(opts.CaseLogPath, rec.finish(status, runErr)); err != nil {
				return fmt.Errorf("case log: %w", err)
			}
		}
		if signal == io.EOF {
			// Clean EOF proves every byte delivered (final-EOF
			// forwarding implies every published target was
			// read and every block processed), so the
			// completion frontier is safe to journal now.
			// Error paths keep the older proven mark
			// instead of certifying doubt.
			if jc != nil {
				select {
				case ff := <-jc.final:
					writeFrontier(opts, ff)
				default:
				}
			}
			return nil
		}
		return signal
	case <-userCtx.Done():
		if rec != nil {
			if err := appendCaseLog(opts.CaseLogPath, rec.finish("canceled", userCtx.Err())); err != nil {
				return fmt.Errorf("case log: %w", err)
			}
		}
		return userCtx.Err()
	}
}

func scanBlocks(ctx context.Context, targets chan scanTarget, emptyBlocks chan *Block, out chan *Block,
	onProgress func(ProgressInfo), opts Options, rootDone chan<- error, jc *journalCtl, gate *pubGate) {
	firstTarget := true
	for {
		var target scanTarget
		select {
		case <-ctx.Done():
			return
		case target = <-targets:
		}
		gate.consumed()

		// Only the root target is journaled; nested archives re-scan on
		// resume, which is cheap relative to the device that holds them.
		isRoot := firstTarget
		firstTarget = false
		outcome, alive := readTarget(ctx, targets, emptyBlocks, out, onProgress, opts, jc, gate, target, isRoot)
		if !alive {
			return
		}
		if isRoot && opts.strictRoot {
			// The root promised bytes but yielded none (vanished
			// mid-run, fully unreadable): that is a failed scan,
			// not a clean one. Unknown or already-consumed sizes
			// (empty files, resume at EOF, -s past the end) stay
			// successes.
			if outcome.rootErr == nil && outcome.covered == 0 && outcome.expected > 0 {
				outcome.rootErr = fmt.Errorf("cannot scan %s: covered 0 of %d expected bytes",
					target.Describe(), outcome.expected)
			}
			rootDone <- outcome.rootErr
		}
		if isRoot && jc != nil && outcome.opened {
			// The completion frontier supersedes any 1MB point;
			// runPipeline writes it on clean EOF, when delivery
			// is proven. A clean full pass from zero also
			// certifies the covered-bytes digest, so a later
			// skip can re-hash instead of trusting metadata.
			ff := frontierFor(opts, target, outcome.end)
			if jc.digest != nil && target.StartOffset() == 0 {
				ff.digest = jc.digest.hex()
			}
			jc.final <- ff
		}
	}
}

// readOutcome carries a finished target read back to scanBlocks:
// bytes covered and expected for strict accounting, the end
// offset for the completion frontier. opened is false when the
// target never yielded a reader.
type readOutcome struct {
	covered  int64
	expected int64
	end      int64
	opened   bool
	rootErr  error
}

// readTarget reads one target fully into blocks, pushing exactly
// one EOF unless canceled. It is reentrant: every read owns its
// file, offset, and tail as locals, so a mid-root drain can pause
// the root by reading nested targets — the stack is the
// save/restore. Only root reads drain and journal (jc non-nil);
// nested reads are plain, so drains never nest.
func readTarget(ctx context.Context, targets chan scanTarget, emptyBlocks chan *Block, out chan *Block,
	onProgress func(ProgressInfo), opts Options, jc *journalCtl, gate *pubGate, target scanTarget, isRoot bool) (readOutcome, bool) {
	var outcome readOutcome
	var f TargetReader
	defer func() {
		// Close before the EOF downstream: the completion races
		// ahead, and on Windows an open handle blocks deleting
		// the file (including test TempDir cleanup) after Scan
		// returns. Every return below pushes its EOF first.
		if f != nil {
			f.Close()
		}
	}()
	var currentOffset int64
	overlap := scanOverlap()
	tail := make([]byte, overlap)
	var haveTail bool
	var blocksSinceCheckpoint int
	strict := isRoot && opts.strictRoot
	// Every target yields exactly one EOF unless canceled; the
	// stages' publish/consume balance depends on it.
	pushEOF := func() bool {
		select {
		case <-ctx.Done():
			return false
		case out <- EOF:
			return true
		}
	}

	opts.logf("[scan] Starting new target: %s\n", target.Describe())
	totalBytes, err := target.Size()
	if err != nil {
		if !strict {
			opts.logf("[scan] Unable to scan target: %s\n", err.Error())
			return outcome, pushEOF()
		}
		// The size feeds only the progress total and the
		// coverage check: a strict root with an unreadable
		// size (empty file, device node) still gets its
		// Open attempt below, with an unknown total like
		// nested gzip members. No warning here: Open and
		// the read loop report real failures themselves,
		// and an unsized-but-readable root is a success.
		totalBytes = -1
	}
	if strict {
		outcome.expected = totalBytes - target.StartOffset()
	}

	if f, err = target.Open(); err != nil {
		opts.logf("[scan] Unable to scan target: %s\n", err.Error())
		if strict {
			outcome.rootErr = fmt.Errorf("cannot scan %s: %w", target.Describe(), err)
		}
		return outcome, pushEOF()
	}
	outcome.opened = true

	if _, err = f.Seek(target.StartOffset(), 0); err != nil {
		opts.logf("[scan] Unable to scan target: %s\n", err.Error())
		if strict {
			outcome.rootErr = fmt.Errorf("cannot scan %s: %w", target.Describe(), err)
		}
		return outcome, pushEOF()
	}

	currentOffset = target.StartOffset()
	haveTail = false
readLoop:
	for {
		var block *Block
		select {
		case <-ctx.Done():
			return outcome, false
		case block = <-emptyBlocks:
		}

		prefix := 0
		if haveTail {
			copy(block.data, tail)
			prefix = overlap
		}
		read, err := io.ReadFull(f, block.data[prefix:prefix+blockSize])
		if read == 0 && isCleanEnd(err) {
			// Normal end of target; the block is unused.
			emptyBlocks <- block
			break readLoop
		}
		if read == 0 {
			// Hard read error with no bytes. On seekable targets the
			// range is retried, then skipped so the rest of the target
			// is still scanned; a skipped gap breaks overlap continuity.
			var seekable bool
			read, err, seekable = retryBlockRead(f, block.data[prefix:prefix+blockSize], currentOffset)
			if read == 0 && isCleanEnd(err) {
				emptyBlocks <- block
				break readLoop
			}
			if read == 0 && !seekable {
				opts.logf("[scan] Unable to scan target: %s\n", err.Error())
				if strict && outcome.rootErr == nil {
					outcome.rootErr = fmt.Errorf("cannot scan %s: %w", target.Describe(), err)
				}
				emptyBlocks <- block
				break readLoop
			}
			if read == 0 {
				reportBadSector(target, currentOffset, currentOffset+blockSize, err, opts.OnBadSector, opts.logWriter())
				currentOffset += blockSize
				haveTail = false
				emptyBlocks <- block
				// Position is indeterminate after failed reads.
				if _, serr := f.Seek(currentOffset, io.SeekStart); serr != nil {
					opts.logf("[scan] Unable to scan target: %s\n", serr.Error())
					if strict && outcome.rootErr == nil {
						outcome.rootErr = fmt.Errorf("cannot scan %s: %w", target.Describe(), serr)
					}
					break readLoop
				}
				continue
			}
		}
		if strict {
			outcome.covered += int64(read)
		}
		// A partial read with an error still yields a valid block: the
		// bytes already returned are real target data. This matters for
		// nested gzip streams followed by trailing garbage, where the
		// reader reports the end of the stream as a format error instead
		// of a clean EOF.

		// The block carries the overlap prefix plus the newly read bytes.
		// block.offset pins the absolute offset of data[0] so archive
		// scanners derive exact nested offsets; the reported location
		// stays on the logical block start to keep offsets stable.
		block.length = prefix + read
		block.overlap = prefix
		block.offset = currentOffset - int64(prefix)
		if opts.caseRec != nil && isRoot {
			// Only the newly read bytes: the overlap prefix was
			// hashed with the previous block, skipped ranges never.
			opts.caseRec.hash(block.data[prefix : prefix+read])
		}
		if jc != nil && jc.digest != nil && isRoot {
			// Manifest digest over the same covered bytes.
			jc.digest.write(block.data[prefix : prefix+read])
		}
		block.final = isCleanEnd(err)
		block.location = fmt.Sprintf("%s in %dkB block at byte offset %d", target.Describe(), blockSize/1024, currentOffset)
		block.source = target

		if block.length >= overlap {
			copy(tail, block.data[block.length-overlap:block.length])
		}
		haveTail = true
		currentOffset += int64(read)
		scanned := currentOffset
		if totalBytes > 0 && scanned > totalBytes {
			scanned = totalBytes // skips may step past the end
		}
		onProgress(ProgressInfo{
			CurrentTarget:    target.Describe(),
			ScannedBytes:     scanned,
			TotalBytes:       totalBytes,
			UnscannedTargets: len(targets)})

		abort := false
		if err != nil && !isCleanEnd(err) {
			// Good bytes above, but the stream position is
			// indeterminate: reposition so the next read retries the
			// failed region. Non-seekable targets end here instead.
			if _, serr := f.Seek(currentOffset, io.SeekStart); serr != nil {
				abort = true
			}
		}
		select {
		case <-ctx.Done():
			return outcome, false
		case out <- block:
		}

		if isRoot && jc != nil {
			blocksSinceCheckpoint++
			if blocksSinceCheckpoint >= checkpointBlockInterval {
				blocksSinceCheckpoint = 0
				// Mid-root drain, after the block is pushed:
				// the frontier counts this block's bytes, so
				// it must travel downstream before the drain
				// proves it delivered. Draining first would
				// journal bytes still in hand — a kill in
				// that window would strand them past the
				// rewind. Barriers fire only here, where the
				// root EOF is provably unpushed, so
				// detectWallets is provably alive and the ack
				// cannot strand.
				if !drainFrontier(ctx, targets, emptyBlocks, out, onProgress, opts, jc, gate, target, currentOffset) {
					return outcome, false
				}
			}
		}
		if block.final || abort {
			break readLoop
		}
	}
	outcome.end = currentOffset
	return outcome, pushEOF()
}

// drainFrontier proves a mid-root journal point: it consumes the
// whole nested backlog through plain nested reads, then
// barrier-rounds until a quiet observation, then journals. The
// caller's root read state rests in its own frame, so the stack
// is the save/restore; nested reads never drain, so drains never
// nest. Barriers fire only here, where the root EOF is provably
// unpushed, so detectWallets is provably alive and the ack cannot
// strand; EOF balance (each published target read exactly once
// with exactly one EOF) keeps nested EOFs consumed upstream no
// matter the interleave. The publication gate caps outstanding
// targets below channel capacity, so an admitted send never
// blocks — even a million-member archive in flight degrades to
// counted skips instead of wedging the barrier behind a stuck
// publisher — and the ack always arrives. Each round strictly
// shrinks undiscovered work, so the drain terminates; on cancel
// it reports false.
func drainFrontier(ctx context.Context, targets chan scanTarget, emptyBlocks chan *Block, out chan *Block,
	onProgress func(ProgressInfo), opts Options, jc *journalCtl, gate *pubGate, root scanTarget, offset int64) bool {
	for {
		drained := false
		for !drained {
			select {
			case <-ctx.Done():
				return false
			case nested := <-targets:
				gate.consumed()
				if _, alive := readTarget(ctx, targets, emptyBlocks, out, onProgress, opts, jc, gate, nested, false); !alive {
					return false
				}
			default:
				drained = true
			}
		}
		ack := make(chan struct{}, 1)
		select {
		case <-ctx.Done():
			return false
		case out <- &Block{barrier: ack}:
		}
		select {
		case <-ctx.Done():
			return false
		case <-ack:
		}
		if !jc.quiet() {
			continue
		}
		if gate.skippedCount() == 0 {
			writeFrontier(opts, frontierFor(opts, root, offset))
		}
		// A skip counted by now poisons this frontier: some
		// nested work from already-read root bytes was
		// dropped, and journaling past it would let a resume
		// skip those bytes forever. Freeze the journal at its
		// last skip-free proven point instead — earlier
		// points stand, because the barrier ack proves every
		// pre-barrier block fully processed, so a skip
		// counted later concerns only later bytes. The EOF
		// error above forces a retry from the frozen point,
		// which re-covers the omitted bytes.
		return true
	}
}

// isCleanEnd reports the read outcomes that mean a target simply ended.
func isCleanEnd(err error) bool {
	return err == io.EOF || err == io.ErrUnexpectedEOF
}

// retryBlockRead re-attempts a failed block read, seeking back to the absolute
// offset before each attempt. It returns the final outcome: recovered bytes,
// a clean end, or a persistent failure. seekable is false when the target
// cannot be repositioned at all, in which case recovery is impossible.
func retryBlockRead(f TargetReader, buf []byte, offset int64) (read int, err error, seekable bool) {
	for attempt := 0; attempt < maxReadAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(readRetryBackoff(attempt))
		}
		if _, serr := f.Seek(offset, io.SeekStart); serr != nil {
			return 0, serr, false
		}
		read, err = io.ReadFull(f, buf)
		if read > 0 || isCleanEnd(err) {
			return read, err, true
		}
	}
	return 0, err, true
}

func reportBadSector(target scanTarget, start, end int64, err error, onBadSector BadSectorFunc, log io.Writer) {
	logLinef(log, "[scan] Skipping unreadable bytes %d-%d in %s: %s\n",
		start, end, target.Describe(), err.Error())
	if onBadSector != nil {
		onBadSector(target.Describe(), start, end, err)
	}
}

var needles = [][]byte{
	// BTC wallets are Berkeley DBs, details on them here: https://github.com/berkeleydb/libdb/blob/master/src/dbinc/db.in
	// The byte chunks below are btc-specific keys that appear in wallets.
	[]byte("orderposnext"),
	[]byte("addrIncoming"),
	[]byte("bestblock"),
	[]byte("defaultkey"),
	[]byte("acentry"),

	// Keys from encrypted and HD legacy wallets.
	[]byte("crypted_key"),
	[]byte("hdseed"),
	[]byte("keymeta"),

	// Keys from modern SQLite descriptor wallets.
	[]byte("walletdescriptor"),
	[]byte("activeblock"),

	// Also worth looking for the standard wallet file name; it might appear both in inodes and in zip file indexes
	[]byte("wallet.dat"),

	// Lightning (lnd): channel.db is bbolt with these bucket names; the
	// .backup file itself is chacha20-encrypted (no content magic), so its
	// file name is the only signal, found in directory entries.
	[]byte("channel.backup"),
	[]byte("channel.db"),
	[]byte("open-chan-bucket"),
	[]byte("closed-chan-bucket"),

	// Deliberately absent: the bare "SQLite format 3" magic (every browser
	// database on the disk would match) and the 4-byte "mkey"/"ckey" keys
	// (expected hundreds of thousands of random hits per terabyte).
}

// Scan blocks for traces of bitcoin wallets, the function will
// wait in blocks on in until it sees EOF, and output scanned blocks
// to out for reuse.
func detectWallets(ctx context.Context, in chan *Block, out chan *Block, onDetection func(Detection), onComplete func(), opts Options, secrets bool) {
	carve := carveConfig{dir: opts.CarveDir, contextBytes: opts.CarveContextBytes, seqStart: opts.CarveSeqStart}
	reveal := opts.Reveal
	seq := carve.seqStart
	for {
		var block *Block
		select {
		case <-ctx.Done():
			return
		case block = <-in:
		}
		if block == EOF {
			onComplete()
			return
		}
		if block.barrier != nil {
			// Drain barrier: every block ahead of it is
			// delivered (FIFO chain), so acknowledge. Not
			// a completion: no onComplete, no recycle.
			block.barrier <- struct{}{}
			continue
		}
		data := block.data[:block.length]
		for _, needle := range needles {
			// Each needle is reported once per block; occurrences fully
			// inside the overlap prefix were already reported with the
			// previous block, keeping exactly-once semantics.
			for i := 0; i+len(needle) <= len(data); {
				j := bytes.Index(data[i:], needle)
				if j == -1 {
					break
				}
				if i+j+len(needle) > block.overlap {
					d := Detection{
						Description: fmt.Sprintf("Found '%s' at %s", needle, block.location),
						Needle:      string(needle),
						Offset:      block.offset + int64(i+j),
						Target:      block.source.Describe(),
						BlockOffset: block.offset + int64(block.overlap),
						MatchLen:    len(needle),
					}
					if carve.dir != "" {
						seq++
						if err := carveDetection(block.source, &d, carve.dir, carve.contextBytes, seq, opts.logWriter()); err != nil {
							opts.logf("[carve] warning: could not carve '%s' at %s byte %d: %s\n",
								needle, d.Target, d.Offset, err.Error())
						}
					}
					onDetection(d)
					break
				}
				i += j + 1
			}
		}
		// Seed phrases use the same exactly-once rule: a phrase ending past
		// the logical block start is reported here, otherwise it was already
		// reported with an earlier block. Only labels, positions, and counts
		// are ever printed; words stay out of logs and output unless reveal.
		// Electrum and SLIP39 seeds compute here too: validated seeds of
		// any wordlist suppress the weaker unordered hint below.
		exact, near, unordered := findBIP39Phrases(data, block.offset, block.overlap == 0, block.final)
		electrumSeeds := findElectrumSeeds(data, block.offset, block.overlap == 0, block.final)
		slip39Seeds := findSLIP39(data, block.offset, block.overlap == 0, block.final)
		for _, m := range exact {
			if m.endAbs > block.offset+int64(block.overlap) {
				label := fmt.Sprintf("bip39-%d", m.words)
				d := Detection{
					Description: fmt.Sprintf("Found '%s seed phrase' at %s", label, block.location),
					Needle:      label,
					Offset:      m.startAbs,
					Target:      block.source.Describe(),
					BlockOffset: block.offset + int64(block.overlap),
					MatchLen:    int(m.endAbs - m.startAbs),
				}
				if reveal {
					d.Words = m.phrase
				}
				if carve.dir != "" {
					seq++
					if err := carveDetection(block.source, &d, carve.dir, carve.contextBytes, seq, opts.logWriter()); err != nil {
						opts.logf("[carve] warning: could not carve '%s' at %s byte %d: %s\n",
							label, d.Target, d.Offset, err.Error())
					}
				}
				onDetection(d)
			}
		}
		for _, m := range near {
			if m.endAbs > block.offset+int64(block.overlap) {
				label := fmt.Sprintf("bip39-%d-near-miss", m.words)
				d := Detection{
					Description: fmt.Sprintf("Found '%s %s' at %s", label, m.pattern(), block.location),
					Needle:      label,
					Offset:      m.startAbs,
					Target:      block.source.Describe(),
					BlockOffset: block.offset + int64(block.overlap),
					MatchLen:    int(m.endAbs - m.startAbs),
				}
				if reveal {
					d.Words = m.phrase
				}
				if carve.dir != "" {
					seq++
					if err := carveDetection(block.source, &d, carve.dir, carve.contextBytes, seq, opts.logWriter()); err != nil {
						opts.logf("[carve] warning: could not carve '%s' at %s byte %d: %s\n",
							label, d.Target, d.Offset, err.Error())
					}
				}
				onDetection(d)
			}
		}
		for _, m := range unordered {
			if m.endAbs > block.offset+int64(block.overlap) {
				if unorderedSuppressedBySeed(m, electrumSeeds, slip39Seeds) {
					continue
				}
				label := "bip39-unordered"
				d := Detection{
					Description: fmt.Sprintf("Found '%s run=%d' at %s", label, m.words, block.location),
					Needle:      label,
					Offset:      m.startAbs,
					Target:      block.source.Describe(),
					BlockOffset: block.offset + int64(block.overlap),
					MatchLen:    int(m.endAbs - m.startAbs),
				}
				if reveal {
					d.Words = m.phrase
				}
				if carve.dir != "" {
					seq++
					if err := carveDetection(block.source, &d, carve.dir, carve.contextBytes, seq, opts.logWriter()); err != nil {
						opts.logf("[carve] warning: could not carve '%s' at %s byte %d: %s\n",
							label, d.Target, d.Offset, err.Error())
					}
				}
				onDetection(d)
			}
		}
		// Opt-in secret matchers share the same exactly-once rule and
		// privacy discipline: labels and offsets only, never secret
		// material. They run only under the secrets profile; the
		// default profile never reaches this branch.
		if secrets {
			for _, m := range findSecrets(data, block.offset, block.overlap == 0, block.final) {
				if m.endAbs > block.offset+int64(block.overlap) {
					d := Detection{
						Description: secretDescription(m.label, m.kind, block.location),
						Needle:      m.label,
						Offset:      m.startAbs,
						Target:      block.source.Describe(),
						BlockOffset: block.offset + int64(block.overlap),
						MatchLen:    int(m.endAbs - m.startAbs),
						Verified:    m.verified,
					}
					if carve.dir != "" {
						seq++
						if err := carveDetection(block.source, &d, carve.dir, carve.contextBytes, seq, opts.logWriter()); err != nil {
							opts.logf("[carve] warning: could not carve '%s' at %s byte %d: %s\n",
								m.label, d.Target, d.Offset, err.Error())
						}
					}
					onDetection(d)
				}
			}
		}
		// Private and extended keys share the seed-phrase reporting rule and
		// its privacy discipline: type labels only, never key material.
		for _, m := range findKeys(data, block.offset, block.overlap == 0, block.final) {
			if m.endAbs > block.offset+int64(block.overlap) {
				d := Detection{
					Description: keyDescription(m.label, m.kind, block.location),
					Needle:      m.label,
					Offset:      m.startAbs,
					Target:      block.source.Describe(),
					BlockOffset: block.offset + int64(block.overlap),
					MatchLen:    int(m.endAbs - m.startAbs),
				}
				if carve.dir != "" {
					seq++
					if err := carveDetection(block.source, &d, carve.dir, carve.contextBytes, seq, opts.logWriter()); err != nil {
						opts.logf("[carve] warning: could not carve '%s' at %s byte %d: %s\n",
							m.label, d.Target, d.Offset, err.Error())
					}
				}
				onDetection(d)
			}
		}
		// Keystore objects share the same exactly-once rule: only objects
		// ending past the logical block start report here.
		for _, m := range findKeystores(data, block.offset) {
			if m.endAbs > block.offset+int64(block.overlap) {
				d := Detection{
					Description: keystoreDescription(block.location),
					Needle:      "eth-keystore",
					Offset:      m.startAbs,
					Target:      block.source.Describe(),
					BlockOffset: block.offset + int64(block.overlap),
					MatchLen:    int(m.endAbs - m.startAbs),
				}
				if carve.dir != "" {
					seq++
					if err := carveDetection(block.source, &d, carve.dir, carve.contextBytes, seq, opts.logWriter()); err != nil {
						opts.logf("[carve] warning: could not carve 'eth-keystore' at %s byte %d: %s\n",
							d.Target, d.Offset, err.Error())
					}
				}
				onDetection(d)
			}
		}
		// Goal 6 formats share the reporting rule and the privacy
		// discipline: type labels only, never key or seed material
		// (words ride along only with --reveal, like BIP39).
		for _, m := range electrumSeeds {
			if m.endAbs > block.offset+int64(block.overlap) {
				if suppressedByBIP39(m, exact) {
					continue
				}
				d := Detection{
					Description: fmt.Sprintf("Found 'electrum-seed' at %s", block.location),
					Needle:      "electrum-seed",
					Offset:      m.startAbs,
					Target:      block.source.Describe(),
					BlockOffset: block.offset + int64(block.overlap),
					MatchLen:    int(m.endAbs - m.startAbs),
				}
				if reveal {
					d.Words = m.phrase
				}
				if carve.dir != "" {
					seq++
					if err := carveDetection(block.source, &d, carve.dir, carve.contextBytes, seq, opts.logWriter()); err != nil {
						opts.logf("[carve] warning: could not carve 'electrum-seed' at %s byte %d: %s\n",
							d.Target, d.Offset, err.Error())
					}
				}
				onDetection(d)
			}
		}
		for _, m := range findElectrumFiles(data, block.offset, block.overlap == 0, block.final) {
			if m.endAbs > block.offset+int64(block.overlap) {
				d := Detection{
					Description: fmt.Sprintf("Found 'electrum-file' at %s", block.location),
					Needle:      "electrum-file",
					Offset:      m.startAbs,
					Target:      block.source.Describe(),
					BlockOffset: block.offset + int64(block.overlap),
					MatchLen:    int(m.endAbs - m.startAbs),
				}
				if carve.dir != "" {
					seq++
					if err := carveDetection(block.source, &d, carve.dir, carve.contextBytes, seq, opts.logWriter()); err != nil {
						opts.logf("[carve] warning: could not carve 'electrum-file' at %s byte %d: %s\n",
							d.Target, d.Offset, err.Error())
					}
				}
				onDetection(d)
			}
		}
		for _, m := range findDescriptors(data, block.offset, block.overlap == 0, block.final) {
			if m.endAbs > block.offset+int64(block.overlap) {
				d := Detection{
					Description: fmt.Sprintf("Found 'descriptor' at %s", block.location),
					Needle:      "descriptor",
					Offset:      m.startAbs,
					Target:      block.source.Describe(),
					BlockOffset: block.offset + int64(block.overlap),
					MatchLen:    int(m.endAbs - m.startAbs),
				}
				if carve.dir != "" {
					seq++
					if err := carveDetection(block.source, &d, carve.dir, carve.contextBytes, seq, opts.logWriter()); err != nil {
						opts.logf("[carve] warning: could not carve 'descriptor' at %s byte %d: %s\n",
							d.Target, d.Offset, err.Error())
					}
				}
				onDetection(d)
			}
		}
		for _, m := range slip39Seeds {
			if m.endAbs > block.offset+int64(block.overlap) {
				label := fmt.Sprintf("slip39-%d", m.words)
				d := Detection{
					Description: fmt.Sprintf("Found '%s share' at %s", label, block.location),
					Needle:      label,
					Offset:      m.startAbs,
					Target:      block.source.Describe(),
					BlockOffset: block.offset + int64(block.overlap),
					MatchLen:    int(m.endAbs - m.startAbs),
				}
				if reveal {
					d.Words = m.phrase
				}
				if carve.dir != "" {
					seq++
					if err := carveDetection(block.source, &d, carve.dir, carve.contextBytes, seq, opts.logWriter()); err != nil {
						opts.logf("[carve] warning: could not carve '%s' at %s byte %d: %s\n",
							label, d.Target, d.Offset, err.Error())
					}
				}
				onDetection(d)
			}
		}
		for _, m := range findMetaMask(data, block.offset, block.overlap == 0, block.final) {
			if m.endAbs > block.offset+int64(block.overlap) {
				d := Detection{
					Description: fmt.Sprintf("Found 'metamask-vault' at %s", block.location),
					Needle:      "metamask-vault",
					Offset:      m.startAbs,
					Target:      block.source.Describe(),
					BlockOffset: block.offset + int64(block.overlap),
					MatchLen:    int(m.endAbs - m.startAbs),
				}
				if carve.dir != "" {
					seq++
					if err := carveDetection(block.source, &d, carve.dir, carve.contextBytes, seq, opts.logWriter()); err != nil {
						opts.logf("[carve] warning: could not carve 'metamask-vault' at %s byte %d: %s\n",
							d.Target, d.Offset, err.Error())
					}
				}
				onDetection(d)
			}
		}
		select {
		case <-ctx.Done():
			return
		case out <- block:
		}
	}
}
