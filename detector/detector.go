package detector

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
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
	// "v1/<relpath>/<needle>/<line-hash>". Set only by -walk sweeps,
	// which know the tree root; empty everywhere else.
	Fingerprint string `json:"fingerprint,omitempty"`
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
	// flows through the onDetection callback.
	Log io.Writer
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

// logf writes one diagnostics line to the configured sink.
func (o Options) logf(format string, args ...any) {
	fmt.Fprintf(o.logWriter(), format, args...)
}

// logLinef writes to an explicit sink, defaulting nil to os.Stderr,
// for helpers that receive the writer instead of full Options.
func logLinef(w io.Writer, format string, args ...any) {
	if w == nil {
		w = os.Stderr
	}
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
func ScanWithOptions(startOffset int64, path string, opts Options, onDetection func(Detection), onProgress func(ProgressInfo)) error {
	onDetection, onProgress = withDefaultCallbacks(onDetection, onProgress)
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("cannot scan %s: %w", path, err)
	}
	if opts.CarveDir != "" {
		if err := os.MkdirAll(opts.CarveDir, 0755); err != nil {
			return fmt.Errorf("cannot create carve directory %s: %w", opts.CarveDir, err)
		}
	}
	target, err := detectScanTarget(path, startOffset)
	if err != nil {
		return err
	}
	return runPipeline(target, opts, onDetection, onProgress)
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
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("cannot scan %s: %w", path, err)
	}
	if opts.CarveDir != "" {
		if err := os.MkdirAll(opts.CarveDir, 0755); err != nil {
			return fmt.Errorf("cannot create carve directory %s: %w", opts.CarveDir, err)
		}
	}
	startIdx := 0
	var startOff int64 = -1
	if opts.Resume {
		if opts.CheckpointPath == "" {
			return fmt.Errorf("resume requires a checkpoint path")
		}
		idx, off, resume, err := readRangeResume(opts.logWriter(), opts.CheckpointPath, path, ranges)
		if err != nil {
			return err
		}
		if !resume {
			return nil // journal says the list already completed
		}
		startIdx, startOff = idx, off
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

// writeScanCheckpoint journals root-target progress: a range entry when
// the pipeline runs inside ScanRangesWithOptions, a legacy entry
// otherwise.
func writeScanCheckpoint(opts Options, target scanTarget, offset int64) {
	log := opts.logWriter()
	if opts.rangeCtx != nil {
		writeCheckpointRange(log, opts.CheckpointPath, target.Describe(), opts.rangeCtx.ranges, opts.rangeCtx.index, offset)
		return
	}
	writeCheckpoint(log, opts.CheckpointPath, target.Describe(), offset)
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
		return fmt.Errorf("unknown scan profile %q (want \"\" or \"secrets\")", opts.Profile)
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
	go scanBlocks(ctx, scanTargets, emptyBlocks, zipDetectionQueue, onProgress, opts)

	// 2. Pass blocks to zipfile detection; any files found will be published as new targets
	go scanZipFiles(ctx, zipDetectionQueue, gzipDetectionQueue, scanTargets, opts.logWriter())

	// 3. Pass blocks to gzip file detection; any files found will be published as new targets
	go scanGzipFiles(ctx, gzipDetectionQueue, walletDetectionQueue, scanTargets, opts.logWriter())

	// 3. And, finally, pass raw and uncompressed blocks both to wallet detection
	go detectWallets(ctx, walletDetectionQueue, emptyBlocks, onDetection, onComplete, opts, secrets)

	// Publish the seed target to scan
	scanTargets <- seed

	// Wait for the system to signal outcome — or for the caller to
	// cancel, which returns promptly with ctx.Err(). Detections
	// already delivered stay delivered; the checkpoint journal keeps
	// its last completed mark (stages exit before writing more).
	select {
	case signal := <-signals:
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
	onProgress func(ProgressInfo), opts Options) {
	var f TargetReader
	var currentOffset int64
	overlap := scanOverlap()
	tail := make([]byte, overlap)
	var haveTail bool
	firstTarget := true
	var checkpointRoot bool
	var blocksSinceCheckpoint int

	for {
		var target scanTarget
		select {
		case <-ctx.Done():
			return
		case target = <-targets:
		}

		// Only the root target is journaled; nested archives re-scan on
		// resume, which is cheap relative to the device that holds them.
		checkpointRoot = firstTarget
		firstTarget = false

		opts.logf("[scan] Starting new target: %s\n", target.Describe())
		totalBytes, err := target.Size()
		if err != nil {
			opts.logf("[scan] Unable to scan target: %s\n", err.Error())
			goto nextTarget
		}

		if f, err = target.Open(); err != nil {
			opts.logf("[scan] Unable to scan target: %s\n", err.Error())
			goto nextTarget
		}

		if _, err = f.Seek(target.StartOffset(), 0); err != nil {
			opts.logf("[scan] Unable to scan target: %s\n", err.Error())
			goto nextTarget
		}

		currentOffset = target.StartOffset()
		haveTail = false
		for {
			var block *Block
			select {
			case <-ctx.Done():
				f.Close()
				return
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
				goto nextTarget
			}
			if read == 0 {
				// Hard read error with no bytes. On seekable targets the
				// range is retried, then skipped so the rest of the target
				// is still scanned; a skipped gap breaks overlap continuity.
				var seekable bool
				read, err, seekable = retryBlockRead(f, block.data[prefix:prefix+blockSize], currentOffset)
				if read == 0 && isCleanEnd(err) {
					emptyBlocks <- block
					goto nextTarget
				}
				if read == 0 && !seekable {
					opts.logf("[scan] Unable to scan target: %s\n", err.Error())
					emptyBlocks <- block
					goto nextTarget
				}
				if read == 0 {
					reportBadSector(target, currentOffset, currentOffset+blockSize, err, opts.OnBadSector, opts.logWriter())
					currentOffset += blockSize
					haveTail = false
					emptyBlocks <- block
					// Position is indeterminate after failed reads.
					if _, serr := f.Seek(currentOffset, io.SeekStart); serr != nil {
						opts.logf("[scan] Unable to scan target: %s\n", serr.Error())
						goto nextTarget
					}
					continue
				}
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
			if opts.caseRec != nil && checkpointRoot {
				// Only the newly read bytes: the overlap prefix was
				// hashed with the previous block, skipped ranges never.
				opts.caseRec.hash(block.data[prefix : prefix+read])
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

			if checkpointRoot && opts.CheckpointPath != "" {
				blocksSinceCheckpoint++
				if blocksSinceCheckpoint >= checkpointBlockInterval {
					blocksSinceCheckpoint = 0
					writeScanCheckpoint(opts, target, currentOffset)
				}
			}

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
				f.Close()
				return
			case out <- block:
			}
			if block.final || abort {
				goto nextTarget
			}
		}

	nextTarget:
		if checkpointRoot && opts.CheckpointPath != "" && f != nil {
			writeScanCheckpoint(opts, target, currentOffset)
		}
		// Close before signalling EOF downstream: the completion races
		// ahead, and on Windows an open handle blocks deleting the file
		// (including test TempDir cleanup) after Scan returns.
		if f != nil {
			f.Close()
			f = nil
		}
		select {
		case <-ctx.Done():
			return
		case out <- EOF:
		}
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
