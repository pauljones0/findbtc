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
// including the widest seed phrase and keystore spans.
func scanOverlap() int {
	max := bip39MaxSpan + 1
	if keystoreMaxSpan+1 > max {
		max = keystoreMaxSpan + 1
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
	maxArchiveDepth = 8
	// maxZipMemberBytes caps the in-memory inflation of one zip member.
	maxZipMemberBytes = 1 << 30
)

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

// Scan runs the detection system with default options; see ScanWithOptions.
func Scan(startOffset int64, path string, onDetection func(Detection), onProgress func(ProgressInfo)) error {
	return ScanWithOptions(startOffset, path, Options{}, onDetection, onProgress)
}

// Bootstrap and run the detection system, scanning the given path
// for remnants of wallets. Normally, the path given would
// be a raw device file handle, like /dev/sdb or some such; the system
// would then scan every sector of that device
func ScanWithOptions(startOffset int64, path string, opts Options, onDetection func(Detection), onProgress func(ProgressInfo)) error {
	// Shutdown is coordinated through ctx: when the final EOF reaches
	// detectWallets it reports completion, Scan returns, and the deferred
	// cancel below tells every pipeline stage to exit. Channels are never
	// closed while another goroutine may still send on them.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("cannot scan %s: %w", path, err)
	}
	if opts.CarveDir != "" {
		if err := os.MkdirAll(opts.CarveDir, 0755); err != nil {
			return fmt.Errorf("cannot create carve directory %s: %w", opts.CarveDir, err)
		}
	}

	signals := make(chan error, 10)

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
	go scanZipFiles(ctx, zipDetectionQueue, gzipDetectionQueue, scanTargets)

	// 3. Pass blocks to gzip file detection; any files found will be published as new targets
	go scanGzipFiles(ctx, gzipDetectionQueue, walletDetectionQueue, scanTargets)

	// 3. And, finally, pass raw and uncompressed blocks both to wallet detection
	go detectWallets(walletDetectionQueue, emptyBlocks, onDetection, onComplete,
		carveConfig{dir: opts.CarveDir, contextBytes: opts.CarveContextBytes})

	// Publish the source file as the first target to scan
	scanTargets <- &fileScanTarget{
		startOffset: startOffset,
		path:        path,
	}

	// Wait for system to signal outcome
	signal := <-signals
	if signal == io.EOF {
		return nil
	}

	return signal
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

		fmt.Fprintf(os.Stderr, "[scan] Starting new target: %s\n", target.Describe())
		totalBytes, err := target.Size()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[scan] Unable to scan target: %s\n", err.Error())
			goto nextTarget
		}

		if f, err = target.Open(); err != nil {
			fmt.Fprintf(os.Stderr, "[scan] Unable to scan target: %s\n", err.Error())
			goto nextTarget
		}

		if _, err = f.Seek(target.StartOffset(), 0); err != nil {
			fmt.Fprintf(os.Stderr, "[scan] Unable to scan target: %s\n", err.Error())
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
					fmt.Fprintf(os.Stderr, "[scan] Unable to scan target: %s\n", err.Error())
					emptyBlocks <- block
					goto nextTarget
				}
				if read == 0 {
					reportBadSector(target, currentOffset, currentOffset+blockSize, err, opts.OnBadSector)
					currentOffset += blockSize
					haveTail = false
					emptyBlocks <- block
					// Position is indeterminate after failed reads.
					if _, serr := f.Seek(currentOffset, io.SeekStart); serr != nil {
						fmt.Fprintf(os.Stderr, "[scan] Unable to scan target: %s\n", serr.Error())
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
					writeCheckpoint(opts.CheckpointPath, target.Describe(), currentOffset)
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
			writeCheckpoint(opts.CheckpointPath, target.Describe(), currentOffset)
		}
		select {
		case <-ctx.Done():
			if f != nil {
				f.Close()
			}
			return
		case out <- EOF:
		}
		if f != nil {
			f.Close()
			f = nil
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

func reportBadSector(target scanTarget, start, end int64, err error, onBadSector BadSectorFunc) {
	fmt.Fprintf(os.Stderr, "[scan] Skipping unreadable bytes %d-%d in %s: %s\n",
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

	// Deliberately absent: the bare "SQLite format 3" magic (every browser
	// database on the disk would match) and the 4-byte "mkey"/"ckey" keys
	// (expected hundreds of thousands of random hits per terabyte).
}

// Scan blocks for traces of bitcoin wallets, the function will
// wait in blocks on in until it sees EOF, and output scanned blocks
// to out for reuse.
func detectWallets(in chan *Block, out chan *Block, onDetection func(Detection), onComplete func(), carve carveConfig) {
	seq := 0
	for block := range in {
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
						if err := carveDetection(block.source, &d, carve.dir, carve.contextBytes, seq); err != nil {
							fmt.Fprintf(os.Stderr, "[carve] warning: could not carve '%s' at %s byte %d: %s\n",
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
		// reported with an earlier block. Only the phrase length is ever
		// printed; the words themselves stay out of logs and output.
		for _, m := range findBIP39(data, block.offset, block.overlap == 0, block.final) {
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
				if carve.dir != "" {
					seq++
					if err := carveDetection(block.source, &d, carve.dir, carve.contextBytes, seq); err != nil {
						fmt.Fprintf(os.Stderr, "[carve] warning: could not carve '%s' at %s byte %d: %s\n",
							label, d.Target, d.Offset, err.Error())
					}
				}
				onDetection(d)
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
					if err := carveDetection(block.source, &d, carve.dir, carve.contextBytes, seq); err != nil {
						fmt.Fprintf(os.Stderr, "[carve] warning: could not carve '%s' at %s byte %d: %s\n",
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
					if err := carveDetection(block.source, &d, carve.dir, carve.contextBytes, seq); err != nil {
						fmt.Fprintf(os.Stderr, "[carve] warning: could not carve 'eth-keystore' at %s byte %d: %s\n",
							d.Target, d.Offset, err.Error())
					}
				}
				onDetection(d)
			}
		}
		out <- block
	}
}
