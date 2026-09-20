package detector

// Fault-injection tests for bad-sector recovery. These live in the internal
// test package because they drive scanBlocks with synthetic failing targets,
// which the path-based Scan API cannot express.

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"testing"
	"time"
)

var errTestIO = errors.New("test I/O error")

// flakyTarget serves data with one unreadable byte range. Reads starting
// inside the range fail; reads crossing into it return the bytes before it.
type flakyTarget struct {
	data     []byte
	badStart int64
	badEnd   int64
	failures int // fail this many reads, then recover (0 = fail persistently)
	delay    time.Duration
	reads    *int
}

func (t *flakyTarget) Describe() string     { return "flaky" }
func (t *flakyTarget) StartOffset() int64   { return 0 }
func (t *flakyTarget) Depth() int           { return 0 }
func (t *flakyTarget) Size() (int64, error) { return int64(len(t.data)), nil }
func (t *flakyTarget) Open() (TargetReader, error) {
	return &flakyReader{t: t}, nil
}

type flakyReader struct {
	t   *flakyTarget
	pos int64
}

func (r *flakyReader) Read(p []byte) (int, error) {
	*r.t.reads++
	if r.t.delay > 0 {
		time.Sleep(r.t.delay)
	}
	if r.t.failures > 0 {
		r.t.failures--
		return 0, errTestIO
	}
	if r.pos >= int64(len(r.t.data)) {
		return 0, io.EOF
	}
	n := int64(len(p))
	if n > 1024 {
		n = 1024 // short reads, like a real device
	}
	if r.pos+int64(n) > int64(len(r.t.data)) {
		n = int64(len(r.t.data)) - r.pos
	}
	if r.pos < r.t.badEnd && r.pos+n > r.t.badStart {
		if r.pos >= r.t.badStart {
			return 0, errTestIO
		}
		n = r.t.badStart - r.pos
	}
	copy(p, r.t.data[r.pos:r.pos+n])
	r.pos += n
	return int(n), nil
}

func (r *flakyReader) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(r.t.data)) {
		return 0, io.EOF
	}
	n := copy(p, r.t.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (r *flakyReader) Seek(offset int64, whence int) (int64, error) {
	var base int64
	switch whence {
	case io.SeekStart:
		base = 0
	case io.SeekCurrent:
		base = r.pos
	case io.SeekEnd:
		base = int64(len(r.t.data))
	default:
		return 0, errors.New("bad whence")
	}
	r.pos = base + offset
	return r.pos, nil
}

func (r *flakyReader) Close() error { return nil }

type badRange struct {
	start, end int64
}

// runScanBlocks feeds one target through scanBlocks and returns deep copies
// of the emitted blocks (buffers are recycled, so references would alias).
func runScanBlocks(t *testing.T, target scanTarget, onBadSector BadSectorFunc) []*Block {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	targets := make(chan scanTarget, 4)
	empty := make(chan *Block, 8)
	out := make(chan *Block, 16)
	for i := 0; i < 8; i++ {
		empty <- &Block{data: make([]byte, blockSize+scanOverlap())}
	}
	targets <- target
	go scanBlocks(ctx, targets, empty, out, func(ProgressInfo) {}, Options{OnBadSector: onBadSector}, make(chan error, 1), nil, nil)

	var blocks []*Block
	timeout := time.After(15 * time.Second)
	for {
		select {
		case b := <-out:
			if b == EOF {
				return blocks
			}
			cp := *b
			cp.data = append([]byte(nil), b.data[:b.length]...)
			blocks = append(blocks, &cp)
			empty <- b // recycle, mimicking detectWallets
		case <-timeout:
			t.Fatal("timed out waiting for scanBlocks")
		}
	}
}

// coveredBytes reassembles the new (non-overlap) bytes of each block into an
// offset->byte map for coverage assertions.
func coveredBytes(blocks []*Block) map[int64]byte {
	covered := map[int64]byte{}
	for _, b := range blocks {
		for i := b.overlap; i < b.length; i++ {
			covered[b.offset+int64(i)] = b.data[i]
		}
	}
	return covered
}

func testPattern(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i*31 + 7)
	}
	return data
}

// A persistently bad sector is skipped and reported, and scanning continues
// past it; the block after the gap carries no overlap prefix.
func TestScanBlocksSkipsBadSector(t *testing.T) {
	data := testPattern(3 * blockSize)
	copy(data[2*blockSize+100:], "bestblock")
	reads := 0
	target := &flakyTarget{data: data, badStart: blockSize, badEnd: blockSize + 512, reads: &reads}

	var ranges []badRange
	blocks := runScanBlocks(t, target, func(_ string, start, end int64, _ error) {
		ranges = append(ranges, badRange{start, end})
	})

	if len(ranges) != 1 || ranges[0] != (badRange{blockSize, 2 * blockSize}) {
		t.Fatalf("expected one skipped range [%d,%d), got %v", blockSize, 2*blockSize, ranges)
	}
	covered := coveredBytes(blocks)
	for off := int64(0); off < int64(len(data)); off++ {
		_, ok := covered[off]
		inGap := off >= blockSize && off < 2*blockSize
		if inGap && ok {
			t.Fatalf("byte %d inside skipped range was delivered", off)
		}
		if !inGap && !ok {
			t.Fatalf("byte %d outside skipped range is missing", off)
		}
		if ok && covered[off] != data[off] {
			t.Fatalf("byte %d corrupted: got %d want %d", off, covered[off], data[off])
		}
	}
	for _, b := range blocks {
		if b.offset == 2*blockSize && b.overlap != 0 {
			t.Fatalf("block after gap must not carry overlap, got %d", b.overlap)
		}
	}
}

// Transient failures recover in place: no skip, no report, no lost bytes.
func TestScanBlocksRecoversTransientFailure(t *testing.T) {
	data := testPattern(2 * blockSize)
	reads := 0
	target := &flakyTarget{data: data, badStart: -1, badEnd: -1, failures: 2, reads: &reads}

	var ranges []badRange
	blocks := runScanBlocks(t, target, func(_ string, start, end int64, _ error) {
		ranges = append(ranges, badRange{start, end})
	})

	if len(ranges) != 0 {
		t.Fatalf("expected no skipped ranges after recovery, got %v", ranges)
	}
	covered := coveredBytes(blocks)
	for off := int64(0); off < int64(len(data)); off++ {
		if !containsByte(t, covered, data, off) {
			t.Fatalf("byte %d missing or corrupted after recovery", off)
		}
	}
}

func TestClassifyEmptyCarve(t *testing.T) {
	info, err := classifyCarve("nonexistent", 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if info.Class != "empty" {
		t.Errorf("expected empty class, got %+v", info)
	}
}

func containsByte(t *testing.T, covered map[int64]byte, data []byte, off int64) bool {
	t.Helper()
	b, ok := covered[off]
	return ok && b == data[off]
}

// The journal is written during the scan, not just at the end: kill the scan
// mid-flight and a partial offset must already be recorded.
func TestCheckpointWrittenDuringScan(t *testing.T) {
	dir := t.TempDir()
	ckpt := filepath.Join(dir, "ckpt.json")

	data := testPattern(2 << 20)
	reads := 0
	target := &flakyTarget{data: data, badStart: -1, badEnd: -1, delay: 2 * time.Millisecond, reads: &reads}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	targets := make(chan scanTarget, 4)
	empty := make(chan *Block, 8)
	out := make(chan *Block, 16)
	for i := 0; i < 8; i++ {
		empty <- &Block{data: make([]byte, blockSize+scanOverlap())}
	}
	targets <- target
	// Real journal control: the harness plays the stages, acking
	// drain barriers and reporting quiescence over its own
	// channels, so this test exercises the proven-frontier drain
	// path production uses — not a legacy direct write.
	jc := &journalCtl{
		quiet: func() bool { return len(out) == 0 && len(targets) == 0 },
		final: make(chan *pendingFrontier, 1),
	}
	go scanBlocks(ctx, targets, empty, out, func(ProgressInfo) {}, Options{CheckpointPath: ckpt}, make(chan error, 1), jc, nil)

	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.After(20 * time.Second)
	for {
		select {
		case b := <-out:
			if b == EOF {
				t.Fatal("scan finished before a mid-scan checkpoint was observed")
			}
			if b.barrier != nil {
				b.barrier <- struct{}{}
				continue
			}
			empty <- b
		case <-ticker.C:
			cp, err := ReadCheckpoint(ckpt)
			if err == nil && cp.Offset > 0 && cp.Offset < int64(len(data)) {
				cancel()
				if cp.Path != "flaky" {
					t.Errorf("expected checkpoint for flaky, got %+v", cp)
				}
				return
			}
		case <-timeout:
			t.Fatal("timed out waiting for a mid-scan checkpoint")
		}
	}
}

// A journaled frontier counts bytes already pushed downstream: the
// drain must run after the block carrying the frontier travels, or
// a kill between journal-write and push strands bytes past the
// rewind. Barriers flow through the same FIFO channel as blocks,
// so the first barrier's position in the receive stream proves
// the order deterministically: the cadence block must arrive
// before it, never after.
func TestDrainJournalsAfterPush(t *testing.T) {
	dir := t.TempDir()
	ckpt := filepath.Join(dir, "ckpt.json")

	data := testPattern(2 << 20)
	reads := 0
	target := &flakyTarget{data: data, badStart: -1, badEnd: -1, reads: &reads}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	targets := make(chan scanTarget, 4)
	empty := make(chan *Block, 8)
	out := make(chan *Block, 16)
	for i := 0; i < 8; i++ {
		empty <- &Block{data: make([]byte, blockSize+scanOverlap())}
	}
	targets <- target
	jc := &journalCtl{
		quiet: func() bool { return len(out) == 0 && len(targets) == 0 },
		final: make(chan *pendingFrontier, 1),
	}
	go scanBlocks(ctx, targets, empty, out, func(ProgressInfo) {}, Options{CheckpointPath: ckpt}, make(chan error, 1), jc, nil)

	blocks := 0
	barrierAt := -1
	timeout := time.After(20 * time.Second)
	for barrierAt < 0 {
		select {
		case b := <-out:
			if b == EOF {
				t.Fatal("scan finished before any drain barrier")
			}
			if b.barrier != nil {
				barrierAt = blocks
				b.barrier <- struct{}{}
				continue
			}
			blocks++
			empty <- b
		case <-timeout:
			t.Fatal("timed out waiting for a drain barrier")
		}
	}
	if barrierAt != checkpointBlockInterval {
		t.Errorf("first barrier after %d blocks, want %d (the cadence block must travel first)",
			barrierAt, checkpointBlockInterval)
	}
	// The acked drain must journal the cadence frontier: the ack
	// proves the pushed prefix delivered, so the journaled offset
	// is its end.
	want := int64(checkpointBlockInterval * blockSize)
	deadline := time.After(20 * time.Second)
	for {
		select {
		case b := <-out:
			if b == EOF {
				t.Fatal("scan finished before the drain journaled")
			}
			if b.barrier != nil {
				b.barrier <- struct{}{}
				continue
			}
			empty <- b
		default:
		}
		if cp, err := ReadCheckpoint(ckpt); err == nil && cp.Offset > 0 {
			cancel()
			if cp.Offset != want {
				t.Errorf("journaled frontier %d, want cadence end %d", cp.Offset, want)
			}
			return
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for the drain journal")
		case <-time.After(time.Millisecond):
		}
	}
}

// A failure mid-block keeps the bytes before it, then skips from the failure
// point; scanning continues after the skipped range.
func TestScanBlocksKeepsPartialBlockBeforeBadSector(t *testing.T) {
	data := testPattern(3 * blockSize)
	reads := 0
	const badStart = blockSize + 904
	target := &flakyTarget{data: data, badStart: badStart, badEnd: badStart + 100, reads: &reads}

	var ranges []badRange
	blocks := runScanBlocks(t, target, func(_ string, start, end int64, _ error) {
		ranges = append(ranges, badRange{start, end})
	})

	if len(ranges) != 1 || ranges[0] != (badRange{badStart, badStart + blockSize}) {
		t.Fatalf("expected one skipped range [%d,%d), got %v", badStart, badStart+blockSize, ranges)
	}
	covered := coveredBytes(blocks)
	for off := int64(0); off < int64(len(data)); off++ {
		_, ok := covered[off]
		inGap := off >= badStart && off < badStart+blockSize
		if inGap && ok {
			t.Fatalf("byte %d inside skipped range was delivered", off)
		}
		if !inGap && !ok {
			t.Fatalf("byte %d outside skipped range is missing", off)
		}
	}
}
