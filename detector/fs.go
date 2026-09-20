package detector

import (
	"fmt"
	"io"
	"os"
)

// Shared filesystem-layer types. The fs layer maps metadata (MFT records,
// inodes) to named byte extents so deleted-but-referenced files can be
// scanned with their names attached, and so raw scans can skip live data.

// FSExtent is an image-absolute byte range [Start, Start+Len).
type FSExtent struct {
	Start int64
	Len   int64
}

// FSEntry is one file described by filesystem metadata.
type FSEntry struct {
	// Name is the best available filename (lossy UTF-8); Names holds all
	// aliases (short names, hard links) when the fs provides them.
	Name  string
	Names []string
	// Size is the file's real data length in bytes.
	Size int64
	// Deleted reports metadata that no longer links the file: a cleared
	// MFT in-use flag, an unlinked inode, or a residual dir entry.
	Deleted bool
	// Extents holds image-absolute content ranges, merged when adjacent.
	// Entries whose content is unknown (orphan names) have none.
	Extents []FSExtent
	// Note locates the metadata: "mft:42" or "inode:12".
	Note string
}

// boundedScanTarget scans one absolute byte range of a file. Describe
// stays the plain path so detections and carves group with the image.
type boundedScanTarget struct {
	path          string
	start, length int64
}

func (t *boundedScanTarget) Describe() string     { return t.path }
func (t *boundedScanTarget) StartOffset() int64   { return t.start }
func (t *boundedScanTarget) Depth() int           { return 0 }
func (t *boundedScanTarget) Size() (int64, error) { return t.start + t.length, nil }
func (t *boundedScanTarget) Open() (TargetReader, error) {
	f, err := os.Open(t.path)
	if err != nil {
		return nil, err
	}
	return &clampedReader{f: f, start: t.start, end: t.start + t.length, pos: t.start}, nil
}

// clampedReader bounds all reads to [start, end); seeks use absolute file
// offsets like *os.File so the block loop and carver work unchanged.
type clampedReader struct {
	f          *os.File
	start, end int64
	pos        int64
}

func (r *clampedReader) Read(p []byte) (int, error) {
	if r.pos >= r.end {
		return 0, io.EOF
	}
	if max := r.end - r.pos; int64(len(p)) > max {
		p = p[:max]
	}
	n, err := r.f.ReadAt(p, r.pos)
	r.pos += int64(n)
	return n, err
}

func (r *clampedReader) ReadAt(p []byte, off int64) (int, error) {
	if off >= r.end {
		return 0, io.EOF
	}
	if max := r.end - off; int64(len(p)) > max {
		p = p[:max]
	}
	return r.f.ReadAt(p, off)
}

func (r *clampedReader) Seek(off int64, whence int) (int64, error) {
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = off
	case io.SeekCurrent:
		abs = r.pos + off
	case io.SeekEnd:
		abs = r.end + off
	default:
		return 0, fmt.Errorf("bad whence %d", whence)
	}
	if abs < r.start {
		abs = r.start
	}
	if abs > r.end {
		abs = r.end
	}
	r.pos = abs
	return abs, nil
}

func (r *clampedReader) Close() error { return r.f.Close() }

// sharedBoundedTarget reads one range through a driver-held shared
// handle (pinned for verification plus every range pipeline of a
// resume) instead of opening the path per range.
type sharedBoundedTarget struct {
	f             *os.File
	path          string
	start, length int64
}

func (t *sharedBoundedTarget) Describe() string     { return t.path }
func (t *sharedBoundedTarget) StartOffset() int64   { return t.start }
func (t *sharedBoundedTarget) Depth() int           { return 0 }
func (t *sharedBoundedTarget) Size() (int64, error) { return t.start + t.length, nil }
func (t *sharedBoundedTarget) Open() (TargetReader, error) {
	return &sharedClampedReader{clampedReader{f: t.f, start: t.start, end: t.start + t.length, pos: t.start}}, nil
}

// sharedClampedReader is a clampedReader that never closes the
// shared handle; the driver owns its lifetime.
type sharedClampedReader struct {
	clampedReader
}

func (r *sharedClampedReader) Close() error { return nil }

// mergeExtents sorts ranges by start and merges adjacent or overlapping
// ones. Zero-length ranges are dropped.
func mergeExtents(in []FSExtent) []FSExtent {
	kept := in[:0]
	for _, e := range in {
		if e.Len > 0 && e.Start >= 0 {
			kept = append(kept, e)
		}
	}
	for i := 1; i < len(kept); i++ {
		for j := i; j > 0 && kept[j].Start < kept[j-1].Start; j-- {
			kept[j], kept[j-1] = kept[j-1], kept[j]
		}
	}
	var out []FSExtent
	for _, e := range kept {
		if n := len(out); n > 0 && e.Start <= out[n-1].Start+out[n-1].Len {
			end := e.Start + e.Len
			if prevEnd := out[n-1].Start + out[n-1].Len; end > prevEnd {
				out[n-1].Len = end - out[n-1].Start
			}
			continue
		}
		out = append(out, e)
	}
	return out
}
