// Forensic image input: Expert Witness Format (EnCase E01) and split raw.
//
// EWF support is a dependency-free reader for the EnCase E01 layout
// (EWF-S01 SMART and EWF2 Ex01/Lx01 are rejected, not misread). Segment
// files are parsed eagerly when the scan target is built so a corrupt or
// truncated set fails the scan up front instead of silently yielding
// partial data. Chunk checksums are verified on decode; a bad chunk is a
// hard error identifying the chunk, never silent corruption.
package detector

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"hash/adler32"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// EWF layout constants (EnCase E01, EWF v1).
const (
	ewfFileHeaderLen = 13
	ewfSectionDesc   = 76
	ewfVolumeLen     = 1052
	ewfHashLen       = 36
	ewfTableHeadLen  = 24
	ewfMaxSegments   = 99
	ewfMaxChunkBytes = 64 << 20
)

var ewfSignature = []byte{0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00}

// splitRawPattern matches EnCase-style split raw footprints: base.001, base.002, ...
var splitRawPattern = regexp.MustCompile(`(?i)\.\d{3}$`)

// detectScanTarget selects the scan target for a root path: EWF sets decode
// through the EWF reader, split raw sets concatenate, everything else scans
// as one raw file. EWF sets are parsed eagerly so corruption fails fast.
func detectScanTarget(path string, startOffset int64) (scanTarget, error) {
	if isEWFSegment(path) {
		layout, err := openEWFLayout(path)
		if err != nil {
			return nil, err
		}
		return &ewfScanTarget{path: path, startOffset: startOffset, layout: layout}, nil
	}
	if splitRawPattern.MatchString(path) {
		set, err := openSplitRaw(path)
		if err != nil {
			return nil, err
		}
		return &splitScanTarget{path: path, startOffset: startOffset, set: set}, nil
	}
	return &fileScanTarget{startOffset: startOffset, path: path}, nil
}

// isEWFSegment reports whether path starts with the EWF file signature.
func isEWFSegment(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var hdr [8]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return false
	}
	return bytes.Equal(hdr[:], ewfSignature)
}

// ewfChunk locates one decoded chunk inside a segment file.
type ewfChunk struct {
	seg        int   // index into layout.paths
	off        int64 // stored-data offset within the segment file
	storedLen  int64 // stored byte length
	compressed bool  // zlib stream when true, raw+adler32 when false
}

// ewfLayout is the fully parsed geometry of an EWF segment set.
type ewfLayout struct {
	paths      []string
	chunks     []ewfChunk
	chunkBytes int64
	mediaSize  int64
	md5        [16]byte
	hasMD5     bool
}

// openEWFLayout parses every segment of the set containing firstPath.
// firstPath must be segment 1 (.E01); the set continues while .E02, .E03,
// ... exist.
func openEWFLayout(firstPath string) (*ewfLayout, error) {
	segNum, err := ewfSegmentNumber(firstPath)
	if err != nil {
		return nil, err
	}
	if segNum != 1 {
		return nil, fmt.Errorf("ewf: pass segment 1 (.E01) of the set, not %s", firstPath)
	}
	base := strings.TrimSuffix(firstPath, filepath.Ext(firstPath))
	var paths []string
	for n := 1; n <= ewfMaxSegments; n++ {
		p := fmt.Sprintf("%s.E%02d", base, n)
		if _, err := os.Stat(p); err != nil {
			if n == 1 {
				return nil, fmt.Errorf("ewf: cannot stat %s: %w", p, err)
			}
			break
		}
		paths = append(paths, p)
	}
	layout := &ewfLayout{paths: paths}
	var volumeSeen bool
	var lastIsNext bool
	for i, p := range paths {
		last, err := layout.parseSegment(p, i+1, &volumeSeen)
		if err != nil {
			return nil, err
		}
		lastIsNext = last
	}
	if lastIsNext {
		return nil, fmt.Errorf("ewf: segment set continues past %s (over %d segments unsupported)",
			paths[len(paths)-1], ewfMaxSegments)
	}
	if !volumeSeen {
		return nil, fmt.Errorf("ewf: no volume section in %s", paths[0])
	}
	if len(layout.chunks) == 0 {
		return nil, fmt.Errorf("ewf: no data chunks in segment set %s", paths[0])
	}
	return layout, nil
}

// ewfSegmentNumber extracts the segment number from an .E01-style path.
func ewfSegmentNumber(path string) (int, error) {
	ext := filepath.Ext(path)
	if len(ext) != 4 || (ext[0] != '.' || (ext[1] != 'E' && ext[1] != 'e')) {
		return 0, fmt.Errorf("ewf: %s is not an EWF segment path (want .E01)", path)
	}
	n, err := strconv.Atoi(ext[2:])
	if err != nil || n < 1 {
		return 0, fmt.Errorf("ewf: %s is not an EWF segment path (want .E01)", path)
	}
	return n, nil
}

// parseSegment walks one segment file, appending its chunks to the layout.
// It reports whether the segment ends with a "next" section (set continues).
func (l *ewfLayout) parseSegment(path string, segNum int, volumeSeen *bool) (bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("ewf: cannot read %s: %w", path, err)
	}
	if len(raw) < ewfFileHeaderLen || !bytes.Equal(raw[:8], ewfSignature) {
		return false, fmt.Errorf("ewf: %s is not an EWF segment file", path)
	}
	if got := int(binary.LittleEndian.Uint16(raw[9:11])); got != segNum {
		return false, fmt.Errorf("ewf: %s declares segment %d, want %d", path, got, segNum)
	}
	var (
		sectorsDesc = int64(-1)
		sectorsEnd  int64
		sawNext     bool
	)
	off := int64(ewfFileHeaderLen)
	for steps := 0; ; steps++ {
		if steps > 1<<20 {
			return false, fmt.Errorf("ewf: %s: section chain too long", path)
		}
		if off+ewfSectionDesc > int64(len(raw)) {
			return false, fmt.Errorf("ewf: %s: section descriptor past end of file", path)
		}
		desc := raw[off : off+ewfSectionDesc]
		typ := string(bytes.TrimRight(desc[:16], "\x00"))
		next := int64(binary.LittleEndian.Uint64(desc[16:24]))
		size := int64(binary.LittleEndian.Uint64(desc[24:32]))
		if adler32.Checksum(desc[:72]) != binary.LittleEndian.Uint32(desc[72:76]) {
			return false, fmt.Errorf("ewf: %s: section %q descriptor checksum mismatch", path, typ)
		}
		if size < 0 || off+size > int64(len(raw)) {
			return false, fmt.Errorf("ewf: %s: section %q overruns file", path, typ)
		}
		var data []byte
		if typ == "done" || typ == "next" {
			if size != 0 {
				return false, fmt.Errorf("ewf: %s: section %q has size %d, want 0", path, typ, size)
			}
		} else {
			if size < ewfSectionDesc {
				return false, fmt.Errorf("ewf: %s: section %q too short", path, typ)
			}
			data = raw[off+ewfSectionDesc : off+size]
		}
		switch typ {
		case "volume":
			if segNum != 1 {
				return false, fmt.Errorf("ewf: %s: volume section outside segment 1", path)
			}
			if err := l.parseVolume(path, data); err != nil {
				return false, err
			}
			*volumeSeen = true
		case "sectors":
			sectorsDesc = off
			sectorsEnd = off + size
		case "table":
			if sectorsDesc < 0 {
				return false, fmt.Errorf("ewf: %s: table section without sectors", path)
			}
			if err := l.parseTable(path, segNum, data, off, sectorsDesc, sectorsEnd); err != nil {
				return false, err
			}
		case "table2":
			// Mirror of table; the primary is authoritative.
		case "hash":
			if err := l.parseHash(path, data); err != nil {
				return false, err
			}
		case "next":
			sawNext = true
		case "done", "header", "header2", "disk", "data", "error2", "session":
		default:
			return false, fmt.Errorf("ewf: %s: unknown section %q", path, typ)
		}
		if typ == "done" || typ == "next" || next == 0 || next == off {
			break
		}
		if next < off+ewfSectionDesc {
			return false, fmt.Errorf("ewf: %s: section chain goes backwards at %q", path, typ)
		}
		off = next
	}
	return sawNext, nil
}

// parseVolume reads media geometry from the volume section data.
func (l *ewfLayout) parseVolume(path string, data []byte) error {
	if len(data) < ewfVolumeLen {
		return fmt.Errorf("ewf: %s: volume section too short (%d bytes)", path, len(data))
	}
	if adler32.Checksum(data[:ewfVolumeLen-4]) != binary.LittleEndian.Uint32(data[ewfVolumeLen-4:ewfVolumeLen]) {
		return fmt.Errorf("ewf: %s: volume checksum mismatch", path)
	}
	chunks := binary.LittleEndian.Uint32(data[4:8])
	spc := binary.LittleEndian.Uint32(data[8:12])
	bps := binary.LittleEndian.Uint32(data[12:16])
	sectors := binary.LittleEndian.Uint64(data[16:24])
	switch bps {
	case 512, 1024, 2048, 4096:
	default:
		return fmt.Errorf("ewf: %s: unsupported bytes-per-sector %d", path, bps)
	}
	if spc == 0 || chunks == 0 {
		return fmt.Errorf("ewf: %s: volume declares empty media", path)
	}
	l.chunkBytes = int64(spc) * int64(bps)
	if l.chunkBytes > ewfMaxChunkBytes {
		return fmt.Errorf("ewf: %s: chunk size %d exceeds limit", path, l.chunkBytes)
	}
	l.mediaSize = int64(sectors) * int64(bps)
	if l.mediaSize <= 0 || l.mediaSize > int64(chunks)*l.chunkBytes {
		return fmt.Errorf("ewf: %s: volume media size %d inconsistent with %d chunks", path, l.mediaSize, chunks)
	}
	return nil
}

// parseTable binds one table section to its sectors section, appending chunks.
func (l *ewfLayout) parseTable(path string, segNum int, data []byte, _ int64, sectorsDesc, sectorsEnd int64) error {
	if len(data) < ewfTableHeadLen {
		return fmt.Errorf("ewf: %s: table section too short", path)
	}
	n := binary.LittleEndian.Uint32(data[0:4])
	base := int64(binary.LittleEndian.Uint64(data[8:16]))
	if adler32.Checksum(data[:20]) != binary.LittleEndian.Uint32(data[20:24]) {
		return fmt.Errorf("ewf: %s: table header checksum mismatch", path)
	}
	want := ewfTableHeadLen + int64(n)*4 + 4
	if int64(len(data)) < want {
		return fmt.Errorf("ewf: %s: table truncated (%d bytes, want %d)", path, len(data), want)
	}
	arr := data[ewfTableHeadLen : ewfTableHeadLen+int64(n)*4]
	if adler32.Checksum(arr) != binary.LittleEndian.Uint32(data[ewfTableHeadLen+int64(n)*4:]) {
		return fmt.Errorf("ewf: %s: table offset checksum mismatch", path)
	}
	prev := int64(-1)
	for i := int64(0); i < int64(n); i++ {
		raw := binary.LittleEndian.Uint32(arr[i*4 : i*4+4])
		start := base + int64(raw&0x7fffffff)
		var end int64
		if i+1 < int64(n) {
			end = base + int64(binary.LittleEndian.Uint32(arr[i*4+4:i*4+8])&0x7fffffff)
		} else {
			end = sectorsEnd
		}
		if start < sectorsDesc+ewfSectionDesc || end > sectorsEnd || end <= start {
			return fmt.Errorf("ewf: %s: chunk %d span [%d,%d) outside sectors section",
				path, len(l.chunks), start, end)
		}
		if start <= prev {
			return fmt.Errorf("ewf: %s: chunk %d offsets not increasing", path, len(l.chunks))
		}
		prev = start
		l.chunks = append(l.chunks, ewfChunk{
			seg:        segNum - 1,
			off:        start,
			storedLen:  end - start,
			compressed: raw&0x80000000 != 0,
		})
	}
	return nil
}

// parseHash records the stored MD5 of the decoded media.
func (l *ewfLayout) parseHash(path string, data []byte) error {
	if len(data) < ewfHashLen {
		return fmt.Errorf("ewf: %s: hash section too short", path)
	}
	if adler32.Checksum(data[:32]) != binary.LittleEndian.Uint32(data[32:36]) {
		return fmt.Errorf("ewf: %s: hash section checksum mismatch", path)
	}
	copy(l.md5[:], data[:16])
	l.hasMD5 = true
	return nil
}

// ewfScanTarget scans the decoded media of an EWF segment set.
type ewfScanTarget struct {
	path        string
	startOffset int64
	layout      *ewfLayout
}

func (t *ewfScanTarget) Describe() string     { return t.path }
func (t *ewfScanTarget) StartOffset() int64   { return t.startOffset }
func (t *ewfScanTarget) Depth() int           { return 0 }
func (t *ewfScanTarget) Size() (int64, error) { return t.layout.mediaSize, nil }
func (t *ewfScanTarget) Open() (TargetReader, error) {
	files := make([]*os.File, len(t.layout.paths))
	for i, p := range t.layout.paths {
		f, err := os.Open(p)
		if err != nil {
			for _, c := range files[:i] {
				c.Close()
			}
			return nil, fmt.Errorf("ewf: cannot open %s: %w", p, err)
		}
		files[i] = f
	}
	return &ewfReader{layout: t.layout, files: files, cacheIdx: -1}, nil
}

// ewfReader streams decoded media bytes with ReadAt/Read/Seek.
type ewfReader struct {
	layout   *ewfLayout
	files    []*os.File
	pos      int64
	cacheIdx int64
	cache    []byte
}

func (r *ewfReader) Close() error {
	var first error
	for _, f := range r.files {
		if err := f.Close(); err != nil && first == nil {
			first = err
		}
	}
	r.files = nil
	return first
}

func (r *ewfReader) Seek(offset int64, whence int) (int64, error) {
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = r.pos + offset
	case io.SeekEnd:
		abs = r.layout.mediaSize + offset
	default:
		return 0, fmt.Errorf("ewf: invalid whence %d", whence)
	}
	if abs < 0 {
		return 0, fmt.Errorf("ewf: negative seek position")
	}
	r.pos = abs
	return abs, nil
}

func (r *ewfReader) Read(p []byte) (int, error) {
	n, err := r.ReadAt(p, r.pos)
	r.pos += int64(n)
	return n, err
}

// ReadAt decodes the media span [off, off+len(p)).
func (r *ewfReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("ewf: negative read offset")
	}
	if off >= r.layout.mediaSize {
		return 0, io.EOF
	}
	if max := r.layout.mediaSize - off; int64(len(p)) > max {
		p = p[:max]
	}
	want := len(p)
	var done int
	for len(p) > 0 {
		idx := (off + int64(done)) / r.layout.chunkBytes
		chunk, err := r.chunk(idx)
		if err != nil {
			if done == 0 {
				return 0, err
			}
			return done, nil
		}
		inner := (off + int64(done)) % r.layout.chunkBytes
		n := copy(p, chunk[inner:])
		done += n
		p = p[n:]
	}
	if done < want {
		return done, io.EOF
	}
	return done, nil
}

// chunk returns the decoded bytes of global chunk idx (cached one deep:
// scans walk media sequentially, so the hot chunk is almost always cached).
func (r *ewfReader) chunk(idx int64) ([]byte, error) {
	if idx == r.cacheIdx {
		return r.cache, nil
	}
	if idx < 0 || idx >= int64(len(r.layout.chunks)) {
		return nil, fmt.Errorf("ewf: chunk %d out of range (%d chunks)", idx, len(r.layout.chunks))
	}
	c := r.layout.chunks[idx]
	stored := make([]byte, c.storedLen)
	if _, err := r.files[c.seg].ReadAt(stored, c.off); err != nil {
		return nil, fmt.Errorf("ewf: chunk %d: cannot read stored data: %w", idx, err)
	}
	var decoded []byte
	if c.compressed {
		zr, err := zlib.NewReader(bytes.NewReader(stored))
		if err != nil {
			return nil, fmt.Errorf("ewf: chunk %d: bad compressed data: %w", idx, err)
		}
		decoded, err = io.ReadAll(zr)
		zr.Close()
		if err != nil {
			return nil, fmt.Errorf("ewf: chunk %d: decompression failed: %w", idx, err)
		}
	} else {
		if len(stored) < 4 {
			return nil, fmt.Errorf("ewf: chunk %d: stored data too short", idx)
		}
		body, want := stored[:len(stored)-4], binary.LittleEndian.Uint32(stored[len(stored)-4:])
		if adler32.Checksum(body) != want {
			return nil, fmt.Errorf("ewf: chunk %d: checksum mismatch (media corrupt)", idx)
		}
		decoded = body
	}
	if int64(len(decoded)) != r.layout.chunkBytes {
		return nil, fmt.Errorf("ewf: chunk %d: decoded %d bytes, want %d",
			idx, len(decoded), r.layout.chunkBytes)
	}
	r.cacheIdx, r.cache = idx, decoded
	return decoded, nil
}

// splitRawSet is an ordered run of base.001, base.002, ... concatenated.
type splitRawSet struct {
	paths []string
	sizes []int64
	total int64
}

// openSplitRaw enumerates the split set containing path, starting at .001.
func openSplitRaw(path string) (*splitRawSet, error) {
	base := path[:len(path)-4]
	var set splitRawSet
	for n := 1; n <= 9999; n++ {
		p := fmt.Sprintf("%s.%03d", base, n)
		st, err := os.Stat(p)
		if err != nil {
			break
		}
		set.paths = append(set.paths, p)
		set.sizes = append(set.sizes, st.Size())
		set.total += st.Size()
	}
	if len(set.paths) == 0 {
		return nil, fmt.Errorf("split raw: no segments for %s", path)
	}
	return &set, nil
}

// splitScanTarget scans a split raw set as one contiguous stream.
type splitScanTarget struct {
	path        string
	startOffset int64
	set         *splitRawSet
}

func (t *splitScanTarget) Describe() string     { return t.path }
func (t *splitScanTarget) StartOffset() int64   { return t.startOffset }
func (t *splitScanTarget) Depth() int           { return 0 }
func (t *splitScanTarget) Size() (int64, error) { return t.set.total, nil }
func (t *splitScanTarget) Open() (TargetReader, error) {
	files := make([]*os.File, len(t.set.paths))
	for i, p := range t.set.paths {
		f, err := os.Open(p)
		if err != nil {
			for _, c := range files[:i] {
				c.Close()
			}
			return nil, fmt.Errorf("split raw: cannot open %s: %w", p, err)
		}
		files[i] = f
	}
	return &splitReader{set: t.set, files: files}, nil
}

// splitReader streams a split raw set with ReadAt/Read/Seek.
type splitReader struct {
	set   *splitRawSet
	files []*os.File
	pos   int64
}

func (r *splitReader) Close() error {
	var first error
	for _, f := range r.files {
		if err := f.Close(); err != nil && first == nil {
			first = err
		}
	}
	r.files = nil
	return first
}

func (r *splitReader) Seek(offset int64, whence int) (int64, error) {
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = r.pos + offset
	case io.SeekEnd:
		abs = r.set.total + offset
	default:
		return 0, fmt.Errorf("split raw: invalid whence %d", whence)
	}
	if abs < 0 {
		return 0, fmt.Errorf("split raw: negative seek position")
	}
	r.pos = abs
	return abs, nil
}

func (r *splitReader) Read(p []byte) (int, error) {
	n, err := r.ReadAt(p, r.pos)
	r.pos += int64(n)
	return n, err
}

// ReadAt reads the concatenated span [off, off+len(p)).
func (r *splitReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("split raw: negative read offset")
	}
	if off >= r.set.total {
		return 0, io.EOF
	}
	if max := r.set.total - off; int64(len(p)) > max {
		p = p[:max]
	}
	want := len(p)
	var done int
	base := int64(0)
	for i, size := range r.set.sizes {
		if off+int64(done) >= base+size {
			base += size
			continue
		}
		inner := off + int64(done) - base
		n, err := r.files[i].ReadAt(p[done:][:min64(int64(len(p))-int64(done), size-inner)], inner)
		done += n
		if err != nil && err != io.EOF {
			if done == 0 {
				return 0, err
			}
			return done, nil
		}
		base += size
		if done >= len(p) {
			break
		}
	}
	if done < want {
		return done, io.EOF
	}
	return done, nil
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
