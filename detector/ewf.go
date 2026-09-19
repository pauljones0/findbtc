// Forensic image input: Expert Witness Format (EnCase E01, SMART S01)
// and split raw.
//
// EWF support is a dependency-free reader for the EWF v1 layouts: E01
// (sectors + table sections, 1052-byte volume) and S01 (table section
// holds the chunk data, 94-byte SMART volume). EWF2 images (Ex01/Lx01,
// "EVF2" magic, compressed metadata) are refused with a conversion
// pointer, never misread. Segment files are parsed eagerly when the scan
// target is built so a corrupt or truncated set fails the scan up front
// instead of silently yielding partial data. Chunk checksums are verified
// on decode; a bad chunk is a hard error identifying the chunk, never
// silent corruption.
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

// EWF layout constants (EWF v1: EnCase E01 and SMART S01).
const (
	ewfFileHeaderLen  = 13
	ewfSectionDesc    = 76
	ewfVolumeLen      = 1052
	ewfSmartVolumeLen = 94
	ewfHashLen        = 36
	ewfTableHeadLen   = 24
	// ewfMaxSegments caps the segment set (.E01-.E99): the extension
	// scheme itself ends there, so longer sets are corrupt, not bigger.
	ewfMaxSegments = 99
	// ewfMaxChunkBytes caps one decoded chunk (64 MiB): chunk inflation
	// is limited to this +1 byte, so a hostile chunk cannot decode
	// gigabytes before the length check sees it.
	ewfMaxChunkBytes = 64 << 20
)

// ewfSmartMarker sits at volume[85:90] in SMART (S01) volume sections.
var ewfSmartMarker = []byte{0x53, 0x4D, 0x41, 0x52, 0x54} // "SMART"

var ewfSignature = []byte{0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00}

// ewf2Signature starts EWF2 images (Ex01/Lx01): same "EVF" stamp, format
// byte 0x32, different framing. Refused, never misread.
var ewf2Signature = []byte{0x45, 0x56, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00}

// splitRawPattern matches EnCase-style split raw footprints: base.001, base.002, ...
var splitRawPattern = regexp.MustCompile(`(?i)\.\d{3}$`)

// detectScanTarget selects the scan target for a root path: EWF sets decode
// through the EWF reader, split raw sets concatenate, everything else scans
// as one raw file. EWF sets are parsed eagerly so corruption fails fast.
func detectScanTarget(path string, startOffset int64) (scanTarget, error) {
	if isEWF2Segment(path) {
		return nil, fmt.Errorf("ewf: %s is an EWF2 image (Ex01/Lx01): only EWF v1 (E01) and SMART (S01) can be scanned directly — convert first with libewf (ewfexport -u -t out -f raw %s) and scan the raw output", path, path)
	}
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

// isEWFSegment reports whether path starts with the EWF v1 signature.
func isEWFSegment(path string) bool {
	return hasFileMagic(path, ewfSignature)
}

// isEWF2Segment reports whether path starts with the EWF2 signature.
func isEWF2Segment(path string) bool {
	return hasFileMagic(path, ewf2Signature)
}

func hasFileMagic(path string, magic []byte) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var hdr [8]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return false
	}
	return bytes.Equal(hdr[:], magic)
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
	flavor     string // "ewf" (.E01) or "smart" (.S01), from the set's extension
	chunks     []ewfChunk
	chunkBytes int64
	mediaSize  int64
	// volumeChunks is the volume-declared chunk count; tables claiming
	// more are lies (checked in parseTable once the volume is seen).
	volumeChunks int64
	md5          [16]byte
	hasMD5       bool
}

// openEWFLayout parses every segment of the set containing firstPath.
// firstPath must be segment 1 (.E01 or .S01); the set continues while
// .E02/.S02, .E03/.S03, ... exist.
func openEWFLayout(firstPath string) (*ewfLayout, error) {
	segNum, kind, err := ewfSegmentNumber(firstPath)
	if err != nil {
		return nil, err
	}
	if segNum != 1 {
		return nil, fmt.Errorf("ewf: pass segment 1 (.%s01) of the set, not %s", kind, firstPath)
	}
	base := strings.TrimSuffix(firstPath, filepath.Ext(firstPath))
	var paths []string
	for n := 1; n <= ewfMaxSegments; n++ {
		p := fmt.Sprintf("%s.%s%02d", base, kind, n)
		if _, err := os.Stat(p); err != nil {
			if n == 1 {
				return nil, fmt.Errorf("ewf: cannot stat %s: %w", p, err)
			}
			break
		}
		paths = append(paths, p)
	}
	flavor := "ewf"
	if kind == "S" || kind == "s" {
		flavor = "smart"
	}
	layout := &ewfLayout{paths: paths, flavor: flavor}
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

// ewfSegmentNumber extracts the segment number and set letter ("E" or
// "S") from an .E01/.S01-style path.
func ewfSegmentNumber(path string) (int, string, error) {
	ext := filepath.Ext(path)
	bad := func() (int, string, error) {
		return 0, "", fmt.Errorf("ewf: %s is not an EWF segment path (want .E01 or .S01)", path)
	}
	if len(ext) != 4 || ext[0] != '.' {
		return bad()
	}
	var kind string
	switch ext[1] {
	case 'E', 'e', 'S', 's':
		// Preserve the input's case: SMART writers emit lowercase
		// .s01/.s02, EnCase writers uppercase .E01/.E02.
		kind = ext[1:2]
	default:
		return bad()
	}
	n, err := strconv.Atoi(ext[2:])
	if err != nil || n < 1 {
		return bad()
	}
	return n, kind, nil
}

// parseSegment walks one segment file, appending its chunks to the layout.
// It reports whether the segment ends with a "next" section (set continues).
// Resource note: the whole segment is held in RAM during eager parse, so
// peak EWF memory is ~the largest segment file plus one decoded chunk
// (ewfMaxChunkBytes). Segment sizes are capped only by the format's own
// sanity (sections must chain within the file); refusing large honest
// segments is not an option, so this stays documented, not limited.
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
			// E01 writers emit size 0; SMART writers emit 76 (the
			// descriptor alone). Both mean "no section data".
			if size != 0 && size != ewfSectionDesc {
				return false, fmt.Errorf("ewf: %s: section %q has size %d, want 0 or %d", path, typ, size, ewfSectionDesc)
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

// parseVolume reads media geometry from the volume section data. E01
// volumes are 1052 bytes; SMART (S01) volumes are 94 bytes with the same
// leading geometry fields, a "SMART" marker, and a trailing checksum.
func (l *ewfLayout) parseVolume(path string, data []byte) error {
	var span int
	switch {
	case len(data) >= ewfVolumeLen:
		span = ewfVolumeLen
	case len(data) == ewfSmartVolumeLen && bytes.Equal(data[85:90], ewfSmartMarker):
		span = ewfSmartVolumeLen
	default:
		return fmt.Errorf("ewf: %s: volume section too short (%d bytes, want %d or SMART %d)", path, len(data), ewfVolumeLen, ewfSmartVolumeLen)
	}
	if adler32.Checksum(data[:span-4]) != binary.LittleEndian.Uint32(data[span-4:span]) {
		return fmt.Errorf("ewf: %s: volume checksum mismatch", path)
	}
	chunks := binary.LittleEndian.Uint32(data[4:8])
	spc := binary.LittleEndian.Uint32(data[8:12])
	bps := binary.LittleEndian.Uint32(data[12:16])
	sectors := binary.LittleEndian.Uint64(data[16:24])
	l.volumeChunks = int64(chunks)
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

// parseTable binds one table section to its chunk data, appending chunks.
// E01 tables point into the segment's sectors section (base-relative
// offsets, offset-array checksum). SMART tables carry the chunk data
// themselves (absolute file offsets, no array checksum, last chunk ends
// at the table section end). off is the table descriptor's file offset.
func (l *ewfLayout) parseTable(path string, segNum int, data []byte, off int64, sectorsDesc, sectorsEnd int64) error {
	if len(data) < ewfTableHeadLen {
		return fmt.Errorf("ewf: %s: table section too short", path)
	}
	n := binary.LittleEndian.Uint32(data[0:4])
	base := int64(binary.LittleEndian.Uint64(data[8:16]))
	if adler32.Checksum(data[:20]) != binary.LittleEndian.Uint32(data[20:24]) {
		return fmt.Errorf("ewf: %s: table header checksum mismatch", path)
	}
	if l.volumeChunks > 0 && int64(len(l.chunks))+int64(n) > l.volumeChunks {
		return fmt.Errorf("ewf: %s: table claims %d chunks, volume declares %d total",
			path, n, l.volumeChunks)
	}
	smart := sectorsDesc < 0
	if smart && l.flavor != "smart" {
		return fmt.Errorf("ewf: %s: table section without sectors", path)
	}
	want := ewfTableHeadLen + int64(n)*4
	var arrEnd int64
	if smart {
		arrEnd = off + ewfSectionDesc + int64(len(data))
	} else {
		want += 4
		arrEnd = sectorsEnd
	}
	if int64(len(data)) < want {
		return fmt.Errorf("ewf: %s: table truncated (%d bytes, want %d)", path, len(data), want)
	}
	arr := data[ewfTableHeadLen : ewfTableHeadLen+int64(n)*4]
	if !smart {
		if adler32.Checksum(arr) != binary.LittleEndian.Uint32(data[ewfTableHeadLen+int64(n)*4:]) {
			return fmt.Errorf("ewf: %s: table offset checksum mismatch", path)
		}
	}
	regionStart := sectorsDesc + ewfSectionDesc
	regionName := "sectors"
	if smart {
		regionStart = off + ewfSectionDesc + ewfTableHeadLen + int64(n)*4
		regionName = "table"
	}
	prev := int64(-1)
	for i := int64(0); i < int64(n); i++ {
		raw := binary.LittleEndian.Uint32(arr[i*4 : i*4+4])
		start := base + int64(raw&0x7fffffff)
		var end int64
		if i+1 < int64(n) {
			end = base + int64(binary.LittleEndian.Uint32(arr[i*4+4:i*4+8])&0x7fffffff)
		} else {
			end = arrEnd
		}
		if start < regionStart || end > arrEnd || end <= start {
			return fmt.Errorf("ewf: %s: chunk %d span [%d,%d) outside %s section",
				path, len(l.chunks), start, end, regionName)
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
		// Cap the inflation: a hostile chunk could otherwise decode
		// gigabytes before the length check below sees it.
		decoded, err = io.ReadAll(io.LimitReader(zr, r.layout.chunkBytes+1))
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
	if last := int64(len(r.layout.chunks)) - 1; idx == last {
		// The final chunk is full or holds exactly the media
		// remainder: E01 writers pad, SMART writers do not, and the
		// volume's media size bounds reads either way.
		rest := r.layout.mediaSize - idx*r.layout.chunkBytes
		if rest <= 0 || rest > r.layout.chunkBytes {
			return nil, fmt.Errorf("ewf: volume media size %d inconsistent with %d chunks",
				r.layout.mediaSize, len(r.layout.chunks))
		}
		if int64(len(decoded)) != r.layout.chunkBytes && int64(len(decoded)) != rest {
			return nil, fmt.Errorf("ewf: chunk %d: decoded %d bytes, want %d or %d",
				idx, len(decoded), r.layout.chunkBytes, rest)
		}
	} else if int64(len(decoded)) != r.layout.chunkBytes {
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
