package detector

import (
	"bytes"
	"compress/zlib"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"hash/adler32"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Minimal EWF writer for tests. The layout mirrors what real EnCase files
// contain (volume/sectors/table/table2/data/hash/done, next-terminated
// non-final segments); the same builder logic was validated against
// libewf's ewfverify/ewfexport during development, and the committed
// testdata/ewf-real.E01 fixture below is libewf-produced.

// ewfTB is the *testing.T / *testing.B subset the builders need, so
// benchmarks reuse the same fixture writers as tests.
type ewfTB interface {
	Helper()
	Fatal(args ...any)
}

type ewfBuildOpt struct {
	sectorsPerChunk uint32
	compress        func(chunk int) bool // default: all compressed
	chunksPerSeg    int                  // 0: single segment
}

// ewfEncodeChunks zlib-compresses or stores every chunk per comp, the
// same encoding E01 and SMART share.
func ewfEncodeChunks(t ewfTB, raw []byte, chunkBytes int, comp func(int) bool) (stored [][]byte, flags []bool) {
	t.Helper()
	nch := (len(raw) + chunkBytes - 1) / chunkBytes
	if comp == nil {
		comp = func(int) bool { return true }
	}
	stored = make([][]byte, nch)
	flags = make([]bool, nch)
	for i := 0; i < nch; i++ {
		c := make([]byte, chunkBytes)
		copy(c, raw[i*chunkBytes:])
		if comp(i) {
			var buf bytes.Buffer
			w := zlib.NewWriter(&buf)
			if _, err := w.Write(c); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			stored[i] = buf.Bytes()
			flags[i] = true
		} else {
			var buf bytes.Buffer
			buf.Write(c)
			var a [4]byte
			binary.LittleEndian.PutUint32(a[:], adler32.Checksum(c))
			buf.Write(a[:])
			stored[i] = buf.Bytes()
		}
	}
	return stored, flags
}

func buildEWF(t ewfTB, dir, name string, raw []byte, opt ewfBuildOpt) string {
	t.Helper()
	spc := opt.sectorsPerChunk
	if spc == 0 {
		spc = 64
	}
	const bps = 512
	chunkBytes := int(spc) * bps
	nch := (len(raw) + chunkBytes - 1) / chunkBytes
	nsec := (len(raw) + bps - 1) / bps
	stored, flags := ewfEncodeChunks(t, raw, chunkBytes, opt.compress)
	var groups [][]int
	if opt.chunksPerSeg > 0 {
		for i := 0; i < nch; i += opt.chunksPerSeg {
			end := i + opt.chunksPerSeg
			if end > nch {
				end = nch
			}
			var g []int
			for j := i; j < end; j++ {
				g = append(g, j)
			}
			groups = append(groups, g)
		}
	} else {
		var g []int
		for i := 0; i < nch; i++ {
			g = append(g, i)
		}
		groups = [][]int{g}
	}
	vol := ewfTestVolume(nch, spc, bps, nsec)
	type part struct {
		typ  string
		data []byte
	}
	for s, g := range groups {
		var pre []part
		if s == 0 {
			pre = append(pre, part{"volume", vol})
		} else {
			pre = append(pre, part{"data", vol})
		}
		secDesc := int64(13)
		for _, p := range pre {
			secDesc += 76 + int64(len(p.data))
		}
		var offs []uint32
		var secdata []byte
		pos := uint32(76)
		for _, ci := range g {
			o := pos
			if flags[ci] {
				o |= 0x80000000
			}
			offs = append(offs, o)
			pos += uint32(len(stored[ci]))
			secdata = append(secdata, stored[ci]...)
		}
		tab := ewfTestTable(offs, uint64(secDesc))
		parts := append(append([]part{}, pre...),
			part{"sectors", secdata}, part{"table", tab}, part{"table2", tab})
		if s == len(groups)-1 {
			if s == 0 {
				parts = append(parts, part{"data", vol})
			}
			h := md5.Sum(raw)
			hd := make([]byte, 36)
			copy(hd, h[:])
			binary.LittleEndian.PutUint32(hd[32:], adler32.Checksum(hd[:32]))
			parts = append(parts, part{"hash", hd}, part{"done", nil})
		} else {
			parts = append(parts, part{"next", nil})
		}
		var out bytes.Buffer
		out.Write(ewfSignature)
		out.WriteByte(0x01)
		var sn [2]byte
		binary.LittleEndian.PutUint16(sn[:], uint16(s+1))
		out.Write(sn[:])
		out.Write([]byte{0x00, 0x00})
		descOff := int64(13)
		var starts []int64
		for _, p := range parts {
			starts = append(starts, descOff)
			descOff += 76 + int64(len(p.data))
		}
		for i, p := range parts {
			nxt := starts[i]
			if i+1 < len(parts) {
				nxt = starts[i+1]
			}
			size := int64(76 + len(p.data))
			data := p.data
			if p.typ == "done" || p.typ == "next" {
				size, data = 0, nil
			}
			hdr := make([]byte, 72)
			copy(hdr, p.typ)
			binary.LittleEndian.PutUint64(hdr[16:], uint64(nxt))
			binary.LittleEndian.PutUint64(hdr[24:], uint64(size))
			out.Write(hdr)
			var a [4]byte
			binary.LittleEndian.PutUint32(a[:], adler32.Checksum(hdr))
			out.Write(a[:])
			out.Write(data)
		}
		if err := os.WriteFile(fmt.Sprintf("%s/%s.E%02d", dir, name, s+1), out.Bytes(), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, name+".E01")
}

func ewfTestVolume(nch int, spc, bps uint32, nsec int) []byte {
	v := make([]byte, 1052)
	binary.LittleEndian.PutUint32(v[0:], 1)
	binary.LittleEndian.PutUint32(v[4:], uint32(nch))
	binary.LittleEndian.PutUint32(v[8:], spc)
	binary.LittleEndian.PutUint32(v[12:], bps)
	binary.LittleEndian.PutUint64(v[16:], uint64(nsec))
	binary.LittleEndian.PutUint32(v[40:], 3)
	binary.LittleEndian.PutUint32(v[1048:], adler32.Checksum(v[:1048]))
	return v
}

func ewfTestTable(offs []uint32, base uint64) []byte {
	h20 := make([]byte, 20)
	binary.LittleEndian.PutUint32(h20[0:], uint32(len(offs)))
	binary.LittleEndian.PutUint64(h20[8:], base)
	t := append([]byte{}, h20...)
	var a [4]byte
	binary.LittleEndian.PutUint32(a[:], adler32.Checksum(h20))
	t = append(t, a[:]...)
	for _, o := range offs {
		var e [4]byte
		binary.LittleEndian.PutUint32(e[:], o)
		t = append(t, e[:]...)
	}
	arr := t[24:]
	binary.LittleEndian.PutUint32(a[:], adler32.Checksum(arr))
	return append(t, a[:]...)
}

// ewfTestRaw returns deterministic pseudo-random bytes with zeros mixed in
// so both compressed and stored chunks exercise real paths.
func ewfTestRaw(t ewfTB, n int) []byte {
	t.Helper()
	rng := rand.New(rand.NewSource(0xE01))
	raw := make([]byte, n)
	rng.Read(raw)
	for i := 0; i < n; i += 7000 {
		for j := i; j < i+3000 && j < n; j++ {
			raw[j] = 0
		}
	}
	return raw
}

func ewfDecodeAll(t *testing.T, tgt scanTarget) []byte {
	t.Helper()
	size, err := tgt.Size()
	if err != nil {
		t.Fatal(err)
	}
	r, err := tgt.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	out, err := io.ReadAll(io.NewSectionReader(r.(io.ReaderAt), 0, size))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestEWFRoundTripCompressed(t *testing.T) {
	dir := t.TempDir()
	raw := ewfTestRaw(t, 100*1024+777) // partial final chunk
	e01 := buildEWF(t, dir, "comp", raw, ewfBuildOpt{sectorsPerChunk: 4})
	tgt, err := detectScanTarget(e01, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tgt.(*ewfScanTarget); !ok {
		t.Fatalf("detect picked %T, want *ewfScanTarget", tgt)
	}
	got := ewfDecodeAll(t, tgt)
	// Media rounds up to whole sectors; the tail past len(raw) is padding.
	wantLen := (len(raw) + 511) / 512 * 512
	if len(got) != wantLen {
		t.Fatalf("decoded %d bytes, want %d", len(got), wantLen)
	}
	if !bytes.Equal(got[:len(raw)], raw) {
		t.Fatalf("decoded content differs at %d", firstDiff(got, raw))
	}
	if rest := bytes.Trim(got[len(raw):], "\x00"); len(rest) != 0 {
		t.Fatal("sector padding is not zero")
	}
}

func TestEWFRoundTripStored(t *testing.T) {
	dir := t.TempDir()
	raw := ewfTestRaw(t, 48*1024)
	e01 := buildEWF(t, dir, "stored", raw, ewfBuildOpt{
		sectorsPerChunk: 4,
		compress:        func(int) bool { return false },
	})
	tgt, err := detectScanTarget(e01, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := ewfDecodeAll(t, tgt); !bytes.Equal(got, raw) {
		t.Fatalf("decoded %d bytes, differ at %d", len(got), firstDiff(got, raw))
	}
}

func TestEWFRoundTripMixed(t *testing.T) {
	dir := t.TempDir()
	raw := ewfTestRaw(t, 64*1024)
	e01 := buildEWF(t, dir, "mixed", raw, ewfBuildOpt{
		sectorsPerChunk: 2,
		compress:        func(i int) bool { return i%2 == 0 },
	})
	tgt, err := detectScanTarget(e01, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := ewfDecodeAll(t, tgt); !bytes.Equal(got, raw) {
		t.Fatalf("decoded %d bytes, differ at %d", len(got), firstDiff(got, raw))
	}
}

func TestEWFMultiSegment(t *testing.T) {
	dir := t.TempDir()
	raw := ewfTestRaw(t, 200*1024)
	e01 := buildEWF(t, dir, "multi", raw, ewfBuildOpt{sectorsPerChunk: 4, chunksPerSeg: 7})
	entries, _ := filepath.Glob(filepath.Join(dir, "multi.E*"))
	if len(entries) < 3 {
		t.Fatalf("want 3+ segments, got %v", entries)
	}
	tgt, err := detectScanTarget(e01, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := ewfDecodeAll(t, tgt); !bytes.Equal(got, raw) {
		t.Fatalf("decoded %d bytes, differ at %d", len(got), firstDiff(got, raw))
	}
}

func TestEWFSeekAndPartialReads(t *testing.T) {
	dir := t.TempDir()
	raw := ewfTestRaw(t, 100*1024)
	e01 := buildEWF(t, dir, "seek", raw, ewfBuildOpt{sectorsPerChunk: 4})
	tgt, err := detectScanTarget(e01, 0)
	if err != nil {
		t.Fatal(err)
	}
	r, err := tgt.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	// Unaligned read spanning several chunks.
	buf := make([]byte, 9999)
	if _, err := r.ReadAt(buf, 1500); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, raw[1500:1500+9999]) {
		t.Fatal("unaligned ReadAt mismatch")
	}
	// Sequential Read from a seek position.
	if _, err := r.Seek(77777, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw[77777:]) {
		t.Fatal("Read-after-Seek mismatch")
	}
	// Read past the end reports EOF.
	if _, err := r.ReadAt(make([]byte, 8), int64(len(raw))); err != io.EOF {
		t.Fatalf("ReadAt past end err=%v, want EOF", err)
	}
}

// TestEWFRealFixture decodes a libewf-produced E01: byte-exactness is
// attested by the MD5 libewf itself stored and verified (ewfverify
// SUCCESS, ewfexport byte-identical to source at fixture creation).
func TestEWFRealFixture(t *testing.T) {
	tgt, err := detectScanTarget("testdata/ewf-real.E01", 0)
	if err != nil {
		t.Fatal(err)
	}
	size, err := tgt.Size()
	if err != nil {
		t.Fatal(err)
	}
	if size != 1048576 {
		t.Fatalf("media size %d, want 1048576", size)
	}
	got := ewfDecodeAll(t, tgt)
	sum := md5.Sum(got)
	if got, want := fmt.Sprintf("%x", sum), "afcc23c8ddd8a8dbd462e2a6de2703a1"; got != want {
		t.Fatalf("decoded md5 %s, want %s", got, want)
	}
}

func TestEWFCorruptChunkFailsLoud(t *testing.T) {
	dir := t.TempDir()
	raw := ewfTestRaw(t, 48*1024)
	e01 := buildEWF(t, dir, "bad", raw, ewfBuildOpt{
		sectorsPerChunk: 4,
		compress:        func(int) bool { return false },
	})
	// Flip a byte inside the third chunk's stored data.
	tgt, err := detectScanTarget(e01, 0)
	if err != nil {
		t.Fatal(err)
	}
	et := tgt.(*ewfScanTarget)
	c := et.layout.chunks[2]
	f, err := os.OpenFile(e01, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	b := []byte{0x00}
	if _, err := f.ReadAt(b, c.off+10); err != nil {
		t.Fatal(err)
	}
	b[0] ^= 0xff
	if _, err := f.WriteAt(b, c.off+10); err != nil {
		t.Fatal(err)
	}
	f.Close()
	r, err := tgt.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.ReadAt(make([]byte, 512), 2*et.layout.chunkBytes); err == nil {
		t.Fatal("corrupt chunk decoded without error")
	} else if !bytes.Contains([]byte(err.Error()), []byte("chunk 2")) {
		t.Fatalf("error %q does not identify chunk 2", err)
	}
}

func TestEWFCorruptTableFailsFast(t *testing.T) {
	dir := t.TempDir()
	raw := ewfTestRaw(t, 48*1024)
	e01 := buildEWF(t, dir, "badtbl", raw, ewfBuildOpt{sectorsPerChunk: 4})
	blob, err := os.ReadFile(e01)
	if err != nil {
		t.Fatal(err)
	}
	// Find the table section and flip an offset-array byte.
	off := int64(13)
	for {
		typ := string(bytes.TrimRight(blob[off:off+16], "\x00"))
		nxt := int64(binary.LittleEndian.Uint64(blob[off+16:]))
		if typ == "table" {
			blob[off+76+30] ^= 0xff
			break
		}
		off = nxt
	}
	if err := os.WriteFile(e01, blob, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := detectScanTarget(e01, 0); err == nil {
		t.Fatal("corrupt table opened without error")
	}
}

func TestEWFTruncatedSetFailsFast(t *testing.T) {
	dir := t.TempDir()
	raw := ewfTestRaw(t, 200*1024)
	e01 := buildEWF(t, dir, "trunc", raw, ewfBuildOpt{sectorsPerChunk: 4, chunksPerSeg: 7})
	if err := os.Remove(filepath.Join(dir, "trunc.E03")); err != nil {
		t.Fatal(err)
	}
	// Renumber E04 over the gap so the set looks contiguous-but-short.
	if err := os.Rename(filepath.Join(dir, "trunc.E04"), filepath.Join(dir, "trunc.E03")); err != nil {
		t.Fatal(err)
	}
	if _, err := detectScanTarget(e01, 0); err == nil {
		t.Fatal("truncated set opened without error")
	}
}

func TestEWFWantsSegmentOne(t *testing.T) {
	dir := t.TempDir()
	raw := ewfTestRaw(t, 200*1024)
	buildEWF(t, dir, "seg", raw, ewfBuildOpt{sectorsPerChunk: 4, chunksPerSeg: 7})
	if _, err := detectScanTarget(filepath.Join(dir, "seg.E02"), 0); err == nil {
		t.Fatal("segment 2 accepted as scan root")
	}
}

func TestSplitRawRoundTrip(t *testing.T) {
	dir := t.TempDir()
	parts := [][]byte{
		bytes.Repeat([]byte("A"), 1000),
		bytes.Repeat([]byte("B"), 70000),
		bytes.Repeat([]byte("C"), 17),
	}
	var want []byte
	for i, p := range parts {
		if err := os.WriteFile(fmt.Sprintf("%s/img.%03d", dir, i+1), p, 0644); err != nil {
			t.Fatal(err)
		}
		want = append(want, p...)
	}
	// Root may be any segment; the whole set scans.
	tgt, err := detectScanTarget(fmt.Sprintf("%s/img.002", dir), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tgt.(*splitScanTarget); !ok {
		t.Fatalf("detect picked %T, want *splitScanTarget", tgt)
	}
	if got := ewfDecodeAll(t, tgt); !bytes.Equal(got, want) {
		t.Fatal("split raw decode mismatch")
	}
	r, err := tgt.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	// Read spanning the .001/.002 boundary.
	buf := make([]byte, 10)
	if _, err := r.ReadAt(buf, 995); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, want[995:1005]) {
		t.Fatal("cross-boundary ReadAt mismatch")
	}
}

func TestSplitRawSingleFile(t *testing.T) {
	dir := t.TempDir()
	want := []byte("lone split body")
	if err := os.WriteFile(filepath.Join(dir, "one.001"), want, 0644); err != nil {
		t.Fatal(err)
	}
	tgt, err := detectScanTarget(filepath.Join(dir, "one.001"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := ewfDecodeAll(t, tgt); !bytes.Equal(got, want) {
		t.Fatal("single-file split decode mismatch")
	}
}

func TestDetectPlainFileUnchanged(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "plain.bin")
	if err := os.WriteFile(p, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	tgt, err := detectScanTarget(p, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tgt.(*fileScanTarget); !ok {
		t.Fatalf("detect picked %T, want *fileScanTarget", tgt)
	}
}

// End to end: a wallet needle inside an E01 is found at its decoded offset.
func TestScanE01FindsWallet(t *testing.T) {
	dir := t.TempDir()
	raw := ewfTestRaw(t, 96*1024)
	const at = 50000
	copy(raw[at:], " "+fuzzyExact12+" ")
	e01 := buildEWF(t, dir, "wallet", raw, ewfBuildOpt{
		sectorsPerChunk: 2,
		compress:        func(i int) bool { return i%2 == 0 },
	})
	var dets []Detection
	err := ScanWithOptions(0, e01, Options{},
		func(d Detection) { dets = append(dets, d) },
		func(ProgressInfo) {})
	if err != nil {
		t.Fatal(err)
	}
	if len(dets) != 1 {
		t.Fatalf("got %d detections, want 1 (%v)", len(dets), dets)
	}
	if dets[0].Needle != "bip39-12" {
		t.Fatalf("needle %q, want bip39-12", dets[0].Needle)
	}
	if dets[0].Offset != at+1 {
		t.Fatalf("offset %d, want %d", dets[0].Offset, at+1)
	}
	if len(dets[0].Words) != 0 {
		t.Fatal("default scan leaks seed words")
	}
}

func firstDiff(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// Minimal SMART (S01) writer for tests. Layout mirrors real libewf SMART
// output (verified byte-for-byte against ewfexport during Goal 14
// development): 94-byte volume with SMART marker, table section carrying
// the chunk data inline with absolute file offsets, hash/done on the
// final segment, next-terminated earlier segments, done/next size 76.

func buildSMART(t ewfTB, dir, name string, raw []byte, opt ewfBuildOpt) string {
	t.Helper()
	spc := opt.sectorsPerChunk
	if spc == 0 {
		spc = 64
	}
	const bps = 512
	chunkBytes := int(spc) * bps
	nch := (len(raw) + chunkBytes - 1) / chunkBytes
	nsec := (len(raw) + bps - 1) / bps
	stored, flags := ewfEncodeChunks(t, raw, chunkBytes, opt.compress)
	var groups [][]int
	if opt.chunksPerSeg > 0 {
		for i := 0; i < nch; i += opt.chunksPerSeg {
			end := i + opt.chunksPerSeg
			if end > nch {
				end = nch
			}
			var g []int
			for j := i; j < end; j++ {
				g = append(g, j)
			}
			groups = append(groups, g)
		}
	} else {
		var g []int
		for i := 0; i < nch; i++ {
			g = append(g, i)
		}
		groups = [][]int{g}
	}
	vol := make([]byte, 94)
	binary.LittleEndian.PutUint32(vol[0:], 1)
	binary.LittleEndian.PutUint32(vol[4:], uint32(nch))
	binary.LittleEndian.PutUint32(vol[8:], spc)
	binary.LittleEndian.PutUint32(vol[12:], bps)
	binary.LittleEndian.PutUint64(vol[16:], uint64(nsec))
	copy(vol[85:], "SMART")
	binary.LittleEndian.PutUint32(vol[90:], adler32.Checksum(vol[:90]))
	type part struct {
		typ  string
		data []byte
	}
	h := md5.Sum(raw)
	hd := make([]byte, 36)
	copy(hd, h[:])
	binary.LittleEndian.PutUint32(hd[32:], adler32.Checksum(hd[:32]))
	for s, g := range groups {
		var parts []part
		tabDesc := int64(13)
		if s == 0 {
			parts = append(parts, part{"volume", vol})
			tabDesc += 76 + int64(len(vol))
		}
		// Table entries are absolute file offsets into this section's
		// own data, which starts after the 24-byte table header and
		// the n*4 offset array.
		dataStart := tabDesc + 76 + 24 + int64(len(g))*4
		var tab bytes.Buffer
		h20 := make([]byte, 20)
		binary.LittleEndian.PutUint32(h20[0:], uint32(len(g)))
		tab.Write(h20)
		var a [4]byte
		binary.LittleEndian.PutUint32(a[:], adler32.Checksum(h20))
		tab.Write(a[:])
		pos := uint32(dataStart)
		for _, ci := range g {
			o := pos
			if flags[ci] {
				o |= 0x80000000
			}
			var e [4]byte
			binary.LittleEndian.PutUint32(e[:], o)
			tab.Write(e[:])
			pos += uint32(len(stored[ci]))
		}
		for _, ci := range g {
			tab.Write(stored[ci])
		}
		parts = append(parts, part{"table", tab.Bytes()})
		if s == len(groups)-1 {
			parts = append(parts, part{"hash", hd}, part{"done", nil})
		} else {
			parts = append(parts, part{"next", nil})
		}
		var out bytes.Buffer
		out.Write(ewfSignature)
		out.WriteByte(0x01)
		var sn [2]byte
		binary.LittleEndian.PutUint16(sn[:], uint16(s+1))
		out.Write(sn[:])
		out.Write([]byte{0x00, 0x00})
		descOff := int64(13)
		var starts []int64
		for _, p := range parts {
			starts = append(starts, descOff)
			size := int64(76 + len(p.data))
			if p.typ == "done" || p.typ == "next" {
				size = 76 // real SMART writers emit the descriptor alone
			}
			descOff += size
		}
		for i, p := range parts {
			nxt := starts[i]
			if i+1 < len(parts) {
				nxt = starts[i+1]
			}
			size := int64(76 + len(p.data))
			data := p.data
			if p.typ == "done" || p.typ == "next" {
				size, data = 76, nil
			}
			hdr := make([]byte, 72)
			copy(hdr, p.typ)
			binary.LittleEndian.PutUint64(hdr[16:], uint64(nxt))
			binary.LittleEndian.PutUint64(hdr[24:], uint64(size))
			out.Write(hdr)
			var a [4]byte
			binary.LittleEndian.PutUint32(a[:], adler32.Checksum(hdr))
			out.Write(a[:])
			out.Write(data)
		}
		if err := os.WriteFile(fmt.Sprintf("%s/%s.s%02d", dir, name, s+1), out.Bytes(), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, name+".s01")
}

func TestSMARTRoundTripMixed(t *testing.T) {
	dir := t.TempDir()
	raw := ewfTestRaw(t, 200*1024)
	path := buildSMART(t, dir, "case", raw, ewfBuildOpt{compress: func(i int) bool { return i%2 == 0 }})
	tgt, err := detectScanTarget(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := ewfDecodeAll(t, tgt); !bytes.Equal(got, raw) {
		t.Fatalf("SMART round trip differs at byte %d", firstDiff(got, raw))
	}
}

func TestSMARTMultiSegment(t *testing.T) {
	dir := t.TempDir()
	raw := ewfTestRaw(t, 300*1024)
	path := buildSMART(t, dir, "case", raw, ewfBuildOpt{chunksPerSeg: 2})
	tgt, err := detectScanTarget(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := ewfDecodeAll(t, tgt); !bytes.Equal(got, raw) {
		t.Fatalf("SMART multi-segment differs at byte %d", firstDiff(got, raw))
	}
}

func TestSMARTRealFixture(t *testing.T) {
	tgt, err := detectScanTarget("testdata/ewf-real.S01", 0)
	if err != nil {
		t.Fatal(err)
	}
	et, ok := tgt.(*ewfScanTarget)
	if !ok {
		t.Fatalf("target %T, want *ewfScanTarget", tgt)
	}
	if et.layout.flavor != "smart" {
		t.Errorf("flavor %q, want smart", et.layout.flavor)
	}
	size, err := tgt.Size()
	if err != nil {
		t.Fatal(err)
	}
	if size != 4096 {
		t.Fatalf("media size %d, want 4096", size)
	}
	got := ewfDecodeAll(t, tgt)
	sum := md5.Sum(got)
	// Acquired with ewfacquire -f smart from 4KiB of wallet-trace text;
	// ewfexport of the same file hashes identically.
	if got, want := fmt.Sprintf("%x", sum), "739687d272315e8c5c1f5dda2086c2dd"; got != want {
		t.Fatalf("decoded md5 %s, want %s", got, want)
	}
	if !et.layout.hasMD5 || fmt.Sprintf("%x", et.layout.md5) != "739687d272315e8c5c1f5dda2086c2dd" {
		t.Errorf("stored MD5 missing or mismatched: has=%v md5=%x", et.layout.hasMD5, et.layout.md5)
	}
}

func TestScanS01FindsWallet(t *testing.T) {
	var dets []Detection
	err := ScanWithOptions(0, "testdata/ewf-real.S01", Options{},
		func(d Detection) { dets = append(dets, d) },
		func(ProgressInfo) {})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range dets {
		if d.Needle == "bestblock" || d.Needle == "orderposnext" {
			found = true
		}
		if d.Target != "testdata/ewf-real.S01" {
			t.Errorf("detection target %q, want the S01 path", d.Target)
		}
	}
	if !found {
		t.Errorf("no wallet needles in S01 scan: %+v", dets)
	}
}

func TestSMARTCorruptTableFailsFast(t *testing.T) {
	raw, err := os.ReadFile("testdata/ewf-real.S01")
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt a table entry offset (table data starts after the volume
	// section; any byte flip inside must fail eager parsing).
	raw[400] ^= 0xFF
	path := filepath.Join(t.TempDir(), "bad.s01")
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := detectScanTarget(path, 0); err == nil {
		t.Error("corrupt S01 table must fail eager parsing")
	}
}

func TestEWF2Refused(t *testing.T) {
	// Real EWF2 sample (ewfacquire -f encase7-v2): refused with a
	// conversion pointer, never misread as raw or v1.
	if _, err := detectScanTarget("testdata/ewf-real.Ex01", 0); err == nil {
		t.Error("Ex01 must be refused")
	} else if !strings.Contains(err.Error(), "EWF2") || !strings.Contains(err.Error(), "ewfexport") {
		t.Errorf("Ex01 refusal must name EWF2 and ewfexport: %v", err)
	}
	// Magic-only probe: any EVF2 file refuses, which also covers Lx01
	// (same EWF2 framing, no acquirable sample).
	magic := append(append([]byte{}, ewf2Signature...), make([]byte, 64)...)
	path := filepath.Join(t.TempDir(), "probe.Lx01")
	if err := os.WriteFile(path, magic, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := detectScanTarget(path, 0); err == nil {
		t.Error("EVF2 magic must be refused")
	} else if !strings.Contains(err.Error(), "EWF2") {
		t.Errorf("EVF2 refusal must name EWF2: %v", err)
	}
}
