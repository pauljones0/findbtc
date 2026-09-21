package detector

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Hand-built FAT images (no mkfs/mount needed): exact geometry,
// known entries, needle-bearing deleted files. See buildTestExt for
// the established pattern.

// fatGeometry describes one fixture image.
type fatGeometry struct {
	fatBits     int // 12, 16, or 32
	bytesPerSec int64
	secPerClust int64
	reserved    int64
	numFATs     int64
	fatSecs     int64
	rootEntries int64
	totalSecs   int64
	rootClust   int64 // FAT32 only
}

func (g fatGeometry) clustBytes() int64 { return g.bytesPerSec * g.secPerClust }
func (g fatGeometry) fatStart() int64   { return g.reserved * g.bytesPerSec }
func (g fatGeometry) dataStart() int64 {
	rootSecs := (g.rootEntries*32 + g.bytesPerSec - 1) / g.bytesPerSec
	return (g.reserved+g.numFATs*g.fatSecs)*g.bytesPerSec + rootSecs*g.bytesPerSec
}
func (g fatGeometry) clustOff(c int64) int64 { return g.dataStart() + (c-2)*g.clustBytes() }

func putBPB(img []byte, g fatGeometry) {
	img[0], img[1], img[2] = 0xEB, 0x3C, 0x90
	copy(img[3:], "MSDOS5.0")
	binary.LittleEndian.PutUint16(img[11:], uint16(g.bytesPerSec))
	img[13] = byte(g.secPerClust)
	binary.LittleEndian.PutUint16(img[14:], uint16(g.reserved))
	img[16] = byte(g.numFATs)
	binary.LittleEndian.PutUint16(img[17:], uint16(g.rootEntries))
	img[21] = 0xF8
	if g.fatBits == 32 {
		binary.LittleEndian.PutUint32(img[32:], uint32(g.totalSecs))
		binary.LittleEndian.PutUint32(img[36:], uint32(g.fatSecs))
		binary.LittleEndian.PutUint32(img[44:], uint32(g.rootClust))
		copy(img[71:], "FINDBTCVOL ")
		copy(img[82:], "FAT32   ")
	} else {
		binary.LittleEndian.PutUint16(img[19:], uint16(g.totalSecs))
		binary.LittleEndian.PutUint16(img[22:], uint16(g.fatSecs))
		copy(img[43:], "FINDBTCVOL ")
		if g.fatBits == 12 {
			copy(img[54:], "FAT12   ")
		} else {
			copy(img[54:], "FAT16   ")
		}
	}
	img[510], img[511] = 0x55, 0xAA
}

// putFAT writes one FAT entry at cluster c.
func putFAT(img []byte, g fatGeometry, c, val int64) {
	base := g.fatStart()
	switch g.fatBits {
	case 12:
		off := base + c*3/2
		prev := int64(img[off]) | int64(img[off+1])<<8
		var next int64
		if c%2 == 0 {
			next = (prev & 0xF000) | (val & 0xFFF)
		} else {
			next = (prev & 0x000F) | ((val & 0xFFF) << 4)
		}
		img[off] = byte(next)
		img[off+1] = byte(next >> 8)
	case 16:
		binary.LittleEndian.PutUint16(img[base+c*2:], uint16(val))
	default:
		binary.LittleEndian.PutUint32(img[base+c*4:], uint32(val))
	}
}

func fatEOCVal(bits int) int64 {
	switch bits {
	case 12:
		return 0xFFF
	case 16:
		return 0xFFFF
	default:
		return 0x0FFFFFFF
	}
}

// putShort writes a 32-byte 8.3 directory slot.
func putShort(dir []byte, slot int, name11 string, attr byte, first int64, size int64) {
	s := dir[slot*32 : (slot+1)*32]
	copy(s, name11)
	s[11] = attr
	binary.LittleEndian.PutUint16(s[26:], uint16(first&0xFFFF))
	binary.LittleEndian.PutUint16(s[20:], uint16(first>>16))
	binary.LittleEndian.PutUint32(s[28:], uint32(size))
}

// lfnChecksum is the stock 8.3 checksum stored in LFN slots.
func lfnChecksum(name11 string) byte {
	var sum byte
	for i := 0; i < 11; i++ {
		sum = ((sum >> 1) | (sum << 7)) + name11[i]
	}
	return sum
}

// putLFN writes the LFN run for name ahead of slot (slots run
// backwards on disk), using alias11 for the checksum. It returns the
// slot index the 8.3 entry must occupy.
func putLFN(dir []byte, slot int, name, alias11 string) int {
	units := []uint16{}
	for _, r := range name {
		units = append(units, uint16(r))
	}
	nparts := (len(units) + 12) / 13
	for len(units) < nparts*13 {
		units = append(units, 0xFFFF)
	}
	// NUL-terminate when room allows (non-final padding stays FFFF).
	if len(name) < nparts*13 {
		units[len(name)] = 0x0000
	}
	chk := lfnChecksum(alias11)
	for p := 0; p < nparts; p++ {
		s := dir[(slot+p)*32 : (slot+p+1)*32]
		seq := byte(nparts - p)
		if p == 0 {
			seq |= 0x40
		}
		s[0] = seq
		s[11] = 0x0F
		s[12] = 0x00
		s[13] = chk
		chunk := units[(nparts-1-p)*13 : (nparts-p)*13]
		offs := []int{1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30}
		for i, u := range chunk {
			binary.LittleEndian.PutUint16(s[offs[i]:], u)
		}
	}
	return slot + nparts
}

// delLFN stamps 0xE5 over an LFN run's sequence bytes, the way real FAT
// deletion leaves surviving slots (fls still recovers these).
func delLFN(dir []byte, first, nparts int) {
	for p := 0; p < nparts; p++ {
		dir[(first+p)*32] = 0xE5
	}
}

func fat32Geometry() fatGeometry {
	// 65536 clusters clears the FAT32 threshold (65525).
	return fatGeometry{fatBits: 32, bytesPerSec: 512, secPerClust: 1,
		reserved: 32, numFATs: 2, fatSecs: 512, rootEntries: 0,
		totalSecs: 32 + 2*512 + 65536, rootClust: 2}
}

// buildTestFAT32: live file, deleted file with needle (chain zeroed,
// prefix recovery), subdir with live + LFN files.
func buildTestFAT32(t *testing.T) string {
	t.Helper()
	g := fat32Geometry()
	img := make([]byte, g.totalSecs*g.bytesPerSec)
	putBPB(img, g)
	eoc := fatEOCVal(32)
	putFAT(img, g, 0, 0x0FFFFFF8)
	putFAT(img, g, 1, 0x0FFFFFFF)
	// Cluster contents.
	putClust := func(c int64, data []byte) {
		copy(img[g.clustOff(c):], data)
	}
	putClust(3, []byte("live and well\n"))
	bin := make([]byte, 600)
	copy(bin, "bestblock")
	putClust(4, bin[:512]) // deleted file head; tail cluster freed
	putClust(5, []byte("gone file\n"))
	putClust(8, []byte("inner file\n"))
	putClust(9, []byte("long name content\n"))
	for _, c := range []int64{2, 3, 7, 8, 9} {
		putFAT(img, g, c, eoc)
	}
	// Cluster 4 stays 0: deleted chain zeroed (prefix recovery).
	// Root dir in cluster 2.
	root := img[g.clustOff(2) : g.clustOff(2)+g.clustBytes()]
	putShort(root, 0, "LIVE    TXT", 0x20, 3, 13)
	next := putLFN(root, 1, "deleted wallet backup.dat", "DELETED BIN")
	delLFN(root, 1, next-1)
	putShort(root, next, "DELETED BIN", 0x20, 4, 600)
	root[next*32] = 0xE5 // deleted
	putShort(root, next+1, "SUBDIR     ", 0x10, 7, 0)
	// Destroyed-LFN control: no surviving run keeps the '?' short form.
	// (Cluster 5 stays FAT-zero like the needle head: deleted chains.)
	putShort(root, next+2, "GONE    TXT", 0x20, 5, 10)
	root[(next+2)*32] = 0xE5
	// Subdir in cluster 7.
	sub := img[g.clustOff(7) : g.clustOff(7)+g.clustBytes()]
	putShort(sub, 0, ".          ", 0x10, 7, 0)
	putShort(sub, 1, "..         ", 0x10, 2, 0)
	putShort(sub, 2, "INNER   TXT", 0x20, 8, 11)
	next = putLFN(sub, 3, "a rather long file name.dat", "ARATHE~1DAT")
	putShort(sub, next, "ARATHE~1DAT", 0x20, 9, 18)
	path := filepath.Join(t.TempDir(), "fat32.img")
	if err := os.WriteFile(path, img, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func fat16Geometry() fatGeometry {
	return fatGeometry{fatBits: 16, bytesPerSec: 512, secPerClust: 1,
		reserved: 8, numFATs: 2, fatSecs: 20, rootEntries: 16,
		totalSecs: 8 + 2*20 + 1 + 5000}
}

// buildTestFAT16 exercises the fixed-root (FAT12/16) path.
func buildTestFAT16(t *testing.T) string {
	t.Helper()
	g := fat16Geometry()
	img := make([]byte, g.totalSecs*g.bytesPerSec)
	putBPB(img, g)
	eoc := fatEOCVal(16)
	putFAT(img, g, 0, 0xFFF8)
	putFAT(img, g, 1, 0xFFFF)
	putClust := func(c int64, data []byte) {
		copy(img[g.clustOff(c):], data)
	}
	putClust(2, []byte("fat16 live\n"))
	bin := make([]byte, 512)
	copy(bin, "bestblock")
	putClust(3, bin)
	putClust(5, []byte("inner16\n"))
	putClust(6, []byte("sixteen content\n"))
	for _, c := range []int64{2, 4, 5, 6} {
		putFAT(img, g, c, eoc)
	}
	rootOff := (g.reserved + g.numFATs*g.fatSecs) * g.bytesPerSec
	root := img[rootOff : rootOff+g.rootEntries*32]
	putShort(root, 0, "LIVE16  TXT", 0x20, 2, 11)
	next := putLFN(root, 1, "old wallet backup.dat", "DEL16   BIN")
	delLFN(root, 1, next-1)
	putShort(root, next, "DEL16   BIN", 0x20, 3, 512)
	root[next*32] = 0xE5
	putShort(root, next+1, "SUB16      ", 0x10, 4, 0)
	next = putLFN(root, next+2, "fat16 long name.txt", "FAT16L~1TXT")
	putShort(root, next, "FAT16L~1TXT", 0x20, 6, 16)
	sub := img[g.clustOff(4) : g.clustOff(4)+g.clustBytes()]
	putShort(sub, 0, ".          ", 0x10, 4, 0)
	putShort(sub, 1, "..         ", 0x10, 0, 0)
	putShort(sub, 2, "INNER16 TXT", 0x20, 5, 8)
	path := filepath.Join(t.TempDir(), "fat16.img")
	if err := os.WriteFile(path, img, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func fat12Geometry() fatGeometry {
	return fatGeometry{fatBits: 12, bytesPerSec: 512, secPerClust: 1,
		reserved: 8, numFATs: 2, fatSecs: 1, rootEntries: 16,
		totalSecs: 8 + 2*1 + 1 + 100}
}

// buildTestFAT12 is minimal: live + deleted, no needles.
func buildTestFAT12(t *testing.T) string {
	t.Helper()
	g := fat12Geometry()
	img := make([]byte, g.totalSecs*g.bytesPerSec)
	putBPB(img, g)
	eoc := fatEOCVal(12)
	putFAT(img, g, 0, 0xFF8)
	putFAT(img, g, 1, 0xFFF)
	copy(img[g.clustOff(2):], []byte("fat12 live\n"))
	copy(img[g.clustOff(3):], []byte("fat12 gone\n"))
	putFAT(img, g, 2, eoc)
	rootOff := (g.reserved + g.numFATs*g.fatSecs) * g.bytesPerSec
	root := img[rootOff : rootOff+g.rootEntries*32]
	putShort(root, 0, "A       TXT", 0x20, 2, 11)
	next := putLFN(root, 1, "gone wall.dat", "B       BIN")
	delLFN(root, 1, next-1)
	putShort(root, next, "B       BIN", 0x20, 3, 11)
	root[next*32] = 0xE5
	path := filepath.Join(t.TempDir(), "fat12.img")
	if err := os.WriteFile(path, img, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func openFATPath(t *testing.T, path string) *fatVol {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	vol, err := OpenFAT(f, 0)
	if err != nil {
		t.Fatalf("OpenFAT: %v", err)
	}
	return vol
}

func fatEntriesByName(t *testing.T, vol *fatVol) map[string]FSEntry {
	t.Helper()
	entries, err := vol.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	out := map[string]FSEntry{}
	for _, e := range entries {
		out[e.Name] = e
	}
	return out
}

func TestFAT32Entries(t *testing.T) {
	vol := openFATPath(t, buildTestFAT32(t))
	if vol.fatType != "fat32" {
		t.Fatalf("type %s, want fat32", vol.fatType)
	}
	byName := fatEntriesByName(t, vol)
	live, ok := byName["LIVE.TXT"]
	if !ok || live.Deleted || live.Size != 13 || len(live.Extents) != 1 {
		t.Errorf("live entry: %+v", live)
	}
	del, ok := byName["deleted wallet backup.dat"]
	if !ok || !del.Deleted || del.Size != 600 {
		t.Fatalf("deleted entry: %+v", del)
	}
	// Chain zeroed: honest prefix (first cluster only).
	if len(del.Extents) != 1 || del.Extents[0].Len != 512 {
		t.Errorf("deleted extents %+v, want one 512-byte prefix", del.Extents)
	}
	// The mangled 8.3 survives as the second alias, never the name.
	if len(del.Names) != 2 || del.Names[1] != "?ELETED.BIN" {
		t.Errorf("deleted aliases %+v, want the long name plus ?ELETED.BIN", del.Names)
	}
	// Destroyed-LFN control: no surviving run keeps the '?' short form.
	if e, ok := byName["?ONE.TXT"]; !ok || !e.Deleted || len(e.Extents) != 1 {
		t.Errorf("destroyed-LFN control: %+v", e)
	}
	inner, ok := byName["INNER.TXT"]
	if !ok || inner.Deleted {
		t.Errorf("subdir file missing: %+v", inner)
	}
	long, ok := byName["a rather long file name.dat"]
	if !ok || len(long.Names) != 2 {
		t.Errorf("LFN entry: %+v", long)
	}
	for _, e := range byName {
		if !strings.HasPrefix(e.Note, "fat:") {
			t.Errorf("note %q must locate the entry", e.Note)
		}
	}
}

func TestFAT16Entries(t *testing.T) {
	vol := openFATPath(t, buildTestFAT16(t))
	if vol.fatType != "fat16" {
		t.Fatalf("type %s, want fat16", vol.fatType)
	}
	byName := fatEntriesByName(t, vol)
	if e, ok := byName["LIVE16.TXT"]; !ok || e.Deleted {
		t.Errorf("live: %+v", e)
	}
	if e, ok := byName["old wallet backup.dat"]; !ok || !e.Deleted {
		t.Errorf("deleted: %+v", e)
	} else if len(e.Names) != 2 || e.Names[1] != "?EL16.BIN" {
		t.Errorf("deleted aliases %+v, want the long name plus ?EL16.BIN", e.Names)
	}
	if e, ok := byName["fat16 long name.txt"]; !ok {
		t.Errorf("LFN missing (have %v)", byName)
	} else if len(e.Names) != 2 {
		t.Errorf("LFN aliases: %+v", e.Names)
	}
	if e, ok := byName["INNER16.TXT"]; !ok || e.Deleted {
		t.Errorf("subdir file: %+v", e)
	}
}

func TestFAT12Entries(t *testing.T) {
	vol := openFATPath(t, buildTestFAT12(t))
	if vol.fatType != "fat12" {
		t.Fatalf("type %s, want fat12", vol.fatType)
	}
	byName := fatEntriesByName(t, vol)
	if e, ok := byName["A.TXT"]; !ok || e.Deleted {
		t.Errorf("live: %+v", e)
	}
	if e, ok := byName["gone wall.dat"]; !ok || !e.Deleted {
		t.Errorf("deleted: %+v", e)
	} else if len(e.Names) != 2 || e.Names[1] != "?.BIN" {
		t.Errorf("deleted aliases %+v, want the long name plus ?.BIN", e.Names)
	}
}

// lfnParts builds an in-memory LFN run for assembleDeletedLFN unit tests.
func lfnParts(t *testing.T, name, alias11 string) [][]byte {
	t.Helper()
	dir := make([]byte, 20*32)
	end := putLFN(dir, 0, name, alias11)
	var parts [][]byte
	for s := 0; s < end; s++ {
		parts = append(parts, append([]byte{}, dir[s*32:(s+1)*32]...))
	}
	return parts
}

func stampE5(parts [][]byte) {
	for _, p := range parts {
		p[0] = 0xE5
	}
}

func TestAssembleDeletedLFN(t *testing.T) {
	const name = "deleted wallet backup.dat"
	// Fully-intact run (only the short entry was stamped): live bar.
	if n, ok := assembleDeletedLFN(lfnParts(t, name, "DELETED BIN")); !ok || n != name {
		t.Errorf("intact run: %q,%v", n, ok)
	}
	// Realistic run: every sequence byte stamped 0xE5.
	e5 := lfnParts(t, name, "DELETED BIN")
	stampE5(e5)
	if n, ok := assembleDeletedLFN(e5); !ok || n != name {
		t.Errorf("E5 run: %q,%v", n, ok)
	}
	// Mixed run: one stamped slot, one intact — fls recovers these.
	mixed := lfnParts(t, name, "DELETED BIN")
	mixed[0][0] = 0xE5
	if n, ok := assembleDeletedLFN(mixed); !ok || n != name {
		t.Errorf("mixed run: %q,%v", n, ok)
	}
	// Single-slot run.
	one := lfnParts(t, "gone wall.dat", "B       BIN")
	stampE5(one)
	if n, ok := assembleDeletedLFN(one); !ok || n != "gone wall.dat" {
		t.Errorf("single slot: %q,%v", n, ok)
	}
	// Checksum disagreement (partial overwrite): refuse, keep '?' short.
	// (Deliberate divergence: fls reports a mid-word truncation here.)
	bad := lfnParts(t, name, "DELETED BIN")
	stampE5(bad)
	bad[0][13] ^= 0xFF
	if n, ok := assembleDeletedLFN(bad); ok {
		t.Errorf("bad checksum accepted: %q (must refuse)", n)
	}
	// Intact slot contradicting positional order: refuse.
	seq := lfnParts(t, name, "DELETED BIN")
	seq[0][0] = 0xE5
	seq[1][0] = 0x05 // claims sequence 5 in a 2-run
	if n, ok := assembleDeletedLFN(seq); ok {
		t.Errorf("bad sequence accepted: %q (must refuse)", n)
	}
	// Empty run: refuse.
	if n, ok := assembleDeletedLFN(nil); ok {
		t.Errorf("empty run accepted: %q (must refuse)", n)
	}
}

// FAT entry decoding per width, including odd-cluster 12-bit packing.
func TestFATEntryWidths(t *testing.T) {
	fat := []byte{
		0xF8, 0xFF, 0xFF, // clusters 0,1 (12-bit)
		0x03, 0x40, 0x00, // c2=0x003, c3=0x004
		0xFF, 0x0F, 0x00, // c4=0xFFF, c5=0x000
	}
	v := &fatVol{fatType: "fat12", fat: fat, clustCount: 6}
	for c, want := range map[int64]int64{2: 0x003, 3: 0x004, 4: 0xFFF, 5: 0} {
		if got := v.fatEntry(c); got != want {
			t.Errorf("fat12 c%d = %#x, want %#x", c, got, want)
		}
	}
	v = &fatVol{fatType: "fat16", fat: []byte{0xF8, 0xFF, 0xFF, 0xFF, 0x05, 0x00, 0xFF, 0xFF}, clustCount: 4}
	if got := v.fatEntry(2); got != 5 {
		t.Errorf("fat16 c2 = %#x", got)
	}
	if !v.fatEOC(v.fatEntry(3)) {
		t.Error("fat16 EOC missed")
	}
	v = &fatVol{fatType: "fat32", fat: []byte{
		0xF8, 0xFF, 0xFF, 0x0F, 0xFF, 0xFF, 0xFF, 0x0F,
		0x07, 0x00, 0x00, 0xF0, 0xF8, 0xFF, 0xFF, 0x0F}, clustCount: 4}
	if got := v.fatEntry(2); got != 7 {
		t.Errorf("fat32 c2 = %#x, want 7 (high nibble masked)", got)
	}
	if !v.fatEOC(v.fatEntry(3)) {
		t.Error("fat32 EOC missed")
	}
}

func TestFAT32Unallocated(t *testing.T) {
	vol := openFATPath(t, buildTestFAT32(t))
	free, err := vol.Unallocated()
	if err != nil {
		t.Fatal(err)
	}
	g := fat32Geometry()
	// Live clusters stay allocated; freed + never-used read free.
	allocBytes := g.clustOff(3)
	freeBytes := g.clustOff(6)
	delHead := g.clustOff(4) // zeroed chain: free again
	covered := func(off int64) bool {
		for _, e := range free {
			if off >= e.Start && off < e.Start+e.Len {
				return true
			}
		}
		return false
	}
	if covered(allocBytes) {
		t.Error("live cluster reported free")
	}
	if !covered(freeBytes) || !covered(delHead) {
		t.Error("free clusters missing from unallocated")
	}
	// Merged into exactly two runs: [4..6] (deleted head, freed tail,
	// never-used) and [10..N] past the live clusters.
	if len(free) != 2 {
		t.Errorf("want 2 merged runs, got %v", free)
	}
}

// TestFATOracleCrossCheck replays the hand-built fixtures through real
// Sleuth Kit tools: entry names/deleted flags vs fls, deleted content
// vs icat, geometry vs fsstat. Skipped when TSK is absent (CI has no
// sleuthkit); run locally with fls/icat/fsstat on PATH.
func TestFATOracleCrossCheck(t *testing.T) {
	for _, tool := range []string{"fls", "icat", "fsstat"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("needs %s (install sleuthkit to cross-check)", tool)
		}
	}
	type fixture struct {
		tskType     string
		build       func(*testing.T) string
		live        []string // names fls must list
		deletedLong string   // deleted LFN fls must star
		control     string   // destroyed-LFN short fls must star ("" to skip)
		long        string   // live LFN fls must list ("" to skip)
	}
	for _, fx := range []fixture{
		{"fat32", buildTestFAT32,
			[]string{"LIVE.TXT", "SUBDIR", "INNER.TXT"}, "deleted wallet backup.dat", "_ONE.TXT", "a rather long file name.dat"},
		{"fat16", buildTestFAT16,
			[]string{"LIVE16.TXT", "SUB16", "INNER16.TXT"}, "old wallet backup.dat", "", "fat16 long name.txt"},
		{"fat12", buildTestFAT12,
			[]string{"A.TXT"}, "gone wall.dat", "", ""},
	} {
		path := fx.build(t)
		listing := tsk(t, "fls", "-r", "-p", "-f", fx.tskType, path)
		t.Logf("%s fls:\n%s", fx.tskType, listing)
		for _, want := range fx.live {
			if !strings.Contains(listing, want) {
				t.Errorf("%s: fls lacks live %q:\n%s", fx.tskType, want, listing)
			}
		}
		if fx.long != "" && !strings.Contains(listing, fx.long) {
			t.Errorf("%s: fls lacks LFN %q:\n%s", fx.tskType, fx.long, listing)
		}
		starred := false
		var delInode string
		for _, line := range strings.Split(listing, "\n") {
			if strings.Contains(line, "*") && strings.Contains(line, fx.deletedLong) {
				starred = true
				// Line shape: "r/r * 5:  deleted wallet backup.dat".
				fields := strings.Fields(line)
				for i, f := range fields {
					if f == "*" && i+1 < len(fields) {
						delInode = strings.TrimSuffix(fields[i+1], ":")
					}
				}
			}
		}
		if !starred {
			t.Errorf("%s: fls lacks starred deleted LFN %q:\n%s", fx.tskType, fx.deletedLong, listing)
		}
		if fx.control != "" {
			found := false
			for _, line := range strings.Split(listing, "\n") {
				if strings.Contains(line, "*") && strings.Contains(line, fx.control) {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: fls lacks starred control %q:\n%s", fx.tskType, fx.control, listing)
			}
		}
		stat := tsk(t, "fsstat", "-f", fx.tskType, path)
		if !strings.Contains(strings.ToUpper(stat), strings.ToUpper(fx.tskType)) {
			t.Errorf("%s: fsstat disagrees on type:\n%s", fx.tskType, stat)
		}
		if delInode == "" {
			t.Errorf("%s: cannot parse deleted inode from fls", fx.tskType)
			continue
		}
		dumped := tskBytes(t, "icat", "-f", fx.tskType, path, delInode)
		// My reader's bytes for the same entry must match what icat
		// returns (prefix when TSK pads a zeroed tail).
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		vol, err := OpenFAT(f, 0)
		if err != nil {
			f.Close()
			t.Fatal(err)
		}
		entries, err := vol.Entries()
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, e := range entries {
			if !e.Deleted || e.Name != fx.deletedLong {
				continue
			}
			found = true
			var mine []byte
			for _, x := range e.Extents {
				mine = append(mine, raw[x.Start:x.Start+x.Len]...)
			}
			if len(dumped) < len(mine) || !bytes.Equal(dumped[:len(mine)], mine) {
				t.Errorf("%s: icat (%d bytes) disagrees with reader (%d bytes)", fx.tskType, len(dumped), len(mine))
			}
			if !bytes.Contains(mine, []byte("bestblock")) && fx.tskType != "fat12" {
				t.Errorf("%s: deleted bytes lack the needle", fx.tskType)
			}
		}
		if !found {
			t.Errorf("%s: reader lost the deleted entry", fx.tskType)
		}
	}
}

func tsk(t *testing.T, name string, args ...string) string {
	t.Helper()
	return string(tskBytes(t, name, args...))
}

func tskBytes(t *testing.T, name string, args ...string) []byte {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return out
}

func TestFATRefusesGarbage(t *testing.T) {
	// Per-format FP bar: random bytes and repo prose are not volumes.
	rngData := make([]byte, 1<<20)
	for i := range rngData {
		rngData[i] = byte(i*31 + 7)
	}
	garbage := map[string][]byte{"random": rngData}
	for _, f := range []string{"../LICENSE", "../README.md", "../GOALS.md", "../main.go"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		garbage[f] = raw
	}
	for name, raw := range garbage {
		if _, err := OpenFAT(bytes.NewReader(raw), 0); err == nil {
			t.Errorf("OpenFAT accepted %s", name)
		}
	}
	// Near-miss BPBs refuse with specifics: bad signature, bad media,
	// wrong type string.
	g := fat16Geometry()
	img := make([]byte, g.totalSecs*g.bytesPerSec)
	putBPB(img, g)
	img[510], img[511] = 0x00, 0x00
	if _, err := OpenFAT(bytes.NewReader(img), 0); err == nil {
		t.Error("missing signature accepted")
	} else if !strings.Contains(err.Error(), "55AA") {
		t.Errorf("refusal must name the signature: %v", err)
	}
	putBPB(img, g)
	img[21] = 0x00
	if _, err := OpenFAT(bytes.NewReader(img), 0); err == nil {
		t.Error("bad media accepted")
	}
	putBPB(img, g)
	copy(img[54:], "NTFS    ")
	if _, err := OpenFAT(bytes.NewReader(img), 0); err == nil {
		t.Error("wrong type string accepted")
	}
}
