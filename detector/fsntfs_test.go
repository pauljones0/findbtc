package detector

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// Synthetic NTFS image: 64 clusters of 4096 bytes (512B sectors).
// Layout: cluster 0 boot, clusters 4-7 MFT, cluster 8 $Bitmap,
// cluster 9 a deleted wallet's freed data.

const (
	ntfsTestClusters = 64
	ntfsTestCluster  = 4096
	ntfsTestRecSize  = 1024
)

func ntfsFileNameAttr(parent uint64, name string, ns byte) []byte {
	u16 := []uint16{}
	for _, r := range name {
		u16 = append(u16, uint16(r))
	}
	val := make([]byte, 66+2*len(u16))
	binary.LittleEndian.PutUint64(val[0:8], parent)
	val[64] = byte(len(u16))
	val[65] = ns
	for i, c := range u16 {
		binary.LittleEndian.PutUint16(val[66+2*i:68+2*i], c)
	}
	return ntfsResidentAttr(ntfsAttrFileName, val)
}

func ntfsResidentAttr(typ uint32, val []byte) []byte {
	attr := make([]byte, 24+len(val))
	binary.LittleEndian.PutUint32(attr[0:4], typ)
	binary.LittleEndian.PutUint32(attr[4:8], uint32(len(attr)))
	attr[8] = 0 // resident
	binary.LittleEndian.PutUint32(attr[16:20], uint32(len(val)))
	binary.LittleEndian.PutUint16(attr[20:22], 24)
	copy(attr[24:], val)
	return attr
}

func ntfsNonresDataAttr(runs [][2]int64, realSize int64) []byte {
	var runBytes []byte
	var prev int64
	for _, rn := range runs {
		lcn, clusters := rn[0], rn[1]
		var lenField []byte
		for c := clusters; c > 0; c >>= 8 {
			lenField = append(lenField, byte(c))
		}
		delta := lcn - prev
		prev = lcn
		var offField []byte
		for i := 0; i < 8; i++ {
			offField = append(offField, byte(delta>>(8*uint(i))))
		}
		for len(offField) > 1 {
			last := offField[len(offField)-1]
			prev := offField[len(offField)-2]
			if (last == 0 && prev&0x80 == 0) || (last == 0xFF && prev&0x80 != 0) {
				offField = offField[:len(offField)-1]
				continue
			}
			break
		}
		runBytes = append(runBytes, byte(len(offField)<<4|len(lenField)))
		runBytes = append(runBytes, lenField...)
		runBytes = append(runBytes, offField...)
	}
	runBytes = append(runBytes, 0)
	attr := make([]byte, 64+len(runBytes))
	binary.LittleEndian.PutUint32(attr[0:4], ntfsAttrData)
	binary.LittleEndian.PutUint32(attr[4:8], uint32(len(attr)))
	attr[8] = 1 // nonresident
	var endVCN int64
	for _, rn := range runs {
		endVCN += rn[1]
	}
	binary.LittleEndian.PutUint64(attr[16:24], 0)
	binary.LittleEndian.PutUint64(attr[24:32], uint64(endVCN-1))
	binary.LittleEndian.PutUint16(attr[32:34], 64)
	binary.LittleEndian.PutUint64(attr[40:48], uint64(endVCN*ntfsTestCluster))
	binary.LittleEndian.PutUint64(attr[48:56], uint64(realSize))
	binary.LittleEndian.PutUint64(attr[56:64], uint64(realSize))
	copy(attr[64:], runBytes)
	return attr
}

func ntfsRecord(num int64, flags uint16, baseRef int64, attrs ...[]byte) []byte {
	rec := make([]byte, ntfsTestRecSize)
	copy(rec[0:4], "FILE")
	binary.LittleEndian.PutUint16(rec[4:6], 48) // USA offset
	binary.LittleEndian.PutUint16(rec[6:8], 3)  // USN + 2 sectors
	binary.LittleEndian.PutUint16(rec[16:18], 1)
	binary.LittleEndian.PutUint16(rec[20:22], 56) // attr offset
	binary.LittleEndian.PutUint16(rec[22:24], flags)
	binary.LittleEndian.PutUint32(rec[28:32], ntfsTestRecSize)
	binary.LittleEndian.PutUint64(rec[32:40], uint64(baseRef))
	p := 56
	for _, a := range attrs {
		copy(rec[p:], a)
		p += (len(a) + 7) &^ 7
	}
	binary.LittleEndian.PutUint32(rec[p:p+4], ntfsAttrEnd)
	p += 8
	binary.LittleEndian.PutUint32(rec[24:28], uint32(p))
	// Fixup: USN 1, stash original sector tails.
	binary.LittleEndian.PutUint16(rec[48:50], 1)
	copy(rec[50:52], rec[510:512])
	copy(rec[52:54], rec[1022:1024])
	binary.LittleEndian.PutUint16(rec[510:512], 1)
	binary.LittleEndian.PutUint16(rec[1022:1024], 1)
	return rec
}

// buildTestNTFS writes the synthetic volume and returns its path.
func buildTestNTFS(t *testing.T) string {
	t.Helper()
	img := make([]byte, ntfsTestClusters*ntfsTestCluster)
	// Boot sector.
	copy(img[3:11], "NTFS    ")
	binary.LittleEndian.PutUint16(img[11:13], 512)
	img[13] = 8
	binary.LittleEndian.PutUint64(img[40:48], ntfsTestClusters*8)
	binary.LittleEndian.PutUint64(img[48:56], 4) // MFT LCN
	img[64] = 0xF6                               // 2^10 record size
	mft := 4 * ntfsTestCluster
	putRec := func(n int, rec []byte) {
		copy(img[mft+n*ntfsTestRecSize:], rec)
	}
	putRec(0, ntfsRecord(0, 1, 0,
		ntfsFileNameAttr(5, "$MFT", 1),
		ntfsNonresDataAttr([][2]int64{{4, 4}}, 4*ntfsTestCluster)))
	putRec(5, ntfsRecord(5, 3, 0, ntfsFileNameAttr(5, ".", 1)))
	putRec(6, ntfsRecord(6, 1, 0,
		ntfsFileNameAttr(5, "$Bitmap", 1),
		ntfsNonresDataAttr([][2]int64{{8, 1}}, ntfsTestCluster)))
	putRec(7, ntfsRecord(7, 1, 0,
		ntfsFileNameAttr(5, "notes.txt", 1),
		ntfsResidentAttr(ntfsAttrData, []byte("hello"))))
	// Deleted wallet.dat with a DOS alias and one freed cluster.
	putRec(8, ntfsRecord(8, 0, 0,
		ntfsFileNameAttr(5, "wallet.dat", 1),
		ntfsFileNameAttr(5, "WALLET~1.DAT", 2),
		ntfsNonresDataAttr([][2]int64{{9, 1}}, 100)))
	copy(img[9*ntfsTestCluster:], []byte("BDB wallet remnants bestblock orderposnext "))
	// Deleted resident file.
	putRec(9, ntfsRecord(9, 0, 0,
		ntfsFileNameAttr(5, "small.txt", 1),
		ntfsResidentAttr(ntfsAttrData, []byte("secret-resident-bytes"))))
	// Extension record of wallet.dat holding a second data run.
	putRec(10, ntfsRecord(10, 0, 8,
		ntfsNonresDataAttr([][2]int64{{11, 1}}, 100)))
	copy(img[11*ntfsTestCluster:], []byte("wallet-tail-run "))
	// $Bitmap: clusters 0-8 allocated, rest free.
	img[8*ntfsTestCluster] = 0xFF
	img[8*ntfsTestCluster+1] = 0x01
	path := filepath.Join(t.TempDir(), "ntfs.img")
	if err := os.WriteFile(path, img, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func openTestNTFS(t *testing.T, path string) (*NTFSVol, *os.File) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	vol, err := OpenNTFS(f, 0)
	if err != nil {
		t.Fatalf("OpenNTFS: %s", err)
	}
	return vol, f
}

func TestNTFSDeletedWallet(t *testing.T) {
	vol, f := openTestNTFS(t, buildTestNTFS(t))
	entries, err := vol.Entries()
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]FSEntry{}
	for _, e := range entries {
		byName[e.Name] = e
	}
	w, ok := byName["wallet.dat"]
	if !ok {
		t.Fatalf("wallet.dat not recovered: %v", entries)
	}
	if !w.Deleted {
		t.Error("wallet.dat must be flagged deleted")
	}
	if w.Size != 100 {
		t.Errorf("wallet.dat size %d, want 100", w.Size)
	}
	if len(w.Names) != 2 {
		t.Errorf("wallet.dat names %v, want 2 aliases", w.Names)
	}
	if len(w.Extents) != 2 || w.Extents[0].Start != 9*ntfsTestCluster ||
		w.Extents[1].Start != 11*ntfsTestCluster {
		t.Errorf("wallet.dat extents %v, want clusters 9+11 (extension merged)", w.Extents)
	}
	content := make([]byte, 100)
	if _, err := f.ReadAt(content, w.Extents[0].Start); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(content, []byte("orderposnext")) {
		t.Errorf("deleted cluster content lost: %q", content)
	}
	s, ok := byName["small.txt"]
	if !ok || !s.Deleted {
		t.Fatalf("deleted resident small.txt not recovered: %v", entries)
	}
	res := make([]byte, s.Size)
	if _, err := f.ReadAt(res, s.Extents[0].Start); err != nil {
		t.Fatal(err)
	}
	if string(res) != "secret-resident-bytes" {
		t.Errorf("resident content %q", res)
	}
	n, ok := byName["notes.txt"]
	if !ok || n.Deleted {
		t.Errorf("live notes.txt missing or flagged deleted: %v", entries)
	}
}

func TestNTFSUnallocated(t *testing.T) {
	vol, _ := openTestNTFS(t, buildTestNTFS(t))
	free, err := vol.Unallocated()
	if err != nil {
		t.Fatal(err)
	}
	if len(free) != 1 {
		t.Fatalf("free ranges %v, want 1 merged range", free)
	}
	if free[0].Start != 9*ntfsTestCluster || free[0].Len != (ntfsTestClusters-9)*ntfsTestCluster {
		t.Errorf("free range %v, want clusters 9-63", free[0])
	}
}

func TestNTFSRejectsNonNTFS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "junk.img")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0xAA}, 4096), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := OpenNTFS(f, 0); err == nil {
		t.Error("garbage must not open as NTFS")
	}
}

// Deleted records with torn fixups (stale USN) must still recover: the
// parser proceeds without the fixup rather than dropping the entry.
func TestNTFSTornFixup(t *testing.T) {
	path := buildTestNTFS(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the sector-tail USN of record 9 (small.txt).
	recOff := 4*ntfsTestCluster + 9*ntfsTestRecSize
	raw[recOff+510] ^= 0xFF
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	vol, _ := openTestNTFS(t, path)
	entries, err := vol.Entries()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Name == "small.txt" && e.Deleted {
			found = true
		}
	}
	if !found {
		t.Error("torn-fixup deleted record lost")
	}
}
