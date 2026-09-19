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

// Hand-built exFAT image: system set (bitmap), live + deleted + subdir
// files, deleted entry with NoFATChain and zeroed FAT.

const (
	exTestClusters = 200
	exTestFATOff   = 12
	exTestHeapOff  = 14
	exTestTotal    = exTestHeapOff + exTestClusters
)

func exClustOff(c int64) int64 { return exTestHeapOff*512 + (c-2)*512 }

func putExBoot(img []byte) {
	img[0] = 0xEB
	copy(img[3:], "EXFAT   ")
	binary.LittleEndian.PutUint64(img[72:], exTestTotal)
	binary.LittleEndian.PutUint32(img[80:], exTestFATOff)
	binary.LittleEndian.PutUint32(img[84:], exTestHeapOff-exTestFATOff)
	binary.LittleEndian.PutUint32(img[88:], exTestHeapOff)
	binary.LittleEndian.PutUint32(img[92:], exTestClusters)
	binary.LittleEndian.PutUint32(img[96:], 2) // root cluster
	img[108] = 9                               // 512-byte sectors
	img[109] = 0                               // 1 sector/cluster
	img[110] = 1                               // one FAT
	img[510], img[511] = 0x55, 0xAA
}

func putExFAT(img []byte, c int64, val uint32) {
	binary.LittleEndian.PutUint32(img[exTestFATOff*512+c*4:], val)
}

// putExFile writes a File+Stream+Name set at slot, returning the next
// free slot. live=false clears the InUse bits (deleted). The set
// checksum is computed so strict readers (TSK verifies it) accept
// the entries.
func putExFile(dir []byte, slot int, name string, attr byte, first, size int64, noFAT, live bool) int {
	file, stream, entry := byte(0x05), byte(0x40), byte(0x41)
	if live {
		file, stream, entry = 0x85, 0xC0, 0xC1
	}
	s := dir[slot*32 : (slot+1)*32]
	s[0], s[1] = file, 2
	binary.LittleEndian.PutUint16(s[4:], uint16(attr))
	// Plausible timestamps (2024-01-01 12:00): TSK rejects file
	// entries with all-zero stamps. The reader stays lenient.
	const stamp = 0x58216000
	binary.LittleEndian.PutUint32(s[8:], stamp)
	binary.LittleEndian.PutUint32(s[12:], stamp)
	binary.LittleEndian.PutUint32(s[16:], stamp)
	s = dir[(slot+1)*32 : (slot+2)*32]
	s[0] = stream
	if noFAT {
		s[1] = 0x02
	}
	s[3] = byte(len(name))
	binary.LittleEndian.PutUint32(s[20:], uint32(first))
	binary.LittleEndian.PutUint64(s[24:], uint64(size))
	s = dir[(slot+2)*32 : (slot+3)*32]
	s[0] = entry
	for i, r := range name {
		binary.LittleEndian.PutUint16(s[2+i*2:], uint16(r))
	}
	set := dir[slot*32 : (slot+3)*32]
	var sum uint32
	for i, b := range set {
		if i == 2 || i == 3 {
			continue
		}
		if sum&1 != 0 {
			sum = 0x80000000 + (sum >> 1)
		} else {
			sum >>= 1
		}
		sum += uint32(b)
	}
	binary.LittleEndian.PutUint16(dir[slot*32+2:], uint16(sum&0xFFFF))
	return slot + 3
}

func buildTestExFAT(t *testing.T) string {
	t.Helper()
	img := make([]byte, exTestTotal*512)
	putExBoot(img)
	const eoc = 0xFFFFFFFF
	putExFAT(img, 0, 0xFFFFFFF8)
	putExFAT(img, 1, 0xFFFFFFFF)
	for _, c := range []int64{2, 3, 6, 8, 9} {
		putExFAT(img, c, eoc)
	}
	// Bitmap at cluster 3: clusters 2,3,6,8,9 allocated.
	img[exClustOff(3)] = 0xD3
	copy(img[exClustOff(6):], "exfat live\n")
	gone := make([]byte, 512)
	copy(gone, "bestblock")
	copy(img[exClustOff(7):], gone)
	copy(img[exClustOff(9):], "deep file\n")
	// Root dir: bitmap + live + deleted + subdir.
	root := img[exClustOff(2) : exClustOff(2)+512]
	bm := root[:32]
	bm[0] = 0x81
	binary.LittleEndian.PutUint32(bm[20:], 3)
	binary.LittleEndian.PutUint64(bm[24:], 25)
	slot := 1
	// Volume Label entry: TSK's fsstat walks the first root sector
	// for a label and never advances (upstream infinite loop), so a
	// labelless fixture hangs the oracle. Real volumes have one.
	lab := root[slot*32 : (slot+1)*32]
	lab[0] = 0x83
	const exLabel = "FINDBTC"
	lab[1] = byte(len(exLabel))
	for i := 0; i < len(exLabel); i++ {
		binary.LittleEndian.PutUint16(lab[2+i*2:], uint16(exLabel[i]))
	}
	slot++
	slot = putExFile(root, slot, "live.txt", 0x20, 6, 11, true, true)
	slot = putExFile(root, slot, "gone.bin", 0x20, 7, 512, true, false)
	slot = putExFile(root, slot, "SUBD", 0x10, 8, 512, false, true)
	_ = slot
	// Subdir: one live file.
	sub := img[exClustOff(8) : exClustOff(8)+512]
	putExFile(sub, 0, "deep.txt", 0x20, 9, 10, true, true)
	path := filepath.Join(t.TempDir(), "exfat.img")
	if err := os.WriteFile(path, img, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func openExFATPath(t *testing.T, path string) *exfatVol {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	vol, err := OpenExFAT(f, 0)
	if err != nil {
		t.Fatalf("OpenExFAT: %v", err)
	}
	return vol
}

func TestExFATEntries(t *testing.T) {
	vol := openExFATPath(t, buildTestExFAT(t))
	entries, err := vol.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	byName := map[string]FSEntry{}
	for _, e := range entries {
		byName[e.Name] = e
	}
	live, ok := byName["live.txt"]
	if !ok || live.Deleted || live.Size != 11 || len(live.Extents) != 1 {
		t.Errorf("live: %+v", live)
	}
	// Deleted exFAT entries keep their names (InUse bits only).
	del, ok := byName["gone.bin"]
	if !ok || !del.Deleted || del.Size != 512 {
		t.Fatalf("deleted: %+v", del)
	}
	// NoFATChain: full contiguous recovery despite zeroed FAT.
	if len(del.Extents) != 1 || del.Extents[0].Len != 512 {
		t.Errorf("deleted extents %+v, want full 512", del.Extents)
	}
	if deep, ok := byName["deep.txt"]; !ok || deep.Deleted {
		t.Errorf("subdir file: %+v", deep)
	}
	if len(byName) != 3 {
		t.Errorf("want 3 file entries, got %v", byName)
	}
	for _, e := range byName {
		if !strings.HasPrefix(e.Note, "exfat:") {
			t.Errorf("note %q must locate the entry", e.Note)
		}
	}
}

func TestExFATUnallocated(t *testing.T) {
	vol := openExFATPath(t, buildTestExFAT(t))
	free, err := vol.Unallocated()
	if err != nil {
		t.Fatal(err)
	}
	covered := func(off int64) bool {
		for _, e := range free {
			if off >= e.Start && off < e.Start+e.Len {
				return true
			}
		}
		return false
	}
	if covered(exClustOff(6)) {
		t.Error("live cluster reported free")
	}
	if !covered(exClustOff(7)) || !covered(exClustOff(4)) || !covered(exClustOff(100)) {
		t.Error("free clusters missing from unallocated")
	}
}

func TestExFATRefusesGarbage(t *testing.T) {
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
		if _, err := OpenExFAT(bytes.NewReader(raw), 0); err == nil {
			t.Errorf("OpenExFAT accepted %s", name)
		}
	}
	img := make([]byte, exTestTotal*512)
	putExBoot(img)
	copy(img[3:], "FAT32   ")
	if _, err := OpenExFAT(bytes.NewReader(img), 0); err == nil {
		t.Error("bad magic accepted")
	} else if !strings.Contains(err.Error(), "bad magic") {
		t.Errorf("refusal must name the magic: %v", err)
	}
	putExBoot(img)
	img[108] = 7
	if _, err := OpenExFAT(bytes.NewReader(img), 0); err == nil {
		t.Error("bad sector shift accepted")
	}
}

// TestExFATOracleCrossCheck replays the fixture through real Sleuth
// Kit tools (see the FAT test for the gating rationale).
func TestExFATOracleCrossCheck(t *testing.T) {
	for _, tool := range []string{"fls", "icat", "fsstat"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("needs %s (install sleuthkit to cross-check)", tool)
		}
	}
	path := buildTestExFAT(t)
	listing := tsk(t, "fls", "-r", "-p", "-f", "exfat", path)
	t.Logf("exfat fls:\n%s", listing)
	for _, want := range []string{"live.txt", "SUBD", "deep.txt"} {
		if !strings.Contains(listing, want) {
			t.Errorf("fls lacks live %q:\n%s", want, listing)
		}
	}
	starred, delInode := false, ""
	for _, line := range strings.Split(listing, "\n") {
		if strings.Contains(line, "*") && strings.Contains(line, "gone.bin") {
			starred = true
			fields := strings.Fields(line)
			for i, f := range fields {
				if f == "*" && i+1 < len(fields) {
					delInode = strings.TrimSuffix(fields[i+1], ":")
				}
			}
		}
	}
	if !starred {
		t.Errorf("fls lacks starred deleted gone.bin:\n%s", listing)
	}
	stat := tsk(t, "fsstat", "-f", "exfat", path)
	if !strings.Contains(stat, "exFAT") && !strings.Contains(stat, "EXFAT") {
		t.Errorf("fsstat disagrees on type:\n%s", stat)
	}
	if delInode == "" {
		t.Fatal("cannot parse deleted inode from fls")
	}
	dumped := tskBytes(t, "icat", "-f", "exfat", path, delInode)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	vol, err := OpenExFAT(f, 0)
	if err != nil {
		f.Close()
		t.Fatal(err)
	}
	entries, err := vol.Entries()
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name != "gone.bin" {
			continue
		}
		var mine []byte
		for _, x := range e.Extents {
			mine = append(mine, raw[x.Start:x.Start+x.Len]...)
		}
		if !bytes.Equal(dumped, mine) {
			t.Errorf("icat (%d bytes) disagrees with reader (%d bytes)", len(dumped), len(mine))
		}
		if !bytes.Contains(mine, []byte("bestblock")) {
			t.Error("deleted bytes lack the needle")
		}
	}
}
