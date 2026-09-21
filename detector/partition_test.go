package detector

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// Goal 12: partition-table parsing. Synthetic MBR/GPT/EBR fixtures are
// built in-code; TestPartitionOracleCrossCheck replays real sfdisk-made
// images when FBT_PART_ORACLE_DIR points at them (see scripts/part-oracle.sh).

func putMBRSlot(img []byte, i int, typ byte, lba, count uint32) {
	e := img[446+i*16 : 446+(i+1)*16]
	e[4] = typ
	binary.LittleEndian.PutUint32(e[8:12], lba)
	binary.LittleEndian.PutUint32(e[12:16], count)
	img[510], img[511] = 0x55, 0xAA
}

type gptTestEntry struct {
	typeGUID [16]byte
	first    uint64
	last     uint64
	name     string
}

var (
	guidBasicData = [16]byte{0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7}
	guidLinuxFS   = [16]byte{0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4}
)

func putGPT(img []byte, entries []gptTestEntry) {
	putMBRSlot(img, 0, 0xEE, 1, uint32(len(img)/512-1))
	const numEntries = 8
	array := make([]byte, numEntries*128)
	for i, e := range entries {
		slot := array[i*128 : (i+1)*128]
		copy(slot[:16], e.typeGUID[:])
		slot[16] = byte(i + 1) // unique GUID stub
		binary.LittleEndian.PutUint64(slot[32:40], e.first)
		binary.LittleEndian.PutUint64(slot[40:48], e.last)
		for j, r := range e.name {
			if j >= 36 {
				break
			}
			binary.LittleEndian.PutUint16(slot[56+j*2:], uint16(r))
		}
	}
	copy(img[2*512:], array)
	hdr := img[512:1024]
	copy(hdr[:8], "EFI PART")
	binary.LittleEndian.PutUint32(hdr[8:12], 0x00010000)
	binary.LittleEndian.PutUint32(hdr[12:16], 92)
	binary.LittleEndian.PutUint64(hdr[24:32], 1)
	binary.LittleEndian.PutUint64(hdr[32:40], uint64(len(img)/512-1))
	binary.LittleEndian.PutUint64(hdr[40:48], 34)
	binary.LittleEndian.PutUint64(hdr[48:56], uint64(len(img)/512-34))
	binary.LittleEndian.PutUint64(hdr[72:80], 2)
	binary.LittleEndian.PutUint32(hdr[80:84], numEntries)
	binary.LittleEndian.PutUint32(hdr[84:88], 128)
	binary.LittleEndian.PutUint32(hdr[88:92], crc32.ChecksumIEEE(array))
	binary.LittleEndian.PutUint32(hdr[16:20], crc32.ChecksumIEEE(hdr[:92]))
}

func TestScanPartitionsMBR(t *testing.T) {
	img := make([]byte, 4*1024*1024)
	putMBRSlot(img, 0, 0x07, 2048, 2048)
	putMBRSlot(img, 1, 0x83, 4096, 2048)
	putMBRSlot(img, 2, 0xDA, 6144, 1024)
	parts, err := ScanPartitions(bytes.NewReader(img))
	if err != nil {
		t.Fatal(err)
	}
	want := []Partition{
		{Scheme: "mbr", Index: 1, Start: 2048 * 512, Size: 2048 * 512, Type: "ntfs"},
		{Scheme: "mbr", Index: 2, Start: 4096 * 512, Size: 2048 * 512, Type: "linux"},
		{Scheme: "mbr", Index: 3, Start: 6144 * 512, Size: 1024 * 512, Type: "mbr-type-da"},
	}
	if !reflect.DeepEqual(parts, want) {
		t.Errorf("got %+v, want %+v", parts, want)
	}
}

func TestScanPartitionsGPT(t *testing.T) {
	img := make([]byte, 5*1024*1024)
	putGPT(img, []gptTestEntry{
		{guidBasicData, 2048, 4095, "ntfs-vol"},
		{guidLinuxFS, 4096, 6143, "ext-vol"},
		{guidBasicData, 6144, 8191, "raw"},
	})
	parts, err := ScanPartitions(bytes.NewReader(img))
	if err != nil {
		t.Fatal(err)
	}
	want := []Partition{
		{Scheme: "gpt", Index: 1, Start: 2048 * 512, Size: 2048 * 512, Type: "basic-data", Name: "ntfs-vol"},
		{Scheme: "gpt", Index: 2, Start: 4096 * 512, Size: 2048 * 512, Type: "linux-filesystem", Name: "ext-vol"},
		{Scheme: "gpt", Index: 3, Start: 6144 * 512, Size: 2048 * 512, Type: "basic-data", Name: "raw"},
	}
	if !reflect.DeepEqual(parts, want) {
		t.Errorf("got %+v, want %+v", parts, want)
	}
}

func TestScanPartitionsEBR(t *testing.T) {
	img := make([]byte, 256*1024)
	putMBRSlot(img, 0, 0x83, 64, 32)
	putMBRSlot(img, 1, 0x0F, 256, 512)
	ebr1 := img[256*512 : 257*512]
	ebr1[446+4] = 0x83
	binary.LittleEndian.PutUint32(ebr1[446+8:], 32) // +EBR base
	binary.LittleEndian.PutUint32(ebr1[446+12:], 32)
	ebr1[462+4] = 0x0F
	binary.LittleEndian.PutUint32(ebr1[462+8:], 128) // +ext base
	binary.LittleEndian.PutUint32(ebr1[462+12:], 128)
	ebr1[510], ebr1[511] = 0x55, 0xAA
	ebr2 := img[384*512 : 385*512]
	ebr2[446+4] = 0x07
	binary.LittleEndian.PutUint32(ebr2[446+8:], 32)
	binary.LittleEndian.PutUint32(ebr2[446+12:], 32)
	ebr2[510], ebr2[511] = 0x55, 0xAA
	parts, err := ScanPartitions(bytes.NewReader(img))
	if err != nil {
		t.Fatal(err)
	}
	want := []Partition{
		{Scheme: "mbr", Index: 1, Start: 64 * 512, Size: 32 * 512, Type: "linux"},
		{Scheme: "mbr", Index: 2, Start: 288 * 512, Size: 32 * 512, Type: "linux"},
		{Scheme: "mbr", Index: 3, Start: 416 * 512, Size: 32 * 512, Type: "ntfs"},
	}
	if !reflect.DeepEqual(parts, want) {
		t.Errorf("got %+v, want %+v", parts, want)
	}
}

func TestScanPartitionsHybrid(t *testing.T) {
	img := make([]byte, 5*1024*1024)
	putMBRSlot(img, 0, 0x83, 2048, 2048)
	putGPT(img, []gptTestEntry{{guidLinuxFS, 2048, 4095, "x"}})
	// putGPT overwrote slot 0 with protective; restore a real entry.
	putMBRSlot(img, 1, 0x83, 4096, 2048)
	if _, err := ScanPartitions(bytes.NewReader(img)); err == nil || !strings.Contains(err.Error(), "hybrid") {
		t.Errorf("protective+real entries must error hybrid, got %v", err)
	}
	img2 := make([]byte, 5*1024*1024)
	putMBRSlot(img2, 0, 0x83, 2048, 2048)
	lba1 := img2[512:1024]
	copy(lba1[:8], "EFI PART")
	if _, err := ScanPartitions(bytes.NewReader(img2)); err == nil || !strings.Contains(err.Error(), "hybrid") {
		t.Errorf("MBR entries+GPT magic must error hybrid, got %v", err)
	}
}

func TestScanPartitionsCorrupt(t *testing.T) {
	cases := map[string]func() []byte{
		"no signature": func() []byte { return make([]byte, 1024) },
		"empty table": func() []byte {
			img := make([]byte, 1024)
			img[510], img[511] = 0x55, 0xAA
			return img
		},
		"protective without GPT": func() []byte {
			img := make([]byte, 2048)
			putMBRSlot(img, 0, 0xEE, 1, 3)
			return img
		},
		"GPT header CRC": func() []byte {
			img := make([]byte, 5*1024*1024)
			putGPT(img, []gptTestEntry{{guidLinuxFS, 2048, 4095, "x"}})
			img[512+40] ^= 0xFF
			return img
		},
		"GPT array CRC": func() []byte {
			img := make([]byte, 5*1024*1024)
			putGPT(img, []gptTestEntry{{guidLinuxFS, 2048, 4095, "x"}})
			img[2*512+40] ^= 0xFF
			return img
		},
		"EBR loop": func() []byte {
			img := make([]byte, 512*1024)
			putMBRSlot(img, 0, 0x0F, 256, 512)
			ebr := img[256*512 : 257*512]
			ebr[446+4] = 0x83
			binary.LittleEndian.PutUint32(ebr[446+8:], 32)
			binary.LittleEndian.PutUint32(ebr[446+12:], 32)
			ebr[462+4] = 0x0F
			binary.LittleEndian.PutUint32(ebr[462+8:], 0) // links to itself
			binary.LittleEndian.PutUint32(ebr[462+12:], 128)
			ebr[510], ebr[511] = 0x55, 0xAA
			return img
		},
	}
	for name, build := range cases {
		if _, err := ScanPartitions(bytes.NewReader(build())); err == nil {
			t.Errorf("%s: must error, got nil", name)
		} else {
			t.Logf("%s: %v", name, err)
		}
	}
}

// composeDisk builds the Goal 12 fixture: a partitioned disk with the
// synthetic NTFS volume at 1MiB, the synthetic ext volume at 2MiB, and a
// raw (unformattable) partition at 3MiB. It returns the path and the
// expected partition starts.
func composeDisk(t *testing.T, scheme string) (string, []int64) {
	t.Helper()
	ntfsImg, err := os.ReadFile(buildTestNTFS(t))
	if err != nil {
		t.Fatal(err)
	}
	extImg, err := os.ReadFile(buildTestExt(t))
	if err != nil {
		t.Fatal(err)
	}
	const mb = 1024 * 1024
	disk := make([]byte, 5*mb)
	copy(disk[mb:], ntfsImg)
	copy(disk[2*mb:], extImg)
	copy(disk[3*mb:], "RAW-NON-FILESYSTEM-DATA ")
	starts := []int64{mb, 2 * mb, 3 * mb}
	switch scheme {
	case "mbr":
		putMBRSlot(disk, 0, 0x07, 2048, 2048)
		putMBRSlot(disk, 1, 0x83, 4096, 2048)
		putMBRSlot(disk, 2, 0xDA, 6144, 2048)
	case "gpt":
		putGPT(disk, []gptTestEntry{
			{guidBasicData, 2048, 4095, "ntfs-vol"},
			{guidLinuxFS, 4096, 6143, "ext-vol"},
			{guidBasicData, 6144, 8191, "raw"},
		})
	default:
		t.Fatalf("unknown scheme %q", scheme)
	}
	path := filepath.Join(t.TempDir(), scheme+".img")
	if err := os.WriteFile(path, disk, 0644); err != nil {
		t.Fatal(err)
	}
	return path, starts
}

func scanAll(t *testing.T, path string, base int64, auto bool) ([]string, []Detection) {
	t.Helper()
	var dets []Detection
	kinds, err := ScanFSVolumes(path, base, auto, Options{},
		func(d Detection) { dets = append(dets, d) },
		func(ProgressInfo) {}, func(string, FSEntry) {})
	if err != nil {
		t.Fatalf("scan auto=%v base=%d: %v", auto, base, err)
	}
	return kinds, dets
}

func TestScanFSVolumesAutoSeed(t *testing.T) {
	for _, scheme := range []string{"mbr", "gpt"} {
		path, starts := composeDisk(t, scheme)
		kinds, auto := scanAll(t, path, 0, true)
		if !reflect.DeepEqual(kinds, []string{"ntfs", "ext"}) {
			t.Errorf("%s: kinds %v, want [ntfs ext]", scheme, kinds)
		}
		if len(auto) == 0 {
			t.Fatalf("%s: auto-seed found no detections", scheme)
		}
		for _, d := range auto {
			if d.FileName == "" {
				t.Errorf("%s: detection without filename: %+v", scheme, d)
			}
		}
		// Auto-seed must equal the manual per-volume scans concatenated.
		var manual []Detection
		for _, base := range starts[:2] {
			_, dets := scanAll(t, path, base, false)
			manual = append(manual, dets...)
		}
		if !reflect.DeepEqual(auto, manual) {
			t.Errorf("%s: auto-seed differs from manual scans:\nauto=%v\nmanual=%v", scheme, auto, manual)
		}
		// Manual -fs-offset still works on each volume.
		if kind, err := ScanFS(path, starts[0], Options{}, func(Detection) {}, func(ProgressInfo) {}, nil); err != nil || kind != "ntfs" {
			t.Errorf("%s: manual ntfs offset: kind=%q err=%v", scheme, kind, err)
		}
		if kind, err := ScanFS(path, starts[1], Options{}, func(Detection) {}, func(ProgressInfo) {}, nil); err != nil || kind != "ext" {
			t.Errorf("%s: manual ext offset: kind=%q err=%v", scheme, kind, err)
		}
	}
}

// composeFATDisk builds the Goal 25 fixture: a partitioned disk with
// the synthetic FAT32 volume at 1MiB and the synthetic exFAT volume at
// 34MiB (past the 32.5MiB FAT32 image).
func composeFATDisk(t *testing.T, scheme string) (string, []int64) {
	t.Helper()
	fatImg, err := os.ReadFile(buildTestFAT32(t))
	if err != nil {
		t.Fatal(err)
	}
	exImg, err := os.ReadFile(buildTestExFAT(t))
	if err != nil {
		t.Fatal(err)
	}
	const mb = 1024 * 1024
	disk := make([]byte, 36*mb)
	copy(disk[mb:], fatImg)
	copy(disk[34*mb:], exImg)
	starts := []int64{mb, 34 * mb}
	fatSecs := uint32(len(fatImg) / 512)
	switch scheme {
	case "mbr":
		putMBRSlot(disk, 0, 0x0C, 2048, fatSecs)
		putMBRSlot(disk, 1, 0x07, uint32(34*mb/512), uint32(len(exImg)/512))
	case "gpt":
		putGPT(disk, []gptTestEntry{
			{guidBasicData, 2048, uint64(2048 + fatSecs - 1), "fat-vol"},
			{guidBasicData, 34 * mb / 512, 34*mb/512 + uint64(len(exImg)/512) - 1, "exfat-vol"},
		})
	default:
		t.Fatalf("unknown scheme %q", scheme)
	}
	path := filepath.Join(t.TempDir(), scheme+"-fat.img")
	if err := os.WriteFile(path, disk, 0644); err != nil {
		t.Fatal(err)
	}
	return path, starts
}

// composeMixedDisk builds the Goal 45 fixture: a partitioned disk with
// the synthetic FAT32 volume at 1MiB and the synthetic ext volume at
// 34MiB (past the 32.5MiB FAT32 image). Both volumes hold deleted
// wallet markers, so a kill lands mid-list only past volume 1.
func composeMixedDisk(t *testing.T, scheme string) (string, []int64) {
	t.Helper()
	fatImg, err := os.ReadFile(buildTestFAT32(t))
	if err != nil {
		t.Fatal(err)
	}
	extImg, err := os.ReadFile(buildTestExt(t))
	if err != nil {
		t.Fatal(err)
	}
	const mb = 1024 * 1024
	disk := make([]byte, 36*mb)
	copy(disk[mb:], fatImg)
	copy(disk[34*mb:], extImg)
	starts := []int64{mb, 34 * mb}
	fatSecs := uint32(len(fatImg) / 512)
	extSecs := uint32(len(extImg) / 512)
	switch scheme {
	case "mbr":
		putMBRSlot(disk, 0, 0x0C, 2048, fatSecs)
		putMBRSlot(disk, 1, 0x83, uint32(34*mb/512), extSecs)
	case "gpt":
		putGPT(disk, []gptTestEntry{
			{guidBasicData, 2048, uint64(2048 + fatSecs - 1), "fat-vol"},
			{guidLinuxFS, 34 * mb / 512, 34*mb/512 + uint64(extSecs) - 1, "ext-vol"},
		})
	default:
		t.Fatalf("unknown scheme %q", scheme)
	}
	path := filepath.Join(t.TempDir(), scheme+"-mixed.img")
	if err := os.WriteFile(path, disk, 0644); err != nil {
		t.Fatal(err)
	}
	return path, starts
}

// Auto-seed must find FAT + exFAT partitions by content (MBR type 0x07
// covers both NTFS and exFAT, so probing — not the type byte — decides).
func TestScanFSVolumesAutoSeedFAT(t *testing.T) {
	for _, scheme := range []string{"mbr", "gpt"} {
		path, starts := composeFATDisk(t, scheme)
		kinds, auto := scanAll(t, path, 0, true)
		if !reflect.DeepEqual(kinds, []string{"fat", "exfat"}) {
			t.Errorf("%s: kinds %v, want [fat exfat]", scheme, kinds)
		}
		if len(auto) == 0 {
			t.Fatalf("%s: auto-seed found no detections", scheme)
		}
		for _, d := range auto {
			if d.FileName == "" {
				t.Errorf("%s: detection without filename: %+v", scheme, d)
			}
		}
		var manual []Detection
		for _, base := range starts {
			_, dets := scanAll(t, path, base, false)
			manual = append(manual, dets...)
		}
		if !reflect.DeepEqual(auto, manual) {
			t.Errorf("%s: auto-seed differs from manual scans:\nauto=%v\nmanual=%v", scheme, auto, manual)
		}
	}
}

func TestResolveVolumesLoudErrors(t *testing.T) {
	blank := filepath.Join(t.TempDir(), "blank.img")
	if err := os.WriteFile(blank, make([]byte, 4096), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveVolumes(blank, 0, true); err == nil {
		t.Error("blank image with auto-seed must error")
	} else if !strings.Contains(err.Error(), blank) || !strings.Contains(err.Error(), "no usable partition table") {
		t.Errorf("blank-image error must name the path and table failure: %v", err)
	}
	rawOnly := make([]byte, 2*1024*1024)
	putMBRSlot(rawOnly, 0, 0xDA, 2048, 2048)
	rawPath := filepath.Join(t.TempDir(), "raw.img")
	if err := os.WriteFile(rawPath, rawOnly, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveVolumes(rawPath, 0, true); err == nil {
		t.Error("raw-only table with auto-seed must error")
	} else if !strings.Contains(err.Error(), "none opens as NTFS/ext/FAT/exFAT") || !strings.Contains(err.Error(), "mbr-type-da") {
		t.Errorf("raw-only error must list the layout tried: %v", err)
	}
	disk, _ := composeDisk(t, "mbr")
	if _, err := resolveVolumes(disk, 0, false); err == nil {
		t.Error("manual mode on a partitioned disk must keep erroring at offset 0")
	} else if !strings.Contains(err.Error(), "offset 0") {
		t.Errorf("manual error must cite offset 0: %v", err)
	}
}

// TestPartitionOracleCrossCheck replays real sfdisk-made images: for each
// <name>.img plus <name>.sfdisk (an `sfdisk -d` dump) in
// FBT_PART_ORACLE_DIR, every parsed partition must match the tool's
// start/size set exactly. Skipped when the dir is unset (CI has no
// fixtures); regenerate with scripts/part-oracle.sh.
func TestPartitionOracleCrossCheck(t *testing.T) {
	dir := os.Getenv("FBT_PART_ORACLE_DIR")
	if dir == "" {
		t.Skip("FBT_PART_ORACLE_DIR unset; run scripts/part-oracle.sh to cross-check")
	}
	imgs, err := filepath.Glob(filepath.Join(dir, "*.img"))
	if err != nil || len(imgs) == 0 {
		t.Fatalf("no oracle images in %s", dir)
	}
	for _, img := range imgs {
		base := strings.TrimSuffix(img, ".img")
		dump, err := os.ReadFile(base + ".sfdisk")
		if err != nil {
			t.Fatalf("missing %s.sfdisk: regenerate with scripts/part-oracle.sh", base)
		}
		want := map[int64]int64{}
		for _, line := range strings.Split(string(dump), "\n") {
			if !strings.Contains(line, "start=") {
				continue
			}
			fields := map[string]string{}
			if i := strings.Index(line, " : "); i >= 0 {
				line = line[i+3:]
			}
			for _, tok := range strings.Split(line, ",") {
				kv := strings.SplitN(strings.TrimSpace(tok), "=", 2)
				if len(kv) == 2 {
					fields[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
				}
			}
			// Skip DOS extended containers: the parser reports the
			// primaries and logicals they hold, not the container.
			if typ := fields["type"]; typ == "5" || typ == "f" || typ == "85" {
				continue
			}
			start, serr := strconv.ParseInt(fields["start"], 10, 64)
			size, zerr := strconv.ParseInt(fields["size"], 10, 64)
			if serr != nil || zerr != nil {
				t.Fatalf("%s: unparsable sfdisk line %q", base, line)
			}
			want[start*512] = size * 512
		}
		f, err := os.Open(img)
		if err != nil {
			t.Fatal(err)
		}
		parts, err := ScanPartitions(f)
		f.Close()
		if err != nil {
			t.Fatalf("%s: %v", img, err)
		}
		got := map[int64]int64{}
		for _, p := range parts {
			got[p.Start] = p.Size
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s:\n got %+v\nwant %+v", img, got, want)
		} else {
			t.Logf("%s: %d partitions match sfdisk", img, len(got))
		}
	}
}
