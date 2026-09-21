package detector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ScanFS over the synthetic NTFS image recovers the deleted wallet by
// name and stamps its content hits.
func TestScanFSNTFS(t *testing.T) {
	path := buildTestNTFS(t)
	var inventory []FSEntry
	var dets []Detection
	kind, err := ScanFS(path, 0, Options{}, func(d Detection) {
		dets = append(dets, d)
	}, func(ProgressInfo) {}, func(_ string, e FSEntry) {
		inventory = append(inventory, e)
	})
	if err != nil {
		t.Fatal(err)
	}
	if kind != "ntfs" {
		t.Errorf("kind %q, want ntfs", kind)
	}
	foundName := false
	for _, e := range inventory {
		if e.Name == "wallet.dat" && e.Deleted {
			foundName = true
		}
	}
	if !foundName {
		t.Error("deleted wallet.dat missing from inventory")
	}
	var named []Detection
	for _, d := range dets {
		if d.FileName == "wallet.dat" {
			named = append(named, d)
		}
	}
	if len(named) != 2 {
		t.Fatalf("wallet.dat hits %v, want bestblock+orderposnext", dets)
	}
	for _, d := range named {
		if d.Offset < 9*ntfsTestCluster || d.Offset >= 10*ntfsTestCluster {
			t.Errorf("hit at %d, want cluster 9", d.Offset)
		}
	}
}

// ScanFS over the synthetic ext image: orphan content is stamped with its
// inode note, associated names with the filename.
func TestScanFSExt(t *testing.T) {
	path := buildTestExt(t)
	var inventory []FSEntry
	var dets []Detection
	kind, err := ScanFS(path, 0, Options{}, func(d Detection) {
		dets = append(dets, d)
	}, func(ProgressInfo) {}, func(_ string, e FSEntry) {
		inventory = append(inventory, e)
	})
	if err != nil {
		t.Fatal(err)
	}
	if kind != "ext" {
		t.Errorf("kind %q, want ext", kind)
	}
	byFile := map[string][]Detection{}
	for _, d := range dets {
		byFile[d.FileName] = append(byFile[d.FileName], d)
	}
	if len(byFile["inode:13"]) != 2 {
		t.Errorf("inode:13 hits %v, want 2", dets)
	}
	if len(byFile["inode:14"]) != 1 {
		t.Errorf("inode:14 hits %v, want 1", dets)
	}
	if len(byFile["wallet2.dat"]) != 1 {
		t.Errorf("wallet2.dat hits %v, want 1", dets)
	}
	foundResidual := false
	for _, e := range inventory {
		if e.Name == "wallet.dat" && e.Deleted && len(e.Extents) == 0 {
			foundResidual = true
		}
	}
	if !foundResidual {
		t.Error("residual wallet.dat name missing from inventory")
	}
}

// ScanFS over the synthetic FAT32 image: the deleted entry's surviving
// prefix scans and its hits carry the recovered long name.
func TestScanFSFAT(t *testing.T) {
	path := buildTestFAT32(t)
	var inventory []FSEntry
	var dets []Detection
	kind, err := ScanFS(path, 0, Options{}, func(d Detection) {
		dets = append(dets, d)
	}, func(ProgressInfo) {}, func(_ string, e FSEntry) {
		inventory = append(inventory, e)
	})
	if err != nil {
		t.Fatal(err)
	}
	if kind != "fat" {
		t.Errorf("kind %q, want fat", kind)
	}
	foundLive, foundDel := false, false
	for _, e := range inventory {
		if e.Name == "LIVE.TXT" && !e.Deleted {
			foundLive = true
		}
		if e.Name == "deleted wallet backup.dat" && e.Deleted {
			foundDel = true
		}
	}
	if !foundLive || !foundDel {
		t.Errorf("inventory lacks live+deleted: %v", inventory)
	}
	var named []Detection
	for _, d := range dets {
		if d.FileName == "deleted wallet backup.dat" {
			named = append(named, d)
		}
	}
	if len(named) != 1 {
		t.Fatalf("deleted wallet backup.dat hits %v, want 1 bestblock", dets)
	}
}

// ScanFS over the synthetic exFAT image: the NoFATChain deleted file
// recovers whole and its hits carry the surviving name.
func TestScanFSExFAT(t *testing.T) {
	path := buildTestExFAT(t)
	var inventory []FSEntry
	var dets []Detection
	kind, err := ScanFS(path, 0, Options{}, func(d Detection) {
		dets = append(dets, d)
	}, func(ProgressInfo) {}, func(_ string, e FSEntry) {
		inventory = append(inventory, e)
	})
	if err != nil {
		t.Fatal(err)
	}
	if kind != "exfat" {
		t.Errorf("kind %q, want exfat", kind)
	}
	foundLive, foundDel := false, false
	for _, e := range inventory {
		if e.Name == "live.txt" && !e.Deleted {
			foundLive = true
		}
		if e.Name == "gone.bin" && e.Deleted {
			foundDel = true
		}
	}
	if !foundLive || !foundDel {
		t.Errorf("inventory lacks live+deleted: %v", inventory)
	}
	var named []Detection
	for _, d := range dets {
		if d.FileName == "gone.bin" {
			named = append(named, d)
		}
	}
	if len(named) != 1 {
		t.Fatalf("gone.bin hits %v, want 1 bestblock", dets)
	}
}

// Unallocated-only scanning finds traces in free space and skips identical
// traces in allocated blocks.
func TestScanRangesSkipsLive(t *testing.T) {
	path := buildTestExt(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Plant a decoy needle in allocated block 6 (live hello.txt data).
	copy(raw[6*extTestBlock:], "bestblock-live-decoy, ignore me")
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	_, free, err := UnallocatedRanges(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	var dets []Detection
	if err := ScanRangesWithOptions(path, free, Options{}, func(d Detection) {
		dets = append(dets, d)
	}, func(ProgressInfo) {}); err != nil {
		t.Fatal(err)
	}
	if len(dets) == 0 {
		t.Fatal("unallocated scan found nothing")
	}
	for _, d := range dets {
		if d.Offset >= 6*extTestBlock && d.Offset < 7*extTestBlock {
			t.Errorf("allocated decoy reported at %d", d.Offset)
		}
		if d.FileName != "" {
			t.Errorf("range scan stamped filename %q", d.FileName)
		}
	}
}

// A checkpointed -fs run over one volume journals the flattened deleted-
// entry list, and resuming from the completion journal scans nothing.
func TestScanFSVolumesSingleVolumeCheckpointRoundTrip(t *testing.T) {
	path := buildTestExt(t)
	ckpt := filepath.Join(t.TempDir(), "cp.json")
	collect := func(opts Options) []Detection {
		var dets []Detection
		if _, err := ScanFSVolumes(path, 0, false, opts,
			func(d Detection) { dets = append(dets, d) },
			func(ProgressInfo) {}, func(string, FSEntry) {}); err != nil {
			t.Fatalf("fs scan: %v", err)
		}
		return dets
	}
	if dets := collect(Options{CheckpointPath: ckpt}); len(dets) == 0 {
		t.Fatal("checkpointed fs scan found nothing")
	}
	if _, err := ReadCheckpoint(ckpt); err != nil {
		t.Fatalf("fs run must leave a journal: %v", err)
	}
	if dets := collect(Options{CheckpointPath: ckpt, Resume: true}); len(dets) != 0 {
		t.Errorf("resuming a completed fs journal must scan nothing, got %v", dets)
	}
}

// A multi-volume run with no deleted ranges anywhere journals nothing:
// flattening an empty list is not a journalable run.
func TestScanFSVolumesMultiVolumeNoRangesNoJournal(t *testing.T) {
	disk, starts := composeMixedDisk(t, "mbr")
	raw, err := os.ReadFile(disk)
	if err != nil {
		t.Fatal(err)
	}
	// Relink ext's deleted inodes (volume 2): live entries inventory
	// but never scan.
	for _, num := range []int64{13, 14, 15, 16} {
		at := starts[1] + 4*extTestBlock + (num-1)*128 + 26
		raw[at], raw[at+1] = 1, 0
	}
	// End the FAT32 root walk at the first deleted slot (volume 1).
	g := fat32Geometry()
	root := starts[0] + g.clustOff(2)
	for slot := int64(0); ; slot++ {
		s := raw[root+slot*32 : root+(slot+1)*32]
		if s[0] == 0x00 {
			break
		}
		if s[0] == 0xE5 {
			s[0] = 0x00
			break
		}
	}
	if err := os.WriteFile(disk, raw, 0644); err != nil {
		t.Fatal(err)
	}
	ckpt := filepath.Join(t.TempDir(), "c.json")
	kinds, err := ScanFSVolumes(disk, 0, true, Options{CheckpointPath: ckpt},
		func(d Detection) { t.Errorf("range-less run detected %+v", d) },
		func(ProgressInfo) {}, func(string, FSEntry) {})
	if err != nil {
		t.Fatal(err)
	}
	if len(kinds) != 2 {
		t.Fatalf("kinds %v, want both volumes inventoried", kinds)
	}
	if _, err := os.Stat(ckpt); !os.IsNotExist(err) {
		t.Errorf("range-less multi-volume run journaled: stat err %v", err)
	}
}

// The range index owns the stamp, not offset containment: a needle
// inside two overlapping ranges attributes to the range being
// scanned. (Unreachable via FS parsers — extents are
// volume-confined — but the flattened list must stay exact if that
// ever changes.) Wired exactly like ScanFSVolumes wires it.
func TestScanFSVolumesOverlapStampsByIndex(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overlap.bin")
	buf := make([]byte, 4096)
	copy(buf[160:], "bestblock")
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}
	ranges := []FSExtent{{Start: 100, Len: 100}, {Start: 150, Len: 100}}
	ro := &rangeOwner{ranges: ranges, owners: []string{"vol1file", "vol2file"}, cur: -1}
	var fired []int
	inner := ro.onRange
	opts := Options{onRange: func(i int) {
		fired = append(fired, i)
		inner(i)
	}}
	var dets []Detection
	if err := ScanRangesWithOptions(path, ranges, opts, func(d Detection) {
		d.FileName = ro.ownerOf(d.Offset)
		dets = append(dets, d)
	}, func(ProgressInfo) {}); err != nil {
		t.Fatal(err)
	}
	if len(fired) != 2 || fired[0] != 0 || fired[1] != 1 {
		t.Fatalf("onRange fired %v, want [0 1]", fired)
	}
	if len(dets) != 2 {
		t.Fatalf("%d detections, want the overlap needle twice: %v", len(dets), dets)
	}
	if dets[0].FileName != "vol1file" || dets[1].FileName != "vol2file" {
		t.Errorf("owners %q,%q, want vol1file then vol2file: %+v",
			dets[0].FileName, dets[1].FileName, dets)
	}
}

// rangeOwner unit contract: the started index wins over containment;
// with no range started the offset search is the fallback.
func TestRangeOwnerIndexWins(t *testing.T) {
	ranges := []FSExtent{{Start: 100, Len: 100}, {Start: 150, Len: 100}}
	ro := &rangeOwner{ranges: ranges, owners: []string{"a", "b"}, cur: -1}
	if got := ro.ownerOf(160); got != "a" {
		t.Errorf("fallback ownerOf(160) = %q, want a", got)
	}
	ro.onRange(1)
	if got := ro.ownerOf(160); got != "b" {
		t.Errorf("indexed ownerOf(160) = %q, want b", got)
	}
	if got := ro.ownerOf(9999); got != "b" {
		t.Errorf("indexed ownerOf(outside) = %q, want b", got)
	}
}

// Case-log records stay per scanned range in flattened volume order —
// exactly what the sequential per-volume runs wrote — and verify
// agrees with every record.
func TestScanFSVolumesMultiVolumeCaseLog(t *testing.T) {
	disk, _ := composeDisk(t, "mbr")
	targets, err := resolveVolumes(disk, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	_, ranges, _, err := flattenDeletedRanges(disk, targets, nil)
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "case.jsonl")
	if _, err := ScanFSVolumes(disk, 0, true,
		Options{CaseLogPath: logPath, ToolVersion: "test"},
		func(Detection) {}, func(ProgressInfo) {}, func(string, FSEntry) {}); err != nil {
		t.Fatal(err)
	}
	recs := readCaseLog(t, logPath)
	if len(recs) != len(ranges) {
		t.Fatalf("%d case-log records, want one per range (%d)", len(recs), len(ranges))
	}
	for i, r := range recs {
		if r.Status != "complete" {
			t.Errorf("record %d status %q, want complete", i, r.Status)
		}
		if r.Source.Kind != "range" {
			t.Errorf("record %d kind %q, want range", i, r.Source.Kind)
		}
		if r.Source.StartOffset != ranges[i].Start || r.Source.Size != ranges[i].Start+ranges[i].Len {
			t.Errorf("record %d covers [%d,%d), want range %+v",
				i, r.Source.StartOffset, r.Source.Size, ranges[i])
		}
	}
	var out strings.Builder
	if err := VerifyCaseLog(logPath, &out); err != nil {
		t.Errorf("verify: %v\n%s", err, out.String())
	}
}

func TestReportShowsFileName(t *testing.T) {
	d := Detection{Description: "x", Needle: "bestblock", Offset: 9, Target: "img",
		BlockOffset: 0, MatchLen: 9, FileName: "wallet.dat"}
	rep := Summarize([]Detection{d})
	if len(rep.Hits) != 1 || rep.Hits[0].FileName != "wallet.dat" {
		t.Fatalf("report lost filename: %+v", rep.Hits)
	}
	if !strings.Contains(rep.Text(), "file=wallet.dat") {
		t.Errorf("report text lacks filename:\n%s", rep.Text())
	}
}
