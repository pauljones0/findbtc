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
