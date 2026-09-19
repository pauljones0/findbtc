package detector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Goal 17: checkpoint/resume for range scans. The 3-range fixture models a
// killed run exactly: the journal is written by the real writer at a real
// journal point, the "killed before block O" prefix is scanned with the
// real code, and resume must reproduce the uninterrupted detection set.

// rangeResumeFixture builds a 4 MiB file with needles placed to stress
// resume: mid-range hits, a duplicate-zone hit inside the rewind window,
// and a needle straddling the journal point O.
func rangeResumeFixture(t *testing.T) (string, []FSExtent, int64) {
	t.Helper()
	const size = 4 << 20
	buf := make([]byte, size)
	place := func(off int64, s string) {
		copy(buf[off:], s)
	}
	ranges := []FSExtent{{Start: 0, Len: 1 << 20}, {Start: 1 << 20, Len: 2 << 20}, {Start: 3 << 20, Len: 1 << 20}}
	const O = 2 << 20 // journal point: 1 MiB grid inside range 1
	place(100, "bestblock")
	place(1<<20+100, "defaultkey")
	place(O-2000, "crypted_key")
	place(O-6, "orderposnext") // straddles O: head before, tail after
	place(O+100, "keymeta")
	place(3<<20+100, "hdseed")
	path := filepath.Join(t.TempDir(), "ranges.bin")
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}
	return path, ranges, O
}

func scanRangeList(t *testing.T, path string, ranges []FSExtent, opts Options) []Detection {
	t.Helper()
	var dets []Detection
	err := ScanRangesWithOptions(path, ranges, opts,
		func(d Detection) { dets = append(dets, d) },
		func(ProgressInfo) {})
	if err != nil {
		t.Fatalf("range scan: %v", err)
	}
	return dets
}

// detSet keys detections by their JSON encoding for order-free set
// comparison (resume legitimately re-reports the rewind window).
func detSet(dets []Detection) map[string]Detection {
	out := map[string]Detection{}
	for _, d := range dets {
		raw, err := json.Marshal(d)
		if err != nil {
			panic(err)
		}
		out[string(raw)] = d
	}
	return out
}

func detListEqual(a, b []Detection) (bool, string) {
	sa, sb := detSet(a), detSet(b)
	if len(sa) != len(sb) {
		return false, "different set sizes"
	}
	for k := range sa {
		if _, ok := sb[k]; !ok {
			return false, "missing: " + k
		}
	}
	return true, ""
}

func TestRangeCheckpointJournalSchema(t *testing.T) {
	path, ranges, _ := rangeResumeFixture(t)
	ckpt := filepath.Join(t.TempDir(), "ckpt.json")
	dets := scanRangeList(t, path, ranges, Options{CheckpointPath: ckpt})
	if len(dets) == 0 {
		t.Fatal("fixture produced no detections")
	}
	cp, err := ReadCheckpoint(ckpt)
	if err != nil {
		t.Fatal(err)
	}
	if cp.Path != path {
		t.Errorf("journal path %q, want %q", cp.Path, path)
	}
	if firstRangeDiff(cp.Ranges, ranges) >= 0 {
		t.Errorf("journal ranges %+v, want %+v", cp.Ranges, ranges)
	}
	last := ranges[len(ranges)-1]
	if cp.RangeIndex != len(ranges)-1 || cp.Offset != last.Start+last.Len {
		t.Errorf("journal at (%d,%d), want completion (%d,%d)",
			cp.RangeIndex, cp.Offset, len(ranges)-1, last.Start+last.Len)
	}
}

// A run killed right after the journal write at (1, O), then resumed,
// must union to the uninterrupted set — including the O straddler, which
// only the grid-aligned rewind can see.
func TestRangeResumeKillMidRange(t *testing.T) {
	path, ranges, O := rangeResumeFixture(t)
	full := scanRangeList(t, path, ranges, Options{})
	if len(full) == 0 {
		t.Fatal("fixture produced no detections")
	}
	ckpt := filepath.Join(t.TempDir(), "ckpt.json")
	writeCheckpointRange(ckpt, path, ranges, 1, O)
	// Run 1 output: everything strictly before block O.
	prefix := []FSExtent{ranges[0], {Start: ranges[1].Start, Len: O - ranges[1].Start}}
	before := scanRangeList(t, path, prefix, Options{})
	after := scanRangeList(t, path, ranges, Options{CheckpointPath: ckpt, Resume: true})
	union := append(append([]Detection{}, before...), after...)
	if ok, why := detListEqual(union, full); !ok {
		t.Errorf("kill/resume union differs from uninterrupted run: %s", why)
	}
	straddler := false
	for _, d := range union {
		if d.Needle == "orderposnext" && d.Offset == O-6 {
			straddler = true
		}
	}
	if !straddler {
		t.Error("needle straddling the journal point was lost across kill/resume")
	}
}

// A run killed between ranges resumes at the next range with no loss.
func TestRangeResumeKillBetweenRanges(t *testing.T) {
	path, ranges, _ := rangeResumeFixture(t)
	full := scanRangeList(t, path, ranges, Options{})
	ckpt := filepath.Join(t.TempDir(), "ckpt.json")
	writeCheckpointRange(ckpt, path, ranges, 0, ranges[0].Start+ranges[0].Len)
	before := scanRangeList(t, path, ranges[:1], Options{})
	after := scanRangeList(t, path, ranges, Options{CheckpointPath: ckpt, Resume: true})
	if ok, why := detListEqual(append(before, after...), full); !ok {
		t.Errorf("between-ranges resume differs: %s", why)
	}
}

func TestRangeResumeMismatch(t *testing.T) {
	path, ranges, O := rangeResumeFixture(t)
	ckpt := filepath.Join(t.TempDir(), "ckpt.json")
	cases := map[string]func() (string, []FSExtent, string){
		"shortened range": func() (string, []FSExtent, string) {
			writeCheckpointRange(ckpt, path, ranges, 1, O)
			bad := append([]FSExtent{}, ranges...)
			bad[1].Len--
			return ckpt, bad, "does not match"
		},
		"reordered": func() (string, []FSExtent, string) {
			writeCheckpointRange(ckpt, path, ranges, 1, O)
			return ckpt, []FSExtent{ranges[1], ranges[0], ranges[2]}, "does not match"
		},
		"dropped range": func() (string, []FSExtent, string) {
			writeCheckpointRange(ckpt, path, ranges, 1, O)
			return ckpt, ranges[:2], "does not match"
		},
		"wrong path": func() (string, []FSExtent, string) {
			writeCheckpointRange(ckpt, "/other/file.bin", ranges, 1, O)
			return ckpt, ranges, "not " + path
		},
		"legacy journal": func() (string, []FSExtent, string) {
			writeCheckpoint(ckpt, path, O)
			return ckpt, ranges, "no range list"
		},
		"index out of range": func() (string, []FSExtent, string) {
			writeCheckpointRange(ckpt, path, ranges, 9, O)
			return ckpt, ranges, "beyond"
		},
		"offset outside range": func() (string, []FSExtent, string) {
			writeCheckpointRange(ckpt, path, ranges, 1, ranges[2].Start+100)
			return ckpt, ranges, "outside range"
		},
	}
	for name, setup := range cases {
		file, list, want := setup()
		err := ScanRangesWithOptions(path, list, Options{CheckpointPath: file, Resume: true},
			func(Detection) {}, func(ProgressInfo) {})
		if err == nil {
			t.Errorf("%s: resume must refuse", name)
		} else if !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error %q must mention %q", name, err, want)
		} else if !strings.Contains(err.Error(), "refus") {
			t.Errorf("%s: error %q must refuse loudly", name, err)
		}
	}
	// Corrupt JSON refuses; a missing journal starts over silently-ish.
	if err := os.WriteFile(ckpt, []byte("{nope"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := ScanRangesWithOptions(path, ranges, Options{CheckpointPath: ckpt, Resume: true},
		func(Detection) {}, func(ProgressInfo) {}); err == nil {
		t.Error("corrupt journal must refuse")
	}
	missing := filepath.Join(t.TempDir(), "absent.json")
	var dets []Detection
	if err := ScanRangesWithOptions(path, ranges, Options{CheckpointPath: missing, Resume: true},
		func(d Detection) { dets = append(dets, d) }, func(ProgressInfo) {}); err != nil {
		t.Errorf("missing journal must start over: %v", err)
	}
	if len(dets) == 0 {
		t.Error("missing-journal resume scanned nothing")
	}
}

// A completion journal resumes to an immediate, silent success.
func TestRangeResumeAlreadyComplete(t *testing.T) {
	path, ranges, _ := rangeResumeFixture(t)
	ckpt := filepath.Join(t.TempDir(), "ckpt.json")
	last := ranges[len(ranges)-1]
	writeCheckpointRange(ckpt, path, ranges, len(ranges)-1, last.Start+last.Len)
	var dets []Detection
	if err := ScanRangesWithOptions(path, ranges, Options{CheckpointPath: ckpt, Resume: true},
		func(d Detection) { dets = append(dets, d) }, func(ProgressInfo) {}); err != nil {
		t.Fatalf("completed resume must succeed: %v", err)
	}
	if len(dets) != 0 {
		t.Errorf("completed resume must scan nothing, got %v", dets)
	}
}

// Checkpointing a range scan without resuming journals and succeeds
// (the old blanket refusal is gone).
func TestRangeCheckpointFreshRun(t *testing.T) {
	path, ranges, _ := rangeResumeFixture(t)
	ckpt := filepath.Join(t.TempDir(), "ckpt.json")
	dets := scanRangeList(t, path, ranges, Options{CheckpointPath: ckpt})
	if len(dets) == 0 {
		t.Fatal("fresh checkpointed scan found nothing")
	}
	if _, err := ReadCheckpoint(ckpt); err != nil {
		t.Errorf("fresh run must leave a journal: %v", err)
	}
}

// Checkpointing across auto-seeded volumes stays refused: one journal
// holds one range list.
func TestScanFSVolumesMultiVolumeCheckpointRefused(t *testing.T) {
	disk, _ := composeDisk(t, "mbr")
	_, err := ScanFSVolumes(disk, 0, true, Options{CheckpointPath: filepath.Join(t.TempDir(), "c.json")},
		func(Detection) {}, func(ProgressInfo) {}, func(string, FSEntry) {})
	if err == nil {
		t.Fatal("multi-volume checkpoint must refuse")
	} else if !strings.Contains(err.Error(), "not supported across 2") {
		t.Errorf("refusal must name the problem: %v", err)
	}
}
