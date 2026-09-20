package detector

import (
	"os"
	"path/filepath"
	"testing"
)

// Raw single-target resume rewind (G42 Key Decision 2): the 1MB journal
// point sits on a block boundary, so a needle straddling it matches in
// neither the killed prefix (tail missing) nor an exact-offset resume
// (the head block never re-scans) — main.go rewinds through
// ResumeRewindOffset(0, offset) so the resumed grid still covers it.
// This mirrors the G17 range fixture in checkpoint_test.go: the journal
// is written by the real writer, the prefix is scanned with real code,
// and resume must union to the uninterrupted set.

// rawResumeFixture builds a 4 MiB file with needles placed to stress
// resume: a head hit, a duplicate-zone hit inside the rewind window,
// a needle straddling the journal point O, and tail hits.
func rawResumeFixture(t *testing.T) (string, int64) {
	t.Helper()
	const size = 4 << 20
	buf := make([]byte, size)
	place := func(off int64, s string) {
		copy(buf[off:], s)
	}
	const O = 1 << 20 // journal point: 1MB grid
	place(100, "bestblock")
	place(O-2000, "crypted_key")
	place(O-6, "orderposnext") // straddles O: head before, tail after
	place(O+100, "defaultkey")
	place(2<<20+100, "keymeta")
	place(3<<20+100, "hdseed")
	path := filepath.Join(t.TempDir(), "raw.bin")
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}
	return path, O
}

func scanRaw(t *testing.T, start int64, path string, opts Options) []Detection {
	t.Helper()
	var dets []Detection
	err := ScanWithOptions(start, path, opts,
		func(d Detection) { dets = append(dets, d) },
		func(ProgressInfo) {})
	if err != nil {
		t.Fatalf("raw scan at %d: %v", start, err)
	}
	return dets
}

// A run killed right after the journal write at O, then resumed from the
// rewound grid point exactly as main.go computes it, must union to the
// uninterrupted set — including the O straddler, which only the rewind
// can see. The resumed case log pins StartOffset to the rewound grid
// point, not the journal point.
func TestRawResumeKillAtJournalPoint(t *testing.T) {
	path, O := rawResumeFixture(t)
	full := scanRaw(t, 0, path, Options{})
	if len(full) == 0 {
		t.Fatal("fixture produced no detections")
	}
	ckpt := filepath.Join(t.TempDir(), "ckpt.json")
	writeCheckpoint(nil, ckpt, path, O, nil, testIdent(path))
	cp, err := ReadCheckpoint(ckpt)
	if err != nil {
		t.Fatal(err)
	}
	// What main.go passes ScanWithOptions on -resume.
	start := ResumeRewindOffset(0, cp.Offset)
	if start%blockSize != 0 {
		t.Fatalf("rewound start %d is not grid-aligned", start)
	}
	// Run 1 output: everything strictly before block O.
	before := scanRangeList(t, path, []FSExtent{{Start: 0, Len: O}}, Options{})
	logPath := filepath.Join(t.TempDir(), "case.jsonl")
	after := scanRaw(t, start, path, Options{CheckpointPath: ckpt, Resume: true, CaseLogPath: logPath, ToolVersion: "test"})
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
	logs := readCaseLog(t, logPath)
	if len(logs) != 1 {
		t.Fatalf("got %d case-log records, want 1", len(logs))
	}
	if logs[0].Source.StartOffset != start {
		t.Errorf("resumed start_offset %d, want rewound grid point %d (journal point %d)",
			logs[0].Source.StartOffset, start, O)
	}
}
