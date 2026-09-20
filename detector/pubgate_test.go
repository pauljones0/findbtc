package detector

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The gate admits up to the cap, refuses beyond it (counting
// skips), and releases on consume. Refusals warn once per run.
func TestPubGateCap(t *testing.T) {
	var log bytes.Buffer
	g := newPubGate(&log)
	for i := int64(0); i < maxOutstandingPubs; i++ {
		if !g.tryPublish() {
			t.Fatalf("refused admission %d below the cap", i)
		}
	}
	if g.tryPublish() {
		t.Fatal("admitted past the cap")
	}
	if g.skippedCount() != 1 {
		t.Fatalf("skipped %d, want 1", g.skippedCount())
	}
	if !strings.Contains(log.String(), "publication backlog") {
		t.Errorf("no warn-once, log: %q", log.String())
	}
	for i := int64(0); i < maxOutstandingPubs; i++ {
		g.consumed()
	}
	if !g.tryPublish() {
		t.Fatal("refused after the backlog drained")
	}
	var nilGate *pubGate
	if !nilGate.tryPublish() {
		t.Error("nil gate must admit (legacy blocking send)")
	}
	nilGate.consumed()
	nilGate.forcePublish()
	if nilGate.skippedCount() != 0 {
		t.Error("nil gate must count nothing")
	}
}

// Tripping the gate end to end: a zip with more members than the
// (lowered) cap drains what it admitted and then reports
// incomplete coverage instead of hanging or certifying clean
// completion. The old nil-error expectation encoded the
// false-completion bug (frozen receipt: 3/10 detections, nil
// error, case-log complete); dropped nested work must surface
// as an error so batch marks the target failed and resume
// retries it instead of skipping it forever.
func TestPubGateTripsEndToEnd(t *testing.T) {
	old := maxOutstandingPubs
	maxOutstandingPubs = 3
	defer func() { maxOutstandingPubs = old }()

	var zb bytes.Buffer
	w := zip.NewWriter(&zb)
	for i := 0; i < 10; i++ {
		fw, err := w.Create("m.dat")
		if err != nil {
			t.Fatal(err)
		}
		// Same name, distinct bytes: archive/zip allows duplicate
		// names, and each member publishes independently.
		if _, err := fw.Write([]byte("bestblock")); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "many.zip")
	if err := os.WriteFile(path, zb.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	var dets int
	err := ScanWithOptions(0, path, Options{Log: &log},
		func(Detection) { dets++ }, func(ProgressInfo) {})
	if err == nil || !strings.Contains(err.Error(), "incomplete coverage") {
		t.Fatalf("gated scan error = %v, want incomplete-coverage error\n%s", err, log.String())
	}
	if !strings.Contains(log.String(), "publication cap") {
		t.Errorf("no gate warning, log:\n%s", log.String())
	}
	if !strings.Contains(log.String(), "coverage is incomplete") {
		t.Errorf("no incompleteness warning, log:\n%s", log.String())
	}
	// No exact count: the admitted-vs-skipped split depends on
	// pipeline timing, so only the congested bound is stable.
	if dets >= 10 {
		t.Errorf("gated scan detections = %d, want fewer than the 10 members (congestion must drop work)", dets)
	}
}

// Cap zero admits nothing: tryPublish refuses before any send,
// so the congested outcome is fully deterministic — zero
// detections plus the incomplete-coverage error.
func TestPubGateCapZeroAdmitsNothing(t *testing.T) {
	old := maxOutstandingPubs
	maxOutstandingPubs = 0
	defer func() { maxOutstandingPubs = old }()

	var zb bytes.Buffer
	w := zip.NewWriter(&zb)
	for i := 0; i < 10; i++ {
		fw, err := w.Create("m.dat")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte("bestblock")); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "many.zip")
	if err := os.WriteFile(path, zb.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	var dets int
	err := ScanWithOptions(0, path, Options{Log: &log},
		func(Detection) { dets++ }, func(ProgressInfo) {})
	if err == nil || !strings.Contains(err.Error(), "incomplete coverage") {
		t.Fatalf("cap-0 scan error = %v, want incomplete-coverage error\n%s", err, log.String())
	}
	if dets != 0 {
		t.Errorf("cap-0 detections = %d, want 0 (every nested publish refused)", dets)
	}
}

// Congested versus baseline: the same ten-needle zip scans clean
// uncongested, fails honestly congested (error, case-log error,
// journal holding only skip-free proven points, never completion,
// so resume cannot advance past omitted nested work), and
// recovers fully on an uncongested retry from that journal. The
// root is padded past the 1MB mid-root drain point so the fixture
// also covers mid-run journaling: the 1MB point is proven (the
// barrier ack shows every pre-barrier block fully processed, so
// the later central-directory skips concern only later bytes),
// while the completion frontier must never journal.
func TestPubGateCongestedVsBaseline(t *testing.T) {
	old := maxOutstandingPubs
	defer func() { maxOutstandingPubs = old }()

	var zb bytes.Buffer
	w := zip.NewWriter(&zb)
	for i := 0; i < 10; i++ {
		fw, err := w.Create("m.dat")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte("bestblock")); err != nil {
			t.Fatal(err)
		}
	}
	// Stored (uncompressed) padding pushes the root past the
	// mid-root drain point; zeros carry no needle.
	ph, err := w.CreateHeader(&zip.FileHeader{Name: "pad.dat", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ph.Write(make([]byte, 1300*1024)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "ten.zip")
	if err := os.WriteFile(path, zb.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	scan := func(cap int64, start int64, cpPath, clPath string) (dets int, err error, log string) {
		maxOutstandingPubs = cap
		var lb bytes.Buffer
		err = ScanWithOptions(start, path, Options{
			Log: &lb, CheckpointPath: cpPath, CaseLogPath: clPath,
		}, func(Detection) { dets++ }, func(ProgressInfo) {})
		return dets, err, lb.String()
	}
	lastCaseStatus := func(t *testing.T, clPath string) string {
		t.Helper()
		raw, err := os.ReadFile(clPath)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
		var rec CaseLog
		if err := json.Unmarshal([]byte(lines[len(lines)-1]), &rec); err != nil {
			t.Fatal(err)
		}
		return rec.Status
	}

	// Baseline: uncongested, full coverage, clean completion.
	bd, berr, blog := scan(100, 0, filepath.Join(dir, "base.cp"), filepath.Join(dir, "base.log"))
	if berr != nil {
		t.Fatalf("baseline scan: %v\n%s", berr, blog)
	}
	if bd != 10 {
		t.Fatalf("baseline detections = %d, want 10\n%s", bd, blog)
	}
	if st := lastCaseStatus(t, filepath.Join(dir, "base.log")); st != "complete" {
		t.Fatalf("baseline case-log status = %q, want complete", st)
	}

	// Congested: partial detections, honest error, frozen journal.
	cpPath, clPath := filepath.Join(dir, "cong.cp"), filepath.Join(dir, "cong.log")
	cd, cerr, clog := scan(3, 0, cpPath, clPath)
	if cerr == nil || !strings.Contains(cerr.Error(), "incomplete coverage") {
		t.Fatalf("congested scan error = %v, want incomplete-coverage error\n%s", cerr, clog)
	}
	if cd >= 10 {
		t.Fatalf("congested detections = %d, want fewer than baseline 10", cd)
	}
	if st := lastCaseStatus(t, clPath); st == "complete" {
		t.Fatalf("congested case-log status = complete, want non-complete (error)")
	}
	cp, err := ReadCheckpoint(cpPath)
	if err != nil {
		t.Fatalf("congested journal unreadable: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if cp.Offset >= fi.Size() {
		t.Fatalf("congested journal offset = %d, want below size %d (completion must never journal)", cp.Offset, fi.Size())
	}

	// Retry equivalence: the same journal, uncongested, converges
	// to the full baseline UNION — banked members defer (never
	// re-read, never re-emitted), omitted members are covered.
	// Union (not per-run re-emission) is the banking contract:
	// concatenated outputs carry each hit exactly once.
	maxOutstandingPubs = 100
	var rlog bytes.Buffer
	var rd int
	rerr := ScanWithOptions(cp.Offset, path, Options{
		Log: &rlog, CheckpointPath: cpPath, CaseLogPath: filepath.Join(dir, "retry.log"),
	}, func(Detection) { rd++ }, func(ProgressInfo) {})
	if rerr != nil {
		t.Fatalf("retry scan: %v\n%s", rerr, rlog.String())
	}
	if cd+rd != 10 {
		t.Fatalf("union detections = %d + %d, want baseline 10\n%s", cd, rd, rlog.String())
	}
	if st := lastCaseStatus(t, filepath.Join(dir, "retry.log")); st != "complete" {
		t.Fatalf("retry case-log status = %q, want complete", st)
	}
}

// A congested batch run must leave its journal entry active with no
// digest: the detector never transitions the manifest (main marks
// the target failed from the returned error and retries it), and a
// digest must vouch only for fully covered bytes. An uncongested
// retry then certifies the digest.
func TestPubGateBatchJournalStaysActive(t *testing.T) {
	old := maxOutstandingPubs
	defer func() { maxOutstandingPubs = old }()

	var zb bytes.Buffer
	w := zip.NewWriter(&zb)
	for i := 0; i < 10; i++ {
		fw, err := w.Create("m.dat")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte("bestblock")); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "ten.zip")
	if err := os.WriteFile(path, zb.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	cpPath := filepath.Join(dir, "batch.cp")

	active := func() *BatchManifest {
		m := NewBatchManifest([]string{path}, BatchRun{})
		m.Targets[0].State = BatchActive
		// batchEntryStart persists the transition before the
		// scan starts; mirror it so the journal exists.
		WriteBatchJournal(io.Discard, cpPath, ManifestSnapshot(m))
		return m
	}
	var log bytes.Buffer
	maxOutstandingPubs = 3
	err := ScanWithOptions(0, path, Options{
		Log: &log, CheckpointPath: cpPath, BatchJournal: active(),
	}, func(Detection) {}, func(ProgressInfo) {})
	if err == nil || !strings.Contains(err.Error(), "incomplete coverage") {
		t.Fatalf("congested batch error = %v, want incomplete-coverage error\n%s", err, log.String())
	}
	cp, rerr := ReadCheckpoint(cpPath)
	if rerr != nil {
		t.Fatalf("congested batch journal unreadable: %v", rerr)
	}
	if len(cp.Targets) != 1 || cp.Targets[0].State != BatchActive {
		t.Fatalf("congested batch entry = %+v, want one active entry", cp.Targets)
	}
	if cp.Targets[0].SHA256 != "" {
		t.Fatalf("congested batch entry carries digest %q, want none", cp.Targets[0].SHA256)
	}

	maxOutstandingPubs = 100
	var rlog bytes.Buffer
	if rerr := ScanWithOptions(0, path, Options{
		Log: &rlog, CheckpointPath: cpPath, BatchJournal: active(),
	}, func(Detection) {}, func(ProgressInfo) {}); rerr != nil {
		t.Fatalf("batch retry: %v\n%s", rerr, rlog.String())
	}
	cp, rerr = ReadCheckpoint(cpPath)
	if rerr != nil {
		t.Fatalf("retry batch journal unreadable: %v", rerr)
	}
	if cp.Targets[0].SHA256 == "" {
		t.Fatal("clean full-pass retry journaled no digest")
	}
}
