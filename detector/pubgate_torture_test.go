package detector

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Scale/torture proof for the nested-publication gate.
//
// A flat many-member zip cannot reach tens of thousands of members
// in test time: every zip member open re-parses the whole central
// directory, so scan cost grows O(members^2) (measured: N=2000 4s,
// N=5000 44s, N=10000 172s under GOMAXPROCS=2). Three nesting
// levels reach the same publication count with small per-level
// directories instead: outer 30 x mid 30 x leaf 25 = 22,500 leaf
// detections across 30 + 900 + 22,500 = 23,430 nested publications
// (plus one pad member), each level's directory holding at most 31
// entries. Total wall time stays well under a minute on an
// unloaded 2-CPU box under the resource bounds in the task.
//
// Archive shape (all DEFLATE except the pad):
//
//	outer.zip: 30 members holding identical mid.zip bytes + pad.dat
//	mid.zip:   30 members holding identical leaf.zip bytes
//	leaf.zip:  25 members each holding exactly "bestblock"
//
// Why the full-coverage count is exact (not merely stable):
// every needle-bearing byte is DEFLATE-compressed in every
// ancestor stream, so raw block scans of the root and of the
// mid/outer members contribute zero detections; each leaf member
// inflates to exactly one "bestblock" occurrence, yielding exactly
// one detection; and the local-header recovery path dedupes
// healthy members against published ranges, so it adds none.
// The peak outstanding publication count is bounded above by the
// total publication count (23,431), far below the default cap, so
// the baseline gate trip is impossible regardless of timing — the
// test also asserts the log carries no gate warning to prove it.
func TestPubGateTorture(t *testing.T) {
	old := maxOutstandingPubs
	defer func() { maxOutstandingPubs = old }()
	// The baseline phase must run under the real default cap; fail
	// loudly if a leaked test mutation changed it instead of
	// silently torturing the wrong gate setting.
	if maxOutstandingPubs != 512*1024 {
		t.Fatalf("maxOutstandingPubs = %d, want default %d", maxOutstandingPubs, 512*1024)
	}
	defCap := maxOutstandingPubs

	const outers, mids, leaves = 30, 30, 25
	const want = outers * mids * leaves // 22,500 leaf detections

	// One leaf template and one mid template, reused by every
	// parent: identical bytes keep the build fast and the root
	// small, while each member still publishes independently.
	leafZip := func() []byte {
		var zb bytes.Buffer
		w := zip.NewWriter(&zb)
		for i := 0; i < leaves; i++ {
			fw, err := w.Create(fmt.Sprintf("leaf%05d.dat", i))
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
		return zb.Bytes()
	}()
	midZip := func() []byte {
		var zb bytes.Buffer
		w := zip.NewWriter(&zb)
		for i := 0; i < mids; i++ {
			fw, err := w.Create(fmt.Sprintf("mid%05d.zip", i))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fw.Write(leafZip); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return zb.Bytes()
	}()
	var zb bytes.Buffer
	w := zip.NewWriter(&zb)
	for i := 0; i < outers; i++ {
		fw, err := w.Create(fmt.Sprintf("inner%04d.zip", i))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(midZip); err != nil {
			t.Fatal(err)
		}
	}
	// Stored (uncompressed) padding pushes the root past the 1MB
	// mid-root drain point; zeros carry no needle. The needle
	// members stay DEFLATE so no inner structure leaks into raw
	// ancestor scans (a Stored needle member would double-count:
	// once raw, once inflated).
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
	path := filepath.Join(dir, "torture.zip")
	if err := os.WriteFile(path, zb.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("torture archive: %d bytes, %d outer + %d mid + %d leaf members",
		fi.Size(), outers, outers*mids, want)

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

	// Phase 1, baseline: under the DEFAULT cap the archive scans
	// fully — nil error, exact detection count (no drops, no
	// hang), clean case-log completion, and the completion
	// frontier journaled at exactly the file size.
	bd, berr, blog := scan(defCap, 0, filepath.Join(dir, "base.cp"), filepath.Join(dir, "base.log"))
	if berr != nil {
		t.Fatalf("baseline scan: %v", berr)
	}
	if bd != want {
		t.Fatalf("baseline detections = %d, want %d", bd, want)
	}
	if strings.Contains(blog, "publication cap") || strings.Contains(blog, "coverage is incomplete") {
		t.Fatal("baseline log carries a gate warning under the default cap")
	}
	if st := lastCaseStatus(t, filepath.Join(dir, "base.log")); st != "complete" {
		t.Fatalf("baseline case-log status = %q, want complete", st)
	}
	bcp, err := ReadCheckpoint(filepath.Join(dir, "base.cp"))
	if err != nil {
		t.Fatalf("baseline journal unreadable: %v", err)
	}
	if bcp.Offset != fi.Size() {
		t.Fatalf("baseline journal offset = %d, want size %d (completion must journal)", bcp.Offset, fi.Size())
	}
	t.Logf("baseline: %d detections, clean completion journaled", bd)

	// Phase 2, congested: the same archive under a lowered cap
	// fails honestly — incomplete-coverage error (never clean
	// completion), fewer than baseline detections, a non-complete
	// case-log record, and a journal frozen below the file size.
	// Congested counts are timing-dependent (the publisher/
	// consumer race decides how much admitted work drains), so
	// only inequalities are asserted here; exactness returns via
	// retry equivalence in phase 3. The frozen offset itself is
	// exact: skips happen only at the end-of-root central-
	// directory burst, after the 1MB drain, so the drain journals
	// skip-free at exactly checkpointBlockInterval 4kB blocks —
	// root reads are sequential full blocks from offset 0.
	cpPath, clPath := filepath.Join(dir, "cong.cp"), filepath.Join(dir, "cong.log")
	cd, cerr, clog := scan(3, 0, cpPath, clPath)
	if cerr == nil || !strings.Contains(cerr.Error(), "incomplete coverage") {
		t.Fatalf("congested scan error = %v, want incomplete-coverage error", cerr)
	}
	if !strings.Contains(clog, "publication cap") {
		t.Error("no gate warning in congested log")
	}
	if !strings.Contains(clog, "coverage is incomplete") {
		t.Error("no incompleteness warning in congested log")
	}
	if cd >= want {
		t.Fatalf("congested detections = %d, want fewer than baseline %d", cd, want)
	}
	if st := lastCaseStatus(t, clPath); st == "complete" {
		t.Fatal("congested case-log status = complete, want non-complete (error)")
	}
	ccp, err := ReadCheckpoint(cpPath)
	if err != nil {
		t.Fatalf("congested journal unreadable: %v", err)
	}
	if ccp.Offset >= fi.Size() {
		t.Fatalf("congested journal offset = %d, want below size %d (completion must never journal)", ccp.Offset, fi.Size())
	}
	if wantOff := int64(checkpointBlockInterval * blockSize); ccp.Offset != wantOff {
		t.Fatalf("congested journal offset = %d, want exactly %d (skip-free 1MB point stands)", ccp.Offset, wantOff)
	}
	t.Logf("congested: %d detections (< %d), honest error, journal frozen at %d", cd, want, ccp.Offset)

	// Phase 3, retry: the frozen journal, uncongested, recovers
	// the full baseline count exactly — omitted work is retried,
	// never lost. Exactness holds because resume re-reads the
	// end-of-root directory (absolute offsets republish every
	// member regardless of the resume point), nested targets
	// always re-scan fully, and the resumed root tail (pad zeros,
	// central directory) carries no raw needle.
	maxOutstandingPubs = defCap
	var rlog bytes.Buffer
	var rd int
	rerr := ScanWithOptions(ccp.Offset, path, Options{
		Log: &rlog, CheckpointPath: cpPath, CaseLogPath: filepath.Join(dir, "retry.log"),
	}, func(Detection) { rd++ }, func(ProgressInfo) {})
	if rerr != nil {
		t.Fatalf("retry scan: %v", rerr)
	}
	if rd != want {
		t.Fatalf("retry detections = %d, want baseline %d", rd, want)
	}
	if st := lastCaseStatus(t, filepath.Join(dir, "retry.log")); st != "complete" {
		t.Fatalf("retry case-log status = %q, want complete", st)
	}
	t.Logf("retry: %d detections, full baseline recovered", rd)
}
