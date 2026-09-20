package detector

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Same-cap resume must converge to full coverage: a congested run
// banks what it covered, resume re-covers the rest, and repeated
// retries at the SAME cap reach complete instead of replaying the
// same admitted prefix forever (the followup-027 gap: 3/10, never
// complete). Ten uniquely-named members keep per-member detections
// distinguishable across attempts; the stored pad pushes the root
// past the mid-root drain point. Four attempts is ceil(10/3): a
// no-drop scheduler banking at least a capful of newly covered
// members per attempt finishes within budget. Fully synchronous —
// ScanWithOptions returns only after the pipeline drains — so
// there is no timing assumption and no sleep.
func TestPubGateSameCapRetryCompletes(t *testing.T) {
	old := maxOutstandingPubs
	defer func() { maxOutstandingPubs = old }()

	var zb bytes.Buffer
	w := zip.NewWriter(&zb)
	for i := 0; i < 10; i++ {
		fw, err := w.Create(fmt.Sprintf("wallet-%02d.dat", i))
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
	path := filepath.Join(dir, "wallets.zip")
	if err := os.WriteFile(path, zb.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	// Baseline: uncongested, full coverage, clean completion.
	maxOutstandingPubs = 100
	var blog bytes.Buffer
	// Nested hits only (Target != path): whether the tiny
	// members' bytes leak a literal needle into the raw root
	// stream depends on the Go flate encoder version (Go 1.24:
	// none; Go 1.27: one at root offset 48), but the gate
	// contract concerns nested publications only. Filtering
	// keeps the absolute counts exact on every toolchain.
	nested := func(d Detection) bool { return d.Target != path }
	baseline := 0
	berr := ScanWithOptions(0, path, Options{
		Log: &blog, CheckpointPath: filepath.Join(dir, "base.cp"),
		CaseLogPath: filepath.Join(dir, "base.log"),
	}, func(d Detection) {
		if nested(d) {
			baseline++
		}
	}, func(ProgressInfo) {})
	if berr != nil {
		t.Fatalf("baseline scan: %v\n%s", berr, blog.String())
	}
	if baseline != 10 {
		t.Fatalf("baseline detections = %d, want 10\n%s", baseline, blog.String())
	}
	if logs := readCaseLog(t, filepath.Join(dir, "base.log")); len(logs) == 0 || logs[len(logs)-1].Status != "complete" {
		t.Fatalf("baseline case-log last status = %+v, want complete", logs)
	}

	// Same-cap retries: each attempt resumes from the journaled
	// offset; unique detections accumulate by target/offset/needle
	// until some attempt reports clean completion.
	maxOutstandingPubs = 3
	cpPath := filepath.Join(dir, "retry.cp")
	clPath := filepath.Join(dir, "retry.log")
	var start int64
	seen := map[string]bool{}
	var emitted int
	complete := false
	var lastErr error
	for attempt := 1; attempt <= 4; attempt++ {
		var lb bytes.Buffer
		hits := 0
		lastErr = ScanWithOptions(start, path, Options{
			Log: &lb, CheckpointPath: cpPath, CaseLogPath: clPath,
		}, func(d Detection) {
			if !nested(d) {
				return
			}
			hits++
			emitted++
			seen[fmt.Sprintf("%s/%d/%s", d.Target, d.Offset, d.Needle)] = true
		}, func(ProgressInfo) {})
		cp, rerr := ReadCheckpoint(cpPath)
		if rerr != nil {
			t.Fatalf("attempt %d: journal unreadable (resume has nowhere to start): %v\n%s", attempt, rerr, lb.String())
		}
		t.Logf("attempt=%d cap=3 offset_before=%d offset_after=%d hits=%d unique=%d err=%v",
			attempt, start, cp.Offset, hits, len(seen), lastErr)
		start = cp.Offset
		if lastErr == nil {
			complete = true
			break
		}
		if !strings.Contains(lastErr.Error(), "incomplete coverage") {
			t.Fatalf("attempt %d: error = %v, want honest incomplete-coverage signal\n%s", attempt, lastErr, lb.String())
		}
	}
	t.Logf("baseline=%d emitted_total=%d unique=%d completed=%v", baseline, emitted, len(seen), complete)
	if !complete {
		t.Fatalf("same-cap resume never completed in 4 attempts (last error: %v); unique %d/%d — retries replay the admitted prefix instead of converging",
			lastErr, len(seen), baseline)
	}
	if len(seen) != baseline {
		t.Fatalf("same-cap resume completed with %d unique detections, want baseline %d (lost coverage certified complete)", len(seen), baseline)
	}
	if logs := readCaseLog(t, clPath); len(logs) == 0 || logs[len(logs)-1].Status != "complete" {
		t.Fatalf("same-cap case-log last status = %+v, want complete", logs)
	}
}
