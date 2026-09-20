package detector

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// A banked covered set is only valid for the bytes that produced
// it: member keys embed the source path and member index, not
// content, so a same-path byte swap must drop the stale set and
// re-read everything. Without identity gating, a fresh run with
// the same checkpoint path would defer members never read in the
// current bytes and certify complete with silent loss.
func TestPubGateStaleCoveredRescans(t *testing.T) {
	old := maxOutstandingPubs
	defer func() { maxOutstandingPubs = old }()

	buildTen := func(t *testing.T, content []byte) []byte {
		t.Helper()
		var zb bytes.Buffer
		w := zip.NewWriter(&zb)
		for i := 0; i < 10; i++ {
			fw, err := w.Create(fmt.Sprintf("wallet-%02d.dat", i))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fw.Write(content); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return zb.Bytes()
	}
	nested := func(path string, d Detection) bool { return d.Target != path }

	// Single-target: congested run files covered members, then
	// the file is swapped (same shape, same keys) and a fresh
	// scan must re-cover all ten.
	dir := t.TempDir()
	path := filepath.Join(dir, "swap.zip")
	if err := os.WriteFile(path, buildTen(t, []byte("bestblock")), 0644); err != nil {
		t.Fatal(err)
	}
	cpPath := filepath.Join(dir, "swap.cp")
	maxOutstandingPubs = 3
	var clog bytes.Buffer
	var cd int
	cerr := ScanWithOptions(0, path, Options{Log: &clog, CheckpointPath: cpPath},
		func(d Detection) {
			if nested(path, d) {
				cd++
			}
		}, func(ProgressInfo) {})
	if cerr == nil {
		t.Fatalf("congested run unexpectedly clean (dets=%d)", cd)
	}
	cp, err := ReadCheckpoint(cpPath)
	if err != nil || len(cp.Covered) == 0 {
		t.Fatalf("congested journal covered = %+v, err = %v; want banked members", cp.Covered, err)
	}
	// Same shape (same keys), fresh identity: content is
	// re-encoded (mtime forced ahead), so size and mtime both
	// differ from the journal.
	if err := os.WriteFile(path, buildTen(t, []byte("bestblock")), 0644); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, fi.ModTime(), fi.ModTime().Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	maxOutstandingPubs = 100
	var rlog bytes.Buffer
	var rd int
	if rerr := ScanWithOptions(0, path, Options{Log: &rlog, CheckpointPath: cpPath},
		func(d Detection) {
			if nested(path, d) {
				rd++
			}
		}, func(ProgressInfo) {}); rerr != nil {
		t.Fatalf("fresh scan after swap: %v\n%s", rerr, rlog.String())
	}
	if rd != 10 {
		t.Fatalf("fresh scan after swap = %d nested hits, want 10 (stale covered must not defer)", rd)
	}
	if !strings.Contains(rlog.String(), "banked members re-scanned") {
		t.Errorf("no stale-covered warning in fresh-scan log:\n%s", rlog.String())
	}

	// Batch entry: a crafted Active entry with mismatched identity
	// and a full covered set must not defer either.
	bdir := t.TempDir()
	bpath := filepath.Join(bdir, "bswap.zip")
	if err := os.WriteFile(bpath, buildTen(t, []byte("bestblock")), 0644); err != nil {
		t.Fatal(err)
	}
	bcp := filepath.Join(bdir, "bswap.cp")
	m := NewBatchManifest([]string{bpath}, BatchRun{})
	m.Targets[0].State = BatchActive
	m.Targets[0].Size, m.Targets[0].Mtime = 1, 1 // forged mismatch
	for i := 0; i < 10; i++ {
		m.Targets[0].Covered = append(m.Targets[0].Covered,
			fmt.Sprintf("Zipfile #%d @ byte 0 in [%s]", i, bpath))
	}
	WriteBatchJournal(io.Discard, bcp, ManifestSnapshot(m))
	maxOutstandingPubs = 100
	var blog2 bytes.Buffer
	var bd int
	if berr := ScanWithOptions(0, bpath, Options{Log: &blog2, CheckpointPath: bcp, BatchJournal: m},
		func(d Detection) {
			if nested(bpath, d) {
				bd++
			}
		}, func(ProgressInfo) {}); berr != nil {
		t.Fatalf("batch fresh scan after swap: %v\n%s", berr, blog2.String())
	}
	if bd != 10 {
		t.Fatalf("batch fresh scan after swap = %d nested hits, want 10 (stale covered must not defer)", bd)
	}
}
