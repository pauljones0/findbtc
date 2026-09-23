package detector

import (
	"archive/zip"
	"bytes"
	"context"
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
// Cover keys discriminate alternate views of the same bytes: a
// stored member carrying a fake central directory can derive the
// same archive start and member index with a different size (or
// overlapping local headers with different lengths). Same
// Describe, different bytes must not defer — only identical keys
// (same bytes) may.
// The banking gate surface is nil-safe throughout: direct
// unit-test drivers with no pipeline must neither crash nor
// record anything.
func TestPubGateBankingNilSafe(t *testing.T) {
	var g *pubGate
	g.seedCovered([]string{"a"}, nil)
	g.bankCovered(&zipScanTarget{source: &fileScanTarget{path: "x"}, fileIndex: 1, zipSize: 9})
	if g.isCovered("a") {
		t.Error("nil gate reports coverage")
	}
	if g.snapshotCovered() != nil {
		t.Error("nil gate snapshots coverage")
	}
	src := &fileScanTarget{path: "x"}
	m := &zipScanTarget{source: src, fileIndex: 1, zipSize: 9}
	ch := make(chan scanTarget, 1)
	if !gatePublish(g, ch, m) {
		t.Error("nil gate must admit (legacy blocking send)")
	}
	<-ch
	if !gatePublishFlush(g, ch, m) {
		t.Error("nil flush gate must admit")
	}
	<-ch
	g.notePublish(m, false)
	g.notePolicySkip(src)
}

// A policy refusal poisons the banked parent chain without
// counting a skip: the filed set must drop the parent so the
// next run re-reads it and re-applies policy.
func TestPubGatePolicySkipPoisonsFiled(t *testing.T) {
	g := newPubGate(io.Discard)
	root := &fileScanTarget{path: "r"}
	mid := &zipScanTarget{source: root, fileIndex: 0, zipSize: 100}
	ch := make(chan scanTarget, 2)
	if !gatePublish(g, ch, mid) {
		t.Fatal("parent publish refused")
	}
	<-ch
	g.bankCovered(mid)
	if got := g.snapshotCovered(); len(got) != 1 {
		t.Fatalf("filed before policy skip = %v, want [parent]", got)
	}
	g.notePolicySkip(mid)
	if got := g.snapshotCovered(); len(got) != 0 {
		t.Fatalf("filed after policy skip = %v, want empty (parent re-read)", got)
	}
	if n := g.skippedCount(); n != 0 {
		t.Fatalf("skipped = %d, want 0 (policy is not congestion)", n)
	}
}

func TestPubGateCoverKeyDiscriminatesViews(t *testing.T) {
	src := &fileScanTarget{path: "view.zip"}
	mkZip := func(size int64) *zipScanTarget {
		return &zipScanTarget{source: src, zipOffset: 0, fileIndex: 3, zipSize: size}
	}
	mkEntry := func(compSize int64, method uint16) *zipEntryTarget {
		return &zipEntryTarget{source: src, name: "m.dat", dataOff: 100, compSize: compSize, method: method}
	}
	if coverKeyOf(mkZip(1000)) == coverKeyOf(mkZip(900)) {
		t.Error("zip cover keys collide across archive sizes")
	}
	if coverKeyOf(mkEntry(50, 8)) == coverKeyOf(mkEntry(40, 8)) {
		t.Error("entry cover keys collide across comp sizes")
	}
	if coverKeyOf(mkEntry(50, 8)) == coverKeyOf(mkEntry(50, 0)) {
		t.Error("entry cover keys collide across methods")
	}
	za, zb := mkZip(1000), mkZip(1000)
	if coverKeyOf(za) != coverKeyOf(zb) {
		t.Error("identical zip members key differently")
	}
	// End to end at the gate: banking one view must not defer
	// the other, but must defer itself.
	g := newPubGate(io.Discard)
	g.bankCovered(mkZip(1000))
	ch := make(chan scanTarget, 4)
	if !gatePublish(g, ch, mkZip(900)) {
		t.Error("different-size view deferred by banked key (would lose bytes)")
	}
	<-ch
	if gatePublish(g, ch, mkZip(1000)) {
		t.Error("identical view admitted despite banked key (would duplicate)")
	}
	g.bankCovered(mkEntry(50, 8))
	if !gatePublishFlush(g, ch, mkEntry(40, 8)) {
		t.Error("different-length recovery entry deferred by banked key")
	}
	<-ch
	if gatePublishFlush(g, ch, mkEntry(50, 8)) {
		t.Error("identical recovery entry admitted despite banked key")
	}
}

// Seeded (journal) deferral cross-checks the filed provenance
// span against the rediscovered candidate's own extent: a filed
// span the candidate does not occupy admits the member loudly
// instead of deferring it. Banked-this-run members (no seeded
// span) still defer unconditionally — their bytes were read
// this run. Gzip candidates check the start alone: the consumed
// end is unknowable before the member reads.
func TestPubGateSeededSpanCrossCheck(t *testing.T) {
	src := &fileScanTarget{path: "span.bin"}
	gz := func() *gzipScanTarget { return &gzipScanTarget{source: src, gzipOffset: 700} }
	z := func() *zipScanTarget { return &zipScanTarget{source: src, zipOffset: 100, fileIndex: 0, zipSize: 500} }
	seed := func(g *pubGate, key string) {
		t.Helper()
		kept, _, _ := g.seedCovered([]string{key}, [][2]int64{{0, 4096}})
		if len(kept) != 1 {
			t.Fatalf("seed kept %v, want the key", kept)
		}
	}
	t.Run("honest spans defer", func(t *testing.T) {
		var log bytes.Buffer
		g := newPubGate(&log)
		seed(g, coverKeyOf(gz())+"|rootext=700-760")
		seed(g, coverKeyOf(z())+"|rootext=100-600")
		ch := make(chan scanTarget, 4)
		if gatePublish(g, ch, gz()) {
			t.Error("honest seeded gzip span admitted (must defer)")
		}
		if gatePublish(g, ch, z()) {
			t.Error("honest seeded zip span admitted (must defer)")
		}
		if log.Len() > 0 {
			t.Errorf("honest spans must defer quietly, got:\n%s", log.String())
		}
	})
	t.Run("forged spans admit loudly", func(t *testing.T) {
		var log bytes.Buffer
		g := newPubGate(&log)
		seed(g, coverKeyOf(gz())+"|rootext=0-100")
		seed(g, coverKeyOf(z())+"|rootext=0-100")
		ch := make(chan scanTarget, 4)
		admitted := 0
		if !gatePublish(g, ch, gz()) {
			t.Error("forged gzip span deferred (must admit + warn)")
		} else {
			admitted++
		}
		if !gatePublish(g, ch, z()) {
			t.Error("forged zip span deferred (must admit + warn)")
		} else {
			admitted++
		}
		if n := strings.Count(log.String(), "provenance span"); n != 2 {
			t.Errorf("want 2 span-mismatch warnings, got %d:\n%s", n, log.String())
		}
		// The lie is dropped, not re-filed: draining the
		// admits leaves no covered keys behind.
		for i := 0; i < admitted; i++ {
			<-ch
		}
		if got := g.snapshotCovered(); len(got) != 0 {
			t.Errorf("dropped seeds re-filed = %v, want empty", got)
		}
	})
	t.Run("banked this run defers without a span", func(t *testing.T) {
		g := newPubGate(io.Discard)
		g.bankCovered(gz())
		ch := make(chan scanTarget, 1)
		if gatePublish(g, ch, gz()) {
			t.Error("banked-this-run member admitted (must defer)")
		}
	})
}

// Conflicting provenance for one identity drops every entry for
// that member, whatever order they filed in: a rejected span
// must never overwrite a retained one (B1), and two acceptances
// have no unique span to retain. The member re-reads; nothing
// is retained for a conflicted base.
func TestSeededConflictsDropEntireBase(t *testing.T) {
	src := &fileScanTarget{path: "inert.bin"}
	m := &zipScanTarget{source: src, zipOffset: 100, zipSize: 500}
	key := coverKeyOf(m)
	spans := [][2]int64{{0, 20}}
	for _, tc := range []struct {
		name  string
		filed []string
	}{
		{"valid plus out-of-proof duplicate", []string{key + "|rootext=0-10", key + "|rootext=100-600"}},
		{"reversed order", []string{key + "|rootext=100-600", key + "|rootext=0-10"}},
		{"two conflicting in-proof spans", []string{key + "|rootext=0-10", key + "|rootext=10-20"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newPubGate(io.Discard)
			kept, dropped, _ := g.seedCovered(tc.filed, spans)
			if len(kept) != 0 {
				t.Errorf("kept = %v, want empty (conflict drops all)", kept)
			}
			if len(dropped) != 2 {
				t.Errorf("dropped = %v, want both filed entries", dropped)
			}
			if g.deferCovered(m) {
				t.Error("conflicted member deferred (must re-read)")
			}
			if _, ok := g.seedSpan[key]; ok {
				t.Errorf("retained span for conflicted base %q", key)
			}
		})
	}
	t.Run("exact duplicates keep once", func(t *testing.T) {
		g := newPubGate(io.Discard)
		kept, dropped, _ := g.seedCovered([]string{key + "|rootext=0-10", key + "|rootext=0-10"}, spans)
		if len(kept) == 0 || len(dropped) != 0 {
			t.Errorf("kept = %v dropped = %v, want the identical span kept", kept, dropped)
		}
		if sp, ok := g.seedSpan[key]; !ok || sp != [2]int64{0, 10} {
			t.Errorf("retained span = %v,%v, want [0 10]", sp, ok)
		}
	})
	t.Run("different members may share spans", func(t *testing.T) {
		other := &zipScanTarget{source: src, zipOffset: 100, fileIndex: 1, zipSize: 500}
		g := newPubGate(io.Discard)
		kept, _, _ := g.seedCovered([]string{key + "|rootext=0-10", coverKeyOf(other) + "|rootext=0-10"}, spans)
		if len(kept) != 2 {
			t.Errorf("kept = %v, want both members (shared spans are depth inheritance, not conflict)", kept)
		}
	})
}

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
		func(d Detection) {
			// Nested hits only: a raw root leak of the
			// needle is Go-flate-version-dependent, but
			// the cap-0 contract (nothing admitted) is
			// about nested publications.
			if d.Target != path {
				dets++
			}
		}, func(ProgressInfo) {})
	if err == nil || !strings.Contains(err.Error(), "incomplete coverage") {
		t.Fatalf("cap-0 scan error = %v, want incomplete-coverage error\n%s", err, log.String())
	}
	if dets != 0 {
		t.Errorf("cap-0 nested detections = %d, want 0 (every nested publish refused)", dets)
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

	// Nested hits only (Target != path): raw root leaks of the
	// needle are Go-flate-version-dependent, but the
	// congested/baseline contract concerns nested members only.
	scan := func(cap int64, start int64, cpPath, clPath string) (dets int, log string, err error) {
		maxOutstandingPubs = cap
		var lb bytes.Buffer
		err = ScanWithOptions(start, path, Options{
			Log: &lb, CheckpointPath: cpPath, CaseLogPath: clPath,
		}, func(d Detection) {
			if d.Target != path {
				dets++
			}
		}, func(ProgressInfo) {})
		return dets, lb.String(), err
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
	bd, blog, berr := scan(100, 0, filepath.Join(dir, "base.cp"), filepath.Join(dir, "base.log"))
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
	cd, clog, cerr := scan(3, 0, cpPath, clPath)
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
	}, func(d Detection) {
		if d.Target != path {
			rd++
		}
	}, func(ProgressInfo) {})
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

// Root026 receipt, preserved verbatim as a living gate: ten
// synthetic ZIP members, uncongested versus backlogged. The
// backlogged case passes only on full recovery (10/10) or honest
// abort (error plus a non-complete case log) — never on partial
// coverage certified successful/complete.
func TestRootPublicationCoverageCaseLog(t *testing.T) {
	// Fixture bytes come from the literal-free builder (member
	// counting assumes the needle is visible only through member
	// decompression); every assertion below is the frozen 026
	// receipt verbatim.
	names := make([]string, 10)
	for i := range names {
		names[i] = "m.dat"
	}
	zb := zipBytesWithoutLiteralNeedle(t, names)
	dir := t.TempDir()
	target := filepath.Join(dir, "synthetic.zip")
	if err := os.WriteFile(target, zb, 0600); err != nil {
		t.Fatal(err)
	}
	old := maxOutstandingPubs
	defer func() { maxOutstandingPubs = old }()
	for _, name := range []string{"uncongested", "backlogged"} {
		maxOutstandingPubs = 100
		if name == "backlogged" {
			maxOutstandingPubs = 3
		}
		var log bytes.Buffer
		count := 0
		casePath := filepath.Join(dir, name+".jsonl")
		err := ScanWithOptions(0, target, Options{Log: &log, CaseLogPath: casePath}, func(Detection) { count++ }, func(ProgressInfo) {})
		body, readErr := os.ReadFile(casePath)
		if readErr != nil {
			t.Fatal(readErr)
		}
		var record CaseLog
		if decodeErr := json.NewDecoder(bytes.NewReader(body)).Decode(&record); decodeErr != nil {
			t.Fatal(decodeErr)
		}
		t.Logf("ROOT_RECEIPT case=%s detections=%d returned_error=%v case_log_status=%s log=%q", name, count, err, record.Status, log.String())
		if name == "uncongested" && (count != 10 || err != nil || record.Status != "complete") {
			t.Fatalf("baseline failed")
		}
		if name == "backlogged" && count != 10 && (err == nil || record.Status == "complete") {
			t.Fatalf("ROOT_CONTRACT_FAIL: incomplete nested coverage was certified successful/complete")
		}
	}
}

// Retry equivalence after an honest backlog abort: the aborted
// run freezes its journal short of completion with exactly the
// reported members banked (no advance past omitted work), and an
// uncongested resume reports the rest — together exactly 10 with
// no replays — then files completion with banking subsumed.
// Per-run splits vary with scheduling (the cap admits at least
// the first 3 publishes but racing consumption admits more),
// so the test pins totals and journal honesty, not the split.
func TestPublicationBacklogRetryEquivalence(t *testing.T) {
	target := buildBacklogZip(t, 10)
	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	old := maxOutstandingPubs
	defer func() { maxOutstandingPubs = old }()
	dir := t.TempDir()
	ckpt := filepath.Join(dir, "c.json")

	maxOutstandingPubs = 3
	var d1 []Detection
	l1 := filepath.Join(dir, "l1.jsonl")
	err1 := ScanWithOptions(0, target, Options{CheckpointPath: ckpt, CaseLogPath: l1},
		func(d Detection) { d1 = append(d1, d) }, func(ProgressInfo) {})
	if err1 == nil || !strings.Contains(err1.Error(), "incomplete coverage") {
		t.Fatalf("backlogged run err=%v, want incomplete-coverage error", err1)
	}
	if len(d1) < 3 || len(d1) >= 10 {
		t.Fatalf("backlogged run reported %d, want a partial 3..9", len(d1))
	}
	if recs := readCaseLog(t, l1); len(recs) != 1 || recs[0].Status != "error" {
		t.Fatalf("backlogged case log %+v, want one error record", recs)
	}
	cp, err := ReadCheckpoint(ckpt)
	if err != nil {
		t.Fatalf("aborted run filed no journal: %v", err)
	}
	if cp.Offset >= int64(len(raw)) || len(cp.Covered) != len(d1) {
		t.Fatalf("aborted journal at offset %d with %d banked, want frozen short of %d with %d banked",
			cp.Offset, len(cp.Covered), len(raw), len(d1))
	}

	maxOutstandingPubs = 100
	var d2 []Detection
	l2 := filepath.Join(dir, "l2.jsonl")
	if err := ScanWithOptions(0, target, Options{CheckpointPath: ckpt, Resume: true, CaseLogPath: l2},
		func(d Detection) { d2 = append(d2, d) }, func(ProgressInfo) {}); err != nil {
		t.Fatalf("uncongested resume: %v", err)
	}
	if len(d1)+len(d2) != 10 {
		t.Fatalf("union %d+%d, want exactly 10 with no replays", len(d1), len(d2))
	}
	if recs := readCaseLog(t, l2); len(recs) != 1 || recs[0].Status != "complete" {
		t.Fatalf("resume case log %+v, want one complete record", recs)
	}
	cp, err = ReadCheckpoint(ckpt)
	if err != nil {
		t.Fatalf("resumed run filed no journal: %v", err)
	}
	if cp.Offset != int64(len(raw)) || len(cp.Covered) != 0 {
		t.Fatalf("resumed journal at offset %d with %d banked, want %d with banking subsumed",
			cp.Offset, len(cp.Covered), len(raw))
	}
}

// Same-cap retries converge instead of replaying: banking defers
// already-read members, so every attempt under the same cap banks
// at least the first 3 unbanked publishes and errors honestly
// until the last member completes the run. Only 10/10 succeeds.
func TestPublicationBacklogSameCapConverges(t *testing.T) {
	target := buildBacklogZip(t, 10)
	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	old := maxOutstandingPubs
	defer func() { maxOutstandingPubs = old }()
	maxOutstandingPubs = 3
	ckpt := filepath.Join(t.TempDir(), "c.json")
	total := 0
	done := false
	for i := 0; i < 6 && !done; i++ {
		var dets []Detection
		opts := Options{CheckpointPath: ckpt}
		if i > 0 {
			opts.Resume = true
		}
		err := ScanWithOptions(0, target, opts,
			func(d Detection) { dets = append(dets, d) }, func(ProgressInfo) {})
		total += len(dets)
		cp, rerr := ReadCheckpoint(ckpt)
		if rerr != nil {
			t.Fatalf("try %d filed no journal: %v", i+1, rerr)
		}
		if err == nil {
			done = true
			if total != 10 {
				t.Fatalf("clean try %d with total %d, want 10", i+1, total)
			}
			if cp.Offset != int64(len(raw)) || len(cp.Covered) != 0 {
				t.Fatalf("converged journal at offset %d with %d banked, want %d subsumed",
					cp.Offset, len(cp.Covered), len(raw))
			}
			continue
		}
		if !strings.Contains(err.Error(), "incomplete coverage") {
			t.Fatalf("try %d err=%v, want incomplete-coverage error", i+1, err)
		}
		// The first 3 publishes always admit (outstanding
		// starts at 0), so every failed try still banks
		// progress; only a full 10 succeeds.
		if len(dets) < 3 || total >= 10 {
			t.Fatalf("try %d reported %d (total %d), want 3+ new with work outstanding",
				i+1, len(dets), total)
		}
		if cp.Offset >= int64(len(raw)) || len(cp.Covered) != total {
			t.Fatalf("try %d journal at offset %d with %d banked, want frozen with %d banked",
				i+1, cp.Offset, len(cp.Covered), total)
		}
	}
	if !done {
		t.Fatalf("no convergence within 6 same-cap tries (total %d)", total)
	}
}

// zipBytesWithoutLiteralNeedle builds a member archive whose raw
// bytes contain no literal needle, so member content is found only
// by decompressing members — never by the raw root scan. Required
// because tiny-payload flate encoding is toolchain-dependent (Go
// 1.27 stores 9-byte members, adding raw root-level hits that break
// member counting). Padding grows until the premise holds —
// deterministic per toolchain — and the test fails loudly if no
// padding works, instead of silently counting wrong.
func zipBytesWithoutLiteralNeedle(t *testing.T, names []string) []byte {
	t.Helper()
	needle := []byte("bestblock")
	pads := []int{0}
	for p := 8; p <= 256; p += 8 {
		pads = append(pads, p)
	}
	pads = append(pads, 512, 1024, 2048, 4096)
	for _, pad := range pads {
		var zb bytes.Buffer
		w := zip.NewWriter(&zb)
		payload := append([]byte("bestblock"), bytes.Repeat([]byte{0xA5}, pad)...)
		for _, nm := range names {
			fw, err := w.Create(nm)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fw.Write(payload); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if bytes.Count(zb.Bytes(), needle) == 0 {
			return zb.Bytes()
		}
	}
	t.Fatal("no padding keeps the needle out of raw archive bytes")
	return nil
}

// buildBacklogZip writes ten same-content members under distinct
// names: identical needles keep counting honest while names keep
// members distinguishable for coverage assertions.
func buildBacklogZip(t *testing.T, n int) string {
	t.Helper()
	names := make([]string, n)
	for i := range names {
		names[i] = "m" + string(rune('0'+i)) + ".dat"
	}
	zb := zipBytesWithoutLiteralNeedle(t, names)
	dir := t.TempDir()
	target := filepath.Join(dir, "synthetic.zip")
	if err := os.WriteFile(target, zb, 0600); err != nil {
		t.Fatal(err)
	}
	return target
}

type orderProbeReader struct{ *bytes.Reader }

func (orderProbeReader) Close() error { return nil }

type orderProbeTarget struct {
	desc string
	data []byte
}

func (t *orderProbeTarget) Describe() string     { return t.desc }
func (t *orderProbeTarget) StartOffset() int64   { return 0 }
func (t *orderProbeTarget) Size() (int64, error) { return int64(len(t.data)), nil }
func (t *orderProbeTarget) Open() (TargetReader, error) {
	return orderProbeReader{bytes.NewReader(t.data)}, nil
}
func (t *orderProbeTarget) Depth() int { return 1 }

// A nested member is banked before its EOF queues: downstream EOF
// proves delivery, and the error path snapshots banking after
// final EOF — so a reported member must already be banked when
// readTarget returns, or a retry replays it (exactly-once
// violation; 026 union divergence). Regression: banking used to
// happen in the caller after return, leaving a window where a
// delivered member was still unbanked at the error snapshot.
func TestNestedBankedBeforeReturn(t *testing.T) {
	ctx := context.Background()
	targets := make(chan scanTarget, 4)
	emptyBlocks := make(chan *Block, 4)
	for i := 0; i < 4; i++ {
		emptyBlocks <- &Block{data: make([]byte, blockSize+scanOverlap())}
	}
	out := make(chan *Block, 16)
	gate := newPubGate(io.Discard)
	tgt := &orderProbeTarget{desc: "order-probe|member", data: []byte("probe payload")}
	outcome, alive := readTarget(ctx, targets, emptyBlocks, out,
		func(ProgressInfo) {}, Options{}, &journalCtl{}, gate, tgt, false)
	if !alive {
		t.Fatal("readTarget not alive")
	}
	if !outcome.opened {
		t.Fatal("readTarget did not open the probe")
	}
	key := coverKeyOf(tgt)
	gate.coverMu.Lock()
	banked := gate.covered[key]
	gate.coverMu.Unlock()
	if !banked {
		t.Fatalf("nested member %q not banked at readTarget return", key)
	}
	eofs := 0
	for len(out) > 0 {
		if <-out == EOF {
			eofs++
		}
	}
	if eofs != 1 {
		t.Fatalf("queued %d EOFs, want exactly 1", eofs)
	}
}
