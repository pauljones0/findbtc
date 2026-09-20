package detector

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Range proofs bind every skipped span to verified content: a
// completed range with a forged or failing proof restarts the
// list there, an active range with a failing proof rescans that
// range, and legacy journals (no proofs) rescan everything. The
// wrong-proof arms run over UNCHANGED bytes so the cheap tier
// passes and the proof alone decides; the tamper arm flips a real
// byte (refused at the cheap tier on posix, at the proof on
// weak-metadata platforms — both rescan).
func TestRangeProofTamperRescans(t *testing.T) {
	path, ranges, O := rangeResumeFixture(t)
	full := scanRangeList(t, path, ranges, Options{})
	if len(full) == 0 {
		t.Fatal("fixture produced no detections")
	}
	goodActive := mustProof(t, path, ranges[1].Start, O-ranges[1].Start)
	goodDone := []RangeProof{mustRangeProof(t, 0, path, ranges[0].Start, ranges[0].Len)}
	forged := func(p *PrefixProof) *PrefixProof {
		out := *p
		out.SHA256 = strings.Repeat("0", 64)
		if out.SHA256 == p.SHA256 {
			out.SHA256 = strings.Repeat("1", 64)
		}
		return &out
	}

	t.Run("completed range forged proof rescans all", func(t *testing.T) {
		ckpt := filepath.Join(t.TempDir(), "ckpt.json")
		bad := mustRangeProof(t, 0, path, ranges[0].Start, ranges[0].Len)
		bad.SHA256 = forged(goodActive).SHA256
		writeCheckpointRange(nil, ckpt, path, ranges, 1, O, nil, testIdent(path), goodActive, []RangeProof{bad})
		var log bytes.Buffer
		after := scanRangeList(t, path, ranges, Options{CheckpointPath: ckpt, Resume: true, Log: &log})
		if !strings.Contains(log.String(), "range 0 proof failed") {
			t.Fatalf("must warn range 0 proof failed, got:\n%s", log.String())
		}
		if ok, why := detListEqual(after, full); !ok {
			t.Fatalf("forged completed proof must rescan all: %s", why)
		}
	})

	t.Run("active range forged proof rescans range", func(t *testing.T) {
		ckpt := filepath.Join(t.TempDir(), "ckpt.json")
		writeCheckpointRange(nil, ckpt, path, ranges, 1, O, nil, testIdent(path), forged(goodActive), goodDone)
		var log bytes.Buffer
		after := scanRangeList(t, path, ranges, Options{CheckpointPath: ckpt, Resume: true, Log: &log})
		if !strings.Contains(log.String(), "range 1 proof failed") {
			t.Fatalf("must warn range 1 proof failed, got:\n%s", log.String())
		}
		// Range 0 stayed skipped (verified): its needle at
		// offset 100 must not re-report.
		for _, d := range after {
			if d.Offset == 100 {
				t.Fatal("verified completed range re-scanned")
			}
		}
		before := scanRangeList(t, path, ranges[:1], Options{})
		if ok, why := detListEqual(append(before, after...), full); !ok {
			t.Fatalf("union differs: %s", why)
		}
	})

	t.Run("legacy range journal rescans all", func(t *testing.T) {
		ckpt := filepath.Join(t.TempDir(), "ckpt.json")
		writeCheckpointRange(nil, ckpt, path, ranges, 1, O, nil, testIdent(path), nil, nil)
		var log bytes.Buffer
		after := scanRangeList(t, path, ranges, Options{CheckpointPath: ckpt, Resume: true, Log: &log})
		if !strings.Contains(log.String(), "rescan") {
			t.Fatalf("legacy journal must warn rescan, got:\n%s", log.String())
		}
		if ok, why := detListEqual(after, full); !ok {
			t.Fatalf("legacy journal must rescan all: %s", why)
		}
	})

	t.Run("tampered completed range rescans", func(t *testing.T) {
		tpath := filepath.Join(t.TempDir(), "ranges.bin")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(tpath, raw, 0644); err != nil {
			t.Fatal(err)
		}
		ckpt := filepath.Join(t.TempDir(), "ckpt.json")
		writeCheckpointRange(nil, ckpt, tpath, ranges, 1, O, nil, testIdent(tpath),
			mustProof(t, tpath, ranges[1].Start, O-ranges[1].Start),
			[]RangeProof{mustRangeProof(t, 0, tpath, ranges[0].Start, ranges[0].Len)})
		// Flip a bulk byte in range 0 (no needle there) and
		// restore the mtime: same size, same mtime, new bytes.
		st, _ := os.Stat(tpath)
		raw[500] ^= 0xff
		if err := os.WriteFile(tpath, raw, 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(tpath, st.ModTime(), st.ModTime()); err != nil {
			t.Fatal(err)
		}
		fullTampered := scanRangeList(t, tpath, ranges, Options{})
		var log bytes.Buffer
		after := scanRangeList(t, tpath, ranges, Options{CheckpointPath: ckpt, Resume: true, Log: &log})
		if !strings.Contains(log.String(), "rescan") {
			t.Fatalf("tamper must warn rescan, got:\n%s", log.String())
		}
		if ok, why := detListEqual(after, fullTampered); !ok {
			t.Fatalf("tampered range must rescan: %s", why)
		}
	})
}

// A resumed-then-completed batch entry must certify the FULL
// stream digest — chained from the verified prefix plus the
// suffix read this run — so a later skip re-hashes the same
// bytes a fresh full pass would.
func TestBatchDigestChaining(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "chain.bin")
	const size = 64 << 10
	raw := make([]byte, size)
	copy(raw[100:], "bestblock")
	copy(raw[40<<10:], "defaultkey")
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	const O = 16 << 10
	start := ResumeRewindOffset(0, O)
	ckpt := filepath.Join(dir, "chain.cp")
	m := NewBatchManifest([]string{path}, BatchRun{})
	m.Targets[0].State = BatchActive
	m.Targets[0].Offset = O
	m.Targets[0].Ident = testIdent(path)
	m.Targets[0].Proof = mustProof(t, path, 0, O)
	WriteBatchJournal(nil, ckpt, ManifestSnapshot(m))
	var log bytes.Buffer
	if err := ScanWithOptions(start, path, Options{CheckpointPath: ckpt, Resume: true, BatchJournal: m, Log: &log},
		func(Detection) {}, func(ProgressInfo) {}); err != nil {
		t.Fatalf("resumed completion: %v\n%s", err, log.String())
	}
	if strings.Contains(log.String(), "rescan") {
		t.Fatalf("honest batch resume must not rescan:\n%s", log.String())
	}
	cp, err := ReadCheckpoint(ckpt)
	if err != nil {
		t.Fatal(err)
	}
	got := cp.Targets[0].SHA256
	want := mustSpanProof(0, raw).SHA256
	if got == "" {
		t.Fatal("resumed completion filed no digest (skip would rescan forever)")
	}
	if got != want {
		t.Fatal("resumed completion digest is not the full-stream hash (suffix-only chaining)")
	}
	if cp.Targets[0].Proof == nil || cp.Targets[0].Proof.Len != size {
		t.Fatalf("completion proof = %+v, want full span", cp.Targets[0].Proof)
	}
	if err := VerifyBatchDigest(path, size, got); err != nil {
		t.Fatalf("chained digest does not verify: %v", err)
	}
}

// The error path must never launder a stale journal offset under
// the current bytes: after a refused claim, the frozen point
// comes from run state only (last filed point, else run start),
// and the filed proof pins bytes actually read this run. (Hole B:
// old code re-filed the stale file offset under the fresh
// identity, authorizing a skip of never-read bytes next run.)
func TestFrozenStaleOffsetNotLaundered(t *testing.T) {
	old := maxOutstandingPubs
	defer func() { maxOutstandingPubs = old }()
	maxOutstandingPubs = 1

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

	t.Run("single", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "data.zip")
		a := buildTen(t, []byte("bestblock"))
		if err := os.WriteFile(path, a, 0600); err != nil {
			t.Fatal(err)
		}
		// Stale claim over A bytes at 1KiB (inside the file).
		const staleOff = 1024
		ckpt := filepath.Join(dir, "run.cp")
		writeCheckpoint(nil, ckpt, path, staleOff, []string{"banked-member"}, testIdent(path), mustProof(t, path, 0, staleOff))
		// Swap to B bytes with a forced-ahead mtime.
		b := buildTen(t, []byte("defaultkey"))
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
		fi, _ := os.Stat(path)
		if err := os.Chtimes(path, fi.ModTime(), fi.ModTime().Add(48*time.Hour)); err != nil {
			t.Fatal(err)
		}
		// Error run from 0 (claim refused): tiny file, no
		// mid-run drain, congestion error at the end.
		var log bytes.Buffer
		err := ScanWithOptions(0, path, Options{CheckpointPath: ckpt, Resume: true, Log: &log},
			func(Detection) {}, func(ProgressInfo) {})
		if err == nil || !strings.Contains(err.Error(), "incomplete coverage") {
			t.Fatalf("want congestion error, got %v\n%s", err, log.String())
		}
		cp, err := ReadCheckpoint(ckpt)
		if err != nil {
			t.Fatal(err)
		}
		if cp.Offset == staleOff {
			t.Fatalf("stale offset %d re-filed under current bytes (laundered)", staleOff)
		}
		if cp.Offset != 0 {
			t.Fatalf("frozen offset = %d, want run start 0", cp.Offset)
		}
		// The filed proof must be self-consistent for the
		// CURRENT bytes: it verifies, so the next run seeds
		// banking from it instead of inheriting stale claims.
		if cp.Proof == nil {
			t.Fatal("error path filed no proof")
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := verifySpan(f, cp.Proof.Start, cp.Proof.Len, cp.Proof.SHA256); err != nil {
			t.Fatalf("filed proof inconsistent with current bytes: %v", err)
		}
	})

	t.Run("batch", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "bdata.zip")
		a := buildTen(t, []byte("bestblock"))
		if err := os.WriteFile(path, a, 0600); err != nil {
			t.Fatal(err)
		}
		const staleOff = 1024
		ckpt := filepath.Join(dir, "batch.cp")
		m := NewBatchManifest([]string{path}, BatchRun{})
		m.Targets[0].State = BatchActive
		m.Targets[0].Offset = staleOff
		m.Targets[0].Covered = []string{"banked-member"}
		m.Targets[0].Ident = testIdent(path)
		m.Targets[0].Proof = mustProof(t, path, 0, staleOff)
		WriteBatchJournal(nil, ckpt, ManifestSnapshot(m))
		b := buildTen(t, []byte("defaultkey"))
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
		fi, _ := os.Stat(path)
		if err := os.Chtimes(path, fi.ModTime(), fi.ModTime().Add(48*time.Hour)); err != nil {
			t.Fatal(err)
		}
		var log bytes.Buffer
		err := ScanWithOptions(0, path, Options{CheckpointPath: ckpt, Resume: true, BatchJournal: m, Log: &log},
			func(Detection) {}, func(ProgressInfo) {})
		if err == nil || !strings.Contains(err.Error(), "incomplete coverage") {
			t.Fatalf("want congestion error, got %v\n%s", err, log.String())
		}
		cp, err := ReadCheckpoint(ckpt)
		if err != nil {
			t.Fatal(err)
		}
		if cp.Targets[0].Offset == staleOff {
			t.Fatalf("stale batch offset %d re-filed under current bytes (laundered)", staleOff)
		}
	})
}

// Multi-segment targets prove the DECODED stream, not one
// segment's metadata: swapping a later segment (same size, first
// segment untouched, so the cheap tier passes) must fail the
// proof and rescan. (Hole D: old code attested only the named
// segment, so the swap was invisible.)
func TestSplitSegmentSwapRescans(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "img")
	seg1, seg2 := base+".001", base+".002"
	s1 := bytes.Repeat([]byte{'A'}, 8192)
	copy(s1[100:], "bestblock")
	s2 := bytes.Repeat([]byte{'B'}, 8192)
	copy(s2[4208:], "bestblock")
	if err := os.WriteFile(seg1, s1, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(seg2, s2, 0600); err != nil {
		t.Fatal(err)
	}
	tgt, err := detectScanTarget(seg1, 0)
	if err != nil {
		t.Fatal(err)
	}
	const O = 12 << 10
	start := ResumeRewindOffset(0, O)
	decoded := func(t *testing.T) []byte {
		t.Helper()
		r, err := tgt.Open()
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		out := make([]byte, O)
		if _, err := io.ReadFull(io.NewSectionReader(r, 0, O), out); err != nil {
			t.Fatalf("short decoded read: %v", err)
		}
		return out
	}
	scanDecoded := func(t *testing.T, start int64, opts Options) []Detection {
		t.Helper()
		var dets []Detection
		if err := ScanWithOptions(start, seg1, opts,
			func(d Detection) { dets = append(dets, d) }, func(ProgressInfo) {}); err != nil {
			t.Fatalf("split scan: %v", err)
		}
		return dets
	}
	proof := mustSpanProof(0, decoded(t))

	t.Run("swapped later segment rescans", func(t *testing.T) {
		ckpt := filepath.Join(t.TempDir(), "ckpt.json")
		writeCheckpoint(nil, ckpt, seg1, O, nil, testIdent(seg1), proof)
		// Swap segment 2's bulk (same size); segment 1
		// untouched, so its metadata still matches.
		st, _ := os.Stat(seg2)
		swapped := bytes.Repeat([]byte{'Q'}, 8192)
		copy(swapped[4208:], "bestblock")
		if err := os.WriteFile(seg2, swapped, 0600); err != nil {
			t.Fatal(err)
		}
		_ = os.Chtimes(seg2, st.ModTime(), st.ModTime())
		full := scanDecoded(t, 0, Options{})
		var log bytes.Buffer
		after := scanDecoded(t, start, Options{CheckpointPath: ckpt, Resume: true, Log: &log})
		if !strings.Contains(log.String(), "proof failed") {
			t.Fatalf("segment swap must fail the proof, got:\n%s", log.String())
		}
		if ok, why := detListEqual(after, full); !ok {
			t.Fatalf("segment swap must rescan fully: %s", why)
		}
	})

	t.Run("positive honors frontier", func(t *testing.T) {
		// Restore segment 2 to journaled bytes.
		if err := os.WriteFile(seg2, s2, 0600); err != nil {
			t.Fatal(err)
		}
		ckpt := filepath.Join(t.TempDir(), "ckpt.json")
		writeCheckpoint(nil, ckpt, seg1, O, nil, testIdent(seg1), mustSpanProof(0, decoded(t)))
		var log bytes.Buffer
		after := scanDecoded(t, start, Options{CheckpointPath: ckpt, Resume: true, Log: &log})
		if strings.Contains(log.String(), "proof failed") || strings.Contains(log.String(), "rescanning") {
			t.Fatalf("honest split resume must not rescan:\n%s", log.String())
		}
		for _, d := range after {
			if d.Offset < start {
				t.Fatalf("honest split resume re-reported head offset %d", d.Offset)
			}
		}
	})
}

// A journal claiming a completed range list verifies every range
// proof before reporting done — including the end-of-last-range
// shape — and a swap or forgery rescans instead of returning
// success over new bytes. (Hole A: the completion early-return
// preceded the trust check.)
func TestRangeCompletionSwapRescans(t *testing.T) {
	path, ranges, _ := rangeResumeFixture(t)
	allProofs := func(t *testing.T) []RangeProof {
		t.Helper()
		var out []RangeProof
		for i, r := range ranges {
			out = append(out, mustRangeProof(t, i, path, r.Start, r.Len))
		}
		return out
	}
	last := ranges[len(ranges)-1]

	t.Run("hand-shape completion with swap rescans", func(t *testing.T) {
		// Journal the ORIGINAL bytes' proofs against a copy
		// holding TAMPERED bytes (so the fixture keeps its
		// bytes for sibling subtests). The filed identity
		// matches the copy — the cheap tier passes — so the
		// range proofs alone must refuse.
		orig, _ := os.ReadFile(path)
		tampered := append([]byte{}, orig...)
		tampered[500] ^= 0xff
		tpath := filepath.Join(t.TempDir(), "ranges.bin")
		if err := os.WriteFile(tpath, tampered, 0600); err != nil {
			t.Fatal(err)
		}
		ckpt := filepath.Join(t.TempDir(), "done.cp")
		var proofs []RangeProof
		for i, r := range ranges {
			proofs = append(proofs, mustRangeProof(t, i, path, r.Start, r.Len))
		}
		writeCheckpointRange(nil, ckpt, tpath, ranges, len(ranges), last.Start+last.Len, nil, testIdent(tpath), nil, proofs)
		var hits int
		err := ScanRangesWithOptions(tpath, ranges, Options{CheckpointPath: ckpt, Resume: true},
			func(Detection) { hits++ }, func(ProgressInfo) {})
		if err != nil {
			t.Fatalf("resume errored: %v", err)
		}
		if hits == 0 {
			t.Fatal("completed journal honored for swapped bytes: silent skip, 0 detections")
		}
	})

	t.Run("genuine completion with swap rescans", func(t *testing.T) {
		raw, _ := os.ReadFile(path)
		tpath := filepath.Join(t.TempDir(), "ranges.bin")
		if err := os.WriteFile(tpath, raw, 0600); err != nil {
			t.Fatal(err)
		}
		ckpt := filepath.Join(t.TempDir(), "done.cp")
		var proofs []RangeProof
		for i, r := range ranges[:len(ranges)-1] {
			proofs = append(proofs, mustRangeProof(t, i, tpath, r.Start, r.Len))
		}
		writeCheckpointRange(nil, ckpt, tpath, ranges, len(ranges)-1, last.Start+last.Len, nil,
			testIdent(tpath), mustProof(t, tpath, last.Start, last.Len), proofs)
		st, _ := os.Stat(tpath)
		raw[500] ^= 0xff
		if err := os.WriteFile(tpath, raw, 0600); err != nil {
			t.Fatal(err)
		}
		_ = os.Chtimes(tpath, st.ModTime(), st.ModTime())
		var hits int
		err := ScanRangesWithOptions(tpath, ranges, Options{CheckpointPath: ckpt, Resume: true},
			func(Detection) { hits++ }, func(ProgressInfo) {})
		if err != nil {
			t.Fatalf("resume errored: %v", err)
		}
		if hits == 0 {
			t.Fatal("genuine completion honored for swapped bytes: 0 detections")
		}
	})

	t.Run("forged completed proof salvages verified ranges", func(t *testing.T) {
		ckpt := filepath.Join(t.TempDir(), "done.cp")
		proofs := allProofs(t)
		proofs[1].SHA256 = strings.Repeat("7", 64)
		writeCheckpointRange(nil, ckpt, path, ranges, len(ranges), last.Start+last.Len, nil, testIdent(path), nil, proofs)
		full := scanRangeList(t, path, ranges, Options{})
		var log bytes.Buffer
		after := scanRangeList(t, path, ranges, Options{CheckpointPath: ckpt, Resume: true, Log: &log})
		if !strings.Contains(log.String(), "range 1 proof failed") {
			t.Fatalf("must warn range 1 proof failed, got:\n%s", log.String())
		}
		// Range 0 verified: its needle must not re-report.
		for _, d := range after {
			if d.Offset == 100 {
				t.Fatal("verified range 0 re-scanned")
			}
		}
		before := scanRangeList(t, path, ranges[:1], Options{})
		if ok, why := detListEqual(append(before, after...), full); !ok {
			t.Fatalf("salvage union differs: %s", why)
		}
	})
}

// An explicit -s start is a caller assertion, never proven bytes:
// its journals file span proofs the next resume refuses, so a
// later -resume without -s rescans from zero instead of skipping
// bytes no run ever read.
func TestAssertedSkipNotJournaled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "skip.bin")
	const size = 64 << 10
	raw := make([]byte, size)
	copy(raw[100:], "bestblock")
	copy(raw[40<<10:], "defaultkey")
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	ckpt := filepath.Join(dir, "skip.cp")
	const asserted = 16 << 10
	if err := ScanWithOptions(asserted, path, Options{CheckpointPath: ckpt},
		func(Detection) {}, func(ProgressInfo) {}); err != nil {
		t.Fatalf("asserted scan: %v", err)
	}
	cp, err := ReadCheckpoint(ckpt)
	if err != nil {
		t.Fatal(err)
	}
	if cp.Proof == nil || cp.Proof.Start != asserted {
		t.Fatalf("asserted journal proof = %+v, want span from %d", cp.Proof, asserted)
	}
	// A later -resume without -s starts near the filed end...
	start := ResumeRewindOffset(0, cp.Offset)
	var log bytes.Buffer
	var dets []Detection
	if err := ScanWithOptions(start, path, Options{CheckpointPath: ckpt, Resume: true, Log: &log},
		func(d Detection) { dets = append(dets, d) }, func(ProgressInfo) {}); err != nil {
		t.Fatalf("resume errored: %v", err)
	}
	if !strings.Contains(log.String(), "explicit skip") {
		t.Fatalf("asserted offset must warn explicit skip, got:\n%s", log.String())
	}
	head := false
	for _, d := range dets {
		if d.Offset < asserted {
			head = true
		}
	}
	if !head {
		t.Fatal("asserted skip honored without proof: head bytes skipped")
	}
}

// Gzip members bank exact compressed spans (counted during the
// member read), so a congested gzip run converges across retries
// exactly like the zip same-cap case: the first attempt banks
// the admitted member with its provenance span, the retry defers
// it and admits the refused one.
func TestGzipProvenanceConverges(t *testing.T) {
	old := maxOutstandingPubs
	defer func() { maxOutstandingPubs = old }()
	maxOutstandingPubs = 1

	gzMember := func(t *testing.T, content string) []byte {
		t.Helper()
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	// Back-to-back members in one block: discovery publishes
	// both while the root read holds the channel, so the second
	// is deterministically refused at cap 1.
	m1 := gzMember(t, "bestblock-one")
	m2 := gzMember(t, "bestblock-two")
	raw := append(append([]byte{}, m1...), m2...)
	dir := t.TempDir()
	path := filepath.Join(dir, "two.gz")
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	ckpt := filepath.Join(dir, "gz.cp")
	nested := func(d Detection) bool { return d.Target != path }

	var log1 bytes.Buffer
	seen := map[string]bool{}
	err := ScanWithOptions(0, path, Options{Log: &log1, CheckpointPath: ckpt},
		func(d Detection) {
			if nested(d) {
				seen[d.Target+"/"+d.Needle] = true
			}
		}, func(ProgressInfo) {})
	if err == nil || !strings.Contains(err.Error(), "incomplete coverage") {
		t.Fatalf("attempt 1: want congestion error, got %v\n%s", err, log1.String())
	}
	cp, err := ReadCheckpoint(ckpt)
	if err != nil {
		t.Fatal(err)
	}
	if len(cp.Covered) != 1 {
		t.Fatalf("attempt 1 covered = %v, want the one admitted member", cp.Covered)
	}
	_, s, e, ok := coverProvenance(cp.Covered[0])
	if !ok {
		t.Fatalf("banked gzip key has no provenance: %q", cp.Covered[0])
	}
	// The span covers the member (plus bounded reader readahead)
	// and stays inside the stream.
	if s != 0 || e < int64(len(m1)) || e > int64(len(raw)) {
		t.Fatalf("gzip span = %d-%d, want [0, >=%d) within %d", s, e, len(m1), len(raw))
	}
	// Retry at the same cap defers the banked member and admits
	// the refused one.
	var log2 bytes.Buffer
	start := cp.Offset
	err = ScanWithOptions(start, path, Options{Log: &log2, CheckpointPath: ckpt},
		func(d Detection) {
			if nested(d) {
				seen[d.Target+"/"+d.Needle] = true
			}
		}, func(ProgressInfo) {})
	if err != nil {
		t.Fatalf("attempt 2: %v\n%s", err, log2.String())
	}
	if len(seen) != 2 {
		t.Fatalf("unique nested = %d, want 2 (retry must admit the refused member)", len(seen))
	}
}
