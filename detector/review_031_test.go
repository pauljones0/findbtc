// Frozen independent-review probes for the 031 fix stack (BLOCK
// verdict 2026-09-20): B1 duplicate-covered fail-open, B2
// verification-open failure, B3 Resume-with-unreadable-journal.
// Preserved verbatim from
// repros/findbtc-031-fix-review-20260920/probe-tree/detector/review_031_test.go
// (sha256 a8eadb0df7a62f385e5edba92dd6e22b6dc9779a3a67f81218e8f161fb5f79b7);
// Call sites track the seedCovered/filter signatures and the
// file is gofmt-clean; assertions are untouched. Do not weaken —
// extend in the B1/B2/B3 tests beside them.
package detector

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Defensive invariant: a rejected duplicate cannot replace the provenance
// of an accepted entry with a span outside the verified bytes.
func TestReviewDuplicateCoveredCannotAuthorizeOutsideProof(t *testing.T) {
	var log bytes.Buffer
	g := newPubGate(&log)
	m := &zipScanTarget{source: &fileScanTarget{path: "inert.bin"}, zipOffset: 100, zipSize: 500}
	key := coverKeyOf(m)
	kept, dropped, _ := g.seedCovered([]string{key + "|rootext=0-10", key + "|rootext=100-600"}, [][2]int64{{0, 20}})
	t.Logf("kept=%d dropped=%d retained_span=%v", len(kept), len(dropped), g.seedSpan[key])
	if g.deferCovered(m) {
		t.Fatalf("member deferred although its actual span [100,600) was rejected outside verified [0,20); log=%q", log.String())
	}
}

type reviewFirstOpenError struct {
	*fileScanTarget
	opens int
}

func (s *reviewFirstOpenError) Open() (TargetReader, error) {
	s.opens++
	if s.opens == 1 {
		return nil, fmt.Errorf("injected transient verification open failure")
	}
	return s.fileScanTarget.Open()
}

func TestReviewVerificationOpenFailureRestarts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "source.bin")
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, 32768), 0600); err != nil {
		t.Fatal(err)
	}
	ckpt := filepath.Join(dir, "source.cp")
	const point = 16384
	writeCheckpoint(nil, ckpt, path, point, nil, testIdent(path), mustProof(t, path, 0, point))
	seed := &reviewFirstOpenError{fileScanTarget: &fileScanTarget{path: path, startOffset: point}}
	jc := &journalCtl{digest: newBatchDigest()}
	var log bytes.Buffer
	got := adoptResume(Options{CheckpointPath: ckpt, Resume: true, Log: &log}, seed, jc, newPubGate(&log))
	f, err := got.Open()
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	t.Logf("verification adopted=%v; opens=%d; retry succeeds; returned start=%d; log=%q", jc.adopted, seed.opens, got.StartOffset(), log.String())
	if !jc.adopted && got.StartOffset() > 0 {
		t.Fatal("failed verification leaves an unverified nonzero start that a successful root retry will honor")
	}
}

func TestReviewResumeUnreadableJournalDoesNotSkip(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		t.Run(fmt.Sprintf("malformed=%v", malformed), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "source.bin")
			raw := bytes.Repeat([]byte{'x'}, 32768)
			copy(raw[100:], "bestblock")
			copy(raw[24000:], "defaultkey")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			ckpt := filepath.Join(dir, "source.cp")
			if malformed {
				if err := os.WriteFile(ckpt, []byte("{invalid"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			casePath := filepath.Join(dir, "case.jsonl")
			var log bytes.Buffer
			head := false
			err := ScanWithOptions(16384, path, Options{CheckpointPath: ckpt, Resume: true, CaseLogPath: casePath, Log: &log}, func(d Detection) {
				if d.Offset == 100 {
					head = true
				}
			}, nil)
			recs := readCaseLog(t, casePath)
			t.Logf("scan_err=%v head_observed=%v case_records=%+v log=%q", err, head, recs, log.String())
			if err == nil && !head {
				t.Fatal("Resume=true with an unreadable journal silently succeeds from the caller's nonzero start")
			}
		})
	}
}
