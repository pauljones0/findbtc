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

// Resume=true without a readable journal restarts at zero with a
// warning (B3) — missing, malformed, and inaccessible journals
// must never silently authorize a caller skip. Without Resume,
// the same unreadable journal beside an explicit start stays an
// explicit caller assertion (fresh journaled runs stay quiet).
func TestResumeUnreadableJournalRestarts(t *testing.T) {
	mkSource := func(t *testing.T) (string, string) {
		t.Helper()
		dir := t.TempDir()
		path := filepath.Join(dir, "source.bin")
		raw := bytes.Repeat([]byte{'x'}, 32<<10)
		copy(raw[100:], "bestblock")
		copy(raw[24000:], "defaultkey")
		if err := os.WriteFile(path, raw, 0644); err != nil {
			t.Fatal(err)
		}
		return path, filepath.Join(dir, "source.cp")
	}
	scan := func(t *testing.T, start int64, path, ckpt string, resume bool) (bool, string) {
		t.Helper()
		var log bytes.Buffer
		head := false
		err := ScanWithOptions(start, path, Options{CheckpointPath: ckpt, Resume: resume, Log: &log},
			func(d Detection) {
				if d.Offset == 100 {
					head = true
				}
			}, nil)
		if err != nil {
			t.Fatalf("scan: %v\n%s", err, log.String())
		}
		return head, log.String()
	}
	const start = 16 << 10
	t.Run("missing journal restarts loudly", func(t *testing.T) {
		path, ckpt := mkSource(t)
		head, log := scan(t, start, path, ckpt, true)
		if !head {
			t.Fatal("Resume with a missing journal skipped the head: silent suffix-only success")
		}
		if !strings.Contains(log, "cannot read checkpoint") || !strings.Contains(log, "starting from the beginning") {
			t.Fatalf("must warn unreadable journal + restart, got:\n%s", log)
		}
	})
	t.Run("malformed journal restarts loudly", func(t *testing.T) {
		path, ckpt := mkSource(t)
		if err := os.WriteFile(ckpt, []byte("{invalid"), 0644); err != nil {
			t.Fatal(err)
		}
		head, log := scan(t, start, path, ckpt, true)
		if !head {
			t.Fatal("Resume with a malformed journal skipped the head: silent suffix-only success")
		}
		if !strings.Contains(log, "cannot read checkpoint") {
			t.Fatalf("must warn unreadable journal, got:\n%s", log)
		}
	})
	t.Run("inaccessible journal restarts loudly", func(t *testing.T) {
		path, ckpt := mkSource(t)
		if err := os.WriteFile(ckpt, []byte("{}"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(ckpt, 0000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(ckpt, 0644) })
		if f, err := os.Open(ckpt); err == nil {
			f.Close()
			t.Skip("platform reads chmod-000 files (Windows/root)")
		}
		head, log := scan(t, start, path, ckpt, true)
		if !head {
			t.Fatal("Resume with an inaccessible journal skipped the head: silent suffix-only success")
		}
		if !strings.Contains(log, "cannot read checkpoint") {
			t.Fatalf("must warn unreadable journal, got:\n%s", log)
		}
	})
	t.Run("resume without a journal path restarts loudly", func(t *testing.T) {
		path, _ := mkSource(t)
		head, log := scan(t, start, path, "", true)
		if !head {
			t.Fatal("Resume without a checkpoint path skipped the head: silent suffix-only success")
		}
		if !strings.Contains(log, "without a checkpoint path") {
			t.Fatalf("must warn missing journal path, got:\n%s", log)
		}
	})
	t.Run("explicit start without resume stays quiet", func(t *testing.T) {
		path, ckpt := mkSource(t)
		head, log := scan(t, start, path, ckpt, false)
		if head {
			t.Fatal("explicit caller start must be honored, not restarted")
		}
		if strings.Contains(log, "cannot read checkpoint") || strings.Contains(log, "WARNING") {
			t.Fatalf("fresh journaled run must stay quiet, got:\n%s", log)
		}
	})
}

// A zero-point journal authorizes nothing (F1): under Resume a
// nonzero start continues no journal point and restarts loudly —
// whether the point carries the tool-filed empty-span proof or a
// legacy nil proof. At start zero the empty-span point adopts
// its nothing quietly; the nil-proof point warns its legacy
// shape and proceeds.
func TestResumeZeroPointJournalRestarts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "zero.bin")
	raw := bytes.Repeat([]byte{'x'}, 32<<10)
	copy(raw[100:], "bestblock")
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	emptySHA := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	scan := func(t *testing.T, start int64, proof *PrefixProof) (bool, string) {
		t.Helper()
		ckpt := filepath.Join(dir, "zero.cp")
		writeCheckpoint(nil, ckpt, path, 0, nil, testIdent(path), proof)
		var log bytes.Buffer
		head := false
		if err := ScanWithOptions(start, path, Options{CheckpointPath: ckpt, Resume: true, Log: &log},
			func(d Detection) {
				if d.Offset == 100 {
					head = true
				}
			}, nil); err != nil {
			t.Fatalf("scan from %d: %v\n%s", start, err, log.String())
		}
		return head, log.String()
	}
	for _, arm := range []struct {
		name  string
		proof *PrefixProof
	}{
		{"tool-filed empty-span proof", &PrefixProof{Version: ProofVersion, Start: 0, Len: 0, SHA256: emptySHA}},
		{"legacy nil proof", nil},
	} {
		t.Run(arm.name+" restarts a nonzero start loudly", func(t *testing.T) {
			head, log := scan(t, 16<<10, arm.proof)
			if !head {
				t.Fatal("Resume with a zero-point journal skipped the head: silent suffix-only success")
			}
			if !strings.Contains(log, "starting from the beginning") && !strings.Contains(log, "rescanning from the start") {
				t.Fatalf("must warn restart, got:\n%s", log)
			}
		})
	}
	t.Run("empty-span point adopts nothing quietly at zero", func(t *testing.T) {
		head, log := scan(t, 0, &PrefixProof{Version: ProofVersion, Start: 0, Len: 0, SHA256: emptySHA})
		if !head {
			t.Fatal("start zero must scan the head")
		}
		if strings.Contains(log, "WARNING") {
			t.Fatalf("nothing skipped, nothing owed: must stay quiet, got:\n%s", log)
		}
	})
	t.Run("nil-proof point warns its shape at zero", func(t *testing.T) {
		head, log := scan(t, 0, nil)
		if !head {
			t.Fatal("start zero must scan the head")
		}
		if !strings.Contains(log, "predates content proofs") {
			t.Fatalf("legacy zero point must warn its shape, got:\n%s", log)
		}
	})
}

// A batch journal with no active entry authorizes no skip for a
// whole-file run (F2): under Resume a nonzero start continues no
// journal point and restarts loudly. Without Resume the explicit
// start stands quietly.
func TestResumeBatchNoActiveEntryRestarts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "alldone.bin")
	raw := bytes.Repeat([]byte{'x'}, 32<<10)
	copy(raw[100:], "bestblock")
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	ckpt := filepath.Join(dir, "alldone.cp")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	fileAllComplete := func(t *testing.T) {
		t.Helper()
		WriteBatchJournal(nil, ckpt, Checkpoint{
			Path: path,
			Run:  &BatchRun{},
			Targets: []BatchTarget{{
				Path:   path,
				Size:   fi.Size(),
				Mtime:  fi.ModTime().Unix(),
				State:  BatchComplete,
				Offset: int64(len(raw)),
				Ident:  testIdent(path),
				Proof:  mustProof(t, path, 0, int64(len(raw))),
			}},
		})
	}
	scan := func(t *testing.T, resume bool) (bool, string) {
		t.Helper()
		// Each scan files fresh: a completed run overwrites
		// the journal it resumed from.
		fileAllComplete(t)
		var log bytes.Buffer
		head := false
		if err := ScanWithOptions(16<<10, path, Options{CheckpointPath: ckpt, Resume: resume, Log: &log},
			func(d Detection) {
				if d.Offset == 100 {
					head = true
				}
			}, nil); err != nil {
			t.Fatalf("scan (resume=%v): %v\n%s", resume, err, log.String())
		}
		return head, log.String()
	}
	t.Run("resume restarts loudly", func(t *testing.T) {
		head, log := scan(t, true)
		if !head {
			t.Fatal("Resume with no active entry skipped the head: silent suffix-only success")
		}
		if !strings.Contains(log, "no active entry") {
			t.Fatalf("must warn no active entry, got:\n%s", log)
		}
	})
	t.Run("explicit start stands quietly", func(t *testing.T) {
		head, log := scan(t, false)
		if head {
			t.Fatal("explicit caller start must be honored, not restarted")
		}
		if strings.Contains(log, "WARNING") {
			t.Fatalf("explicit start with no journal case must stay quiet, got:\n%s", log)
		}
	})
}

// The banked-members warning fires only when banked bytes really
// re-scan (N2): on honored-start mismatch paths the journal is
// ignored and its members dropped, so claiming a re-scan lies.
func TestBankedMembersWarningOnlyOnRescan(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.bin")
	raw := bytes.Repeat([]byte{'x'}, 32<<10)
	copy(raw[100:], "bestblock")
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	ckpt := filepath.Join(dir, "a.cp")
	other := filepath.Join(dir, "b.bin")
	scan := func(t *testing.T, resume bool) (bool, string) {
		t.Helper()
		// A journal for another path with banked members:
		// nothing in it can seed this scan. Filed fresh per
		// scan: a completed run overwrites its journal.
		writeCheckpoint(nil, ckpt, other, 16<<10,
			[]string{"member|rootext=0-100"}, testIdent(path), mustProof(t, path, 0, 16<<10))
		var log bytes.Buffer
		head := false
		if err := ScanWithOptions(16<<10, path, Options{CheckpointPath: ckpt, Resume: resume, Log: &log},
			func(d Detection) {
				if d.Offset == 100 {
					head = true
				}
			}, nil); err != nil {
			t.Fatalf("scan (resume=%v): %v\n%s", resume, err, log.String())
		}
		return head, log.String()
	}
	t.Run("honored start drops the warning", func(t *testing.T) {
		head, log := scan(t, false)
		if head {
			t.Fatal("explicit caller start must be honored")
		}
		if !strings.Contains(log, "journal ignored") {
			t.Fatalf("mismatch must say the journal is ignored, got:\n%s", log)
		}
		if strings.Contains(log, "banked members re-scanned") {
			t.Fatalf("dropped members must not claim a re-scan, got:\n%s", log)
		}
	})
	t.Run("restart keeps the warning", func(t *testing.T) {
		head, log := scan(t, true)
		if !head {
			t.Fatal("Resume mismatch must restart at zero")
		}
		if !strings.Contains(log, "banked members re-scanned") {
			t.Fatalf("restart must warn the re-scan, got:\n%s", log)
		}
	})
}

// A verification open failure refuses loudly and restarts (B2):
// returning the original nonzero seed would let a later
// successful root open honor an offset never proven. Transient
// failure restarts at zero with a warning and seeds nothing;
// zero start stays at zero but still warns (verification was
// attempted and errored); persistent failure reaches the root
// read and errors with a case-log record.
func TestAdoptResumeOpenFailureRestarts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "openfail.bin")
	raw := bytes.Repeat([]byte{'x'}, 32<<10)
	copy(raw[100:], "bestblock")
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	const point = 16 << 10
	ckpt := filepath.Join(dir, "openfail.cp")
	writeCheckpoint(nil, ckpt, path, point, nil, testIdent(path), mustProof(t, path, 0, point))
	adopt := func(start int64) (scanTarget, *journalCtl, string, *reviewFirstOpenError) {
		t.Helper()
		seed := &reviewFirstOpenError{fileScanTarget: &fileScanTarget{path: path, startOffset: start}}
		jc := &journalCtl{digest: newBatchDigest()}
		var log bytes.Buffer
		got := adoptResume(Options{CheckpointPath: ckpt, Resume: true, Log: &log}, seed, jc, newPubGate(&log))
		return got, jc, log.String(), seed
	}
	t.Run("transient failure restarts with no seeded state", func(t *testing.T) {
		got, jc, log, seed := adopt(point)
		if got.StartOffset() != 0 {
			t.Fatalf("start = %d, want 0 (unverified offset must not survive)", got.StartOffset())
		}
		if !strings.Contains(log, "cannot open") || !strings.Contains(log, "rescanning from the start") {
			t.Fatalf("must warn cannot-open + rescan, got:\n%s", log)
		}
		if jc.adopted {
			t.Fatal("adopted after failed verification")
		}
		if jc.preopened != nil {
			t.Fatal("verified handle preserved after failed verification")
		}
		// The retry the probe models now opens at zero: full
		// coverage, not an honored skip.
		f, err := got.Open()
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		if seed.opens != 2 {
			t.Fatalf("opens = %d, want 2 (failed verify + root retry)", seed.opens)
		}
	})
	t.Run("zero start warns and stays at zero", func(t *testing.T) {
		// A sub-overlap journal point continues at run start
		// 0 (rewind(0, point) == 0), so the claim builds and
		// the open failure hits the verification path.
		const tiny = 512
		tinyCkpt := filepath.Join(dir, "tiny.cp")
		writeCheckpoint(nil, tinyCkpt, path, tiny, nil, testIdent(path), mustProof(t, path, 0, tiny))
		seed := &reviewFirstOpenError{fileScanTarget: &fileScanTarget{path: path}}
		jc := &journalCtl{digest: newBatchDigest()}
		var log bytes.Buffer
		got := adoptResume(Options{CheckpointPath: tinyCkpt, Resume: true, Log: &log}, seed, jc, newPubGate(&log))
		if got.StartOffset() != 0 {
			t.Fatalf("start = %d, want 0", got.StartOffset())
		}
		if !strings.Contains(log.String(), "cannot open") {
			t.Fatalf("zero-start verification failure must still warn, got:\n%s", log.String())
		}
		if jc.adopted || jc.preopened != nil {
			t.Fatal("failed verification seeded state")
		}
	})
	t.Run("persistent failure errors with a case record", func(t *testing.T) {
		noperm := filepath.Join(dir, "noperm.bin")
		if err := os.WriteFile(noperm, raw, 0644); err != nil {
			t.Fatal(err)
		}
		nocp := filepath.Join(dir, "noperm.cp")
		writeCheckpoint(nil, nocp, noperm, point, nil, testIdent(noperm), mustProof(t, noperm, 0, point))
		if err := os.Chmod(noperm, 0000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(noperm, 0644) })
		if f, err := os.Open(noperm); err == nil {
			f.Close()
			t.Skip("platform reads chmod-000 files (Windows/root)")
		}
		casePath := filepath.Join(dir, "case.jsonl")
		var log bytes.Buffer
		err := ScanWithOptions(point, noperm,
			Options{CheckpointPath: nocp, CaseLogPath: casePath, ToolVersion: "test", Resume: true, Log: &log},
			func(Detection) {}, nil)
		if err == nil {
			t.Fatalf("unreadable root must error, got nil\n%s", log.String())
		}
		if !strings.Contains(log.String(), "cannot open") {
			t.Fatalf("must warn cannot-open, got:\n%s", log.String())
		}
		recs := readCaseLog(t, casePath)
		if len(recs) != 1 || recs[0].Status == "complete" {
			t.Fatalf("case records = %+v, want one non-complete record", recs)
		}
	})
}

// Caller-driven resume (doc.go: ReadCheckpoint, pass the offset
// back, Options.Resume unset) must honor the "rescanning from
// the start" promise when the journal point is unprovable: a
// legacy journal, a proof shorter than the filed offset, and a
// foreign-span proof (an explicit -s skip, never proven bytes)
// all restart at zero with a warning. Only a start that
// continues no journal point is an explicit caller assertion,
// silently honored with no rescan.
func TestCallerResumeRefusedShapesRescan(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caller.bin")
	const size = 64 << 10
	const point = 32 << 10
	raw := bytes.Repeat([]byte{'x'}, size)
	copy(raw[100:], "bestblock")
	copy(raw[40<<10:], "defaultkey")
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	scan := func(start int64, ckpt string) ([]Detection, string) {
		t.Helper()
		var log bytes.Buffer
		var dets []Detection
		if err := ScanWithOptions(start, path, Options{CheckpointPath: ckpt, Log: &log},
			func(d Detection) { dets = append(dets, d) }, nil); err != nil {
			t.Fatalf("scan from %d: %v\n%s", start, err, log.String())
		}
		return dets, log.String()
	}
	head := func(dets []Detection) bool {
		for _, d := range dets {
			if d.Offset == 100 {
				return true
			}
		}
		return false
	}
	file := func(name string, proof *PrefixProof) string {
		t.Helper()
		ckpt := filepath.Join(dir, name)
		writeCheckpoint(nil, ckpt, path, point, nil, testIdent(path), proof)
		return ckpt
	}
	for _, arm := range []struct {
		name  string
		proof *PrefixProof
		want  string
	}{
		{"legacy journal", nil, "predates content proofs"},
		{"short proof", mustProof(t, path, 0, point/2), "shorter than the journaled offset"},
		{"foreign span", mustProof(t, path, point, size-point), "never proven bytes"},
	} {
		t.Run(arm.name, func(t *testing.T) {
			dets, log := scan(point, file(arm.name+".ckpt", arm.proof))
			if !strings.Contains(log, arm.want) || !strings.Contains(log, "rescanning from the start") {
				t.Fatalf("must warn %q + rescan, got:\n%s", arm.want, log)
			}
			if !head(dets) {
				t.Fatalf("head needle lost: warning promised a rescan but start %d was honored (got %d detections)", point, len(dets))
			}
		})
	}
	t.Run("explicit start elsewhere silently honored", func(t *testing.T) {
		const start = 20 << 10
		if start == point || start == rewindOffset(0, point) {
			t.Fatalf("start %d continues the journal point %d; pick another", start, point)
		}
		dets, log := scan(start, file("valid.ckpt", mustProof(t, path, 0, point)))
		if strings.Contains(log, "rescan") || strings.Contains(log, "WARNING") {
			t.Fatalf("explicit caller start must stay silent, got:\n%s", log)
		}
		if head(dets) {
			t.Fatal("explicit start honored must not re-report the head needle")
		}
		if len(dets) == 0 {
			t.Fatal("explicit start honored must still scan the tail")
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
// A filed cover span asserts a member's TRUE bytes: it is not
// enough for the span to sit inside verified bytes. A journal
// that banks a member under a span the rediscovered member does
// not occupy (a hand edit, or a stale key after target bytes
// moved) must re-read the member with a warning — silently
// deferring it would skip bytes never read. An honest span that
// merely sits outside verified bytes re-reads through the
// existing dropped-seed path with no mismatch warning.
func TestFiledCoverSpanMismatchRereads(t *testing.T) {
	var mbuf bytes.Buffer
	w := gzip.NewWriter(&mbuf)
	if _, err := w.Write([]byte("bestblock-deep")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	const memberAt = 15 << 10
	const size = 32 << 10
	raw := bytes.Repeat([]byte{'x'}, size)
	copy(raw[memberAt:], mbuf.Bytes())
	dir := t.TempDir()
	path := filepath.Join(dir, "span.bin")
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	// The real banked key, built from the real constructors: the
	// forgery below differs ONLY in the span. (A wrong base key
	// could never defer, so the warning assertion below guards
	// the test against its own key drift.)
	base := coverKeyOf(&gzipScanTarget{source: &fileScanTarget{path: path}, gzipOffset: memberAt})
	const point = 8 << 10
	ckpt := filepath.Join(dir, "span.cp")
	writeCheckpoint(nil, ckpt, path, point,
		[]string{fmt.Sprintf("%s%s0-100", base, rootExtSuffix)},
		testIdent(path), mustProof(t, path, 0, point))
	var log bytes.Buffer
	nested := 0
	if err := ScanWithOptions(point, path, Options{CheckpointPath: ckpt, Log: &log},
		func(d Detection) {
			if d.Target != path {
				nested++
			}
		}, nil); err != nil {
		t.Fatalf("resume: %v\n%s", err, log.String())
	}
	if nested == 0 {
		t.Fatal("member silently deferred under a span it does not occupy: 0 nested hits vs 1 on a fresh scan")
	}
	if !strings.Contains(log.String(), "provenance span") || !strings.Contains(log.String(), "re-scanned") {
		t.Fatalf("span mismatch must warn, got:\n%s", log.String())
	}
}

// A journal that files one member under two spans drops the
// member entirely (B1): conflicting provenance has no unique
// span to retain, so the member re-reads with a conflict
// warning — never defers under either span.
func TestFiledCoverConflictsRereadLoudly(t *testing.T) {
	var mbuf bytes.Buffer
	w := gzip.NewWriter(&mbuf)
	if _, err := w.Write([]byte("bestblock-deep")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	const memberAt = 15 << 10
	const size = 32 << 10
	raw := bytes.Repeat([]byte{'x'}, size)
	copy(raw[memberAt:], mbuf.Bytes())
	dir := t.TempDir()
	path := filepath.Join(dir, "dup.bin")
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	base := coverKeyOf(&gzipScanTarget{source: &fileScanTarget{path: path}, gzipOffset: memberAt})
	const point = 8 << 10
	ckpt := filepath.Join(dir, "dup.cp")
	writeCheckpoint(nil, ckpt, path, point,
		[]string{
			fmt.Sprintf("%s%s0-100", base, rootExtSuffix),
			fmt.Sprintf("%s%s%d-%d", base, rootExtSuffix, memberAt, memberAt+100),
		},
		testIdent(path), mustProof(t, path, 0, point))
	var log bytes.Buffer
	nested := 0
	if err := ScanWithOptions(point, path, Options{CheckpointPath: ckpt, Log: &log},
		func(d Detection) {
			if d.Target != path {
				nested++
			}
		}, nil); err != nil {
		t.Fatalf("resume: %v\n%s", err, log.String())
	}
	if nested == 0 {
		t.Fatal("conflicted member deferred: 0 nested hits vs 1 on a fresh scan")
	}
	if !strings.Contains(log.String(), "conflicting spans") {
		t.Fatalf("conflict must warn precisely, got:\n%s", log.String())
	}
	if strings.Contains(log.String(), "outside verified bytes") {
		t.Fatalf("conflict must not misreport as outside-verified, got:\n%s", log.String())
	}
}

func TestGzipProvenanceConverges(t *testing.T) {
	old := maxOutstandingPubs
	defer func() { maxOutstandingPubs = old }()
	maxOutstandingPubs = 1

	// Attempt-1 congestion here is timing-based with a wide
	// margin, not synchronized: cap slots release when
	// scanBlocks RECEIVES a target, but its loop then blocks
	// reading that member's bulk bytes, so the back-to-back
	// members' publishes (microseconds apart) pile onto the
	// outstanding count and refuse. A producer stall spanning
	// the millisecond read window would admit everything and
	// fail the attempt-1 congestion assertion below; endangered
	// only in theory (10/10 at GOMAXPROCS=8 plus every gate
	// run). What the test proves regardless of interleaving:
	// same-cap retries converge, every member is covered, every
	// filed span is valid, and nested hits emit exactly once.
	// Process restart is the kill tests' contract, not this one's.
	gzMember := func(t *testing.T, tag string) []byte {
		t.Helper()
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		if _, err := w.Write([]byte(tag)); err != nil {
			t.Fatal(err)
		}
		// Bulk zeros: milliseconds to read through the
		// single scanBlocks loop, microseconds to discover
		// (compressed bytes stay tiny). Zeros carry no needle.
		if _, err := w.Write(make([]byte, 8<<20)); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	var raw []byte
	var members [][]byte
	for i := 0; i < 4; i++ {
		m := gzMember(t, fmt.Sprintf("bestblock-%d", i))
		members = append(members, m)
		raw = append(raw, m...)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "four.gz")
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	ckpt := filepath.Join(dir, "gz.cp")
	nested := func(d Detection) bool { return d.Target != path }
	// Triples, not pairs: one member read emits its whole
	// trailing multistream (member 0's stream carries all four
	// tags), so (target, needle) repeats within a single honest
	// read. A repeated TRIPLE, though, is a re-read of banked
	// bytes — the replay this pins against.
	seen := map[string]bool{}
	emitted := 0
	note := func(d Detection) {
		if nested(d) {
			emitted++
			seen[fmt.Sprintf("%s/%s/%d", d.Target, d.Needle, d.Offset)] = true
		}
	}

	var log1 bytes.Buffer
	err := ScanWithOptions(0, path, Options{Log: &log1, CheckpointPath: ckpt},
		func(d Detection) { note(d) }, func(ProgressInfo) {})
	if err == nil || !strings.Contains(err.Error(), "incomplete coverage") {
		t.Fatalf("attempt 1: want congestion error, got %v\n%s", err, log1.String())
	}
	cp, err := ReadCheckpoint(ckpt)
	if err != nil {
		t.Fatal(err)
	}
	if len(cp.Covered) < 1 {
		t.Fatalf("attempt 1 covered = %v, want at least one admitted member", cp.Covered)
	}
	// Every banked span starts at a real member offset, covers
	// at least its member's compressed bytes (plus bounded
	// reader readahead), and stays inside the stream.
	starts := map[int64]int64{}
	var off int64
	for _, m := range members {
		starts[off] = off + int64(len(m))
		off += int64(len(m))
	}
	for _, k := range cp.Covered {
		_, s, e, ok := coverProvenance(k)
		if !ok {
			t.Fatalf("banked gzip key has no provenance: %q", k)
		}
		minEnd, known := starts[s]
		if !known || e < minEnd || e > int64(len(raw)) {
			t.Fatalf("gzip span = %d-%d, want a member start with end inside [member end, %d]", s, e, len(raw))
		}
	}
	// Same-cap retries defer the banked members and admit the
	// refused ones, converging to clean completion whatever
	// each attempt's admitted/refused split is.
	complete := false
	start := cp.Offset
	for attempt := 2; attempt <= 5; attempt++ {
		var lb bytes.Buffer
		err = ScanWithOptions(start, path, Options{Log: &lb, CheckpointPath: ckpt},
			func(d Detection) { note(d) }, func(ProgressInfo) {})
		cp, rerr := ReadCheckpoint(ckpt)
		if rerr != nil {
			t.Fatalf("attempt %d: journal unreadable: %v\n%s", attempt, rerr, lb.String())
		}
		start = cp.Offset
		if err == nil {
			complete = true
			break
		}
		if !strings.Contains(err.Error(), "incomplete coverage") {
			t.Fatalf("attempt %d: error = %v, want honest incomplete-coverage signal\n%s", attempt, err, lb.String())
		}
	}
	if !complete {
		t.Fatalf("same-cap retries never completed in 5 attempts; unique %d/10 — retries replay instead of converging", len(seen))
	}
	// Four members multistream to 4+3+2+1 = 10 triples: every
	// member covered through its own read.
	if len(seen) != 10 {
		t.Fatalf("unique nested triples = %d, want 10 (every member covered)", len(seen))
	}
	if emitted != len(seen) {
		t.Fatalf("nested emitted = %d but unique = %d: a banked member re-read instead of deferring", emitted, len(seen))
	}
}
