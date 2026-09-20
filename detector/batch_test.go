package detector

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testBatchRun() BatchRun {
	return BatchRun{Profile: "p", CarveDir: "c", Context: 8, JSON: true, Reveal: true, Baseline: "b", CaseLog: "l"}
}

func TestMatchBatchManifestOK(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.bin")
	b := filepath.Join(dir, "b.bin")
	if err := os.WriteFile(a, []byte("aaa"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("bbb"), 0644); err != nil {
		t.Fatal(err)
	}
	run := testBatchRun()
	m := NewBatchManifest([]string{a, b}, run)
	m.Targets[0].State = BatchComplete
	m.Targets[1].State = BatchActive
	m.Targets[1].Offset = 1 << 20
	cp := ManifestSnapshot(m)
	got, err := MatchBatchManifest(cp, []string{a, b}, run)
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	if len(got.Targets) != 2 || got.Targets[0].State != BatchComplete || got.Targets[1].Offset != 1<<20 {
		t.Fatalf("matched manifest lost state: %+v", got.Targets)
	}
}

func TestMatchBatchManifestRefusals(t *testing.T) {
	run := testBatchRun()
	mkcp := func(targets []BatchTarget, run *BatchRun) Checkpoint {
		return Checkpoint{Path: "x", Targets: targets, Run: run}
	}
	id := BatchTarget{Path: "a", Size: 3, Mtime: 1, State: BatchPending}
	runp := run
	cases := []struct {
		name    string
		cp      Checkpoint
		targets []string
		run     BatchRun
	}{
		{"legacy", Checkpoint{Path: "a", Offset: 5}, []string{"a"}, run},
		{"length", mkcp([]BatchTarget{id}, &runp), []string{"a", "b"}, run},
		{"order", mkcp([]BatchTarget{id, {Path: "b", Size: 1, Mtime: 1, State: BatchPending}}, &runp), []string{"b", "a"}, run},
		{"norun", mkcp([]BatchTarget{id}, nil), []string{"a"}, run},
		{"profile", mkcp([]BatchTarget{id}, &runp), []string{"a"}, BatchRun{Profile: "q", CarveDir: "c", Context: 8, JSON: true, Reveal: true, Baseline: "b", CaseLog: "l"}},
		{"carvedir", mkcp([]BatchTarget{id}, &runp), []string{"a"}, BatchRun{Profile: "p", CarveDir: "d", Context: 8, JSON: true, Reveal: true, Baseline: "b", CaseLog: "l"}},
		{"json", mkcp([]BatchTarget{id}, &runp), []string{"a"}, BatchRun{Profile: "p", CarveDir: "c", Context: 8, Baseline: "b", CaseLog: "l"}},
	}
	for _, c := range cases {
		if _, err := MatchBatchManifest(c.cp, c.targets, c.run); err == nil {
			t.Errorf("%s: matched, want refusal", c.name)
		}
	}
}

func TestBatchIdentityMatches(t *testing.T) {
	known := BatchTarget{Path: "a", Size: 10, Mtime: 5, State: BatchActive}
	if !BatchIdentityMatches(known, 10, 5) {
		t.Error("identical identity did not match")
	}
	if BatchIdentityMatches(known, 11, 5) || BatchIdentityMatches(known, 10, 6) {
		t.Error("changed identity matched")
	}
	unknown := BatchTarget{Path: "a", Size: -1, State: BatchActive}
	if BatchIdentityMatches(unknown, -1, 0) {
		t.Error("unknown identity matched")
	}
}

func TestNextCarveSeq(t *testing.T) {
	if got := NextCarveSeq(filepath.Join(t.TempDir(), "missing")); got != 1 {
		t.Errorf("missing dir: got %d, want 1", got)
	}
	dir := t.TempDir()
	touch := func(name string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	touch("hit-000003.bin")
	touch("hit-000003.json")
	touch("hit-000007.salvage.db")
	touch("notes.txt")
	touch("hit-nope.bin")
	if got := NextCarveSeq(dir); got != 8 {
		t.Errorf("got %d, want 8", got)
	}
	// A resumed run numbering from NextCarveSeq-1 must not collide
	// with the pre-kill carves already on disk.
	if got := NextCarveSeq(t.TempDir()); got != 1 {
		t.Errorf("empty dir: got %d, want 1", got)
	}
}

func TestWriteFrontierAdoptsDigest(t *testing.T) {
	dir := t.TempDir()
	ckpt := filepath.Join(dir, "ckpt.json")
	const digest = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	m := NewBatchManifest([]string{"a"}, testBatchRun())
	m.Targets[0].State = BatchActive
	opts := Options{CheckpointPath: ckpt, BatchJournal: m}
	writeFrontier(opts, &pendingFrontier{desc: "a", offset: 10})
	cp, err := ReadCheckpoint(ckpt)
	if err != nil {
		t.Fatal(err)
	}
	if cp.Targets[0].Offset != 10 || cp.Targets[0].SHA256 != "" {
		t.Fatalf("mid-run point journals offset only, got %+v", cp.Targets[0])
	}
	writeFrontier(opts, &pendingFrontier{desc: "a", offset: 20, digest: digest})
	cp, err = ReadCheckpoint(ckpt)
	if err != nil {
		t.Fatal(err)
	}
	if cp.Targets[0].Offset != 20 || cp.Targets[0].SHA256 != digest {
		t.Fatalf("completion journals offset+digest, got %+v", cp.Targets[0])
	}
}

func TestVerifyBatchDigest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.bin")
	content := []byte("bestblock-bytes")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	want := hex.EncodeToString(sum[:])
	if err := VerifyBatchDigest(path, int64(len(content)), want); err != nil {
		t.Errorf("valid digest: %v", err)
	}
	if err := VerifyBatchDigest(path, int64(len(content)), strings.Repeat("0", 64)); err == nil {
		t.Error("mismatch verified")
	}
	if err := VerifyBatchDigest(path, int64(len(content)+1), want); err == nil {
		t.Error("short file verified")
	}
	if err := VerifyBatchDigest(filepath.Join(t.TempDir(), "missing"), 1, want); err == nil {
		t.Error("missing file verified")
	}
	if err := VerifyBatchDigest(path, int64(len(content)), ""); err == nil {
		t.Error("empty digest verified")
	}
}

func TestManifestSnapshotLegacyFields(t *testing.T) {
	run := testBatchRun()
	m := NewBatchManifest([]string{"a"}, run)
	m.Targets[0].State = BatchActive
	m.Targets[0].Offset = 1 << 20
	cp := ManifestSnapshot(m)
	if cp.Offset != 0 {
		t.Errorf("legacy offset %d, want 0 so old binaries rescan", cp.Offset)
	}
	if cp.Path != "a" {
		t.Errorf("legacy path %q, want first target", cp.Path)
	}
	if cp.Run == nil || cp.Run.Profile != "p" {
		t.Errorf("run binding lost: %+v", cp.Run)
	}
}
