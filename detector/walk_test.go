package detector

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Goal 13: directory-tree sweeps. Fixture trees are built in TempDir;
// TestWalkSelfScanRepo sweeps this repository itself.

const walkProse = "the quick brown fox jumps over the lazy dog\n" +
	"pack my box with five dozen liquor jugs\n" +
	"sphinx of black quartz judge my vow\n"

const walkLeak = "notes: rotate the bestblock and orderposnext reminders\n"

func writeWalkFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func collectWalk(t *testing.T, root string, wopts WalkOptions) (WalkStats, []Detection) {
	t.Helper()
	var dets []Detection
	stats, err := Walk(root, wopts, func(d Detection) { dets = append(dets, d) }, func(ProgressInfo) {})
	if err != nil {
		t.Fatalf("Walk(%s): %v", root, err)
	}
	return stats, dets
}

func TestWalkFindsNeedleSilentOnProse(t *testing.T) {
	root := t.TempDir()
	writeWalkFile(t, filepath.Join(root, "prose.txt"), walkProse)
	writeWalkFile(t, filepath.Join(root, "leak.txt"), walkLeak)
	writeWalkFile(t, filepath.Join(root, "sub", "nested.txt"), "residue defaultkey tail\n")
	stats, dets := collectWalk(t, root, WalkOptions{})
	if stats.Files != 3 {
		t.Errorf("Files=%d, want 3", stats.Files)
	}
	if stats.FailedTotal != 0 {
		t.Errorf("FailedTotal=%d, want 0 (%+v)", stats.FailedTotal, stats.Failed)
	}
	seen := map[string]int{}
	for _, d := range dets {
		seen[filepath.Base(d.Target)]++
	}
	if seen["leak.txt"] == 0 || seen["nested.txt"] == 0 {
		t.Errorf("needle files not found: %v", seen)
	}
	if seen["prose.txt"] != 0 {
		t.Errorf("prose file produced %d detections", seen["prose.txt"])
	}
	for _, d := range dets {
		if !strings.HasPrefix(d.Target, root) {
			t.Errorf("detection target escapes tree: %q", d.Target)
		}
	}
}

func TestWalkSymlinkPolicy(t *testing.T) {
	root := t.TempDir()
	writeWalkFile(t, filepath.Join(root, "leak.txt"), walkLeak)
	if err := os.Symlink("leak.txt", filepath.Join(root, "alias.txt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	loopDir := filepath.Join(root, "loopdir")
	if err := os.Mkdir(loopDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..", filepath.Join(loopDir, "up")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	// Default: no following. The alias is skipped, the loop harmless.
	stats, dets := collectWalk(t, root, WalkOptions{})
	if stats.SkippedSymlinks != 2 {
		t.Errorf("SkippedSymlinks=%d, want 2", stats.SkippedSymlinks)
	}
	if stats.Files != 1 {
		t.Errorf("Files=%d, want 1", stats.Files)
	}
	for _, d := range dets {
		if strings.Contains(d.Target, "alias.txt") {
			t.Errorf("followed symlink by default: %q", d.Target)
		}
	}
	// Opt-in follow: the alias target is scanned once; the dir cycle is
	// recorded and the walk terminates.
	stats, _ = collectWalk(t, root, WalkOptions{FollowSymlinks: true})
	if stats.SkippedSymlinks != 0 {
		t.Errorf("follow mode SkippedSymlinks=%d, want 0", stats.SkippedSymlinks)
	}
	if stats.FailedTotal == 0 {
		t.Error("follow mode must record the directory cycle as a failure")
	} else if !strings.Contains(stats.Failed[0].Err, "cycle") {
		t.Errorf("cycle failure must say so: %+v", stats.Failed[0])
	}
	if _, err := Walk(filepath.Join(root, "alias.txt"), WalkOptions{}, func(Detection) {}, func(ProgressInfo) {}); err == nil {
		t.Error("symlinked root without FollowSymlinks must error loudly")
	}
}

func TestWalkUnreadableIsolated(t *testing.T) {
	root := t.TempDir()
	writeWalkFile(t, filepath.Join(root, "good.txt"), walkLeak)
	bad := filepath.Join(root, "bad.txt")
	writeWalkFile(t, bad, walkLeak)
	if err := os.Chmod(bad, 0000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { os.Chmod(bad, 0644) })
	stats, dets := collectWalk(t, root, WalkOptions{})
	if len(dets) == 0 {
		t.Error("readable file was not scanned alongside the unreadable one")
	}
	if f, err := os.Open(bad); err == nil {
		f.Close() // probe handle must close: on Windows it blocks TempDir cleanup
		t.Log("platform reads chmod-000 files (Windows/root); isolation still held")
		return
	}
	if stats.FailedTotal != 1 {
		t.Errorf("FailedTotal=%d, want 1 (%+v)", stats.FailedTotal, stats.Failed)
	}
}

func TestWalkMaxDepth(t *testing.T) {
	root := t.TempDir()
	writeWalkFile(t, filepath.Join(root, "top.txt"), walkLeak)
	writeWalkFile(t, filepath.Join(root, "sub", "deep.txt"), walkLeak)
	stats, dets := collectWalk(t, root, WalkOptions{MaxDepth: 1})
	if stats.SkippedDepth == 0 {
		t.Error("expected depth pruning")
	}
	for _, d := range dets {
		if strings.Contains(d.Target, "deep.txt") {
			t.Errorf("depth limit breached: %q", d.Target)
		}
	}
	_, dets = collectWalk(t, root, WalkOptions{})
	found := false
	for _, d := range dets {
		found = found || strings.Contains(d.Target, "deep.txt")
	}
	if !found {
		t.Error("unlimited walk must reach deep.txt")
	}
}

func TestWalkOwnOutputSkipped(t *testing.T) {
	root := t.TempDir()
	writeWalkFile(t, filepath.Join(root, "leak.txt"), walkLeak)
	carveDir := filepath.Join(root, "carve")
	writeWalkFile(t, filepath.Join(carveDir, "hit-000000.bin"), walkLeak)
	caseLog := filepath.Join(root, "case.jsonl")
	writeWalkFile(t, caseLog, walkLeak)
	stats, dets := collectWalk(t, root, WalkOptions{Scan: Options{CarveDir: carveDir, CaseLogPath: caseLog}})
	if stats.SkippedOwn < 2 {
		t.Errorf("SkippedOwn=%d, want >=2 (stale carve + case log)", stats.SkippedOwn)
	}
	for _, d := range dets {
		if strings.Contains(d.Target, "carve") || strings.Contains(d.Target, "case.jsonl") {
			t.Errorf("scanned its own output: %q", d.Target)
		}
	}
	// The sweep still carved the real hit next to the stale file.
	matches, _ := filepath.Glob(filepath.Join(carveDir, "hit-*.bin"))
	if len(matches) < 2 {
		t.Errorf("expected stale + fresh carves, got %v", matches)
	}
	if runtime.GOOS == "windows" {
		t.Log("carve counts on Windows use the same sequence")
	}
}

func TestWalkCarveSeqUnique(t *testing.T) {
	root := t.TempDir()
	writeWalkFile(t, filepath.Join(root, "a.txt"), walkLeak)
	writeWalkFile(t, filepath.Join(root, "b.txt"), "residue defaultkey tail\n")
	carveDir := filepath.Join(t.TempDir(), "carve")
	stats, _ := collectWalk(t, root, WalkOptions{Scan: Options{CarveDir: carveDir}})
	matches, _ := filepath.Glob(filepath.Join(carveDir, "hit-*.bin"))
	if int64(len(matches)) != stats.Detections {
		t.Errorf("%d carve files for %d detections: %v", len(matches), stats.Detections, matches)
	}
	seen := map[string]bool{}
	for _, m := range matches {
		if seen[m] {
			t.Errorf("duplicate carve %q", m)
		}
		seen[m] = true
	}
}

func TestWalkRefusesCheckpoint(t *testing.T) {
	_, err := Walk(t.TempDir(), WalkOptions{Scan: Options{CheckpointPath: "c"}},
		func(Detection) {}, func(ProgressInfo) {})
	if err == nil || !strings.Contains(err.Error(), "checkpoint") {
		t.Errorf("checkpointed walk must refuse, got %v", err)
	}
}

func TestWalkBadRoot(t *testing.T) {
	if _, err := Walk(filepath.Join(t.TempDir(), "missing"), WalkOptions{},
		func(Detection) {}, func(ProgressInfo) {}); err == nil {
		t.Error("missing root must error")
	}
}

// TestWalkSelfScanRepo sweeps this repository: the documented fixture
// needles must show up, and needle-free prose/code (LICENSE, main.go)
// must stay silent. README.md and GOALS.md intentionally name needle
// labels, so hits there are expected and counted, not failures.
func TestWalkSelfScanRepo(t *testing.T) {
	if testing.Short() {
		t.Skip("self-scan needs the full tree; skipped in -short mode")
	}
	stats, dets := collectWalk(t, "..", WalkOptions{})
	if stats.Files == 0 {
		t.Fatal("self-scan found no files")
	}
	fixture := false
	docHits := 0
	for _, d := range dets {
		base := filepath.Base(d.Target)
		if strings.Contains(d.Target, "test_wallet.dat") {
			fixture = true
		}
		switch base {
		case "LICENSE", "main.go":
			t.Errorf("needle-free file %q produced a detection: %+v", d.Target, d)
		case "README.md", "GOALS.md":
			docHits++
		}
	}
	if !fixture {
		t.Error("self-scan missed the documented test_wallet.dat needles")
	}
	if docHits == 0 {
		t.Error("expected the documented needle mentions in README/GOALS to register")
	}
	t.Logf("self-scan: %d files, %d detections (%d doc mentions), %d failures",
		stats.Files, stats.Detections, docHits, stats.FailedTotal)
}
