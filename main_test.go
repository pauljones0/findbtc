package main

import (
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/pauljones0/findbtc/detector"
)

// The module path is the SBOM identity and the go install address: pin it.
func TestModulePath(t *testing.T) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("no build info available")
	}
	if want := "github.com/pauljones0/findbtc"; info.Main.Path != want {
		t.Fatalf("module path = %q, want %q", info.Main.Path, want)
	}
}

func TestFormatETA(t *testing.T) {
	for in, want := range map[time.Duration]string{
		-5 * time.Second:             "0s",
		0:                            "0s",
		45 * time.Second:             "45s",
		90 * time.Second:             "1m30s",
		61 * time.Minute:             "1h1m",
		26 * time.Hour:               "26h0m",
		5*time.Hour + 30*time.Second: "5h0m",
	} {
		if got := formatETA(in); got != want {
			t.Errorf("formatETA(%v) = %q, want %q", in, got, want)
		}
	}
}

// captureProgress runs samples through a reporter with a fake clock,
// advancing now to each sample's time. interval -1 reports every sample.
func captureProgress(t *testing.T, at []time.Time, samples []detector.ProgressInfo) string {
	t.Helper()
	if len(at) != len(samples) {
		t.Fatalf("times/samples mismatch: %d vs %d", len(at), len(samples))
	}
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	defer func() { os.Stderr = old }()

	now := at[0]
	p := &progressReporter{interval: -1, now: func() time.Time { return now }}
	for i, s := range samples {
		now = at[i]
		p.onProgress(s)
	}
	w.Close()
	os.Stderr = old
	raw, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// Progress lines carry throughput and ETA once past the warmup window.
func TestProgressReporterShowsRateAndETA(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	out := captureProgress(t, []time.Time{t0, t0.Add(10 * time.Second)}, []detector.ProgressInfo{
		{CurrentTarget: "d", ScannedBytes: 100 << 20, TotalBytes: 1000 << 20},
		{CurrentTarget: "d", ScannedBytes: 200 << 20, TotalBytes: 1000 << 20},
	})
	for _, want := range []string{"%", "MB/s", "ETA"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected progress output to contain %q, got:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "10.0MB/s") {
		t.Errorf("100MB in 10s must read 10.0MB/s, got:\n%s", out)
	}
}

// Before the warmup window elapses, lines show percent/bytes only —
// sub-second averages would print noise like 0.0MB/s with a wild ETA.
func TestProgressReporterWarmup(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	out := captureProgress(t, []time.Time{t0, t0.Add(time.Second)}, []detector.ProgressInfo{
		{CurrentTarget: "d", ScannedBytes: 100 << 20, TotalBytes: 1000 << 20},
		{CurrentTarget: "d", ScannedBytes: 200 << 20, TotalBytes: 1000 << 20},
	})
	if !strings.Contains(out, "%") {
		t.Fatalf("warmup lines must still show percent, got:\n%s", out)
	}
	for _, banned := range []string{"MB/s", "ETA"} {
		if strings.Contains(out, banned) {
			t.Errorf("warmup lines must not show %q, got:\n%s", banned, out)
		}
	}
}

// A slowing scan shows a RISING ETA: the estimate follows the measured
// average, and holding an old low figure would contradict the line's
// own rate. (An earlier clamp blessed the stale figure; the goal's
// progress honesty forbids it.)
func TestProgressReporterETAHonest(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	out := captureProgress(t,
		[]time.Time{t0, t0.Add(10 * time.Second), t0.Add(100 * time.Second)},
		[]detector.ProgressInfo{
			{CurrentTarget: "d", ScannedBytes: 0, TotalBytes: 1000 << 20},
			{CurrentTarget: "d", ScannedBytes: 500 << 20, TotalBytes: 1000 << 20},
			{CurrentTarget: "d", ScannedBytes: 510 << 20, TotalBytes: 1000 << 20},
		})
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 lines, got %d:\n%s", len(lines), out)
	}
	// Fast start: 500MB in 10s → 500MB left at 50MB/s → ETA 10s.
	if !strings.Contains(lines[1], "ETA 10s") {
		t.Errorf("line 2 must show ETA 10s, got: %s", lines[1])
	}
	// Stall after: 490MB left at the measured 5.1MB/s → ~96s, shown
	// honestly instead of the stale 10s.
	if !strings.Contains(lines[2], "ETA 1m36s") {
		t.Errorf("line 3 must show the risen ETA 1m36s, got: %s", lines[2])
	}
}

// A new target restarts the baseline: walk reuses one reporter across
// files, and the next file must not inherit timing. Identity and
// counter resets mark the switch — not the total alone, since
// same-size and unknown-size targets share a TotalBytes.
func TestProgressReporterRetarget(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	out := captureProgress(t,
		[]time.Time{t0, t0.Add(10 * time.Second), t0.Add(20 * time.Second), t0.Add(30 * time.Second)},
		[]detector.ProgressInfo{
			{CurrentTarget: "first.img", ScannedBytes: 100 << 20, TotalBytes: 1000 << 20},
			{CurrentTarget: "first.img", ScannedBytes: 200 << 20, TotalBytes: 1000 << 20},
			// Same total, new target: without identity tracking
			// this line inherits first.img's baseline and prints
			// a negative rate (-4.5MB/s).
			{CurrentTarget: "second.img", ScannedBytes: 10 << 20, TotalBytes: 1000 << 20},
			// Unknown-size targets all share total 0: identity
			// still restarts the baseline.
			{CurrentTarget: "third.img", ScannedBytes: 5 << 20, TotalBytes: 0},
		})
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 4 {
		t.Fatalf("want 4 lines, got %d:\n%s", len(lines), out)
	}
	// Retarget restarts warmup: percent/bytes only, no inherited rate.
	if lines[2] != "[1.00%]" {
		t.Errorf("same-size retarget must print bare percent, got: %s", lines[2])
	}
	if lines[3] != "[5mb/??mb]" {
		t.Errorf("unknown-size retarget must print bare megabytes, got: %s", lines[3])
	}
}

// A counter reset within one target also restarts the baseline:
// bytes only ever flow forward inside a scan.
func TestProgressReporterCounterReset(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	out := captureProgress(t,
		[]time.Time{t0, t0.Add(10 * time.Second), t0.Add(20 * time.Second)},
		[]detector.ProgressInfo{
			{CurrentTarget: "d", ScannedBytes: 100 << 20, TotalBytes: 1000 << 20},
			{CurrentTarget: "d", ScannedBytes: 200 << 20, TotalBytes: 1000 << 20},
			{CurrentTarget: "d", ScannedBytes: 10 << 20, TotalBytes: 1000 << 20},
		})
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 lines, got %d:\n%s", len(lines), out)
	}
	if lines[2] != "[1.00%]" {
		t.Errorf("counter reset must restart warmup, got: %s", lines[2])
	}
}

// Carve reads behind -tokenlist hits.jsonl must respect the byte budget
// in the read itself: carves bypass the initial LimitReader, so a
// whole-file read before the cap check would let one oversized carve
// OOM first. Small injected limits prove the reader/budget path
// without allocating gigabytes.
func TestReadCarveCapped(t *testing.T) {
	dir := t.TempDir()
	full := filepath.Join(dir, "full.bin")
	if err := os.WriteFile(full, []byte("abcdefgh"), 0644); err != nil {
		t.Fatal(err)
	}
	// Under budget: everything, no overflow.
	kept, overflow, err := readCarveCapped(full, 8)
	if err != nil || overflow || string(kept) != "abcdefgh" {
		t.Fatalf("exact fit: kept=%q overflow=%v err=%v", kept, overflow, err)
	}
	kept, overflow, err = readCarveCapped(full, 20)
	if err != nil || overflow || string(kept) != "abcdefgh" {
		t.Fatalf("headroom: kept=%q overflow=%v err=%v", kept, overflow, err)
	}
	// Over budget: truncated to max, overflow set, never more kept.
	kept, overflow, err = readCarveCapped(full, 5)
	if err != nil || !overflow || string(kept) != "abcde" {
		t.Fatalf("overflow: kept=%q overflow=%v err=%v", kept, overflow, err)
	}
	// Zero budget: nothing kept, still reports overflow, tiny alloc.
	kept, overflow, err = readCarveCapped(full, 0)
	if err != nil || !overflow || len(kept) != 0 {
		t.Fatalf("zero budget: kept=%q overflow=%v err=%v", kept, overflow, err)
	}
	// Missing file errors instead of returning empty bytes.
	if _, _, err = readCarveCapped(filepath.Join(dir, "absent.bin"), 8); err == nil {
		t.Fatal("missing carve must error")
	}
	// Empty file: no bytes, no overflow, no error.
	empty := filepath.Join(dir, "empty.bin")
	if err := os.WriteFile(empty, nil, 0644); err != nil {
		t.Fatal(err)
	}
	kept, overflow, err = readCarveCapped(empty, 8)
	if err != nil || overflow || len(kept) != 0 {
		t.Fatalf("empty: kept=%q overflow=%v err=%v", kept, overflow, err)
	}
}

// The follow-up crack commands after -hashes must name the right
// hashcat mode per wallet kind: a swapped -m would fail loudly in a
// cracker, but only after the owner trusted our suggestion.
func TestHashCommands(t *testing.T) {
	if cmds := hashCommands(nil); len(cmds) != 0 {
		t.Fatalf("no hashes: cmds = %q", cmds)
	}
	cmds := hashCommands([]detector.CrackHash{
		{Format: "bitcoin-core-mkey"},
		{Format: "ethereum-keystore", KDF: "scrypt"},
		{Format: "ethereum-keystore", KDF: "pbkdf2-hmac-sha256"},
		{Format: "bitcoin-core-mkey"}, // twin dedupes
		{Format: "unknown-thing"},     // ignored
	})
	want := []string{
		"hashcat -m 11300 hashes.txt passwords.txt",
		"hashcat -m 15700 hashes.txt passwords.txt",
		"hashcat -m 15600 hashes.txt passwords.txt",
	}
	if strings.Join(cmds, "\n") != strings.Join(want, "\n") {
		t.Fatalf("cmds = %q\nwant %q", cmds, want)
	}
}
