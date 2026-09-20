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

// Progress lines carry throughput and ETA once two samples exist.
func TestProgressReporterShowsRateAndETA(t *testing.T) {
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	defer func() { os.Stderr = old }()

	p := &progressReporter{interval: -1} // report every sample
	p.onProgress(detector.ProgressInfo{CurrentTarget: "d", ScannedBytes: 100 << 20, TotalBytes: 1000 << 20})
	time.Sleep(10 * time.Millisecond)
	p.onProgress(detector.ProgressInfo{CurrentTarget: "d", ScannedBytes: 200 << 20, TotalBytes: 1000 << 20})
	w.Close()
	os.Stderr = old

	raw, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	out := string(raw)
	for _, want := range []string{"%", "MB/s", "ETA"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected progress output to contain %q, got:\n%s", want, out)
		}
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
