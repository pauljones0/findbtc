package main

import (
	"io"
	"os"
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
