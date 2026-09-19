//go:build linux

package detector_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pauljones0/findbtc/detector"
)

func countOpen(t *testing.T, path string) int {
	t.Helper()
	n := 0
	entries, _ := os.ReadDir("/proc/self/fd")
	for _, e := range entries {
		if target, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name())); err == nil && strings.Contains(target, path) {
			n++
		}
	}
	return n
}

func TestScanClosesSourceFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "leak.zip")
	if err := os.WriteFile(path, makeZip(t, "a.txt", padHidden("padding bestblock padding")), 0644); err != nil {
		t.Fatal(err)
	}
	if err := detector.Scan(0, path, func(detector.Detection) {}, func(detector.ProgressInfo) {}); err != nil {
		t.Fatal(err)
	}
	if n := countOpen(t, "leak.zip"); n != 0 {
		t.Fatalf("%d open handles to %s after Scan", n, path)
	}
}
