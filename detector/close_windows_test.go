//go:build windows

package detector_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pauljones0/findbtc/detector"
)

// After Scan returns, the source file must already be closed: Windows
// refuses to delete open files, so a lingering handle fails the remove.
// The completion signal races the close, so repeat to catch regressions.
func TestScanClosesSourceFile(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 20; i++ {
		path := filepath.Join(dir, "close.bin")
		if err := os.WriteFile(path, makeZip(t, "a.txt", padHidden("padding bestblock padding")), 0644); err != nil {
			t.Fatal(err)
		}
		if err := detector.Scan(0, path, func(detector.Detection) {}, func(detector.ProgressInfo) {}); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatalf("iteration %d: source still open after Scan: %s", i, err)
		}
	}
}
