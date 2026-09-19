package detector

import (
	"os"
	"path/filepath"
	"testing"
)

// Nil scan callbacks are no-ops at every public entry point: library
// callers pass nil for streams they ignore.
func TestNilCallbacksIgnored(t *testing.T) {
	dir := t.TempDir()
	raw := filepath.Join(dir, "raw.bin")
	buf := make([]byte, 8192)
	copy(buf[100:], "bestblock")
	if err := os.WriteFile(raw, buf, 0644); err != nil {
		t.Fatal(err)
	}
	if err := ScanWithOptions(0, raw, Options{}, nil, nil); err != nil {
		t.Errorf("ScanWithOptions with nil callbacks: %v", err)
	}
	if err := Scan(0, raw, nil, nil); err != nil {
		t.Errorf("Scan with nil callbacks: %v", err)
	}
	if err := ScanRangesWithOptions(raw, []FSExtent{{Start: 0, Len: 8192}}, Options{}, nil, nil); err != nil {
		t.Errorf("ScanRangesWithOptions with nil callbacks: %v", err)
	}
	if _, err := Walk(dir, WalkOptions{}, nil, nil); err != nil {
		t.Errorf("Walk with nil callbacks: %v", err)
	}
	ext := buildTestExt(t)
	if _, err := ScanFSVolumes(ext, 0, false, Options{}, nil, nil, nil); err != nil {
		t.Errorf("ScanFSVolumes with nil callbacks: %v", err)
	}
	if _, err := ScanFS(ext, 0, Options{}, nil, nil, nil); err != nil {
		t.Errorf("ScanFS with nil callbacks: %v", err)
	}
}
