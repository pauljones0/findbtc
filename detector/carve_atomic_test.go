package detector

import (
	"os"
	"path/filepath"
	"testing"
)

// Atomic carve outputs commit whole files: content lands exactly,
// no staging litter survives, and reaps only touch our prefix.
func TestWriteFileAtomicRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := writeFileAtomic(dir, "hit-000001.bin", []byte("bytes")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "hit-000001.bin"))
	if err != nil || string(raw) != "bytes" {
		t.Fatalf("round trip: %q, %v", raw, err)
	}
	if n := CleanCarveTemps(dir); n != 0 {
		t.Errorf("reaped %d, want 0 (nothing staged)", n)
	}
	// Overwrite commits too (fresh run into a dirty dir).
	if err := writeFileAtomic(dir, "hit-000001.bin", []byte("new")); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(filepath.Join(dir, "hit-000001.bin"))
	if string(raw) != "new" {
		t.Errorf("overwrite left %q", raw)
	}
}

func TestCleanCarveTemps(t *testing.T) {
	dir := t.TempDir()
	keep := filepath.Join(dir, "hit-000001.bin")
	if err := os.WriteFile(keep, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(dir, carveTempPrefix+"12345")
	if err := os.WriteFile(stale, []byte("torn"), 0644); err != nil {
		t.Fatal(err)
	}
	if n := CleanCarveTemps(dir); n != 1 {
		t.Errorf("reaped %d, want 1", n)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("real carve reaped: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("staging file survives: %v", err)
	}
	if n := CleanCarveTemps(filepath.Join(dir, "missing")); n != 0 {
		t.Errorf("missing dir reaped %d, want 0", n)
	}
}
