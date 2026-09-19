package detector

// Baseline tests (Goal 29): fingerprints survive the edit patterns
// that move raw offsets (append, insert-above, rewrite) while new or
// changed secret lines still report.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// baselineSweep walks root and returns detections plus stats.
func baselineSweep(t *testing.T, root string, baseline map[string]bool) ([]Detection, WalkStats) {
	t.Helper()
	var dets []Detection
	stats, err := Walk(root, WalkOptions{Scan: Options{Profile: "secrets"}, Baseline: baseline},
		func(d Detection) { dets = append(dets, d) }, func(ProgressInfo) {})
	if err != nil {
		t.Fatal(err)
	}
	return dets, stats
}

// writeBaselineFile serializes dets as a hits.jsonl baseline on disk,
// exercising the real LoadBaselineFingerprints path.
func writeBaselineFile(t *testing.T, dets []Detection) map[string]bool {
	t.Helper()
	path := filepath.Join(t.TempDir(), "baseline.jsonl")
	var sb strings.Builder
	for _, d := range dets {
		raw, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		sb.Write(raw)
		sb.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(sb.String()), 0644); err != nil {
		t.Fatal(err)
	}
	keys, err := LoadBaselineFingerprints(path)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

const baselineSecretLine = "aws_key = AKIAIOSFODNN7EXAMPLE"

// A repo file with one accepted secret line: the baseline records it,
// and the three edit patterns keep it suppressed.
func TestBaselineSurvivesEdits(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "config.py")
	first := "# config\n" + baselineSecretLine + "\n# end\n"
	if err := os.WriteFile(file, []byte(first), 0644); err != nil {
		t.Fatal(err)
	}
	dets, _ := baselineSweep(t, dir, nil)
	if len(dets) != 1 || dets[0].Fingerprint == "" {
		t.Fatalf("first sweep = %+v, want 1 fingerprinted hit", dets)
	}
	if !strings.HasPrefix(dets[0].Fingerprint, "v1/config.py/aws-access-key/") {
		t.Errorf("fingerprint %q must key relpath + needle", dets[0].Fingerprint)
	}
	keys := writeBaselineFile(t, dets)
	if len(keys) != 1 {
		t.Fatalf("baseline keys = %d, want 1", len(keys))
	}

	edits := map[string]string{
		// New lines after the secret.
		"append": first + "# more\n# more\n",
		// New lines above move the raw offset.
		"insert-above": "# new header\n# another\n" + first,
		// Rewrite around the untouched secret line.
		"rewrite": "# rewritten\n" + baselineSecretLine + "\n",
	}
	for name, content := range edits {
		if err := os.WriteFile(file, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		dets, stats := baselineSweep(t, dir, keys)
		if len(dets) != 0 || stats.SuppressedBaseline != 1 {
			t.Errorf("%s: reported %d, suppressed %d; want 0/1", name, len(dets), stats.SuppressedBaseline)
		}
	}
}

// A new secret of the same type in the same file is a different line:
// it must report despite the baseline.
func TestBaselineNewSecretReports(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "config.py")
	if err := os.WriteFile(file, []byte(baselineSecretLine+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	dets, _ := baselineSweep(t, dir, nil)
	keys := writeBaselineFile(t, dets)
	second := baselineSecretLine + "\naws_key2 = AKIAI44QH8DHBEXAMPLE\n"
	if err := os.WriteFile(file, []byte(second), 0644); err != nil {
		t.Fatal(err)
	}
	dets, stats := baselineSweep(t, dir, keys)
	if len(dets) != 1 || stats.SuppressedBaseline != 1 {
		t.Fatalf("reported %d, suppressed %d; want 1/1", len(dets), stats.SuppressedBaseline)
	}
	if !strings.Contains(dets[0].Fingerprint, "aws-access-key") {
		t.Errorf("new hit lacks a fingerprint: %+v", dets[0])
	}
}

// Rotating the secret changes the line: the old key stays silent
// (it no longer matches anything) and the new line reports.
func TestBaselineRotatedSecretReports(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "config.py")
	if err := os.WriteFile(file, []byte(baselineSecretLine+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	dets, _ := baselineSweep(t, dir, nil)
	keys := writeBaselineFile(t, dets)
	if err := os.WriteFile(file, []byte("aws_key = AKIAI44QH8DHBEXAMPLE\n"), 0644); err != nil {
		t.Fatal(err)
	}
	dets, stats := baselineSweep(t, dir, keys)
	if len(dets) != 1 || stats.SuppressedBaseline != 0 {
		t.Errorf("reported %d, suppressed %d; want 1/0", len(dets), stats.SuppressedBaseline)
	}
}

// Baseline entries without fingerprints (other modes, old sidecars)
// match nothing and break nothing.
func TestBaselineSkipsUnfingerprinted(t *testing.T) {
	keys, err := LoadBaselineFingerprints("testdata/baseline_mixed.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || !keys["v1/a.txt/aws-access-key/0123456789abcdef"] {
		t.Errorf("keys = %v, want only the fingerprinted entry", keys)
	}
	if _, err := LoadBaselineFingerprints(filepath.Join(t.TempDir(), "missing.jsonl")); err == nil {
		t.Error("missing baseline file must error loudly")
	}
}
