package detector

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyCaseLogMatch(t *testing.T) {
	dir := t.TempDir()
	rawPath := filepath.Join(dir, "v.bin")
	payload := bytes.Repeat([]byte{0x5A}, 50*1024)
	if err := os.WriteFile(rawPath, payload, 0644); err != nil {
		t.Fatal(err)
	}
	ewfRaw := bytes.Repeat([]byte{0}, 64*1024)
	e01 := buildEWF(t, dir, "v", ewfRaw, ewfBuildOpt{sectorsPerChunk: 8})
	logPath := filepath.Join(dir, "case.jsonl")
	opts := Options{CaseLogPath: logPath, ToolVersion: "test"}
	noop := func(ProgressInfo) {}
	if err := ScanWithOptions(0, rawPath, opts, func(Detection) {}, noop); err != nil {
		t.Fatal(err)
	}
	if err := ScanWithOptions(0, e01, opts, func(Detection) {}, noop); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := VerifyCaseLog(logPath, &out); err != nil {
		t.Fatalf("verify failed: %s\n%s", err, out.String())
	}
	if got := out.String(); !strings.Contains(got, "record 1: OK") || !strings.Contains(got, "record 2: OK") {
		t.Fatalf("output:\n%s", got)
	}
}

// Flipping one source byte after the scan must fail verification.
func TestVerifyCaseLogTamper(t *testing.T) {
	dir := t.TempDir()
	rawPath := filepath.Join(dir, "t.bin")
	if err := os.WriteFile(rawPath, bytes.Repeat([]byte{0x11}, 32*1024), 0644); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "case.jsonl")
	if err := ScanWithOptions(0, rawPath, Options{CaseLogPath: logPath, ToolVersion: "test"},
		func(Detection) {}, func(ProgressInfo) {}); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(rawPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte{0xFF}, 1000); err != nil {
		t.Fatal(err)
	}
	f.Close()
	var out bytes.Buffer
	if err := VerifyCaseLog(logPath, &out); err == nil {
		t.Fatal("tampered source verified clean")
	} else if !strings.Contains(out.String(), "MISMATCH") {
		t.Fatalf("no MISMATCH in:\n%s", out.String())
	}
}

// Corrupting an E01 segment after the scan must fail verification.
func TestVerifyCaseLogEWFTamper(t *testing.T) {
	dir := t.TempDir()
	e01 := buildEWF(t, dir, "te", bytes.Repeat([]byte{0x22}, 64*1024),
		ewfBuildOpt{sectorsPerChunk: 8, compress: func(int) bool { return false }})
	logPath := filepath.Join(dir, "case.jsonl")
	if err := ScanWithOptions(0, e01, Options{CaseLogPath: logPath, ToolVersion: "test"},
		func(Detection) {}, func(ProgressInfo) {}); err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(e01)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt deep in the sectors data: chunk checksums must catch it.
	blob[len(blob)-2000] ^= 0xff
	if err := os.WriteFile(e01, blob, 0644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := VerifyCaseLog(logPath, &out); err == nil {
		t.Fatal("tampered E01 verified clean")
	}
}

// Skipped ranges are excluded from the re-hash, not hashed as zeros.
func TestVerifyCaseLogSkipped(t *testing.T) {
	dir := t.TempDir()
	rawPath := filepath.Join(dir, "s.bin")
	payload := bytes.Repeat([]byte{0x77}, 20*1024)
	if err := os.WriteFile(rawPath, payload, 0644); err != nil {
		t.Fatal(err)
	}
	// Hash of everything except [5000, 9000), as a scan with one
	// bad-sector skip would record.
	var kept []byte
	kept = append(kept, payload[:5000]...)
	kept = append(kept, payload[9000:]...)
	rec := CaseLog{
		Tool:   "findbtc",
		Status: "complete",
		Source: CaseSource{Path: rawPath, Kind: "raw", Size: int64(len(payload))},
		Hash: CaseHash{SHA256: hexSHA256(kept), MD5: hexMD5(kept),
			BytesHashed: int64(len(kept))},
		Skipped: []CaseSkipped{{Target: rawPath, Start: 5000, End: 9000, Error: "x"}},
	}
	line, _ := json.Marshal(rec)
	logPath := filepath.Join(dir, "case.jsonl")
	if err := os.WriteFile(logPath, append(line, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := VerifyCaseLog(logPath, &out); err != nil {
		t.Fatalf("verify failed: %s\n%s", err, out.String())
	}
}

func TestVerifyCaseLogMissingSource(t *testing.T) {
	dir := t.TempDir()
	rec := CaseLog{
		Tool:   "findbtc",
		Status: "complete",
		Source: CaseSource{Path: filepath.Join(dir, "gone.bin"), Kind: "raw", Size: 10},
	}
	line, _ := json.Marshal(rec)
	logPath := filepath.Join(dir, "case.jsonl")
	if err := os.WriteFile(logPath, append(line, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := VerifyCaseLog(logPath, &out); err == nil {
		t.Fatal("missing source verified clean")
	} else if !strings.Contains(out.String(), "MISMATCH") {
		t.Fatalf("no MISMATCH in:\n%s", out.String())
	}
}

// Zero-coverage attempt records are evidence of failure, not hash
// claims: the verifier reports them as NOT SCANNED without failing,
// beside the OK lines for completed records.
func TestVerifyCaseLogAttemptNeutral(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "a.bin")
	if err := os.WriteFile(target, []byte("0123456789"), 0644); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "case.jsonl")
	missing := filepath.Join(dir, "gone.bin")
	if err := ScanWithOptions(0, target,
		Options{CaseLogPath: logPath, ToolVersion: "test"},
		func(Detection) {}, func(ProgressInfo) {}); err != nil {
		t.Fatal(err)
	}
	if err := ScanWithOptions(0, missing,
		Options{CaseLogPath: logPath, ToolVersion: "test"},
		func(Detection) {}, func(ProgressInfo) {}); err == nil {
		t.Fatal("missing target scanned clean")
	}
	var out bytes.Buffer
	if err := VerifyCaseLog(logPath, &out); err != nil {
		t.Fatalf("log with an attempt record must verify: %v\n%s", err, out.String())
	}
	text := out.String()
	if !strings.Contains(text, "OK "+target) {
		t.Errorf("completed record lost its OK line:\n%s", text)
	}
	if !strings.Contains(text, "NOT SCANNED "+missing) {
		t.Errorf("attempt record needs a NOT SCANNED line:\n%s", text)
	}
	if strings.Contains(text, "MISMATCH") {
		t.Errorf("attempt record must not mismatch:\n%s", text)
	}
}
