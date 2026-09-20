package detector

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readCaseLog(t *testing.T, path string) []CaseLog {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var logs []CaseLog
	for _, line := range bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n")) {
		var l CaseLog
		if err := json.Unmarshal(line, &l); err != nil {
			t.Fatalf("bad case-log line %q: %s", line, err)
		}
		logs = append(logs, l)
	}
	return logs
}

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hexMD5(b []byte) string {
	sum := md5.Sum(b)
	return hex.EncodeToString(sum[:])
}

// A full raw scan is logged with exact streaming hashes and counts.
func TestCaseLogRawScan(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "case.bin")
	buf := bytes.Repeat([]byte{0}, 100*1024)
	copy(buf[5000:], " "+fuzzyExact12+" ")
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "case.jsonl")
	var dets int
	err := ScanWithOptions(0, path, Options{CaseLogPath: logPath, ToolVersion: "test",
		Flags: []string{"-json", "-case-log", logPath, path}, CheckpointPath: filepath.Join(dir, "cp.json")},
		func(Detection) { dets++ }, func(ProgressInfo) {})
	if err != nil {
		t.Fatal(err)
	}
	if dets != 1 {
		t.Fatalf("got %d detections, want 1", dets)
	}
	logs := readCaseLog(t, logPath)
	if len(logs) != 1 {
		t.Fatalf("got %d records, want 1", len(logs))
	}
	l := logs[0]
	if l.Tool != "findbtc" || l.Version != "test" || l.Status != "complete" {
		t.Fatalf("identity/status %+v", l)
	}
	if l.Source.Kind != "raw" || l.Source.Size != int64(len(buf)) || l.Source.StartOffset != 0 {
		t.Fatalf("source %+v", l.Source)
	}
	if l.Hash.SHA256 != hexSHA256(buf) || l.Hash.MD5 != hexMD5(buf) {
		t.Fatal("streaming hashes do not match source bytes")
	}
	if l.Hash.BytesHashed != int64(len(buf)) {
		t.Fatalf("bytes_hashed %d, want %d", l.Hash.BytesHashed, len(buf))
	}
	if l.Detections != 1 || len(l.Skipped) != 0 || l.EWF != nil {
		t.Fatalf("counts %+v", l)
	}
	if len(l.Flags) != 4 || l.Flags[0] != "-json" {
		t.Fatalf("flags %+v", l.Flags)
	}
	if l.Source.Checkpoint == "" || !strings.HasSuffix(l.Source.Checkpoint, "cp.json") {
		t.Fatalf("checkpoint %q", l.Source.Checkpoint)
	}
}

// A resumed scan hashes only the bytes it read; the record says where.
func TestCaseLogStartOffset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resume.bin")
	buf := bytes.Repeat([]byte{0xAB}, 60*1024)
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "case.jsonl")
	err := ScanWithOptions(1000, path, Options{CaseLogPath: logPath, ToolVersion: "test"},
		func(Detection) {}, func(ProgressInfo) {})
	if err != nil {
		t.Fatal(err)
	}
	l := readCaseLog(t, logPath)[0]
	if l.Source.StartOffset != 1000 {
		t.Fatalf("start_offset %d", l.Source.StartOffset)
	}
	if l.Hash.SHA256 != hexSHA256(buf[1000:]) {
		t.Fatal("hash does not cover exactly the resumed bytes")
	}
	if l.Hash.BytesHashed != int64(len(buf))-1000 {
		t.Fatalf("bytes_hashed %d", l.Hash.BytesHashed)
	}
}

// An E01 scan cross-checks decoded bytes against the stored MD5.
func TestCaseLogEWF(t *testing.T) {
	dir := t.TempDir()
	raw := bytes.Repeat([]byte{0}, 96*1024)
	copy(raw[5000:], " "+fuzzyExact12+" ")
	e01 := buildEWF(t, dir, "case", raw, ewfBuildOpt{sectorsPerChunk: 4})
	logPath := filepath.Join(dir, "case.jsonl")
	var dets int
	err := ScanWithOptions(0, e01, Options{CaseLogPath: logPath, ToolVersion: "test"},
		func(Detection) { dets++ }, func(ProgressInfo) {})
	if err != nil {
		t.Fatal(err)
	}
	if dets != 1 {
		t.Fatalf("got %d detections, want 1", dets)
	}
	l := readCaseLog(t, logPath)[0]
	if l.Source.Kind != "ewf" {
		t.Fatalf("kind %q", l.Source.Kind)
	}
	if l.Hash.SHA256 != hexSHA256(raw) || l.Hash.BytesHashed != int64(len(raw)) {
		t.Fatal("streaming hash does not match decoded media")
	}
	if l.EWF == nil || l.EWF.StoredMD5 != hexMD5(raw) {
		t.Fatalf("ewf record %+v", l.EWF)
	}
	if l.EWF.MD5Match == nil || !*l.EWF.MD5Match {
		t.Fatal("stored MD5 should match decoded bytes")
	}
}

// caseFailReader fails every read touching [failStart, failEnd), like a
// disk defect that survives retries.
type caseFailReader struct {
	data      []byte
	pos       int64
	failStart int64
	failEnd   int64
}

var errCaseDefect = errors.New("simulated defect")

func (r *caseFailReader) fail(off int64) bool { return off >= r.failStart && off < r.failEnd }

func (r *caseFailReader) Read(p []byte) (int, error) {
	if r.pos >= int64(len(r.data)) {
		return 0, io.EOF
	}
	if r.fail(r.pos) {
		return 0, errCaseDefect
	}
	n := copy(p, r.data[r.pos:])
	r.pos += int64(n)
	return n, nil
}

func (r *caseFailReader) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(r.data)) {
		return 0, io.EOF
	}
	if r.fail(off) {
		return 0, errCaseDefect
	}
	n := copy(p, r.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (r *caseFailReader) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		r.pos = offset
	case io.SeekCurrent:
		r.pos += offset
	case io.SeekEnd:
		r.pos = int64(len(r.data)) + offset
	}
	return r.pos, nil
}

func (r *caseFailReader) Close() error { return nil }

type caseFailTarget struct {
	name      string
	data      []byte
	failStart int64
	failEnd   int64
}

func (t *caseFailTarget) Describe() string   { return t.name }
func (t *caseFailTarget) StartOffset() int64 { return 0 }
func (t *caseFailTarget) Depth() int         { return 0 }
func (t *caseFailTarget) Size() (int64, error) {
	return int64(len(t.data)), nil
}
func (t *caseFailTarget) Open() (TargetReader, error) {
	return &caseFailReader{data: t.data, failStart: t.failStart, failEnd: t.failEnd}, nil
}

// Unreadable ranges are skipped, excluded from the hash, and recorded.
func TestCaseLogBadSector(t *testing.T) {
	data := bytes.Repeat([]byte{0xCD}, 40*1024)
	badStart := int64(2 * blockSize)
	seed := &caseFailTarget{name: "defect.img", data: data, failStart: badStart, failEnd: badStart + blockSize}
	var chained int
	logPath := filepath.Join(t.TempDir(), "case.jsonl")
	err := runPipeline(seed,
		Options{CaseLogPath: logPath, ToolVersion: "test",
			OnBadSector: func(string, int64, int64, error) { chained++ }},
		func(Detection) {}, func(ProgressInfo) {})
	if err != nil {
		t.Fatal(err)
	}
	if chained != 1 {
		t.Fatalf("user OnBadSector chained %d times, want 1", chained)
	}
	l := readCaseLog(t, logPath)[0]
	if l.Status != "complete" {
		t.Fatalf("status %q", l.Status)
	}
	if len(l.Skipped) != 1 {
		t.Fatalf("skipped %+v", l.Skipped)
	}
	s := l.Skipped[0]
	if s.Target != "defect.img" || s.Start != badStart || s.End != badStart+blockSize {
		t.Fatalf("skipped %+v", s)
	}
	if !strings.Contains(s.Error, "simulated defect") {
		t.Fatalf("skipped error %q", s.Error)
	}
	var hashed []byte
	hashed = append(hashed, data[:badStart]...)
	hashed = append(hashed, data[badStart+blockSize:]...)
	if l.Hash.SHA256 != hexSHA256(hashed) {
		t.Fatal("hash covers other than the readable bytes")
	}
	if l.Hash.BytesHashed != int64(len(hashed)) {
		t.Fatalf("bytes_hashed %d, want %d", l.Hash.BytesHashed, len(hashed))
	}
}

// Each scan appends; a range scan leaves one record per range.
func TestCaseLogAppends(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.bin")
	if err := os.WriteFile(path, bytes.Repeat([]byte{1}, 8192), 0644); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "case.jsonl")
	opts := Options{CaseLogPath: logPath, ToolVersion: "test"}
	noop := func(ProgressInfo) {}
	if err := ScanWithOptions(0, path, opts, func(Detection) {}, noop); err != nil {
		t.Fatal(err)
	}
	if err := ScanWithOptions(0, path, opts, func(Detection) {}, noop); err != nil {
		t.Fatal(err)
	}
	if logs := readCaseLog(t, logPath); len(logs) != 2 {
		t.Fatalf("got %d records, want 2", len(logs))
	}
}

func TestCaseLogRangeKind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "r.bin")
	buf := bytes.Repeat([]byte{7}, 16384)
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "case.jsonl")
	err := ScanRangesWithOptions(path, []FSExtent{{Start: 100, Len: 5000}},
		Options{CaseLogPath: logPath, ToolVersion: "test"},
		func(Detection) {}, func(ProgressInfo) {})
	if err != nil {
		t.Fatal(err)
	}
	l := readCaseLog(t, logPath)[0]
	if l.Source.Kind != "range" {
		t.Fatalf("kind %q", l.Source.Kind)
	}
	if l.Hash.SHA256 != hexSHA256(buf[100:5100]) || l.Hash.BytesHashed != 5000 {
		t.Fatal("range hash mismatch")
	}
}

// A scan that never starts still leaves exactly one record: the
// attempted path with status error, zero bytes, and no digests —
// never invented coverage, never zero records.
func TestCaseLogFailedAttempt(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "case.jsonl")
	missing := filepath.Join(dir, "gone.bin")
	err := ScanWithOptions(0, missing,
		Options{CaseLogPath: logPath, ToolVersion: "test"},
		func(Detection) {}, func(ProgressInfo) {})
	if err == nil {
		t.Fatal("missing target scanned clean")
	}
	recs := readCaseLog(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want exactly 1 attempt record, got %d", len(recs))
	}
	rec := recs[0]
	if rec.Status != "error" {
		t.Errorf("status %q, want error", rec.Status)
	}
	if rec.Source.Path != missing {
		t.Errorf("path %q, want %q", rec.Source.Path, missing)
	}
	if rec.Source.Kind != "unknown" {
		t.Errorf("kind %q, want unknown", rec.Source.Kind)
	}
	if rec.Hash.BytesHashed != 0 || rec.Hash.SHA256 != "" || rec.Hash.MD5 != "" {
		t.Errorf("attempt invents coverage: %+v", rec.Hash)
	}
	if !strings.Contains(rec.Error, missing) {
		t.Errorf("attempt must carry the reason, got %q", rec.Error)
	}
	if rec.Detections != 0 {
		t.Errorf("detections %d, want 0", rec.Detections)
	}
}

// A broken case log cannot hide the outcome: the append failure
// joins the scan error instead of replacing it.
func TestCaseLogAttemptAppendError(t *testing.T) {
	dir := t.TempDir()
	// A directory as the log path makes every append fail.
	logPath := filepath.Join(dir, "is-a-dir")
	if err := os.Mkdir(logPath, 0755); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "gone.bin")
	err := ScanWithOptions(0, missing,
		Options{CaseLogPath: logPath, ToolVersion: "test"},
		func(Detection) {}, func(ProgressInfo) {})
	if err == nil {
		t.Fatal("missing target scanned clean")
	}
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("outcome hidden, got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "unwritable") {
		t.Errorf("append failure hidden, got %q", err.Error())
	}
}
