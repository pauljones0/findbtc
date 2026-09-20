package detector

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// stdinIdentityFixture holds a wallet needle straddling the first
// 4 KiB block edge (overlap exercise) plus a secrets-profile cue, in
// ~12 KiB of filler. All credential material is fake.
func stdinIdentityFixture() []byte {
	buf := bytes.Repeat([]byte("p"), 12288)
	copy(buf[4090:], "wallet.dat")
	copy(buf[9000:], secretAWScue)
	return buf
}

func collectDetections() (*[]Detection, func(Detection)) {
	var dets []Detection
	return &dets, func(d Detection) { dets = append(dets, d) }
}

// A piped scan must find exactly what a file scan of the same bytes
// finds: same offsets, same needles, same count — only the Target
// label differs ("stdin" vs the path). Covers both profiles and a
// nonzero start offset.
func TestStdinFileIdentity(t *testing.T) {
	fixture := stdinIdentityFixture()
	file := filepath.Join(t.TempDir(), "pipe.bin")
	if err := os.WriteFile(file, fixture, 0644); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, profile := range []string{"", "secrets"} {
		for _, start := range []int64{0, 7} {
			opts := Options{Profile: profile, Log: io.Discard}
			fileDets, fileCollect := collectDetections()
			var fileProg []ProgressInfo
			fileOpts := opts
			if err := ScanWithOptions(start, file, fileOpts, fileCollect, func(p ProgressInfo) {
				fileProg = append(fileProg, p)
			}); err != nil {
				t.Fatalf("profile %q start %d file scan: %v", profile, start, err)
			}
			stdinDets, stdinCollect := collectDetections()
			var stdinProg []ProgressInfo
			stdinOpts := opts
			if err := ScanStdinWithOptions(bytes.NewReader(fixture), start, stdinOpts, stdinCollect, func(p ProgressInfo) {
				stdinProg = append(stdinProg, p)
			}); err != nil {
				t.Fatalf("profile %q start %d stdin scan: %v", profile, start, err)
			}
			for i := range stdinProg {
				stdinProg[i].CurrentTarget = file
			}
			for i := range fileProg {
				fileProg[i].CurrentTarget = file
			}
			if !reflect.DeepEqual(stdinProg, fileProg) {
				t.Fatalf("profile %q start %d: stdin progress diverges from file:\nstdin: %#v\nfile:  %#v",
					profile, start, stdinProg, fileProg)
			}
			if len(*fileDets) == 0 {
				t.Fatalf("profile %q start %d: file scan found nothing; fixture is vacuous", profile, start)
			}
			if len(*stdinDets) != len(*fileDets) {
				t.Fatalf("profile %q start %d: stdin found %d detections, file found %d",
					profile, start, len(*stdinDets), len(*fileDets))
			}
			norm := make([]Detection, len(*stdinDets))
			copy(norm, *stdinDets)
			for i := range norm {
				if norm[i].Target != StdinTargetName {
					t.Fatalf("profile %q start %d: detection %d targets %q, want %q",
						profile, start, i, norm[i].Target, StdinTargetName)
				}
				norm[i].Target = file
				// Description embeds the same label ("at <target> in ... block").
				norm[i].Description = strings.Replace(norm[i].Description,
					"at "+StdinTargetName+" in", "at "+file+" in", 1)
			}
			if !reflect.DeepEqual(norm, *fileDets) {
				t.Fatalf("profile %q start %d: stdin detections differ from file:\nstdin: %#v\nfile:  %#v",
					profile, start, norm, *fileDets)
			}
			counts[profile] = len(*fileDets)
		}
	}
	if counts["secrets"] <= counts[""] {
		t.Fatalf("secrets profile found %d detections vs %d default; the AWS cue must add hits",
			counts["secrets"], counts[""])
	}
}

// Hits inside zip/gzip members must match too. Nested labels embed
// the parent ("... in [<parent>]"), so the normalizer maps the
// bracketed parent as well as the root "at <target> in" clause.
func TestStdinArchiveIdentity(t *testing.T) {
	var outer bytes.Buffer
	zw := zip.NewWriter(&outer)
	w, err := zw.Create("inner.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(bytes.Repeat([]byte("z"), 3000)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("wallet.dat")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	var gzipped bytes.Buffer
	gw := gzip.NewWriter(&gzipped)
	if _, err := gw.Write(bytes.Repeat([]byte("g"), 5000)); err != nil {
		t.Fatal(err)
	}
	if _, err := gw.Write([]byte("orderposnext")); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	fixture := append(append(bytes.Repeat([]byte("p"), 1000), outer.Bytes()...),
		append(bytes.Repeat([]byte("p"), 1000), gzipped.Bytes()...)...)
	fixture = append(fixture, bytes.Repeat([]byte("p"), 1000)...)
	file := filepath.Join(t.TempDir(), "archives.bin")
	if err := os.WriteFile(file, fixture, 0644); err != nil {
		t.Fatal(err)
	}
	opts := Options{Log: io.Discard}
	fileDets, fileCollect := collectDetections()
	if err := ScanWithOptions(0, file, opts, fileCollect, nil); err != nil {
		t.Fatalf("file scan: %v", err)
	}
	stdinDets, stdinCollect := collectDetections()
	if err := ScanStdinWithOptions(bytes.NewReader(fixture), 0, opts, stdinCollect, nil); err != nil {
		t.Fatalf("stdin scan: %v", err)
	}
	if len(*fileDets) == 0 {
		t.Fatal("file scan found nothing; archive fixture is vacuous")
	}
	nested := 0
	for _, d := range *fileDets {
		if strings.Contains(d.Target, "in [") {
			nested++
		}
	}
	if nested == 0 {
		t.Fatalf("no nested-member hits; fixture never entered archives: %#v", *fileDets)
	}
	if len(*stdinDets) != len(*fileDets) {
		t.Fatalf("stdin found %d detections, file found %d", len(*stdinDets), len(*fileDets))
	}
	norm := make([]Detection, len(*stdinDets))
	copy(norm, *stdinDets)
	for i := range norm {
		norm[i].Target = strings.ReplaceAll(norm[i].Target, "["+StdinTargetName+"]", "["+file+"]")
		if norm[i].Target == StdinTargetName {
			norm[i].Target = file
		}
		norm[i].Description = strings.ReplaceAll(norm[i].Description, "["+StdinTargetName+"]", "["+file+"]")
		norm[i].Description = strings.Replace(norm[i].Description,
			"at "+StdinTargetName+" in", "at "+file+" in", 1)
	}
	if !reflect.DeepEqual(norm, *fileDets) {
		t.Fatalf("stdin archive detections differ from file:\nstdin: %#v\nfile:  %#v",
			norm, *fileDets)
	}
}

// Carves come from the spill: same hit bytes must land in the carve
// files whether the input arrived as a file or a pipe.
func TestStdinCarveIdentity(t *testing.T) {
	fixture := stdinIdentityFixture()
	file := filepath.Join(t.TempDir(), "pipe.bin")
	if err := os.WriteFile(file, fixture, 0644); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	fileCarves := filepath.Join(dir, "file")
	stdinCarves := filepath.Join(dir, "stdin")
	fileDets, fileCollect := collectDetections()
	fileOpts := Options{CarveDir: fileCarves, CarveContextBytes: 16, Log: io.Discard}
	if err := ScanWithOptions(0, file, fileOpts, fileCollect, nil); err != nil {
		t.Fatalf("file scan: %v", err)
	}
	stdinDets, stdinCollect := collectDetections()
	stdinOpts := Options{CarveDir: stdinCarves, CarveContextBytes: 16, Log: io.Discard}
	if err := ScanStdinWithOptions(bytes.NewReader(fixture), 0, stdinOpts, stdinCollect, nil); err != nil {
		t.Fatalf("stdin scan: %v", err)
	}
	if len(*fileDets) == 0 || len(*stdinDets) != len(*fileDets) {
		t.Fatalf("carve identity needs equal nonzero hits: file %d, stdin %d",
			len(*fileDets), len(*stdinDets))
	}
	bins := func(carveDir string) [][]byte {
		matches, err := filepath.Glob(filepath.Join(carveDir, "hit-*.bin"))
		if err != nil {
			t.Fatal(err)
		}
		var out [][]byte
		for _, m := range matches {
			b, err := os.ReadFile(m)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, b)
		}
		return out
	}
	fileBins, stdinBins := bins(fileCarves), bins(stdinCarves)
	if len(fileBins) == 0 {
		t.Fatal("file scan carved nothing; identity is vacuous")
	}
	if !reflect.DeepEqual(stdinBins, fileBins) {
		t.Fatalf("stdin carved %d files, file carved %d, or bytes differ", len(stdinBins), len(fileBins))
	}
}

// Past the spill cap the scan fails loudly, naming the cap — a
// truncated pipe is never mistaken for a short one.
func TestStdinSpillCapRefusesLoudly(t *testing.T) {
	oldMax, oldDir := MaxStdinSpillBytes, stdinSpillDir
	MaxStdinSpillBytes, stdinSpillDir = 64, t.TempDir()
	defer func() { MaxStdinSpillBytes, stdinSpillDir = oldMax, oldDir }()
	err := ScanStdinWithOptions(bytes.NewReader(bytes.Repeat([]byte("x"), 1024)), 0,
		Options{Log: io.Discard}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "spill cap") {
		t.Fatalf("oversized pipe must fail naming the spill cap, got: %v", err)
	}
	if entries, rerr := os.ReadDir(stdinSpillDir); rerr != nil || len(entries) != 0 {
		t.Fatalf("failed spill must leave no residue, entries=%v err=%v", entries, rerr)
	}
}

// A final chunk coalesced with EOF is legal for io.Reader; it must
// still trip the cap rather than scanning an over-cap spill.
func TestStdinSpillCapCoalescedEOF(t *testing.T) {
	oldMax, oldDir := MaxStdinSpillBytes, stdinSpillDir
	MaxStdinSpillBytes, stdinSpillDir = 64, t.TempDir()
	defer func() { MaxStdinSpillBytes, stdinSpillDir = oldMax, oldDir }()
	r := &coalesceReader{data: bytes.Repeat([]byte("x"), 1024)}
	err := ScanStdinWithOptions(r, 0, Options{Log: io.Discard}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "spill cap") {
		t.Fatalf("coalesced over-cap pipe must fail naming the spill cap, got: %v", err)
	}
	if entries, rerr := os.ReadDir(stdinSpillDir); rerr != nil || len(entries) != 0 {
		t.Fatalf("failed spill must leave no residue, entries=%v err=%v", entries, rerr)
	}
}

// coalesceReader returns its whole payload alongside EOF in a single
// Read, which io.Reader permits but pipes and files never do.
type coalesceReader struct {
	data []byte
	done bool
}

func (r *coalesceReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	return copy(p, r.data), io.EOF
}

// A pipe that dies mid-spill fails loudly, reporting how far the
// spill got, and leaves no residue.
func TestStdinSpillReadError(t *testing.T) {
	oldDir := stdinSpillDir
	stdinSpillDir = t.TempDir()
	defer func() { stdinSpillDir = oldDir }()
	err := ScanStdinWithOptions(&failReader{after: 100}, 0, Options{Log: io.Discard}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "pipe read failed") {
		t.Fatalf("dying pipe must fail naming the read, got: %v", err)
	}
	if !strings.Contains(err.Error(), "100 bytes") {
		t.Fatalf("dying pipe must report how far the spill got, got: %v", err)
	}
	if entries, rerr := os.ReadDir(stdinSpillDir); rerr != nil || len(entries) != 0 {
		t.Fatalf("failed spill must leave no residue, entries=%v err=%v", entries, rerr)
	}
}

// failReader yields `after` good bytes, then fails permanently.
type failReader struct {
	after int
}

func (r *failReader) Read(p []byte) (int, error) {
	if r.after <= 0 {
		return 0, errors.New("simulated pipe failure")
	}
	n := min(len(p), r.after)
	for i := range n {
		p[i] = 'x'
	}
	r.after -= n
	return n, nil
}

// A scan that fails after the spill (here: unknown profile) still
// removes the spill.
func TestStdinSpillCleanedAfterScanError(t *testing.T) {
	oldDir := stdinSpillDir
	stdinSpillDir = t.TempDir()
	defer func() { stdinSpillDir = oldDir }()
	err := ScanStdinWithOptions(bytes.NewReader([]byte("wallet.dat")), 0,
		Options{Profile: "bogus", Log: io.Discard}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "unknown scan profile") {
		t.Fatalf("bogus profile must fail loudly, got: %v", err)
	}
	if entries, rerr := os.ReadDir(stdinSpillDir); rerr != nil || len(entries) != 0 {
		t.Fatalf("post-spill failure must clean up, entries=%v err=%v", entries, rerr)
	}
}

// Piped EnCase bytes scan raw (segments cannot decode from one flat
// stream), so the scan warns loudly instead of failing silently with
// near-certain false negatives. EWF2 advice differs because file
// scans refuse EWF2 too — only libewf conversion helps there.
func TestStdinEWFMagicWarns(t *testing.T) {
	for _, tc := range []struct {
		name  string
		magic []byte
		want  string
	}{
		{"ewf", ewfSignature, "looks like an EnCase (EWF) container; scanning raw bytes — pass the image file to decode it"},
		{"ewf2", ewf2Signature, "looks like an EnCase EWF2 container; scanning raw bytes — convert with libewf (ewfexport) and scan the raw output"},
	} {
		payload := append(append([]byte{}, tc.magic...), bytes.Repeat([]byte("e"), 1000)...)
		var log bytes.Buffer
		if err := ScanStdinWithOptions(bytes.NewReader(payload), 0,
			Options{Log: &log}, nil, nil); err != nil {
			t.Fatalf("%s: stdin scan: %v", tc.name, err)
		}
		if !strings.Contains(log.String(), tc.want) {
			t.Fatalf("%s: pipe must warn %q, log:\n%s", tc.name, tc.want, log.String())
		}
	}
}

// The cap boundary is exact: cap bytes scan, cap+1 refuses.
func TestStdinSpillCapBoundary(t *testing.T) {
	oldMax, oldDir := MaxStdinSpillBytes, stdinSpillDir
	MaxStdinSpillBytes, stdinSpillDir = 64, t.TempDir()
	defer func() { MaxStdinSpillBytes, stdinSpillDir = oldMax, oldDir }()
	if err := ScanStdinWithOptions(bytes.NewReader(bytes.Repeat([]byte("x"), 64)), 0,
		Options{Log: io.Discard}, nil, nil); err != nil {
		t.Fatalf("exactly-cap input must scan, got: %v", err)
	}
	err := ScanStdinWithOptions(bytes.NewReader(bytes.Repeat([]byte("x"), 65)), 0,
		Options{Log: io.Discard}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "spill cap") {
		t.Fatalf("cap+1 input must fail naming the spill cap, got: %v", err)
	}
}

// A cancelled context stops the spill: pre-cancel never touches the
// pipe, mid-spill cancel stops between reads. Both surface the
// context error for errors.Is.
func TestStdinSpillHonorsCancel(t *testing.T) {
	oldDir := stdinSpillDir
	stdinSpillDir = t.TempDir()
	defer func() { stdinSpillDir = oldDir }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	counting := &countReader{r: bytes.NewReader([]byte("wallet.dat"))}
	err := ScanStdinWithOptions(counting, 0, Options{Context: ctx, Log: io.Discard}, nil, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled spill must surface context.Canceled, got: %v", err)
	}
	if counting.calls != 0 {
		t.Fatalf("pre-cancelled spill read the pipe %d times", counting.calls)
	}

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	release := make(chan struct{})
	defer close(release) // frees the probe reader even on failure
	done := make(chan error, 1)
	go func() {
		done <- ScanStdinWithOptions(&cancelReader{ctx: ctx2, cancel: cancel2, release: release}, 0,
			Options{Context: ctx2, Log: io.Discard}, nil, nil)
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("mid-spill cancel must surface context.Canceled, got: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("mid-spill cancel did not stop the spill within 10s")
	}
	if entries, rerr := os.ReadDir(stdinSpillDir); rerr != nil || len(entries) != 0 {
		t.Fatalf("cancelled spill must leave no residue, entries=%v err=%v", entries, rerr)
	}
}

// countReader records how often the pipe was touched.
type countReader struct {
	r     io.Reader
	calls int
}

func (r *countReader) Read(p []byte) (int, error) {
	r.calls++
	return r.r.Read(p)
}

// cancelReader yields one chunk while cancelling ctx, then blocks
// until release closes — proving the spill stops between reads.
type cancelReader struct {
	ctx     context.Context
	cancel  context.CancelFunc
	release chan struct{}
	fired   bool
}

func (r *cancelReader) Read(p []byte) (int, error) {
	if !r.fired {
		r.fired = true
		r.cancel()
		p[0] = 'x'
		return 1, nil
	}
	<-r.release
	return 0, io.EOF
}

// The spill is temp state: removed after a successful scan too.
func TestStdinSpillCleanedAfterSuccess(t *testing.T) {
	oldDir := stdinSpillDir
	stdinSpillDir = t.TempDir()
	defer func() { stdinSpillDir = oldDir }()
	if err := ScanStdinWithOptions(bytes.NewReader(stdinIdentityFixture()), 0,
		Options{Log: io.Discard}, nil, nil); err != nil {
		t.Fatalf("stdin scan: %v", err)
	}
	if entries, rerr := os.ReadDir(stdinSpillDir); rerr != nil || len(entries) != 0 {
		t.Fatalf("successful spill must be cleaned up, entries=%v err=%v", entries, rerr)
	}
}

// Journals and resume need a stable path; a spill that vanishes at
// scan end can offer neither, so both fail up front.
func TestStdinRefusesCheckpoint(t *testing.T) {
	oldDir := stdinSpillDir
	stdinSpillDir = t.TempDir()
	defer func() { stdinSpillDir = oldDir }()
	for _, opts := range []Options{
		{CheckpointPath: filepath.Join(t.TempDir(), "ckpt.json"), Log: io.Discard},
		{Resume: true, Log: io.Discard},
	} {
		err := ScanStdinWithOptions(bytes.NewReader([]byte("x")), 0, opts, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "resume") {
			t.Fatalf("opts %+v must fail naming resume, got: %v", opts, err)
		}
	}
	if entries, rerr := os.ReadDir(stdinSpillDir); rerr != nil || len(entries) != 0 {
		t.Fatalf("refused scan must not spill, entries=%v err=%v", entries, rerr)
	}
}

// The case log identifies piped input honestly: kind "stdin", the
// stable label as path (never the temp spill name), real byte size.
func TestStdinCaseLogKind(t *testing.T) {
	dir := t.TempDir()
	fixture := stdinIdentityFixture()
	logPath := filepath.Join(dir, "case.jsonl")
	if err := ScanStdinWithOptions(bytes.NewReader(fixture), 0,
		Options{CaseLogPath: logPath, ToolVersion: "test", Log: io.Discard}, nil, nil); err != nil {
		t.Fatalf("stdin scan: %v", err)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	var rec CaseLog
	if err := json.Unmarshal(bytes.TrimSpace(raw), &rec); err != nil {
		t.Fatalf("case log is not JSON: %v", err)
	}
	if rec.Source.Kind != "stdin" || rec.Source.Path != StdinTargetName {
		t.Fatalf("case source = %+v, want kind/path stdin", rec.Source)
	}
	if rec.Source.Size != int64(len(fixture)) {
		t.Fatalf("case source size = %d, want %d", rec.Source.Size, len(fixture))
	}
}

// An empty pipe scans like an empty file: success, no detections.
func TestStdinEmpty(t *testing.T) {
	dets, collect := collectDetections()
	if err := ScanStdinWithOptions(bytes.NewReader(nil), 0, Options{Log: io.Discard}, collect, nil); err != nil {
		t.Fatalf("empty stdin: %v", err)
	}
	if len(*dets) != 0 {
		t.Fatalf("empty stdin found %d detections", len(*dets))
	}
}
