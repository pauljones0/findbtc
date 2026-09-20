package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pauljones0/findbtc/detector"
)

// Batch crash/resume boundary proof (Goal 42): a real SIGKILLed
// batch run plus its resume must union to the uninterrupted run —
// no lost detections, no phantom detections, duplicates bounded
// by the rewind seam — with carve bytes preserved (continuation,
// never overwrite) and the case log completed. Delivery ORDER is
// the one free variable: drains reorder nested work earlier, so
// every comparison is order-free but multiplicity-exact.

// batchKillFixture builds the two batch targets: a small file A
// that always completes before the kill, and a 64MB file B with
// raw hits, a frontier straddler, and two intact nested zips
// (zip1 ahead of the first drain point, so a drain consumes a
// real nested backlog). It returns the targets plus every raw
// hit offset and zip span in B for seam-bound derivation.
func batchKillFixture(t *testing.T, dir string) (a, b string, rawHits []int64, zips [][2]int64, zipHits []int) {
	t.Helper()
	a = filepath.Join(dir, "a.bin")
	abuf := make([]byte, 200000)
	copy(abuf[100000:], "bestblock")
	if err := os.WriteFile(a, abuf, 0644); err != nil {
		t.Fatal(err)
	}
	const size = 64 << 20
	buf := make([]byte, size)
	place := func(off int64, s string) {
		copy(buf[off:], s)
		rawHits = append(rawHits, off)
	}
	const MB = 1 << 20
	place(100, "bestblock")
	place(MB-6, "orderposnext") // straddles the 1MB journal point
	place(MB+100, "defaultkey")
	place(3*MB+100, "crypted_key")
	place(size-1000, "hdseed")
	mkzip := func(at int64, hits ...string) {
		var zb bytes.Buffer
		w := zip.NewWriter(&zb)
		fw, err := w.Create("member.dat")
		if err != nil {
			t.Fatal(err)
		}
		body := make([]byte, 60000)
		for i := range body {
			body[i] = byte('a' + i%26)
		}
		for i, h := range hits {
			copy(body[1000+i*20000:], h)
		}
		if _, err := fw.Write(body); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		copy(buf[at:], zb.Bytes())
		zips = append(zips, [2]int64{at, at + int64(zb.Len())})
		zipHits = append(zipHits, len(hits))
	}
	mkzip(512<<10, "keymeta", "hdseed")
	mkzip(5*MB/2, "crypted_key")
	b = filepath.Join(dir, "b.bin")
	if err := os.WriteFile(b, buf, 0644); err != nil {
		t.Fatal(err)
	}
	return a, b, rawHits, zips, zipHits
}

// normalizeDetectionLine parses one -json detection line and
// zeroes the run-specific fields (carve sequence paths), so
// kill/resume output compares equal to an uninterrupted run when
// the same bytes were covered.
func normalizeDetectionLine(t *testing.T, line string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("stdout line is not JSON: %q: %v", line, err)
	}
	delete(m, "carve_path")
	if s, ok := m["salvage"].(map[string]any); ok {
		delete(s, "path")
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func detectionMultiset(t *testing.T, path string) map[string]int {
	t.Helper()
	return detectionMultisetTail(t, path, false)
}

// detectionMultisetTail parses prefix output that may end in a
// kill-torn line: when tornTailOK and the file's last line lacks
// its newline and fails JSON, that line is dropped. Dropping is
// sound because a torn tail was printed microseconds before the
// kill, so its bytes sit at the kill point — inside the seam the
// resume re-covers — while a genuinely lost pre-seam line still
// trips the no-loss assertion (absent from both sides).
func detectionMultisetTail(t *testing.T, path string, tornTailOK bool) map[string]int {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(raw), "\n")
	// A trailing newline leaves an empty final element; anything
	// else means the last line may be torn.
	if tornTailOK && len(raw) > 0 && raw[len(raw)-1] != '\n' && len(lines) > 0 {
		last := lines[len(lines)-1]
		var m map[string]any
		if strings.TrimSpace(last) != "" && json.Unmarshal([]byte(last), &m) != nil {
			t.Logf("dropping kill-torn tail line: %.80q", last)
			lines = lines[:len(lines)-1]
		}
	}
	out := map[string]int{}
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		out[normalizeDetectionLine(t, line)]++
	}
	return out
}

// carveBinMultiset hashes every hit-*.bin carve: content identity
// is the overwrite-proof property (names legitimately differ by
// delivery order). It also reports orphan sidecars.
func carveBinMultiset(t *testing.T, dir string) (map[string]int, int, int) {
	t.Helper()
	out := map[string]int{}
	bins, sides := 0, 0
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		switch {
		case strings.HasPrefix(name, "hit-") && strings.HasSuffix(name, ".bin"):
			raw, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(raw)
			out[hex.EncodeToString(sum[:])]++
			bins++
		case strings.HasPrefix(name, "hit-") && strings.HasSuffix(name, ".json"):
			sides++
		}
	}
	return out, bins, sides
}

// assertMultisetCover proves killed+resumed output covers the
// uninterrupted run exactly: every uninterrupted line present at
// least as often (no loss), no line outside it (no phantoms),
// and total duplicates within the seam bound.
func assertMultisetCover(t *testing.T, what string, prefix, suffix, full map[string]int, bound int) {
	t.Helper()
	union := map[string]int{}
	for l, c := range prefix {
		union[l] += c
	}
	for l, c := range suffix {
		union[l] += c
	}
	for l := range union {
		if _, ok := full[l]; !ok {
			t.Errorf("%s: phantom line missing from uninterrupted run: %.120q", what, l)
		}
	}
	for l, c := range full {
		if union[l] < c {
			t.Errorf("%s: lost line (want %d, got %d): %.120q", what, c, union[l], l)
		}
	}
	excess := 0
	for l, c := range full {
		excess += union[l] - c
	}
	if excess > bound {
		t.Errorf("%s: %d duplicate lines, bound is %d (rewind seam)", what, excess, bound)
	}
}

func TestBatchResumeRealSIGKILL(t *testing.T) {
	if testing.Short() {
		t.Skip("real-kill fixture needs -short=false")
	}
	dir := t.TempDir()
	a, b, rawHits, zips, zipHits := batchKillFixture(t, dir)
	journal := filepath.Join(dir, "j.json")
	carveKill := filepath.Join(dir, "carves")
	carveFull := filepath.Join(dir, "carves-full")
	caseLog := filepath.Join(dir, "case.jsonl")
	caseFull := filepath.Join(dir, "case-full.jsonl")
	if err := os.MkdirAll(carveKill, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(carveFull, 0755); err != nil {
		t.Fatal(err)
	}

	// Uninterrupted reference: same batch, fresh journal and carves.
	refJournal := filepath.Join(dir, "ref.json")
	refOut := filepath.Join(dir, "u.json")
	cmd := exec.Command(testBinary, "-json", "-checkpoint", refJournal,
		"-extract-dir", carveFull, "-context", "4096", "-case-log", caseFull, a, b)
	refStdout, err := os.Create(refOut)
	if err != nil {
		t.Fatal(err)
	}
	var refStderr strings.Builder
	cmd.Stdout, cmd.Stderr = refStdout, &refStderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("reference run: %v\n%s", err, refStderr.String())
	}
	refStdout.Close()
	full := detectionMultiset(t, refOut)
	if len(full) == 0 {
		t.Fatal("reference run produced no detections")
	}

	// Killed run: stdout to a file (the process dies), poll the
	// journal for B active past 1MB, then SIGKILL. The kill
	// condition proves A already completed (targets run in
	// order), so the only seam is inside B.
	prefixOut := filepath.Join(dir, "p.json")
	kill := exec.Command(testBinary, "-json", "-checkpoint", journal,
		"-extract-dir", carveKill, "-context", "4096", "-case-log", caseLog, a, b)
	prefixFile, err := os.Create(prefixOut)
	if err != nil {
		t.Fatal(err)
	}
	var killStderr strings.Builder
	kill.Stdout, kill.Stderr = prefixFile, &killStderr
	if err := kill.Start(); err != nil {
		t.Fatal(err)
	}
	killed := false
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
		cp, err := detector.ReadCheckpoint(journal)
		if err != nil {
			continue
		}
		if len(cp.Targets) != 2 {
			continue
		}
		if cp.Targets[0].State != detector.BatchComplete {
			continue
		}
		ent := cp.Targets[1]
		if ent.State == detector.BatchComplete {
			t.Fatal("B completed before the kill landed; fixture too fast")
		}
		if ent.State == detector.BatchActive && ent.Offset >= 1<<20 {
			if err := kill.Process.Kill(); err != nil {
				// The process may have exited between the
				// journal read and the kill; discriminate a
				// too-late kill from a real kill failure.
				time.Sleep(50 * time.Millisecond)
				if cp, cerr := detector.ReadCheckpoint(journal); cerr == nil &&
					len(cp.Targets) == 2 && cp.Targets[1].State == detector.BatchComplete {
					t.Fatal("B completed between journal read and kill; fixture too fast")
				}
				t.Fatalf("kill: %v", err)
			}
			killed = true
			break
		}
	}
	kill.Wait()
	prefixFile.Close()
	if !killed {
		t.Fatal("kill window never opened within 120s")
	}
	cp, err := detector.ReadCheckpoint(journal)
	if err != nil {
		t.Fatalf("journal unreadable after kill: %v", err)
	}
	if len(cp.Targets) == 2 && cp.Targets[1].State == detector.BatchComplete {
		t.Fatal("kill landed after B completed; fixture too fast")
	}
	if cp.Targets[0].State != detector.BatchComplete || cp.Targets[1].State != detector.BatchActive {
		t.Fatalf("post-kill states %+v, want [complete active]", cp.Targets)
	}
	frontier := cp.Targets[1].Offset
	if frontier < 1<<20 {
		t.Fatalf("post-kill frontier %d, want >= 1MB", frontier)
	}

	// Resume into the same journal, carve dir, and case log.
	suffixOut := filepath.Join(dir, "s.json")
	stderr, exit := runTestBinaryToFile(t, suffixOut, "-json", "-checkpoint", journal,
		"-resume", "-extract-dir", carveKill, "-context", "4096", "-case-log", caseLog, a, b)
	if exit != 0 {
		t.Fatalf("resume exit %d\n%s", exit, stderr)
	}
	for _, want := range []string{"batch: skipping " + a, "batch: resuming " + b, "carve numbering continues at", "[COMPLETE]"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("resume stderr lacks %q\n%s", want, stderr)
		}
	}
	cp, err = detector.ReadCheckpoint(journal)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range cp.Targets {
		if e.State != detector.BatchComplete {
			t.Fatalf("post-resume states %+v, want all complete", cp.Targets)
		}
	}

	// Seam bound, derived from evidence, not assumed: resume
	// re-covers [start, killpoint), so duplicates can only come
	// from fixture hits in that window. The kill point is
	// unknown, but the prefix's furthest B detection plus one
	// block bounds it from above.
	prefix := detectionMultisetTail(t, prefixOut, true)
	suffix := detectionMultiset(t, suffixOut)
	start := detector.ResumeRewindOffset(0, frontier)
	maxPrefix := int64(0)
	for line := range prefix {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatal(err)
		}
		tgt, _ := m["target"].(string)
		off, _ := m["offset"].(float64)
		if strings.Contains(tgt, b) && int64(off) > maxPrefix {
			maxPrefix = int64(off)
		}
	}
	// Plus one for a needle straddling just below the rewound
	// start: its offset misses the window but its match spans it.
	bound := 1
	ceil := maxPrefix + 64<<10
	for _, h := range rawHits {
		if h >= start && h <= ceil {
			bound++
		}
	}
	for i, z := range zips {
		if z[1] >= start && z[0] <= ceil {
			bound += zipHits[i] // a re-read zip re-derives its member hits
		}
	}
	assertMultisetCover(t, "detections", prefix, suffix, full, bound)

	fullCarves, _, _ := carveBinMultiset(t, carveFull)
	resumedCarves, bins, sides := carveBinMultiset(t, carveKill)
	// SIGKILL can tear one carve pair (.bin committed, sidecar
	// not); more than one orphan means carves are lost, not torn.
	if sides > bins || bins-sides > 1 {
		t.Errorf("%d carve sidecars for %d bins, want a sidecar per carve (at most one kill-torn pair)", sides, bins)
	}
	// One extra carve beyond the detection seam: a kill landing
	// between carve-commit and print leaves an orphan carve for
	// a line the prefix never printed, and the resume re-carves
	// it. detectWallets is single-threaded, so one kill tears at
	// most one such window.
	assertMultisetCover(t, "carves", map[string]int{}, resumedCarves, fullCarves, bound+1)
	for _, e := range readDirNames(t, carveKill) {
		if strings.HasPrefix(e, ".findbtc-tmp-") {
			t.Errorf("staging file %s left behind; resume must reap it", e)
		}
	}

	// The resumed case log completes B; A was completed by the
	// killed run and never re-recorded.
	rawLog, err := os.ReadFile(caseLog)
	if err != nil {
		t.Fatal(err)
	}
	completeB, recordsA := 0, 0
	for _, line := range strings.Split(string(rawLog), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("case log line is not JSON: %v", err)
		}
		status, _ := m["status"].(string)
		src, _ := m["source"].(map[string]any)
		path, _ := src["path"].(string)
		switch {
		case path == b && status == "complete":
			completeB++
		case path == a:
			recordsA++
		}
	}
	if completeB != 1 {
		t.Errorf("B completed %d times in resumed case log, want 1", completeB)
	}
	if recordsA != 1 {
		t.Errorf("A recorded %d times across kill+resume, want 1 (skip, not rescan)", recordsA)
	}
}

// A completed batch journal resumes by skipping everything: all
// targets already covered, exit 0, nothing rescanned.
func TestBatchResumeSkipsComplete(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.bin")
	b := filepath.Join(dir, "b.bin")
	if err := os.WriteFile(a, []byte("bestblock"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("crypted_key"), 0644); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(dir, "j.json")
	stdout, stderr, exit := runTestBinary(t, "-json", "-checkpoint", journal, a, b)
	if exit != 0 {
		t.Fatalf("fresh batch exit %d\n%s", exit, stderr)
	}
	if len(strings.Split(strings.TrimSpace(stdout), "\n")) != 2 {
		t.Fatalf("fresh batch printed %q, want 2 hits", stdout)
	}
	stdout, stderr, exit = runTestBinary(t, "-json", "-checkpoint", journal, "-resume", a, b)
	if exit != 0 {
		t.Fatalf("resume exit %d\n%s", exit, stderr)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Errorf("resume reprinted hits: %q", stdout)
	}
	for _, want := range []string{"batch: skipping " + a, "batch: skipping " + b, "[COMPLETE]"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("resume stderr lacks %q\n%s", want, stderr)
		}
	}
}

// A skip vouches for exact bytes: the journal carries a digest of
// each clean full pass, and resume re-hashes before skipping. A
// same-size replacement with a restored mtime fools the metadata
// but must fail verification and rescan; a size change rescans on
// identity alone.
func TestBatchResumeSkipVerifiesDigest(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.bin")
	b := filepath.Join(dir, "b.bin")
	acontent := []byte("bestblock-pad!")
	bcontent := []byte("crypted_key-pad")
	if err := os.WriteFile(a, acontent, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, bcontent, 0644); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(dir, "j.json")
	if _, stderr, exit := runTestBinary(t, "-json", "-checkpoint", journal, a, b); exit != 0 {
		t.Fatalf("fresh batch exit %d\n%s", exit, stderr)
	}
	rawJournal, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	var cp struct {
		Targets []struct {
			Path   string
			State  string
			SHA256 string `json:"sha256"`
		}
	}
	if err := json.Unmarshal(rawJournal, &cp); err != nil {
		t.Fatal(err)
	}
	asum := sha256.Sum256(acontent)
	bsum := sha256.Sum256(bcontent)
	want := map[string]string{a: hex.EncodeToString(asum[:]), b: hex.EncodeToString(bsum[:])}
	for _, e := range cp.Targets {
		if e.State != "complete" {
			t.Fatalf("entry %s state %s, want complete", e.Path, e.State)
		}
		if e.SHA256 != want[e.Path] {
			t.Errorf("entry %s digest %q, want file sha256 %q", e.Path, e.SHA256, want[e.Path])
		}
	}
	// Same-size tamper with restored mtime: metadata matches, so
	// only the digest can catch it.
	st, err := os.Stat(b)
	if err != nil {
		t.Fatal(err)
	}
	tampered := []byte("crypted_key-PWN")
	if len(tampered) != len(bcontent) {
		t.Fatal("tamper fixture must preserve size")
	}
	if err := os.WriteFile(b, tampered, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(b, st.ModTime(), st.ModTime()); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, exit := runTestBinary(t, "-json", "-checkpoint", journal, "-resume", a, b)
	if exit != 0 {
		t.Fatalf("resume exit %d\n%s", exit, stderr)
	}
	if !strings.Contains(stderr, "batch: skipping "+a) {
		t.Errorf("a should skip\n%s", stderr)
	}
	if !strings.Contains(stderr, "fails digest verification") {
		t.Errorf("tampered b should fail verification\n%s", stderr)
	}
	if !strings.Contains(stdout, "crypted_key") {
		t.Errorf("tampered b should rescan and reprint\n%s", stdout)
	}
	// Size change rescans on identity, before any hashing.
	f, err := os.OpenFile(a, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	f.Close()
	stdout, stderr, exit = runTestBinary(t, "-json", "-checkpoint", journal, "-resume", a, b)
	if exit != 0 {
		t.Fatalf("resume exit %d\n%s", exit, stderr)
	}
	if !strings.Contains(stderr, "changed since completion") {
		t.Errorf("grown a should rescan on identity\n%s", stderr)
	}
	if !strings.Contains(stdout, "bestblock") {
		t.Errorf("grown a should reprint\n%s", stdout)
	}
	if !strings.Contains(stderr, "batch: skipping "+b) {
		t.Errorf("re-completed b should skip on digest\n%s", stderr)
	}
}

// Batch resume refusals: corrupt journals, shape mismatches, list
// mismatches, and run-binding mismatches all exit loudly — a
// journal must never promise another run's artifacts.
func TestBatchResumeRefusals(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.bin")
	b := filepath.Join(dir, "b.bin")
	c := filepath.Join(dir, "c.bin")
	for _, p := range []string{a, b, c} {
		if err := os.WriteFile(p, []byte("bestblock"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	journal := filepath.Join(dir, "j.json")
	if _, stderr, exit := runTestBinary(t, "-checkpoint", journal, a, b); exit != 0 {
		t.Fatalf("fresh batch exit %d\n%s", exit, stderr)
	}
	cases := []struct {
		name string
		args []string
		want string
		jail func() // optional journal sabotage before the run
	}{
		{"corrupt", []string{"-checkpoint", journal, "-resume", a, b}, "bad checkpoint",
			func() { os.WriteFile(journal, []byte("{nope"), 0644) }},
		{"legacy", []string{"-checkpoint", journal, "-resume", a, b}, "not a batch journal",
			func() {
				os.WriteFile(journal, []byte(`{"path":"`+a+`","offset":5,"updated":"2026-01-01T00:00:00Z"}`+"\n"), 0644)
			}},
		{"length", []string{"-checkpoint", journal, "-resume", a, b, c}, "covers 2 targets, run lists 3", nil},
		{"order", []string{"-checkpoint", journal, "-resume", b, a}, "run lists", nil},
		{"binding", []string{"-json", "-checkpoint", journal, "-resume", a, b}, "json=", nil},
		{"singlefrombatch", []string{"-checkpoint", journal, "-resume", a}, "batch journal", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.jail != nil {
				tc.jail()
				defer func() {
					if _, stderr, exit := runTestBinary(t, "-checkpoint", journal, a, b); exit != 0 {
						t.Fatalf("journal restore exit %d\n%s", exit, stderr)
					}
				}()
			}
			_, stderr, exit := runTestBinary(t, tc.args...)
			if exit == 0 {
				t.Fatalf("exit 0, want refusal containing %q", tc.want)
			}
			if !strings.Contains(stderr, tc.want) {
				t.Errorf("stderr lacks %q\n%s", tc.want, stderr)
			}
		})
	}
}

// An unwritable journal must warn, never fail the scan: lost
// marks only cost rescanned work.
func TestCheckpointUnwritableWarns(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.bin")
	if err := os.WriteFile(a, []byte("bestblock"), 0644); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "missing-dir", "j.json")
	stdout, stderr, exit := runTestBinary(t, "-json", "-checkpoint", bad, a)
	if exit != 0 {
		t.Fatalf("exit %d, want 0 despite unwritable journal\n%s", exit, stderr)
	}
	if !strings.Contains(stdout, "bestblock") {
		t.Errorf("hit lost with unwritable journal: %q", stdout)
	}
	if !strings.Contains(stderr, "[checkpoint] warning") {
		t.Errorf("stderr lacks checkpoint warning\n%s", stderr)
	}
}

// Single-target resume continues carve numbering past pre-kill
// carves instead of overwriting them: run to completion, resume
// (which re-covers the tail window), and every run-1 carve must
// survive byte-identical.
func TestSingleResumeCarveContinuation(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.bin")
	buf := make([]byte, 3<<20)
	copy(buf[100:], "bestblock")
	copy(buf[(1<<20)+100:], "defaultkey")
	copy(buf[(2<<20)+100:], "keymeta")
	if err := os.WriteFile(a, buf, 0644); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(dir, "j.json")
	carves := filepath.Join(dir, "carves")
	if err := os.MkdirAll(carves, 0755); err != nil {
		t.Fatal(err)
	}
	if _, stderr, exit := runTestBinary(t, "-json", "-checkpoint", journal,
		"-extract-dir", carves, "-context", "1024", a); exit != 0 {
		t.Fatalf("first run exit %d\n%s", exit, stderr)
	}
	before := map[string]string{}
	entries, err := os.ReadDir(carves)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("first run carved nothing")
	}
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(dir, "carves", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		before[e.Name()] = hex.EncodeToString(sum[:])
	}
	_, stderr, exit := runTestBinary(t, "-json", "-checkpoint", journal,
		"-resume", "-extract-dir", carves, "-context", "1024", a)
	if exit != 0 {
		t.Fatalf("resume exit %d\n%s", exit, stderr)
	}
	if !strings.Contains(stderr, "carve numbering continues at") {
		t.Errorf("stderr lacks carve continuation\n%s", stderr)
	}
	for name, sum := range before {
		raw, err := os.ReadFile(filepath.Join(carves, name))
		if err != nil {
			t.Errorf("pre-resume carve %s gone: %v", name, err)
			continue
		}
		after := sha256.Sum256(raw)
		if hex.EncodeToString(after[:]) != sum {
			t.Errorf("pre-resume carve %s overwritten with different content", name)
		}
	}
}

func readDirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// runTestBinaryToFile runs the test binary with stdout to path
// (for runs whose process may die) and returns stderr and exit.
func runTestBinaryToFile(t *testing.T, stdoutPath string, args ...string) (stderr string, exit int) {
	t.Helper()
	cmd := exec.Command(testBinary, args...)
	f, err := os.Create(stdoutPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var errBuf strings.Builder
	cmd.Stdout, cmd.Stderr = f, &errBuf
	err = cmd.Run()
	exit = 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("cannot run test binary: %v", err)
		}
		exit = ee.ExitCode()
	}
	return errBuf.String(), exit
}
