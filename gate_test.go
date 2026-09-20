package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// testBinary is a built findbtc used by subprocess exit-code tests.
// Built once in TestMain so flag/exit behavior is tested through the
// real CLI surface, not by calling run* helpers in-process.
var testBinary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "findbtc-gate-test")
	if err != nil {
		fmt.Fprintln(os.Stderr, "test setup:", err)
		os.Exit(1)
	}
	testBinary = filepath.Join(dir, "findbtc-test")
	if runtime.GOOS == "windows" {
		testBinary += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", testBinary, ".").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "test setup: cannot build test binary: %v\n%s\n", err, out)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func runTestBinary(t *testing.T, args ...string) (stdout, stderr string, exit int) {
	t.Helper()
	cmd := exec.Command(testBinary, args...)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	exit = 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("cannot run test binary: %v", err)
		}
		exit = ee.ExitCode()
	}
	return outBuf.String(), errBuf.String(), exit
}

// runTestBinaryStdin runs the test binary with stdin closed over input.
func runTestBinaryStdin(t *testing.T, input string, args ...string) (stdout, stderr string, exit int) {
	t.Helper()
	cmd := exec.Command(testBinary, args...)
	cmd.Stdin = strings.NewReader(input)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	exit = 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("cannot run test binary: %v", err)
		}
		exit = ee.ExitCode()
	}
	return outBuf.String(), errBuf.String(), exit
}

// A piped scan must report what a file scan of the same bytes
// reports: identical -json hits modulo the target label, exit 0,
// [COMPLETE] on stderr.
func TestStdinPipeIdentity(t *testing.T) {
	dir := t.TempDir()
	body := strings.Repeat("q", 5000) + "wallet.dat" + strings.Repeat("q", 5000)
	target := writeGateFile(t, dir, "pipe.bin", body)
	fileOut, _, fileExit := runTestBinary(t, "-json", target)
	if fileExit != 0 {
		t.Fatalf("file scan exit %d", fileExit)
	}
	if !strings.Contains(fileOut, "wallet.dat") {
		t.Fatalf("file scan found nothing; fixture is vacuous")
	}
	pipeOut, pipeErr, pipeExit := runTestBinaryStdin(t, body, "-json", "-")
	if pipeExit != 0 {
		t.Fatalf("pipe scan exit %d (stderr: %s)", pipeExit, firstLine(pipeErr))
	}
	if !strings.Contains(pipeErr, "[COMPLETE]") {
		t.Errorf("pipe scan must print [COMPLETE], stderr:\n%s", pipeErr)
	}
	// Normalize structurally (parsed JSON): Windows paths carry
	// backslashes that JSON-escaping would defeat in a string
	// replace. Descriptions embed the same label
	// ("at <target> in ... block").
	norm := func(s string) string {
		var out []string
		for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
			var m map[string]any
			if err := json.Unmarshal([]byte(line), &m); err != nil {
				t.Fatalf("hit is not JSON: %v\n%s", err, line)
			}
			tgt, _ := m["target"].(string)
			m["target"] = "NORM"
			if desc, ok := m["description"].(string); ok && tgt != "" {
				m["description"] = strings.ReplaceAll(desc, tgt, "NORM")
			}
			raw, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, string(raw))
		}
		return strings.Join(out, "\n")
	}
	if got, want := norm(pipeOut), norm(fileOut); got != want {
		t.Errorf("pipe hits differ from file hits:\npipe:\n%s\nfile:\n%s", got, want)
	}
}

// Pipes have no offsets to journal, no ranges to seek, no directory
// to sweep: every mode needing one must refuse loudly, not mis-scan.
func TestStdinRefusals(t *testing.T) {
	dir := t.TempDir()
	ckpt := writeGateFile(t, dir, "ckpt.json", "{}\n")
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"fs", []string{"-fs", "-"}, "seekable"},
		{"walk", []string{"-walk", "-"}, "directory"},
		{"checkpoint", []string{"-checkpoint", ckpt, "-"}, "not supported with stdin"},
		{"resume", []string{"-checkpoint", ckpt, "-resume", "-"}, "not supported with stdin"},
		{"unallocated", []string{"-unallocated-only", "-"}, "filesystem offsets"},
	} {
		_, stderr, exit := runTestBinary(t, tc.args...)
		if exit != 1 {
			t.Errorf("%s: expected exit 1, got %d", tc.name, exit)
		}
		if !strings.Contains(stderr, tc.want) {
			t.Errorf("%s: stderr must contain %q, got:\n%s", tc.name, tc.want, stderr)
		}
	}
}

// gitHistoryRepo builds a fixture repo with a committed-then-removed
// fake AWS key (the actual leak shape) and returns the repo dir plus
// the two commit shas. Hermetic: identity, branch, and HOME are all
// pinned so user config cannot interfere.
func gitHistoryRepo(t *testing.T) (dir, sha1, sha2 string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir = t.TempDir()
	home := t.TempDir()
	run := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", dir,
			"-c", "user.name=Gate", "-c", "user.email=gate@x",
			"-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false",
		}, args...)...)
		cmd.Env = append(os.Environ(), "HOME="+home, "GIT_CONFIG_NOSYSTEM=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init")
	writeGateFile(t, dir, "config.env", "user=ops\naws_access_key_id=AKIAIOSFODNN7EXAMPLE\n")
	run("add", "config.env")
	run("commit", "-m", "add deploy config")
	sha1 = run("rev-parse", "HEAD")
	writeGateFile(t, dir, "config.env", "user=ops\n")
	run("commit", "-am", "remove leaked key")
	sha2 = run("rev-parse", "HEAD")
	return dir, sha1, sha2
}

func gitLogPatch(t *testing.T, dir string, args ...string) string {
	t.Helper()
	home := t.TempDir()
	cmd := exec.Command("git", append([]string{"-C", dir, "log", "-p",
		"--no-color", "--no-ext-diff", "--no-textconv",
	}, args...)...)
	cmd.Env = append(os.Environ(), "HOME="+home, "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git log -p: %v\n%s", err, out)
	}
	return string(out)
}

// The history-gate contract (Goal 36): `git log -p` piped through
// -patch attributes the leaked-then-removed key to its commits +
// path, a reviewed baseline suppresses exactly the known findings
// while a newly committed key still reports, and -fail-on-hit
// exits 3 on unbaselined history.
func TestPatchHistoryGate(t *testing.T) {
	dir, sha1, sha2 := gitHistoryRepo(t)
	patch := gitLogPatch(t, dir)

	stdout, stderr, exit := runTestBinaryStdin(t, patch, "-profile=secrets", "-patch", "-json", "-")
	if exit != 0 {
		t.Fatalf("history scan exit %d (stderr: %s)", exit, firstLine(stderr))
	}
	var added, removed bool
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		if !strings.Contains(line, `"needle":"aws-access-key"`) {
			continue
		}
		switch {
		case strings.Contains(line, `"commit":"`+sha1+`"`) &&
			strings.Contains(line, `"path":"config.env"`) &&
			strings.Contains(line, `"line":2`):
			added = true
		case strings.Contains(line, `"commit":"`+sha2+`"`) &&
			strings.Contains(line, `"path":"config.env"`) &&
			!strings.Contains(line, `"line":`):
			removed = true
		}
	}
	if !added || !removed {
		t.Fatalf("want added-line hit (%s) and removed-line hit (%s), got:\n%s", sha1, sha2, stdout)
	}

	// A reviewed baseline silences exactly the known findings.
	baseline := writeGateFile(t, dir, "known.jsonl", stdout)
	gotOut, gotErr, gotExit := runTestBinaryStdin(t, patch, "-profile=secrets", "-patch", "-json", "-baseline", baseline, "-")
	if gotExit != 0 {
		t.Fatalf("baselined history exit %d (stderr: %s)", gotExit, firstLine(gotErr))
	}
	if strings.TrimSpace(gotOut) != "" {
		t.Fatalf("baselined history must print no hits, got:\n%s", gotOut)
	}
	if !strings.Contains(gotErr, "suppressed by baseline") {
		t.Errorf("baselined history must report suppression, stderr:\n%s", gotErr)
	}

	// Without the baseline the gate trips.
	_, _, failExit := runTestBinaryStdin(t, patch, "-profile=secrets", "-patch", "-fail-on-hit", "-")
	if failExit != 3 {
		t.Errorf("ungated history with -fail-on-hit must exit 3, got %d", failExit)
	}

	// A newly committed key reports while the old findings stay silent.
	writeGateFile(t, dir, "config.env", "user=ops\naws_access_key_id=AKIAZZZZZZZZZZZZZZZZ\n")
	home := t.TempDir()
	add := exec.Command("git", "-C", dir, "-c", "user.name=Gate", "-c", "user.email=gate@x",
		"commit", "-am", "rotate key")
	add.Env = append(os.Environ(), "HOME="+home, "GIT_CONFIG_NOSYSTEM=1")
	if out, err := add.CombinedOutput(); err != nil {
		t.Fatalf("commit 3: %v\n%s", err, out)
	}
	rev := exec.Command("git", "-C", dir, "rev-parse", "HEAD")
	rev.Env = append(os.Environ(), "HOME="+home, "GIT_CONFIG_NOSYSTEM=1")
	sha3out, err := rev.CombinedOutput()
	if err != nil {
		t.Fatalf("rev-parse: %v", err)
	}
	sha3 := strings.TrimSpace(string(sha3out))
	patch3 := gitLogPatch(t, dir)
	newOut, _, newExit := runTestBinaryStdin(t, patch3, "-profile=secrets", "-patch", "-json", "-baseline", baseline, "-")
	if newExit != 0 {
		t.Fatalf("ranged re-gate exit %d", newExit)
	}
	if !strings.Contains(newOut, `"commit":"`+sha3+`"`) {
		t.Fatalf("new commit %s must report, got:\n%s", sha3, newOut)
	}
	if strings.Contains(newOut, `"commit":"`+sha1+`"`) || strings.Contains(newOut, `"commit":"`+sha2+`"`) {
		t.Fatalf("old commits must stay suppressed, got:\n%s", newOut)
	}
}

// -patch attributes one patch stream: modes that slice, sweep, or
// decode other shapes refuse it, and -baseline without -patch (or
// -walk) still refuses.
func TestPatchRefusals(t *testing.T) {
	dir := t.TempDir()
	target := writeGateFile(t, dir, "target.bin", strings.Repeat("x", 100))
	ckpt := writeGateFile(t, dir, "known.jsonl", "{}\n")
	for _, tc := range []struct {
		name string
		args []string
		want string
		exit int
	}{
		{"fs", []string{"-patch", "-fs", target}, "no meaning for -fs", 1},
		{"walk", []string{"-patch", "-walk", dir}, "not patches", 1},
		{"unallocated", []string{"-patch", "-unallocated-only", target}, "would misattribute", 1},
		{"checkpoint", []string{"-patch", "-checkpoint", ckpt, target}, "not supported with -patch", 1},
		{"resume", []string{"-patch", "-checkpoint", ckpt, "-resume", target}, "not supported with -patch", 1},
		{"fs-baseline", []string{"-fs", target, "-baseline", ckpt}, "no meaning for -fs", 2},
		{"baseline", []string{"-baseline", ckpt, target}, "-walk and -patch findings only", 2},
	} {
		_, stderr, exit := runTestBinary(t, tc.args...)
		if exit != tc.exit {
			t.Errorf("%s: expected exit %d, got %d", tc.name, tc.exit, exit)
		}
		if !strings.Contains(stderr, tc.want) {
			t.Errorf("%s: stderr must contain %q, got:\n%s", tc.name, tc.want, stderr)
		}
	}
}

func writeGateFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// The -fail-on-hit contract: exit 3 on hits only with the flag;
// default behavior (exit 0 with hits) frozen; errors still exit 1,
// usage still 2.
func TestFailOnHitMatrix(t *testing.T) {
	dir := t.TempDir()
	clean := writeGateFile(t, dir, "clean.txt", "hello prose, nothing to find here\n")
	dirty := writeGateFile(t, dir, "dirty.bin", "padding bestblock padding\n")
	cleanDir := t.TempDir()
	writeGateFile(t, cleanDir, "ok.txt", "nothing here either\n")
	dirtyDir := t.TempDir()
	writeGateFile(t, dirtyDir, "leak.txt", "residue defaultkey tail\n")
	emptyHits := writeGateFile(t, dir, "empty.jsonl", "")
	hitsOut := filepath.Join(dir, "hits.jsonl")
	// Generate the hits file through the binary under test.
	cmd := exec.Command(testBinary, "-json", dirty)
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("cannot generate hits fixture: %v", err)
	}
	if err := os.WriteFile(hitsOut, raw, 0644); err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Fatal("hits fixture is empty")
	}
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"scan clean with flag", []string{"-fail-on-hit", clean}, 0},
		{"scan dirty with flag", []string{"-fail-on-hit", dirty}, 3},
		{"scan dirty default", []string{dirty}, 0},
		{"scan clean default", []string{clean}, 0},
		{"walk clean with flag", []string{"-walk", cleanDir, "-fail-on-hit"}, 0},
		{"walk dirty with flag", []string{"-walk", dirtyDir, "-fail-on-hit"}, 3},
		{"walk dirty default", []string{"-walk", dirtyDir}, 0},
		{"report hits with flag", []string{"-report", hitsOut, "-fail-on-hit"}, 3},
		{"report empty with flag", []string{"-report", emptyHits, "-fail-on-hit"}, 0},
		{"report hits default", []string{"-report", hitsOut}, 0},
		{"missing with flag", []string{"-fail-on-hit", filepath.Join(dir, "absent.bin")}, 1},
		{"bad flag", []string{"-bogus-flag-xyz"}, 2},
	}
	for _, c := range cases {
		_, stderr, exit := runTestBinary(t, c.args...)
		if exit != c.want {
			t.Errorf("%s: exit %d, want %d (stderr: %s)", c.name, exit, c.want, firstLine(stderr))
		}
	}
	// The trip is loud on stderr, so CI logs explain themselves.
	_, stderr, _ := runTestBinary(t, "-fail-on-hit", dirty)
	if !strings.Contains(stderr, "exiting 3") {
		t.Errorf("gate trip must say so on stderr, got: %s", firstLine(stderr))
	}
}

// The coverage-honesty contract (Goal 31): a scan whose ROOT target
// fails exits 1 with the reason on stderr; a -walk that scanned
// nothing exits 1; a bad nested archive inside a good root stays a
// warning with exit 0; -report names the empty-input ambiguity.
func TestCoverageExitMatrix(t *testing.T) {
	dir := t.TempDir()
	clean := writeGateFile(t, dir, "clean.txt", "hello prose, nothing to find here\n")
	dirty := writeGateFile(t, dir, "dirty.bin", "padding bestblock padding\n")
	empty := writeGateFile(t, dir, "empty.bin", "")
	nested := writeCorruptZipRoot(t, dir, "nested.bin")

	// chmod-000 only bites on enforcing platforms; where the probe
	// open succeeds (Windows/root) the permission cases cannot run.
	noperm := writeGateFile(t, dir, "noperm.bin", "bestblock but unreadable\n")
	canEnforce := true
	if err := os.Chmod(noperm, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(noperm, 0644) })
	if f, err := os.Open(noperm); err == nil {
		f.Close()
		canEnforce = false
		t.Log("platform reads chmod-000 files; permission cases skipped")
	}

	allFailed := t.TempDir()
	for _, n := range []string{"a.bin", "b.bin"} {
		p := writeGateFile(t, allFailed, n, "bestblock but unreadable\n")
		if err := os.Chmod(p, 0000); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(p, 0644)
	}
	partialDir := t.TempDir()
	writeGateFile(t, partialDir, "good.txt", "residue defaultkey tail\n")
	partialBad := writeGateFile(t, partialDir, "bad.txt", "bestblock but unreadable\n")
	if err := os.Chmod(partialBad, 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(partialBad, 0644)
	nestedDir := t.TempDir()
	nestedCopy, err := os.ReadFile(nested)
	if err != nil {
		t.Fatal(err)
	}
	writeGateFile(t, nestedDir, "nested.bin", string(nestedCopy))
	emptyDir := t.TempDir()
	emptyHits := writeGateFile(t, dir, "empty.jsonl", "")

	cases := []struct {
		name       string
		args       []string
		want       int
		needsPerms bool
	}{
		// Root-target failure is exit 1, never a silent success.
		{"chmod-000 root scan", []string{noperm}, 1, true},
		{"all-failed walk", []string{"-walk", allFailed}, 1, true},
		{"empty-dir walk scans nothing", []string{"-walk", emptyDir}, 1, false},
		// Nested-target tolerance is unchanged: still 0.
		{"nested corrupt archive scan", []string{"-json", nested}, 0, false},
		{"nested corrupt archive walk", []string{"-walk", nestedDir}, 0, false},
		// Normal scans are unchanged.
		{"clean scan", []string{clean}, 0, false},
		{"dirty scan default", []string{dirty}, 0, false},
		{"empty file scan", []string{empty}, 0, false},
		{"partial-failure walk", []string{"-walk", partialDir}, 0, false},
		{"report empty", []string{"-report", emptyHits}, 0, false},
	}
	for _, c := range cases {
		if c.needsPerms && !canEnforce {
			continue
		}
		_, stderr, exit := runTestBinary(t, c.args...)
		if exit != c.want {
			t.Errorf("%s: exit %d, want %d (stderr: %s)", c.name, exit, c.want, firstLine(stderr))
		}
	}

	// The root failure names its reason on stderr.
	if canEnforce {
		_, stderr, _ := runTestBinary(t, noperm)
		if !strings.Contains(stderr, "Exiting due to error") {
			t.Errorf("root failure must exit loudly, got: %s", firstLine(stderr))
		}
		if !strings.Contains(stderr, "permission denied") {
			t.Errorf("root failure must name the reason, got: %s", firstLine(stderr))
		}
		// The zero-coverage walk says what happened, not just a code.
		_, stderr, _ = runTestBinary(t, "-walk", allFailed)
		if !strings.Contains(stderr, "nothing was covered") {
			t.Errorf("zero-coverage walk must say so, got: %s", firstLine(stderr))
		}
		// Partial failure stays 0 but is loud.
		_, stderr, _ = runTestBinary(t, "-walk", partialDir)
		if !strings.Contains(stderr, "WARNING") || !strings.Contains(stderr, "coverage is incomplete") {
			t.Errorf("partial-failure walk must warn loudly, got: %s", firstLine(stderr))
		}
	}

	// Nested tolerance proof: the root needle still reports, the
	// nested failure still warns, the exit stays 0.
	stdout, stderr, exit := runTestBinary(t, "-json", nested)
	if exit != 0 {
		t.Errorf("nested tolerance: exit %d, want 0 (stderr: %s)", exit, firstLine(stderr))
	}
	if !strings.Contains(stdout, "bestblock") {
		t.Errorf("nested tolerance: root needle lost (stdout: %s)", firstLine(stdout))
	}
	if !strings.Contains(stderr, "Unable to scan target") {
		t.Errorf("nested tolerance: nested failure must still warn (stderr: %s)", firstLine(stderr))
	}

	// -report distinguishes "no detections" from "nothing scanned".
	stdout, _, _ = runTestBinary(t, "-report", emptyHits)
	if !strings.Contains(stdout, "nothing to pursue") {
		t.Errorf("empty report lost its verdict (stdout: %s)", firstLine(stdout))
	}
	if !strings.Contains(stdout, "nothing was scanned") {
		t.Errorf("empty report must name the nothing-scanned ambiguity (stdout: %s)", firstLine(stdout))
	}
}

// writeCorruptZipRoot builds the nested-tolerance fixture: a root file
// carrying a live needle plus a zip whose headers are intact but whose
// member data is corrupt. The member publishes (headers parse) then
// fails at inflate (nested warning, tolerated). Corruption is verified
// with archive/zip itself: NewReader must succeed, member read must fail.
func writeCorruptZipRoot(t *testing.T, dir, name string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("member.txt")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		fmt.Fprintf(w, "member line %04d with varied payload text %d\n", i, i*7919)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	// Local header (30 bytes) + "member.txt" (10 bytes): deflated data
	// starts at 40. Corrupt inside the data, far from the ECD/central
	// directory at the tail.
	if len(raw) < 120 {
		t.Fatalf("zip fixture too small (%d bytes) to corrupt safely", len(raw))
	}
	for _, off := range []int{48, 52, 56, 60} {
		raw[off] ^= 0xff
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("fixture headers must stay intact: %v", err)
	}
	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(rc); err == nil {
		t.Fatal("fixture member must fail to inflate")
	}
	rc.Close()
	root := append([]byte("root needle bestblock above the archive\n"), raw...)
	return writeGateFile(t, dir, name, string(root))
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// The pre-commit sample gates a real git repo end to end: clean
// commits pass, a planted secret fails with exit 3. Unix-only (sh);
// the flag matrix above covers Windows.
func TestPreCommitSample(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh hook sample; unix only")
	}
	for _, tool := range []string{"sh", "git"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("needs %s: %v", tool, err)
		}
	}
	repo := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q")
	writeGateFile(t, repo, "notes.txt", "just prose, nothing secret\n")
	hookPath, err := filepath.Abs("samples/pre-commit")
	if err != nil {
		t.Fatal(err)
	}
	hook := func() (string, int) {
		t.Helper()
		cmd := exec.Command("sh", hookPath)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(), "FINDBTC="+testBinary)
		var errBuf strings.Builder
		cmd.Stderr = &errBuf
		err := cmd.Run()
		exit := 0
		if err != nil {
			ee, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatalf("cannot run hook sample: %v", err)
			}
			exit = ee.ExitCode()
		}
		return errBuf.String(), exit
	}
	if stderr, exit := hook(); exit != 0 {
		t.Errorf("clean repo: hook exit %d, want 0 (stderr: %s)", exit, firstLine(stderr))
	}
	// A planted AWS key ID (AWS's published example shape, fake).
	writeGateFile(t, repo, "env.txt", "aws_access_key_id=AKIAIOSFODNN7EXAMPLE\n")
	stderr, exit := hook()
	if exit != 3 {
		t.Errorf("planted secret: hook exit %d, want 3 (stderr: %s)", exit, firstLine(stderr))
	}
	if !strings.Contains(stderr, "not committing") {
		t.Errorf("hook must explain the block, got: %s", firstLine(stderr))
	}
}

// The -report -complete contract (Goal 32): a follow-up, not a mode.
// Flag misuse exits 2; a smudged-word file completes end to end with
// the original word among the candidates; crafted 3-gap input refuses
// loudly toward BTCRecover; -complete-out feeds -watch with no
// copy-paste.
func TestCompleteCLI(t *testing.T) {
	dir := t.TempDir()
	// Smudged-paper recipe: 11 known words + xxxx placeholder.
	smudged := writeGateFile(t, dir, "smudged.txt",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon xxxx\n")
	cmd := exec.Command(testBinary, "--reveal", "-json", smudged)
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("cannot generate completion fixture: %v", err)
	}
	if !strings.Contains(string(raw), "near-miss") {
		t.Fatalf("smudged fixture must scan as near-miss, got: %s", firstLine(string(raw)))
	}
	hits := writeGateFile(t, dir, "hits.jsonl", string(raw))

	cases := []struct {
		name string
		args []string
		want int
	}{
		{"complete without report", []string{"-complete", "--reveal"}, 2},
		{"complete-out without complete", []string{"-report", hits, "-complete-out", "k.txt"}, 2},
		{"complete without reveal", []string{"-report", hits, "-complete"}, 2},
		{"complete with json", []string{"-report", hits, "-complete", "--reveal", "-json"}, 2},
		{"complete-max zero", []string{"-report", hits, "-complete", "--reveal", "-complete-max", "0"}, 2},
		{"complete-max huge", []string{"-report", hits, "-complete", "--reveal", "-complete-max", "99999"}, 2},
		{"complete happy path", []string{"-report", hits, "-complete", "--reveal", "-complete-max", "5"}, 0},
	}
	for _, c := range cases {
		_, stderr, exit := runTestBinary(t, c.args...)
		if exit != c.want {
			t.Errorf("%s: exit %d, want %d (stderr: %s)", c.name, exit, c.want, firstLine(stderr))
		}
	}
	_, stderr, _ := runTestBinary(t, "-report", hits, "-complete")
	if !strings.Contains(stderr, "--reveal") {
		t.Errorf("missing---reveal refusal must name --reveal, got: %s", firstLine(stderr))
	}
	// End to end: the original 12th word ("about") is among the
	// candidates, most-likely first, with the scam shield on stderr.
	stdout, stderr, _ := runTestBinary(t, "-report", hits, "-complete", "--reveal")
	if !strings.Contains(stdout, "128 checksum-valid completions") {
		t.Errorf("completion must report the oracle total 128, got: %s", firstLine(stdout))
	}
	if !strings.Contains(stdout, "candidate 1: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about") {
		t.Errorf("head candidate must restore the phrase, got: %s", firstLine(stdout))
	}
	for _, want := range []string{"SCAM SHIELD", "local terminal"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q: %s", want, firstLine(stderr))
		}
	}
	// Crafted 3-gap input refuses loudly toward BTCRecover, exit 0
	// (completed triage, like "no crack material").
	refusal := writeGateFile(t, dir, "refusal.jsonl",
		`{"description":"Found 'bip39-12-near-miss gaps=[0,1,2]' at x","needle":"bip39-12-near-miss","offset":0,"target":"x","block_offset":0,"match_length":10,"words":["xxxx","xxxx","xxxx","abandon","abandon","abandon","abandon","abandon","abandon","abandon","abandon","abandon"]}`+"\n")
	stdout, _, exit := runTestBinary(t, "-report", refusal, "-complete", "--reveal")
	if exit != 0 {
		t.Errorf("refusal exit %d, want 0", exit)
	}
	for _, want := range []string{"REFUSED", "BTCRecover", "GPU"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("refusal lacks %q: %s", want, firstLine(stdout))
		}
	}
	// Handoff: -complete-out keys feed -watch with no copy-paste.
	keys := filepath.Join(dir, "keys.txt")
	addrs := filepath.Join(dir, "addrs.csv")
	_, _, exit = runTestBinary(t, "-report", hits, "-complete", "--reveal", "-complete-max", "2", "-complete-out", keys)
	if exit != 0 {
		t.Fatalf("complete-out exit %d", exit)
	}
	keysRaw, err := os.ReadFile(keys)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(keysRaw), "# candidate "); n != 2 {
		t.Errorf("keys file holds %d candidate blocks, want 2", n)
	}
	for _, prefix := range []string{"xpub", "ypub", "zpub"} {
		if !strings.Contains(string(keysRaw), prefix) {
			t.Errorf("keys file lacks %s keys", prefix)
		}
	}
	if strings.Contains(string(keysRaw), "abandon") {
		t.Error("keys file must never hold phrase words")
	}
	_, stderr, exit = runTestBinary(t, "-watch", keys, "-watch-out", addrs)
	if exit != 0 {
		t.Fatalf("watch handoff exit %d (stderr: %s)", exit, firstLine(stderr))
	}
	addrsRaw, err := os.ReadFile(addrs)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(addrsRaw)), "\n")
	if len(lines) != 1+6*2*20 { // header + 6 keys x 2 chains x 20
		t.Errorf("handoff derived %d CSV rows, want %d", len(lines), 1+6*2*20)
	}
}

// The -tokenlist contract (Goal 33): flag misuse exits 2; a context file
// yields the golden tokenlist on stdout or -tokenlist-out; hits.jsonl
// with carves reads through to the carve bytes; empty input is a
// completed answer (exit 0), like "No crack material found". The real
// BTCRecover crack runs in CI (scripts/password-handoff.sh); this pins
// the CLI side of that contract.
func TestTokenlistCLI(t *testing.T) {
	dir := t.TempDir()
	ctx := writeGateFile(t, dir, "ctx.bin", "\x00kern river 2019\x00")
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"out without tokenlist", []string{"-tokenlist-out", "t.txt"}, 2},
		{"max without tokenlist", []string{"-tokenlist-max", "5"}, 2},
		{"max zero", []string{"-tokenlist", ctx, "-tokenlist-max", "0"}, 2},
		{"max huge", []string{"-tokenlist", ctx, "-tokenlist-max", "100001"}, 2},
		{"missing file", []string{"-tokenlist", filepath.Join(dir, "absent.bin")}, 1},
		{"happy path", []string{"-tokenlist", ctx}, 0},
	}
	for _, c := range cases {
		_, stderr, exit := runTestBinary(t, c.args...)
		if exit != c.want {
			t.Errorf("%s: exit %d, want %d (stderr: %s)", c.name, exit, c.want, firstLine(stderr))
		}
	}
	want := "# findbtc tokenlist: 3 base words, one line each.\n" +
		"# Same-line tokens are mutually exclusive variants; tune --max-tokens.\n" +
		"kern KERN Kern\nriver RIVER River\n2019\n"
	stdout, _, _ := runTestBinary(t, "-tokenlist", ctx)
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	out := filepath.Join(dir, "tokens.txt")
	stdout, _, exit := runTestBinary(t, "-tokenlist", ctx, "-tokenlist-out", out)
	if exit != 0 {
		t.Fatalf("tokenlist-out exit %d", exit)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != want {
		t.Errorf("file = %q, want %q", raw, want)
	}
	if !strings.Contains(stdout, "Wrote 3 token lines") || !strings.Contains(stdout, "btcrecover.py") {
		t.Errorf("file mode must report + point at BTCRecover, got: %s", firstLine(stdout))
	}
	// Truncation warns on stderr and cuts whole lines.
	_, stderr, _ := runTestBinary(t, "-tokenlist", ctx, "-tokenlist-max", "2")
	if !strings.Contains(stderr, "showing first 2") {
		t.Errorf("truncation must warn, got: %s", firstLine(stderr))
	}
	// Empty input completes (exit 0), like -hashes with no material.
	empty := writeGateFile(t, dir, "empty.bin", "\x00\x01 a bb")
	stdout, _, exit = runTestBinary(t, "-tokenlist", empty)
	if exit != 0 || !strings.Contains(stdout, "No token words found") {
		t.Errorf("empty: exit %d stdout %q", exit, firstLine(stdout))
	}
	// hits.jsonl with a carve reads through to the carve bytes.
	carve := writeGateFile(t, dir, "carve.bin", "quiet harbor pilot static")
	hits := writeGateFile(t, dir, "hits.jsonl",
		`{"description":"d","needle":"bestblock","offset":0,"target":"t","block_offset":0,"match_length":8,"carve_path":"`+carve+`"}`+"\n")
	stdout, _, exit = runTestBinary(t, "-tokenlist", hits)
	if exit != 0 {
		t.Fatalf("hits.jsonl exit %d", exit)
	}
	if !strings.Contains(stdout, "harbor HARBOR Harbor") || !strings.Contains(stdout, "pilot PILOT Pilot") {
		t.Errorf("hits.jsonl must read carve bytes, got:\n%s", stdout)
	}
	// hits.jsonl without carves errors loudly (mirrors -watch).
	nocarve := writeGateFile(t, dir, "nocarve.jsonl",
		`{"description":"d","needle":"bestblock","offset":0,"target":"t","block_offset":0,"match_length":8}`+"\n")
	_, stderr, exit = runTestBinary(t, "-tokenlist", nocarve)
	if exit != 1 || !strings.Contains(stderr, "no carve paths") {
		t.Errorf("carveless hits: exit %d stderr %q", exit, firstLine(stderr))
	}
}

// The -hashes contract (Goal 33): crack-ready hashes on stdout, skip
// reasons on stderr (stdout stays a pure hash list in both modes),
// exit 0 throughout — only I/O failures exit 1.
func TestHashesCLI(t *testing.T) {
	dir := t.TempDir()
	// Happy path: the committed BDB mkey fixture exports one hash.
	stdout, stderr, exit := runTestBinary(t, "-hashes", filepath.Join("testdata", "password-handoff", "core-bdb-mkey.bin"))
	if exit != 0 {
		t.Fatalf("happy path exit %d (stderr: %s)", exit, firstLine(stderr))
	}
	if !strings.Contains(stdout, "$bitcoin$") {
		t.Errorf("happy path must print the hash, got: %s", firstLine(stdout))
	}
	if strings.Contains(stderr, "skipped") {
		t.Errorf("happy path must not report skips, got: %s", firstLine(stderr))
	}
	// Unsupported-but-complete keystore: generic stdout plus a stderr
	// reason naming the cipher — never silent, never a bogus hash.
	bad := writeGateFile(t, dir, "cbc.json",
		`{"address":"de0b295669a9fd93d5f28d9ec85e40f4cb697bae",`+
			`"crypto":{"cipher":"aes-256-cbc","ciphertext":"ab12","cipherparams":{"iv":"00112233445566778899aabbccddeeff"},`+
			`"kdf":"pbkdf2","kdfparams":{"dklen":32,"c":4096,"prf":"hmac-sha256","salt":"aabbccdd"},`+
			`"mac":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"},`+
			`"id":"00000000-0000-4000-8000-000000000000","version":3}`)
	stdout, stderr, exit = runTestBinary(t, "-hashes", bad)
	if exit != 0 || !strings.Contains(stdout, "No crack material found") {
		t.Errorf("unsupported cipher: exit %d stdout %q", exit, firstLine(stdout))
	}
	if want := `skipped ethereum-keystore @0: unsupported cipher "aes-256-cbc"`; !strings.Contains(stderr, want) {
		t.Errorf("unsupported cipher must explain on stderr, got: %q", firstLine(stderr))
	}
	// Presale: detected as out of scope.
	pre := writeGateFile(t, dir, "presale.json",
		`{"encseed":"00112233445566778899aabbccddeeff","ethaddr":"de0b295669a9fd93d5f28d9ec85e40f4cb697bae",`+
			`"bkp":"00112233445566778899aabbccddeeff","email":"owner@example.com"}`)
	stdout, stderr, exit = runTestBinary(t, "-hashes", pre)
	if exit != 0 || !strings.Contains(stdout, "No crack material found") {
		t.Errorf("presale: exit %d stdout %q", exit, firstLine(stdout))
	}
	if !strings.Contains(stderr, "skipped ethereum-presale") || !strings.Contains(stderr, "out of scope") {
		t.Errorf("presale must be detected as out of scope, got: %q", firstLine(stderr))
	}
	// -json keeps the pure-array shape; the skip still rides stderr.
	stdout, stderr, exit = runTestBinary(t, "-hashes", bad, "-json")
	if exit != 0 {
		t.Fatalf("json exit %d", exit)
	}
	if strings.TrimSpace(stdout) != "[]" {
		t.Errorf("json with no hashes must be [], got: %q", firstLine(stdout))
	}
	if !strings.Contains(stderr, "skipped ethereum-keystore") {
		t.Errorf("json mode must still explain skips, got: %q", firstLine(stderr))
	}
	// Missing file is the only loud failure.
	_, _, exit = runTestBinary(t, "-hashes", filepath.Join(dir, "absent.bin"))
	if exit != 1 {
		t.Errorf("missing file exit %d, want 1", exit)
	}
}

// Carves that all fail to read fail the run (exit 1): zero bytes
// scanned is blindness, not the "No token words found" success.
func TestTokenlistAllCarvesUnreadable(t *testing.T) {
	dir := t.TempDir()
	hits := writeGateFile(t, dir, "dead.jsonl",
		`{"description":"d","needle":"bestblock","offset":0,"target":"t","block_offset":0,"match_length":8,"carve_path":"`+filepath.Join(dir, "absent.bin")+`"}`+"\n")
	stdout, stderr, exit := runTestBinary(t, "-tokenlist", hits)
	if exit != 1 {
		t.Fatalf("all-unreadable carves exit %d, want 1 (stdout %q)", exit, firstLine(stdout))
	}
	if !strings.Contains(stderr, "none could be read") {
		t.Errorf("must name the failure, stderr: %q", firstLine(stderr))
	}
}

// Foreign JSON that merely parses is used verbatim, not refused as
// carveless hits: Detection has no required fields, so shape (any
// description/needle/target) is what marks real hits.jsonl.
func TestTokenlistForeignJSONVerbatim(t *testing.T) {
	dir := t.TempDir()
	foreign := writeGateFile(t, dir, "s.json", "{\"abc\": 1}\n")
	stdout, _, exit := runTestBinary(t, "-tokenlist", foreign)
	if exit != 0 {
		t.Fatalf("foreign JSON exit %d, want 0", exit)
	}
	if !strings.Contains(stdout, "abc ABC Abc") {
		t.Errorf("foreign JSON must extract words verbatim, got:\n%s", stdout)
	}
}

// Resuming prints the resume position, not just the byte offset: the
// owner sees where in the target the scan continues.
func TestResumePrintsPosition(t *testing.T) {
	dir := t.TempDir()
	target := writeGateFile(t, dir, "target.bin", strings.Repeat("x", 100))
	ckpt := writeGateFile(t, dir, "ckpt.json",
		fmt.Sprintf("{\"path\":%q,\"offset\":41,\"updated\":\"2026-01-01T00:00:00Z\"}\n", target))
	_, stderr, exit := runTestBinary(t, "-checkpoint", ckpt, "-resume", target)
	if exit != 0 {
		t.Fatalf("resume exit %d (stderr: %s)", exit, firstLine(stderr))
	}
	if !strings.Contains(stderr, "at byte offset 41 (continuing at 41%)") {
		t.Errorf("resume must print byte offset and percent, stderr:\n%s", stderr)
	}
}

// The doc-commands contract (Goal 33): every ```sh line in
// docs/PASSWORD_RECOVERY.md must be shaped to run verbatim under
// scripts/password-handoff.sh (same fence convention, known lead tool,
// no continuations, no output leaks), the harness must actually read
// those fences, CI must invoke the harness in a `password-handoff` job,
// and the doc's version stamp must match the CI pins. The real
// execution happens in CI; this test pins the wiring in-repo.
func TestPasswordRecoveryDocCommands(t *testing.T) {
	doc, err := os.ReadFile("docs/PASSWORD_RECOVERY.md")
	if err != nil {
		t.Fatal(err)
	}
	var cmds []string
	inBlock := false
	for _, line := range strings.Split(string(doc), "\n") {
		switch {
		case line == "```sh":
			if inBlock {
				t.Fatal("nested ```sh fence")
			}
			inBlock = true
		case line == "```":
			inBlock = false
		case inBlock:
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			cmds = append(cmds, line)
		}
	}
	if inBlock {
		t.Fatal("unclosed ```sh fence")
	}
	if len(cmds) < 20 {
		t.Fatalf("only %d doc commands; the runbook must stay executable", len(cmds))
	}
	for _, c := range cmds {
		lead := strings.SplitN(c, " ", 2)[0]
		switch lead {
		case "findbtc", "hashcat", "john", "python3":
		default:
			t.Errorf("doc command has unknown lead tool %q: %s", lead, c)
		}
		if strings.HasSuffix(c, "\\") {
			t.Errorf("doc command uses continuations (harness runs one line at a time): %s", c)
		}
		if strings.HasPrefix(c, "$") {
			t.Errorf("doc sh block leaks output, not a command: %s", c)
		}
	}
	harness, err := os.ReadFile("scripts/password-handoff.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(harness), "^```sh$") {
		t.Error("harness lost its ```sh fence extraction")
	}
	// Bare-name john takes conf AND pot from the CWD, so the harness
	// must link run files excluding prior session state — otherwise a
	// replayed run passes the crack assertions without cracking.
	if !strings.Contains(string(harness), "*.pot*|*.log*|*.rec") {
		t.Error("harness lost its john pot isolation")
	}
	ci, err := os.ReadFile(".github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"password-handoff", "scripts/password-handoff.sh"} {
		if !strings.Contains(string(ci), want) {
			t.Errorf("ci.yml lost %q", want)
		}
	}
	// The stamp names the pinned tools: CI pins are the source of
	// truth, the doc repeats them, and the harness re-checks both.
	pins := map[string]string{
		"JOHN_VERSION: '":        "1.9.0-jumbo-1",
		"HASHCAT_VERSION: '":     "6.2.6",
		"BTCR_SHA: '":            "1457088",
		"ETH_KEYFILE_VERSION: '": "0.6.0",
	}
	for key, want := range pins {
		if !strings.Contains(string(ci), key+want) {
			t.Errorf("ci.yml lost pin %s%s", key, want)
		}
		if !strings.Contains(string(doc), want) {
			t.Errorf("doc stamp lost %q (pin %s)", want, key)
		}
	}
}

// Wiring pin, not behavior proof: the workflow sample must keep
// invoking the same sweep the hook sample runs, so both gates agree.
// (Behavior is proven by the flag matrix + hook test; CI YAML itself
// only runs on GitHub.)
func TestSecretsGateWorkflowWiring(t *testing.T) {
	raw, err := os.ReadFile("samples/secrets-gate.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ghcr.io/pauljones0/findbtc",
		"-walk /repo -profile=secrets -fail-on-hit",
		"samples/pre-commit",
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("workflow sample lost %q", want)
		}
	}
	hook, err := os.ReadFile("samples/pre-commit")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(hook), "-walk \"$TOP\" -profile=secrets -fail-on-hit -json") {
		t.Error("hook sample drifted from the tested sweep shape")
	}
}
