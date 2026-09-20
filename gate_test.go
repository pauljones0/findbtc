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

	"github.com/pauljones0/findbtc/detector"
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

// advisedCommand runs -advise on dir and returns the Recommended
// line with the findbtc binary name swapped for the test binary
// (quoted, since it may hold spaces).
func advisedCommand(t *testing.T, dir string) string {
	t.Helper()
	stdout, _, exit := runTestBinary(t, "-advise", dir)
	if exit != 0 {
		t.Fatalf("-advise exit %d", exit)
	}
	for _, line := range strings.Split(stdout, "\n") {
		if rest, ok := strings.CutPrefix(line, "Recommended: findbtc "); ok {
			return `"` + testBinary + `" ` + rest
		}
	}
	t.Fatalf("no Recommended line in:\n%s", stdout)
	return ""
}

// The advised command must paste: on unix the recommendation for a
// spaced directory executes through a real sh byte-identical.
func TestAdviseCommandPastesSh(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh paste proof; unix only")
	}
	dir := filepath.Join(t.TempDir(), "spaced dir")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "m.bin")
	if err := os.WriteFile(marker, []byte(strings.Repeat("q", 5000)+"wallet.dat"+strings.Repeat("q", 5000)), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", advisedCommand(t, dir))
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		t.Fatalf("pasted advice failed: %v\nstderr:\n%s", err, errBuf.String())
	}
	if !strings.Contains(outBuf.String(), "m.bin") {
		t.Errorf("pasted walk found no hit in %s:\n%s", marker, outBuf.String())
	}
	if !strings.Contains(errBuf.String(), "[COMPLETE]") {
		t.Errorf("pasted walk never completed, stderr:\n%s", errBuf.String())
	}
}

// The advised command must paste on Windows through the labeled
// shell: the recommendation for a spaced directory executes through
// a real powershell.exe, and the quoted path round-trips through
// Write-Output byte-identical. (cmd.exe is not the labeled shell:
// PowerShell single-quote quoting would reach it literally.)
func TestAdviseCommandPastesPowerShell(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("powershell paste proof; windows only")
	}
	ps, err := exec.LookPath("powershell")
	if err != nil {
		t.Skip("no powershell available")
	}
	dir := filepath.Join(t.TempDir(), "spaced dir")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "m.bin")
	if err := os.WriteFile(marker, []byte(strings.Repeat("q", 5000)+"wallet.dat"+strings.Repeat("q", 5000)), 0644); err != nil {
		t.Fatal(err)
	}
	line := advisedCommand(t, dir)
	cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", "& "+line)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		t.Fatalf("pasted advice failed in powershell: %v\nstderr:\n%s", err, errBuf.String())
	}
	if !strings.Contains(outBuf.String(), "m.bin") {
		t.Errorf("pasted walk found no hit in %s:\n%s", marker, outBuf.String())
	}
	if !strings.Contains(errBuf.String(), "[COMPLETE]") {
		t.Errorf("pasted walk never completed, stderr:\n%s", errBuf.String())
	}
	// The quoted path echoes back byte-identical (ASCII path;
	// byte-exact nasty-name proof lives in the detector native
	// round-trip test).
	quoted, _ := strings.CutPrefix(line, `"`+testBinary+`" -walk `)
	out, err := exec.Command(ps, "-NoProfile", "-Command", "Write-Output "+quoted).CombinedOutput()
	if err != nil {
		t.Fatalf("powershell echo failed: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != dir {
		t.Errorf("powershell round-trip gave %q, want %q", got, dir)
	}
}

// Windows root semantics where supported (Goal 41): advising the
// drive root routes a walk without running one, and a small known
// system file scans identically under its plain and extended-length
// (\\?\) forms with honest completion. Only completion and coverage
// assert — the file's contents are the machine's, not a fixture.
// UNC (\\server\share) is explicitly out of scope: no offline SMB
// fixture exists, so no silent skip pretends to cover it.
func TestWindowsRootAndExtendedPath(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows root semantics; windows only")
	}
	stdout, _, exit := runTestBinary(t, "-advise", `C:\`)
	if exit != 0 {
		t.Fatalf("-advise C:\\ exit %d", exit)
	}
	if !strings.HasPrefix(strings.TrimSpace(firstLine(stdout)), "Target: ") {
		t.Fatalf("-advise C:\\ printed no target line:\n%s", stdout)
	}
	line := advisedCommand(t, `C:\`)
	if !strings.HasPrefix(line, `"`+testBinary+`" -walk `) {
		t.Fatalf("drive-root advice %q, want a -walk route (never executed here)", line)
	}
	hosts := filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", "etc", "hosts")
	if hosts == "" || os.Getenv("SystemRoot") == "" {
		t.Skip("no SystemRoot; cannot stage the known system file")
	}
	if _, err := os.Stat(hosts); err != nil {
		t.Skipf("hosts file unreadable (%v); nothing to prove root semantics on", err)
	}
	for _, target := range []string{hosts, `\\?\` + hosts} {
		log := filepath.Join(t.TempDir(), "case.jsonl")
		stdout, stderr, exit := runTestBinary(t, "-json", "-case-log", log, target)
		if exit != 0 {
			t.Errorf("scan of %q exit %d, stderr:\n%s", target, exit, stderr)
			continue
		}
		if !strings.Contains(stderr, "[COMPLETE]") {
			t.Errorf("scan of %q never completed, stderr:\n%s", target, stderr)
		}
		if strings.Contains(stderr, "WARNING") {
			t.Errorf("scan of %q warned, stderr:\n%s", target, stderr)
		}
		for i, line := range strings.Split(strings.TrimRight(stdout, "\n"), "\n") {
			if line == "" {
				continue
			}
			var hit map[string]any
			if err := json.Unmarshal([]byte(line), &hit); err != nil {
				t.Errorf("scan of %q line %d not JSON: %v", target, i, err)
			}
		}
		vout, _, vexit := runTestBinary(t, "-verify-case-log", log)
		if vexit != 0 {
			t.Errorf("case-log for %q failed verification:\n%s", target, vout)
		}
	}
}

// runTestBinaryDir runs the test binary with its working directory
// set, for relative-path cases like dash-prefixed filenames.
func runTestBinaryDir(t *testing.T, dir string, args ...string) (stdout, stderr string, exit int) {
	t.Helper()
	cmd := exec.Command(testBinary, args...)
	cmd.Dir = dir
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

// writeCarveHits writes a one-line hits.jsonl pointing at carvePath.
// The line is marshaled, never concatenated: raw Windows paths hold
// backslashes that would otherwise emit invalid JSON and silently
// exercise the foreign-text fallback instead of the carve reader.
func writeCarveHits(t *testing.T, dir, name, carvePath string) string {
	t.Helper()
	line, err := json.Marshal(map[string]any{
		"description":  "d",
		"needle":       "bestblock",
		"offset":       0,
		"target":       "t",
		"block_offset": 0,
		"match_length": 8,
		"carve_path":   carvePath,
	})
	if err != nil {
		t.Fatal(err)
	}
	return writeGateFile(t, dir, name, string(line)+"\n")
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
	hits := writeCarveHits(t, dir, "hits.jsonl", carve)
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
	hits := writeCarveHits(t, dir, "dead.jsonl", filepath.Join(dir, "absent.bin"))
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
// owner sees where in the target the scan continues. The announcement
// names the rewound grid point actually scanned, not the raw journal
// point: offset 41 minus the 2048-byte overlap clamps to 0, so this
// tiny fixture announces byte offset 0 (continuing at 0%).
func TestResumePrintsPosition(t *testing.T) {
	dir := t.TempDir()
	target := writeGateFile(t, dir, "target.bin", strings.Repeat("x", 10000))
	ident, ok := detector.FileIdentityOf(target)
	if !ok {
		t.Skip("no byte identity on this platform")
	}
	identJSON, err := json.Marshal(ident)
	if err != nil {
		t.Fatal(err)
	}
	// Genuine identity + mid-file offset: the frontier is
	// honored (rewound past the overlap window to the block
	// grid), proving resume — not rescan — prints the position.
	ckpt := writeGateFile(t, dir, "ckpt.json",
		fmt.Sprintf("{\"path\":%q,\"offset\":9000,\"updated\":\"2026-01-01T00:00:00Z\",\"identity\":%s}\n", target, identJSON))
	_, stderr, exit := runTestBinary(t, "-checkpoint", ckpt, "-resume", target)
	if exit != 0 {
		t.Fatalf("resume exit %d (stderr: %s)", exit, firstLine(stderr))
	}
	if !strings.Contains(stderr, "at byte offset 4096 (continuing at 40%)") {
		t.Errorf("resume must print byte offset and percent, stderr:\n%s", stderr)
	}
}

// Swapped bytes must not inherit a single-target frontier: a
// genuine journal (offset past the only needle) plus a
// same-size, mtime-restored replacement rescans from zero and
// reprints, instead of skipping contents never read.
func TestResumeSwappedBytesRescan(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("in-place mtime forgery is invisible to Windows stdlib identity (documented residual)")
	}
	dir := t.TempDir()
	// Needle up front, bulk after: an honored offset would skip
	// the only hit.
	target := writeGateFile(t, dir, "target.bin", "bestblock"+strings.Repeat("z", 10000))
	journal := filepath.Join(dir, "swap.cp")
	stdout, stderr, exit := runTestBinary(t, "-json", "-checkpoint", journal, target)
	if exit != 0 {
		t.Fatalf("initial scan exit %d\n%s", exit, stderr)
	}
	if !strings.Contains(stdout, "bestblock") {
		t.Fatalf("initial scan missed the needle\n%s", stdout)
	}
	// Same size, restored mtime, changed middle: the cheap
	// metadata matches, so only kernel identity refuses.
	st, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	swapped := "bestblock" + strings.Repeat("q", 10000)
	if len(swapped) != int(st.Size()) {
		t.Fatalf("swap fixture must preserve size: %d vs %d", len(swapped), st.Size())
	}
	if err := os.WriteFile(target, []byte(swapped), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(target, st.ModTime(), st.ModTime()); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, exit = runTestBinary(t, "-json", "-checkpoint", journal, "-resume", target)
	if exit != 0 {
		t.Fatalf("resume exit %d\n%s", exit, stderr)
	}
	if !strings.Contains(stderr, "rescanning from the start") {
		t.Errorf("swapped bytes must refuse the frontier loudly, stderr:\n%s", stderr)
	}
	if !strings.Contains(stdout, "bestblock") {
		t.Errorf("swapped bytes must rescan and reprint the hit, stdout:\n%s", stdout)
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

// The owner rehearsal (Goal 41) runs one README block verbatim:
// the markers must fence exactly one ```sh block of findbtc-only
// commands, and the harness plus CI must keep executing it.
func TestOwnerRehearsalWiring(t *testing.T) {
	raw, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	start, end := "<!-- owner-rehearsal:start -->", "<!-- owner-rehearsal:end -->"
	if strings.Count(doc, start) != 1 || strings.Count(doc, end) != 1 {
		t.Fatal("README must fence exactly one owner-rehearsal block")
	}
	inner := doc[strings.Index(doc, start):strings.Index(doc, end)]
	var cmds []string
	inBlock := false
	fences := 0
	for _, line := range strings.Split(inner, "\n") {
		switch {
		case line == "```sh":
			if inBlock {
				t.Fatal("nested ```sh fence in rehearsal block")
			}
			inBlock = true
			fences++
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
		t.Fatal("unclosed ```sh fence in rehearsal block")
	}
	if fences != 1 {
		t.Fatalf("%d ```sh fences in rehearsal block, want 1", fences)
	}
	if len(cmds) < 5 {
		t.Fatalf("only %d rehearsal commands; the owner path must stay executable", len(cmds))
	}
	for _, c := range cmds {
		lead := strings.SplitN(c, " ", 2)[0]
		if lead != "findbtc" {
			t.Errorf("rehearsal command has non-findbtc lead %q: %s", lead, c)
		}
		if strings.HasSuffix(c, "\\") {
			t.Errorf("rehearsal command uses continuations (harness runs one line at a time): %s", c)
		}
		if strings.HasPrefix(c, "$") {
			t.Errorf("rehearsal sh block leaks output, not a command: %s", c)
		}
	}
	harness, err := os.ReadFile("scripts/owner-rehearsal.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{start, end, "^```sh$"} {
		if !strings.Contains(string(harness), want) {
			t.Errorf("harness lost %q", want)
		}
	}
	ci, err := os.ReadFile(".github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"owner-rehearsal", "scripts/owner-rehearsal.sh"} {
		if !strings.Contains(string(ci), want) {
			t.Errorf("ci.yml lost %q", want)
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

// Multi-target batch (Goal 38): one run over mixed good/bad
// targets prints one hits stream with per-hit targets, appends one
// case-log record per scanned target, warns loudly about the bad
// one, and still exits 0 with [COMPLETE] — the Goal 31 walk rule.
// An all-bad batch exits 1 with no [COMPLETE].
func TestMultiTargetBatch(t *testing.T) {
	dir := t.TempDir()
	mkhit := func(name string) string {
		return writeGateFile(t, dir, name, strings.Repeat("q", 5000)+"wallet.dat"+strings.Repeat("q", 5000))
	}
	good1, good2 := mkhit("batch1.bin"), mkhit("batch2.bin")
	missing := filepath.Join(dir, "no-such-image.bin")
	caseLog := filepath.Join(dir, "case.jsonl")

	stdout, stderr, exit := runTestBinary(t, "-json", "-case-log", caseLog, good1, missing, good2)
	if exit != 0 {
		t.Fatalf("mixed batch exit %d, want 0 (stderr:\n%s)", exit, stderr)
	}
	if !strings.Contains(stderr, "[COMPLETE]") {
		t.Errorf("mixed batch must print [COMPLETE], stderr:\n%s", stderr)
	}
	if !strings.Contains(stderr, "WARNING") || !strings.Contains(stderr, missing) {
		t.Errorf("mixed batch must warn loudly naming %s, stderr:\n%s", missing, stderr)
	}
	// One hits stream, both targets labeled.
	var targets []string
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("hit is not JSON: %v\n%s", err, line)
		}
		tgt, _ := m["target"].(string)
		targets = append(targets, tgt)
	}
	seen := map[string]bool{}
	for _, tg := range targets {
		seen[tg] = true
	}
	if !seen[good1] || !seen[good2] {
		t.Errorf("one stream must carry both targets, got %v", targets)
	}
	if len(targets) == 0 {
		t.Error("batch fixtures produced no hits; test is vacuous")
	}
	// One case-log record per requested target: complete scans
	// plus a zero-coverage attempt record for the failure — failed
	// targets must not vanish from the durable evidence.
	raw, err := os.ReadFile(caseLog)
	if err != nil {
		t.Fatal(err)
	}
	var logged []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var rec struct {
			Status string `json:"status"`
			Error  string `json:"error"`
			Source struct {
				Path string `json:"path"`
				Kind string `json:"kind"`
			} `json:"source"`
			Hash struct {
				SHA256      string `json:"sha256"`
				MD5         string `json:"md5"`
				BytesHashed int64  `json:"bytes_hashed"`
			} `json:"hash"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("case-log line is not JSON: %v\n%s", err, line)
		}
		logged = append(logged, rec.Source.Path+":"+rec.Status)
		if rec.Source.Path == missing {
			if rec.Status != "error" {
				t.Errorf("failed target logged status %q, want error", rec.Status)
			}
			if rec.Hash.BytesHashed != 0 || rec.Hash.SHA256 != "" || rec.Hash.MD5 != "" {
				t.Errorf("attempt record invents coverage: %+v", rec.Hash)
			}
			if rec.Source.Kind != "unknown" {
				t.Errorf("attempt record kind %q, want unknown", rec.Source.Kind)
			}
			if !strings.Contains(rec.Error, missing) {
				t.Errorf("attempt record must carry the reason, got %q", rec.Error)
			}
		} else if rec.Status != "complete" {
			t.Errorf("scanned target logged status %q, want complete", rec.Status)
		}
	}
	want := []string{good1 + ":complete", missing + ":error", good2 + ":complete"}
	if strings.Join(logged, "\n") != strings.Join(want, "\n") {
		t.Errorf("want per-target records in scan order:\n%s\ngot:\n%s", strings.Join(want, "\n"), strings.Join(logged, "\n"))
	}

	// All-bad batch: zero coverage exits 1 with no [COMPLETE] —
	// but every attempt still leaves its record.
	badLog := filepath.Join(dir, "bad-case.jsonl")
	_, stderr, exit = runTestBinary(t, "-json", "-case-log", badLog, filepath.Join(dir, "missing-a.bin"), filepath.Join(dir, "missing-b.bin"))
	if exit != 1 {
		t.Errorf("all-bad batch exit %d, want 1 (stderr:\n%s)", exit, stderr)
	}
	if strings.Contains(stderr, "[COMPLETE]") {
		t.Errorf("all-bad batch must not print [COMPLETE], stderr:\n%s", stderr)
	}
	if !strings.Contains(stderr, "nothing was covered") {
		t.Errorf("all-bad batch must say nothing was covered, stderr:\n%s", stderr)
	}
	raw, err = os.ReadFile(badLog)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("all-bad batch must leave 2 attempt records, got %d", len(lines))
	}
	for _, line := range lines {
		var rec struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		if rec.Status != "error" {
			t.Errorf("all-bad record status %q, want error", rec.Status)
		}
	}
}

// Batch reports through the real CLI: a mixed hit/clean/missing
// scan exits 0 with [COMPLETE], yet its report lists only the
// hit-bearing target — so both the nonempty and the empty report
// must warn that hit targets are not coverage and point at the
// case log.
func TestBatchReportCoverage(t *testing.T) {
	dir := t.TempDir()
	hit := writeGateFile(t, dir, "hit.bin", strings.Repeat("q", 5000)+"wallet.dat"+strings.Repeat("q", 5000))
	clean := writeGateFile(t, dir, "clean.bin", strings.Repeat("z", 10010))
	missing := filepath.Join(dir, "missing.bin")
	caseLog := filepath.Join(dir, "case.jsonl")

	stdout, stderr, exit := runTestBinary(t, "-json", "-case-log", caseLog, hit, clean, missing)
	if exit != 0 {
		t.Fatalf("mixed batch exit %d", exit)
	}
	if !strings.Contains(stderr, "[COMPLETE]") {
		t.Fatalf("mixed batch must print [COMPLETE]")
	}
	hitsFile := writeGateFile(t, dir, "hits.jsonl", stdout)
	repOut, _, exit := runTestBinary(t, "-report", hitsFile)
	if exit != 0 {
		t.Fatalf("-report exit %d", exit)
	}
	if !strings.Contains(repOut, hit) {
		t.Errorf("report must list the hit-bearing target:\n%s", repOut)
	}
	if strings.Contains(repOut, clean) || strings.Contains(repOut, missing) {
		t.Errorf("report must not invent clean/failed targets:\n%s", repOut)
	}
	if !strings.Contains(repOut, "not scan coverage") || !strings.Contains(repOut, "complete case-log record") {
		t.Errorf("nonempty report must warn hit targets are not coverage:\n%s", repOut)
	}
	repJSON, _, _ := runTestBinary(t, "-report", hitsFile, "-json")
	var rep struct {
		CoverageNote string `json:"coverage_note"`
	}
	if err := json.Unmarshal([]byte(repJSON), &rep); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rep.CoverageNote, "not scan coverage") {
		t.Errorf("report JSON must carry the coverage note: %q", rep.CoverageNote)
	}

	// All-failed batch: empty hits, and the empty report must say
	// coverage is unknown with the case log as the check.
	emptyOut, _, exit := runTestBinary(t, "-json", missing, filepath.Join(dir, "missing2.bin"))
	if exit != 1 || emptyOut != "" {
		t.Fatalf("all-failed batch exit %d stdout %q, want 1/empty", exit, emptyOut)
	}
	emptyFile := writeGateFile(t, dir, "empty.jsonl", emptyOut)
	repOut, _, _ = runTestBinary(t, "-report", emptyFile)
	if !strings.Contains(repOut, "nothing was scanned") || !strings.Contains(repOut, "complete case-log record") {
		t.Errorf("empty batch report must disclaim coverage:\n%s", repOut)
	}
}

// -targets FILE joins positionals: blank lines and # comments are
// skipped, positionals scan first. A missing list file exits 1.
func TestTargetsFile(t *testing.T) {
	dir := t.TempDir()
	good := writeGateFile(t, dir, "listed.bin", strings.Repeat("q", 5000)+"wallet.dat"+strings.Repeat("q", 5000))
	first := writeGateFile(t, dir, "first.bin", strings.Repeat("q", 5000)+"wallet.dat"+strings.Repeat("q", 5000))
	list := writeGateFile(t, dir, "targets.txt", "# batch list\n\n"+good+"\n")
	caseLog := filepath.Join(dir, "case.jsonl")

	stdout, stderr, exit := runTestBinary(t, "-json", "-case-log", caseLog, "-targets", list, first)
	if exit != 0 {
		t.Fatalf("-targets run exit %d (stderr:\n%s)", exit, stderr)
	}
	// Parsed-JSON comparison: raw Contains fails on Windows,
	// where JSON escapes the backslashes in temp paths.
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("hit is not JSON: %v\n%s", err, line)
		}
		tgt, _ := m["target"].(string)
		seen[tgt] = true
	}
	if !seen[first] || !seen[good] {
		t.Errorf("-targets run must carry positional and listed hits, got targets %v", seen)
	}
	raw, err := os.ReadFile(caseLog)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 case-log records, got %d", len(lines))
	}
	var rec struct {
		Source struct {
			Path string `json:"path"`
		} `json:"source"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Source.Path != first {
		t.Errorf("positional must scan before listed targets, first record is %s", rec.Source.Path)
	}

	_, stderr, exit = runTestBinary(t, "-targets", filepath.Join(dir, "no-list.txt"), first)
	if exit != 1 {
		t.Errorf("missing -targets file exit %d, want 1 (stderr:\n%s)", exit, stderr)
	}
	if !strings.Contains(stderr, "no-list.txt") {
		t.Errorf("missing -targets file must be named, stderr:\n%s", stderr)
	}
}

// Single-target-only inputs refuse loudly in a multi-target run:
// stdin cannot be consumed twice, one -s cannot offset N targets,
// and a checkpoint journals one target.
// Multi-target checkpointing journals a per-target batch manifest
// (Goal 42); only the unallocated range journals stay refused.
func TestMultiTargetRefusals(t *testing.T) {
	dir := t.TempDir()
	a := writeGateFile(t, dir, "a.bin", "nothing here")
	b := writeGateFile(t, dir, "b.bin", "nothing here either")
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"stdin-mix", []string{"-", a}, "scanned alone"},
		{"start-offset", []string{"-s", "10", a, b}, "-s offsets one target"},
		{"checkpoint-unallocated", []string{"-unallocated-only", "-checkpoint", filepath.Join(dir, "c.json"), a, b}, "not supported with -unallocated-only"},
		{"resume-unallocated", []string{"-unallocated-only", "-checkpoint", filepath.Join(dir, "c.json"), "-resume", a, b}, "not supported with -unallocated-only"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, stderr, exit := runTestBinary(t, tc.args...)
			if exit != 2 {
				t.Errorf("%s exit %d, want 2 (stderr:\n%s)", tc.name, exit, stderr)
			}
			if !strings.Contains(stderr, tc.want) {
				t.Errorf("%s must explain %q, stderr:\n%s", tc.name, tc.want, stderr)
			}
		})
	}
}

// helpFlagNames parses the live flag table out of -h output (the
// flag package's own rendering: "  -name" lines), so the freshness
// tests below never hand-list a flag.
func helpFlagNames(t *testing.T) []string {
	t.Helper()
	stdout, stderr, exit := runTestBinary(t, "-h")
	if exit != 0 {
		t.Fatalf("-h exit %d, want 0", exit)
	}
	var names []string
	for _, line := range strings.Split(stdout+stderr, "\n") {
		if !strings.HasPrefix(line, "  -") || strings.HasPrefix(line, "   ") {
			continue
		}
		rest := strings.TrimPrefix(line, "  -")
		i := 0
		for i < len(rest) && (rest[i] == '-' || rest[i] >= 'a' && rest[i] <= 'z' || rest[i] >= 'A' && rest[i] <= 'Z' || rest[i] >= '0' && rest[i] <= '9') {
			i++
		}
		if i == 0 {
			continue
		}
		names = append(names, rest[:i])
	}
	if len(names) < 30 {
		t.Fatalf("-h parsed %d flags, table looks truncated", len(names))
	}
	return names
}

// Completions are generated from the real flag table (Goal 39):
// each committed script must byte-match a fresh render, and every
// -h flag must appear in every shell's script.
func TestGeneratedCompletionsFresh(t *testing.T) {
	shells := map[string]string{
		"bash": "packaging/completion/findbtc.bash",
		"zsh":  "packaging/completion/_findbtc",
		"fish": "packaging/completion/findbtc.fish",
	}
	for _, shell := range []string{"bash", "zsh", "fish"} {
		stdout, stderr, exit := runTestBinary(t, "-gen-completion="+shell)
		if exit != 0 {
			t.Fatalf("-gen-completion=%s exit %d (stderr: %s)", shell, exit, firstLine(stderr))
		}
		raw, err := os.ReadFile(shells[shell])
		if err != nil {
			t.Fatal(err)
		}
		if stdout != string(raw) {
			t.Errorf("%s completion drifted: re-run -gen-completion=%s", shells[shell], shell)
		}
	}
	names := helpFlagNames(t)
	// Anchored needles: a bare substring would let short flags
	// like -s match inside other words.
	raw, err := os.ReadFile(shells["bash"])
	if err != nil {
		t.Fatal(err)
	}
	var listed []string
	for _, line := range strings.Split(string(raw), "\n") {
		if i := strings.Index(line, `compgen -W "`); i >= 0 {
			rest := line[i+len(`compgen -W "`):]
			listed = strings.Fields(rest[:strings.Index(rest, `"`)])

		}
	}
	have := map[string]bool{}
	for _, tok := range listed {
		have[tok] = true
	}
	for _, n := range names {
		if !have["-"+n] {
			t.Errorf("bash completion lacks flag %q", n)
		}
	}
	raw, err = os.ReadFile(shells["zsh"])
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if !strings.Contains(string(raw), "'-"+n+"[") {
			t.Errorf("zsh completion lacks flag %q", n)
		}
	}
	raw, err = os.ReadFile(shells["fish"])
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if !strings.Contains(string(raw), "-o "+n+" ") {
			t.Errorf("fish completion lacks flag %q", n)
		}
	}
}

// The man page comes from the same source (Goal 39): the committed
// page must byte-match a fresh render, every -h flag must appear in
// OPTIONS, and SEE ALSO must link the three orphan guides.
func TestGeneratedManFresh(t *testing.T) {
	stdout, stderr, exit := runTestBinary(t, "-gen-man")
	if exit != 0 {
		t.Fatalf("-gen-man exit %d (stderr: %s)", exit, firstLine(stderr))
	}
	raw, err := os.ReadFile("packaging/man/findbtc.1")
	if err != nil {
		t.Fatal(err)
	}
	if stdout != string(raw) {
		t.Error("man page drifted: re-run -gen-man")
	}
	for _, n := range helpFlagNames(t) {
		// Troff escapes dashes; anchor on the .B request line.
		needle := ".B \\-" + strings.ReplaceAll(n, "-", `\-`)
		if !strings.Contains(string(raw), needle) {
			t.Errorf("man page lacks flag %q", n)
		}
	}
	for _, d := range []string{"BENCHMARKS.md", "PIPELINE_INGEST.md", "RESOURCE_BOUNDS.md"} {
		if !strings.Contains(string(raw), d) {
			t.Errorf("man page SEE ALSO lacks orphan doc %s", d)
		}
	}
}

// Generator misuse refuses loudly: an unknown shell and the
// completion+man combination both exit 2.
func TestGenRefusals(t *testing.T) {
	_, stderr, exit := runTestBinary(t, "-gen-completion=powershell")
	if exit != 2 {
		t.Errorf("bad shell exit %d, want 2 (stderr:\n%s)", exit, stderr)
	}
	if !strings.Contains(stderr, "bash, zsh, or fish") {
		t.Errorf("bad shell must list shells, stderr:\n%s", stderr)
	}
	_, stderr, exit = runTestBinary(t, "-gen-completion=bash", "-gen-man")
	if exit != 2 {
		t.Errorf("combined generators exit %d, want 2 (stderr:\n%s)", exit, stderr)
	}
}

// Scan inputs refuse in non-scan modes: -targets and stray
// positionals must exit 2 naming the mode, never vanish silently —
// including a missing -targets file, which must still error.
func TestScanInputModeGuard(t *testing.T) {
	dir := t.TempDir()
	list := writeGateFile(t, dir, "targets.txt", "a.bin\n")
	missingList := filepath.Join(dir, "no-list.txt")
	target := writeGateFile(t, dir, "t.bin", "nothing here")
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"targets-walk", []string{"-walk", dir, "-targets", list}, "-targets " + list},
		{"targets-walk-missing", []string{"-walk", dir, "-targets", missingList}, "no-list.txt"},
		{"targets-report", []string{"-report", target, "-targets", list}, "-report"},
		{"targets-fs", []string{"-fs", target, "-targets", list}, "-fs"},
		{"targets-advise", []string{"-advise", target, "-targets", list}, "-advise"},
		{"targets-gen", []string{"-gen-man", "-targets", list}, "generation"},
		{"positional-walk", []string{"-walk", dir, target}, "positional"},
		{"positional-report", []string{"-report", target, target}, "-report"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, stderr, exit := runTestBinary(t, tc.args...)
			if exit != 2 {
				t.Errorf("%s exit %d, want 2 (stderr:\n%s)", tc.name, exit, stderr)
			}
			if !strings.Contains(stderr, tc.want) {
				t.Errorf("%s must explain %q, stderr:\n%s", tc.name, tc.want, stderr)
			}
		})
	}
}

// Flags stop at the first positional (Go parsing): a -targets flag
// after a target is data, not a flag — and -- rescues filenames
// that start with a dash.
func TestFlagsBeforeTargets(t *testing.T) {
	dir := t.TempDir()
	marker := writeGateFile(t, dir, "marker.bin", strings.Repeat("q", 5000)+"wallet.dat"+strings.Repeat("q", 5000))
	plain := writeGateFile(t, dir, "plain.bin", strings.Repeat("z", 10010))
	list := writeGateFile(t, dir, "targets.txt", marker+"\n")

	// Flags-after-positional scans the tokens as media: neither
	// plain.bin nor targets.txt holds a marker, so opening the
	// list would be the only way a hit appears — and -targets
	// itself fails as a filename.
	stdout, stderr, exit := runTestBinary(t, "-json", plain, "-targets", list)
	if exit != 0 {
		t.Fatalf("flags-after run exit %d, want 0 (partial batch)", exit)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Errorf("flags-after-positional must not open the list:\n%s", stdout)
	}
	if !strings.Contains(stderr, "[main] failed: -targets") {
		t.Errorf("-targets token must fail as a filename, stderr:\n%s", stderr)
	}

	// -- passes dash-prefixed filenames through as targets.
	dash := writeGateFile(t, dir, "-dash.bin", strings.Repeat("q", 5000)+"wallet.dat"+strings.Repeat("q", 5000))
	stdout, stderr, exit = runTestBinaryDir(t, dir, "-json", "--", "-dash.bin")
	if exit != 0 {
		t.Fatalf("-- dash file exit %d (stderr:\n%s)", exit, stderr)
	}
	if !strings.Contains(stdout, "-dash.bin") {
		t.Errorf("-- dash file produced no hit for %s:\n%s", dash, stdout)
	}
	_, _, exit = runTestBinaryDir(t, dir, "-json", "-dash.bin")
	if exit != 2 {
		t.Errorf("bare dash filename exit %d, want 2 (flag parse must fail)", exit)
	}
}

// A batch run journals per-target digests; the -resume rerun
// skips both targets without re-scanning, and a tampered target
// rescans loudly instead of skipping.
func TestBatchCheckpointResumeCLI(t *testing.T) {
	dir := t.TempDir()
	a := writeGateFile(t, dir, "a.bin", strings.Repeat("q", 5000)+"bestblock"+strings.Repeat("q", 5000))
	b := writeGateFile(t, dir, "b.bin", strings.Repeat("q", 5000)+"defaultkey"+strings.Repeat("q", 5000))
	ckpt := filepath.Join(dir, "batch.cp")
	_, stderr, exit := runTestBinary(t, "-checkpoint", ckpt, a, b)
	if exit != 0 {
		t.Fatalf("batch run exit %d:\n%s", exit, stderr)
	}
	stdout, stderr, exit := runTestBinary(t, "-checkpoint", ckpt, "-resume", a, b)
	if exit != 0 {
		t.Fatalf("batch resume exit %d:\n%s", exit, stderr)
	}
	if strings.Count(stderr, "batch: skipping") != 2 {
		t.Errorf("resume must skip both targets, stderr:\n%s", stderr)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Errorf("skipped resume must print no hits:\n%s", stdout)
	}
	// Tamper target B (same size): the next resume rescans it
	// loudly while still skipping A.
	raw, err := os.ReadFile(b)
	if err != nil {
		t.Fatal(err)
	}
	raw[100] ^= 0xff
	if err := os.WriteFile(b, raw, 0644); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, exit = runTestBinary(t, "-checkpoint", ckpt, "-resume", a, b)
	if exit != 0 {
		t.Fatalf("tampered resume exit %d:\n%s", exit, stderr)
	}
	if strings.Count(stderr, "batch: skipping") != 1 || !strings.Contains(stderr, "skipping "+a) {
		t.Errorf("tampered resume must skip only A, stderr:\n%s", stderr)
	}
	if !strings.Contains(stderr, "fails digest verification") && !strings.Contains(stderr, "changed since completion") {
		t.Errorf("tampered target must warn loudly, stderr:\n%s", stderr)
	}
	if !strings.Contains(stdout, "defaultkey") {
		t.Errorf("rescan must re-report B hits:\n%s", stdout)
	}
}
