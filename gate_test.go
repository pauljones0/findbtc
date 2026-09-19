package main

import (
	"fmt"
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
