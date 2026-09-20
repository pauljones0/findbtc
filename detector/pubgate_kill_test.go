package detector

// Real-crash proof for the congested (publication-gate-tripped)
// path: a congested scan is SIGKILLed mid-run from a parent test,
// then resumed uncongested to full baseline coverage. Companion to
// TestPubGateCongestedVsBaseline, which proves the same retry
// equivalence without a crash; this test proves the journal and
// case log the killed run leaves behind are resume-honest.

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Child-process wiring: the parent re-executes the test binary with
// FINDBTC_PUBGATE_CHILD=1 and the run paths below; the helper runs
// the congested scan and stalls it mid-flight so the parent's
// SIGKILL lands deterministically.
const (
	pubgateChildEnv  = "FINDBTC_PUBGATE_CHILD"
	pubgateScanEnv   = "FINDBTC_PUBGATE_SCAN"
	pubgateCkptEnv   = "FINDBTC_PUBGATE_CKPT"
	pubgateCaseEnv   = "FINDBTC_PUBGATE_CASELOG"
	pubgateLogEnv    = "FINDBTC_PUBGATE_CHILDLOG"
	pubgateSignalEnv = "FINDBTC_PUBGATE_SIGNAL"
	pubgateDetsEnv   = "FINDBTC_PUBGATE_DETS"
)

// TestPubGateKillChild is the crash victim: a congested scan (cap 3
// over a 10-member zip) that signals its first detection and then
// stalls inside onDetection. The stall backpressures the whole
// pipeline (detectWallets calls onDetection synchronously), so the
// parent kills a provably mid-run scan. Inert in normal runs.
func TestPubGateKillChild(t *testing.T) {
	if os.Getenv(pubgateChildEnv) != "1" {
		return
	}
	path := os.Getenv(pubgateScanEnv)
	ckpt := os.Getenv(pubgateCkptEnv)
	caseLog := os.Getenv(pubgateCaseEnv)
	childLog := os.Getenv(pubgateLogEnv)
	signal := os.Getenv(pubgateSignalEnv)
	detsPath := os.Getenv(pubgateDetsEnv)
	for _, p := range []string{path, ckpt, caseLog, childLog, signal, detsPath} {
		if p == "" {
			t.Fatal("pubgate child: missing env wiring")
		}
	}
	logf, err := os.Create(childLog)
	if err != nil {
		t.Fatal(err)
	}
	defer logf.Close()
	maxOutstandingPubs = 3
	dets := 0
	nestedDets := 0
	err = ScanWithOptions(0, path, Options{
		Log: logf, CheckpointPath: ckpt, CaseLogPath: caseLog,
	}, func(d Detection) {
		dets++
		f, ferr := os.OpenFile(detsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if ferr != nil {
			return
		}
		// Target-qualified: raw root leaks of the needle are
		// Go-flate-version-dependent, so the parent counts
		// nested lines only.
		_, _ = f.WriteString(fmt.Sprintf("%s/%d/%s\n", d.Target, d.Offset, d.Needle))
		_ = f.Sync()
		_ = f.Close()
		// Stall at the first NESTED hit (not merely the first
		// hit): a raw root leak can arrive before the burst
		// publishes, which would wedge the pipeline ahead of
		// the trip. A nested hit proves a member was
		// admitted and read, so the root read — and its
		// gate-tripping publish loop — finished. Park here
		// so the parent's kill lands mid-drain; the budget
		// only bounds a leaked child when the parent
		// already failed, no timing depends on it.
		if d.Target != path {
			nestedDets++
			if nestedDets == 1 {
				if werr := os.WriteFile(signal, []byte("1"), 0644); werr != nil {
					return
				}
				time.Sleep(2 * time.Minute)
			}
		}
	}, func(ProgressInfo) {})
	// Reached only if the park expires without a kill (parent
	// bug): record the outcome for diagnosis.
	_, _ = logf.WriteString("child scan returned unexpectedly\n")
	if err != nil {
		t.Logf("child scan returned: dets=%d err=%v", dets, err)
	}
}

// A congested scan killed mid-run leaves a resume-honest journal
// (frozen at the last skip-free proven point, never completion)
// and no completion claim; an uncongested resume from that journal
// recovers the full 10/10 baseline.
func TestPubGateCrashResumeCongested(t *testing.T) {
	old := maxOutstandingPubs
	defer func() { maxOutstandingPubs = old }()

	// Fixture: the ten-needle padded zip idiom from
	// TestPubGateCongestedVsBaseline — the root spans the 1MB
	// mid-root drain point, the central directory trips the gate
	// at its end.
	var zb bytes.Buffer
	w := zip.NewWriter(&zb)
	for i := 0; i < 10; i++ {
		fw, err := w.Create("m.dat")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte("bestblock")); err != nil {
			t.Fatal(err)
		}
	}
	ph, err := w.CreateHeader(&zip.FileHeader{Name: "pad.dat", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ph.Write(make([]byte, 1300*1024)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	scanPath := filepath.Join(dir, "ten.zip")
	if err := os.WriteFile(scanPath, zb.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	ckpt := filepath.Join(dir, "cong.cp")
	caseLog := filepath.Join(dir, "cong.log")
	childLog := filepath.Join(dir, "child.log")
	signal := filepath.Join(dir, "signal")
	detsPath := filepath.Join(dir, "dets")

	cmd := exec.Command(os.Args[0], "-test.run", "^TestPubGateKillChild$")
	cmd.Env = append(os.Environ(),
		pubgateChildEnv+"=1",
		pubgateScanEnv+"="+scanPath,
		pubgateCkptEnv+"="+ckpt,
		pubgateCaseEnv+"="+caseLog,
		pubgateLogEnv+"="+childLog,
		pubgateSignalEnv+"="+signal,
		pubgateDetsEnv+"="+detsPath,
	)
	var childOut bytes.Buffer
	cmd.Stdout = &childOut
	cmd.Stderr = &childOut
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Safety: reap the child if a wait below fails first. Kill
	// after Wait is a no-op (already-finished handle), and the
	// second Wait's error is ignored.
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	// Liveness first: the stall signal proves the child delivered
	// a nested hit and parked mid-drain — past the root read, so
	// past the gate-tripping publish loop.
	pubgateWaitFile(t, signal, 60*time.Second)
	// Trip proof: the gate's warn-once line in the child log.
	pubgateWaitLog(t, childLog, "publication backlog", 15*time.Second)
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill missed a live child (scan exited early?): %v\nchild output:\n%s", err, childOut.String())
	}
	werr := cmd.Wait()
	if werr == nil {
		t.Fatalf("killed child exited cleanly, want SIGKILL death\nchild output:\n%s", childOut.String())
	}
	ee, ok := werr.(*exec.ExitError)
	if !ok {
		t.Fatalf("child wait error = %v, want ExitError\nchild output:\n%s", werr, childOut.String())
	}
	if runtime.GOOS != "windows" {
		ws, ok := ee.Sys().(syscall.WaitStatus)
		if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
			t.Fatalf("child death = %v, want SIGKILL\nchild output:\n%s", werr, childOut.String())
		}
	}

	// Mid-run proof: the drain-then-error report runs only at
	// scan end, so its absence proves the kill landed mid-run.
	rawLog, err := os.ReadFile(childLog)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawLog), "coverage is incomplete") {
		t.Fatal("child logged the end-of-run incompleteness report: kill landed post-completion, not mid-run")
	}
	// Partial at kill: exactly the first nested detection got out
	// before the stall parked the pipeline (raw root leaks ahead
	// of it are Go-flate-version-dependent and ignored).
	rawDets, err := os.ReadFile(detsPath)
	if err != nil {
		t.Fatalf("child detections unreadable: %v", err)
	}
	nestedAtKill := 0
	for _, line := range strings.Split(strings.TrimSpace(string(rawDets)), "\n") {
		// Root lines start with the scan path; nested
		// targets start with Zipfile/ZipEntry/Gzipfile.
		if !strings.HasPrefix(line, scanPath+"/") {
			nestedAtKill++
		}
	}
	if nestedAtKill != 1 {
		t.Fatalf("child nested detections at kill = %d, want exactly 1 (stalled pipeline)", nestedAtKill)
	}
	// Journal honesty: frozen at the skip-free 1MB proven point,
	// never completion.
	cp, err := ReadCheckpoint(ckpt)
	if err != nil {
		t.Fatalf("killed-run journal unreadable: %v", err)
	}
	fi, err := os.Stat(scanPath)
	if err != nil {
		t.Fatal(err)
	}
	if cp.Offset != 1<<20 {
		t.Fatalf("killed-run journal offset = %d, want frozen 1MB point %d", cp.Offset, 1<<20)
	}
	if cp.Offset >= fi.Size() {
		t.Fatalf("killed-run journal offset = %d, want below size %d (completion must never journal)", cp.Offset, fi.Size())
	}
	// Case-log honesty: the kill precedes the end-of-run append,
	// so no record exists — and never a completion claim.
	if raw, rerr := os.ReadFile(caseLog); rerr == nil && len(bytes.TrimSpace(raw)) != 0 {
		t.Fatalf("killed-run case log holds %d bytes, want none (kill precedes the end-of-run append)", len(raw))
	}
	// Resume equivalence: the frozen journal, uncongested,
	// recovers the full baseline.
	maxOutstandingPubs = 100
	var rlog bytes.Buffer
	rd := 0
	rerr := ScanWithOptions(cp.Offset, scanPath, Options{
		Log: &rlog, CheckpointPath: ckpt, CaseLogPath: filepath.Join(dir, "retry.log"),
	}, func(d Detection) {
		// Nested hits only: raw root leaks are
		// Go-flate-version-dependent.
		if d.Target != scanPath {
			rd++
		}
	}, func(ProgressInfo) {})
	if rerr != nil {
		t.Fatalf("resume scan: %v\n%s", rerr, rlog.String())
	}
	if rd != 10 {
		t.Fatalf("resume detections = %d, want baseline 10\n%s", rd, rlog.String())
	}
	logs := readCaseLog(t, filepath.Join(dir, "retry.log"))
	if len(logs) == 0 || logs[len(logs)-1].Status != "complete" {
		t.Fatalf("resume case-log last status = %+v, want complete", logs)
	}
}

// pubgateWaitFile polls for path's appearance: a readiness signal,
// not a blind sleep — the child writes it at a defined pipeline
// point (first detection delivered, stall engaged).
func pubgateWaitFile(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s", timeout, path)
		}
		time.Sleep(time.Millisecond)
	}
}

// pubgateWaitLog polls a child's log for substr: the gate's own
// warn-once line, proving the gate tripped before the kill.
func pubgateWaitLog(t *testing.T, path, substr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if raw, err := os.ReadFile(path); err == nil && strings.Contains(string(raw), substr) {
			return
		}
		if time.Now().After(deadline) {
			raw, _ := os.ReadFile(path)
			t.Fatalf("timed out after %s waiting for %q in %s (log: %q)", timeout, substr, path, string(raw))
		}
		time.Sleep(2 * time.Millisecond)
	}
}
