package detector

// Embedding tests (Goal 28): Options.Log routes diagnostics with
// byte-identical default output; Options.Context cancels promptly
// with partial results kept, the checkpoint journal left at its last
// mark, and no goroutine leaks.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// captureStderr swaps os.Stderr for the duration of fn and returns
// what was written. The library writes diagnostics from pipeline
// goroutines that all join before Scan returns, so no sleep is needed.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = old }()
	fn()
	w.Close()
	os.Stderr = old
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func writeEmbedFixture(t *testing.T, size int) string {
	t.Helper()
	raw := make([]byte, size)
	for i := range raw {
		raw[i] = byte(i*31 + 7)
	}
	copy(raw[100:], "bestblock")
	path := filepath.Join(t.TempDir(), "embed.bin")
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOptionsLogByteIdentical(t *testing.T) {
	path := writeEmbedFixture(t, 1<<20)
	scan := func(opts Options) {
		if err := ScanWithOptions(0, path, opts, func(Detection) {}, func(ProgressInfo) {}); err != nil {
			t.Errorf("scan: %v", err)
		}
	}
	stderrOut := captureStderr(t, func() { scan(Options{}) })
	var buf bytes.Buffer
	scan(Options{Log: &buf})
	if stderrOut == "" || !strings.Contains(stderrOut, "[scan]") {
		t.Fatalf("default run wrote no diagnostics to stderr: %q", stderrOut)
	}
	if buf.String() != stderrOut {
		t.Errorf("Log output differs from stderr default:\nlog=%q\nstderr=%q", buf.String(), stderrOut)
	}
}

func TestOptionsLogDiscardIsQuiet(t *testing.T) {
	path := writeEmbedFixture(t, 1<<20)
	stderrOut := captureStderr(t, func() {
		opts := Options{Log: io.Discard}
		if err := ScanWithOptions(0, path, opts, func(Detection) {}, func(ProgressInfo) {}); err != nil {
			t.Errorf("scan: %v", err)
		}
	})
	if stderrOut != "" {
		t.Errorf("discarded Log still wrote to stderr: %q", stderrOut)
	}
}

func TestOptionsContextCancelsPromptly(t *testing.T) {
	path := writeEmbedFixture(t, 64<<20)
	ctx, cancel := context.WithCancel(context.Background())
	var dets int
	done := make(chan error, 1)
	go func() {
		done <- ScanWithOptions(0, path, Options{Context: ctx, Log: io.Discard},
			func(Detection) { dets++ }, func(ProgressInfo) {})
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	start := time.Now()
	select {
	case err := <-done:
		if wait := time.Since(start); wait > 10*time.Second {
			t.Errorf("cancel took %v, want prompt", wait)
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("canceled scan did not return")
	}
}

func TestOptionsContextKeepsPartialResults(t *testing.T) {
	path := writeEmbedFixture(t, 64<<20)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var dets []Detection
	// Cancel after the first detection: everything delivered before
	// the cancel must survive.
	err := ScanWithOptions(0, path, Options{Context: ctx, Log: io.Discard}, func(d Detection) {
		dets = append(dets, d)
		if len(dets) == 1 {
			cancel()
		}
	}, func(ProgressInfo) {})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if len(dets) == 0 {
		t.Error("no partial detections survived cancellation")
	}
}

func TestOptionsContextCheckpointLeftBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.bin")
	raw := make([]byte, 8<<20)
	for i := range raw {
		raw[i] = byte(i*31 + 7)
	}
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	ckpt := filepath.Join(dir, "resume.journal")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	err := ScanWithOptions(0, path, Options{Context: ctx, CheckpointPath: ckpt, Log: io.Discard},
		func(Detection) {}, func(ProgressInfo) {
			calls++
			// Past the first 1MB journal mark (256 blocks), well
			// before the 8MB end.
			if calls == 300 {
				cancel()
			}
		})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	cp, rerr := ReadCheckpoint(ckpt)
	if rerr != nil {
		t.Fatalf("no journal left behind: %v", rerr)
	}
	// Last completed 1MB mark, strictly before the end: the cancel
	// wrote nothing further.
	if cp.Offset <= 0 || cp.Offset >= int64(len(raw)) {
		t.Errorf("journal offset %d, want a partial mark", cp.Offset)
	}
}

func TestOptionsContextCaseLogCanceled(t *testing.T) {
	path := writeEmbedFixture(t, 32<<20)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	caseLog := filepath.Join(t.TempDir(), "case.jsonl")
	err := ScanWithOptions(0, path, Options{Context: ctx, CaseLogPath: caseLog, ToolVersion: "test", Log: io.Discard},
		func(Detection) {}, func(ProgressInfo) { cancel() })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	raw, rerr := os.ReadFile(caseLog)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if !strings.Contains(string(raw), `"status": "canceled"`) && !strings.Contains(string(raw), `"status":"canceled"`) {
		t.Errorf("case log lacks canceled status:\n%s", raw)
	}
}

func goroutinesSettle(want int, timeout time.Duration) int {
	deadline := time.Now().Add(timeout)
	got := runtime.NumGoroutine()
	for time.Now().Before(deadline) {
		if got <= want {
			return got
		}
		time.Sleep(20 * time.Millisecond)
		got = runtime.NumGoroutine()
	}
	return got
}

func TestOptionsContextNoLeak(t *testing.T) {
	path := writeEmbedFixture(t, 32<<20)
	// Warm up so one-time runtime goroutines are already live.
	_ = ScanWithOptions(0, path, Options{Log: io.Discard}, func(Detection) {}, func(ProgressInfo) {})
	base := goroutinesSettle(runtime.NumGoroutine(), 2*time.Second)
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // cancel-before-start: stages must still all exit
		if err := ScanWithOptions(0, path, Options{Context: ctx, Log: io.Discard},
			func(Detection) {}, func(ProgressInfo) {}); !errors.Is(err, context.Canceled) {
			t.Fatalf("iter %d: err = %v, want context.Canceled", i, err)
		}
	}
	if got := goroutinesSettle(base, 5*time.Second); got > base {
		t.Errorf("goroutines grew %d -> %d after canceled scans", base, got)
	}
}

func TestWalkContextCancels(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 20; i++ {
		raw := bytes.Repeat([]byte{byte(i + 1)}, 1<<20)
		if err := os.WriteFile(filepath.Join(dir, string(rune('a'+i))+".bin"), raw, 0644); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stats, err := Walk(dir, WalkOptions{Scan: Options{Context: ctx, Log: io.Discard}},
		func(Detection) {}, func(ProgressInfo) { cancel() })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if stats.Files == 0 || stats.Files >= 20 {
		t.Errorf("files swept = %d, want a partial sweep", stats.Files)
	}
}
