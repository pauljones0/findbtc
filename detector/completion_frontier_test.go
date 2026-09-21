package detector

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Notify when the completion path evaluates its cancellation channel. The
// frontier remains unavailable until the test releases it: no timing retries
// or production scheduling hooks are needed to exercise the final wait.
type completionWaitContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *completionWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func waitForCompletionSelect(t *testing.T, ctx *completionWaitContext) {
	t.Helper()
	select {
	case <-ctx.waiting:
	case <-time.After(5 * time.Second):
		t.Fatal("completion did not reach the frontier wait")
	}
}

func completionResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("completion did not return")
		return nil
	}
}

func TestCompletionCancelPreservesJournal(t *testing.T) {
	for _, mode := range []string{"fresh", "single", "range", "batch"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "source.bin")
			data := []byte("bestblock")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			opts := Options{CheckpointPath: filepath.Join(dir, "journal.json"), CaseLogPath: filepath.Join(dir, "case.jsonl"), Log: io.Discard}
			cp := Checkpoint{Path: path, Offset: 2, Ident: testIdent(path), Proof: mustProof(t, path, 0, 2)}
			switch mode {
			case "range":
				cp.Ranges = []FSExtent{{Start: 0, Len: int64(len(data))}}
			case "batch":
				opts.BatchJournal = NewBatchManifest([]string{path, filepath.Join(dir, "next.bin")}, BatchRun{})
				opts.BatchJournal.Targets[0].State = BatchActive
				opts.BatchJournal.Targets[0].Offset = cp.Offset
				opts.BatchJournal.Targets[0].Proof = cp.Proof
				cp = ManifestSnapshot(opts.BatchJournal)
			}
			var before []byte
			if mode != "fresh" {
				writeCheckpointData(io.Discard, opts.CheckpointPath, cp)
				var err error
				before, err = os.ReadFile(opts.CheckpointPath)
				if err != nil {
					t.Fatal(err)
				}
			}
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := &completionWaitContext{Context: parent, waiting: make(chan struct{})}
			jc := &journalCtl{final: make(chan *pendingFrontier, 1)}
			rec := newCaseRecorder(&fileScanTarget{path: path}, "test", nil, opts.CheckpointPath)
			rec.hash(data)
			rec.noteDetection()
			done := make(chan error, 1)
			go func() { done <- finishCompletedScan(ctx, opts, jc, rec) }()
			waitForCompletionSelect(t, ctx)
			if _, err := os.Stat(opts.CaseLogPath); !os.IsNotExist(err) {
				t.Errorf("outcome recorded before the final wait resolved: %v", err)
			}
			cancel()
			if err := completionResult(t, done); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled final wait returned %v", err)
			}
			if mode == "fresh" {
				if _, err := os.Stat(opts.CheckpointPath); !os.IsNotExist(err) {
					t.Errorf("canceled scan created a completion journal: %v", err)
				}
			} else if after, err := os.ReadFile(opts.CheckpointPath); err != nil || !bytes.Equal(before, after) {
				t.Errorf("cancellation changed the previous proven journal: %v", err)
			}
			logs := readCaseLog(t, opts.CaseLogPath)
			if len(logs) != 1 || logs[0].Status != "canceled" || logs[0].Error != context.Canceled.Error() || logs[0].Detections != 1 || logs[0].Hash.BytesHashed != int64(len(data)) {
				t.Errorf("cancellation lost delivered facts or claimed completion: %+v", logs)
			}
			// The buffer-one producer may still finish after cancellation;
			// it cannot block waiting for the departed receiver.
			select {
			case jc.final <- &pendingFrontier{desc: path, offset: int64(len(data))}:
			default:
				t.Fatal("completion producer would be stranded")
			}
		})
	}
}

func TestCompletionWaitFilesReceipt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "source.bin")
	data := []byte("bestblock")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	opts := Options{CheckpointPath: filepath.Join(dir, "journal.json"), CaseLogPath: filepath.Join(dir, "case.jsonl"), Log: io.Discard}
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &completionWaitContext{Context: parent, waiting: make(chan struct{})}
	jc := &journalCtl{final: make(chan *pendingFrontier, 1)}
	rec := newCaseRecorder(&fileScanTarget{path: path}, "test", nil, opts.CheckpointPath)
	rec.hash(data)
	done := make(chan error, 1)
	go func() { done <- finishCompletedScan(ctx, opts, jc, rec) }()
	waitForCompletionSelect(t, ctx)
	if _, err := os.Stat(opts.CaseLogPath); !os.IsNotExist(err) {
		t.Errorf("completion recorded before its frontier arrived: %v", err)
	}
	jc.final <- &pendingFrontier{desc: path, offset: int64(len(data)), ident: testIdent(path), proof: mustProof(t, path, 0, int64(len(data))), covered: []string{"subsumed"}}
	if err := completionResult(t, done); err != nil {
		t.Fatal(err)
	}
	cp, err := ReadCheckpoint(opts.CheckpointPath)
	if err != nil || cp.Offset != int64(len(data)) || cp.Proof == nil || cp.Proof.Len != int64(len(data)) || len(cp.Covered) != 0 {
		t.Fatalf("completed receipt: %+v, %v", cp, err)
	}
	if logs := readCaseLog(t, opts.CaseLogPath); len(logs) != 1 || logs[0].Status != "complete" {
		t.Fatalf("completion record: %+v", logs)
	}

	// Tolerated unopened roots send nil, which must release the receiver.
	jc.final <- nil
	if err := finishCompletedScan(context.Background(), Options{Log: io.Discard}, jc, nil); err != nil {
		t.Fatal(err)
	}
}
