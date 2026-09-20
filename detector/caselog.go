// Forensic case log: every scan can append one JSON record describing what
// was scanned, what was hashed, and what was found, so a later reviewer
// can re-derive the result from the source media.
package detector

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// CaseLog is one appended record in the -case-log JSONL file.
type CaseLog struct {
	Tool       string        `json:"tool"`
	Version    string        `json:"version"`
	Started    string        `json:"started"`
	Finished   string        `json:"finished"`
	Status     string        `json:"status"` // "complete", "error", or "canceled"
	Error      string        `json:"error,omitempty"`
	Source     CaseSource    `json:"source"`
	Hash       CaseHash      `json:"hash"`
	Skipped    []CaseSkipped `json:"skipped_ranges,omitempty"`
	Detections int64         `json:"detections"`
	EWF        *CaseEWF      `json:"ewf,omitempty"`
	// Flags reproduces the invocation that produced this record.
	Flags []string `json:"flags,omitempty"`
}

// CaseSource identifies the scanned root target.
type CaseSource struct {
	Path        string `json:"path"`
	Kind        string `json:"kind"` // raw, ewf, split, range, stdin, or unknown (see recordAttempt)
	Size        int64  `json:"size"`
	StartOffset int64  `json:"start_offset"`
	// Checkpoint names the progress journal when one was used; a
	// nonzero start_offset with a checkpoint means a resumed scan.
	Checkpoint string `json:"checkpoint,omitempty"`
}

// CaseHash is the streaming digest over the bytes actually read from the
// root target: [start_offset, size) minus skipped_ranges. A verifier
// reproduces it by hashing exactly those bytes.
type CaseHash struct {
	SHA256      string `json:"sha256"`
	MD5         string `json:"md5"`
	BytesHashed int64  `json:"bytes_hashed"`
}

// CaseSkipped records one unreadable range that the hash does not cover.
type CaseSkipped struct {
	Target string `json:"target"`
	Start  int64  `json:"start"`
	End    int64  `json:"end"`
	Error  string `json:"error"`
}

// CaseEWF cross-checks decoded EWF bytes against the set's stored MD5.
// MD5Match is nil when the comparison is meaningless (resumed scan or
// skipped bytes): the stored hash covers the whole decoded media.
type CaseEWF struct {
	StoredMD5 string `json:"stored_md5"`
	MD5Match  *bool  `json:"md5_match"`
}

// caseRecorder accumulates one CaseLog during a pipeline run. Block bytes
// arrive from the scan goroutine, detections from the detect goroutine.
type caseRecorder struct {
	mu         sync.Mutex
	sha        hash.Hash
	md5h       hash.Hash
	bytes      int64
	skipped    []CaseSkipped
	detections int64
	start      time.Time
	seed       scanTarget
	version    string
	flags      []string
	checkpoint string
}

func newCaseRecorder(seed scanTarget, version string, flags []string, checkpoint string) *caseRecorder {
	return &caseRecorder{
		sha:        sha256.New(),
		md5h:       md5.New(),
		start:      time.Now().UTC(),
		seed:       seed,
		version:    version,
		flags:      flags,
		checkpoint: checkpoint,
	}
}

// hash folds freshly read root-target bytes into the streaming digests.
func (r *caseRecorder) hash(p []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sha.Write(p)
	r.md5h.Write(p)
	r.bytes += int64(len(p))
}

func (r *caseRecorder) noteSkipped(target string, start, end int64, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	r.skipped = append(r.skipped, CaseSkipped{Target: target, Start: start, End: end, Error: msg})
}

func (r *caseRecorder) noteDetection() {
	atomic.AddInt64(&r.detections, 1)
}

func caseKind(seed scanTarget) string {
	switch seed.(type) {
	case *ewfScanTarget:
		return "ewf"
	case *splitScanTarget:
		return "split"
	case *boundedScanTarget:
		return "range"
	case *stdinScanTarget:
		return "stdin"
	default:
		return "raw"
	}
}

// finish builds the record. status is "complete", "error", or
// "canceled" (caller-cancelled scans record partial hashes honestly).
func (r *caseRecorder) finish(status string, runErr error) CaseLog {
	r.mu.Lock()
	defer r.mu.Unlock()
	size, _ := r.seed.Size()
	log := CaseLog{
		Tool:     "findbtc",
		Version:  r.version,
		Started:  r.start.Format(time.RFC3339),
		Finished: time.Now().UTC().Format(time.RFC3339),
		Status:   status,
		Source: CaseSource{
			Path:        r.seed.Describe(),
			Kind:        caseKind(r.seed),
			Size:        size,
			StartOffset: r.seed.StartOffset(),
			Checkpoint:  r.checkpoint,
		},
		Flags: r.flags,
		Hash: CaseHash{
			SHA256:      hex.EncodeToString(r.sha.Sum(nil)),
			MD5:         hex.EncodeToString(r.md5h.Sum(nil)),
			BytesHashed: r.bytes,
		},
		Skipped:    r.skipped,
		Detections: atomic.LoadInt64(&r.detections),
	}
	if runErr != nil {
		log.Error = runErr.Error()
	}
	if et, ok := r.seed.(*ewfScanTarget); ok && et.layout.hasMD5 {
		ce := &CaseEWF{StoredMD5: hex.EncodeToString(et.layout.md5[:])}
		if r.seed.StartOffset() == 0 && len(r.skipped) == 0 {
			match := log.Hash.MD5 == ce.StoredMD5
			ce.MD5Match = &match
		}
		log.EWF = ce
	}
	return log
}

// recordAttempt appends one zero-coverage attempt record and returns
// runErr: the scan never started (missing target, unreadable source,
// refused flag combination), so the record carries the attempted path
// and the outcome with no invented bytes or hashes. Every scan entry
// point calls this on its pre-pipeline failures, so a requested
// target always leaves exactly one record — the pipeline appends its
// own on started scans, never both. A broken case log cannot hide
// the outcome either: an append failure joins the returned error.
//
// RecordAttempt is the exported form for main's pre-scan setup
// (unallocated-range seeding), which fails before any entry point.
// Kind stays "unknown": a kind is attested only by a started scan,
// and attempts never start one.
func recordAttempt(opts Options, path string, runErr error) error {
	if opts.CaseLogPath == "" {
		return runErr
	}
	now := time.Now().UTC().Format(time.RFC3339)
	rec := CaseLog{
		Tool:     "findbtc",
		Version:  opts.ToolVersion,
		Started:  now,
		Finished: now,
		Status:   "error",
		Error:    runErr.Error(),
		Source: CaseSource{
			Path:       path,
			Kind:       "unknown",
			Checkpoint: opts.CheckpointPath,
		},
		Flags: opts.Flags,
	}
	if err := appendCaseLog(opts.CaseLogPath, rec); err != nil {
		return fmt.Errorf("%w (case log %s unwritable: %s)", runErr, opts.CaseLogPath, err.Error())
	}
	return runErr
}

// RecordAttempt appends one zero-coverage attempt record for a scan
// that never started; see recordAttempt.
func RecordAttempt(opts Options, path string, runErr error) error {
	return recordAttempt(opts, path, runErr)
}

// appendCaseLog appends one record to the JSONL case log.
func appendCaseLog(path string, log CaseLog) error {
	raw, err := json.Marshal(log)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	raw = append(raw, '\n')
	_, err = f.Write(raw)
	return err
}
