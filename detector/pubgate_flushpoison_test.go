package detector

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pubgateLocalOnlyMember builds one deflated local-header-only zip
// member: no central directory entry, no end-of-central-directory
// record at all — recovery-only coverage, published at root EOF
// via the candidate flush, after any mid-root frontier journaled.
func pubgateLocalOnlyMember(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var comp bytes.Buffer
	w, err := flate.NewWriter(&comp, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	data := comp.Bytes()
	hdr := make([]byte, 30)
	binary.LittleEndian.PutUint32(hdr[0:4], 0x04034b50)
	binary.LittleEndian.PutUint16(hdr[4:6], 20)
	binary.LittleEndian.PutUint16(hdr[6:8], 0)
	binary.LittleEndian.PutUint16(hdr[8:10], 8)
	binary.LittleEndian.PutUint32(hdr[14:18], crc32.ChecksumIEEE(content))
	binary.LittleEndian.PutUint32(hdr[18:22], uint32(len(data)))
	binary.LittleEndian.PutUint32(hdr[22:26], uint32(len(content)))
	binary.LittleEndian.PutUint16(hdr[26:28], uint16(len(name)))
	out := append(hdr, []byte(name)...)
	return append(out, data...)
}

// pubgateDetKey identifies a detection by stable emitted identity,
// the same key shape TestPubGateSameCapRetryCompletes uses for
// union accounting. Recovery-only members share a name but their
// Target embeds the member data offset, so identical members stay
// distinguishable.
func pubgateDetKey(d Detection) string {
	return fmt.Sprintf("%s/%d/%s", d.Target, d.Offset, d.Needle)
}

// An EOF-flush gate trip must never poison the frozen journal: the
// flush publishes pre-frontier bytes (directory-less members the
// root pass already walked past), so the frozen point must still
// re-cover them on retry — never certify complete with lost
// coverage. Fully synchronous, no timing assumption, no sleep.
//
// UNION ACCOUNTING (not per-run re-emission): the no-drop
// scheduler banks covered members by stable identity and retries
// DEFER banked members — never re-read, never re-emitted — so
// concatenated attempt outputs carry each hit exactly once.
// Asserting the retry re-emits all 10 would contradict that
// deferral, and the deferral is exactly what same-cap convergence
// (TestPubGateSameCapRetryCompletes) requires: without it, retries
// replay the admitted prefix forever instead of converging. The
// binding criterion is therefore the UNION across attempts —
// congested ∪ retry must equal the full baseline set, with an
// EMPTY intersection proving banked members deferred (no
// duplicates) and a complete retry proving nothing was lost.
func TestPubGateFlushSkipRetryRecovers(t *testing.T) {
	old := maxOutstandingPubs
	defer func() { maxOutstandingPubs = old }()

	var raw bytes.Buffer
	for i := 0; i < 10; i++ {
		raw.Write(pubgateLocalOnlyMember(t, "m.dat", []byte("padding bestblock padding")))
	}
	// Trailing zeros push the root past the 1MB mid-root drain
	// point, so the congested run journals a mid-root frontier
	// before the EOF flush publishes the recovery-only members.
	raw.Write(make([]byte, 1300*1024))
	dir := t.TempDir()
	path := filepath.Join(dir, "noecd.bin")
	if err := os.WriteFile(path, raw.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	// Nested hits only (Target != path): whether fixture bytes
	// leak a literal needle into a raw stream depends on the Go
	// flate encoder version, but the banking contract concerns
	// nested members only. Filtering keeps counts exact on every
	// toolchain.
	scan := func(cap int64, start int64, cpPath, clPath string) (keys map[string]bool, log string, err error) {
		maxOutstandingPubs = cap
		keys = map[string]bool{}
		var lb bytes.Buffer
		err = ScanWithOptions(start, path, Options{
			Log: &lb, CheckpointPath: cpPath, CaseLogPath: clPath,
		}, func(d Detection) {
			if d.Target != path {
				keys[pubgateDetKey(d)] = true
			}
		}, func(ProgressInfo) {})
		return keys, lb.String(), err
	}

	// Baseline: uncongested, recovery finds all 10.
	bkeys, blog, berr := scan(100, 0, filepath.Join(dir, "base.cp"), filepath.Join(dir, "base.log"))
	if berr != nil {
		t.Fatalf("baseline scan: %v\n%s", berr, blog)
	}
	if len(bkeys) != 10 {
		t.Fatalf("baseline unique detections = %d, want 10\n%s", len(bkeys), blog)
	}
	if logs := readCaseLog(t, filepath.Join(dir, "base.log")); len(logs) == 0 || logs[len(logs)-1].Status != "complete" {
		t.Fatalf("baseline case-log last status = %+v, want complete", logs)
	}

	// Congested: honest error, journal frozen below size. (No
	// nonzero-floor assertion: a no-drop journal may honestly
	// freeze at 0 when nothing past the start is proven.)
	cpPath, clPath := filepath.Join(dir, "cong.cp"), filepath.Join(dir, "cong.log")
	ckeys, clog, cerr := scan(3, 0, cpPath, clPath)
	if cerr == nil || !strings.Contains(cerr.Error(), "incomplete coverage") {
		t.Fatalf("congested scan error = %v, want incomplete-coverage error\n%s", cerr, clog)
	}
	cp, err := ReadCheckpoint(cpPath)
	if err != nil {
		t.Fatalf("congested journal unreadable: %v", err)
	}
	t.Logf("congested unique=%d frozen_offset=%d size=%d", len(ckeys), cp.Offset, fi.Size())
	if cp.Offset >= fi.Size() {
		t.Fatalf("congested journal offset = %d, want below size %d (completion must never journal)", cp.Offset, fi.Size())
	}
	if logs := readCaseLog(t, clPath); len(logs) == 0 || logs[len(logs)-1].Status == "complete" {
		t.Fatalf("congested case-log last status = %+v, want non-complete (error)", logs)
	}

	// Retry: the frozen journal, uncongested, must complete with
	// the omitted remainder — union(congested, retry) re-covers
	// the full baseline, never lost behind a completion claim,
	// never double-emitted.
	maxOutstandingPubs = 100
	var rlog bytes.Buffer
	rkeys := map[string]bool{}
	rerr := ScanWithOptions(cp.Offset, path, Options{
		Log: &rlog, CheckpointPath: cpPath, CaseLogPath: filepath.Join(dir, "retry.log"),
	}, func(d Detection) {
		if d.Target != path {
			rkeys[pubgateDetKey(d)] = true
		}
	}, func(ProgressInfo) {})
	rlogs := readCaseLog(t, filepath.Join(dir, "retry.log"))
	rstatus := ""
	if len(rlogs) != 0 {
		rstatus = rlogs[len(rlogs)-1].Status
	}
	t.Logf("retry unique=%d err=%v status=%s frozen_offset=%d", len(rkeys), rerr, rstatus, cp.Offset)
	if rerr != nil {
		t.Fatalf("retry scan: %v\n%s", rerr, rlog.String())
	}
	if rstatus != "complete" {
		t.Fatalf("retry case-log last status = %q, want complete", rstatus)
	}
	// Banked members must defer: any key in BOTH attempts is a
	// duplicate emission, contradicting no-drop deferral.
	for k := range rkeys {
		if ckeys[k] {
			t.Fatalf("retry re-emitted banked detection %q: intersection must be empty (banked members defer, never re-emit)", k)
		}
	}
	// Union must be exactly the baseline set: complete with
	// anything less (or anything extra) is a dishonest claim.
	union := map[string]bool{}
	for k := range ckeys {
		union[k] = true
	}
	for k := range rkeys {
		union[k] = true
	}
	t.Logf("congested=%d retry=%d union=%d baseline=%d", len(ckeys), len(rkeys), len(union), len(bkeys))
	if len(union) != len(bkeys) {
		t.Fatalf("union(congested, retry) = %d unique, want baseline %d: status %q certifies complete with lost coverage (frozen offset %d skipped pre-frontier bytes)",
			len(union), len(bkeys), rstatus, cp.Offset)
	}
	for k := range bkeys {
		if !union[k] {
			t.Fatalf("union missing baseline detection %q: status %q certifies complete with lost coverage", k, rstatus)
		}
	}
	for k := range union {
		if !bkeys[k] {
			t.Fatalf("union carries phantom detection %q outside the baseline set", k)
		}
	}
}
