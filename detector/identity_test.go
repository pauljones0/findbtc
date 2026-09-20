package detector

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Content proofs must bind journaled progress to exact bytes: a
// same-size rewrite with restored mtime changes content no
// metadata pair can see. Only a re-read content proof authorizes
// offset or covered reuse — and the changed-middle controls below
// pin that no content sampling is involved: prefix and suffix are
// byte-identical, only the middle differs, yet reuse must refuse.
// Metadata (the cheap tier) may pass or fail; it authorizes
// nothing either way.
func TestProofSameSizeRestoredMtime(t *testing.T) {
	// O=12KiB rewinds to R=8KiB (overlap 2KiB, grid 4KiB), so
	// head/tail needles distinguish honor from rescan sharply.
	const O = 12 << 10
	mkcontent := func(middle byte) []byte {
		content := append([]byte{}, bytes.Repeat([]byte{'P'}, 1024)...)
		content = append(content, bytes.Repeat([]byte{middle}, 16<<10)...)
		return append(content, bytes.Repeat([]byte{'S'}, 1024)...)
	}
	// assertSwapShape verifies the control holds size, mtime,
	// prefix, and suffix constant while changing the middle.
	assertSwapShape := func(t *testing.T, before, after []byte, fixed time.Time, path string) {
		t.Helper()
		if len(before) != len(after) {
			t.Fatalf("control shapes differ in size: %d vs %d", len(before), len(after))
		}
		if !bytes.Equal(before[:1024], after[:1024]) || !bytes.Equal(before[len(before)-1024:], after[len(after)-1024:]) {
			t.Fatal("control shapes differ outside the middle")
		}
		if bytes.Equal(before[1024:len(before)-1024], after[1024:len(after)-1024]) {
			t.Fatal("control middles unexpectedly identical")
		}
		if fi, _ := os.Stat(path); !fi.ModTime().Equal(fixed) {
			t.Fatalf("control mtime not restored: %v", fi.ModTime())
		}
	}
	// fileClaim journals a frontier at 1024 over the CURRENT
	// bytes with a real proof, then returns the journal path.
	fileClaim := func(t *testing.T, dir, path string) string {
		t.Helper()
		ident, ok := FileIdentityOf(path)
		if !ok {
			t.Skip("no byte identity on this platform")
		}
		cpPath := filepath.Join(dir, "swap.cp")
		// A banked-looking member with provenance inside the
		// proven span: kept on honest resume, dropped on
		// tamper (its re-read is what the seed assertion
		// checks).
		covered := []string{"Zipfile #0 @ byte 0 in [" + path + "]|zipsize=2048|rootext=0-2048"}
		writeCheckpoint(nil, cpPath, path, O, covered, ident, mustProof(t, path, 0, O))
		return cpPath
	}
	// assertRescanned runs the resume the way main.go would and
	// requires a from-zero rescan: the head needle (inside the
	// journaled prefix) must re-report, and the log must warn.
	assertRescanned := func(t *testing.T, cpPath, path string) {
		t.Helper()
		cp, err := ReadCheckpoint(cpPath)
		if err != nil {
			t.Fatal(err)
		}
		start := ResumeRewindOffset(0, cp.Offset)
		var log bytes.Buffer
		var dets []Detection
		err = ScanWithOptions(start, path, Options{CheckpointPath: cpPath, Resume: true, Log: &log},
			func(d Detection) { dets = append(dets, d) }, func(ProgressInfo) {})
		if err != nil {
			t.Fatalf("resume errored: %v", err)
		}
		if !strings.Contains(log.String(), "rescan") {
			t.Fatalf("rescan must warn loudly, got:\n%s", log.String())
		}
		head := false
		for _, d := range dets {
			if d.Offset < start {
				head = true
			}
		}
		if !head {
			t.Fatal("swapped bytes skipped the journaled prefix instead of rescanning")
		}
	}

	t.Run("replace", func(t *testing.T) {
		// Replace-shape swap (rename over the path): new inode
		// everywhere. The cheap tier refuses on all platforms;
		// the proof would refuse too.
		dir := t.TempDir()
		path := filepath.Join(dir, "data.bin")
		fixed := time.Unix(1780000000, 0)
		raw := mkcontent('A')
		copy(raw[100:], "bestblock")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, fixed, fixed); err != nil {
			t.Fatal(err)
		}
		before, _ := os.ReadFile(path)
		cpPath := fileClaim(t, dir, path)
		swapped := mkcontent('B')
		copy(swapped[100:], "bestblock")
		tmp := filepath.Join(dir, "new.bin")
		if err := os.WriteFile(tmp, swapped, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(tmp, fixed, fixed); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, path); err != nil {
			t.Fatal(err)
		}
		after, _ := os.ReadFile(path)
		assertSwapShape(t, before, after, fixed, path)
		assertRescanned(t, cpPath, path)
	})

	t.Run("inplace", func(t *testing.T) {
		// In-place rewrite plus mtime restore: same inode,
		// forged mtime. Posix ctime refuses at the cheap tier;
		// where the tier passes (Windows-shape metadata, see
		// TestCheapTierPassAuthorizesNothing), the proof
		// refuses on content.
		dir := t.TempDir()
		path := filepath.Join(dir, "data.bin")
		fixed := time.Unix(1780000000, 0)
		raw := mkcontent('A')
		copy(raw[100:], "bestblock")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, fixed, fixed); err != nil {
			t.Fatal(err)
		}
		before, _ := os.ReadFile(path)
		cpPath := fileClaim(t, dir, path)
		over := mkcontent('B')
		copy(over[100:], "bestblock")
		if err := os.WriteFile(path, over, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, fixed, fixed); err != nil {
			t.Fatal(err)
		}
		after, _ := os.ReadFile(path)
		assertSwapShape(t, before, after, fixed, path)
		assertRescanned(t, cpPath, path)
	})

	t.Run("positive", func(t *testing.T) {
		// Unchanged bytes keep full reuse: the frontier is
		// honored (no head re-report) and the banked member
		// seeds. Banning reuse outright would revive the
		// liveness failure.
		dir := t.TempDir()
		path := filepath.Join(dir, "data.bin")
		raw := mkcontent('A')
		copy(raw[100:], "bestblock")
		copy(raw[O+100:], "bestblock")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		cpPath := fileClaim(t, dir, path)
		cp, err := ReadCheckpoint(cpPath)
		if err != nil {
			t.Fatal(err)
		}
		start := ResumeRewindOffset(0, cp.Offset)
		var log bytes.Buffer
		var dets []Detection
		err = ScanWithOptions(start, path, Options{CheckpointPath: cpPath, Resume: true, Log: &log},
			func(d Detection) { dets = append(dets, d) }, func(ProgressInfo) {})
		if err != nil {
			t.Fatalf("resume errored: %v", err)
		}
		if strings.Contains(log.String(), "rescan") {
			t.Fatalf("honest resume must not rescan, got:\n%s", log.String())
		}
		for _, d := range dets {
			if d.Offset < start {
				t.Fatalf("honest resume re-reported head offset %d (start %d)", d.Offset, start)
			}
		}
		tail := false
		for _, d := range dets {
			if d.Offset >= start {
				tail = true
			}
		}
		if !tail {
			t.Fatal("honest resume reported no tail hits")
		}
	})

	t.Run("legacy", func(t *testing.T) {
		// Journals without proofs (older binaries) rescan once
		// on upgrade instead of inheriting — including 030-era
		// journals that carry an identity but no proof.
		dir := t.TempDir()
		path := filepath.Join(dir, "data.bin")
		raw := mkcontent('A')
		copy(raw[100:], "bestblock")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		ident, ok := FileIdentityOf(path)
		if !ok {
			t.Skip("no byte identity on this platform")
		}
		cpPath := filepath.Join(dir, "legacy.cp")
		writeCheckpoint(nil, cpPath, path, O, []string{"banked-member"}, ident, nil)
		assertRescanned(t, cpPath, path)
	})
}

// fakeFileInfo is a minimal os.FileInfo for cheap-tier unit tests.
type fakeFileInfo struct {
	mode os.FileMode
	size int64
}

func (f fakeFileInfo) Name() string       { return "fake" }
func (f fakeFileInfo) Size() int64        { return f.size }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (fakeFileInfo) ModTime() time.Time   { return time.Time{} }
func (fakeFileInfo) IsDir() bool          { return false }
func (fakeFileInfo) Sys() any             { return nil }

// TestCheapTierPassAuthorizesNothing is the isolated
// platform-contract test: a metadata match — including a
// Windows-kind in-place rewrite with restored timestamps, which
// no Linux test can stage natively — returns pass=true, and that
// pass authorizes nothing by itself. Only a verified content
// proof adopts a claim; here the proof fails over the tampered
// bytes, so the combined decision refuses. Any caller treating a
// pass as authorization breaks this test's premise (audited: the
// only pass consumers feed verifySpan next).
func TestCheapTierPassAuthorizesNothing(t *testing.T) {
	reg := fakeFileInfo{mode: 0600, size: 4096}
	current := FileIdentity{Kind: "windows", Dev: 7, Ino: 11, Size: 4096, MtimeNS: 12300, CtimeNS: 45600}
	filed := current // identical metadata: forged mtime restore
	pass, _ := cheapTierPass(filed, reg, current, true, `C:\evidence\data.bin`)
	if !pass {
		t.Fatal("control failed: identical metadata must pass the cheap tier (else the tier is not cheap)")
	}
	// The tampered stream behind that metadata.
	tampered := &closableBytesReader{Reader: bytes.NewReader(bytes.Repeat([]byte{'B'}, 4096))}
	proofOfA := mustSpanProof(0, bytes.Repeat([]byte{'A'}, 4096))
	if _, err := verifySpan(tampered, proofOfA.Start, proofOfA.Len, proofOfA.SHA256); err == nil {
		t.Fatal("proof verified tampered bytes")
	}
	// Combined consumer decision: pass AND proof must both hold.
	// (adoptResume/verifyRangePlan encode this; the unit pins it.)
	if pass {
		tampered2 := &closableBytesReader{Reader: bytes.NewReader(bytes.Repeat([]byte{'B'}, 4096))}
		if _, err := verifySpan(tampered2, proofOfA.Start, proofOfA.Len, proofOfA.SHA256); err == nil {
			t.Fatal("pass plus failed proof must refuse")
		}
	}
	// And a non-regular target always proceeds to the proof, which
	// decides alone.
	dev := fakeFileInfo{mode: os.ModeDevice, size: 0}
	if pass, _ := cheapTierPass(FileIdentity{}, dev, FileIdentity{}, false, "/dev/zero"); !pass {
		t.Fatal("non-regular targets must proceed to proof verification")
	}
}

// TestRawProofRefusesUnprovenPrefix exercises the consumer path
// with a passing cheap tier end to end: /dev/zero is non-regular,
// so the tier always proceeds and the proof alone decides. A wrong
// proof restarts at 0 with a warning; the exact proof honors the
// frontier. The scan cancels after first progress (an infinite
// device must never run to completion).
func TestRawProofRefusesUnprovenPrefix(t *testing.T) {
	if _, err := os.Stat("/dev/zero"); err != nil {
		t.Skip("no /dev/zero on this platform")
	}
	const O = 1 << 20
	zeros := bytes.Repeat([]byte{0}, O)
	run := func(t *testing.T, proof *PrefixProof) (firstProgress int64, log string) {
		t.Helper()
		dir := t.TempDir()
		ckpt := filepath.Join(dir, "zero.cp")
		writeCheckpoint(nil, ckpt, "/dev/zero", O, nil, FileIdentity{}, proof)
		start := ResumeRewindOffset(0, O)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var buf bytes.Buffer
		seen := false
		err := ScanWithOptions(start, "/dev/zero",
			Options{CheckpointPath: ckpt, Resume: true, Log: &buf, Context: ctx},
			func(Detection) {},
			func(p ProgressInfo) {
				if !seen {
					seen = true
					firstProgress = p.ScannedBytes
					cancel()
				}
			})
		if err != nil && err != context.Canceled {
			t.Fatalf("scan errored: %v", err)
		}
		if !seen {
			t.Fatal("no progress reported before cancel")
		}
		return firstProgress, buf.String()
	}
	t.Run("wrong proof restarts", func(t *testing.T) {
		first, log := run(t, mustSpanProof(0, bytes.Repeat([]byte{1}, O)))
		if !strings.Contains(log, "proof failed") {
			t.Fatalf("wrong proof must warn loudly, got:\n%s", log)
		}
		if first >= ResumeRewindOffset(0, O) {
			t.Fatalf("wrong proof honored the frontier (first progress %d)", first)
		}
	})
	t.Run("exact proof honors", func(t *testing.T) {
		first, log := run(t, mustSpanProof(0, zeros))
		if strings.Contains(log, "proof failed") || strings.Contains(log, "rescanning") {
			t.Fatalf("exact proof must not refuse, got:\n%s", log)
		}
		if first < ResumeRewindOffset(0, O) {
			t.Fatalf("exact proof restarted (first progress %d)", first)
		}
	})
}
