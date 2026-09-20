package detector

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const (
	patchC1 = "1111111111111111111111111111111111111111"
	patchC2 = "2222222222222222222222222222222222222222"
)

// patchFixture is a two-commit series: an added secret, a commit
// message mentioning a needle, and a removed + re-added secret.
// Needles differ per hit: each needle reports once per block.
const patchFixture = `commit 1111111111111111111111111111111111111111
Author: A <a@x>

    first

diff --git a/one.txt b/one.txt
--- /dev/null
+++ b/one.txt
@@ -0,0 +1,3 @@
+aaa
+wallet.dat
+bbb
commit 2222222222222222222222222222222222222222
Author: B <b@x>

    second mentions hdseed in message

diff --git a/two.txt b/two.txt
--- a/two.txt
+++ b/two.txt
@@ -1,2 +1,3 @@
 ctx
-keymeta
+defaultkey
+new
`

// byOffset sorts detections into stream order: the pipeline
// delivers needle-major within a block, while patch positions read
// top-to-bottom.
func byOffset(dets []Detection) []Detection {
	sort.SliceStable(dets, func(a, b int) bool { return dets[a].Offset < dets[b].Offset })
	return dets
}

func scanPatchBytes(t *testing.T, data []byte, opts Options) []Detection {
	t.Helper()
	if opts.Log == nil {
		opts.Log = io.Discard
	}
	opts.Patch = true
	file := filepath.Join(t.TempDir(), "series.patch")
	if err := os.WriteFile(file, data, 0644); err != nil {
		t.Fatal(err)
	}
	dets, collect := collectDetections()
	if err := ScanWithOptions(0, file, opts, collect, nil); err != nil {
		t.Fatalf("patch scan: %v", err)
	}
	return *dets
}

// Each hit lands on its commit + path + new-file line: added hits
// carry lines, removed/message hits carry commit+path with line 0,
// and every committed hit carries a history fingerprint.
func TestPatchAttribution(t *testing.T) {
	dets := byOffset(scanPatchBytes(t, []byte(patchFixture), Options{}))
	want := []struct {
		commit, path, needle string
		line                 int
	}{
		{patchC1, "one.txt", "wallet.dat", 2},
		{patchC2, "", "hdseed", 0},
		{patchC2, "two.txt", "keymeta", 0},
		{patchC2, "two.txt", "defaultkey", 2},
	}
	if len(dets) != len(want) {
		t.Fatalf("got %d detections, want %d: %#v", len(dets), len(want), dets)
	}
	for i := range want {
		d := dets[i]
		if d.Commit != want[i].commit || d.Path != want[i].path || d.Line != want[i].line {
			t.Errorf("hit %d: got (%s,%s,%d), want (%s,%s,%d)",
				i, d.Commit, d.Path, d.Line, want[i].commit, want[i].path, want[i].line)
		}
		if d.Needle != want[i].needle {
			t.Errorf("hit %d: needle %q, want %q", i, d.Needle, want[i].needle)
		}
		fp := "v1/history/" + want[i].commit + "/" + want[i].path + "/" + want[i].needle + "/"
		if !strings.HasPrefix(d.Fingerprint, fp) || len(d.Fingerprint) != len(fp)+16 {
			t.Errorf("hit %d: fingerprint %q lacks shape %q+16hex", i, d.Fingerprint, fp)
		}
	}
}

// History fingerprints survive re-ranging: the same commit bytes
// scanned alone key identically, so baselines match across `git log`
// ranges and repeat sweeps.
func TestPatchFingerprintStableAcrossRanges(t *testing.T) {
	full := scanPatchBytes(t, []byte(patchFixture), Options{})
	sub := patchFixture[strings.Index(patchFixture, "commit "+patchC2):]
	ranged := scanPatchBytes(t, []byte(sub), Options{})
	fullFP := map[string]bool{}
	for _, d := range full {
		fullFP[d.Fingerprint] = true
	}
	if len(ranged) != 3 {
		t.Fatalf("ranged scan found %d hits, want 3", len(ranged))
	}
	for _, d := range ranged {
		if !fullFP[d.Fingerprint] {
			t.Errorf("ranged fingerprint %q matches no full-history key", d.Fingerprint)
		}
	}
}

// The fingerprint hashes the raw patch line (marker prefix
// included): independently, sha256("+aws_access_key_id=...")[:8] is
// 0416fbeaa334cf7a (see sha256sum probe in review notes).
func TestPatchFingerprintGolden(t *testing.T) {
	patch := "commit " + patchC1 + "\n\ndiff --git a/d.env b/d.env\n--- /dev/null\n+++ b/d.env\n@@ -0,0 +1 @@\n+aws_access_key_id=AKIAIOSFODNN7EXAMPLE\n"
	dets := scanPatchBytes(t, []byte(patch), Options{Profile: "secrets"})
	if len(dets) != 1 {
		t.Fatalf("got %d detections, want 1: %#v", len(dets), dets)
	}
	want := "v1/history/" + patchC1 + "/d.env/aws-access-key/0416fbeaa334cf7a"
	if dets[0].Fingerprint != want {
		t.Errorf("fingerprint %q, want %q", dets[0].Fingerprint, want)
	}
}

// Deleted files attribute to the removed path (line 0: the bytes
// hold no new-file line); renames attribute to the new path.
func TestPatchDeletedAndRenamed(t *testing.T) {
	patch := `commit 3333333333333333333333333333333333333333

diff --git a/gone.txt b/gone.txt
deleted file mode 100644
--- a/gone.txt
+++ /dev/null
@@ -1 +0,0 @@
-wallet.dat
diff --git a/old.txt b/new.txt
similarity index 90%
rename from old.txt
rename to new.txt
--- a/old.txt
+++ b/new.txt
@@ -1 +1 @@
-hdseed
+keymeta
`
	dets := byOffset(scanPatchBytes(t, []byte(patch), Options{}))
	want := []Detection{
		{Commit: "3333333333333333333333333333333333333333", Path: "gone.txt", Line: 0},
		{Commit: "3333333333333333333333333333333333333333", Path: "new.txt", Line: 0},
		{Commit: "3333333333333333333333333333333333333333", Path: "new.txt", Line: 1},
	}
	if len(dets) != len(want) {
		t.Fatalf("got %d detections, want %d: %#v", len(dets), len(want), dets)
	}
	for i := range want {
		d := dets[i]
		if d.Commit != want[i].Commit || d.Path != want[i].Path || d.Line != want[i].Line {
			t.Errorf("hit %d: got (%s,%s,%d), want (%s,%s,%d)",
				i, d.Commit, d.Path, d.Line, want[i].Commit, want[i].Path, want[i].Line)
		}
	}
}

// Hunk line tracking: later hunks restart from their own new
// offset, context lines advance and attribute, "-" lines and
// no-newline markers hold no line, and binary-diff notices break
// nothing.
func TestPatchHunkLines(t *testing.T) {
	patch := `commit 4444444444444444444444444444444444444444

diff --git a/f.txt b/f.txt
--- a/f.txt
+++ b/f.txt
@@ -1,2 +1,2 @@
 a
-wallet.dat
+b
@@ -10,2 +20,2 @@
 c
+hdseed
diff --git a/nl.txt b/nl.txt
--- a/nl.txt
+++ b/nl.txt
@@ -1 +1 @@
-old
\ No newline at end of file
+keymeta
\ No newline at end of file
diff --git a/a.bin b/a.bin
Binary files a/a.bin and b/a.bin differ
diff --git a/b.txt b/b.txt
--- a/b.txt
+++ b/b.txt
@@ -5 +5 @@
+defaultkey
`
	dets := byOffset(scanPatchBytes(t, []byte(patch), Options{}))
	want := []struct {
		path string
		line int
	}{
		{"f.txt", 0},
		{"f.txt", 21},
		{"nl.txt", 1},
		{"b.txt", 5},
	}
	if len(dets) != len(want) {
		t.Fatalf("got %d detections, want %d: %#v", len(dets), len(want), dets)
	}
	for i := range want {
		d := dets[i]
		if d.Path != want[i].path || d.Line != want[i].line {
			t.Errorf("hit %d: got (%s,%d), want (%s,%d)",
				i, d.Path, d.Line, want[i].path, want[i].line)
		}
		if d.Commit != "4444444444444444444444444444444444444444" {
			t.Errorf("hit %d: commit %q", i, d.Commit)
		}
	}
}

// Quoted diffs inside (indented) commit messages must not hijack
// attribution: only column-0 headers count.
func TestPatchQuotedDiffInMessage(t *testing.T) {
	patch := `commit 5555555555555555555555555555555555555555

    See this diff:
        diff --git a/fake b/fake
        --- a/fake
        +++ b/fake
        @@ -1 +1 @@
        +wallet.dat
    (quoted above)

diff --git a/real.txt b/real.txt
--- /dev/null
+++ b/real.txt
@@ -0,0 +1 @@
+hdseed
`
	dets := byOffset(scanPatchBytes(t, []byte(patch), Options{}))
	if len(dets) != 2 {
		t.Fatalf("got %d detections, want 2: %#v", len(dets), dets)
	}
	if dets[0].Path != "" || dets[0].Line != 0 {
		t.Errorf("quoted hit attributed to (%q,%d), want (\"\",0)", dets[0].Path, dets[0].Line)
	}
	if dets[0].Commit != "5555555555555555555555555555555555555555" {
		t.Errorf("quoted hit commit %q", dets[0].Commit)
	}
	if dets[1].Path != "real.txt" || dets[1].Line != 1 {
		t.Errorf("real hit got (%q,%d), want (real.txt,1)", dets[1].Path, dets[1].Line)
	}
}

// Content that looks like file headers must not hijack the path:
// an added "++ ..." line and a removed "-- ..." line stay content,
// and the hunk's line counting continues past them.
func TestPatchHeaderLikeContent(t *testing.T) {
	patch := `commit 7777777777777777777777777777777777777777

diff --git a/plus.txt b/plus.txt
--- /dev/null
+++ b/plus.txt
@@ -0,0 +1,3 @@
+++ wallet.dat docs
+middle hdseed line
+tail
diff --git a/minus.txt b/minus.txt
--- a/minus.txt
+++ b/minus.txt
@@ -1,2 +1,2 @@
--- keymeta note
+defaultkey here
`
	dets := byOffset(scanPatchBytes(t, []byte(patch), Options{}))
	want := []struct {
		path, needle string
		line         int
	}{
		{"plus.txt", "wallet.dat", 1},
		{"plus.txt", "hdseed", 2},
		{"minus.txt", "keymeta", 0},
		{"minus.txt", "defaultkey", 1},
	}
	if len(dets) != len(want) {
		t.Fatalf("got %d detections, want %d: %#v", len(dets), len(want), dets)
	}
	for i := range want {
		d := dets[i]
		if d.Path != want[i].path || d.Line != want[i].line || d.Needle != want[i].needle {
			t.Errorf("hit %d: got (%s,%s,%d), want (%s,%s,%d)",
				i, d.Path, d.Needle, d.Line, want[i].path, want[i].needle, want[i].line)
		}
	}
}

// Combined (merge) diffs name the path directly after the mode
// word; the mode word itself is not part of the path.
func TestPatchCombinedDiff(t *testing.T) {
	patch := `commit 9999999999999999999999999999999999999999

diff --cc merge.txt
--- a/merge.txt
+++ b/merge.txt
@@@ -1,2 -1,2 +1,3 @@@
  ctx
++hdseed added
`
	dets := scanPatchBytes(t, []byte(patch), Options{})
	if len(dets) != 1 {
		t.Fatalf("got %d detections, want 1: %#v", len(dets), dets)
	}
	d := dets[0]
	if d.Path != "merge.txt" || d.Line != 2 {
		t.Errorf("combined hit got (%q,%d), want (merge.txt,2)", d.Path, d.Line)
	}
}

// Quoted paths (spaces, non-ASCII) unquote to the repo path.
func TestPatchQuotedPath(t *testing.T) {
	patch := "commit aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n" +
		"\n" +
		"diff --git \"a/sp ace.txt\" \"b/sp ace.txt\"\n" +
		"--- \"a/sp ace.txt\"\n" +
		"+++ \"b/sp ace.txt\"\n" +
		"@@ -0,0 +1 @@\n" +
		"+wallet.dat\n"
	dets := scanPatchBytes(t, []byte(patch), Options{})
	if len(dets) != 1 {
		t.Fatalf("got %d detections, want 1: %#v", len(dets), dets)
	}
	if dets[0].Path != "sp ace.txt" {
		t.Errorf("quoted path got %q, want %q", dets[0].Path, "sp ace.txt")
	}
}

// Context lines that look like headers stay content: an "@@..."
// context line must not restart hunk numbering.
func TestPatchHeaderLikeContext(t *testing.T) {
	patch := `commit bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

diff --git a/ctx.txt b/ctx.txt
--- a/ctx.txt
+++ b/ctx.txt
@@ -1,3 +1,3 @@
 @@ -9 +9 @@ quoted
 wallet.dat here
+hdseed tail
`
	dets := byOffset(scanPatchBytes(t, []byte(patch), Options{}))
	if len(dets) != 2 {
		t.Fatalf("got %d detections, want 2: %#v", len(dets), dets)
	}
	if dets[0].Path != "ctx.txt" || dets[0].Line != 2 || dets[0].Needle != "wallet.dat" {
		t.Errorf("context hit got (%s,%s,%d)", dets[0].Path, dets[0].Needle, dets[0].Line)
	}
	if dets[1].Path != "ctx.txt" || dets[1].Line != 3 || dets[1].Needle != "hdseed" {
		t.Errorf("added hit got (%s,%s,%d)", dets[1].Path, dets[1].Needle, dets[1].Line)
	}
}

// Truncated and malformed headers manufacture no attribution: a
// cut-off hunk header ends cleanly and later bytes keep their
// commit+path with line 0, never a confident wrong line.
func TestPatchTruncated(t *testing.T) {
	patch := "commit cccccccccccccccccccccccccccccccccccccccc\n" +
		"\n" +
		"diff --git a/t.txt b/t.txt\n" +
		"--- a/t.txt\n" +
		"+++ b/t.txt\n" +
		"@@ -1 +1"
	dets := scanPatchBytes(t, []byte(patch), Options{})
	if len(dets) != 0 {
		t.Fatalf("truncated header-only patch must hold no hits, got %#v", dets)
	}
	patch2 := patch + "\n+wallet.dat\n"
	dets2 := scanPatchBytes(t, []byte(patch2), Options{})
	if len(dets2) != 1 {
		t.Fatalf("got %d detections, want 1: %#v", len(dets2), dets2)
	}
	d := dets2[0]
	if d.Commit != "cccccccccccccccccccccccccccccccccccccccc" || d.Path != "t.txt" || d.Line != 0 {
		t.Errorf("truncated-hunk hit got (%s,%s,%d), want line 0", d.Commit, d.Path, d.Line)
	}
}

// CRLF patch bytes attribute with clean paths (no stray \r).
func TestPatchCRLF(t *testing.T) {
	patch := "commit 8888888888888888888888888888888888888888\r\n" +
		"\r\n" +
		"diff --git a/win.txt b/win.txt\r\n" +
		"--- a/win.txt\r\n" +
		"+++ b/win.txt\r\n" +
		"@@ -1 +1 @@\r\n" +
		"+wallet.dat\r\n"
	dets := scanPatchBytes(t, []byte(patch), Options{})
	if len(dets) != 1 {
		t.Fatalf("got %d detections, want 1: %#v", len(dets), dets)
	}
	d := dets[0]
	if d.Path != "win.txt" || d.Line != 1 || d.Commit != "8888888888888888888888888888888888888888" {
		t.Errorf("crlf hit got (%s,%s,%d)", d.Commit, d.Path, d.Line)
	}
}

// mbox format-patch series carry the sha on From lines, in
// sha1 (40) or sha256 (64) hex alike.
func TestPatchMboxFrom(t *testing.T) {
	for _, sha := range []string{
		"6666666666666666666666666666666666666666",
		"7777777777777777777777777777777777777777777777777777777777777777",
	} {
		patch := "From " + sha + " Mon Sep 17 00:00:00 2001\nSubject: leak\n\ndiff --git a/m.txt b/m.txt\n--- /dev/null\n+++ b/m.txt\n@@ -0,0 +1 @@\n+wallet.dat\n"
		dets := scanPatchBytes(t, []byte(patch), Options{})
		if len(dets) != 1 {
			t.Fatalf("sha %s: got %d detections, want 1: %#v", sha, len(dets), dets)
		}
		d := dets[0]
		if d.Commit != sha || d.Path != "m.txt" || d.Line != 1 {
			t.Errorf("sha %s: mbox hit got (%s,%s,%d)", sha, d.Commit, d.Path, d.Line)
		}
	}
}

// No commit boundaries means baselines are inert: warn loudly
// instead of reporting everything forever without explanation.
func TestPatchNoCommitsWarns(t *testing.T) {
	var log bytes.Buffer
	dets := scanPatchBytes(t, []byte("junk\nwallet.dat\njunk\n"), Options{Log: &log})
	if len(dets) != 1 || dets[0].Fingerprint != "" {
		t.Fatalf("bare input must report once unfingerprinted, got %#v", dets)
	}
	if !strings.Contains(log.String(), "no patch commits found") {
		t.Fatalf("missing zero-commit warning, log:\n%s", log.String())
	}
	var clean bytes.Buffer
	scanPatchBytes(t, []byte(patchFixture), Options{Log: &clean})
	if strings.Contains(clean.String(), "no patch commits found") {
		t.Fatalf("real patch must not warn, log:\n%s", clean.String())
	}
}

// Patch findings buffer for attribution, so a checkpoint would
// journal completion before any finding delivers: a crash in
// between resumes past lost hits. The combination refuses.
func TestPatchCheckpointRefused(t *testing.T) {
	file := filepath.Join(t.TempDir(), "s.patch")
	if err := os.WriteFile(file, []byte(patchFixture), 0644); err != nil {
		t.Fatal(err)
	}
	for _, opts := range []Options{
		{Patch: true, CheckpointPath: filepath.Join(t.TempDir(), "c.json"), Log: io.Discard},
		{Patch: true, Resume: true, Log: io.Discard},
	} {
		if err := ScanWithOptions(0, file, opts, nil, nil); err == nil ||
			!strings.Contains(err.Error(), "buffered findings") {
			t.Errorf("opts %+v must refuse naming buffered findings, got: %v", opts, err)
		}
	}
}

// Directory sweeps scan files, not patch streams: Walk refuses
// Patch so walked hits never carry patch Commit/Path/Line.
func TestPatchWalkRefused(t *testing.T) {
	_, err := Walk(t.TempDir(), WalkOptions{Scan: Options{Patch: true, Log: io.Discard}}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "not supported for directory sweeps") {
		t.Fatalf("Walk+Patch must refuse loudly, got: %v", err)
	}
}

// Cancellation returns promptly: pre-cancel delivers nothing, and
// a cancel landing mid-reread aborts the pass without delivery.
func TestPatchCancel(t *testing.T) {
	file := filepath.Join(t.TempDir(), "s.patch")
	if err := os.WriteFile(file, []byte(patchFixture), 0644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var delivered int
	err := ScanWithOptions(0, file, Options{Patch: true, Context: ctx, Log: io.Discard},
		func(Detection) { delivered++ }, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled patch must surface context.Canceled, got: %v", err)
	}
	if delivered != 0 {
		t.Fatalf("pre-cancelled patch delivered %d findings", delivered)
	}

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	target := &cancelRereadTarget{
		data:   []byte("commit dddddddddddddddddddddddddddddddddddddddd\n\ndiff --git a/c.txt b/c.txt\n--- /dev/null\n+++ b/c.txt\n@@ -0,0 +1 @@\n+wallet.dat\n"),
		cancel: cancel2,
	}
	var delivered2 int
	err = scanPatch(target, Options{Context: ctx2, Log: io.Discard},
		func(Detection) { delivered2++ }, func(ProgressInfo) {})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-reread cancel must surface context.Canceled, got: %v", err)
	}
	if delivered2 != 0 {
		t.Fatalf("mid-reread cancel delivered %d findings", delivered2)
	}
}

// cancelRereadTarget scans normally on first Open, then cancels the
// context on the attribution re-read's first Read.
type cancelRereadTarget struct {
	data   []byte
	cancel context.CancelFunc
	opens  int
}

func (t *cancelRereadTarget) Describe() string   { return "mem-patch" }
func (t *cancelRereadTarget) StartOffset() int64 { return 0 }
func (t *cancelRereadTarget) Depth() int         { return 0 }
func (t *cancelRereadTarget) Size() (int64, error) {
	return int64(len(t.data)), nil
}
func (t *cancelRereadTarget) Open() (TargetReader, error) {
	t.opens++
	if t.opens == 1 {
		return &nopCloser{Reader: bytes.NewReader(t.data)}, nil
	}
	return &cancelOnceReader{Reader: bytes.NewReader(t.data), cancel: t.cancel}, nil
}

type nopCloser struct {
	*bytes.Reader
}

func (nopCloser) Close() error { return nil }

type cancelOnceReader struct {
	*bytes.Reader
	cancel context.CancelFunc
	fired  bool
}

func (r *cancelOnceReader) Read(p []byte) (int, error) {
	if !r.fired {
		r.fired = true
		r.cancel()
	}
	return r.Reader.Read(p)
}
func (r *cancelOnceReader) Close() error { return nil }

// -patch over non-patch bytes reports unattributed and
// unfingerprinted: everything still reports, nothing suppresses.
func TestPatchNonPatchInput(t *testing.T) {
	dets := scanPatchBytes(t, []byte("junk\nwallet.dat\njunk\n"), Options{})
	if len(dets) != 1 {
		t.Fatalf("got %d detections, want 1: %#v", len(dets), dets)
	}
	d := dets[0]
	if d.Commit != "" || d.Path != "" || d.Line != 0 || d.Fingerprint != "" {
		t.Errorf("non-patch hit must stay bare, got %#v", d)
	}
}

// Nested-archive hits use member-relative offsets, meaningless
// against patch bytes: they stay unattributed while root hits
// attribute normally.
func TestPatchNestedUnattributed(t *testing.T) {
	var outer bytes.Buffer
	zw := zip.NewWriter(&outer)
	w, err := zw.Create("inner.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("zip-slip wallet.dat end")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	patch := "commit " + patchC1 + "\n\ndiff --git a/z.bin b/z.bin\n--- /dev/null\n+++ b/z.bin\n@@ -0,0 +1 @@\n+wallet.dat\nTRAILER\n"
	data := append([]byte(patch), outer.Bytes()...)
	dets := scanPatchBytes(t, data, Options{})
	if len(dets) != 2 {
		t.Fatalf("got %d detections, want 2 (root + nested): %#v", len(dets), dets)
	}
	var root, nested *Detection
	for i := range dets {
		if strings.Contains(dets[i].Target, "in [") {
			nested = &dets[i]
		} else {
			root = &dets[i]
		}
	}
	if root == nil || nested == nil {
		t.Fatalf("want one root and one nested hit: %#v", dets)
	}
	if root.Commit != patchC1 || root.Path != "z.bin" || root.Line != 1 {
		t.Errorf("root hit got (%s,%s,%d)", root.Commit, root.Path, root.Line)
	}
	if nested.Commit != "" || nested.Path != "" || nested.Fingerprint != "" {
		t.Errorf("nested hit must stay bare, got %#v", nested)
	}
}

// Carve sidecars are written mid-scan, before attribution exists;
// the post-pass re-marshals them with commit/path.
func TestPatchSidecarRewrite(t *testing.T) {
	dir := t.TempDir()
	carves := filepath.Join(dir, "carves")
	dets := scanPatchBytes(t, []byte(patchFixture), Options{CarveDir: carves, CarveContextBytes: 16})
	if len(dets) != 4 {
		t.Fatalf("got %d detections, want 4", len(dets))
	}
	matches, err := filepath.Glob(filepath.Join(carves, "hit-*.json"))
	if err != nil || len(matches) != 4 {
		t.Fatalf("want 4 sidecars, got %v (err %v)", matches, err)
	}
	for _, m := range matches {
		raw, err := os.ReadFile(m)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), `"commit": "`) {
			t.Errorf("sidecar %s lacks commit attribution:\n%s", m, raw)
		}
	}
}

// Range scans slice the input, so patch positions would
// misattribute; the combination refuses loudly.
func TestPatchRangesRefused(t *testing.T) {
	err := ScanRangesWithOptions("whatever", nil, Options{Patch: true, Log: io.Discard}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "would misattribute") {
		t.Fatalf("range+patch must refuse loudly, got: %v", err)
	}
}
