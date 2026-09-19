package detector

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"hash/adler32"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Goal 16 hostile-image resource audit: worst-case fixtures proving the
// documented bounds. Time guards are generous hang-catchers (minutes),
// not benchmarks — see docs/BENCHMARKS.md for throughput.

// withLoweredZipCap runs f with the member inflation cap lowered so
// bomb tests need megabytes, not gibibytes. No test here is parallel.
func withLoweredZipCap(t *testing.T, cap int64, f func()) {
	t.Helper()
	old := maxZipMemberBytes
	maxZipMemberBytes = cap
	defer func() { maxZipMemberBytes = old }()
	f()
}

// patchZipCentralSize rewrites the first central-directory record's
// uncompressed size, mimicking a hostile header that lies.
func patchZipCentralSize(t *testing.T, raw []byte, size uint32) []byte {
	t.Helper()
	at := bytes.Index(raw, []byte{0x50, 0x4b, 0x01, 0x02})
	if at < 0 {
		t.Fatal("no central directory in crafted zip")
	}
	out := append([]byte{}, raw...)
	binary.LittleEndian.PutUint32(out[at+24:], size)
	return out
}

func writeZipMember(t *testing.T, path, name string, content []byte) {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
}

// inflateCapped is the enforcement mechanism both zip inflate paths
// share: over-cap streams fail, at-cap streams pass through intact.
func TestInflateCapped(t *testing.T) {
	big := bytes.NewReader(make([]byte, 2<<20))
	if _, err := inflateCapped(big, 1<<20, "test"); err == nil {
		t.Error("2 MiB past a 1 MiB cap must fail")
	} else if !strings.Contains(err.Error(), "inflates past") {
		t.Errorf("cap error must say so: %v", err)
	}
	exact := bytes.NewReader(make([]byte, 1<<20))
	got, err := inflateCapped(exact, 1<<20, "test")
	if err != nil {
		t.Errorf("at-cap stream must pass: %v", err)
	} else if len(got) != 1<<20 {
		t.Errorf("at-cap stream truncated to %d", len(got))
	}
}

// A zip bomb that declares 1 byte but inflates 5 MiB must never inflate:
// archive/zip enforces declared sizes on read (failing loud here), the
// publish check plus inflateCapped bound honest paths, and the scan
// completes with the member skipped.
func TestZipLiedSizeCapped(t *testing.T) {
	withLoweredZipCap(t, 1<<20, func() {
		dir := t.TempDir()
		content := make([]byte, 5<<20)
		copy(content[len(content)-9:], "bestblock")
		path := filepath.Join(dir, "lied.zip")
		writeZipMember(t, path, "bomb.bin", content)
		content = nil
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, patchZipCentralSize(t, raw, 1), 0644); err != nil {
			t.Fatal(err)
		}
		// Direct: member Open must fail, never inflate 5 MiB.
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		zt := &zipScanTarget{source: &fileScanTarget{path: path}, fileIndex: 0, zipSize: st.Size()}
		if r, err := zt.Open(); err == nil {
			r.Close()
			t.Fatal("lied member Open must fail")
		}
		// Full scan: completes quickly, member skipped, no detections.
		start := time.Now()
		var dets []Detection
		err = ScanWithOptions(0, path, Options{},
			func(d Detection) { dets = append(dets, d) },
			func(ProgressInfo) {})
		if err != nil {
			t.Fatalf("bombed scan must complete: %v", err)
		}
		if time.Since(start) > 120*time.Second {
			t.Error("bombed scan took suspiciously long")
		}
		for _, d := range dets {
			if strings.Contains(d.Target, "Zipfile") {
				t.Errorf("skipped member produced a detection: %+v", d)
			}
		}
	})
}

// A 1 GiB-claim member (tiny body, giant declared size) is skipped at
// publish without inflating anything.
func TestZipGiantClaimSkippedFast(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claim.zip")
	writeZipMember(t, path, "tiny.bin", []byte("bestblock"))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, patchZipCentralSize(t, raw, 1<<30), 0644); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	var dets []Detection
	if err := ScanWithOptions(0, path, Options{},
		func(d Detection) { dets = append(dets, d) },
		func(ProgressInfo) {}); err != nil {
		t.Fatalf("scan must complete: %v", err)
	}
	if time.Since(start) > 120*time.Second {
		t.Error("giant-claim scan took suspiciously long")
	}
	if len(dets) != 0 {
		t.Errorf("skipped member must stay silent, got %v", dets)
	}
}

// An E01 chunk whose zlib inflates past the chunk size must fail loud,
// naming the chunk — the decode is capped, never ballooned.
func TestEWFChunkBombFailsLoud(t *testing.T) {
	dir := t.TempDir()
	raw := ewfTestRaw(t, 100*1024)
	path := buildEWF(t, dir, "bomb", raw, ewfBuildOpt{poisonExtra: 32768})
	tgt, err := detectScanTarget(path, 0)
	if err != nil {
		t.Fatalf("poisoned set must parse eagerly (bomb is in decode): %v", err)
	}
	r, err := tgt.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	buf := make([]byte, 4096)
	_, err = r.(interface {
		ReadAt([]byte, int64) (int, error)
	}).ReadAt(buf, 0)
	if err == nil {
		t.Fatal("chunk bomb decode must fail")
	} else if !strings.Contains(err.Error(), "chunk 0") {
		t.Errorf("bomb error must name chunk 0: %v", err)
	}
}

// An E01 table claiming more chunks than the volume declares must fail
// eager parsing (table lies cannot size the chunk index).
func TestEWFTableExceedsVolume(t *testing.T) {
	dir := t.TempDir()
	raw := ewfTestRaw(t, 200*1024)
	path := buildEWF(t, dir, "lie", raw, ewfBuildOpt{})
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Volume data starts at 13 + 76; chunks u32 at +4, sectors u64 at +16,
	// checksum over [:1048] at [1048:1052]. Shrink the declared media to
	// one chunk so only the table cross-check can fire.
	const voff = 13 + 76
	binary.LittleEndian.PutUint32(blob[voff+4:], 1)
	binary.LittleEndian.PutUint64(blob[voff+16:], 64)
	binary.LittleEndian.PutUint32(blob[voff+1048:], adler32.Checksum(blob[voff:voff+1048]))
	if err := os.WriteFile(path, blob, 0644); err != nil {
		t.Fatal(err)
	}
	_, err = detectScanTarget(path, 0)
	if err == nil {
		t.Fatal("table exceeding the volume must fail eager parsing")
	} else if !strings.Contains(err.Error(), "volume declares") {
		t.Errorf("lie error must cite the volume count: %v", err)
	}
}

// A 10 MiB gzip bomb streams through bounded RAM: the needle at the end
// of the inflated stream is still found and the scan completes.
func TestGzipBombStreams(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bomb.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := gzip.NewWriter(f)
	if _, err := w.Write(make([]byte, 10<<20)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("bestblock-tail")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	var dets []Detection
	if err := ScanWithOptions(0, path, Options{},
		func(d Detection) { dets = append(dets, d) },
		func(ProgressInfo) {}); err != nil {
		t.Fatalf("bomb scan must complete: %v", err)
	}
	if time.Since(start) > 120*time.Second {
		t.Error("gzip bomb scan took suspiciously long")
	}
	found := false
	for _, d := range dets {
		if d.Needle == "bestblock" {
			found = true
		}
	}
	if !found {
		t.Error("needle at the end of the bomb stream was missed")
	}
}
