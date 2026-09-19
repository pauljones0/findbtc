package detector

import (
	"archive/zip"
	"bytes"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// Goal 15 throughput benchmarks. Fixtures are deterministic (fixed seed)
// and sized to dominate pipeline startup: 32 MiB raw, 8 MiB through a
// nested zip, 32 MiB through E01. Numbers for the reference machine live
// in docs/BENCHMARKS.md; reproduce with:
//   go test ./detector/ -run '^$' -bench 'BenchmarkScan' -benchtime 1x

var benchOnce sync.Once
var benchDir string

func benchFixtures(b *testing.B) string {
	b.Helper()
	benchOnce.Do(func() {
		dir, err := os.MkdirTemp("", "findbtc-bench")
		if err != nil {
			panic(err)
		}
		benchDir = dir
		raw := benchRaw(32 << 20)
		if err := os.WriteFile(filepath.Join(dir, "raw.img"), raw, 0644); err != nil {
			panic(err)
		}
		inner := benchZip("inner.dat", benchRaw(8<<20))
		outer := benchZip("outer.zip", inner)
		if err := os.WriteFile(filepath.Join(dir, "nested.zip"), outer, 0644); err != nil {
			panic(err)
		}
		buildEWF(b, dir, "bench", raw, ewfBuildOpt{compress: func(i int) bool { return i%2 == 0 }})
	})
	return benchDir
}

// benchRaw returns size deterministic bytes with a wallet needle every
// MiB so detection (not just I/O) is exercised.
func benchRaw(size int) []byte {
	rng := rand.New(rand.NewSource(0xB15))
	buf := make([]byte, size)
	rng.Read(buf)
	for off := 0; off+9 < size; off += 1 << 20 {
		copy(buf[off:], "bestblock")
	}
	return buf
}

func benchZip(name string, content []byte) []byte {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.Create(name)
	if err != nil {
		panic(err)
	}
	if _, err := f.Write(content); err != nil {
		panic(err)
	}
	if err := w.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func benchScan(b *testing.B, path string, media int64) {
	b.Helper()
	b.SetBytes(media)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := ScanWithOptions(0, path, Options{},
			func(Detection) {}, func(ProgressInfo) {}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkScanRaw32MB(b *testing.B) {
	dir := benchFixtures(b)
	benchScan(b, filepath.Join(dir, "raw.img"), 32<<20)
}

func BenchmarkScanNestedZip8MB(b *testing.B) {
	dir := benchFixtures(b)
	benchScan(b, filepath.Join(dir, "nested.zip"), 8<<20)
}

func BenchmarkScanE01Mixed32MB(b *testing.B) {
	dir := benchFixtures(b)
	benchScan(b, filepath.Join(dir, "bench.E01"), 32<<20)
}
