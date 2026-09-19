package detector

// Fragment-aware salvage tests. BDB fixtures are synthesized to the db.in
// header layout (confirmed against test_wallet.dat); the SQLite fixture is
// BTCRecover's public bitcoincore-0.21.1 test wallet (password
// 'btcr-test-password', no funds), verified quick_check-clean at commit.

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildBDB assembles a synthetic wallet-style database: meta page naming the
// size plus btree pages with sequential pgnos, one carrying a wallet needle.
func buildBDB(t *testing.T, pageSize, nPages int) []byte {
	t.Helper()
	img := make([]byte, pageSize*nPages)
	for p := 0; p < nPages; p++ {
		off := p * pageSize
		binary.LittleEndian.PutUint32(img[off+8:], uint32(p))
		binary.LittleEndian.PutUint32(img[off+12:], bdbBtreeMagic)
		binary.LittleEndian.PutUint32(img[off+16:], 9)
		for i := off + 20; i < off+pageSize; i++ {
			img[i] = byte(p + 1)
		}
	}
	binary.LittleEndian.PutUint32(img[20:], uint32(pageSize))
	if len(img) > 3*pageSize+100 {
		copy(img[3*pageSize+100:], "bestblock")
	}
	return img
}

// fragmentPages shuffles page-aligned chunks with junk between, returning the
// buffer and the expected pgno→offset map.
func fragmentPages(t *testing.T, img []byte, pageSize int, order []int, junk []byte) ([]byte, map[uint32]int64) {
	t.Helper()
	var buf []byte
	buf = append(buf, bytes.Repeat([]byte{0xAA}, 100)...)
	offsets := map[uint32]int64{}
	for _, p := range order {
		offsets[uint32(p)] = int64(len(buf))
		buf = append(buf, img[p*pageSize:(p+1)*pageSize]...)
		buf = append(buf, junk...)
	}
	return buf, offsets
}

func TestSalvageBDBRoundTrip(t *testing.T) {
	const ps, n = 1024, 6
	img := buildBDB(t, ps, n)
	order := []int{3, 0, 5, 1, 4, 2}
	buf, offsets := fragmentPages(t, img, ps, order, bytes.Repeat([]byte{0xAA}, 300))
	r := Salvage(buf, 1000)
	if r == nil {
		t.Fatal("no salvage result")
	}
	if !bytes.Equal(r.Image, img) {
		t.Fatal("stitched image differs from original")
	}
	info := r.Info
	if info.Kind != "bdb" || info.PageSize != ps || !info.Complete || !info.Ordered {
		t.Fatalf("info = %+v", info)
	}
	if len(info.Pages) != n {
		t.Fatalf("pages = %d, want %d", len(info.Pages), n)
	}
	for _, p := range info.Pages {
		if want := 1000 + offsets[p.PgNo]; p.Offset != want {
			t.Errorf("pgno %d offset = %d, want %d", p.PgNo, p.Offset, want)
		}
	}
	if len(info.Runs) != n {
		t.Errorf("runs = %+v, want %d single-page runs", info.Runs, n)
	}
}

// The real fixture holds exactly two headed pages (probe-verified); the
// parser must find both, size via meta, and nothing else.
func TestSalvageBDBRealPages(t *testing.T) {
	raw, err := os.ReadFile("testdata/test_wallet.dat")
	if err != nil {
		t.Fatal(err)
	}
	found := scanBDBHeaders(raw, 0)
	var pgnos []uint32
	for _, p := range found {
		pgnos = append(pgnos, p.pgno)
	}
	if len(pgnos) != 2 || pgnos[0] != 0 || pgnos[1] != 2 {
		t.Fatalf("pgnos = %v, want [0 2]", pgnos)
	}
	if ps := bdbPageSize(raw, 0, found); ps != 4096 {
		t.Fatalf("pagesize = %d, want 4096", ps)
	}
}

func TestSalvageBDBSinglePage(t *testing.T) {
	img := buildBDB(t, 1024, 1)
	if r := Salvage(img, 0); r != nil {
		t.Fatalf("single page salvaged: %+v", r.Info)
	}
	// Clipped final page is skipped, leaving one page: no salvage.
	if r := Salvage(img[:1000], 0); r != nil {
		t.Fatalf("clipped page salvaged: %+v", r.Info)
	}
}

func readSQLiteWallet(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/sqlite_wallet.dat")
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 5*4096 {
		t.Fatalf("fixture size = %d, want 20480", len(raw))
	}
	return raw
}

func TestSalvageSQLiteShuffled(t *testing.T) {
	raw := readSQLiteWallet(t)
	order := []int{2, 0, 4, 1, 3}
	var buf []byte
	buf = append(buf, bytes.Repeat([]byte{0}, 100)...)
	offsets := map[int]int64{}
	for _, p := range order {
		offsets[p] = int64(len(buf))
		buf = append(buf, raw[p*4096:(p+1)*4096]...)
		buf = append(buf, bytes.Repeat([]byte{0}, 500)...)
	}
	r := Salvage(buf, 0)
	if r == nil {
		t.Fatal("no salvage result")
	}
	info := r.Info
	if info.Kind != "sqlite" || info.PageSize != 4096 {
		t.Fatalf("info = %+v", info)
	}
	if len(info.Pages) != 5 || !info.Complete || info.Ordered {
		t.Fatalf("pages=%d complete=%v ordered=%v, want 5/true/false",
			len(info.Pages), info.Complete, info.Ordered)
	}
	// Page map must cover every source page exactly once.
	seen := map[int64]bool{}
	master := 0
	for _, p := range info.Pages {
		seen[p.Offset] = true
		if p.Kind == "sqlite-master" {
			master++
			if p.Offset != offsets[0] {
				t.Errorf("master offset = %d, want %d", p.Offset, offsets[0])
			}
		}
	}
	if master != 1 {
		t.Fatalf("masters = %d, want 1", master)
	}
	for p, off := range offsets {
		if !seen[off] {
			t.Errorf("source page %d at %d missing from map", p, off)
		}
	}
}

func TestSalvageSQLiteOrdered(t *testing.T) {
	raw := readSQLiteWallet(t)
	r := Salvage(raw, 500)
	if r == nil {
		t.Fatal("no salvage result")
	}
	// Byte-identical to the original, which quick_check-verified clean at
	// fixture commit — so the assembly opens wherever it opens.
	if !bytes.Equal(r.Image, raw) {
		t.Fatal("ordered assembly differs from original")
	}
	if !r.Info.Complete || !r.Info.Ordered || len(r.Info.Runs) != 1 {
		t.Fatalf("info = %+v", r.Info)
	}
}

func TestSalvageSQLiteNoHeader(t *testing.T) {
	raw := readSQLiteWallet(t)[4096:] // pages 2-5, page 1 gone
	r := Salvage(raw, 0)
	if r == nil {
		t.Fatal("no salvage result")
	}
	if r.Info.PageSize != 4096 || len(r.Info.Pages) != 4 {
		t.Fatalf("info = %+v", r.Info)
	}
	if r.Info.Complete || r.Info.Ordered {
		t.Fatalf("complete/ordered = %v/%v, want false/false", r.Info.Complete, r.Info.Ordered)
	}
}

func TestSalvageNoise(t *testing.T) {
	// Deterministic filler: every byte value cycled, no valid headers.
	noise := make([]byte, 1<<20)
	for i := range noise {
		noise[i] = byte(i * 7919)
	}
	if r := Salvage(noise, 0); r != nil {
		t.Fatalf("noise salvaged: %+v", r.Info)
	}
	if r := Salvage(bytes.Repeat([]byte{0}, 8192), 0); r != nil {
		t.Fatalf("zeros salvaged: %+v", r.Info)
	}
	if r := Salvage(nil, 0); r != nil {
		t.Fatal("nil salvaged")
	}
}

// End to end: a scan hit whose carve holds database pages surfaces salvage
// on the detection, writes the .salvage.db, and records the page map.
func TestScanCarveSalvages(t *testing.T) {
	dir := t.TempDir()
	imgPath := filepath.Join(dir, "disk.img")
	img := buildBDB(t, 1024, 2)
	copy(img[1024+100:], "bestblock")
	if err := os.WriteFile(imgPath, img, 0644); err != nil {
		t.Fatal(err)
	}
	carveDir := filepath.Join(dir, "carve")
	var dets []Detection
	err := ScanWithOptions(0, imgPath, Options{CarveDir: carveDir, CarveContextBytes: 2048},
		func(d Detection) { dets = append(dets, d) },
		func(ProgressInfo) {})
	if err != nil {
		t.Fatal(err)
	}
	if len(dets) != 1 {
		t.Fatalf("detections = %d, want 1", len(dets))
	}
	s := dets[0].Salvage
	if s == nil || len(s.Pages) != 2 || !s.Complete || !s.Ordered {
		t.Fatalf("salvage = %+v", s)
	}
	// Synthetic filler pages are structurally incomplete: the verdict
	// must say suspect, not valid.
	if s.Verdict != SalvageSuspect || len(s.Reasons) == 0 {
		t.Errorf("salvage verdict = %q reasons %v, want suspect", s.Verdict, s.Reasons)
	}
	raw, err := os.ReadFile(filepath.Join(carveDir, "hit-000001.salvage.db"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, img) {
		t.Fatal("salvage image differs from source pages")
	}
	sidecar, err := os.ReadFile(filepath.Join(carveDir, "hit-000001.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sidecar), `"salvage"`) {
		t.Errorf("sidecar lacks salvage:\n%s", sidecar)
	}
	if !strings.Contains(string(sidecar), `"verdict": "suspect"`) || !strings.Contains(string(sidecar), `"reasons"`) {
		t.Errorf("sidecar lacks verdict/reasons:\n%s", sidecar)
	}
}
