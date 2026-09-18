package detector_test

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jakewins/findbtc/detector"
)

// Ground truth for test_wallet.dat (90112 bytes), verified with grep -boa:
// bestblock @ 53876, 53988 (-> 4kB block @53248) and @ 90092 (-> block @86016),
// defaultkey @ 53964 (-> block @53248). Blocks are 4kB; each needle is reported
// once per block that contains it, at its first occurrence in that block.

func TestFindsRegularWallet(t *testing.T) {
	recorder := &detectionRecorder{}

	detector.Scan(0, "./testdata/test_wallet.dat", recorder.OnDetection, recorder.OnProgress)

	// keymeta firsts per block (@12648 @25024 @28904 @33040 @49376 @54132
	// @61664 @66084 @75380), verified with grep -boa; none straddle a boundary.
	expected := []detector.Detection{
		{Description: "Found 'keymeta' at ./testdata/test_wallet.dat in 4kB block at byte offset 12288", Needle: "keymeta", Offset: 12648, Target: "./testdata/test_wallet.dat", BlockOffset: 12288, MatchLen: 7},
		{Description: "Found 'keymeta' at ./testdata/test_wallet.dat in 4kB block at byte offset 24576", Needle: "keymeta", Offset: 25024, Target: "./testdata/test_wallet.dat", BlockOffset: 24576, MatchLen: 7},
		{Description: "Found 'keymeta' at ./testdata/test_wallet.dat in 4kB block at byte offset 28672", Needle: "keymeta", Offset: 28904, Target: "./testdata/test_wallet.dat", BlockOffset: 28672, MatchLen: 7},
		{Description: "Found 'keymeta' at ./testdata/test_wallet.dat in 4kB block at byte offset 32768", Needle: "keymeta", Offset: 33040, Target: "./testdata/test_wallet.dat", BlockOffset: 32768, MatchLen: 7},
		{Description: "Found 'keymeta' at ./testdata/test_wallet.dat in 4kB block at byte offset 49152", Needle: "keymeta", Offset: 49376, Target: "./testdata/test_wallet.dat", BlockOffset: 49152, MatchLen: 7},
		{Description: "Found 'bestblock' at ./testdata/test_wallet.dat in 4kB block at byte offset 53248", Needle: "bestblock", Offset: 53876, Target: "./testdata/test_wallet.dat", BlockOffset: 53248, MatchLen: 9},
		{Description: "Found 'defaultkey' at ./testdata/test_wallet.dat in 4kB block at byte offset 53248", Needle: "defaultkey", Offset: 53964, Target: "./testdata/test_wallet.dat", BlockOffset: 53248, MatchLen: 10},
		{Description: "Found 'keymeta' at ./testdata/test_wallet.dat in 4kB block at byte offset 53248", Needle: "keymeta", Offset: 54132, Target: "./testdata/test_wallet.dat", BlockOffset: 53248, MatchLen: 7},
		{Description: "Found 'keymeta' at ./testdata/test_wallet.dat in 4kB block at byte offset 61440", Needle: "keymeta", Offset: 61664, Target: "./testdata/test_wallet.dat", BlockOffset: 61440, MatchLen: 7},
		{Description: "Found 'keymeta' at ./testdata/test_wallet.dat in 4kB block at byte offset 65536", Needle: "keymeta", Offset: 66084, Target: "./testdata/test_wallet.dat", BlockOffset: 65536, MatchLen: 7},
		{Description: "Found 'keymeta' at ./testdata/test_wallet.dat in 4kB block at byte offset 73728", Needle: "keymeta", Offset: 75380, Target: "./testdata/test_wallet.dat", BlockOffset: 73728, MatchLen: 7},
		{Description: "Found 'bestblock' at ./testdata/test_wallet.dat in 4kB block at byte offset 86016", Needle: "bestblock", Offset: 90092, Target: "./testdata/test_wallet.dat", BlockOffset: 86016, MatchLen: 9},
	}
	if !reflect.DeepEqual(expected, recorder.detections) {
		t.Errorf("Expected %v to be %v", recorder.detections, expected)
	}
}

// The raw zip bytes contain the stored filename "test_wallet.dat" twice:
// in the local header (@ byte 35 -> block @0) and in the central directory
// (@ byte 22945 -> block @20480). The nested member decompresses to the raw
// wallet above, so its hits match TestFindsRegularWallet.

func TestFindsWalletInZipFile(t *testing.T) {
	recorder := &detectionRecorder{}

	detector.Scan(0, "./testdata/test_wallet.dat.zip", recorder.OnDetection, recorder.OnProgress)

	nested := "Zipfile #0 @ byte 0 in [./testdata/test_wallet.dat.zip]"
	n := func(needle string, offset, block int64) detector.Detection {
		return detector.Detection{
			Description: fmt.Sprintf("Found '%s' at %s in 4kB block at byte offset %d", needle, nested, block),
			Needle:      needle, Offset: offset, Target: nested, BlockOffset: block, MatchLen: len(needle),
		}
	}
	expected := []detector.Detection{
		{Description: "Found 'wallet.dat' at ./testdata/test_wallet.dat.zip in 4kB block at byte offset 0", Needle: "wallet.dat", Offset: 35, Target: "./testdata/test_wallet.dat.zip", BlockOffset: 0, MatchLen: 10},
		{Description: "Found 'wallet.dat' at ./testdata/test_wallet.dat.zip in 4kB block at byte offset 20480", Needle: "wallet.dat", Offset: 22945, Target: "./testdata/test_wallet.dat.zip", BlockOffset: 20480, MatchLen: 10},
		n("keymeta", 12648, 12288),
		n("keymeta", 25024, 24576),
		n("keymeta", 28904, 28672),
		n("keymeta", 33040, 32768),
		n("keymeta", 49376, 49152),
		n("bestblock", 53876, 53248),
		n("defaultkey", 53964, 53248),
		n("keymeta", 54132, 53248),
		n("keymeta", 61664, 61440),
		n("keymeta", 66084, 65536),
		n("keymeta", 75380, 73728),
		n("bestblock", 90092, 86016),
	}
	if !reflect.DeepEqual(expected, recorder.detections) {
		t.Errorf("Expected %v to be %v", recorder.detections, expected)
	}
}

// The gzip stream is a tar archive: a 512-byte header shifts member bytes, and
// the header itself stores "test_wallet.dat" (@ byte 5 -> block @0).
// Member hits shift accordingly: bestblock @ 54388, 54500 (-> block @53248),
// defaultkey @ 54476 (-> block @53248), bestblock @ 90604 (-> block @90112).

func TestFindsWalletInGzipFile(t *testing.T) {
	recorder := &detectionRecorder{}

	detector.Scan(0, "./testdata/test_wallet.dat.tar.gz", recorder.OnDetection, recorder.OnProgress)

	nested := "Gzipfile @ byte 0 in [./testdata/test_wallet.dat.tar.gz]"
	n := func(needle string, offset, block int64) detector.Detection {
		return detector.Detection{
			Description: fmt.Sprintf("Found '%s' at %s in 4kB block at byte offset %d", needle, nested, block),
			Needle:      needle, Offset: offset, Target: nested, BlockOffset: block, MatchLen: len(needle),
		}
	}
	// keymeta straddles into block @16384 from @16380, so it is reported
	// there (this is the overlap window working, not a misattribution).
	expected := []detector.Detection{
		n("wallet.dat", 5, 0),
		n("keymeta", 13160, 12288),
		n("keymeta", 16380, 16384),
		n("keymeta", 25536, 24576),
		n("keymeta", 29416, 28672),
		n("keymeta", 33552, 32768),
		n("keymeta", 36948, 36864),
		n("keymeta", 49888, 49152),
		n("bestblock", 54388, 53248),
		n("defaultkey", 54476, 53248),
		n("keymeta", 54644, 53248),
		n("keymeta", 57428, 57344),
		n("keymeta", 62176, 61440),
		n("keymeta", 66596, 65536),
		n("keymeta", 75892, 73728),
		n("keymeta", 77908, 77824),
		n("bestblock", 90604, 90112),
	}
	if !reflect.DeepEqual(expected, recorder.detections) {
		t.Errorf("Expected %v to be %v", recorder.detections, expected)
	}
}

// A needle starting 3 bytes before the 4kB boundary ends 6 bytes into the
// next block. It must be reported exactly once, at the block holding its tail.
func TestFindsNeedleSplitAcrossBlockBoundary(t *testing.T) {
	const blockSize = 4 * 1024
	dir := t.TempDir()
	path := filepath.Join(dir, "split.bin")

	buf := bytes.Repeat([]byte{'x'}, 2*blockSize+64)
	copy(buf[blockSize-3:], "bestblock")
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}

	recorder := &detectionRecorder{}
	detector.Scan(0, path, recorder.OnDetection, recorder.OnProgress)

	expected := []detector.Detection{
		{Description: fmt.Sprintf("Found 'bestblock' at %s in 4kB block at byte offset %d", path, blockSize), Needle: "bestblock", Offset: blockSize - 3, Target: path, BlockOffset: blockSize, MatchLen: 9},
	}
	if !reflect.DeepEqual(expected, recorder.detections) {
		t.Errorf("Expected %v to be %v", recorder.detections, expected)
	}
}

// Two small zip archives concatenated into one file share 4kB block 0, so both
// end-of-central-directory records must be found; each member's wallet trace
// must be reported via its own nested target. Member names carry no needles
// and contents are deflated, so all hits below come from nested targets.
func TestFindsWalletsInTwoZipsSharingOneBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "two.zip")

	zip1 := makeZip(t, "a.txt", "padding bestblock padding")
	zip2 := makeZip(t, "b.txt", "padding defaultkey padding")
	if err := os.WriteFile(path, append(zip1, zip2...), 0644); err != nil {
		t.Fatal(err)
	}

	recorder := &detectionRecorder{}
	detector.Scan(0, path, recorder.OnDetection, recorder.OnProgress)

	expected := []detector.Detection{
		{Description: fmt.Sprintf("Found 'bestblock' at Zipfile #0 @ byte 0 in [%s] in 4kB block at byte offset 0", path), Needle: "bestblock", Offset: 8, Target: fmt.Sprintf("Zipfile #0 @ byte 0 in [%s]", path), BlockOffset: 0, MatchLen: 9},
		{Description: fmt.Sprintf("Found 'defaultkey' at Zipfile #0 @ byte %d in [%s] in 4kB block at byte offset 0", len(zip1), path), Needle: "defaultkey", Offset: 8, Target: fmt.Sprintf("Zipfile #0 @ byte %d in [%s]", len(zip1), path), BlockOffset: 0, MatchLen: 10},
	}
	if !reflect.DeepEqual(expected, recorder.detections) {
		t.Errorf("Expected %v to be %v", recorder.detections, expected)
	}
}

func makeZip(t *testing.T, name, content string) []byte {
	t.Helper()
	return makeZipFiles(t, zipMember{name, []byte(content)})
}

type zipMember struct {
	name    string
	content []byte
}

func makeZipFiles(t *testing.T, members ...zipMember) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, m := range members {
		f, err := w.Create(m.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(m.content); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// Archives nested past the depth cap are not traversed: the depth-3 note is
// found through three levels of zips, while the depth-10 core is skipped.
func TestNestedArchivesStopAtDepthCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested.zip")

	core := []byte("padding defaultkey padding")
	for level := 10; level >= 1; level-- {
		if level == 3 {
			core = makeZipFiles(t,
				zipMember{"next.zip", core},
				zipMember{"note.txt", []byte("padding bestblock padding")},
			)
		} else {
			core = makeZipFiles(t, zipMember{"next.zip", core})
		}
	}
	if err := os.WriteFile(path, core, 0644); err != nil {
		t.Fatal(err)
	}

	recorder := &detectionRecorder{}
	detector.Scan(0, path, recorder.OnDetection, recorder.OnProgress)

	if len(recorder.detections) != 1 {
		t.Fatalf("expected only the depth-3 hit, got %v", recorder.detections)
	}
	d := recorder.detections[0]
	if d.Needle != "bestblock" || strings.Count(d.Target, "Zipfile") != 3 {
		t.Errorf("expected the depth-3 bestblock hit, got %+v", d)
	}
}

// A zip member past the inflation cap is skipped from its metadata without
// inflating a gigabyte to find the needle at its end.
func TestSkipsZipMemberOverInflationCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.zip")

	content := make([]byte, (1<<30)+1)
	copy(content[len(content)-9:], "bestblock")
	if err := os.WriteFile(path, makeZipFiles(t, zipMember{"big.bin", content}), 0644); err != nil {
		t.Fatal(err)
	}
	content = nil

	recorder := &detectionRecorder{}
	detector.Scan(0, path, recorder.OnDetection, recorder.OnProgress)

	if len(recorder.detections) != 0 {
		t.Errorf("expected the oversized member to be skipped, got %v", recorder.detections)
	}
}

// A gzip stream starting at the last byte of a block has its 2-byte magic
// split across the boundary; the nested content must still be found.
func TestFindsGzipSplitAcrossBlockBoundary(t *testing.T) {
	const blockSize = 4 * 1024
	dir := t.TempDir()
	path := filepath.Join(dir, "split.gz.bin")

	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	if _, err := w.Write([]byte("padding bestblock padding")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	buf := bytes.Repeat([]byte{'x'}, blockSize+len(gz.Bytes())+64)
	copy(buf[blockSize-1:], gz.Bytes())
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}

	recorder := &detectionRecorder{}
	detector.Scan(0, path, recorder.OnDetection, recorder.OnProgress)

	nested := fmt.Sprintf("Gzipfile @ byte %d in [%s]", blockSize-1, path)
	expected := []detector.Detection{
		{Description: fmt.Sprintf("Found 'bestblock' at %s in 4kB block at byte offset 0", nested), Needle: "bestblock", Offset: 8, Target: nested, BlockOffset: 0, MatchLen: 9},
	}
	if !reflect.DeepEqual(expected, recorder.detections) {
		t.Errorf("Expected %v to be %v", recorder.detections, expected)
	}
}

// A completed scan leaves a journal pointing at the end of the target.
func TestCheckpointWrittenOnCompletion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.bin")

	const size = 3 << 20
	buf := bytes.Repeat([]byte{'x'}, size)
	copy(buf[100:], "bestblock")
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}

	ckpt := filepath.Join(dir, "ckpt.json")
	recorder := &detectionRecorder{}
	err := detector.ScanWithOptions(0, path,
		detector.Options{CheckpointPath: ckpt}, recorder.OnDetection, recorder.OnProgress)
	if err != nil {
		t.Fatal(err)
	}
	if len(recorder.detections) != 1 {
		t.Fatalf("expected 1 detection, got %v", recorder.detections)
	}

	cp, err := detector.ReadCheckpoint(ckpt)
	if err != nil {
		t.Fatal(err)
	}
	if cp.Path != path || cp.Offset != size {
		t.Errorf("expected checkpoint {path %s, offset %d}, got %+v", path, size, cp)
	}
}

// Resuming from a journal offset skips earlier bytes: only the tail hit is
// reported. This is the contract main.go relies on for -resume.
func TestResumeFromCheckpointSkipsScannedBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resume.bin")

	const size = (2 << 20) + 4096
	buf := bytes.Repeat([]byte{'x'}, size)
	copy(buf[100:], "bestblock")
	copy(buf[2<<20+100:], "defaultkey")
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}

	ckpt := filepath.Join(dir, "ckpt.json")
	raw, err := json.Marshal(detector.Checkpoint{Path: path, Offset: 2 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ckpt, raw, 0644); err != nil {
		t.Fatal(err)
	}

	cp, err := detector.ReadCheckpoint(ckpt)
	if err != nil {
		t.Fatal(err)
	}
	recorder := &detectionRecorder{}
	if err := detector.ScanWithOptions(cp.Offset, path,
		detector.Options{}, recorder.OnDetection, recorder.OnProgress); err != nil {
		t.Fatal(err)
	}

	expected := []detector.Detection{
		{Description: fmt.Sprintf("Found 'defaultkey' at %s in 4kB block at byte offset %d", path, 2<<20), Needle: "defaultkey", Offset: 2<<20 + 100, Target: path, BlockOffset: 2 << 20, MatchLen: 10},
	}
	if !reflect.DeepEqual(expected, recorder.detections) {
		t.Errorf("Expected %v to be %v", recorder.detections, expected)
	}
}

// A missing root target is a hard error, not a silent empty scan.
func TestScanMissingPathReturnsError(t *testing.T) {
	recorder := &detectionRecorder{}
	err := detector.Scan(0, filepath.Join(t.TempDir(), "nope.bin"), recorder.OnDetection, recorder.OnProgress)
	if err == nil {
		t.Fatal("expected an error scanning a missing path, got nil")
	}
	if len(recorder.detections) != 0 {
		t.Errorf("expected no detections, got %v", recorder.detections)
	}
}

// Carving a root-level hit writes exactly [offset-context, offset+len+context)
// plus a JSON sidecar describing the same detection.
func TestCarvesRootDetection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wallet.bin")

	content := bytes.Repeat([]byte{'x'}, 10000)
	copy(content[5000:], "bestblock")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	carveDir := filepath.Join(dir, "carve")
	recorder := &detectionRecorder{}
	err := detector.ScanWithOptions(0, path,
		detector.Options{CarveDir: carveDir, CarveContextBytes: 100},
		recorder.OnDetection, recorder.OnProgress)
	if err != nil {
		t.Fatal(err)
	}
	if len(recorder.detections) != 1 {
		t.Fatalf("expected 1 detection, got %v", recorder.detections)
	}
	d := recorder.detections[0]
	if d.CarvePath != filepath.Join(carveDir, "hit-000001.bin") {
		t.Errorf("unexpected carve path %q", d.CarvePath)
	}
	carved, err := os.ReadFile(d.CarvePath)
	if err != nil {
		t.Fatal(err)
	}
	if want := content[4900 : 5000+9+100]; !bytes.Equal(carved, want) {
		t.Errorf("carved %d bytes, want exact source slice of %d bytes", len(carved), len(want))
	}

	var sidecar detector.Detection
	raw, err := os.ReadFile(filepath.Join(carveDir, "hit-000001.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &sidecar); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sidecar, d) {
		t.Errorf("sidecar %v does not match detection %v", sidecar, d)
	}
}

// Carving a hit inside a zip member carves the decompressed member bytes.
func TestCarvesNestedZipDetection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "member.zip")
	member := "padding bestblock padding"

	if err := os.WriteFile(path, makeZip(t, "a.txt", member), 0644); err != nil {
		t.Fatal(err)
	}

	carveDir := filepath.Join(dir, "carve")
	recorder := &detectionRecorder{}
	err := detector.ScanWithOptions(0, path,
		detector.Options{CarveDir: carveDir, CarveContextBytes: 4},
		recorder.OnDetection, recorder.OnProgress)
	if err != nil {
		t.Fatal(err)
	}
	if len(recorder.detections) != 1 {
		t.Fatalf("expected 1 detection, got %v", recorder.detections)
	}
	carved, err := os.ReadFile(recorder.detections[0].CarvePath)
	if err != nil {
		t.Fatal(err)
	}
	if want := member[4 : 8+9+4]; string(carved) != want {
		t.Errorf("carved %q, want %q", carved, want)
	}
}

// Carving a hit inside a gzip member carves the decompressed stream bytes,
// exercising the non-seekable read path.
func TestCarvesNestedGzipDetection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "member.gz")
	member := "padding bestblock padding"

	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	if _, err := w.Write([]byte(member)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, gz.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	carveDir := filepath.Join(dir, "carve")
	recorder := &detectionRecorder{}
	err := detector.ScanWithOptions(0, path,
		detector.Options{CarveDir: carveDir, CarveContextBytes: 4},
		recorder.OnDetection, recorder.OnProgress)
	if err != nil {
		t.Fatal(err)
	}
	if len(recorder.detections) != 1 {
		t.Fatalf("expected 1 detection, got %v", recorder.detections)
	}
	carved, err := os.ReadFile(recorder.detections[0].CarvePath)
	if err != nil {
		t.Fatal(err)
	}
	if want := member[4 : 8+9+4]; string(carved) != want {
		t.Errorf("carved %q, want %q", carved, want)
	}
}

// Each newer needle (encrypted/HD legacy keys, descriptor-wallet keys) is
// found at its exact offset when placed one per block.
func TestFindsNewNeedles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new.bin")

	buf := bytes.Repeat([]byte{'x'}, 6*4096)
	placed := []struct {
		needle string
		offset int
	}{
		{"crypted_key", 100},
		{"hdseed", 4200},
		{"keymeta", 8300},
		{"walletdescriptor", 12400},
		{"activeblock", 16500},
	}
	for _, p := range placed {
		copy(buf[p.offset:], p.needle)
	}
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}

	recorder := &detectionRecorder{}
	detector.Scan(0, path, recorder.OnDetection, recorder.OnProgress)

	var expected []detector.Detection
	for _, p := range placed {
		block := int64(p.offset/4096) * 4096
		expected = append(expected, detector.Detection{
			Description: fmt.Sprintf("Found '%s' at %s in 4kB block at byte offset %d", p.needle, path, block),
			Needle:      p.needle, Offset: int64(p.offset), Target: path, BlockOffset: block, MatchLen: len(p.needle),
		})
	}
	if !reflect.DeepEqual(expected, recorder.detections) {
		t.Errorf("Expected %v to be %v", recorder.detections, expected)
	}
}

// 1MB of deterministic pseudo-random data must yield no wallet traces and no
// phantom archives; this bounds the false-positive rate of the needle set.
func TestRandomDataYieldsNoDetections(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "random.bin")

	rng := rand.New(rand.NewSource(42))
	buf := make([]byte, 1<<20)
	if _, err := rng.Read(buf); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}

	recorder := &detectionRecorder{}
	detector.Scan(0, path, recorder.OnDetection, recorder.OnProgress)

	if len(recorder.detections) != 0 {
		t.Errorf("expected no detections in random data, got %v", recorder.detections)
	}
}

// Checksum-valid 12- and 24-word phrases are found at their exact offsets.
// Vectors generated independently (see slice-3 notes); only the word count
// is ever reported, never the words themselves.
func TestFindsBIP39SeedPhrases(t *testing.T) {
	const v12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	const v15 = "abandon amount liar amount expire adjust cage candy arch gather drum bullet absurd math exhibit"
	const v18 = "abandon amount liar amount expire adjust cage candy arch gather drum bullet absurd math era live bid rib"
	const v21 = "abandon amount liar amount expire adjust cage candy arch gather drum bullet absurd math era live bid rhythm alien crouch saddle"
	const v24 = "abandon amount liar amount expire adjust cage candy arch gather drum bullet absurd math era live bid rhythm alien crouch range attend journey unaware"

	dir := t.TempDir()
	path := filepath.Join(dir, "seed.bin")
	buf := bytes.Repeat([]byte{'x'}, 8*4096)
	copy(buf[500:], " "+v12+" ") // spaces: the letter fill must not glue to words
	copy(buf[5000:], " "+v15+" ")
	copy(buf[9000:], " "+v18+" ")
	copy(buf[13000:], " "+v21+" ")
	copy(buf[17000:], " "+v24+" ")
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}

	recorder := &detectionRecorder{}
	detector.Scan(0, path, recorder.OnDetection, recorder.OnProgress)

	n := func(label string, offset, block, span int64) detector.Detection {
		return detector.Detection{
			Description: fmt.Sprintf("Found '%s seed phrase' at %s in 4kB block at byte offset %d", label, path, block),
			Needle:      label, Offset: offset, Target: path, BlockOffset: block, MatchLen: int(span),
		}
	}
	expected := []detector.Detection{
		n("bip39-12", 501, 0, int64(len(v12))),
		n("bip39-15", 5001, 4096, int64(len(v15))),
		n("bip39-18", 9001, 8192, int64(len(v18))),
		n("bip39-21", 13001, 12288, int64(len(v21))),
		n("bip39-24", 17001, 16384, int64(len(v24))),
	}
	if !reflect.DeepEqual(expected, recorder.detections) {
		t.Errorf("Expected %v to be %v", recorder.detections, expected)
	}
}

// Separators and letter case do not matter: tabs, newlines, doubled spaces
// and uppercase spell the same phrase.
func TestFindsBIP39WithMixedCaseAndSeparators(t *testing.T) {
	words := []string{"abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "about"}
	seps := []string{"\n", "  ", "\t", " ", "\n\n", " ", "\t ", "  ", "\n", " ", " "}
	var mangled string
	for i, w := range words {
		if i > 0 {
			mangled += seps[i-1]
		}
		if i%2 == 1 {
			mangled += strings.ToUpper(w)
		} else {
			mangled += w
		}
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "mangled.bin")
	buf := bytes.Repeat([]byte{'x'}, 2*4096)
	copy(buf[299:], " "+mangled+" ")
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}

	recorder := &detectionRecorder{}
	detector.Scan(0, path, recorder.OnDetection, recorder.OnProgress)

	expected := []detector.Detection{
		{Description: fmt.Sprintf("Found 'bip39-12 seed phrase' at %s in 4kB block at byte offset 0", path), Needle: "bip39-12", Offset: 300, Target: path, BlockOffset: 0, MatchLen: len(mangled)},
	}
	if !reflect.DeepEqual(expected, recorder.detections) {
		t.Errorf("Expected %v to be %v", recorder.detections, expected)
	}
}

// Valid words with a bad checksum, and runs too short to be phrases, report
// nothing.
func TestRejectsInvalidBIP39Checksum(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.bin")
	buf := bytes.Repeat([]byte{'x'}, 2*4096)
	copy(buf[500:], " "+strings.Repeat("abandon ", 12))
	copy(buf[2000:], " "+strings.Repeat("abandon ", 11))
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}

	recorder := &detectionRecorder{}
	detector.Scan(0, path, recorder.OnDetection, recorder.OnProgress)

	if len(recorder.detections) != 0 {
		t.Errorf("expected no detections for bad checksums, got %v", recorder.detections)
	}
}

// A carved seed hit writes the phrase bytes to disk, while the detection
// itself (and its JSON sidecar) carries only the word count, never the words.
func TestCarvesBIP39WithoutLeakingWords(t *testing.T) {
	const v12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

	dir := t.TempDir()
	path := filepath.Join(dir, "seedcarve.bin")
	buf := bytes.Repeat([]byte{'x'}, 2*4096)
	copy(buf[500:], " "+v12+" ")
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}

	carveDir := filepath.Join(dir, "carve")
	recorder := &detectionRecorder{}
	err := detector.ScanWithOptions(0, path,
		detector.Options{CarveDir: carveDir, CarveContextBytes: 4},
		recorder.OnDetection, recorder.OnProgress)
	if err != nil {
		t.Fatal(err)
	}
	if len(recorder.detections) != 1 {
		t.Fatalf("expected 1 detection, got %v", recorder.detections)
	}
	d := recorder.detections[0]
	carved, err := os.ReadFile(d.CarvePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(carved, []byte(v12)) {
		t.Errorf("carved bytes do not contain the phrase")
	}
	line, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"abandon", "about", v12} {
		if strings.Contains(string(line), leak) {
			t.Errorf("detection JSON leaks seed words: %s", line)
		}
	}
	raw, err := os.ReadFile(filepath.Join(carveDir, "hit-000001.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "abandon") {
		t.Errorf("carve sidecar leaks seed words: %s", raw)
	}
}

// A phrase straddling the 4kB boundary is reported exactly once, at the block
// holding its tail, with its true start offset.
func TestFindsBIP39AcrossBlockBoundary(t *testing.T) {
	const v12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	const start = 4096 - 40

	dir := t.TempDir()
	path := filepath.Join(dir, "bound.bin")
	buf := bytes.Repeat([]byte{'x'}, 3*4096)
	copy(buf[start-1:], " "+v12+" ")
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}

	recorder := &detectionRecorder{}
	detector.Scan(0, path, recorder.OnDetection, recorder.OnProgress)

	expected := []detector.Detection{
		{Description: fmt.Sprintf("Found 'bip39-12 seed phrase' at %s in 4kB block at byte offset 4096", path), Needle: "bip39-12", Offset: start, Target: path, BlockOffset: 4096, MatchLen: len(v12)},
	}
	if !reflect.DeepEqual(expected, recorder.detections) {
		t.Errorf("Expected %v to be %v", recorder.detections, expected)
	}
}

// makeLocalEntry builds a bare local-file-header entry with no central
// directory and no ECD: the truncated-zip case recovery exists for.
func makeLocalEntry(t *testing.T, name string, method, flags uint16, content []byte) []byte {
	t.Helper()
	data := content
	comp, uncomp := uint32(len(content)), uint32(len(content))
	if method == 8 {
		var buf bytes.Buffer
		w, err := flate.NewWriter(&buf, flate.DefaultCompression)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(content); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		data = buf.Bytes()
		comp = uint32(len(data))
		if flags&0x8 != 0 {
			comp, uncomp = 0, 0 // data-descriptor entries carry no sizes
		}
	}
	hdr := make([]byte, 30)
	binary.LittleEndian.PutUint32(hdr[0:4], 0x04034b50)
	binary.LittleEndian.PutUint16(hdr[4:6], 20)
	binary.LittleEndian.PutUint16(hdr[6:8], flags)
	binary.LittleEndian.PutUint16(hdr[8:10], method)
	binary.LittleEndian.PutUint32(hdr[14:18], crc32.ChecksumIEEE(content))
	binary.LittleEndian.PutUint32(hdr[18:22], comp)
	binary.LittleEndian.PutUint32(hdr[22:26], uncomp)
	binary.LittleEndian.PutUint16(hdr[26:28], uint16(len(name)))
	out := append(hdr, []byte(name)...)
	return append(out, data...)
}

// A truncated zip (local headers only, ECD lost) still yields its stored
// member; the raw hit comes first since stored bytes sit in the clear.
func TestRecoversTruncatedStoredZip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trunc.bin")

	buf := bytes.Repeat([]byte{'x'}, 2048)
	entry := makeLocalEntry(t, "w.dat", 0, 0, []byte("padding bestblock padding"))
	copy(buf[100:], entry)
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}

	recorder := &detectionRecorder{}
	detector.Scan(0, path, recorder.OnDetection, recorder.OnProgress)

	nested := fmt.Sprintf("ZipEntry \"w.dat\" @ byte %d in [%s]", 100+30+5, path)
	expected := []detector.Detection{
		{Description: fmt.Sprintf("Found 'bestblock' at %s in 4kB block at byte offset 0", path), Needle: "bestblock", Offset: 100 + 30 + 5 + 8, Target: path, BlockOffset: 0, MatchLen: 9},
		{Description: fmt.Sprintf("Found 'bestblock' at %s in 4kB block at byte offset 0", nested), Needle: "bestblock", Offset: 8, Target: nested, BlockOffset: 0, MatchLen: 9},
	}
	if !reflect.DeepEqual(expected, recorder.detections) {
		t.Errorf("Expected %v to be %v", recorder.detections, expected)
	}
}

// Same, but deflated: the raw bytes hide the needle, so only the recovered
// inflated member reports it.
func TestRecoversTruncatedDeflatedZip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "truncd.bin")

	buf := bytes.Repeat([]byte{'x'}, 2048)
	entry := makeLocalEntry(t, "w.dat", 8, 0, []byte("padding bestblock padding"))
	copy(buf[100:], entry)
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}

	recorder := &detectionRecorder{}
	detector.Scan(0, path, recorder.OnDetection, recorder.OnProgress)

	nested := fmt.Sprintf("ZipEntry \"w.dat\" @ byte %d in [%s]", 100+30+5, path)
	expected := []detector.Detection{
		{Description: fmt.Sprintf("Found 'bestblock' at %s in 4kB block at byte offset 0", nested), Needle: "bestblock", Offset: 8, Target: nested, BlockOffset: 0, MatchLen: 9},
	}
	if !reflect.DeepEqual(expected, recorder.detections) {
		t.Errorf("Expected %v to be %v", recorder.detections, expected)
	}
}

// Data-descriptor entries carry no sizes and are skipped quietly.
func TestSkipsDataDescriptorEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "desc.bin")

	buf := bytes.Repeat([]byte{'x'}, 2048)
	copy(buf[100:], makeLocalEntry(t, "w.dat", 8, 0x8, []byte("padding bestblock padding")))
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}

	recorder := &detectionRecorder{}
	detector.Scan(0, path, recorder.OnDetection, recorder.OnProgress)

	if len(recorder.detections) != 0 {
		t.Errorf("expected no detections, got %v", recorder.detections)
	}
}

// Garbage behind a local-header magic (unknown method, inconsistent stored
// sizes) is rejected without hanging or reporting.
func TestSkipsGarbageLocalHeaders(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "garbage.bin")

	buf := bytes.Repeat([]byte{'x'}, 2048)
	bad1 := makeLocalEntry(t, "w.dat", 99, 0, []byte("padding bestblock padding"))
	bad2 := makeLocalEntry(t, "w.dat", 0, 0, []byte("padding bestblock padding"))
	binary.LittleEndian.PutUint32(bad2[22:26], 9999) // stored sizes must match
	copy(buf[100:], bad1)
	copy(buf[600:], bad2)
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}

	recorder := &detectionRecorder{}
	detector.Scan(0, path, recorder.OnDetection, recorder.OnProgress)

	for _, d := range recorder.detections {
		if strings.Contains(d.Target, "ZipEntry") {
			t.Errorf("garbage header produced a recovery target: %+v", d)
		}
	}
}

// Checksum-valid WIF and extended keys are found at exact offsets. The xprv
// is BIP32 test vector 1; the rest are synthetic checksum-valid vectors
// (deterministic filler, not secrets), all verified by an independent
// base58check implementation with no valid sub-windows.
func TestFindsPrivateKeys(t *testing.T) {
	const wifu = "5HpjKrb7dH5kKQQzmbjB87Mxova7mek5bXUTWfndcX6tBoqUwzm"
	const wifc = "KwFfpDsaF7yxCELuyrH9gP5XL7TAt5b9HPWC1xCQbmrxvhJgMQHb"
	const wift = "91bMubQfDW9tHTvHPwd5zhuvTavpvpHGwULQbJ98xFqvxsUsWbZ"
	const xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
	const xpub = "xpub661MyMwAqRbcEwdCwTTxJyb5Y1kUEBvKzorS2dKhJr9vkBAVcHW7VVEAiKdExnqZ4GnaorJRKVLRAH1hFH3Uh7ding2Za8oYrQgfkWX5SeZ"
	const tprv = "tprv8ZgxMBicQKsPdGnGVznT7VGLJ7LC4FEUy8qx6fLYEV7ReyaS47XcTSH8nEqYxwayjp9heARX8gKnEuSiXanXVXM82B4MguxSRJceAzecMUR"

	dir := t.TempDir()
	path := filepath.Join(dir, "keys.bin")
	buf := bytes.Repeat([]byte{'x'}, 5*4096)
	copy(buf[500:], " "+wifu+" ") // spaces: the base58 fill must not glue to keys
	copy(buf[2000:], " "+wifc+" ")
	copy(buf[4000:], " "+wift+" ")
	copy(buf[6000:], " "+xprv+" ")
	copy(buf[9000:], " "+xpub+" ")
	copy(buf[12000:], " "+tprv+" ")
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}

	recorder := &detectionRecorder{}
	detector.Scan(0, path, recorder.OnDetection, recorder.OnProgress)

	n := func(label, kind string, offset, block, span int64) detector.Detection {
		return detector.Detection{
			Description: fmt.Sprintf("Found '%s %s' at %s in 4kB block at byte offset %d", label, kind, path, block),
			Needle:      label, Offset: offset, Target: path, BlockOffset: block, MatchLen: int(span),
		}
	}
	expected := []detector.Detection{
		n("wif", "private key", 501, 0, 51),
		n("wif", "private key", 2001, 0, 52),
		n("wif-testnet", "private key", 4001, 0, 51),
		n("xprv", "extended key", 6001, 4096, 111),
		n("xpub", "extended key", 9001, 8192, 111),
		n("tprv", "extended key", 12001, 8192, 111),
	}
	if !reflect.DeepEqual(expected, recorder.detections) {
		t.Errorf("Expected %v to be %v", recorder.detections, expected)
	}
}

// Right shape and prefix but a broken checksum: nothing is reported.
func TestRejectsInvalidKeyChecksums(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "badkeys.bin")
	buf := bytes.Repeat([]byte{'x'}, 3*4096)
	copy(buf[500:], " KwFfpDsaF7yxCELuyrH9gP5XL7TAt5b9HPWC1xCQbmrxvhJgMQHc ")                                                             // last char flipped
	copy(buf[2000:], " xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHj ") // last char flipped
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}

	recorder := &detectionRecorder{}
	detector.Scan(0, path, recorder.OnDetection, recorder.OnProgress)

	if len(recorder.detections) != 0 {
		t.Errorf("expected no detections for bad checksums, got %v", recorder.detections)
	}
}

// A 111-byte extended key straddling the 4kB boundary is reported exactly
// once, at the block holding its tail, with its true start offset.
func TestFindsKeyAcrossBlockBoundary(t *testing.T) {
	const xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
	const start = 4096 - 46

	dir := t.TempDir()
	path := filepath.Join(dir, "keybound.bin")
	buf := bytes.Repeat([]byte{'x'}, 3*4096)
	copy(buf[start-1:], " "+xprv+" ")
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}

	recorder := &detectionRecorder{}
	detector.Scan(0, path, recorder.OnDetection, recorder.OnProgress)

	expected := []detector.Detection{
		{Description: fmt.Sprintf("Found 'xprv extended key' at %s in 4kB block at byte offset 4096", path), Needle: "xprv", Offset: start, Target: path, BlockOffset: 4096, MatchLen: 111},
	}
	if !reflect.DeepEqual(expected, recorder.detections) {
		t.Errorf("Expected %v to be %v", recorder.detections, expected)
	}
}

// Key detections carry type labels only; the key itself appears nowhere.
func TestKeyDetectionsLeakNothing(t *testing.T) {
	const wifc = "KwFfpDsaF7yxCELuyrH9gP5XL7TAt5b9HPWC1xCQbmrxvhJgMQHb"

	dir := t.TempDir()
	path := filepath.Join(dir, "keypriv.bin")
	buf := bytes.Repeat([]byte{'x'}, 4096)
	copy(buf[500:], " "+wifc+" ")
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}

	recorder := &detectionRecorder{}
	detector.Scan(0, path, recorder.OnDetection, recorder.OnProgress)

	if len(recorder.detections) != 1 {
		t.Fatalf("expected 1 detection, got %v", recorder.detections)
	}
	line, err := json.Marshal(recorder.detections[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(line), wifc) {
		t.Errorf("detection JSON leaks key material: %s", line)
	}
	if !strings.Contains(string(line), `"needle":"wif"`) {
		t.Errorf("detection JSON lost its label: %s", line)
	}
}

// Synthetic but structurally valid keystores (fixed hex debris, not secrets)
// in both "crypto" and legacy "Crypto" shapes are found at exact offsets.
const testKeystore = `{"address":"abababababababababababababababababababab","crypto":{"cipher":"aes-128-ctr","ciphertext":"d172bf74d172bf74d172bf74d172bf74d172bf74d172bf74d172bf74d172bf74","cipherparams":{"iv":"85c2d1b9d5e5b0f38a0d781b033b008a"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"85c2d1b985c2d1b985c2d1b985c2d1b985c2d1b985c2d1b985c2d1b985c2d1b9"},"mac":"85c2d1b985c2d1b985c2d1b985c2d1b985c2d1b985c2d1b985c2d1b985c2d1b9"},"id":"7e59429e-4c8c-4c9e-9e9e-9e9e9e9e9e9e","version":3}`

const testKeystoreCap = `{"address":"abababababababababababababababababababab","id":"7e59429e-4c8c-4c9e-9e9e-9e9e9e9e9e9e","version":3,"Crypto":{"cipher":"aes-128-ctr","ciphertext":"d172bf74d172bf74d172bf74d172bf74d172bf74d172bf74d172bf74d172bf74","cipherparams":{"iv":"85c2d1b9d5e5b0f38a0d781b033b008a"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"85c2d1b985c2d1b985c2d1b985c2d1b985c2d1b985c2d1b985c2d1b985c2d1b9"},"mac":"85c2d1b985c2d1b985c2d1b985c2d1b985c2d1b985c2d1b985c2d1b985c2d1b9"}}`

func TestFindsEthKeystores(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keystore.bin")
	buf := bytes.Repeat([]byte{'x'}, 4*4096)
	copy(buf[500:], testKeystore)
	copy(buf[5000:], testKeystoreCap)
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}

	recorder := &detectionRecorder{}
	detector.Scan(0, path, recorder.OnDetection, recorder.OnProgress)

	n := func(offset, block int64, span int) detector.Detection {
		return detector.Detection{
			Description: fmt.Sprintf("Found 'eth-keystore' at %s in 4kB block at byte offset %d", path, block),
			Needle:      "eth-keystore", Offset: offset, Target: path, BlockOffset: block, MatchLen: span,
		}
	}
	expected := []detector.Detection{
		n(500, 0, len(testKeystore)),
		n(5000, 4096, len(testKeystoreCap)),
	}
	if !reflect.DeepEqual(expected, recorder.detections) {
		t.Errorf("Expected %v to be %v", recorder.detections, expected)
	}
}

// A keystore straddling the 4kB boundary is reported exactly once, at the
// block holding its tail, with its true start offset.
func TestFindsKeystoreAcrossBlockBoundary(t *testing.T) {
	const start = 4096 - 200

	dir := t.TempDir()
	path := filepath.Join(dir, "ksbound.bin")
	buf := bytes.Repeat([]byte{'x'}, 3*4096)
	copy(buf[start:], testKeystore)
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}

	recorder := &detectionRecorder{}
	detector.Scan(0, path, recorder.OnDetection, recorder.OnProgress)

	expected := []detector.Detection{
		{Description: fmt.Sprintf("Found 'eth-keystore' at %s in 4kB block at byte offset 4096", path), Needle: "eth-keystore", Offset: start, Target: path, BlockOffset: 4096, MatchLen: len(testKeystore)},
	}
	if !reflect.DeepEqual(expected, recorder.detections) {
		t.Errorf("Expected %v to be %v", recorder.detections, expected)
	}
}

// Near-misses (no crypto section, no address, bad address, non-hex
// ciphertext) report nothing.
func TestRejectsKeystoreLookalikes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lookalike.bin")
	buf := bytes.Repeat([]byte{'x'}, 4*4096)
	copy(buf[100:], `{"address":"abababababababababababababababababababab","version":3}`)
	copy(buf[1000:], `{"crypto":{"cipher":"aes-128-ctr","ciphertext":"d172bf74","kdf":"scrypt"}}`)
	copy(buf[2000:], `{"address":"xyz","crypto":{"cipher":"c","ciphertext":"ab12","kdf":"k"}}`)
	copy(buf[3000:], `{"address":"abababababababababababababababababababab","crypto":{"cipher":"c","ciphertext":"zz-top","kdf":"k"}}`)
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}

	recorder := &detectionRecorder{}
	detector.Scan(0, path, recorder.OnDetection, recorder.OnProgress)

	if len(recorder.detections) != 0 {
		t.Errorf("expected no detections for lookalikes, got %v", recorder.detections)
	}
}

// Carving a keystore hit always captures the whole object: even a tiny
// context brackets it fully since the match spans object start to end.
func TestCarvesWholeKeystoreObject(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kscarve.bin")
	buf := bytes.Repeat([]byte{'x'}, 2*4096)
	copy(buf[500:], testKeystore)
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}

	carveDir := filepath.Join(dir, "carve")
	recorder := &detectionRecorder{}
	err := detector.ScanWithOptions(0, path,
		detector.Options{CarveDir: carveDir, CarveContextBytes: 8},
		recorder.OnDetection, recorder.OnProgress)
	if err != nil {
		t.Fatal(err)
	}
	if len(recorder.detections) != 1 {
		t.Fatalf("expected 1 detection, got %v", recorder.detections)
	}
	carved, err := os.ReadFile(recorder.detections[0].CarvePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(carved, []byte(testKeystore)) {
		t.Errorf("carved bytes do not contain the whole keystore object")
	}
	var back map[string]any
	if err := json.Unmarshal([]byte(testKeystore), &back); err != nil {
		t.Fatal(err)
	}
	if back["address"] != "abababababababababababababababababababab" {
		t.Errorf("fixture keystore does not round-trip: %v", back)
	}
}

// Each carve reports the wallet-structure magic nearest its hit, with the
// magic's carve-file offset. Magics sit 100 bytes before their needles with
// a 512-byte context, so every magic lands at carve offset 412.
func TestCarveClassificationMagics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "magics.bin")
	buf := bytes.Repeat([]byte{'x'}, 4*4096)
	placements := []struct {
		magic []byte
		at    int
	}{
		{[]byte("SQLite format 3\x00"), 500},
		{[]byte{0x62, 0x31, 0x05, 0x00}, 4500},
		{[]byte{0x1f, 0x8b, 0x08}, 8500},
		{[]byte{0x50, 0x4b, 0x03, 0x04}, 12500},
	}
	for _, p := range placements {
		copy(buf[p.at:], p.magic)
		copy(buf[p.at+100:], "bestblock")
	}
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}

	carveDir := filepath.Join(dir, "carve")
	recorder := &detectionRecorder{}
	err := detector.ScanWithOptions(0, path,
		detector.Options{CarveDir: carveDir, CarveContextBytes: 512},
		recorder.OnDetection, recorder.OnProgress)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"sqlite", "bdb", "gzip", "zip"}
	if len(recorder.detections) != len(want) {
		t.Fatalf("expected %d detections, got %v", len(want), recorder.detections)
	}
	for i, d := range recorder.detections {
		if d.Carve == nil || d.Carve.Class != want[i] {
			t.Errorf("hit %d: expected class %q, got %+v", i, want[i], d.Carve)
			continue
		}
		if d.Carve.MagicOffset == nil || *d.Carve.MagicOffset != 412 {
			t.Errorf("hit %d: expected magic at carve offset 412, got %+v", i, d.Carve)
		}
	}
}

// Plain filler carves as text; random bytes carve as high-entropy.
func TestCarveClassificationTextAndEntropy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "classes.bin")
	buf := bytes.Repeat([]byte{'x'}, 6*4096)
	copy(buf[500:], "bestblock")
	rng := rand.New(rand.NewSource(7))
	random := make([]byte, 3*4096)
	if _, err := rng.Read(random); err != nil {
		t.Fatal(err)
	}
	copy(buf[2*4096:], random)
	copy(buf[2*4096+4096+100:], "bestblock")
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}

	carveDir := filepath.Join(dir, "carve")
	recorder := &detectionRecorder{}
	err := detector.ScanWithOptions(0, path,
		detector.Options{CarveDir: carveDir, CarveContextBytes: 512},
		recorder.OnDetection, recorder.OnProgress)
	if err != nil {
		t.Fatal(err)
	}
	if len(recorder.detections) != 2 {
		t.Fatalf("expected 2 detections, got %v", recorder.detections)
	}
	if got := recorder.detections[0].Carve.Class; got != "text" {
		t.Errorf("expected text carve, got %q", got)
	}
	if got := recorder.detections[1].Carve.Class; got != "high-entropy" {
		t.Errorf("expected high-entropy carve, got %q", got)
	}
	if recorder.detections[0].Carve.MagicOffset != nil {
		t.Errorf("text carve should have no magic offset, got %+v", recorder.detections[0].Carve)
	}
}

type detectionRecorder struct {
	detections []detector.Detection
}

func (r *detectionRecorder) OnDetection(detection detector.Detection) {
	r.detections = append(r.detections, detection)
}
func (r *detectionRecorder) OnProgress(pg detector.ProgressInfo) {
}
