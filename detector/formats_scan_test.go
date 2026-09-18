package detector

import (
	"bytes"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// End to end: every Goal 6 format is found by a real scan with exact
// offsets, and seed words stay out of default output.
func TestScanGoal6Formats(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "formats.bin")
	buf := bytes.Repeat([]byte{0x00}, 7*4096)
	put := func(off int, s string) {
		if off+len(s) > len(buf) {
			t.Fatalf("fixture overflows image at %d", off)
		}
		copy(buf[off:], " "+s+" ")
	}
	put(500, electrumStandardSeed)
	put(2000, descPK)
	put(4000, slip39Valid20)
	put(8000, mmOldVault)
	put(12000, electrumFileJSON)
	put(16000, "open-chan-bucket")
	put(17000, "channel.backup")
	put(20000, slip39Valid33)
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}

	var dets []Detection
	err := ScanWithOptions(0, path, Options{},
		func(d Detection) { dets = append(dets, d) },
		func(ProgressInfo) {})
	if err != nil {
		t.Fatal(err)
	}
	var needles []string
	for _, d := range dets {
		needles = append(needles, d.Needle)
		// Privacy: no fixture material in descriptions or words.
		if strings.Contains(d.Description, "since sick") || len(d.Words) != 0 {
			t.Errorf("default scan leaks seed material in %v", d)
		}
	}
	// Order is per-block detector-loop order, not offset order: the
	// electrum-file markers at 12000 sit in the same block as the vault
	// at 8000, and the file loop runs before the vault loop.
	want := []string{"electrum-seed", "descriptor", "slip39-20", "electrum-file",
		"metamask-vault", "open-chan-bucket", "channel.backup", "slip39-33"}
	if !reflect.DeepEqual(needles, want) {
		t.Fatalf("needles %v, want %v", needles, want)
	}
	byNeedle := map[string]Detection{}
	for _, d := range dets {
		byNeedle[d.Needle] = d
	}
	if d := byNeedle["electrum-seed"]; d.Offset != 501 {
		t.Errorf("electrum-seed at %d, want 501", d.Offset)
	}
	if d := byNeedle["descriptor"]; d.Offset != 2001 {
		t.Errorf("descriptor at %d, want 2001", d.Offset)
	}
	if d := byNeedle["slip39-20"]; d.Offset != 4001 {
		t.Errorf("slip39-20 at %d, want 4001", d.Offset)
	}
	if d := byNeedle["slip39-33"]; d.Offset != 20001 {
		t.Errorf("slip39-33 at %d, want 20001", d.Offset)
	}
	if d := byNeedle["metamask-vault"]; d.Offset != 8011 {
		t.Errorf("metamask-vault at %d, want 8011", d.Offset)
	}
}

// Lightning markers are long distinctive strings; they must not occur in
// random bytes or project prose. (The SCB file itself is encrypted and has
// no content magic, so file names are the only signal by design.)
func TestLightningNoiseCorpus(t *testing.T) {
	markers := [][]byte{[]byte("channel.backup"), []byte("channel.db"),
		[]byte("open-chan-bucket"), []byte("closed-chan-bucket")}
	rng := rand.New(rand.NewSource(99))
	noise := make([]byte, 1<<20)
	if _, err := rng.Read(noise); err != nil {
		t.Fatal(err)
	}
	for _, m := range markers {
		if bytes.Contains(noise, m) {
			t.Fatalf("noise contains %q", m)
		}
	}
	for _, f := range []string{"../LICENSE", "../main.go"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range markers {
			if bytes.Contains(raw, m) {
				t.Errorf("%s contains %q", f, m)
			}
		}
	}
	// README and GOALS name the two file markers deliberately (like
	// wallet.dat); the bucket markers must still be absent.
	for _, f := range []string{"../README.md", "../GOALS.md"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range [][]byte{[]byte("open-chan-bucket"), []byte("closed-chan-bucket")} {
			if bytes.Contains(raw, m) {
				t.Errorf("%s contains %q", f, m)
			}
		}
	}
}

// With --reveal the new seed finders attach words, like BIP39.
func TestScanGoal6Reveal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "r.bin")
	payload := []byte("pad " + electrumSegwitSeed + " mid " + slip39Share20 + " end")
	if err := os.WriteFile(path, payload, 0644); err != nil {
		t.Fatal(err)
	}
	var dets []Detection
	err := ScanWithOptions(0, path, Options{Reveal: true},
		func(d Detection) { dets = append(dets, d) },
		func(ProgressInfo) {})
	if err != nil {
		t.Fatal(err)
	}
	if len(dets) != 2 {
		t.Fatalf("got %d detections, want 2", len(dets))
	}
	if strings.Join(dets[0].Words, " ") != electrumSegwitSeed {
		t.Error("electrum words must round-trip with --reveal")
	}
	if strings.Join(dets[1].Words, " ") != slip39Share20 {
		t.Error("slip39 words must round-trip with --reveal")
	}
}
