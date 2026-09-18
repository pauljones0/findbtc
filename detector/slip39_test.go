package detector

import (
	"math/rand"
	"os"
	"strings"
	"testing"
)

// SLIP39 fixtures from the official vectors.json (trezor/python-shamir-
// mnemonic): valid 20/33-word shares, an extendable share, and shares whose
// checksums fail.

const slip39Valid20 = "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard"
const slip39BadSum20 = "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision kidney"
const slip39Share20 = "shadow pistol academic always adequate wildlife fancy gross oasis cylinder mustang wrist rescue view short owner flip making coding armed"
const slip39Valid33 = "theory painting academic academic armed sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips brave detect luck"
const slip39BadSum33 = "theory painting academic academic armed sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips brave detect lunar"
const slip39Extendable20 = "testify swimming academic academic column loyalty smear include exotic bedroom exotic wrist lobe cover grief golden smart junior estimate learn"

func TestRS1024Vectors(t *testing.T) {
	for _, v := range []string{slip39Valid20, slip39Share20, slip39Valid33, slip39Extendable20} {
		if err := validSLIP39(strings.Split(v, " ")); err != nil {
			t.Errorf("valid share rejected: %s", err)
		}
	}
	for _, v := range []string{slip39BadSum20, slip39BadSum33} {
		if err := validSLIP39(strings.Split(v, " ")); err == nil {
			t.Errorf("bad checksum accepted: %s...", v[:40])
		}
	}
	// 19- and 21-word lengths are not valid shares.
	if err := validSLIP39(strings.Split(slip39Valid20, " ")[:19]); err == nil {
		t.Error("19-word input accepted")
	}
}

func TestFindSLIP39(t *testing.T) {
	buf := []byte("pad " + slip39Valid20 + " mid " + slip39Valid33 + " end")
	matches := findSLIP39(buf, 200, true, true)
	if len(matches) != 2 {
		t.Fatalf("got %d matches, want 2", len(matches))
	}
	if matches[0].words != 20 || matches[1].words != 33 {
		t.Errorf("lengths %d,%d, want 20,33", matches[0].words, matches[1].words)
	}
	if m := findSLIP39([]byte(slip39BadSum20), 0, true, true); len(m) != 0 {
		t.Error("bad checksum must stay silent")
	}
	// Extendable shares (customization "shamir_extendable") also report.
	if m := findSLIP39([]byte(slip39Extendable20), 0, true, true); len(m) != 1 {
		t.Errorf("extendable share: %d matches, want 1", len(m))
	}
}

func TestSLIP39NoiseCorpus(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	noise := make([]byte, 1<<20)
	if _, err := rng.Read(noise); err != nil {
		t.Fatal(err)
	}
	if m := findSLIP39(noise, 0, true, true); len(m) != 0 {
		t.Fatalf("noise: %d matches, want 0", len(m))
	}
	for _, f := range []string{"../LICENSE", "../README.md", "../GOALS.md", "../main.go"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if m := findSLIP39(raw, 0, true, true); len(m) != 0 {
			t.Errorf("%s: %d matches, want 0", f, len(m))
		}
	}
}

func TestSLIP39Reveal(t *testing.T) {
	matches := findSLIP39([]byte(slip39Valid20), 0, true, true)
	if len(matches) != 1 {
		t.Fatalf("got %d matches, want 1", len(matches))
	}
	if strings.Join(matches[0].phrase, " ") != slip39Valid20 {
		t.Error("phrase must round-trip for --reveal")
	}
}
