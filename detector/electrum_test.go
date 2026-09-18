package detector

import (
	"math/rand"
	"os"
	"strings"
	"testing"
)

// Electrum fixtures. Seed vectors were brute-forced against the HMAC rule
// and confirmed with Electrum's own calc_seed_type (new-seed prefixes
// 01/100/101/102 from electrum/version.py).

const electrumStandardSeed = "since sick check reward swamp mind board moral cross bounce mutual equip"
const electrumSegwitSeed = "exchange wonder picnic sort bulk coil strong abstract monitor arm culture panda"

const electrumFileJSON = `{"addr_history": {}, "addresses": {"change": [], "receiving": []}, ` +
	`"keystore": {"type": "bip32", "xpub": "xpub661MyMwAqRbcFtXgS31sXRBN3fca9XwxwMQr99p9DRkYEYosiyXeY9wk6AxKjzyUKMewVUdmyFvyBGCixdAPH3MaaFoV"}, ` +
	`"seed_version": 17, "use_encryption": false, "wallet_type": "standard"}`

func TestFindElectrumSeeds(t *testing.T) {
	buf := []byte("noise " + electrumStandardSeed + " middle " + electrumSegwitSeed + " tail")
	matches := findElectrumSeeds(buf, 1000, true, true)
	if len(matches) != 2 {
		t.Fatalf("got %d matches, want 2", len(matches))
	}
	if matches[0].seedType != "standard" || matches[1].seedType != "segwit" {
		t.Errorf("types %q,%q, want standard,segwit", matches[0].seedType, matches[1].seedType)
	}
	// Twelve in-list words with no version prefix must stay silent
	// (the standard vector reversed).
	dud := "equip mutual bounce cross moral board mind swamp reward check sick since"
	if m := findElectrumSeeds([]byte(dud), 0, true, true); len(m) != 0 {
		t.Errorf("non-seed phrase reported %d matches", len(m))
	}
}

func TestFindElectrumFiles(t *testing.T) {
	buf := []byte("xx " + electrumFileJSON + " yy")
	matches := findElectrumFiles(buf, 500, true, true)
	if len(matches) != 1 {
		t.Fatalf("got %d matches, want 1", len(matches))
	}
	m := matches[0]
	span := buf[m.startAbs-500 : m.endAbs-500]
	if !strings.Contains(string(span), `"seed_version"`) || !strings.Contains(string(span), `"wallet_type"`) {
		t.Errorf("match span %q covers only part of the wallet markers", span)
	}
	// seed_version alone, without a wallet_type nearby, is not a wallet.
	if matches := findElectrumFiles([]byte(`{"seed_version": 17}`), 0, true, true); len(matches) != 0 {
		t.Error("seed_version without wallet_type must stay silent")
	}
	// Non-numeric seed_version is not a wallet.
	dud := `{"seed_version": "seventeen", "wallet_type": "standard"}`
	if matches := findElectrumFiles([]byte(dud), 0, true, true); len(matches) != 0 {
		t.Error("string seed_version must stay silent")
	}
}

// The Goal 6 FP bar, same corpus as the BIP39 detectors: silence on 1MB of
// random bytes and on the project's own prose.
func TestElectrumNoiseCorpus(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	noise := make([]byte, 1<<20)
	if _, err := rng.Read(noise); err != nil {
		t.Fatal(err)
	}
	if m := findElectrumSeeds(noise, 0, true, true); len(m) != 0 {
		t.Fatalf("noise seeds: %d matches, want 0", len(m))
	}
	if m := findElectrumFiles(noise, 0, true, true); len(m) != 0 {
		t.Fatalf("noise files: %d matches, want 0", len(m))
	}
	for _, f := range []string{"../LICENSE", "../README.md", "../GOALS.md", "../main.go"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if m := findElectrumSeeds(raw, 0, true, true); len(m) != 0 {
			t.Errorf("%s: %d seed matches, want 0", f, len(m))
		}
		if m := findElectrumFiles(raw, 0, true, true); len(m) != 0 {
			t.Errorf("%s: %d file matches, want 0", f, len(m))
		}
	}
}

// The overlap window cannot exceed one block: the tail-copy pipeline sizes
// every block buffer as blockSize+overlap and prefixes the full overlap,
// so a larger overlap corrupts offsets. Every span const must respect it.
func TestScanOverlapBelowBlockSize(t *testing.T) {
	if scanOverlap() >= blockSize {
		t.Fatalf("scanOverlap %d >= blockSize %d", scanOverlap(), blockSize)
	}
}

func TestSuppressedByBIP39(t *testing.T) {
	long := []bip39Match{{words: 21, startAbs: 100, endAbs: 227}}
	inside := electrumSeedMatch{startAbs: 150, endAbs: 220}
	if !suppressedByBIP39(inside, long) {
		t.Error("window inside a longer exact phrase must suppress")
	}
	identical := electrumSeedMatch{startAbs: 100, endAbs: 227}
	same := []bip39Match{{words: 12, startAbs: 100, endAbs: 227}}
	if suppressedByBIP39(identical, same) {
		t.Error("identical spans must report both")
	}
	outside := electrumSeedMatch{startAbs: 300, endAbs: 370}
	if suppressedByBIP39(outside, long) {
		t.Error("disjoint window must not suppress")
	}
}

// Seed words ride along for --reveal but never serialize into descriptions.
func TestElectrumSeedReveal(t *testing.T) {
	matches := findElectrumSeeds([]byte(electrumStandardSeed), 0, true, true)
	if len(matches) != 1 {
		t.Fatalf("got %d matches, want 1", len(matches))
	}
	if strings.Join(matches[0].phrase, " ") != electrumStandardSeed {
		t.Error("phrase must round-trip for --reveal")
	}
}
