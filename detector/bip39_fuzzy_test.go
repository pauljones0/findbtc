package detector

// Fuzzy BIP39 tests: near-miss windows (missing/typo words), unordered runs,
// --reveal plumbing, and the false-positive bar.

import (
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Canonical 12-word vector (zero entropy): abandon x11 + about.
const fuzzyExact12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

func TestNearMissMissingWord(t *testing.T) {
	words := strings.Split(fuzzyExact12, " ")
	words[3] = "zzzzzzzzzzzzz" // long garbage: deterministically zero typo candidates
	data := []byte(strings.Join(words, " "))
	exact, near, unordered := findBIP39Phrases(data, 0, true, true)
	if len(exact) != 0 {
		t.Fatalf("exact = %d, want 0", len(exact))
	}
	if len(near) != 1 {
		t.Fatalf("near = %d, want 1", len(near))
	}
	n := near[0]
	if n.words != 12 || len(n.gaps) != 1 || n.gaps[0] != 3 {
		t.Fatalf("gaps = %v (words=%d), want [3]", n.gaps, n.words)
	}
	if len(n.typo) != 1 || n.typo[0] != 0 || len(n.validating) != 1 || n.validating[0] != 0 {
		t.Fatalf("typo/validating = %v/%v, want [0]/[0]", n.typo, n.validating)
	}
	if got := n.pattern(); got != "gaps=[3] typo=[0] validating=[0]" {
		t.Fatalf("pattern = %q", got)
	}
	if n.phrase[3] != "zzzzzzzzzzzzz" || n.phrase[0] != "abandon" {
		t.Fatalf("phrase = %v", n.phrase)
	}
	if len(unordered) != 0 {
		t.Fatalf("unordered = %d, want 0", len(unordered))
	}
}

func TestNearMissTypo(t *testing.T) {
	words := strings.Split(fuzzyExact12, " ")
	words[0] = "abandonn" // d=1 from abandon
	data := []byte(strings.Join(words, " "))
	_, near, _ := findBIP39Phrases(data, 0, true, true)
	if len(near) != 1 {
		t.Fatalf("near = %d, want 1", len(near))
	}
	n := near[0]
	if len(n.gaps) != 1 || n.gaps[0] != 0 {
		t.Fatalf("gaps = %v, want [0]", n.gaps)
	}
	// Oracle-verified (independent Python Levenshtein over the wordlist):
	// exactly one word within d=2 (abandon), and it validates because it
	// restores the known-valid phrase.
	if n.typo[0] != 1 || n.validating[0] != 1 {
		t.Fatalf("typo/validating = %v/%v, want [1]/[1]", n.typo, n.validating)
	}
	if n.validating[0] > n.typo[0] {
		t.Fatalf("validating %d > typo %d", n.validating[0], n.typo[0])
	}
	found := false
	for _, idx := range typoCandidates("abandonn") {
		if idx == 0 {
			found = true
		}
		if levenshteinBounded("abandonn", bip39Words[idx], 2) > 2 {
			t.Fatalf("candidate %q exceeds distance 2", bip39Words[idx])
		}
	}
	if !found {
		t.Fatal("candidates for abandonn lack abandon (index 0)")
	}
	// Deterministic across runs.
	_, near2, _ := findBIP39Phrases(data, 0, true, true)
	if near2[0].pattern() != n.pattern() {
		t.Fatal("pattern not deterministic")
	}
}

func TestNearMissTwoGaps(t *testing.T) {
	words := strings.Split(fuzzyExact12, " ")
	words[2] = "qqqqqqqqqqqq"
	words[9] = "wwwwwwwwwwww"
	data := []byte(strings.Join(words, " "))
	_, near, _ := findBIP39Phrases(data, 0, true, true)
	if len(near) != 1 {
		t.Fatalf("near = %d, want 1", len(near))
	}
	if got := near[0].pattern(); got != "gaps=[2,9] typo=[0,0] validating=[0,0]" {
		t.Fatalf("pattern = %q", got)
	}
}

func TestUnorderedRun(t *testing.T) {
	// Twelve valid words, bad checksum (verified by the assertions below).
	data := []byte("abandon ability able about above absent absorb abstract absurd abuse access accident")
	exact, near, unordered := findBIP39Phrases(data, 0, true, true)
	if len(exact) != 0 {
		t.Fatalf("exact = %d, want 0 (fixture must not validate)", len(exact))
	}
	if len(near) != 0 {
		t.Fatalf("near = %d, want 0", len(near))
	}
	if len(unordered) != 1 || unordered[0].words != 12 {
		t.Fatalf("unordered = %+v, want one run=12", unordered)
	}
	if len(unordered[0].phrase) != 12 || unordered[0].phrase[0] != "abandon" {
		t.Fatalf("phrase = %v", unordered[0].phrase)
	}
}

func TestExactSuppressesHints(t *testing.T) {
	// Exact phrase plus adjacent junk: the derivative near-miss windows and
	// the unordered run must stay silent.
	data := []byte(fuzzyExact12 + " junkword")
	exact, near, unordered := findBIP39Phrases(data, 0, true, true)
	if len(exact) != 1 {
		t.Fatalf("exact = %d, want 1", len(exact))
	}
	if len(near) != 0 {
		t.Fatalf("near = %+v, want none (derivative of exact)", near)
	}
	if len(unordered) != 0 {
		t.Fatalf("unordered = %+v, want none (run holds exact)", unordered)
	}
	// Thirteen valid words holding an exact phrase: no unordered hint.
	data = []byte(fuzzyExact12 + " abandon")
	exact, near, unordered = findBIP39Phrases(data, 0, true, true)
	if len(exact) == 0 {
		t.Fatal("exact = 0, want >=1")
	}
	if len(near) != 0 || len(unordered) != 0 {
		t.Fatalf("near=%d unordered=%d, want none", len(near), len(unordered))
	}
}

func TestLevenshteinBounded(t *testing.T) {
	for _, tc := range []struct {
		a, b  string
		bound int
		want  int
	}{
		{"kitten", "sitting", 10, 3},
		{"", "abc", 10, 3},
		{"abc", "", 10, 3},
		{"abandon", "abandon", 2, 0},
		{"abandonn", "abandon", 2, 1},
	} {
		if got := levenshteinBounded(tc.a, tc.b, tc.bound); got != tc.want {
			t.Errorf("d(%q,%q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
		if got := levenshteinBounded("abc", "xyz", 1); got <= 1 {
			t.Errorf("bounded overflow = %d, want >1", got)
		}
	}
}

func TestTypoCandidates(t *testing.T) {
	got := typoCandidates("abandon")
	if len(got) != 1 || got[0] != 0 {
		t.Fatalf("candidates(abandon) = %v, want [0]", got)
	}
	if got := typoCandidates("abcdefghijklmnop"); got != nil {
		t.Fatalf("long token candidates = %v, want nil", got)
	}
	a, b := typoCandidates("abandonn"), typoCandidates("ABANDONN")
	if len(a) == 0 || len(a) != len(b) {
		t.Fatalf("case handling: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatal("candidates not case-insensitive")
		}
	}
}

// The FP bar: silence on 1MB of random bytes and on the project's own prose
// (~50KB of LICENSE/README/GOALS/main.go). The wordlist file itself is
// excluded by design — it is a known-positive unordered run.
func TestFuzzyNoiseCorpus(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	noise := make([]byte, 1<<20)
	if _, err := rng.Read(noise); err != nil {
		t.Fatal(err)
	}
	exact, near, unordered := findBIP39Phrases(noise, 0, true, true)
	if len(exact)+len(near)+len(unordered) != 0 {
		t.Fatalf("noise: exact=%d near=%d unordered=%d, want all zero",
			len(exact), len(near), len(unordered))
	}
	for _, f := range []string{"../LICENSE", "../README.md", "../GOALS.md", "../main.go"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		exact, near, unordered := findBIP39Phrases(raw, 0, true, true)
		if len(exact)+len(near)+len(unordered) != 0 {
			t.Errorf("%s: exact=%d near=%d unordered=%d, want all zero",
				f, len(exact), len(near), len(unordered))
		}
	}
}

// Default output must never contain words; --reveal must contain exactly the
// phrase. End to end through Scan with Reveal off and on.
func TestScanRevealWords(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "disk.img")
	payload := []byte("prefix-noise " + fuzzyExact12 + " suffix-noise")
	if err := os.WriteFile(img, payload, 0644); err != nil {
		t.Fatal(err)
	}
	scan := func(reveal bool) []Detection {
		var dets []Detection
		err := ScanWithOptions(0, img, Options{Reveal: reveal},
			func(d Detection) { dets = append(dets, d) },
			func(ProgressInfo) {})
		if err != nil {
			t.Fatal(err)
		}
		return dets
	}
	byNeedle := func(dets []Detection, needle string) []Detection {
		var out []Detection
		for _, d := range dets {
			if d.Needle == needle {
				out = append(out, d)
			}
		}
		return out
	}
	plain := scan(false)
	found := byNeedle(plain, "bip39-12")
	if len(found) != 1 {
		t.Fatalf("default: bip39-12 hits = %d, want 1", len(found))
	}
	if len(found[0].Words) != 0 {
		t.Fatalf("default: Words = %v, want empty", found[0].Words)
	}
	raw, err := json.Marshal(found[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"abandon", "about"} {
		if strings.Contains(string(raw), w) {
			t.Fatalf("default JSON leaks %q:\n%s", w, raw)
		}
	}
	rev := scan(true)
	found = byNeedle(rev, "bip39-12")
	if len(found) != 1 {
		t.Fatalf("reveal: bip39-12 hits = %d, want 1", len(found))
	}
	want := strings.Split(fuzzyExact12, " ")
	if strings.Join(found[0].Words, " ") != strings.Join(want, " ") {
		t.Fatalf("reveal: Words = %v", found[0].Words)
	}
}

// Near-miss descriptions carry positions and counts only.
func TestNearMissPatternLeaksNoWords(t *testing.T) {
	words := strings.Split(fuzzyExact12, " ")
	words[5] = "abandonn"
	_, near, _ := findBIP39Phrases([]byte(strings.Join(words, " ")), 0, true, true)
	if len(near) != 1 {
		t.Fatalf("near = %d, want 1", len(near))
	}
	desc := "Found 'bip39-12-near-miss " + near[0].pattern() + "' at test"
	for _, w := range append(strings.Split(fuzzyExact12, " "), "abandonn") {
		if strings.Contains(desc, w) {
			t.Fatalf("description leaks %q: %s", w, desc)
		}
	}
}

// Boundary windows that are a valid run plus overhang stay silent; the
// unordered hint describes the location instead.
func TestNearMissBarnacleDropped(t *testing.T) {
	data := []byte("qzx qzx qzx abandon ability able about above absent absorb abstract absurd abuse access accident qzx qzx")
	exact, near, unordered := findBIP39Phrases(data, 0, true, true)
	if len(exact) != 0 || len(near) != 0 {
		t.Fatalf("exact=%d near=%+v, want none", len(exact), near)
	}
	if len(unordered) != 1 || unordered[0].words != 12 {
		t.Fatalf("unordered = %+v, want one run=12", unordered)
	}
}

// A truncated phrase (11 valid words, nothing beyond) still reports: the
// barnacle rule only drops windows where valid words continue past the edge.
func TestTruncatedPhraseKept(t *testing.T) {
	words := strings.Split(fuzzyExact12, " ")[:11]
	data := []byte(strings.Join(words, " ") + " qzx")
	_, near, unordered := findBIP39Phrases(data, 0, true, true)
	if len(near) != 1 {
		t.Fatalf("near = %+v, want 1", near)
	}
	// Oracle-verified counts: 5 words within d=2 of qzx, none validating.
	if got := near[0].pattern(); got != "gaps=[11] typo=[5] validating=[0]" {
		t.Fatalf("pattern = %q", got)
	}
	if len(unordered) != 0 {
		t.Fatalf("unordered = %+v, want none", unordered)
	}
}

// A 13-word run reports as unordered; the overlapping near-miss-15 windows
// lose to the run that describes the location better.
func TestRunBeatsOverlappingNear(t *testing.T) {
	data := []byte("abandon ability able about above absent absorb abstract absurd abuse access accident abandon qzx qzx")
	exact, near, unordered := findBIP39Phrases(data, 0, true, true)
	if len(exact) != 0 {
		t.Fatalf("exact = %d, want 0 (fixture must not validate)", len(exact))
	}
	if len(near) != 0 {
		t.Fatalf("near = %+v, want none (run wins)", near)
	}
	if len(unordered) != 1 || unordered[0].words != 13 {
		t.Fatalf("unordered = %+v, want one run=13", unordered)
	}
}

// Cross-block runs report approximately once: a run touching the leading
// trimmed edge belongs to the previous block.
func TestUnorderedLeadingEdge(t *testing.T) {
	data := []byte("abandon ability able about above absent absorb abstract absurd abuse access accident")
	_, _, unordered := findBIP39Phrases(data, 0, false, true)
	if len(unordered) != 0 {
		t.Fatalf("leading-edge run: unordered = %+v, want none", unordered)
	}
	_, _, unordered = findBIP39Phrases(data, 0, true, true)
	if len(unordered) != 1 {
		t.Fatalf("first-block run: unordered = %+v, want 1", unordered)
	}
}

// All five lengths fire near-miss on one 24-token fragment: an exact phrase,
// one garbage gap, then 11 valid words. Same-gap windows dedupe to one hit
// per length; the exact phrase still reports exactly once.
func TestNearMissAllLengths(t *testing.T) {
	data := []byte(fuzzyExact12 + " zzzzzzzzzzzzz" + strings.Repeat(" abandon", 11))
	exact, near, unordered := findBIP39Phrases(data, 0, true, true)
	if len(exact) != 1 || exact[0].words != 12 {
		t.Fatalf("exact = %+v, want one bip39-12", exact)
	}
	if len(near) != 5 {
		t.Fatalf("near = %+v, want one per length", near)
	}
	wantGaps := map[int][]int{12: {10}, 15: {12}, 18: {12}, 21: {12}, 24: {12}}
	for _, n := range near {
		want, ok := wantGaps[n.words]
		if !ok {
			t.Fatalf("unexpected near-miss length %+v", n)
		}
		delete(wantGaps, n.words)
		if len(n.gaps) != 1 || n.gaps[0] != want[0] {
			t.Errorf("length %d gaps = %v, want %v", n.words, n.gaps, want)
		}
		if n.typo[0] != 0 || n.validating[0] != 0 {
			t.Errorf("length %d typo/validating = %v/%v, want [0]/[0]", n.words, n.typo, n.validating)
		}
	}
	if len(unordered) != 0 {
		t.Fatalf("unordered = %+v, want none", unordered)
	}
}
