package detector

// Seed-completion tests (Goal 32): checksum-gated enumeration of 1–2
// missing words, most-likely-first ordering, "did you mean" correction,
// loud refusal past 2 missing, and the seed→watch-only handoff.
//
// Known-answer vectors come from the independent pure-stdlib oracle
// /tmp/seedvec.py (BIP39 checksum reimplemented from the spec, brute
// force in wordlist order; PBKDF2 cross-checked hashlib vs manual HMAC
// loop; BIP32 chain verified against the in-repo hardcoded xprv and
// Go/Python EC cross-check). This file asserts the oracle's numbers —
// never the implementation's own assumptions.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Oracle phrases: fixed entropy per length (12-word is the official BIP39
// zero-entropy vector abandon x11 + about).
var seedOraclePhrases = map[int]string{
	12: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
	15: "abandon amount liar amount expire adjust cage candy arch gather drum bullet absurd math exhibit",
	18: "absurd document sheriff demise dress october topic angry exact priority boat stay bleak divert boss raw option below",
	21: "agree movie slam income gown rabbit remove extend net aspect puzzle museum funny jewel usual carpet case limit family put document",
	24: "add acid final upset enrich trash promote again drastic winner chapter horror disease alley poverty uncle light volume wage tuition carry plate plastic shed",
}

// Gap token for order-sensitive tests: 13 letters, so every wordlist word
// is past typo range and all candidates tie — enumeration must fall back
// to wordlist order, exactly the oracle's order.
const seedOracleGap = "zzzzzzzzzzzzz"

func seedOracleWords(t *testing.T, length, pos int) []string {
	t.Helper()
	words := strings.Split(seedOraclePhrases[length], " ")
	if len(words) != length {
		t.Fatalf("oracle phrase length %d = %d words, want %d", length, len(words), length)
	}
	words[pos] = seedOracleGap
	return words
}

// TestCompleteSeedKnownAnswer1Missing checks every length at first, middle,
// and checksum-word (last) positions against the oracle: exact total,
// oracle wordlist-order edges, and the original word as a member.
func TestCompleteSeedKnownAnswer1Missing(t *testing.T) {
	cases := []struct {
		length      int
		pos         int
		total       int
		orig        string
		first, last []string
	}{
		{12, 0, 133, "abandon", []string{"abandon", "abstract", "account"}, []string{"weather", "wheat", "yard"}},
		{12, 6, 135, "abandon", []string{"abandon", "above", "adjust"}, []string{"whisper", "width", "wood"}},
		{12, 11, 128, "about", []string{"about", "actual", "age"}, []string{"wife", "world", "wrap"}},
		{15, 0, 74, "abandon", []string{"abandon", "afford", "alpha"}, []string{"voyage", "wet", "wisdom"}},
		{15, 7, 77, "candy", []string{"acquire", "alone", "angle"}, []string{"travel", "tribe", "wealth"}},
		{15, 14, 64, "exhibit", []string{"admit", "aisle", "animal"}, []string{"wasp", "weekend", "winter"}},
		{18, 0, 33, "absurd", []string{"absurd", "access", "author"}, []string{"stereo", "surround", "tape"}},
		{18, 9, 37, "priority", []string{"aim", "amount", "artist"}, []string{"tattoo", "tortoise", "wrist"}},
		{18, 17, 32, "below", []string{"absent", "artefact", "below"}, []string{"trim", "volume", "wrestle"}},
		{21, 0, 16, "agree", []string{"age", "agree", "cloth"}, []string{"popular", "sight", "sustain"}},
		{21, 10, 19, "puzzle", []string{"alley", "bleak", "bulk"}, []string{"traffic", "truth", "vault"}},
		{21, 20, 16, "document", []string{"already", "brass", "clean"}, []string{"surround", "tomato", "venture"}},
		{24, 0, 5, "add", []string{"add", "category", "fall"}, []string{"fall", "random", "undo"}},
		{24, 12, 12, "disease", []string{"awake", "brain", "cherry"}, []string{"piano", "traffic", "trouble"}},
		{24, 23, 8, "shed", []string{"acquire", "ceiling", "end"}, []string{"satisfy", "shed", "toward"}},
	}
	for _, c := range cases {
		res, err := CompleteSeed(seedOracleWords(t, c.length, c.pos), 1000)
		if err != nil {
			t.Errorf("L=%d pos=%d: %s", c.length, c.pos, err)
			continue
		}
		if res.Total != c.total {
			t.Errorf("L=%d pos=%d: total %d, want oracle %d", c.length, c.pos, res.Total, c.total)
		}
		if len(res.Shown) != c.total || res.Truncated {
			t.Errorf("L=%d pos=%d: shown %d truncated=%v, want all %d",
				c.length, c.pos, len(res.Shown), res.Truncated, c.total)
		}
		fills := make([]string, len(res.Shown))
		for i, s := range res.Shown {
			fills[i] = s.Fill[0]
		}
		for i, w := range c.first {
			if fills[i] != w {
				t.Errorf("L=%d pos=%d: first[%d] = %q, want oracle %q", c.length, c.pos, i, fills[i], w)
			}
		}
		for i, w := range c.last {
			if got := fills[len(fills)-len(c.last)+i]; got != w {
				t.Errorf("L=%d pos=%d: last[%d] = %q, want oracle %q", c.length, c.pos, i, got, w)
			}
		}
		found := false
		for _, f := range fills {
			if f == c.orig {
				found = true
			}
		}
		if !found {
			t.Errorf("L=%d pos=%d: original word %q not among completions", c.length, c.pos, c.orig)
		}
		// Every shown completion must be a full checksum-valid phrase.
		for _, s := range res.Shown {
			if len(s.Words) != c.length || s.Words[c.pos] != s.Fill[0] {
				t.Errorf("L=%d pos=%d: malformed completion %+v", c.length, c.pos, s)
				break
			}
			idx := make([]uint16, c.length)
			for i, w := range s.Words {
				idx[i] = bip39WordIndex[w]
			}
			if !bip39ChecksumValid(idx) {
				t.Errorf("L=%d pos=%d: completion fails checksum: %v", c.length, c.pos, s.Words)
				break
			}
		}
	}
}

// TestCompleteSeedFullSet24 pins the entire completion sets (not just
// edges) for the small 24-word cases.
func TestCompleteSeedFullSet24(t *testing.T) {
	cases := map[int][]string{
		0:  {"add", "category", "fall", "random", "undo"},
		12: {"awake", "brain", "cherry", "disease", "excuse", "grunt", "item", "maximum", "pass", "piano", "traffic", "trouble"},
		23: {"acquire", "ceiling", "end", "kiwi", "life", "satisfy", "shed", "toward"},
	}
	for pos, want := range cases {
		res, err := CompleteSeed(seedOracleWords(t, 24, pos), 1000)
		if err != nil {
			t.Fatalf("pos=%d: %s", pos, err)
		}
		if len(res.Shown) != len(want) {
			t.Fatalf("pos=%d: %d completions, want oracle %d", pos, len(res.Shown), len(want))
		}
		for i, s := range res.Shown {
			if s.Fill[0] != want[i] {
				t.Errorf("pos=%d fill[%d] = %q, want oracle %q", pos, i, s.Fill[0], want[i])
			}
		}
	}
}

// TestCompleteSeedKnownAnswer2Missing checks two-gap enumeration against
// the oracle at every length: exact totals (4M tries each — the "still
// fast" claim) and wordlist-ordered heads. Placements cover adjacent
// interior gaps, edges, and the checksum word. Note the totals with a
// checksum-word gap are exactly 4M/2^csbits (not statistical): the last
// word holds the final entropy bits plus all checksum bits, so each
// fixed partner word admits exactly 2^(11-csbits) last words.
func TestCompleteSeedKnownAnswer2Missing(t *testing.T) {
	cases := []struct {
		length int
		gaps   [2]int
		total  int
		first  [][2]string
	}{
		{12, [2]int{0, 11}, 262144,
			[][2]string{{"abandon", "about"}, {"abandon", "actual"}, {"abandon", "age"}}},
		{12, [2]int{5, 6}, 262001,
			[][2]string{{"abandon", "abandon"}, {"abandon", "above"}, {"abandon", "adjust"}}},
		{15, [2]int{0, 14}, 131072,
			[][2]string{{"abandon", "admit"}, {"abandon", "aisle"}, {"abandon", "animal"}}},
		{18, [2]int{4, 13}, 65624,
			[][2]string{{"abandon", "arrange"}, {"abandon", "ask"}, {"abandon", "bottom"}}},
		{21, [2]int{10, 20}, 32768,
			[][2]string{{"abandon", "angry"}, {"abandon", "bar"}, {"abandon", "cargo"}}},
		{24, [2]int{0, 23}, 16384,
			[][2]string{{"abandon", "boat"}, {"abandon", "claim"}, {"abandon", "entire"}}},
	}
	for _, c := range cases {
		words := strings.Split(seedOraclePhrases[c.length], " ")
		words[c.gaps[0]], words[c.gaps[1]] = seedOracleGap, seedOracleGap
		res, err := CompleteSeed(words, 128)
		if err != nil {
			t.Errorf("L=%d gaps=%v: %s", c.length, c.gaps, err)
			continue
		}
		if res.Total != c.total {
			t.Errorf("L=%d gaps=%v: total %d, want oracle %d", c.length, c.gaps, res.Total, c.total)
		}
		if !res.Truncated || len(res.Shown) != 128 {
			t.Errorf("L=%d gaps=%v: shown %d truncated=%v, want 128 + truncated",
				c.length, c.gaps, len(res.Shown), res.Truncated)
		}
		for i, want := range c.first {
			if res.Shown[i].Fill[0] != want[0] || res.Shown[i].Fill[1] != want[1] {
				t.Errorf("L=%d gaps=%v: shown[%d] = %v, want oracle %v",
					c.length, c.gaps, i, res.Shown[i].Fill, want)
			}
		}
		// Garbage gaps all tie on score, so the head must run in
		// (gap0, gap1) wordlist order.
		prev0, prev1 := -1, -1
		for _, s := range res.Shown {
			i0, i1 := int(bip39WordIndex[s.Fill[0]]), int(bip39WordIndex[s.Fill[1]])
			if i0 < prev0 || (i0 == prev0 && i1 < prev1) {
				t.Errorf("L=%d gaps=%v: head not in wordlist order at %v", c.length, c.gaps, s.Fill)
				break
			}
			prev0, prev1 = i0, i1
		}
	}
	// Original-pair membership: the L12 oracle heads both lists with
	// the restored pair, so the capped head proves it there; 1-gap
	// tests prove restorability at every other length.
	words := strings.Split(seedOraclePhrases[12], " ")
	words[0], words[11] = seedOracleGap, seedOracleGap
	res, err := CompleteSeed(words, 1)
	if err != nil {
		t.Fatal(err)
	}
	if res.Shown[0].Fill[0] != "abandon" || res.Shown[0].Fill[1] != "about" {
		t.Errorf("L=12 head %v is not the original pair", res.Shown[0].Fill)
	}
}

// TestCompleteSeedMostLikelyFirst proves typo-near candidates sort before
// the rest: "abandonn" (d=1 from abandon, the only word within d=2) must
// head the list with the restored phrase.
func TestCompleteSeedMostLikelyFirst(t *testing.T) {
	words := strings.Split(seedOraclePhrases[12], " ")
	words[0] = "abandonn"
	res, err := CompleteSeed(words, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 133 { // oracle count for L=12 pos=0 (gap token independent)
		t.Errorf("total %d, want oracle 133", res.Total)
	}
	if len(res.Shown) == 0 || res.Shown[0].Fill[0] != "abandon" {
		t.Fatalf("head = %+v, want fill abandon", res.Shown)
	}
	if res.Shown[0].Score != 1 {
		t.Errorf("head score %d, want 1", res.Shown[0].Score)
	}
	if got := strings.Join(res.Shown[0].Words, " "); got != seedOraclePhrases[12] {
		t.Errorf("head restores %q, want the oracle phrase", got)
	}
	for i := 1; i < len(res.Shown); i++ {
		if res.Shown[i].Score < res.Shown[i-1].Score {
			t.Errorf("score drops at %d: %d after %d", i, res.Shown[i].Score, res.Shown[i-1].Score)
			break
		}
	}
}

// TestDidYouMean checks the near-miss correction shape: typo gaps get
// "did you mean" suggestions (validating neighbors, most-likely first);
// garbage gaps get none.
func TestDidYouMean(t *testing.T) {
	words := strings.Split(seedOraclePhrases[12], " ")
	words[0] = "abandonn"
	res, err := CompleteSeed(words, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Corrections) != 1 {
		t.Fatalf("corrections = %+v, want one gap", res.Corrections)
	}
	c := res.Corrections[0]
	if c.Position != 0 || c.Token != "abandonn" {
		t.Errorf("correction targets %+v, want pos 0 token abandonn", c)
	}
	if len(c.Suggest) == 0 || c.Suggest[0] != "abandon" {
		t.Errorf("suggest = %v, want abandon first", c.Suggest)
	}
	garbage := seedOracleWords(t, 12, 11)
	res, err = CompleteSeed(garbage, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Corrections) != 0 {
		t.Errorf("garbage gap corrections = %+v, want none", res.Corrections)
	}
}

// TestCompleteSeedRefusals pins the loud guardrails: 3+ missing words
// refuse with the BTCRecover/GPU pointer (never a partial enumeration),
// bad lengths refuse, and a complete phrase validates or errors.
func TestCompleteSeedRefusals(t *testing.T) {
	words := strings.Split(seedOraclePhrases[12], " ")
	words[0], words[1], words[2] = seedOracleGap, seedOracleGap, seedOracleGap
	_, err := CompleteSeed(words, 0)
	if err == nil {
		t.Fatal("3 missing words must refuse")
	}
	for _, want := range []string{"BTCRecover", "GPU", "8,589,934,592"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal lacks %q: %s", want, err)
		}
	}
	words24 := strings.Split(seedOraclePhrases[24], " ")
	for _, pos := range []int{0, 1, 2, 3} {
		words24[pos] = seedOracleGap
	}
	if _, err := CompleteSeed(words24, 0); err == nil {
		t.Error("4 missing words must refuse")
	}
	for _, n := range []int{11, 13, 23, 25} {
		bad := make([]string, n)
		for i := range bad {
			bad[i] = "abandon"
		}
		if _, err := CompleteSeed(bad, 0); err == nil {
			t.Errorf("%d-word input must refuse (not a seed length)", n)
		}
	}
	exact := strings.Split(seedOraclePhrases[12], " ")
	res, err := CompleteSeed(exact, 0)
	if err != nil {
		t.Errorf("complete valid phrase: %s", err)
	} else if res.Total != 1 || len(res.Shown) != 1 {
		t.Errorf("complete valid phrase: total %d shown %d, want 1 self-completion",
			res.Total, len(res.Shown))
	}
	broken := strings.Split(seedOraclePhrases[12], " ")
	broken[0] = "zoo" // valid word, breaks the checksum
	if _, err := CompleteSeed(broken, 0); err == nil {
		t.Error("complete invalid phrase must error, not self-complete")
	}
}

// TestCompleteSeedDeterminism runs the same input twice: identical order.
func TestCompleteSeedDeterminism(t *testing.T) {
	words := seedOracleWords(t, 15, 7)
	a, err := CompleteSeed(words, 1000)
	if err != nil {
		t.Fatal(err)
	}
	b, err := CompleteSeed(words, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if a.Total != b.Total || len(a.Shown) != len(b.Shown) {
		t.Fatalf("totals %d/%d shown %d/%d", a.Total, b.Total, len(a.Shown), len(b.Shown))
	}
	for i := range a.Shown {
		if a.Shown[i].Fill[0] != b.Shown[i].Fill[0] {
			t.Fatalf("position %d differs: %q vs %q", i, a.Shown[i].Fill, b.Shown[i].Fill)
		}
	}
}

// TestCompleteMaxCap pins truncation: shown caps at max, total stays
// exact, and absurd max values clamp to the hard cap.
func TestCompleteMaxCap(t *testing.T) {
	words := seedOracleWords(t, 12, 0)
	res, err := CompleteSeed(words, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Shown) != 10 || res.Total != 133 || !res.Truncated {
		t.Errorf("shown %d total %d truncated=%v, want 10/133/true",
			len(res.Shown), res.Total, res.Truncated)
	}
	res, err = CompleteSeed(words, CompleteHardMax+1)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Shown) != 133 || res.Truncated {
		t.Errorf("uncapped small set: shown %d truncated=%v, want 133/false",
			len(res.Shown), res.Truncated)
	}
}

// TestSeedToAccountsOracle pins the watch-only handoff: the abandon×11 +
// about mnemonic must derive the three mainnet account keys
// (m/44'/0'/0' xpub, m/49'/0'/0' ypub, m/84'/0'/0' zpub). Three
// independent implementations agree on these bytes: btcsuite (the
// watch_test.go constants, derived from the same mnemonic), the fixed
// pure-Python oracle (child number 0' = 0x80000000, not 0 — the first
// oracle draft got this wrong and the mismatch caught it), and the Go
// code under test.
func TestSeedToAccountsOracle(t *testing.T) {
	mn := strings.Split(seedOraclePhrases[12], " ")
	accts, err := SeedToAccounts(mn)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"XPub44": "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj",
		"YPub49": "ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP",
		"ZPub84": "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
	}
	got := map[string]string{"XPub44": accts.XPub44, "YPub49": accts.YPub49, "ZPub84": accts.ZPub84}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s:\n got %s\nwant %s", k, got[k], w)
		}
		// Each handoff key must parse under the existing watch-only
		// parser and derive script-correct addresses through the
		// existing flow (no copy-paste, no forked derivation).
		x, err := ParseXPub(got[k])
		if err != nil {
			t.Errorf("%s does not parse: %s", k, err)
			continue
		}
		entries, err := CollectWatchAddrs([]string{got[k]}, 1)
		if err != nil {
			t.Errorf("%s does not derive: %s", k, err)
			continue
		}
		if len(entries) != 2 || entries[0].Script != x.Script {
			t.Errorf("%s: %d entries script %q", k, len(entries), entries[0].Script)
		}
	}
	if fp := mustParseXPub(t, got["XPub44"]).Fingerprint(); fp != "6cc9f252" {
		t.Errorf("account fingerprint %s, want oracle 6cc9f252", fp)
	}
}

// TestSeedToAccountsRefusesInvalid pins the guard: no derivation from a
// checksum-broken phrase, wrong length, or unknown word.
func TestSeedToAccountsRefusesInvalid(t *testing.T) {
	broken := strings.Split(seedOraclePhrases[12], " ")
	broken[0] = "zoo"
	if _, err := SeedToAccounts(broken); err == nil {
		t.Error("broken checksum must refuse")
	}
	if _, err := SeedToAccounts(broken[:11]); err == nil {
		t.Error("11 words must refuse")
	}
	unknown := strings.Split(seedOraclePhrases[12], " ")
	unknown[5] = "notaword"
	if _, err := SeedToAccounts(unknown); err == nil {
		t.Error("unknown word must refuse")
	}
}

// TestSeedCompleteWarningText pins the anti-scam box + local-terminal
// warning that travels with every completion run.
func TestSeedCompleteWarningText(t *testing.T) {
	w := SeedCompleteWarning()
	for _, want := range []string{
		"never send", "seed", "anyone", "offline", "local terminal",
		"never transmitted", "--reveal",
	} {
		if !strings.Contains(strings.ToLower(w), strings.ToLower(want)) {
			t.Errorf("warning lacks %q:\n%s", want, w)
		}
	}
}

// TestNoNewNetImports is the Goal 32 network guard: only the explicit
// opt-in balance client (watch.go) may import network packages. New
// completion code must stay offline — this fails the build if a net
// import appears anywhere else.
func TestNoNewNetImports(t *testing.T) {
	allowed := map[string]bool{"watch.go": true}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no go files found")
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			if strings.Contains(trimmed, `"net/`) || trimmed == `"net"` {
				if !allowed[f] {
					t.Errorf("%s imports network package: %s (only watch.go may)", f, trimmed)
				}
			}
		}
	}
}

// TestReportPointsAtSeedCompletion pins the -report follow-up pointer:
// near-miss hits advertise the offline completion path.
func TestReportPointsAtSeedCompletion(t *testing.T) {
	rep := Summarize([]Detection{reportFixtureDetection("bip39-12-near-miss", "/dev/sda", 10)})
	joined := strings.Join(rep.Playbook, "\n")
	if !strings.Contains(joined, "-complete") {
		t.Errorf("near-miss playbook lacks the -complete pointer:\n%s", joined)
	}
	exact := Summarize([]Detection{reportFixtureDetection("bip39-12", "/dev/sda", 10)})
	if strings.Contains(strings.Join(exact.Playbook, "\n"), "-complete") {
		t.Errorf("exact-seed playbook must not advertise -complete:\n%s",
			strings.Join(exact.Playbook, "\n"))
	}
}
