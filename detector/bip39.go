package detector

import (
	"crypto/sha256"
	_ "embed"
	"fmt"
	"strings"
)

//go:embed bip39-english.txt
var bip39WordlistRaw string

var bip39Words = strings.Split(strings.TrimSpace(bip39WordlistRaw), "\n")

var bip39WordIndex = func() map[string]uint16 {
	m := make(map[string]uint16, len(bip39Words))
	for i, w := range bip39Words {
		m[w] = uint16(i)
	}
	return m
}()

// bip39MaxSpan bounds the byte length of a reported seed phrase. Phrases
// within the span always fit the block overlap window, which keeps the
// exactly-once reporting rule intact; wider-spaced phrases are out of scope.
const bip39MaxSpan = 511

var bip39Lengths = []int{12, 15, 18, 21, 24}

// Near-miss (fuzzy) detection: windows that look like seed phrases with
// something wrong — missing words, typos, or scrambled order. Realistic
// recovery input is almost never a perfect phrase, so the exact detector
// alone misses the recoverable cases.
//
// Three confidences, highest first:
//
//   - exact: every word valid, checksum verifies (existing behavior).
//   - near-miss: 1–2 unknown tokens among valid words. Gaps, typo
//     candidates, and checksum-validating candidates are counted per gap.
//   - unordered: 12+ consecutive valid words with no validating window —
//     a stored phrase in the wrong order, or prose that happens to qualify.
//     Reported once per run, never per window.
//
// Deliberately absent: solving reorder by permutation search. For 12 known
// words ~1/16 of all 12! orders validate the 4-bit checksum, so any swap
// "solution" a scanner finds is one of millions — pure noise. Ordering
// search belongs in BTCRecover; the scanner reports the location.
//
// Privacy: only labels, positions, and counts leave this module. Word
// strings ride along transiently for --reveal and never serialize otherwise.
const (
	// bip39MaxUnknown caps unknown tokens per near-miss window.
	bip39MaxUnknown = 2
	// bip39TypoDistance caps the edit distance for typo candidates.
	bip39TypoDistance = 2
	// bip39MaxValidatePerGap caps checksum trials per gap (wordlist-order
	// prefix), bounding two-gap windows to 64*64 trials.
	bip39MaxValidatePerGap = 64
	// bip39MinUnorderedRun is the shortest valid-word run worth an
	// unordered hint.
	bip39MinUnorderedRun = 12
)

type bip39Match struct {
	words    int // phrase length in words
	startAbs int64
	endAbs   int64
	phrase   []string // word strings for --reveal; never serialized otherwise
}

// bip39NearMiss is a phrase-length window with 1–2 unknown tokens. Gaps
// holds the unknown window positions; typo/validating hold per-gap
// candidate counts aligned with gaps.
type bip39NearMiss struct {
	words      int
	startAbs   int64
	endAbs     int64
	gaps       []int
	typo       []int
	validating []int
	phrase     []string // valid words canonical, unknown tokens verbatim
	startTok   int
	endTok     int
}

// bip39Unordered is a maximal run of valid words with no validating window.
type bip39Unordered struct {
	words            int // run length in words
	startAbs         int64
	endAbs           int64
	phrase           []string
	startTok, endTok int
}

// pattern renders the gap report: positions and counts, never words.
func (m bip39NearMiss) pattern() string {
	return fmt.Sprintf("gaps=[%s] typo=[%s] validating=[%s]",
		joinInts(m.gaps), joinInts(m.typo), joinInts(m.validating))
}

func joinInts(ns []int) string {
	var b strings.Builder
	for i, n := range ns {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%d", n)
	}
	return b.String()
}

// findBIP39 returns every checksum-valid seed phrase fully contained in data.
// baseAbs is the absolute offset of data[0]. first/final describe whether the
// data starts/ends the target: otherwise a leading/trailing letter run may be
// a word fragment split across the edge and is excluded (a phrase using it is
// evaluated whole in the neighboring block instead).
func findBIP39(data []byte, baseAbs int64, first, final bool) []bip39Match {
	data, off := trimEdgeFragments(data, first, final, isBIP39Letter)
	baseAbs += int64(off)
	var out []bip39Match
	for _, w := range exactWindows(tokenizeBIP39(data), data, baseAbs) {
		out = append(out, w.match)
	}
	return out
}

// findBIP39Phrases scans once for exact, near-miss, and unordered phrases.
// Precedence is exact, then unordered runs, then near-miss: stronger
// evidence suppresses weaker. Exact derivative windows (all valid words
// inside one exact window) and run barnacles (a valid run plus window
// overhang) are dropped as noise rather than reported twice.
func findBIP39Phrases(data []byte, baseAbs int64, first, final bool) (exact []bip39Match, near []bip39NearMiss, unordered []bip39Unordered) {
	data, off := trimEdgeFragments(data, first, final, isBIP39Letter)
	baseAbs += int64(off)
	tokens := tokenizeBIP39(data)
	exactWin := exactWindows(tokens, data, baseAbs)
	for _, w := range exactWin {
		exact = append(exact, w.match)
	}
	unordered = unorderedRuns(tokens, data, baseAbs, first, exactWin)
	near = nearMissWindows(tokens, data, baseAbs, exactWin, unordered)
	return exact, near, unordered
}

type bip39Token struct {
	index uint16
	valid bool
	start int // offsets within the tokenized data
	end   int
}

// bip39ExactWindow is an exact match plus its token range for overlap tests.
type bip39ExactWindow struct {
	match            bip39Match
	startTok, endTok int
}

// unorderedSuppressedBySeed extends the unordered-run contract — "12+
// consecutive valid words with no validating window" — across wordlists: a
// run containing a validated Electrum or SLIP39 seed reports the seed, not
// the weaker hint. Mirrors the exact-window containment rule in
// unorderedRuns.
func unorderedSuppressedBySeed(u bip39Unordered, electrum []electrumSeedMatch, slip39 []slip39Match) bool {
	for _, m := range electrum {
		if m.startAbs >= u.startAbs && m.endAbs <= u.endAbs {
			return true
		}
	}
	for _, m := range slip39 {
		if m.startAbs >= u.startAbs && m.endAbs <= u.endAbs {
			return true
		}
	}
	return false
}

func isBIP39Letter(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

func tokenizeBIP39(data []byte) []bip39Token {
	var tokens []bip39Token
	var lower [16]byte // longest BIP39 word is 8 letters; anything more is invalid
	for i := 0; i < len(data); {
		if !isBIP39Letter(data[i]) {
			i++
			continue
		}
		start := i
		for i < len(data) && isBIP39Letter(data[i]) {
			i++
		}
		tok := bip39Token{start: start, end: i}
		if n := i - start; n >= 3 && n <= 8 {
			for k := 0; k < n; k++ {
				c := data[start+k]
				if c >= 'A' && c <= 'Z' {
					c += 'a' - 'A'
				}
				lower[k] = c
			}
			if index, ok := bip39WordIndex[string(lower[:n])]; ok {
				tok.index, tok.valid = index, true
			}
		}
		tokens = append(tokens, tok)
	}
	return tokens
}

// tokenRun is a maximal run of consecutive wordlist words with its token offset.
type tokenRun struct {
	toks  []bip39Token
	start int
}

// validRuns splits tokens into maximal runs of wordlist words; anything else
// breaks a candidate phrase.
func validRuns(tokens []bip39Token) []tokenRun {
	var runs []tokenRun
	for i := 0; i < len(tokens); {
		if !tokens[i].valid {
			i++
			continue
		}
		j := i
		for j < len(tokens) && tokens[j].valid {
			j++
		}
		runs = append(runs, tokenRun{toks: tokens[i:j], start: i})
		i = j
	}
	return runs
}

func exactWindows(tokens []bip39Token, data []byte, baseAbs int64) []bip39ExactWindow {
	var out []bip39ExactWindow
	for _, run := range validRuns(tokens) {
		for i := range run.toks {
			for _, length := range bip39Lengths {
				if i+length > len(run.toks) {
					break
				}
				seq := run.toks[i : i+length]
				span := seq[length-1].end - seq[0].start
				if span > bip39MaxSpan {
					break // longer phrases only span more
				}
				indices := make([]uint16, length)
				for k, tok := range seq {
					indices[k] = tok.index
				}
				if !bip39ChecksumValid(indices) {
					continue
				}
				phrase := make([]string, length)
				for k, tok := range seq {
					phrase[k] = bip39Words[tok.index]
				}
				out = append(out, bip39ExactWindow{
					match: bip39Match{
						words:    length,
						startAbs: baseAbs + int64(seq[0].start),
						endAbs:   baseAbs + int64(seq[length-1].end),
						phrase:   phrase,
					},
					startTok: run.start + i,
					endTok:   run.start + i + length,
				})
			}
		}
	}
	return out
}

func nearMissWindows(tokens []bip39Token, data []byte, baseAbs int64, exact []bip39ExactWindow, unordered []bip39Unordered) []bip39NearMiss {
	var out []bip39NearMiss
	seen := map[string]bool{}
	for i := range tokens {
		for _, length := range bip39Lengths {
			if i+length > len(tokens) {
				break
			}
			seq := tokens[i : i+length]
			span := seq[length-1].end - seq[0].start
			if span > bip39MaxSpan {
				break
			}
			var gaps []int
			for k, tok := range seq {
				if !tok.valid {
					gaps = append(gaps, k)
				}
			}
			if len(gaps) == 0 || len(gaps) > bip39MaxUnknown {
				continue
			}
			// Overlapping windows share gap sets; report each once. The mark
			// goes down only for survivors: a dropped window must not claim
			// the gap set and silence a later qualifying one.
			key := fmt.Sprintf("%d:", length)
			for _, g := range gaps {
				key += fmt.Sprintf("%d,", baseAbs+int64(seq[g].start))
			}
			if seen[key] {
				continue
			}
			if coveredByExact(i, length, gaps, exact) {
				continue
			}
			if barnacleWindow(tokens, i, length) {
				continue
			}
			if overlappedByRun(i, i+length, unordered) {
				continue
			}
			seen[key] = true
			typo, validating := gapAnalysis(seq, gaps, data)
			phrase := make([]string, length)
			for k, tok := range seq {
				if tok.valid {
					phrase[k] = bip39Words[tok.index]
				} else {
					phrase[k] = string(data[tok.start:tok.end])
				}
			}
			out = append(out, bip39NearMiss{
				words:      length,
				startAbs:   baseAbs + int64(seq[0].start),
				endAbs:     baseAbs + int64(seq[length-1].end),
				gaps:       gaps,
				typo:       typo,
				validating: validating,
				phrase:     phrase,
				startTok:   i,
				endTok:     i + length,
			})
		}
	}
	return out
}

// coveredByExact reports whether every valid token of a near-miss window
// lies inside a single exact window — i.e. the window is a derivative of a
// reported phrase (exact words plus adjacent junk), not new evidence.
func coveredByExact(start, length int, gaps []int, exact []bip39ExactWindow) bool {
	for _, e := range exact {
		allInside := true
		for p := 0; p < length; p++ {
			gap := false
			for _, g := range gaps {
				if g == p {
					gap = true
					break
				}
			}
			if gap {
				continue
			}
			if start+p < e.startTok || start+p >= e.endTok {
				allInside = false
				break
			}
		}
		if allInside {
			return true
		}
	}
	return false
}

// gapAnalysis counts, per gap, wordlist words within typo distance and the
// subset that validate the window checksum when substituted.
func gapAnalysis(seq []bip39Token, gaps []int, data []byte) (typo, validating []int) {
	base := make([]uint16, len(seq))
	for k, tok := range seq {
		if tok.valid {
			base[k] = tok.index
		}
	}
	cands := make([][]uint16, len(gaps))
	for gi, g := range gaps {
		raw := string(data[seq[g].start:seq[g].end])
		cands[gi] = typoCandidates(raw)
		typo = append(typo, len(cands[gi]))
	}
	return typo, validatingCounts(base, gaps, cands)
}

// typoCandidates returns wordlist words within bip39TypoDistance of token,
// in wordlist order. Tokens longer than 10 bytes short-circuit: the length
// difference alone exceeds the bound.
func typoCandidates(token string) []uint16 {
	token = strings.ToLower(token)
	if len(token) > 10 {
		return nil
	}
	var out []uint16
	for i, w := range bip39Words {
		if len(w) > len(token)+bip39TypoDistance || len(token) > len(w)+bip39TypoDistance {
			continue
		}
		if levenshteinBounded(token, w, bip39TypoDistance) <= bip39TypoDistance {
			out = append(out, uint16(i))
		}
	}
	return out
}

// levenshteinBounded computes edit distance, bailing past bound (returns
// bound+1). Inputs are short lowercase words; plain DP is plenty.
func levenshteinBounded(a, b string, bound int) int {
	if a == b {
		return 0
	}
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr := make([]int, lb+1)
		curr[0] = i
		rowMin := i
		for j := 1; j <= lb; j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			curr[j] = min(prev[j]+1, min(curr[j-1]+1, prev[j-1]+cost))
			if curr[j] < rowMin {
				rowMin = curr[j]
			}
		}
		if rowMin > bound {
			return bound + 1
		}
		prev = curr
	}
	return prev[lb]
}

// validatingCounts counts, per gap, typo candidates that make the window
// checksum-validate when substituted. With two gaps a candidate counts when
// ANY pairing validates. Lists cap at bip39MaxValidatePerGap (wordlist-order
// prefix), bounding work to 64*64 trials per window.
func validatingCounts(base []uint16, gaps []int, cands [][]uint16) []int {
	capped := make([][]uint16, len(cands))
	for i, c := range cands {
		if len(c) > bip39MaxValidatePerGap {
			c = c[:bip39MaxValidatePerGap]
		}
		capped[i] = c
	}
	out := make([]int, len(gaps))
	if len(gaps) == 1 {
		for _, c := range capped[0] {
			indices := make([]uint16, len(base))
			copy(indices, base)
			indices[gaps[0]] = c
			if bip39ChecksumValid(indices) {
				out[0]++
			}
		}
		return out
	}
	if len(gaps) == 2 {
		marked0 := map[uint16]bool{}
		marked1 := map[uint16]bool{}
		for _, c0 := range capped[0] {
			for _, c1 := range capped[1] {
				indices := make([]uint16, len(base))
				copy(indices, base)
				indices[gaps[0]], indices[gaps[1]] = c0, c1
				if bip39ChecksumValid(indices) {
					marked0[c0] = true
					marked1[c1] = true
				}
			}
		}
		out[0], out[1] = len(marked0), len(marked1)
	}
	return out
}

// unorderedRuns reports maximal valid-word runs worth an order-agnostic
// hint: 12+ consecutive wordlist words with no validating window. Runs
// containing an exact match are dropped — the phrase already reported.
// Runs touching the leading trimmed edge are dropped too: they continue
// from the previous block, which reported them (approximately-once
// semantics for cross-block runs).
func unorderedRuns(tokens []bip39Token, data []byte, baseAbs int64, first bool, exact []bip39ExactWindow) []bip39Unordered {
	var out []bip39Unordered
runLoop:
	for _, run := range validRuns(tokens) {
		if len(run.toks) < bip39MinUnorderedRun {
			continue
		}
		if !first && run.toks[0].start == 0 {
			continue
		}
		runStart, runEnd := run.start, run.start+len(run.toks)
		for _, e := range exact {
			if e.startTok >= runStart && e.endTok <= runEnd {
				continue runLoop
			}
		}
		phrase := make([]string, len(run.toks))
		for k, tok := range run.toks {
			phrase[k] = bip39Words[tok.index]
		}
		out = append(out, bip39Unordered{
			words:    len(run.toks),
			startAbs: baseAbs + int64(run.toks[0].start),
			endAbs:   baseAbs + int64(run.toks[len(run.toks)-1].end),
			phrase:   phrase,
			startTok: runStart,
			endTok:   runEnd,
		})
	}
	return out
}

// barnacleWindow drops windows that are a valid run plus window overhang:
// an edge unknown where valid words continue past the far edge. Truly
// truncated phrases (nothing beyond the run) are kept, as are windows with
// interior unknowns. A side effect: a missing word at the very edge of a
// 12+ run is dropped with the barnacle — the unordered hint still points
// at the location.
func barnacleWindow(tokens []bip39Token, start, length int) bool {
	if !tokens[start].valid && start+length < len(tokens) && tokens[start+length].valid {
		return true
	}
	if !tokens[start+length-1].valid && start > 0 && tokens[start-1].valid {
		return true
	}
	return false
}

// overlappedByRun reports whether a token range touches any reported
// unordered run; the run describes the location better than the window.
func overlappedByRun(start, end int, unordered []bip39Unordered) bool {
	for _, u := range unordered {
		if start < u.endTok && end > u.startTok {
			return true
		}
	}
	return false
}

// bip39ChecksumValid implements the BIP39 checksum: the entropy bits are the
// word indices minus the trailing checksum bits, and the checksum must match
// the first bits of SHA256(entropy).
func bip39ChecksumValid(indices []uint16) bool {
	var csBits int
	switch len(indices) {
	case 12:
		csBits = 4
	case 15:
		csBits = 5
	case 18:
		csBits = 6
	case 21:
		csBits = 7
	case 24:
		csBits = 8
	default:
		return false
	}
	totalBits := len(indices) * 11
	entBits := totalBits - csBits
	packed := make([]byte, (totalBits+7)/8)
	for i := 0; i < totalBits; i++ {
		if indices[i/11]>>(10-(i%11))&1 == 1 {
			packed[i/8] |= 1 << (7 - (i % 8))
		}
	}
	sum := sha256.Sum256(packed[:entBits/8])
	for i := 0; i < csBits; i++ {
		have := packed[(entBits+i)/8] >> (7 - ((entBits + i) % 8)) & 1
		want := sum[i/8] >> (7 - (i % 8)) & 1
		if have != want {
			return false
		}
	}
	return true
}
