package detector

import (
	"crypto/sha256"
	_ "embed"
	"strings"
)

//go:embed bip39-english.txt
var bip39WordlistRaw string

var bip39WordIndex = func() map[string]uint16 {
	words := strings.Split(strings.TrimSpace(bip39WordlistRaw), "\n")
	m := make(map[string]uint16, len(words))
	for i, w := range words {
		m[w] = uint16(i)
	}
	return m
}()

// bip39MaxSpan bounds the byte length of a reported seed phrase. Phrases
// within the span always fit the block overlap window, which keeps the
// exactly-once reporting rule intact; wider-spaced phrases are out of scope.
const bip39MaxSpan = 511

var bip39Lengths = []int{12, 15, 18, 21, 24}

type bip39Match struct {
	words    int   // phrase length in words
	startAbs int64 // absolute offset of the first word
	endAbs   int64 // absolute offset just past the last word
}

// findBIP39 returns every checksum-valid seed phrase fully contained in data.
// baseAbs is the absolute offset of data[0]. first/final describe whether the
// data starts/ends the target: otherwise a leading/trailing letter run may be
// a word fragment split across the edge and is excluded (a phrase using it is
// evaluated whole in the neighboring block instead).
func findBIP39(data []byte, baseAbs int64, first, final bool) []bip39Match {
	data, off := trimEdgeFragments(data, first, final, isBIP39Letter)
	baseAbs += int64(off)

	tokens := tokenizeBIP39(data)
	var matches []bip39Match
	for _, run := range validRuns(tokens) {
		for i := range run {
			for _, length := range bip39Lengths {
				if i+length > len(run) {
					break
				}
				seq := run[i : i+length]
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
				matches = append(matches, bip39Match{
					words:    length,
					startAbs: baseAbs + int64(seq[0].start),
					endAbs:   baseAbs + int64(seq[length-1].end),
				})
			}
		}
	}
	return matches
}

type bip39Token struct {
	index uint16
	valid bool
	start int // offsets within the tokenized data
	end   int
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

// validRuns splits tokens into maximal runs of consecutive wordlist words;
// anything else breaks a candidate phrase.
func validRuns(tokens []bip39Token) [][]bip39Token {
	var runs [][]bip39Token
	for i := 0; i < len(tokens); {
		if !tokens[i].valid {
			i++
			continue
		}
		j := i
		for j < len(tokens) && tokens[j].valid {
			j++
		}
		runs = append(runs, tokens[i:j])
		i = j
	}
	return runs
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
