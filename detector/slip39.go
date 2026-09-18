package detector

import (
	_ "embed"
	"errors"
	"strings"
)

// SLIP39 Shamir share detection. Shares are 20-word (128-bit) or 33-word
// (256-bit) mnemonics from a 1024-word list with an RS1024 checksum over
// GF(1024) — the 1-in-a-billion checksum plus group-parameter sanity keeps
// prose silent. Only 20/33-word lengths scan: every implementation MUST
// support those, and anything else is vanishingly rare.
//
// Only labels and positions leave this module; share words ride along
// transiently for --reveal, exactly like BIP39 phrases.

//go:embed slip39-words.txt
var slip39WordlistRaw string

var slip39Words = strings.Split(strings.TrimSpace(slip39WordlistRaw), "\n")

var slip39WordIndex = func() map[string]int {
	m := make(map[string]int, len(slip39Words))
	for i, w := range slip39Words {
		m[w] = i
	}
	return m
}()

// slip39Lengths are the scanned share lengths in words.
var slip39Lengths = []int{20, 33}

// slip39MaxSpan bounds a 33-word share (words are at most 8 letters).
const slip39MaxSpan = 33 * 9

// rs1024 generators (SLIP39 checksum section).
var rs1024Gen = []uint32{
	0xe0e040, 0x1c1c080, 0x3838100, 0x7070200, 0xe0e0009,
	0x1c0c2412, 0x38086c24, 0x3090fc48, 0x21b1f890, 0x3f3f120,
}

func rs1024Polymod(values []uint32) uint32 {
	var chk uint32 = 1
	for _, v := range values {
		b := chk >> 20
		chk = ((chk & 0xfffff) << 10) ^ v
		for i := 0; i < 10; i++ {
			if (b>>i)&1 != 0 {
				chk ^= rs1024Gen[i]
			}
		}
	}
	return chk
}

// validSLIP39 enforces share validity: supported length, in-list words,
// group-threshold sanity, and the RS1024 checksum with the customization
// string the extendable flag selects.
func validSLIP39(words []string) error {
	if len(words) != 20 && len(words) != 33 {
		return errors.New("unsupported length")
	}
	idx := make([]uint32, len(words))
	for i, w := range words {
		v, ok := slip39WordIndex[w]
		if !ok {
			return errors.New("word not in list")
		}
		idx[i] = uint32(v)
	}
	// Layout: id[15] ext[1] e[4] GI[4] Gt[4] g[4] I[4] t[4] ps C[30].
	ext := (idx[1] >> 4) & 1
	gt := (idx[2] >> 2) & 15
	g := ((idx[2] & 3) << 2) | (idx[3] >> 8)
	if gt > g {
		return errors.New("group threshold exceeds group count")
	}
	cs := "shamir"
	if ext == 1 {
		cs = "shamir_extendable"
	}
	values := make([]uint32, 0, len(cs)+len(idx))
	for i := 0; i < len(cs); i++ {
		values = append(values, uint32(cs[i]))
	}
	values = append(values, idx...)
	if rs1024Polymod(values) != 1 {
		return errors.New("bad checksum")
	}
	return nil
}

type slip39Match struct {
	words            int
	startAbs, endAbs int64
	phrase           []string // word strings for --reveal; never serialized otherwise
}

// findSLIP39 returns every validating 20/33-word in-list window fully
// contained in data. Edge fragments are handled like seed phrases.
func findSLIP39(data []byte, baseAbs int64, first, final bool) []slip39Match {
	data, off := trimEdgeFragments(data, first, final, isBIP39Letter)
	baseAbs += int64(off)
	toks := alphaTokens(data)
	indexed := make([]int, len(toks))
	for i, t := range toks {
		v, ok := slip39WordIndex[strings.ToLower(string(data[t.start:t.end]))]
		if !ok {
			indexed[i] = -1
			continue
		}
		indexed[i] = v
	}
	var out []slip39Match
	for _, n := range slip39Lengths {
		for i := 0; i+n <= len(toks); i++ {
			words := make([]string, n)
			ok := true
			for k := 0; k < n; k++ {
				if indexed[i+k] < 0 {
					ok = false
					break
				}
				words[k] = slip39Words[indexed[i+k]]
			}
			if !ok {
				continue
			}
			if validSLIP39(words) != nil {
				continue
			}
			out = append(out, slip39Match{
				words:    n,
				startAbs: baseAbs + int64(toks[i].start),
				endAbs:   baseAbs + int64(toks[i+n-1].end),
				phrase:   words,
			})
		}
	}
	return out
}
