package detector

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	_ "embed"
	"encoding/hex"
	"strings"
)

// Electrum wallet detection: new-style seeds (HMAC version check) and wallet
// JSON files (seed_version + wallet_type co-occurrence).
//
// Old-style Electrum seeds are out of scope: they use a different 1626-word
// list and Electrum's own legacy check is deliberately weak, so a scanner
// cannot validate them without noise.
//
// Only labels and positions leave this module; seed words ride along
// transiently for --reveal, exactly like BIP39 phrases.

//go:embed electrum-english.txt
var electrumWordlistRaw string

var electrumWords = splitWordlist(electrumWordlistRaw)

var electrumWordIndex = func() map[string]bool {
	m := make(map[string]bool, len(electrumWords))
	for _, w := range electrumWords {
		m[w] = true
	}
	return m
}()

// electrumSeedPrefixes are the new-seed version prefixes from
// electrum/version.py: standard, segwit, 2fa, 2fa_segwit. The 2fa prefix
// additionally constrains word count, which a 12-word window satisfies.
var electrumSeedPrefixes = []string{"01", "100", "101", "102"}

// electrumMaxSpan bounds a 12-word seed (words are at most 8 letters).
const electrumMaxSpan = 12 * 9

// electrumFileMaxSpan bounds the seed_version/wallet_type co-occurrence
// window. Wallet files pretty-print with the keys near each other; huge
// address arrays between them are out of scope. It must stay below the
// block size: the overlap window cannot exceed one block.
const electrumFileMaxSpan = 2048

type electrumSeedMatch struct {
	seedType         string
	startAbs, endAbs int64
	phrase           []string // word strings for --reveal; never serialized otherwise
}

// electrumVersion returns the hex seed-version of a joined phrase.
func electrumVersion(phrase string) string {
	mac := hmac.New(sha512.New, []byte("Seed version"))
	mac.Write([]byte(phrase))
	return hex.EncodeToString(mac.Sum(nil))
}

// electrumSeedType classifies a 12-word phrase, or "" when it validates as
// no Electrum seed type. Matching mirrors Electrum's calc_seed_type for
// 12-word inputs (old-seed forms cannot occur: old seeds use another list).
func electrumSeedType(phrase []string) string {
	v := electrumVersion(strings.Join(phrase, " "))
	types := []string{"standard", "segwit", "2fa", "2fa_segwit"}
	for i, p := range electrumSeedPrefixes {
		if strings.HasPrefix(v, p) {
			return types[i]
		}
	}
	return ""
}

// findElectrumSeeds returns every 12-word in-list window whose seed version
// matches a known prefix. Edge fragments are handled like seed phrases: a
// window using bytes past the edge is evaluated whole next door instead.
func findElectrumSeeds(data []byte, baseAbs int64, first, final bool) []electrumSeedMatch {
	data, off := trimEdgeFragments(data, first, final, isBIP39Letter)
	baseAbs += int64(off)
	toks := alphaTokens(data)
	var out []electrumSeedMatch
	for i := 0; i+12 <= len(toks); i++ {
		words := make([]string, 12)
		ok := true
		for k := 0; k < 12; k++ {
			w := strings.ToLower(string(data[toks[i+k].start:toks[i+k].end]))
			if !electrumWordIndex[w] {
				ok = false
				break
			}
			words[k] = w
		}
		if !ok {
			continue
		}
		if t := electrumSeedType(words); t != "" {
			out = append(out, electrumSeedMatch{
				seedType: t,
				startAbs: baseAbs + int64(toks[i].start),
				endAbs:   baseAbs + int64(toks[i+11].end),
				phrase:   words,
			})
		}
	}
	return out
}

// suppressedByBIP39 reports whether an electrum window is fully contained
// in a strictly longer exact BIP39 match. With a ~0.5% version-hit rate
// per window, long BIP39 phrases constantly contain validating 12-word
// windows that are near-certainly hitchhikers, not second seeds.
// Identical spans stay genuinely ambiguous and still report both.
func suppressedByBIP39(m electrumSeedMatch, exact []bip39Match) bool {
	for _, e := range exact {
		if e.startAbs <= m.startAbs && m.endAbs <= e.endAbs &&
			e.endAbs-e.startAbs > m.endAbs-m.startAbs {
			return true
		}
	}
	return false
}

// alphaToken is a letter run with byte offsets.
type alphaToken struct {
	start, end int
}

// alphaTokens splits letter runs; callers lowercase before list lookup.
func alphaTokens(data []byte) []alphaToken {
	var out []alphaToken
	for i := 0; i < len(data); {
		if !isBIP39Letter(data[i]) {
			i++
			continue
		}
		j := i + 1
		for j < len(data) && isBIP39Letter(data[j]) {
			j++
		}
		out = append(out, alphaToken{i, j})
		i = j
	}
	return out
}

type electrumFileMatch struct {
	startAbs, endAbs int64
}

var electrumSeedVersionKey = []byte(`"seed_version"`)
var electrumWalletTypeKey = []byte(`"wallet_type"`)

// findElectrumFiles returns spans where "seed_version" (numeric value) and
// "wallet_type" (quoted value) co-occur within electrumFileMaxSpan. Full
// wallets can be megabytes, so the validator checks the two keys and their
// value shapes instead of parsing the whole file.
func findElectrumFiles(data []byte, baseAbs int64, first, final bool) []electrumFileMatch {
	_ = first
	_ = final
	var out []electrumFileMatch
	for i := 0; i+len(electrumSeedVersionKey) <= len(data); {
		j := bytes.Index(data[i:], electrumSeedVersionKey)
		if j == -1 {
			break
		}
		anchor := i + j
		valEnd, ok := jsonNumberValue(data, anchor+len(electrumSeedVersionKey))
		if !ok {
			i = anchor + 1
			continue
		}
		if s, e, ok := electrumFileSpan(data, anchor, valEnd); ok {
			out = append(out, electrumFileMatch{baseAbs + int64(s), baseAbs + int64(e)})
		}
		i = anchor + 1
	}
	return out
}

// electrumFileSpan finds a wallet_type key near the seed_version anchor and
// returns the span covering both, or false.
func electrumFileSpan(data []byte, anchor, valEnd int) (int, int, bool) {
	lo := anchor - electrumFileMaxSpan
	if lo < 0 {
		lo = 0
	}
	hi := anchor + electrumFileMaxSpan
	if hi > len(data) {
		hi = len(data)
	}
	window := data[lo:hi]
	k := bytes.Index(window, electrumWalletTypeKey)
	if k == -1 {
		return 0, 0, false
	}
	wvEnd, ok := jsonStringValue(data, lo+k+len(electrumWalletTypeKey))
	if !ok {
		return 0, 0, false
	}
	start, end := anchor, valEnd
	if lo+k < start {
		start = lo + k
	}
	if wvEnd > end {
		end = wvEnd
	}
	// Include the enclosing object opener when it sits just before.
	for s := start - 1; s >= 0 && start-s < 64; s-- {
		if data[s] == '{' {
			start = s
			break
		}
		if data[s] != ' ' && data[s] != '\t' && data[s] != '\n' && data[s] != '\r' && data[s] != ',' {
			break
		}
	}
	return start, end, true
}

// jsonNumberValue parses optional whitespace, a colon, optional whitespace,
// and a JSON number at data[pos:], returning the offset just past it.
func jsonNumberValue(data []byte, pos int) (int, bool) {
	p := skipJSONSpace(data, pos)
	if p >= len(data) || data[p] != ':' {
		return 0, false
	}
	p = skipJSONSpace(data, p+1)
	start := p
	if p < len(data) && (data[p] == '-' || data[p] == '+') {
		p++
	}
	for p < len(data) && data[p] >= '0' && data[p] <= '9' {
		p++
	}
	if p == start {
		return 0, false
	}
	if p-start > 4 {
		return 0, false // seed versions are small; longer is something else
	}
	return p, true
}

// jsonStringValue parses optional whitespace, a colon, optional whitespace,
// and a quoted string at data[pos:], returning the offset just past the
// closing quote.
func jsonStringValue(data []byte, pos int) (int, bool) {
	p := skipJSONSpace(data, pos)
	if p >= len(data) || data[p] != ':' {
		return 0, false
	}
	p = skipJSONSpace(data, p+1)
	if p >= len(data) || data[p] != '"' {
		return 0, false
	}
	strStart := p + 1
	p++
	escaped := false
	for ; p < len(data); p++ {
		if escaped {
			escaped = false
			continue
		}
		if data[p] == '\\' {
			escaped = true
			continue
		}
		if data[p] == '"' {
			if p-strStart > 64 {
				return 0, false
			}
			return p + 1, true
		}
	}
	return 0, false
}

func skipJSONSpace(data []byte, pos int) int {
	for pos < len(data) {
		if c := data[pos]; c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			pos++
			continue
		}
		break
	}
	return pos
}
