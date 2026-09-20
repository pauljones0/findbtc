package detector

import (
	"fmt"
	"strings"
)

// BTCRecover tokenlist generation from hit context (Goal 33).
//
// Password cracking fails most often on tokenlist authoring: BTCRecover
// combines whatever tokens it is given, and owners stare at a blank
// tokens.txt. The carves around a hit already hold the most likely parts
// (nearby words), so -tokenlist turns those bytes into a starting
// tokenlist: one line per distinct word, case mutations space-separated
// on the same line (BTCRecover reads same-line tokens as mutually
// exclusive). The owner then trims, anchors, and adds wildcards per
// docs/PASSWORD_RECOVERY.md.

const (
	// TokenlistMaxBytes caps -tokenlist input; larger buffers are
	// refused before extraction instead of ballooning memory.
	TokenlistMaxBytes = 64 << 20
	// TokenlistDefaultMax caps emitted lines; BTCRecover tries every
	// combination up to --max-tokens, so unbounded lines mean
	// unbounded runs. -tokenlist-max overrides up to TokenlistHardMax.
	TokenlistDefaultMax = 256
	TokenlistHardMax    = 100000
	tokenMinLen         = 3
	tokenMaxLen         = 32
)

// TokenlistStats describes one BuildTokenlist call.
type TokenlistStats struct {
	Words     int  // distinct words found
	Lines     int  // lines emitted
	Truncated bool // max cut the output short
}

// ExtractTokenWords returns the distinct runs of ASCII letters/digits in
// data, first-seen order, keeping lengths tokenMinLen..tokenMaxLen.
// Everything else (short fragments, long blobs, non-ASCII) is skipped:
// tokenlists are guesses, and noise only multiplies combinations.
func ExtractTokenWords(data []byte) []string {
	var out []string
	seen := map[string]bool{}
	start := -1
	flush := func(end int) {
		if start < 0 {
			return
		}
		w := string(data[start:end])
		start = -1
		if len(w) < tokenMinLen || len(w) > tokenMaxLen || seen[w] {
			return
		}
		seen[w] = true
		out = append(out, w)
	}
	for i, c := range data {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			if start < 0 {
				start = i
			}
			continue
		}
		flush(i)
	}
	flush(len(data))
	return out
}

// TokenVariants returns a word's case mutations in fixed order —
// original, lower, UPPER, Capitalized — dropping duplicates. Variants of
// one word share a tokenlist line, so BTCRecover never combines a word
// with itself.
func TokenVariants(word string) []string {
	cands := []string{word, strings.ToLower(word), strings.ToUpper(word), capitalize(word)}
	var out []string
	seen := map[string]bool{}
	for _, c := range cands {
		c = EscapeToken(c)
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
}

// EscapeToken quotes the BTCRecover tokenlist metacharacters: % is always
// special, ^ only in first position, $ only in last (docs/tokenlist_file
// semantics). # and + need no handling: the extractor alphabet holds
// neither, so a line can never start with them.
func EscapeToken(tok string) string {
	var b strings.Builder
	for i := 0; i < len(tok); i++ {
		switch c := tok[i]; {
		case c == '%':
			b.WriteString("%%")
		case c == '^' && i == 0:
			b.WriteString("%^")
		case c == '$' && i == len(tok)-1:
			b.WriteString("%S")
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// BuildTokenlist renders data's words as a BTCRecover tokenlist: a #
// comment header plus one line per word, most max lines. It returns ""
// with zero stats when data holds no words.
func BuildTokenlist(data []byte, max int) (string, TokenlistStats) {
	words := ExtractTokenWords(data)
	if len(words) == 0 {
		return "", TokenlistStats{}
	}
	if max < 1 {
		max = 1
	}
	stats := TokenlistStats{Words: len(words)}
	shown := words
	if len(shown) > max {
		shown = shown[:max]
		stats.Truncated = true
	}
	stats.Lines = len(shown)
	var b strings.Builder
	fmt.Fprintf(&b, "# findbtc tokenlist: %d base words, one line each.\n", len(words))
	b.WriteString("# Same-line tokens are mutually exclusive variants; tune --max-tokens.\n")
	for _, w := range shown {
		b.WriteString(strings.Join(TokenVariants(w), " "))
		b.WriteByte('\n')
	}
	return b.String(), stats
}
