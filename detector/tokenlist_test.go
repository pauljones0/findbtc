package detector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Extraction: words are runs of ASCII letters/digits out of binary
// context, first-seen order, exact-dedupe. Shorter than 3 or longer
// than 32 bytes never becomes a token.
func TestExtractTokenWords(t *testing.T) {
	data := []byte("\x00\xfflaptop COP\x00remember the old kern river stone valley " +
		"harbor pilot jacket melody anchor orbit 2019 retry junk !!\x00 a of to " +
		"river River abcdefghijklmnopqrstuvwxyzabcdef abcdefghijklmnopqrstuvwxyzabcdefg")
	words := ExtractTokenWords(data)
	want := []string{"laptop", "COP", "remember", "the", "old", "kern", "river",
		"stone", "valley", "harbor", "pilot", "jacket", "melody", "anchor",
		"orbit", "2019", "retry", "junk", "River", "abcdefghijklmnopqrstuvwxyzabcdef"}
	if strings.Join(words, " ") != strings.Join(want, " ") {
		t.Fatalf("words = %q\nwant %q", words, want)
	}
	if got := ExtractTokenWords(nil); len(got) != 0 {
		t.Fatalf("nil input: words = %q", got)
	}
	if got := ExtractTokenWords([]byte("\x00\x01\x02 a bb !")); len(got) != 0 {
		t.Fatalf("no-word input: words = %q", got)
	}
}

// Variants: original, lower, UPPER, Capitalized, deduped in that order.
// Pure-digit words collapse to one token.
func TestTokenVariants(t *testing.T) {
	cases := map[string][]string{
		"river": {"river", "RIVER", "River"},
		"River": {"River", "river", "RIVER"},
		"2019":  {"2019"},
		"COP":   {"COP", "cop", "Cop"},
		"a":     {"a", "A"},
	}
	for in, want := range cases {
		if got := TokenVariants(in); strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("TokenVariants(%q) = %q, want %q", in, got, want)
		}
	}
}

// Escaping must match the BTCRecover tokenlist syntax: % is always
// special, ^ only first, $ only last (# and + cannot appear: the
// extractor alphabet has neither, and lines never start with them).
func TestEscapeToken(t *testing.T) {
	cases := map[string]string{
		"plain": "plain",
		"100%d": "100%%d",
		"%":     "%%",
		"^head": "%^head",
		"mid^x": "mid^x",
		"tail$": "tail%S",
		"$mid":  "$mid",
		"a%b$c": "a%%b$c",
	}
	for in, want := range cases {
		if got := EscapeToken(in); got != want {
			t.Errorf("EscapeToken(%q) = %q, want %q", in, got, want)
		}
	}
}

// Golden: header plus one mutually-exclusive line per word.
func TestBuildTokenlist(t *testing.T) {
	got, stats := BuildTokenlist([]byte("\x00kern river 2019\x00"), 256)
	want := "# findbtc tokenlist: 3 base words, one line each.\n" +
		"# Same-line tokens are mutually exclusive variants; tune --max-tokens.\n" +
		"kern KERN Kern\n" +
		"river RIVER River\n" +
		"2019\n"
	if got != want {
		t.Fatalf("tokenlist = %q\nwant %q", got, want)
	}
	if stats.Words != 3 || stats.Lines != 3 || stats.Truncated {
		t.Fatalf("stats = %+v", stats)
	}
}

// The cap truncates whole lines and says so.
func TestBuildTokenlistTruncates(t *testing.T) {
	got, stats := BuildTokenlist([]byte("alpha bravo gamma delta"), 2)
	if stats.Words != 4 || stats.Lines != 2 || !stats.Truncated {
		t.Fatalf("stats = %+v", stats)
	}
	if strings.Count(got, "\n") != 4 { // header x2 + 2 lines
		t.Fatalf("truncated output has %d lines:\n%s", strings.Count(got, "\n"), got)
	}
	if strings.Contains(got, "gamma") {
		t.Fatalf("truncated output leaks word 3:\n%s", got)
	}
}

func TestBuildTokenlistEmpty(t *testing.T) {
	if got, stats := BuildTokenlist([]byte("\x00\x01 a bb"), 256); got != "" || stats.Words != 0 {
		t.Fatalf("empty = %q %+v", got, stats)
	}
}

// Corpus wiring: the committed hit-context fixture must yield the exact
// tokens whose combination unlocks eth-pbkdf2.json (River+Stone+2019).
// The real crack runs in CI (scripts/password-handoff.sh); this pins the
// generator side of that contract.
func TestCorpusTokenlistHoldsPasswordParts(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "password-handoff", "wallet-context.bin"))
	if err != nil {
		t.Fatal(err)
	}
	got, stats := BuildTokenlist(raw, 256)
	if stats.Truncated {
		t.Fatalf("corpus tokenlist truncated: %+v", stats)
	}
	for _, want := range []string{"\nriver RIVER River\n", "\nstone STONE Stone\n", "\n2019\n"} {
		if !strings.Contains(got, want) {
			t.Fatalf("tokenlist lacks %q:\n%s", want, got)
		}
	}
}
