package detector

// Guards the embedded wordlist: vector tests prove the checked-in words are
// right, this proves none are missing or reordered at the edges.

import "testing"

func TestBIP39Wordlist(t *testing.T) {
	if len(bip39WordIndex) != 2048 {
		t.Fatalf("expected 2048 words, got %d", len(bip39WordIndex))
	}
	for word, want := range map[string]uint16{"abandon": 0, "about": 3, "zoo": 2047} {
		if got, ok := bip39WordIndex[word]; !ok || got != want {
			t.Errorf("expected %s at index %d, got %d (present=%v)", word, want, got, ok)
		}
	}
}

// A CRLF checkout must not poison lookups: every word keeps its index.
func TestSplitWordlistCRLF(t *testing.T) {
	words := splitWordlist("abandon\r\nabout\r\nzoo\r\n")
	if len(words) != 3 || words[0] != "abandon" || words[1] != "about" || words[2] != "zoo" {
		t.Fatalf("CRLF split gave %q", words)
	}
}
