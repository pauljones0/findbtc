package detector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Unsupported-but-complete keystores must explain themselves: a bare "No
// crack material found" sends the owner to carve wider when the record is
// complete and merely unsupported.
func TestExtractHashesSkipsUnsupportedCipher(t *testing.T) {
	raw := `{"address":"de0b295669a9fd93d5f28d9ec85e40f4cb697bae",` +
		`"crypto":{"cipher":"aes-256-cbc","ciphertext":"ab12","cipherparams":{"iv":"00112233445566778899aabbccddeeff"},` +
		`"kdf":"pbkdf2","kdfparams":{"dklen":32,"c":4096,"prf":"hmac-sha256","salt":"aabbccdd"},` +
		`"mac":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"},` +
		`"id":"00000000-0000-4000-8000-000000000000","version":3}`
	hashes, skips := ExtractHashesWithSkips([]byte(raw), 0)
	if len(hashes) != 0 {
		t.Fatalf("unsupported cipher must yield no hashes, got %d", len(hashes))
	}
	if len(skips) != 1 {
		t.Fatalf("unsupported cipher must yield one skip, got %+v", skips)
	}
	s := skips[0]
	if s.Kind != "ethereum-keystore" || s.Offset != 0 {
		t.Fatalf("skip = %+v", s)
	}
	if want := `unsupported cipher "aes-256-cbc"`; s.Reason != want {
		t.Fatalf("reason = %q, want %q", s.Reason, want)
	}
	// The legacy entry point keeps its shape: skips stay out of hashes.
	if got := ExtractHashes([]byte(raw), 0); len(got) != 0 {
		t.Fatalf("ExtractHashes must stay empty, got %d", len(got))
	}
}

// Presale wallets are detected as out of scope — a distinct, honest
// signal, not the generic nothing-found message.
func TestExtractHashesSkipsPresale(t *testing.T) {
	raw := `{"encseed":"00112233445566778899aabbccddeeff","ethaddr":"de0b295669a9fd93d5f28d9ec85e40f4cb697bae",` +
		`"bkp":"00112233445566778899aabbccddeeff","email":"owner@example.com"}`
	hashes, skips := ExtractHashesWithSkips([]byte(raw), 100)
	if len(hashes) != 0 {
		t.Fatalf("presale must yield no hashes, got %d", len(hashes))
	}
	if len(skips) != 1 {
		t.Fatalf("presale must yield one skip, got %+v", skips)
	}
	s := skips[0]
	if s.Kind != "ethereum-presale" || s.Offset != 100 {
		t.Fatalf("skip = %+v", s)
	}
	if !strings.Contains(s.Reason, "out of scope") {
		t.Fatalf("presale reason must say out of scope: %q", s.Reason)
	}
}

// Prose mentioning presale fields must not report: the sniff requires a
// valid JSON object, not a substring.
func TestExtractHashesPresaleProseSilent(t *testing.T) {
	for _, raw := range []string{
		"the encseed field holds the encrypted seed",
		`{"note": "encseed and bkp are presale fields"`, // unbalanced
		`{"encseed": "orphan without sibling fields"}`,
	} {
		hashes, skips := ExtractHashesWithSkips([]byte(raw), 0)
		if len(hashes) != 0 || len(skips) != 0 {
			t.Fatalf("prose %q: hashes=%d skips=%+v", raw, len(hashes), skips)
		}
	}
}

// Valid records still flow with no skips, and skips sort by offset.
func TestExtractHashesHappyPathNoSkips(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "password-handoff", "core-bdb-mkey.bin"))
	if err != nil {
		t.Fatal(err)
	}
	ks := `{"address":"de0b295669a9fd93d5f28d9ec85e40f4cb697bae",` +
		`"crypto":{"cipher":"aes-128-ctr","ciphertext":"ab12","cipherparams":{"iv":"00112233445566778899aabbccddeeff"},` +
		`"kdf":"pbkdf2","kdfparams":{"dklen":32,"c":4096,"prf":"hmac-sha256","salt":"aabbccdd"},` +
		`"mac":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"},` +
		`"id":"00000000-0000-4000-8000-000000000000","version":3}`
	buf := append(append([]byte{}, raw...), []byte("  "+ks)...)
	hashes, skips := ExtractHashesWithSkips(buf, 0)
	if len(skips) != 0 {
		t.Fatalf("valid records must not skip: %+v", skips)
	}
	if len(hashes) != 2 {
		t.Fatalf("want mkey + keystore hashes, got %d", len(hashes))
	}
	if hashes[0].Offset != 0 || !strings.HasPrefix(hashes[0].Hash, "$bitcoin$") {
		t.Fatalf("first hash = %+v", hashes[0])
	}
	if !strings.HasPrefix(hashes[1].Hash, "$ethereum$p*4096*") {
		t.Fatalf("second hash = %+v", hashes[1])
	}
}

// Truncated mkey patterns stay silent by design: anything looser than
// the full 66-byte shape would report noise (pinned, not accidental).
func TestExtractHashesTruncatedMkeySilent(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "password-handoff", "core-bdb-mkey.bin"))
	if err != nil {
		t.Fatal(err)
	}
	hashes, skips := ExtractHashesWithSkips(raw[:len(raw)-1], 0)
	if len(hashes) != 0 || len(skips) != 0 {
		t.Fatalf("65-byte mkey: hashes=%d skips=%+v", len(hashes), skips)
	}
}
