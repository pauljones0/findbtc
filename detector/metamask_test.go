package detector

import (
	"math/rand"
	"os"
	"strings"
	"testing"
)

// MetaMask vault fixtures shaped per @metamask/browser-passworder: data/iv
// base64 (AES-GCM), iv 16 bytes, salt base64 of 32 bytes, new format with a
// PBKDF2 keyMetadata object. Payload bytes are random, not a real vault.

const mmData = "eOZFLylpzM3CcQyDhp7LeXn+P6HtZyydU4gAyyUUqS+TeRgYxu1TcoG0q02cr0wkJS82F1/R54k/3UTPwPnv4ycvhbFif2uiZ6u4CsuGbpg0B3H7cr1qZbhd+vaqePdzlndnp1OXKb1+hJWdOA1rpmeIUSimWIWfhBbXA9Bl6tS2/kOHi5MrENO9Pg9liiAJC32xMI8rK+E4+u89JZKAmRR+swfAHDLHrmjEdhP2h1O4pcZwIx5Jl+1NqdfqlAAyYFHlhEYz0Ds="
const mmIV = "bSXPc0xJod0nPk2Pq19b2w=="
const mmSalt = "jRCZ7AXo/cfB1zR3dkirc73iAYJQReTaMtpelnlrnTA="

var mmOldVault = `{"data": "` + mmData + `", "iv": "` + mmIV + `", "salt": "` + mmSalt + `"}`

var mmNewVault = `{"data": "` + mmData + `", "iv": "` + mmIV + `", "keyMetadata": {"algorithm": "PBKDF2", "params": {"iterations": 900000}}, "salt": "` + mmSalt + `"}`

func TestFindMetaMask(t *testing.T) {
	for name, vault := range map[string]string{"old": mmOldVault, "new": mmNewVault} {
		buf := []byte("xx " + vault + " yy")
		matches := findMetaMask(buf, 700, true, true)
		if len(matches) != 1 {
			t.Fatalf("%s: got %d matches, want 1", name, len(matches))
		}
		span := buf[matches[0].startAbs-700 : matches[0].endAbs-700]
		if !strings.Contains(string(span), mmIV) {
			t.Errorf("%s: match span misses the vault", name)
		}
	}
	// LevelDB form: the vault JSON-escaped inside an outer object.
	escaped := `{"KeyringController": {"vault": "` + escapeJSON(mmOldVault) + `"}}`
	if m := findMetaMask([]byte(escaped), 0, true, true); len(m) != 1 {
		t.Errorf("escaped vault: %d matches, want 1", len(m))
	}
	// Wrong iv length is not a vault.
	dud := `{"data": "` + mmData + `", "iv": "aGk=", "salt": "` + mmSalt + `"}`
	if m := findMetaMask([]byte(dud), 0, true, true); len(m) != 0 {
		t.Error("short iv must stay silent")
	}
	// Missing salt is not a vault.
	dud2 := `{"data": "` + mmData + `", "iv": "` + mmIV + `"}`
	if m := findMetaMask([]byte(dud2), 0, true, true); len(m) != 0 {
		t.Error("missing salt must stay silent")
	}
	// Non-base64 data is not a vault.
	dud3 := `{"data": "!!!not-base64!!!", "iv": "` + mmIV + `", "salt": "` + mmSalt + `"}`
	if m := findMetaMask([]byte(dud3), 0, true, true); len(m) != 0 {
		t.Error("non-base64 data must stay silent")
	}
}

func escapeJSON(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, `"`, `\"`)
}

func TestMetaMaskNoiseCorpus(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	noise := make([]byte, 1<<20)
	if _, err := rng.Read(noise); err != nil {
		t.Fatal(err)
	}
	if m := findMetaMask(noise, 0, true, true); len(m) != 0 {
		t.Fatalf("noise: %d matches, want 0", len(m))
	}
	for _, f := range []string{"../LICENSE", "../README.md", "../GOALS.md", "../main.go"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if m := findMetaMask(raw, 0, true, true); len(m) != 0 {
			t.Errorf("%s: %d matches, want 0", f, len(m))
		}
	}
}
