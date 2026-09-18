package detector

import (
	"encoding/json"
	"strings"
	"testing"
)

// Keystore fixtures with field values fed to the real ethereum2john.py; the
// expected strings below are its outputs minus the filename prefix.

// Scrypt keystore ("crypto" object, geth style).
const keystoreScryptJSON = `{"address":"de0b295669a9fd93d5f28d9ec85e40f4cb697bae",` +
	`"crypto":{"cipher":"aes-128-ctr",` +
	`"ciphertext":"4e0653b69e462c9ccdc998b803664e0653b69e462c9ccdc998b80366",` +
	`"cipherparams":{"iv":"90258a30b897a3dc2aaf0000000000000"},"kdf":"scrypt",` +
	`"kdfparams":{"dklen":32,"n":262144,"r":8,"p":1,` +
	`"salt":"1ebcc4774a90add12f0000000000000000000000000000000000000000000000"},` +
	`"mac":"f86fc22dce87d6f98740a88df000000000000000000000000000000000000000","version":1},` +
	`"id":"test","version":3}`

const keystoreScryptHash = "$ethereum$s*262144*8*1*1ebcc4774a90add12f0000000000000000000000000000000000000000000000*4e0653b69e462c9ccdc998b803664e0653b69e462c9ccdc998b80366*f86fc22dce87d6f98740a88df000000000000000000000000000000000000000"

// PBKDF2 keystore ("Crypto" object, older capitalized variant).
const keystorePBKDF2JSON = `{"address":"de0b295669a9fd93d5f28d9ec85e40f4cb697bae",` +
	`"Crypto":{"cipher":"aes-128-ctr","ciphertext":"abcd0011abcd0011abcd0011abcd0011abcd0011abcd0011abcd0011abcd0011",` +
	`"cipherparams":{"iv":"00112233445566778899aabbccddeeff"},"kdf":"pbkdf2",` +
	`"kdfparams":{"c":10240,"dklen":32,"prf":"hmac-sha256","salt":"ff00ff00ff00ff00ff00ff00ff00ff00"},` +
	`"mac":"99001122334455667788990011223344","version":1},` +
	`"id":"test","version":3}`

const keystorePBKDF2Hash = "$ethereum$p*10240*ff00ff00ff00ff00ff00ff00ff00ff00*abcd0011abcd0011abcd0011abcd0011abcd0011abcd0011abcd0011abcd0011*99001122334455667788990011223344"

func TestParseKeystoreGoldens(t *testing.T) {
	for _, tc := range []struct {
		name string
		json string
		hash string
		kdf  string
	}{
		{"scrypt", keystoreScryptJSON, keystoreScryptHash, "scrypt"},
		{"pbkdf2", keystorePBKDF2JSON, keystorePBKDF2Hash, "pbkdf2-hmac-sha256"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Detection and export must agree: the scanner finds it...
			found := findKeystores([]byte(tc.json), 500)
			if len(found) != 1 {
				t.Fatalf("findKeystores found %d objects, want 1", len(found))
			}
			span := []byte(tc.json)[found[0].startAbs-500 : found[0].endAbs-500]
			// ...and the exporter turns the same span into the reference hash.
			p, err := ParseKeystore(span, found[0].startAbs)
			if err != nil {
				t.Fatal(err)
			}
			h, err := p.Hash()
			if err != nil {
				t.Fatal(err)
			}
			if h.Hash != tc.hash {
				t.Errorf("hash = %s\nwant %s", h.Hash, tc.hash)
			}
			if h.Format != "ethereum-keystore" || h.KDF != tc.kdf {
				t.Errorf("metadata = %+v", h)
			}
			raw, err := json.Marshal(h)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), "de0b2956") {
				t.Errorf("exported hash leaks the address:\n%s", raw)
			}
		})
	}
}

func TestParseKeystoreRejects(t *testing.T) {
	base := `{"crypto":{"cipher":"aes-128-ctr","ciphertext":"abcd","kdf":"scrypt",` +
		`"kdfparams":{"dklen":32,"n":1024,"r":8,"p":1,"salt":"aabb"},"mac":"ccdd"}}`
	cases := map[string]string{
		"not json":       `{"crypto":`,
		"no crypto":      `{"address":"de0b295669a9fd93d5f28d9ec85e40f4cb697bae"}`,
		"presale shape":  `{"encseed":"aa","ethaddr":"bb","bkp":"cc"}`,
		"bad cipher":     strings.Replace(base, "aes-128-ctr", "aes-128-cbc", 1),
		"bad ciphertext": strings.Replace(base, `"ciphertext":"abcd"`, `"ciphertext":"xyz"`, 1),
		"missing mac":    strings.Replace(base, `,"mac":"ccdd"`, ``, 1),
		"bad kdf":        strings.Replace(base, `"kdf":"scrypt"`, `"kdf":"argon2"`, 1),
		"zero n":         strings.Replace(base, `"n":1024`, `"n":0`, 1),
		"bad salt":       strings.Replace(base, `"salt":"aabb"`, `"salt":"zz"`, 1),
		"bad prf":        strings.Replace(strings.Replace(base, `"kdf":"scrypt"`, `"kdf":"pbkdf2"`, 1), `"n":1024,"r":8,"p":1`, `"c":1024,"prf":"hmac-sha1"`, 1),
		"pbkdf2 zero c":  strings.Replace(strings.Replace(base, `"kdf":"scrypt"`, `"kdf":"pbkdf2"`, 1), `"n":1024,"r":8,"p":1`, `"c":0,"prf":"hmac-sha256"`, 1),
		"quoted n":       strings.Replace(base, `"n":1024`, `"n":"1024"`, 1),
	}
	for name, raw := range cases {
		if _, err := ParseKeystore([]byte(raw), 0); err == nil {
			t.Errorf("%s: parsed without error", name)
		}
	}
	// A valid record must survive a strict re-parse.
	p, err := ParseKeystore([]byte(base), 9)
	if err != nil {
		t.Fatal(err)
	}
	if p.Offset != 9 || p.N != 1024 {
		t.Errorf("params = %+v", p)
	}
	if _, err := p.Hash(); err != nil {
		t.Fatal(err)
	}
	if _, err := (KeystoreParams{KDF: "argon2"}).Hash(); err == nil {
		t.Error("unknown KDF hashed without error")
	}
}
