package detector

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Ethereum Web3 Secret Storage keystore detection. Unlike substring needles,
// a hit must JSON-parse with the keystore structure (40-hex address plus a
// crypto object carrying ciphertext, cipher and kdf), so prose mentioning
// keystores does not report.
//
// Only the keystore label is ever reported; addresses stay out of output
// even though they are not secrets.

// keystoreMaxSpan bounds the byte length of a reported keystore object so it
// always fits the block overlap window and keeps exactly-once reporting.
// Real keystores run about 500 bytes; pretty-printed ones stay far below this.
const keystoreMaxSpan = 2048

// keystoreAnchor locates candidate objects; validation decides.
var keystoreAnchor = []byte(`"ciphertext"`)

type keystoreMatch struct {
	startAbs, endAbs int64
}

// findKeystores returns every structurally valid keystore object fully
// contained in data. Objects cut by a data edge are skipped here and caught
// whole in the neighboring block instead.
func findKeystores(data []byte, baseAbs int64) []keystoreMatch {
	var matches []keystoreMatch
	for i := 0; i+len(keystoreAnchor) <= len(data); {
		j := bytes.Index(data[i:], keystoreAnchor)
		if j == -1 {
			break
		}
		anchor := i + j
		if start, end, ok := keystoreBounds(data, anchor); ok {
			matches = append(matches, keystoreMatch{baseAbs + int64(start), baseAbs + int64(end)})
		}
		i = anchor + 1
	}
	return matches
}

// presaleAnchor marks Ethereum presale wallets (the encseed shape), which
// carry no crypto object and therefore never match findKeystores. They
// are detected as out of scope: no supported cracker input exists.
var presaleAnchor = []byte(`"encseed"`)

// findPresales returns a skip per presale-shaped object in data: valid
// JSON holding encseed plus a second presale field, so prose mentioning
// encseed does not report. baseAbs is the absolute offset of data[0].
func findPresales(data []byte, baseAbs int64) []HashSkip {
	var skips []HashSkip
	seen := map[int64]bool{}
	for i := 0; i+len(presaleAnchor) <= len(data); {
		j := bytes.Index(data[i:], presaleAnchor)
		if j == -1 {
			break
		}
		anchor := i + j
		back := anchor - keystoreMaxSpan
		if back < 0 {
			back = 0
		}
		// Candidate braces nearest-first like keystoreBounds: the
		// nearest '{' may open a nested object, so try outward.
		tried := 0
		for s := anchor - 1; s >= back && tried < 32; s-- {
			if data[s] != '{' {
				continue
			}
			tried++
			end := braceEnd(data, s)
			if end <= 0 || end-s > keystoreMaxSpan {
				continue
			}
			obj := data[s:end]
			if !bytes.Contains(obj, presaleAnchor) {
				continue
			}
			if !bytes.Contains(obj, []byte(`"bkp"`)) && !bytes.Contains(obj, []byte(`"ethaddr"`)) {
				continue
			}
			var v map[string]json.RawMessage
			if json.Unmarshal(obj, &v) != nil {
				continue
			}
			if _, ok := v["encseed"]; !ok || seen[int64(s)] {
				continue
			}
			seen[int64(s)] = true
			skips = append(skips, HashSkip{
				Offset: baseAbs + int64(s),
				Kind:   "ethereum-presale",
				Reason: "presale wallets are out of scope (no supported cracker export)",
			})
			break
		}
		i = anchor + 1
	}
	return skips
}

// keystoreBounds locates the JSON object enclosing the anchor: candidate
// braces are tried nearest-first and the first structurally valid object wins.
func keystoreBounds(data []byte, anchor int) (int, int, bool) {
	back := anchor - 2048
	if back < 0 {
		back = 0
	}
	tried := 0
	for s := anchor; s >= back && tried < 32; s-- {
		if data[s] != '{' {
			continue
		}
		tried++
		end := braceEnd(data, s)
		if end < 0 || end-s > keystoreMaxSpan {
			continue
		}
		if validKeystore(data[s:end]) {
			return s, end, true
		}
	}
	return 0, 0, false
}

// braceEnd returns the offset just past the object opened at start, skipping
// over string literals, or -1 when unbalanced or past the forward bound.
func braceEnd(data []byte, start int) int {
	depth := 0
	inString := false
	escaped := false
	for i := start; i < len(data) && i-start < 8192; i++ {
		c := data[i]
		if inString {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return -1
}

type keystoreCrypto struct {
	Cipher     string `json:"cipher"`
	Ciphertext string `json:"ciphertext"`
	KDF        string `json:"kdf"`
}

type keystoreFile struct {
	Address string          `json:"address"`
	Crypto  *keystoreCrypto `json:"crypto"`
	CryptoC *keystoreCrypto `json:"Crypto"` // older capitalized variant
}

// validKeystore enforces the keystore structure: a 40-hex address plus a
// crypto object naming cipher, kdf and hex ciphertext.
func validKeystore(raw []byte) bool {
	var ks keystoreFile
	if err := json.Unmarshal(raw, &ks); err != nil {
		return false
	}
	if !isHexAddress(ks.Address) {
		return false
	}
	crypto := ks.Crypto
	if crypto == nil {
		crypto = ks.CryptoC
	}
	if crypto == nil || crypto.Cipher == "" || crypto.KDF == "" {
		return false
	}
	return len(crypto.Ciphertext) > 0 && isHex(crypto.Ciphertext)
}

func isHexAddress(s string) bool {
	s = trim0x(s)
	return len(s) == 40 && isHex(s)
}

func trim0x(s string) string {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		return s[2:]
	}
	return s
}

func isHex(s string) bool {
	if len(s) == 0 || len(s)%2 != 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' {
			continue
		}
		return false
	}
	return true
}

// keystoreDescription renders a match without address material.
func keystoreDescription(location string) string {
	return fmt.Sprintf("Found 'eth-keystore' at %s", location)
}

// KeystoreParams is the crack-relevant parameter set of a Web3 Secret
// Storage keystore: everything ethereum2john.py forwards to a cracker.
// Addresses are never read: they stay out of output by construction.
type KeystoreParams struct {
	Cipher     string
	Ciphertext string
	MAC        string
	KDF        string // "scrypt" or "pbkdf2"
	N, R, P    int    // scrypt
	C          int    // pbkdf2 iterations
	PRF        string // pbkdf2 prf
	Salt       string
	DKLen      int
	Offset     int64
}

type keystoreKDFParams struct {
	DKLen int    `json:"dklen"`
	N     int    `json:"n"`
	R     int    `json:"r"`
	P     int    `json:"p"`
	C     int    `json:"c"`
	PRF   string `json:"prf"`
	Salt  string `json:"salt"`
}

type keystoreCryptoFull struct {
	Cipher     string            `json:"cipher"`
	Ciphertext string            `json:"ciphertext"`
	MAC        string            `json:"mac"`
	KDF        string            `json:"kdf"`
	KDFParams  keystoreKDFParams `json:"kdfparams"`
}

type keystoreFileFull struct {
	Crypto  *keystoreCryptoFull `json:"crypto"`
	CryptoC *keystoreCryptoFull `json:"Crypto"`
}

// ParseKeystore extracts the crack-relevant parameters from one keystore
// object at absolute offset. It is strict: anything ethereum2john.py would
// reject (or silently mangle) errors here instead of producing a hash no
// cracker could use.
func ParseKeystore(raw []byte, offset int64) (KeystoreParams, error) {
	fail := func(format string, args ...any) (KeystoreParams, error) {
		return KeystoreParams{}, fmt.Errorf("keystore at byte %d: %s", offset, fmt.Sprintf(format, args...))
	}
	var ks keystoreFileFull
	if err := json.Unmarshal(raw, &ks); err != nil {
		return fail("not valid JSON: %s", err)
	}
	c := ks.Crypto
	if c == nil {
		c = ks.CryptoC
	}
	if c == nil {
		return fail("no crypto object (presale wallets unsupported)")
	}
	if c.Cipher != "aes-128-ctr" {
		return fail("unsupported cipher %q", c.Cipher)
	}
	if !isHex(c.Ciphertext) {
		return fail("ciphertext is not hex")
	}
	if !isHex(c.MAC) {
		return fail("mac is missing or not hex")
	}
	p := KeystoreParams{
		Cipher: c.Cipher, Ciphertext: c.Ciphertext, MAC: c.MAC,
		KDF: c.KDF, Salt: c.KDFParams.Salt, DKLen: c.KDFParams.DKLen, Offset: offset,
	}
	switch c.KDF {
	case "scrypt":
		p.N, p.R, p.P = c.KDFParams.N, c.KDFParams.R, c.KDFParams.P
		if p.N <= 0 || p.R <= 0 || p.P <= 0 {
			return fail("scrypt needs positive n/r/p, got %d/%d/%d", p.N, p.R, p.P)
		}
		if !isHex(p.Salt) {
			return fail("scrypt salt is missing or not hex")
		}
	case "pbkdf2":
		p.C, p.PRF = c.KDFParams.C, c.KDFParams.PRF
		if p.PRF != "hmac-sha256" {
			return fail("unsupported pbkdf2 prf %q", p.PRF)
		}
		if p.C <= 0 {
			return fail("pbkdf2 needs positive iteration count, got %d", p.C)
		}
		if !isHex(p.Salt) {
			return fail("pbkdf2 salt is missing or not hex")
		}
	default:
		return fail("unsupported kdf %q", c.KDF)
	}
	return p, nil
}

// Hash renders the hashcat/John `ethereum` input exactly as ethereum2john.py
// does, minus its filename prefix (which hashcat rejects so loudly the forum
// tells everyone to strip it):
//
//	scrypt: $ethereum$s*<n>*<r>*<p>*<salt>*<ciphertext>*<mac>
//	pbkdf2: $ethereum$p*<c>*<salt>*<ciphertext>*<mac>
func (p KeystoreParams) Hash() (CrackHash, error) {
	params := map[string]string{
		"cipher": p.Cipher,
		"dklen":  fmt.Sprint(p.DKLen),
	}
	var hash, kdf string
	var iters uint32
	switch p.KDF {
	case "scrypt":
		hash = fmt.Sprintf("$ethereum$s*%d*%d*%d*%s*%s*%s",
			p.N, p.R, p.P, p.Salt, p.Ciphertext, p.MAC)
		kdf, iters = "scrypt", uint32(p.N)
		params["n"], params["r"], params["p"] = fmt.Sprint(p.N), fmt.Sprint(p.R), fmt.Sprint(p.P)
	case "pbkdf2":
		hash = fmt.Sprintf("$ethereum$p*%d*%s*%s*%s", p.C, p.Salt, p.Ciphertext, p.MAC)
		kdf, iters = "pbkdf2-hmac-sha256", uint32(p.C)
		params["prf"] = p.PRF
	default:
		return CrackHash{}, fmt.Errorf("cannot hash keystore with kdf %q", p.KDF)
	}
	return CrackHash{
		Format:     "ethereum-keystore",
		Hash:       hash,
		KDF:        kdf,
		Iterations: iters,
		SaltHex:    p.Salt,
		Params:     params,
		Offset:     p.Offset,
	}, nil
}
