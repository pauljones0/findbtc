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
