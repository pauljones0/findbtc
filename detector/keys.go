package detector

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// Private and extended key detection. Unlike wallet-file needles, every hit
// below is checksum-validated, so random data is effectively silent: a stray
// 51-byte window passes base58check with probability 1 in 4 billion.
//
// Only key types are ever reported; key material stays out of descriptions,
// logs and JSON. Carved bytes intentionally still hold the key itself.

// Base58 alphabet (no 0OIl).
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// base58Value maps bytes to their base58 value, or -1.
var base58Value = func() [256]int {
	var t [256]int
	for i := range t {
		t[i] = -1
	}
	for i := 0; i < len(base58Alphabet); i++ {
		t[base58Alphabet[i]] = i
	}
	return t
}()

func isBase58Char(b byte) bool {
	return base58Value[b] >= 0
}

func isWIFStart(b byte) bool {
	switch b {
	case '5', 'K', 'L', '9', 'c':
		return true
	}
	return false
}

var xkeyPrefixes = []string{"xprv", "xpub", "tprv", "tpub", "yprv", "ypub", "zprv", "zpub"}

func isXKeyPrefix(s []byte) bool {
	if len(s) < 4 {
		return false
	}
	for _, p := range xkeyPrefixes {
		if s[0] == p[0] && s[1] == p[1] && s[2] == p[2] && s[3] == p[3] {
			return true
		}
	}
	return false
}

var xkeyVersions = map[uint32]string{
	0x0488ADE4: "xprv", 0x0488B21E: "xpub",
	0x04358394: "tprv", 0x043587CF: "tpub",
	0x049D7878: "yprv", 0x049D7CB2: "ypub",
	0x04B2430C: "zprv", 0x04B24746: "zpub",
}

// base58Decode decodes alphabet-only input. Inputs past the longest key are
// rejected so hostile callers cannot force quadratic work.
func base58Decode(s string) ([]byte, bool) {
	if len(s) == 0 || len(s) > 128 {
		return nil, false
	}
	zeros := 0
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}
	var num []byte
	for i := zeros; i < len(s); i++ {
		v := base58Value[s[i]]
		if v < 0 {
			return nil, false
		}
		carry := v
		for j := 0; j < len(num); j++ {
			carry += int(num[j]) * 58
			num[j] = byte(carry)
			carry >>= 8
		}
		for carry > 0 {
			num = append(num, byte(carry))
			carry >>= 8
		}
	}
	out := make([]byte, zeros+len(num))
	for i, j := zeros, len(num)-1; j >= 0; i, j = i+1, j-1 {
		out[i] = num[j]
	}
	return out, true
}

// base58CheckDecode verifies the trailing 4-byte double-SHA256 checksum and
// returns the payload without it.
func base58CheckDecode(s string) ([]byte, bool) {
	raw, ok := base58Decode(s)
	if !ok || len(raw) < 5 {
		return nil, false
	}
	payload := raw[:len(raw)-4]
	sum := sha256.Sum256(payload)
	sum2 := sha256.Sum256(sum[:])
	for i := 0; i < 4; i++ {
		if raw[len(payload)+i] != sum2[i] {
			return nil, false
		}
	}
	return payload, true
}

// classifyWIF validates a checksummed WIF payload: version byte plus 32 key
// bytes, with a trailing 0x01 compression flag on 34-byte payloads.
func classifyWIF(payload []byte) (string, bool) {
	if len(payload) != 33 && len(payload) != 34 {
		return "", false
	}
	if payload[0] != 0x80 && payload[0] != 0xEF {
		return "", false
	}
	if len(payload) == 34 && payload[33] != 0x01 {
		return "", false
	}
	if payload[0] == 0xEF {
		return "wif-testnet", true
	}
	return "wif", true
}

// classifyXKey validates a checksummed 78-byte extended-key payload by its
// version bytes.
func classifyXKey(payload []byte) (string, bool) {
	if len(payload) != 78 {
		return "", false
	}
	label, ok := xkeyVersions[binary.BigEndian.Uint32(payload[:4])]
	return label, ok
}

type keyMatch struct {
	label            string
	kind             string // "private key" or "extended key", for descriptions
	startAbs, endAbs int64
}

// findKeys returns every checksum-valid key fully contained in data. Edge
// fragments are handled exactly like seed phrases: a key using bytes past the
// edge is evaluated whole in the neighboring block instead.
func findKeys(data []byte, baseAbs int64, first, final bool) []keyMatch {
	data, off := trimEdgeFragments(data, first, final, isBase58Char)
	baseAbs += int64(off)
	var matches []keyMatch
	for i := 0; i < len(data); {
		if !isBase58Char(data[i]) {
			i++
			continue
		}
		j := i
		for j < len(data) && isBase58Char(data[j]) {
			j++
		}
		matches = append(matches, scanKeyRun(data[i:j], baseAbs+int64(i))...)
		i = j
	}
	return matches
}

func scanKeyRun(run []byte, baseAbs int64) []keyMatch {
	var out []keyMatch
	for i := 0; i < len(run); i++ {
		if isWIFStart(run[i]) {
			for _, length := range []int{51, 52} {
				if i+length > len(run) {
					break
				}
				if payload, ok := base58CheckDecode(string(run[i : i+length])); ok {
					if label, ok := classifyWIF(payload); ok {
						out = append(out, keyMatch{label, "private key", baseAbs + int64(i), baseAbs + int64(i+length)})
					}
				}
			}
		}
		if i+111 <= len(run) && isXKeyPrefix(run[i:]) {
			if payload, ok := base58CheckDecode(string(run[i : i+111])); ok {
				if label, ok := classifyXKey(payload); ok {
					out = append(out, keyMatch{label, "extended key", baseAbs + int64(i), baseAbs + int64(i+111)})
				}
			}
		}
	}
	return out
}

// keyDescription renders a match without key material.
func keyDescription(label, kind, location string) string {
	return fmt.Sprintf("Found '%s %s' at %s", label, kind, location)
}
