package detector

import (
	"bytes"
	"encoding/base64"
)

// MetaMask vault detection (@metamask/browser-passworder format). A hit is a
// JSON object — plain or JSON-escaped as in LevelDB storage — carrying
// base64 data/iv/salt with the encryptor's exact decoded lengths (iv 16,
// salt 32 bytes). Vaults are always encrypted, so the report flags them.
//
// Only the label and offsets leave this module; vault ciphertext is
// password-protected secrets.

// metamaskMaxSpan bounds the data/iv/salt co-occurrence window. Vault data
// grows with the wallet; objects past this are out of scope. It must stay
// below the block size: the overlap window cannot exceed one block.
const metamaskMaxSpan = 2048

type metamaskMatch struct {
	startAbs, endAbs int64
}

// findMetaMask returns every span where vault data/iv/salt keys co-occur
// with valid encryptor-shaped values, in plain or escaped form.
func findMetaMask(data []byte, baseAbs int64, first, final bool) []metamaskMatch {
	_ = first
	_ = final
	var out []metamaskMatch
	for _, escaped := range []bool{false, true} {
		anchor := []byte(`"iv"`)
		if escaped {
			anchor = []byte(`\"iv\"`)
		}
		for i := 0; i+len(anchor) <= len(data); {
			j := bytes.Index(data[i:], anchor)
			if j == -1 {
				break
			}
			a := i + j
			if s, e, ok := metamaskSpan(data, a, len(anchor), escaped); ok {
				out = append(out, metamaskMatch{baseAbs + int64(s), baseAbs + int64(e)})
			}
			i = a + 1
		}
	}
	return out
}

// metamaskSpan validates the iv value at the anchor and requires data and
// salt siblings with valid shapes nearby, in the same escaping style.
func metamaskSpan(data []byte, anchor, anchorLen int, escaped bool) (int, int, bool) {
	ivEnd, ok := metamaskValue(data, anchor+anchorLen, escaped)
	if !ok {
		return 0, 0, false
	}
	iv, err := base64.StdEncoding.DecodeString(string(data[valueStart(data, anchor+anchorLen, escaped):ivEnd]))
	if err != nil || len(iv) != 16 {
		return 0, 0, false
	}
	lo := anchor - metamaskMaxSpan
	if lo < 0 {
		lo = 0
	}
	hi := anchor + metamaskMaxSpan
	if hi > len(data) {
		hi = len(data)
	}
	start, end := anchor, ivEnd
	for _, key := range []string{"data", "salt"} {
		ks, ke, ok := metamaskSibling(data, lo, hi, key, escaped)
		if !ok {
			return 0, 0, false
		}
		val, err := base64.StdEncoding.DecodeString(string(data[ks:ke]))
		if err != nil {
			return 0, 0, false
		}
		if key == "salt" && len(val) != 32 {
			return 0, 0, false
		}
		if key == "data" && len(val) < 16 {
			return 0, 0, false
		}
		if ks < start {
			start = ks
		}
		if ke > end {
			end = ke
		}
	}
	return start, end, true
}

// metamaskSibling finds key's value within [lo,hi) and returns its byte
// range (without quotes).
func metamaskSibling(data []byte, lo, hi int, key string, escaped bool) (int, int, bool) {
	pattern := `"` + key + `"`
	if escaped {
		pattern = `\"` + key + `\"`
	}
	at := bytes.Index(data[lo:hi], []byte(pattern))
	if at == -1 {
		return 0, 0, false
	}
	a := lo + at
	ve, ok := metamaskValue(data, a+len(pattern), escaped)
	if !ok {
		return 0, 0, false
	}
	return valueStart(data, a+len(pattern), escaped), ve, true
}

// metamaskValue parses ':' + optional space + quoted value at pos,
// returning the offset just before the closing quote (escaped form allows
// a backslash before the quotes).
func metamaskValue(data []byte, pos int, escaped bool) (int, bool) {
	p := skipJSONSpace(data, pos)
	if p >= len(data) || data[p] != ':' {
		return 0, false
	}
	p = skipJSONSpace(data, p+1)
	if escaped {
		if p >= len(data) || data[p] != '\\' {
			return 0, false
		}
		p++
	}
	if p >= len(data) || data[p] != '"' {
		return 0, false
	}
	p++
	start := p
	for p < len(data) {
		if data[p] == '"' {
			if !escaped {
				if p-start > metamaskMaxSpan {
					return 0, false
				}
				return p, true
			}
			if p > start && data[p-1] == '\\' {
				if p-1-start > metamaskMaxSpan {
					return 0, false
				}
				return p - 1, true // exclude the closer's backslash
			}
			return 0, false
		}
		p++
	}
	return 0, false
}

// valueStart replays metamaskValue's opener to locate the value's first byte.
func valueStart(data []byte, pos int, escaped bool) int {
	p := skipJSONSpace(data, pos) + 1 // colon
	p = skipJSONSpace(data, p)
	if escaped {
		p++ // backslash
	}
	return p + 1 // quote
}
