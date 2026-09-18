package detector

import "strings"

// Output descriptor detection (BIP380 checksums). A hit is a parenthesized
// descriptor body followed by '#' and the 8-character checksum from
// Bitcoin Core's DescriptorChecksum. The 1-in-2^40 checksum makes prose
// matches effectively impossible.
//
// Descriptors can embed private keys, so only the label and offsets leave
// this module — never the descriptor text.

// descriptorMaxSpan bounds one candidate body. Real descriptors (even large
// multisigs) stay far below; longer bodies are out of scope so matches
// always fit the block overlap window. It must stay below the block size:
// the overlap window cannot exceed one block.
const descriptorMaxSpan = 2048

// descriptorMinBody is the shortest plausible body: "pk(" + key + ")".
const descriptorMinBody = 12

const descriptorInputCharset = "0123456789()[],'/*abcdefgh@:$%{}" +
	"IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~" +
	"ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "

const descriptorChecksumCharset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var descriptorInputIndex = func() [256]int {
	var t [256]int
	for i := range t {
		t[i] = -1
	}
	for i := 0; i < len(descriptorInputCharset); i++ {
		t[descriptorInputCharset[i]] = i
	}
	return t
}()

func isDescriptorChecksumChar(b byte) bool {
	return strings.IndexByte(descriptorChecksumCharset, b) >= 0
}

func descriptorPolyMod(c uint64, val int) uint64 {
	c0 := byte(c >> 35)
	c = ((c & 0x7ffffffff) << 5) ^ uint64(val)
	if c0&1 != 0 {
		c ^= 0xf5dee51989
	}
	if c0&2 != 0 {
		c ^= 0xa9fdca3312
	}
	if c0&4 != 0 {
		c ^= 0x1bab10e32d
	}
	if c0&8 != 0 {
		c ^= 0x3706b1677a
	}
	if c0&16 != 0 {
		c ^= 0x644d626ffd
	}
	return c
}

// descriptorChecksum computes Core's DescriptorChecksum over body, or ""
// when the body holds characters outside the input set.
func descriptorChecksum(body string) string {
	var c uint64 = 1
	cls, clscount := 0, 0
	for i := 0; i < len(body); i++ {
		pos := descriptorInputIndex[body[i]]
		if pos < 0 {
			return ""
		}
		c = descriptorPolyMod(c, pos&31)
		cls = cls*3 + (pos >> 5)
		clscount++
		if clscount == 3 {
			c = descriptorPolyMod(c, cls)
			cls, clscount = 0, 0
		}
	}
	if clscount > 0 {
		c = descriptorPolyMod(c, cls)
	}
	for j := 0; j < 8; j++ {
		c = descriptorPolyMod(c, 0)
	}
	c ^= 1
	var out [8]byte
	for j := 0; j < 8; j++ {
		out[j] = descriptorChecksumCharset[(c>>(5*(7-j)))&31]
	}
	return string(out[:])
}

type descriptorMatch struct {
	startAbs, endAbs int64
}

// findDescriptors returns every checksummed descriptor fully contained in
// data. Candidates anchor on '#' followed by exactly 8 checksum characters;
// starts are tried at each '(' back to the span bound, nearest-first, and
// the first validating body wins.
func findDescriptors(data []byte, baseAbs int64, first, final bool) []descriptorMatch {
	_ = first
	_ = final
	var out []descriptorMatch
	for i := 0; i < len(data); i++ {
		if data[i] != '#' {
			continue
		}
		if i+9 > len(data) {
			break
		}
		ok := true
		for k := 1; k <= 8; k++ {
			if !isDescriptorChecksumChar(data[i+k]) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		// Exactly 8: a 9th checksum character means a longer token.
		if i+9 < len(data) && isDescriptorChecksumChar(data[i+9]) {
			continue
		}
		if i == 0 || data[i-1] != ')' {
			continue
		}
		if s, e, found := descriptorBody(data, i, i+9); found {
			out = append(out, descriptorMatch{baseAbs + int64(s), baseAbs + int64(e)})
		}
	}
	return out
}

// descriptorBody tries candidate bodies ending at hashEnd (just past the 8
// checksum characters). Each '(' within the span bound is a candidate start,
// nearest-first.
func descriptorBody(data []byte, hash, hashEnd int) (int, int, bool) {
	back := hash - descriptorMaxSpan
	if back < 0 {
		back = 0
	}
	tried := 0
	for s := hash - 1; s >= back && tried < 64; s-- {
		if data[s] != '(' {
			continue
		}
		tried++
		// The function name precedes '(': walk back over letters only.
		name := s
		for name > back && isDescriptorNameChar(data[name-1]) {
			name--
		}
		if name == s || hash-name < descriptorMinBody {
			continue
		}
		body := string(data[name:hash])
		if strings.Contains(body, "#") {
			continue
		}
		want := string(data[hash+1 : hashEnd])
		if descriptorChecksum(body) == want {
			return name, hashEnd, true
		}
	}
	return 0, 0, false
}

func isDescriptorNameChar(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_'
}
