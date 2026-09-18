package detector

import "math/bits"

// RIPEMD-160, one-shot. findbtc needs it only for HASH160 (Bitcoin address
// derivation); a small local implementation keeps the module dependency-free.
//
// Algorithm: Dobbertin/Bosselaers/Preneel, "RIPEMD-160" (AB-9601). Verified
// against Python hashlib and golang.org/x/crypto on random inputs; the
// committed vectors in watch_test.go come from those oracles.

// ripemdInit is the chaining-value IV.
var ripemdInit = [5]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0}

// Message-word order and rotation amounts for the left and right lines.
var ripemdML = [80]uint{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
	3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
	1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
	4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
}

var ripemdRL = [80]uint{
	11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
	7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
	11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
	11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
	9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
}

var ripemdMR = [80]uint{
	5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
	6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
	15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
	8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
	12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
}

var ripemdRR = [80]uint{
	8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
	9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
	9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
	15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
	8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
}

// Round constants, left line then right line.
var ripemdKL = [5]uint32{0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e}
var ripemdKR = [5]uint32{0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000}

func ripemdFL(round int, b, c, d uint32) uint32 {
	switch round {
	case 0:
		return b ^ c ^ d
	case 1:
		return (b & c) | (^b & d)
	case 2:
		return (b | ^c) ^ d
	case 3:
		return (b & d) | (c & ^d)
	default:
		return b ^ (c | ^d)
	}
}

func ripemdFR(round int, b, c, d uint32) uint32 {
	switch round {
	case 0:
		return b ^ (c | ^d)
	case 1:
		return (b & d) | (c & ^d)
	case 2:
		return (b | ^c) ^ d
	case 3:
		return (b & c) | (^b & d)
	default:
		return b ^ c ^ d
	}
}

func ripemdBlock(s [5]uint32, p []byte) [5]uint32 {
	var x [16]uint32
	for i := 0; i < 16; i++ {
		x[i] = uint32(p[i*4]) | uint32(p[i*4+1])<<8 |
			uint32(p[i*4+2])<<16 | uint32(p[i*4+3])<<24
	}
	a, b, c, d, e := s[0], s[1], s[2], s[3], s[4]
	aa, bb, cc, dd, ee := a, b, c, d, e
	for i := 0; i < 80; i++ {
		round := i / 16
		t := a + ripemdFL(round, b, c, d) + x[ripemdML[i]] + ripemdKL[round]
		t = bits.RotateLeft32(t, int(ripemdRL[i])) + e
		a, b, c, d, e = e, t, b, bits.RotateLeft32(c, 10), d

		t = aa + ripemdFR(round, bb, cc, dd) + x[ripemdMR[i]] + ripemdKR[round]
		t = bits.RotateLeft32(t, int(ripemdRR[i])) + ee
		aa, bb, cc, dd, ee = ee, t, bb, bits.RotateLeft32(cc, 10), dd
	}
	dd += c + s[1]
	s[1] = s[2] + d + ee
	s[2] = s[3] + e + aa
	s[3] = s[4] + a + bb
	s[4] = s[0] + b + cc
	s[0] = dd
	return s
}

// ripemd160Sum returns the RIPEMD-160 digest of b.
func ripemd160Sum(b []byte) [20]byte {
	s := ripemdInit
	// Padded length: data + 0x80 + zeros + 8-byte bit length, multiple of 64.
	pad := 56 - len(b)%64
	if len(b)%64 >= 56 {
		pad += 64
	}
	msg := make([]byte, 0, len(b)+pad+8)
	msg = append(msg, b...)
	msg = append(msg, 0x80)
	msg = append(msg, make([]byte, pad-1)...)
	bitLen := uint64(len(b)) << 3
	for i := 0; i < 8; i++ {
		msg = append(msg, byte(bitLen>>(8*i)))
	}
	for len(msg) > 0 {
		s = ripemdBlock(s, msg[:64])
		msg = msg[64:]
	}
	var out [20]byte
	for i, v := range s {
		out[i*4] = byte(v)
		out[i*4+1] = byte(v >> 8)
		out[i*4+2] = byte(v >> 16)
		out[i*4+3] = byte(v >> 24)
	}
	return out
}
