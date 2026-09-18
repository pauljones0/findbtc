package detector

import (
	"fmt"
	"strings"
)

// Bech32 segwit-address encoding (BIP173), encode-only: watch-only export
// produces addresses but never parses them.

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func bech32Polymod(values []int) int {
	gen := []int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := 1
	for _, v := range values {
		b := chk >> 25
		chk = ((chk & 0x1ffffff) << 5) ^ v
		for i := 0; i < 5; i++ {
			if (b>>i)&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func bech32HRPExpand(hrp string) []int {
	out := make([]int, 0, 2*len(hrp)+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, int(hrp[i]>>5))
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, int(hrp[i]&31))
	}
	return out
}

// convertBits regroups data from fromBits to toBits, padding the tail.
func convertBits(data []byte, fromBits, toBits uint) ([]int, error) {
	var out []int
	acc, bits := 0, uint(0)
	maxv := (1 << toBits) - 1
	for _, b := range data {
		acc = (acc << fromBits) | int(b)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			out = append(out, (acc>>bits)&maxv)
		}
	}
	if bits > 0 {
		out = append(out, (acc<<(toBits-bits))&maxv)
	}
	return out, nil
}

// bech32SegwitEncode renders a version/program pair as a segwit address.
// Only version 0 (P2WPKH/P2WSH lengths) is supported; watch-only derivation
// never produces anything else.
func bech32SegwitEncode(hrp string, version byte, program []byte) (string, error) {
	if version != 0 {
		return "", fmt.Errorf("unsupported witness version %d", version)
	}
	if len(program) != 20 && len(program) != 32 {
		return "", fmt.Errorf("unsupported witness program length %d", len(program))
	}
	hrp = strings.ToLower(hrp)
	data, err := convertBits(program, 8, 5)
	if err != nil {
		return "", err
	}
	values := append([]int{int(version)}, data...)
	pm := bech32Polymod(append(bech32HRPExpand(hrp), append(values, 0, 0, 0, 0, 0, 0)...)) ^ 1
	var b strings.Builder
	b.WriteString(hrp)
	b.WriteByte('1')
	for _, v := range values {
		b.WriteByte(bech32Charset[v])
	}
	for i := 0; i < 6; i++ {
		b.WriteByte(bech32Charset[(pm>>(5*(5-i)))&31])
	}
	return b.String(), nil
}
