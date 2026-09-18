package detector

// Fuzzing for the hostile-input parsers: every byte here can come straight
// off a disk. Beyond crashing, each target asserts its output invariants.

import (
	"bytes"
	"testing"
)

func FuzzBIP39(f *testing.F) {
	f.Add([]byte("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"), int64(0), byte(0))
	f.Add([]byte("xx abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about yy"), int64(0), byte(1))
	f.Add([]byte{}, int64(0), byte(2))
	f.Add([]byte("a"), int64(0), byte(3))
	f.Add(bytes.Repeat([]byte{'a'}, 600), int64(0), byte(0))
	f.Add([]byte("abandon\x00abandon\nABANDON\tability able about zoo zoo zoo"), int64(0), byte(1))
	f.Fuzz(func(t *testing.T, data []byte, base int64, flags byte) {
		if len(data) > 8192 {
			t.Skip()
		}
		if base < 0 || base > 1<<40 {
			t.Skip()
		}
		first, final := flags&1 != 0, flags&2 != 0
		for _, m := range findBIP39(data, base, first, final) {
			if m.startAbs < base || m.endAbs > base+int64(len(data)) || m.startAbs >= m.endAbs {
				t.Fatalf("match out of bounds: %+v base %d len %d", m, base, len(data))
			}
			if m.endAbs-m.startAbs > bip39MaxSpan {
				t.Fatalf("match exceeds max span: %+v", m)
			}
			if m.words != 12 && m.words != 15 && m.words != 18 && m.words != 21 && m.words != 24 {
				t.Fatalf("bad word count: %+v", m)
			}
		}
		_, near, unordered := findBIP39Phrases(data, base, first, final)
		for _, m := range near {
			if m.startAbs < base || m.endAbs > base+int64(len(data)) || m.startAbs >= m.endAbs {
				t.Fatalf("near-miss out of bounds: %+v base %d len %d", m, base, len(data))
			}
			if m.endAbs-m.startAbs > bip39MaxSpan {
				t.Fatalf("near-miss exceeds max span: %+v", m)
			}
			if len(m.gaps) == 0 || len(m.gaps) > bip39MaxUnknown {
				t.Fatalf("bad gap count: %+v", m)
			}
			for _, g := range m.gaps {
				if g < 0 || g >= m.words {
					t.Fatalf("gap out of range: %+v", m)
				}
			}
			if len(m.typo) != len(m.gaps) || len(m.validating) != len(m.gaps) {
				t.Fatalf("gap counts misaligned: %+v", m)
			}
			for i := range m.gaps {
				if m.validating[i] > m.typo[i] {
					t.Fatalf("validating exceeds typo: %+v", m)
				}
			}
		}
		for _, u := range unordered {
			if u.startAbs < base || u.endAbs > base+int64(len(data)) || u.startAbs >= u.endAbs {
				t.Fatalf("unordered out of bounds: %+v base %d len %d", u, base, len(data))
			}
			if u.words < bip39MinUnorderedRun {
				t.Fatalf("short unordered run: %+v", u)
			}
		}
	})
}

func FuzzKeys(f *testing.F) {
	f.Add([]byte("5HpjKrb7dH5kKQQzmbjB87Mxova7mek5bXUTWfndcX6tBoqUwzm"), int64(0), byte(0))
	f.Add([]byte(" KwFfpDsaF7yxCELuyrH9gP5XL7TAt5b9HPWC1xCQbmrxvhJgMQHb "), int64(0), byte(1))
	f.Add([]byte("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"), int64(0), byte(2))
	f.Add([]byte{}, int64(0), byte(3))
	f.Add([]byte("5"), int64(0), byte(0))
	f.Add([]byte("xprv"), int64(0), byte(1))
	f.Add(bytes.Repeat([]byte{'5'}, 200), int64(0), byte(2))
	f.Add(bytes.Repeat([]byte{'1'}, 200), int64(0), byte(3))
	f.Fuzz(func(t *testing.T, data []byte, base int64, flags byte) {
		if len(data) > 8192 {
			t.Skip()
		}
		if base < 0 || base > 1<<40 {
			t.Skip()
		}
		first, final := flags&1 != 0, flags&2 != 0
		for _, m := range findKeys(data, base, first, final) {
			if m.startAbs < base || m.endAbs > base+int64(len(data)) || m.startAbs >= m.endAbs {
				t.Fatalf("match out of bounds: %+v base %d len %d", m, base, len(data))
			}
			span := m.endAbs - m.startAbs
			if span != 51 && span != 52 && span != 111 {
				t.Fatalf("bad key span %d: %+v", span, m)
			}
			if m.label == "" || m.kind == "" {
				t.Fatalf("empty label: %+v", m)
			}
		}
	})
}

func FuzzKeystore(f *testing.F) {
	f.Add([]byte(`{"address":"abababababababababababababababababababab","crypto":{"cipher":"aes-128-ctr","ciphertext":"d172bf74","kdf":"scrypt"}}`), int64(0))
	f.Add([]byte(`xx {"address":"abababababababababababababababababababab","crypto":{"cipher":"c","ciphertext":"ab12","kdf":"k"}} yy`), int64(0))
	f.Add([]byte(`{"ciphertext":}`), int64(0))
	f.Add([]byte{}, int64(0))
	f.Add([]byte("{"), int64(0))
	f.Add(bytes.Repeat([]byte{'{'}, 100), int64(0))
	f.Add([]byte(`{"a":"\"quoted\" braces { inside string","ciphertext":"ab12"}`), int64(0))
	f.Fuzz(func(t *testing.T, data []byte, base int64) {
		if len(data) > 8192 {
			t.Skip()
		}
		if base < 0 || base > 1<<40 {
			t.Skip()
		}
		for _, m := range findKeystores(data, base) {
			if m.startAbs < base || m.endAbs > base+int64(len(data)) || m.startAbs >= m.endAbs {
				t.Fatalf("match out of bounds: %+v base %d len %d", m, base, len(data))
			}
			if m.endAbs-m.startAbs > keystoreMaxSpan {
				t.Fatalf("match exceeds max span: %+v", m)
			}
		}
	})
}

func FuzzBase58(f *testing.F) {
	f.Add("5HpjKrb7dH5kKQQzmbjB87Mxova7mek5bXUTWfndcX6tBoqUwzm")
	f.Add("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
	f.Add("")
	f.Add("1")
	f.Add("0OIl") // non-alphabet
	f.Add("111111111111111111111111111111111111111111111111111")
	f.Fuzz(func(t *testing.T, s string) {
		out, ok := base58Decode(s)
		if !ok {
			return
		}
		if len(out) > len(s) {
			t.Fatalf("decoded %d bytes from %d chars", len(out), len(s))
		}
		again, ok2 := base58Decode(s)
		if !ok2 || !bytes.Equal(out, again) {
			t.Fatalf("nondeterministic decode of %q", s)
		}
		if _, ok := base58CheckDecode(s); ok && len(out) < 5 {
			t.Fatalf("check decode accepted %d bytes", len(out))
		}
	})
}

// memSource serves fuzz bytes as a scan target so header parsing exercises
// both the block-contained and ReadAt paths.
type memSource struct {
	data []byte
}

func (s *memSource) Describe() string     { return "mem" }
func (s *memSource) StartOffset() int64   { return 0 }
func (s *memSource) Size() (int64, error) { return int64(len(s.data)), nil }
func (s *memSource) Open() (TargetReader, error) {
	return &closableBytesReader{bytes.NewReader(s.data)}, nil
}
func (s *memSource) Depth() int { return 0 }

func FuzzZipLocalHeader(f *testing.F) {
	f.Add(append([]byte{0x50, 0x4b, 0x03, 0x04, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0}, []byte("a.txtHELLO")...), 0)
	f.Add([]byte("PK\x03\x04"), 0)
	f.Add([]byte{}, 0)
	f.Add(bytes.Repeat([]byte{0x50}, 100), 3)
	f.Fuzz(func(t *testing.T, data []byte, hdr int) {
		if len(data) > 8192 {
			t.Skip()
		}
		// Header offsets roam slightly past the edges to hit boundary code.
		off := int64(hdr)
		span := int64(len(data)) + 32
		if span <= 0 {
			span = 32
		}
		off = ((off%span)+span)%span - 16
		src := &memSource{data: data}
		c, ok := parseZipCandidate(src, data, off, 0, int64(len(data)))
		if !ok {
			return
		}
		if c.dataOff < off+30 || c.compSize <= 0 || c.uncompSize <= 0 {
			t.Fatalf("bad candidate geometry: %+v", c)
		}
		if c.method != 0 && c.method != 8 {
			t.Fatalf("bad method: %+v", c)
		}
	})
}
