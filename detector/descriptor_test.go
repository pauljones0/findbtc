package detector

import (
	"math/rand"
	"os"
	"testing"
)

// Descriptor fixtures. The multi/rawtr vectors come from Bitcoin Core's
// descriptor_tests.cpp; the short vectors were minted by an independent
// Python reimplementation of DescriptorChecksum (verified against Core).

const descMulti = "sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjg09x5t"

const descRawTR = "rawtr(xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/86'/1'/0'/1/*)#4ur3xhft"

const descPK = "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)#gn28ywm7"

func TestDescriptorChecksumVectors(t *testing.T) {
	for _, v := range []string{descMulti, descRawTR, descPK} {
		payload, sum := splitDescriptor(v)
		if got := descriptorChecksum(payload); got != sum {
			t.Errorf("%s...: checksum %s, want %s", v[:20], got, sum)
		}
	}
	// A single flipped payload character must break the checksum.
	bad := descPK[:10] + "0" + descPK[11:]
	if payload, sum := splitDescriptor(bad); descriptorChecksum(payload) == sum {
		t.Error("flipped payload still validates")
	}
}

func splitDescriptor(v string) (string, string) {
	for i := len(v) - 1; i >= 0; i-- {
		if v[i] == '#' {
			return v[:i], v[i+1:]
		}
	}
	return v, ""
}

func TestFindDescriptors(t *testing.T) {
	buf := []byte("wallet dump: " + descPK + " then " + descRawTR + " end")
	matches := findDescriptors(buf, 100, true, true)
	if len(matches) != 2 {
		t.Fatalf("got %d matches, want 2", len(matches))
	}
	if string(buf[matches[0].startAbs-100:matches[0].endAbs-100]) != descPK {
		t.Errorf("first match spans %q", buf[matches[0].startAbs-100:matches[0].endAbs-100])
	}
	// Wrong checksum: same payload shape, must stay silent.
	dud := "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)#deadbeef"
	if m := findDescriptors([]byte(dud), 0, true, true); len(m) != 0 {
		t.Error("bad checksum must stay silent")
	}
	// Bare hash without parens is not a descriptor.
	if m := findDescriptors([]byte("issue #gn28ywm7 fixed"), 0, true, true); len(m) != 0 {
		t.Error("bare #hash must stay silent")
	}
	// Nine checksum characters is not a checksum.
	if m := findDescriptors([]byte(descPK+"q"), 0, true, true); len(m) != 0 {
		t.Error("9-char checksum must stay silent")
	}
}

func TestDescriptorNoiseCorpus(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	noise := make([]byte, 1<<20)
	if _, err := rng.Read(noise); err != nil {
		t.Fatal(err)
	}
	if m := findDescriptors(noise, 0, true, true); len(m) != 0 {
		t.Fatalf("noise: %d matches, want 0", len(m))
	}
	for _, f := range []string{"../LICENSE", "../README.md", "../GOALS.md", "../main.go"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if m := findDescriptors(raw, 0, true, true); len(m) != 0 {
			t.Errorf("%s: %d matches, want 0", f, len(m))
		}
	}
}
