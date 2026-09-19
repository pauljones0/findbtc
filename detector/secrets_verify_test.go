package detector

// Offline structural verification for PEM blocks (Goal 30): DER-family
// bodies must base64-decode and parse as a DER SEQUENCE or they do
// not report. Verified hits carry confidence; malformed bodies are
// silent; bodies cut by the window edge report unverified.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"
)

// genPEMBlock returns an armored block of fresh random key material.
// Nothing here is a real credential: keys are generated, armored,
// and discarded within the test.
func genPEMBlock(t *testing.T, typ string) string {
	t.Helper()
	var der []byte
	switch typ {
	case "RSA PRIVATE KEY":
		key, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatal(err)
		}
		der = x509.MarshalPKCS1PrivateKey(key)
	case "PRIVATE KEY":
		key, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatal(err)
		}
		if der, err = x509.MarshalPKCS8PrivateKey(key); err != nil {
			t.Fatal(err)
		}
	case "EC PRIVATE KEY":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if der, err = x509.MarshalECPrivateKey(key); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown block type %q", typ)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))
}

func TestPEMStructuralVerification(t *testing.T) {
	rsaBlock := genPEMBlock(t, "RSA PRIVATE KEY")
	pkcs8Block := genPEMBlock(t, "PRIVATE KEY")
	ecBlock := genPEMBlock(t, "EC PRIVATE KEY")
	// Hand-built DER envelope (any SEQUENCE passes: the check reads
	// the tag and length octets, never key fields).
	minDER := "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
		"MCIBAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEi\n" +
		"-----END ENCRYPTED PRIVATE KEY-----\n"
	cases := []struct {
		name     string
		data     string
		final    bool
		want     int
		verified bool
	}{
		{"rsa-valid", rsaBlock, true, 1, true},
		{"pkcs8-valid", pkcs8Block, true, 1, true},
		{"ec-valid", ecBlock, true, 1, true},
		{"envelope-valid", minDER, true, 1, true},
		{"crlf-valid", strings.ReplaceAll(rsaBlock, "\n", "\r\n"), true, 1, true},
		{"truncated-body", rsaBlock[:len(rsaBlock)/2], true, 0, false},
		{"truncated-end", rsaBlock[:len(rsaBlock)-60] + "-----END RSA PRIVATE KEY-----\n", true, 0, false},
		{"garbage-body", "-----BEGIN RSA PRIVATE KEY-----\n!!!not-base64!!!\n-----END RSA PRIVATE KEY-----\n", true, 0, false},
		{"short-body", "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n", true, 0, false},
		{"header-only", "-----BEGIN RSA PRIVATE KEY-----\n", true, 0, false},
		{"valid-before-noise", rsaBlock + "GARBAGE\x00\x01LINE\n", true, 1, true},
		{"window-cut", rsaBlock[:len(rsaBlock)/2], false, 1, false},
		{"openssh-stub", secretPEMcue, true, 1, false},
		{"pgp-header", "x-----BEGIN PGP PRIVATE KEY BLOCK-----y", true, 1, false},
	}
	for _, c := range cases {
		m := findSecrets([]byte(c.data), 0, true, c.final)
		if len(m) != c.want {
			t.Errorf("%s: %d matches, want %d", c.name, len(m), c.want)
			continue
		}
		if c.want == 1 && m[0].verified != c.verified {
			t.Errorf("%s: verified=%v, want %v", c.name, m[0].verified, c.verified)
		}
	}
	// An absurdly long undecodable body is garbage, not a key.
	var huge strings.Builder
	huge.WriteString("-----BEGIN RSA PRIVATE KEY-----\n")
	for i := 0; i < 300; i++ {
		huge.WriteString(strings.Repeat("A", 64) + "\n")
	}
	if m := findSecrets([]byte(huge.String()), 0, true, true); len(m) != 0 {
		t.Errorf("huge body: %d matches, want 0", len(m))
	}
}

func TestPEMVerifiedEndToEnd(t *testing.T) {
	block := genPEMBlock(t, "RSA PRIVATE KEY")
	path := writeTempFile(t, "keyscan.bin", "prefix\n"+block+"suffix\n")
	var dets []Detection
	if err := ScanWithOptions(0, path, Options{Profile: "secrets"},
		func(d Detection) { dets = append(dets, d) }, nil); err != nil {
		t.Fatal(err)
	}
	if len(dets) != 1 || dets[0].Needle != "pem-private-key" {
		t.Fatalf("detections = %+v, want 1 pem hit", dets)
	}
	if !dets[0].Verified {
		t.Error("structurally valid PEM must carry Verified")
	}
	if dets[0].MatchLen != len("-----BEGIN RSA PRIVATE KEY-----") {
		t.Errorf("match span %d covers more than the header", dets[0].MatchLen)
	}
}

func TestPEMConfidenceInReport(t *testing.T) {
	mk := func(verified bool, off int64) Detection {
		return Detection{Description: "d", Needle: "pem-private-key", Offset: off,
			Target: "t", BlockOffset: 0, MatchLen: 31, Verified: verified}
	}
	rep := Summarize([]Detection{mk(true, 1), mk(false, 2)})
	got := map[int64]string{}
	for _, h := range rep.Hits {
		got[h.Offset] = h.Confidence
	}
	if got[1] != "high" || got[2] != "medium" {
		t.Errorf("confidence = %v, want offset1=high offset2=medium", got)
	}
}

func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	path := t.TempDir() + "/" + name
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}
