package detector

import (
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Documented recall fixtures: each secrets-profile matcher must find
// its shape. All credential material below is fake (AWS's published
// example ID, all-A token bodies, a stub key block).
const (
	secretPEMcue = "deploy key:\n-----BEGIN OPENSSH PRIVATE KEY-----\nZHVtbXkta2V5LWJvZHktbm90LXJlYWw=\n-----END OPENSSH PRIVATE KEY-----\n"
	secretAWScue = "aws_access_key_id=AKIAIOSFODNN7EXAMPLE\n"
	secretGHcue  = "token=ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
)

func TestSecretsRecall(t *testing.T) {
	pemAt := strings.Index(secretPEMcue, "-----BEGIN")
	awsAt := strings.Index(secretAWScue, "AKIA")
	ghAt := strings.Index(secretGHcue, "ghp_")
	cases := []struct {
		name  string
		data  string
		label string
		start int
		len   int
	}{
		{"pem", secretPEMcue, "pem-private-key", pemAt, len("-----BEGIN OPENSSH PRIVATE KEY-----")},
		{"pem-rsa", "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n", "pem-private-key", 0, len("-----BEGIN RSA PRIVATE KEY-----")},
		{"pem-pgp", "x-----BEGIN PGP PRIVATE KEY BLOCK-----y", "pem-private-key", 1, len("-----BEGIN PGP PRIVATE KEY BLOCK-----")},
		{"aws", secretAWScue, "aws-access-key", awsAt, 20},
		{"github", secretGHcue, "github-token", ghAt, 40},
		{"github-oauth", "x=gho_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB;", "github-token", 2, 40},
	}
	for _, c := range cases {
		m := findSecrets([]byte(c.data), 1000, true, true)
		if len(m) != 1 {
			t.Errorf("%s: %d matches, want 1 (%v)", c.name, len(m), m)
			continue
		}
		if m[0].label != c.label || m[0].startAbs != 1000+int64(c.start) || m[0].endAbs != 1000+int64(c.start+c.len) {
			t.Errorf("%s: got %+v, want %s [%d,%d)", c.name, m[0], c.label, 1000+c.start, 1000+c.start+c.len)
		}
	}
	// Near-misses stay silent: truncated bodies, wrong alphabets, and
	// lookalike prefixes must not match.
	misses := []string{
		"-----BEGIN PUBLIC KEY-----\nAAAA\n",
		"-----BEGIN RSA PUBLIC KEY-----\n",
		"AKIAIOSFODNN7EXAMPL",    // 15-char body, one short
		"AKIAiosfodnn7example00", // lowercase body
		"ghp_short",
	}
	for i, data := range misses {
		if m := findSecrets([]byte(data), 0, true, true); len(m) != 0 {
			t.Errorf("miss %d (%q): %d matches, want 0", i, data, len(m))
		}
	}
	// An overlong body still holds a valid token at offset 0: the
	// maximal run starts with prefix + 36 valid chars.
	long := "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 37-char body
	if m := findSecrets([]byte(long), 0, true, true); len(m) != 1 || m[0].startAbs != 0 || m[0].endAbs != 40 {
		t.Errorf("long body: got %v, want one token [0,40)", m)
	}
}

// The Goal 6 FP bar for the secrets matchers: silence on 1MB of random
// bytes and on the project's own prose.
func TestSecretsNoiseCorpus(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	noise := make([]byte, 1<<20)
	if _, err := rng.Read(noise); err != nil {
		t.Fatal(err)
	}
	if m := findSecrets(noise, 0, true, true); len(m) != 0 {
		t.Fatalf("noise: %d matches, want 0 (%v)", len(m), m[:min(3, len(m))])
	}
	for _, f := range []string{"../LICENSE", "../README.md", "../GOALS.md", "../main.go"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if m := findSecrets(raw, 0, true, true); len(m) != 0 {
			t.Errorf("%s: %d matches, want 0 (%v)", f, len(m), m[:min(3, len(m))])
		}
	}
}

// End to end: the secrets profile finds all three shapes plus wallet
// needles in one scan, with labels and offsets only.
func TestSecretsProfileEndToEnd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leak.bin")
	buf := make([]byte, 1<<16)
	copy(buf[100:], "bestblock")
	copy(buf[5000:], secretPEMcue)
	copy(buf[9000:], secretAWScue)
	copy(buf[12000:], secretGHcue)
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}
	var dets []Detection
	if err := ScanWithOptions(0, path, Options{Profile: "secrets"},
		func(d Detection) { dets = append(dets, d) }, nil); err != nil {
		t.Fatal(err)
	}
	labels := map[string]int64{}
	for _, d := range dets {
		labels[d.Needle] = d.Offset
		// Labels and offsets only: no key, token, or block bytes.
		for _, leak := range []string{"AKIA", "ghp_", "BEGIN", "PRIVATE KEY"} {
			if strings.Contains(d.Description, leak) {
				t.Errorf("description leaks material: %q", d.Description)
			}
		}
	}
	want := map[string]int64{
		"bestblock":       100,
		"pem-private-key": 5000 + int64(strings.Index(secretPEMcue, "-----BEGIN")),
		"aws-access-key":  9000 + int64(strings.Index(secretAWScue, "AKIA")),
		"github-token":    12000 + int64(strings.Index(secretGHcue, "ghp_")),
	}
	for label, off := range want {
		if got, ok := labels[label]; !ok {
			t.Errorf("missing %s (got %v)", label, labels)
		} else if got != off {
			t.Errorf("%s at %d, want %d", label, got, off)
		}
	}
}

// The default profile is byte-identical with secrets present: wallet
// detections match the secrets-profile run exactly, and secret shapes
// alone produce nothing.
func TestDefaultProfileEquivalence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mixed.bin")
	buf := make([]byte, 1<<16)
	copy(buf[100:], "bestblock")
	copy(buf[200:], "crypted_key")
	copy(buf[5000:], secretPEMcue)
	copy(buf[9000:], secretAWScue)
	copy(buf[12000:], secretGHcue)
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}
	scan := func(profile string) []Detection {
		t.Helper()
		var dets []Detection
		if err := ScanWithOptions(0, path, Options{Profile: profile},
			func(d Detection) { dets = append(dets, d) }, nil); err != nil {
			t.Fatalf("profile %q: %v", profile, err)
		}
		return dets
	}
	def, sec := scan(""), scan("secrets")
	var secWallet []Detection
	for _, d := range sec {
		switch d.Needle {
		case "pem-private-key", "aws-access-key", "github-token":
		default:
			secWallet = append(secWallet, d)
		}
	}
	rawDef, _ := json.Marshal(def)
	rawSec, _ := json.Marshal(secWallet)
	if string(rawDef) != string(rawSec) {
		t.Errorf("default-profile detections differ:\ndefault: %s\nsecrets-minus-secrets: %s", rawDef, rawSec)
	}
	foundSecret := false
	for _, d := range sec {
		if d.Needle == "pem-private-key" || d.Needle == "aws-access-key" || d.Needle == "github-token" {
			foundSecret = true
		}
	}
	if !foundSecret {
		t.Error("secrets profile found no secret shapes on the mixed fixture")
	}
	for _, d := range def {
		if d.Needle == "pem-private-key" || d.Needle == "aws-access-key" || d.Needle == "github-token" {
			t.Errorf("default profile leaked a secret detection: %+v", d)
		}
	}
	// Secrets alone: the default profile stays silent.
	only := filepath.Join(t.TempDir(), "only.bin")
	raw := make([]byte, 8192)
	copy(raw[100:], secretPEMcue)
	copy(raw[2000:], secretAWScue)
	if err := os.WriteFile(only, raw, 0644); err != nil {
		t.Fatal(err)
	}
	var dets []Detection
	if err := ScanWithOptions(0, only, Options{}, func(d Detection) { dets = append(dets, d) }, nil); err != nil {
		t.Fatal(err)
	}
	if len(dets) != 0 {
		t.Errorf("default profile on secrets-only input: %v", dets)
	}
}

func TestUnknownProfileRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.bin")
	if err := os.WriteFile(path, []byte("bestblock"), 0644); err != nil {
		t.Fatal(err)
	}
	err := ScanWithOptions(0, path, Options{Profile: "bogus"}, nil, nil)
	if err == nil {
		t.Fatal("unknown profile must fail")
	}
	if !strings.Contains(err.Error(), `unknown scan profile "bogus"`) {
		t.Errorf("refusal must name the profile: %v", err)
	}
}
