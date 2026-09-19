package detector

import (
	"bytes"
	"fmt"
)

// Opt-in secret profiles (Goal 20): non-wallet matchers for secret
// hygiene on repos, laptops, and images. They run only when
// Options.Profile selects them — the default profile never calls
// findSecrets, so default behavior is byte-identical with or without
// this file.
//
// Matches carry labels and offsets only, never secret material.
// Private-key derivation is never attempted and found secrets are
// never verified online (both are explicit non-goals).

// secretsMaxSpan bounds the byte length of a reported secret match.
// Like every span const it must stay far below the block overlap
// window (see TestScanOverlapBelowBlockSize).
const secretsMaxSpan = 64

type secretMatch struct {
	label            string
	kind             string // for descriptions, e.g. "private-key block"
	startAbs, endAbs int64
}

// pemHeaders anchors armored private-key blocks. Only the header line
// matches: the key body that follows is never inspected, hashed, or
// derived from.
var pemHeaders = [][]byte{
	[]byte("-----BEGIN PRIVATE KEY-----"),
	[]byte("-----BEGIN RSA PRIVATE KEY-----"),
	[]byte("-----BEGIN DSA PRIVATE KEY-----"),
	[]byte("-----BEGIN EC PRIVATE KEY-----"),
	[]byte("-----BEGIN OPENSSH PRIVATE KEY-----"),
	[]byte("-----BEGIN ENCRYPTED PRIVATE KEY-----"),
	[]byte("-----BEGIN PGP PRIVATE KEY BLOCK-----"),
}

// githubPrefixes are the GitHub token families sharing the 36-char
// base62 body shape (PATs, OAuth, user, server, refresh tokens).
var githubPrefixes = []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"}

func isTokenChar(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b == '_'
}

func isUpperAlnum(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'A' && b <= 'Z'
}

func isBase62(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z'
}

// findSecrets returns every private-key block and credential shape
// fully contained in data. PEM anchors are fixed literals matched on
// the raw data (overlap covers splits, exactly-once is enforced at
// emission); token shapes scan trimmed runs so a token split across a
// block edge is evaluated whole in the neighboring block instead.
func findSecrets(data []byte, baseAbs int64, first, final bool) []secretMatch {
	var matches []secretMatch
	for _, anchor := range pemHeaders {
		for i := 0; i+len(anchor) <= len(data); {
			j := bytes.Index(data[i:], anchor)
			if j == -1 {
				break
			}
			start := baseAbs + int64(i+j)
			matches = append(matches, secretMatch{"pem-private-key", "private-key block", start, start + int64(len(anchor))})
			i += j + 1
		}
	}
	trimmed, off := trimEdgeFragments(data, first, final, isTokenChar)
	tbase := baseAbs + int64(off)
	for i := 0; i < len(trimmed); {
		if !isTokenChar(trimmed[i]) {
			i++
			continue
		}
		j := i
		for j < len(trimmed) && isTokenChar(trimmed[j]) {
			j++
		}
		matches = append(matches, scanSecretRun(trimmed[i:j], tbase+int64(i))...)
		i = j
	}
	return matches
}

func scanSecretRun(run []byte, baseAbs int64) []secretMatch {
	var out []secretMatch
	for i := 0; i < len(run); i++ {
		// AWS access key ID: AKIA + 16 uppercase alphanumerics.
		if i+20 <= len(run) && string(run[i:i+4]) == "AKIA" {
			ok := true
			for _, b := range run[i+4 : i+20] {
				if !isUpperAlnum(b) {
					ok = false
					break
				}
			}
			if ok {
				out = append(out, secretMatch{"aws-access-key", "access key ID", baseAbs + int64(i), baseAbs + int64(i+20)})
			}
		}
		// GitHub tokens: family prefix + 36 base62 chars.
		for _, p := range githubPrefixes {
			if i+4+36 > len(run) || string(run[i:i+4]) != p {
				continue
			}
			ok := true
			for _, b := range run[i+4 : i+40] {
				if !isBase62(b) {
					ok = false
					break
				}
			}
			if ok {
				out = append(out, secretMatch{"github-token", "token", baseAbs + int64(i), baseAbs + int64(i+40)})
			}
			break
		}
	}
	return out
}

// secretDescription renders a match without secret material.
func secretDescription(label, kind, location string) string {
	return fmt.Sprintf("Found '%s %s' at %s", label, kind, location)
}
