package detector

import (
	"bytes"
	"encoding/base64"
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
// never verified online (both are explicit non-goals). DER-family PEM
// bodies ARE inspected structurally (Goal 30: base64-decode plus a
// tag-and-length SEQUENCE parse, in memory only) so truncated and
// garbage bodies stay silent instead of reporting on a header alone.
// See the privacy audit in docs/SECRETS_PROFILE.md for exactly which
// bytes are touched.

// secretsMaxSpan bounds the byte length of a reported secret match.
// Like every span const it must stay far below the block overlap
// window (see TestScanOverlapBelowBlockSize).
const secretsMaxSpan = 64

type secretMatch struct {
	label            string
	kind             string // for descriptions, e.g. "private-key block"
	startAbs, endAbs int64
	verified         bool // body structurally validated (DER family only)
}

// pemAnchor is one armored private-key header. der marks the DER
// family (PKCS#8, PKCS#1 variants, encrypted PKCS#8), whose bodies
// must base64-decode and parse as a DER SEQUENCE or the header alone
// does not report. OpenSSH and PGP bodies are not DER, so those stay
// header-only matches and never verify.
type pemAnchor struct {
	header []byte
	der    bool
}

var pemAnchors = []pemAnchor{
	{[]byte("-----BEGIN PRIVATE KEY-----"), true},
	{[]byte("-----BEGIN RSA PRIVATE KEY-----"), true},
	{[]byte("-----BEGIN DSA PRIVATE KEY-----"), true},
	{[]byte("-----BEGIN EC PRIVATE KEY-----"), true},
	{[]byte("-----BEGIN OPENSSH PRIVATE KEY-----"), false},
	{[]byte("-----BEGIN ENCRYPTED PRIVATE KEY-----"), true},
	{[]byte("-----BEGIN PGP PRIVATE KEY BLOCK-----"), false},
}

// pemBodyCaps bound structural validation: 256 body lines and 64KB
// of base64 cover absurd keys (RSA-16384 is ~200 lines) while a
// header glued to megabytes of alphabet soup stays cheap to reject.
const (
	pemMaxBodyLines = 256
	pemMaxBodyBytes = 64 << 10
	// pemMinDERBytes floors plausible private-key DER: real keys
	// start near a hundred bytes; anything smaller that "parses" is
	// a coincidental SEQUENCE tag, not a key.
	pemMinDERBytes = 32
)

var pemEndPrefix = []byte("-----END")

func isBase64Line(line []byte) bool {
	if len(line) == 0 {
		return false
	}
	for _, b := range line {
		if b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '+' || b == '/' || b == '=' {
			continue
		}
		return false
	}
	return true
}

// pemBodyVerdict classifies a DER-family body: valid (decodes and
// parses), malformed (provably not a key — suppress), or unknown
// (ran into the window edge on a non-final block — the body may
// continue past what this block holds).
type pemBodyVerdict int

const (
	pemValid pemBodyVerdict = iota
	pemMalformed
	pemUnknown
)

// validatePEMBody reads the lines after a DER-family header within
// the window. final reports whether the window ends the target: only
// then is a missing END line evidence rather than a window edge.
func validatePEMBody(after []byte, final bool) pemBodyVerdict {
	// Skip to the first body line: anything else on the header line
	// is junk, and junk there means a forged header.
	nl := bytes.IndexByte(after, '\n')
	if nl < 0 {
		if final {
			return pemMalformed
		}
		return pemUnknown
	}
	rest := after[nl+1:]
	var body []byte
	lines := 0
	complete := false
	for len(rest) > 0 {
		var line []byte
		if i := bytes.IndexByte(rest, '\n'); i < 0 {
			line, rest = rest, nil
		} else {
			line, rest = rest[:i], rest[i+1:]
		}
		line = bytes.TrimSuffix(line, []byte("\r"))
		if bytes.HasPrefix(line, pemEndPrefix) {
			complete = true
			break
		}
		if len(line) == 0 {
			continue
		}
		if !isBase64Line(line) {
			// Body ended in garbage: whatever accumulated is all
			// there is. A complete key before noise still counts.
			complete = true
			break
		}
		body = append(body, line...)
		lines++
		if lines > pemMaxBodyLines || len(body) > pemMaxBodyBytes {
			complete = true
			break
		}
	}
	if !complete && !final {
		return pemUnknown
	}
	if parseDERSequence(decodeBase64(body)) {
		return pemValid
	}
	return pemMalformed
}

func decodeBase64(body []byte) []byte {
	if len(body) == 0 || len(body)%4 != 0 {
		return nil
	}
	der := make([]byte, base64.StdEncoding.DecodedLen(len(body)))
	n, err := base64.StdEncoding.Decode(der, body)
	if err != nil {
		return nil
	}
	return der[:n]
}

// parseDERSequence reports whether der is exactly one DER SEQUENCE:
// tag 0x30, well-formed definite length (minimal encoding), total
// length matching the buffer, and a plausible key size. Only the tag
// and length octets are read — never key fields.
func parseDERSequence(der []byte) bool {
	if len(der) < pemMinDERBytes || der[0] != 0x30 {
		return false
	}
	b := der[1]
	var ln, hdr int
	if b < 0x80 {
		ln, hdr = int(b), 2
	} else {
		n := int(b & 0x7f)
		if n == 0 || n > 4 || 2+n > len(der) {
			return false
		}
		for _, c := range der[2 : 2+n] {
			ln = ln<<8 | int(c)
		}
		hdr = 2 + n
		if ln < 128 {
			return false // non-minimal long form
		}
	}
	return hdr+ln == len(der)
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
	for _, anchor := range pemAnchors {
		for i := 0; i+len(anchor.header) <= len(data); {
			j := bytes.Index(data[i:], anchor.header)
			if j == -1 {
				break
			}
			abs := i + j
			start := baseAbs + int64(abs)
			end := start + int64(len(anchor.header))
			if anchor.der {
				switch validatePEMBody(data[abs+len(anchor.header):], final) {
				case pemMalformed:
					i = abs + 1
					continue
				case pemValid:
					matches = append(matches, secretMatch{"pem-private-key", "private-key block", start, end, true})
				case pemUnknown:
					matches = append(matches, secretMatch{"pem-private-key", "private-key block", start, end, false})
				}
			} else {
				matches = append(matches, secretMatch{"pem-private-key", "private-key block", start, end, false})
			}
			i = abs + 1
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
				out = append(out, secretMatch{"aws-access-key", "access key ID", baseAbs + int64(i), baseAbs + int64(i+20), false})
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
				out = append(out, secretMatch{"github-token", "token", baseAbs + int64(i), baseAbs + int64(i+40), false})
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
