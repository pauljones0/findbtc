package detector

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// Baselines (Goal 29): repeat -walk sweeps re-report known findings,
// so accepted hits are fingerprinted and suppressed on later sweeps
// while new hits still report. The fingerprint must survive file
// edits — raw offsets do not — so each finding is keyed by the
// repository-relative path, the needle, and a hash of the full line
// holding the match:
//
//	v1/<relpath>/<needle>/<line-sha256-64>
//
// Appending lines, inserting lines above the hit, and rewriting the
// file around it all leave the key unchanged. Changing the line
// (rotating a secret), adding a same-type secret elsewhere in the
// file, or converting line endings changes the key, so the finding
// reports again — the safe direction for hygiene. Fingerprints record
// hashes, never secret bytes, but a low-entropy line stays guessable
// from its hash: store baselines with the usual care.
//
// Fingerprints are computed for every -walk detection (the baseline
// file is just a reviewed hits.jsonl from a prior sweep) and matched
// by exact string equality: no fuzzy matching, no auto-update.

// FingerprintFinding keys one walk detection for baseline matching.
// root is the walked tree (absolute); target the scanned file;
// needle and offset locate the match. "" means unfingerprintable
// (unreadable file, unrelativizable path): such findings always
// report, never suppress.
func FingerprintFinding(root, target, needle string, offset int64, matchLen int) string {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return ""
	}
	line, err := matchLine(target, offset, matchLen)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(line)
	return "v1/" + filepath.ToSlash(rel) + "/" + needle + "/" + hex.EncodeToString(sum[:8])
}

// matchLineWindow bounds the hunt for the line holding a match: 4KB
// back for the start, 8KB forward for the end. Binary files and
// minified giants hit the caps and fingerprint the capped window,
// which is still stable across edits elsewhere.
const matchLineWindow = 4096

func matchLine(path string, offset int64, matchLen int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	if offset < 0 || offset >= size {
		return nil, fmt.Errorf("offset %d outside %s (%d bytes)", offset, path, size)
	}
	start := offset - matchLineWindow
	if start < 0 {
		start = 0
	}
	end := offset + int64(matchLen) + 2*matchLineWindow
	if end > size {
		end = size
	}
	win := make([]byte, end-start)
	if _, err := f.ReadAt(win, start); err != nil {
		return nil, err
	}
	rel := offset - start
	var lineStart int64
	for i := rel; i >= 0; i-- {
		if win[i] == '\n' {
			lineStart = i + 1
			break
		}
	}
	lineEnd := int64(len(win))
	for i := rel + int64(matchLen); i < int64(len(win)); i++ {
		if win[i] == '\n' {
			lineEnd = i
			break
		}
	}
	return win[lineStart:lineEnd], nil
}

// LoadBaselineFingerprints reads a reviewed hits.jsonl sweep and
// returns its fingerprint set for suppression. Findings without a
// fingerprint (pre-baseline sidecars, other modes) contribute
// nothing: they can neither suppress nor be suppressed by key.
func LoadBaselineFingerprints(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot load baseline %s: %w", path, err)
	}
	defer f.Close()
	dets, err := ReadDetections(f)
	if err != nil {
		return nil, fmt.Errorf("cannot parse baseline %s: %w", path, err)
	}
	out := map[string]bool{}
	for _, d := range dets {
		if d.Fingerprint != "" {
			out[d.Fingerprint] = true
		}
	}
	return out, nil
}
