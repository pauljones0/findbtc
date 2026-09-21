package detector

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"strconv"
	"strings"
)

// ProofVersion is the only prefix-proof version this binary verifies.
// Journals carrying any other version rescan: an unknown proof shape
// authorizes nothing.
const ProofVersion = 1

// PrefixProof pins the exact bytes a journaled frontier was produced
// from: SHA-256 over the consumed stream's span [Start, Start+Len).
// Whole-file frontiers prove from stream base (Start 0); range-scan
// active frontiers prove from their range start. The proof is byte
// identity, independent of the coverage offset filed beside it: an
// error path may rewind the offset to the last proven point while
// the proof still pins every byte read this run, so banked members
// from proven bytes survive the rewind.
//
// A frontier offset O is honored only with a proof whose span
// covers [streamBase, O): the resume re-reads the whole span from
// the opened handle and compares. Anything else — missing proof,
// wrong base, short span, mismatch, read error — rescans from the
// stream base with banked members dropped. Metadata identity is only
// a cheap rejection tier in front of this check, never an
// authorization: see cheapTierPass.
type PrefixProof struct {
	Version int    `json:"version,omitempty"`
	Start   int64  `json:"start,omitempty"`
	Len     int64  `json:"len,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
}

// RangeProof pins one completed range of a range-scan journal: the
// full span [Start, Start+Len) with its content hash. Resume
// re-reads and verifies every completed range before skipping it;
// the first unverified range restarts the list there.
type RangeProof struct {
	Version int    `json:"version,omitempty"`
	Index   int    `json:"index,omitempty"`
	Start   int64  `json:"start,omitempty"`
	Len     int64  `json:"len,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
}

// validPrefixProof reports whether p is well-formed (structurally;
// content verification is verifySpan). Malformed proofs are corrupt
// journals and refuse, never silent rescans.
func validPrefixProof(p *PrefixProof) bool {
	return p != nil && p.Version == ProofVersion && p.Start >= 0 && p.Len >= 0 && isHexDigest(p.SHA256)
}

// validRangeProof reports whether p is well-formed.
func validRangeProof(p RangeProof) bool {
	return p.Version == ProofVersion && p.Index >= 0 && p.Start >= 0 && p.Len >= 0 && isHexDigest(p.SHA256)
}

// verifySpan re-reads [start, start+length) from r (positioned by
// Seek) and compares its SHA-256 against want. It returns the live
// hash state on success so the caller can keep streaming the run
// digest from the verified prefix instead of re-hashing. Any seek
// error, short read, read error, or digest mismatch fails: the
// caller rescans, never skips.
func verifySpan(r TargetReader, start, length int64, want string) (hash.Hash, error) {
	if _, err := r.Seek(start, io.SeekStart); err != nil {
		return nil, fmt.Errorf("proof seek to %d: %w", start, err)
	}
	h := sha256.New()
	left := length
	buf := make([]byte, 64<<10)
	for left > 0 {
		n := int64(len(buf))
		if n > left {
			n = left
		}
		m, err := io.ReadFull(r, buf[:n])
		if m > 0 {
			h.Write(buf[:m])
			left -= int64(m)
		}
		if err != nil {
			return nil, fmt.Errorf("proof read [%d,%d): %w", start, start+length, err)
		}
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return nil, fmt.Errorf("proof digest mismatch over [%d,%d)", start, start+length)
	}
	return h, nil
}

// cheapTierPass is the metadata rejection tier in front of proof
// verification. filed is the journaled identity, fi the fstat of the
// opened handle (open-then-fstat, so NFS revalidates and the
// double-stat race collapses), attested the identity converted from
// that fstat with attOK. Pass=true means NOT-YET-REJECTED — only a
// verified content proof authorizes offset or covered reuse, and no
// caller may treat a pass as authorization. Mismatched metadata
// skips the re-read cost and rescans; matching metadata (including
// weak matches like Windows in-place rewrites with restored
// timestamps, or coarse-clock filesystems) still pays verification.
// Non-regular targets have no metadata tier and always proceed to
// proof verification; legacy journals (empty filed identity) rescan
// on regular files and proceed to verification on non-regular ones,
// where every journal is effectively legacy.
func cheapTierPass(filed FileIdentity, fi os.FileInfo, attested FileIdentity, attOK bool, path string) (pass bool, note string) {
	regular := fi != nil && fi.Mode().IsRegular()
	if !regular {
		if filed.Kind != "" {
			return false, fmt.Sprintf("journal identity for %s no longer describes a regular file; rescanning from the start", path)
		}
		return true, ""
	}
	if filed.Kind == "" {
		return false, fmt.Sprintf("journal for %s predates content proofs; rescanning from the start", path)
	}
	if !attOK {
		return false, fmt.Sprintf("no byte identity available for %s; rescanning from the start", path)
	}
	if !filed.Matches(attested) {
		return false, fmt.Sprintf("journal identity for %s does not match current bytes; rescanning from the start", path)
	}
	return true, ""
}

// rootExtSuffix carries a banked member's depth-1 provenance extent
// in its filed cover key: base+"|rootext=A-B" names the absolute
// stream span the member's bytes derive from (the root archive
// extent for zip/gzip members, the header-through-data span for
// recovery entries). Seeding keeps the member only when that span
// sits inside verified bytes. Keys without the suffix (older
// binaries) never authorize deferral and re-read.
const rootExtSuffix = "|rootext="

// coverProvenance parses the provenance extent from a filed cover
// key, returning the base key (for deferral matching) and the span.
func coverProvenance(filed string) (base string, start, end int64, ok bool) {
	i := strings.LastIndex(filed, rootExtSuffix)
	if i < 0 {
		return "", 0, 0, false
	}
	span := filed[i+len(rootExtSuffix):]
	dash := strings.Index(span, "-")
	if dash <= 0 {
		return "", 0, 0, false
	}
	s, err1 := strconv.ParseInt(span[:dash], 10, 64)
	e, err2 := strconv.ParseInt(span[dash+1:], 10, 64)
	if err1 != nil || err2 != nil || s < 0 || e < s {
		return "", 0, 0, false
	}
	return filed[:i], s, e, true
}

// spanCovers reports whether [start, end) sits inside any verified span.
func spanCovers(spans [][2]int64, start, end int64) bool {
	for _, sp := range spans {
		if sp[0] <= start && end <= sp[1] {
			return true
		}
	}
	return false
}

// filterCoveredBySpans splits filed cover keys into reusable base
// keys (provenance inside spans) and dropped keys (no parseable
// provenance, provenance outside verified bytes, or conflicting
// provenance). A base key filed under two different spans — a
// malformed or merged journal — drops EVERY entry for that base,
// whatever order they filed in: a rejected entry must never
// alter retained provenance, and conflicting acceptances have no
// unique span to retain. (Different members legitimately share
// spans through depth inheritance; only same-identity conflicts
// drop. Exact-duplicate filed entries keep.) validated carries
// the unique span per kept base, so seeding retains the accepted
// pair as one object instead of rebuilding provenance from filed
// input; conflicts lists the filed entries dropped for conflict
// (a subset of dropped) for precise warnings. Dropped members
// re-read; nothing is deferred over unverified bytes.
func filterCoveredBySpans(filed []string, spans [][2]int64) (kept, dropped []string, validated map[string][2]int64, conflicts []string) {
	type entry struct {
		filed  string
		base   string
		span   [2]int64
		parsed bool
		in     bool
	}
	entries := make([]entry, 0, len(filed))
	seen := map[string]map[[2]int64]bool{}
	for _, k := range filed {
		base, s, e, ok := coverProvenance(k)
		en := entry{filed: k, base: base, span: [2]int64{s, e}, parsed: ok && base != ""}
		if en.parsed {
			en.in = spanCovers(spans, s, e)
			m := seen[base]
			if m == nil {
				m = map[[2]int64]bool{}
				seen[base] = m
			}
			m[en.span] = true
		}
		entries = append(entries, en)
	}
	validated = map[string][2]int64{}
	for _, en := range entries {
		if !en.parsed || !en.in || len(seen[en.base]) > 1 {
			dropped = append(dropped, en.filed)
			if en.parsed && len(seen[en.base]) > 1 {
				conflicts = append(conflicts, en.filed)
			}
			continue
		}
		kept = append(kept, en.base)
		validated[en.base] = en.span
	}
	return kept, dropped, validated, conflicts
}
