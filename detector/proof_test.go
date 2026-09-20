package detector

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// mustProof crafts a valid content proof over path's span
// [start, start+length) for journal fixtures.
func mustProof(t *testing.T, path string, start, length int64) *PrefixProof {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if start < 0 || length < 0 || start+length > int64(len(raw)) {
		t.Fatalf("proof span [%d,%d) outside %s (%d bytes)", start, start+length, path, len(raw))
	}
	sum := sha256.Sum256(raw[start : start+length])
	return &PrefixProof{Version: ProofVersion, Start: start, Len: length, SHA256: hex.EncodeToString(sum[:])}
}

// mustRangeProof crafts a valid completed-range proof over path's
// span for journal fixtures.
func mustRangeProof(t *testing.T, index int, path string, start, length int64) RangeProof {
	t.Helper()
	p := mustProof(t, path, start, length)
	return RangeProof{Version: ProofVersion, Index: index, Start: start, Len: length, SHA256: p.SHA256}
}

// mustSpanProof crafts a proof over an explicit byte slice (for
// non-file streams like /dev/zero prefixes).
func mustSpanProof(start int64, data []byte) *PrefixProof {
	sum := sha256.Sum256(data)
	return &PrefixProof{Version: ProofVersion, Start: start, Len: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}
}

func TestVerifySpan(t *testing.T) {
	data := bytes.Repeat([]byte{'A'}, 8192)
	r := &closableBytesReader{Reader: bytes.NewReader(data)}
	h, err := verifySpan(r, 0, 8192, mustSpanProof(0, data).SHA256)
	if err != nil {
		t.Fatalf("exact span refused: %v", err)
	}
	// The returned state chains: streaming more bytes extends the
	// verified prefix hash.
	h.Write([]byte{'B'})
	sum := sha256.Sum256(append(append([]byte{}, data...), 'B'))
	if hex.EncodeToString(h.Sum(nil)) != hex.EncodeToString(sum[:]) {
		t.Fatal("verified state does not chain")
	}
	// Wrong content, short span, bad seek all fail.
	bad := &closableBytesReader{Reader: bytes.NewReader(bytes.Repeat([]byte{'B'}, 8192))}
	if _, err := verifySpan(bad, 0, 8192, mustSpanProof(0, data).SHA256); err == nil {
		t.Fatal("tampered span verified")
	}
	short := &closableBytesReader{Reader: bytes.NewReader(data[:100])}
	if _, err := verifySpan(short, 0, 8192, mustSpanProof(0, data).SHA256); err == nil {
		t.Fatal("short span verified")
	}
	if _, err := verifySpan(r, 1<<20, 10, mustSpanProof(0, data).SHA256); err == nil {
		t.Fatal("out-of-range span verified")
	}
}

func TestFilterCoveredBySpans(t *testing.T) {
	spans := [][2]int64{{0, 4096}, {8192, 12288}}
	filed := []string{
		"member-a|rootext=0-4096",     // inside first span
		"member-b|rootext=100-200",    // inside first span
		"member-c|rootext=0-4097",     // straddles: out
		"member-d|rootext=9000-9001",  // inside second span
		"member-e|rootext=4096-8192",  // gap: out
		"legacy-member",               // no provenance: out
		"member-f|rootext=bad",        // malformed: out
		"member-g|rootext=200-100",    // inverted: out
		"member-h|zipsize=9|rootext=8-16|rootext=0-8", // last suffix wins: in
	}
	kept, dropped := filterCoveredBySpans(filed, spans)
	want := map[string]bool{"member-a": true, "member-b": true, "member-d": true, "member-h|zipsize=9|rootext=8-16": true}
	if len(kept) != len(want) {
		t.Fatalf("kept = %v, want %d members", kept, len(want))
	}
	for _, k := range kept {
		if !want[k] {
			t.Fatalf("kept = %v, unexpected %q", kept, k)
		}
	}
	if len(kept)+len(dropped) != len(filed) {
		t.Fatalf("kept+dropped = %d, want %d", len(kept)+len(dropped), len(filed))
	}
}

func TestCoverProvenanceRoundTrip(t *testing.T) {
	// Filed keys strip to base keys for deferral matching.
	base, s, e, ok := coverProvenance("Zipfile #3 @ byte 0 in [f]|zipsize=100|rootext=10-20")
	if !ok || base != "Zipfile #3 @ byte 0 in [f]|zipsize=100" || s != 10 || e != 20 {
		t.Fatalf("parse = %q,%d,%d,%v", base, s, e, ok)
	}
	if _, _, _, ok := coverProvenance("plain-key"); ok {
		t.Fatal("plain key parsed provenance")
	}
}

func TestSnapshotProvenance(t *testing.T) {
	// Banking resolves depth-1 provenance through live chains;
	// unresolvable members are omitted (re-read), never filed
	// without a span.
	root := &fileScanTarget{path: "r"}
	z := &zipScanTarget{source: root, zipOffset: 100, fileIndex: 0, zipSize: 500}
	inner := &zipScanTarget{source: z, zipOffset: 10, fileIndex: 2, zipSize: 50}
	g := newPubGate(io.Discard)
	g.bankCovered(inner) // parent not banked: unresolvable
	if got := g.snapshotCovered(); len(got) != 0 {
		t.Fatalf("filed with unbanked parent = %v, want empty", got)
	}
	g.bankCovered(z)
	got := g.snapshotCovered()
	if len(got) != 2 {
		t.Fatalf("filed = %v, want parent+child", got)
	}
	// Both inherit the depth-1 archive span [100,600).
	for _, k := range got {
		_, s, e, ok := coverProvenance(k)
		if !ok || s != 100 || e != 600 {
			t.Fatalf("key %q provenance = %d-%d,%v, want 100-600", k, s, e, ok)
		}
	}
	// Gzip without a completed read (consumed 0) never files.
	gz := &gzipScanTarget{source: root, gzipOffset: 700}
	g2 := newPubGate(io.Discard)
	g2.bankCovered(gz)
	if got := g2.snapshotCovered(); len(got) != 0 {
		t.Fatalf("unread gzip filed = %v, want empty", got)
	}
	gz.consumed = 60
	if got := g2.snapshotCovered(); len(got) != 1 {
		t.Fatalf("read gzip filed = %v, want one", got)
	} else if _, s, e, _ := coverProvenance(got[0]); s != 700 || e != 760 {
		t.Fatalf("gzip span = %d-%d, want 700-760", s, e)
	}
	// Recovery entries span header through data.
	re := &zipEntryTarget{source: root, name: "m", headerOff: 800, dataOff: 860, compSize: 40}
	g3 := newPubGate(io.Discard)
	g3.bankCovered(re)
	if got := g3.snapshotCovered(); len(got) != 1 {
		t.Fatalf("recovery filed = %v, want one", got)
	} else if _, s, e, _ := coverProvenance(got[0]); s != 800 || e != 900 {
		t.Fatalf("recovery span = %d-%d, want 800-900", s, e)
	}
	// Seeded-only members re-file their seed-time span (else
	// every attempt would replay them and never converge).
	g4 := newPubGate(io.Discard)
	kept, _ := g4.seedCovered([]string{"seeded-m|rootext=0-100"}, [][2]int64{{0, 4096}})
	if len(kept) != 1 || !g4.isCovered("seeded-m") {
		t.Fatalf("seeded member not deferred: kept=%v", kept)
	}
	if got := g4.snapshotCovered(); len(got) != 1 || got[0] != "seeded-m|rootext=0-100" {
		t.Fatalf("seeded re-file = %v, want seed-time span", got)
	}
}

func TestVerifyStable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.bin")
	if err := os.WriteFile(path, []byte("stable-bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	preFi, preAtt, preOK := FileIdentityOfFile(f)
	if err := verifyStable(f, preFi, preAtt, preOK); err != nil {
		t.Fatalf("stable file refused: %v", err)
	}
	// Append through a second handle: size moves, stability fails.
	w, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("more")); err != nil {
		t.Fatal(err)
	}
	w.Close()
	if err := verifyStable(f, preFi, preAtt, preOK); err == nil {
		t.Fatal("appended file passed stability")
	}
}
