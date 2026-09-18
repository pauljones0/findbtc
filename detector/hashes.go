package detector

import "sort"

// HashScanMaxBytes caps crack-material extraction input; larger buffers skip
// extraction instead of ballooning memory. Carves are ~MBs; whole-file mode
// refuses oversized input before calling.
const HashScanMaxBytes = 256 << 20

// ExtractHashes finds all crack-ready password material in data: Bitcoin
// Core mkey records and Ethereum keystores. baseAbs is the absolute offset
// of data[0], so hits stay located in the scanned bytes. Records that fail
// strict validation are skipped — extraction never emits a hash no cracker
// could use. Results sort by offset for stable output.
func ExtractHashes(data []byte, baseAbs int64) []CrackHash {
	if len(data) > HashScanMaxBytes {
		return nil
	}
	var out []CrackHash
	seen := map[string]bool{}
	// Whole files (SQLite pages, BDB duplicates) can hold the same record
	// twice; a cracker gains nothing from the twin, so keep the first.
	emit := func(h CrackHash, err error) {
		if err == nil && !seen[h.Hash] {
			seen[h.Hash] = true
			out = append(out, h)
		}
	}
	for _, m := range FindMasterKeys(data, baseAbs) {
		emit(m.Hash())
	}
	for _, km := range findKeystores(data, baseAbs) {
		raw := data[km.startAbs-baseAbs : km.endAbs-baseAbs]
		p, err := ParseKeystore(raw, km.startAbs)
		if err != nil {
			continue
		}
		emit(p.Hash())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Offset < out[j].Offset })
	return out
}
