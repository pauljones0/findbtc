package detector

import (
	"fmt"
	"sort"
	"strings"
)

// HashScanMaxBytes caps crack-material extraction input; larger buffers skip
// extraction instead of ballooning memory. Carves are ~MBs; whole-file mode
// refuses oversized input before calling.
const HashScanMaxBytes = 256 << 20

// HashSkip is a wallet-shaped record that failed strict validation: the
// bytes looked like a wallet but produced no cracker-usable hash. Skips
// explain "No crack material found" — truncated input and unsupported
// records print the same stdout, so the reason travels here instead of
// leaving the user to guess between "carve wider" and "not supported".
// (Core mkey patterns stay silent by design: near-misses need 66 exact
// bytes plus method 0 plus sane iterations, and anything looser would
// report noise — see FindMasterKeys.)
type HashSkip struct {
	Offset int64  `json:"offset"`
	Kind   string `json:"kind"` // "ethereum-keystore" or "ethereum-presale"
	Reason string `json:"reason"`
}

// ExtractHashes finds all crack-ready password material in data: Bitcoin
// Core mkey records and Ethereum keystores. baseAbs is the absolute offset
// of data[0], so hits stay located in the scanned bytes. Records that fail
// strict validation are skipped — extraction never emits a hash no cracker
// could use. Results sort by offset for stable output.
func ExtractHashes(data []byte, baseAbs int64) []CrackHash {
	hashes, _ := ExtractHashesWithSkips(data, baseAbs)
	return hashes
}

// ExtractHashesWithSkips is ExtractHashes plus the reasons behind its
// rejections: keystore-shaped records that failed strict validation and
// presale wallets (detected as out of scope). Skips sort by offset.
func ExtractHashesWithSkips(data []byte, baseAbs int64) ([]CrackHash, []HashSkip) {
	if len(data) > HashScanMaxBytes {
		return nil, nil
	}
	var out []CrackHash
	var skips []HashSkip
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
			skips = append(skips, HashSkip{Offset: km.startAbs, Kind: "ethereum-keystore", Reason: skipReason(km.startAbs, err)})
			continue
		}
		h, herr := p.Hash()
		if herr != nil {
			skips = append(skips, HashSkip{Offset: km.startAbs, Kind: "ethereum-keystore", Reason: herr.Error()})
			continue
		}
		emit(h, nil)
	}
	skips = append(skips, findPresales(data, baseAbs)...)
	sort.Slice(out, func(i, j int) bool { return out[i].Offset < out[j].Offset })
	sort.Slice(skips, func(i, j int) bool { return skips[i].Offset < skips[j].Offset })
	return out, skips
}

// skipReason strips ParseKeystore's "keystore at byte N: " prefix: the
// skip already carries the offset, so stderr would otherwise name it twice.
func skipReason(offset int64, err error) string {
	msg := err.Error()
	if reason, ok := strings.CutPrefix(msg, fmt.Sprintf("keystore at byte %d: ", offset)); ok {
		return reason
	}
	return msg
}
