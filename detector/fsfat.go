package detector

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
)

// FAT12/16/32 reader (Goal 25): volume inventory for USB sticks, SD
// cards, and old externals — exactly where owners keep wallet backups.
// Live and deleted (0xE5) entries resolve to cluster chains; free
// clusters come from zeroed FAT entries.
//
// Strictness is deliberate: the BPB checks (signature, geometry,
// media, "FAT12/16/32" type string) must all pass, so random bytes
// and prose refuse as non-volumes (the per-format FP bar). Deleted
// entries report 8.3-derived names ('?' for the lost first byte);
// long-name recovery for deleted entries is a known recall gap.

// FAT type by data-cluster count (Microsoft thresholds).
const (
	fat12MaxClust = 4085
	fat16MaxClust = 65525
)

type fatVol struct {
	r           io.ReaderAt
	base        int64
	fatType     string // "fat12", "fat16", "fat32"
	bytesPerSec int64
	secPerClust int64
	clustBytes  int64
	fatStart    int64 // absolute byte offset of FAT #1
	dataStart   int64 // absolute byte offset of cluster 2
	clustCount  int64 // number of data clusters
	rootClust   int64 // FAT32 root dir first cluster
	rootStart   int64 // FAT12/16 root dir absolute offset
	rootEntries int64 // FAT12/16 root dir slot count
	fat         []byte
}

// OpenFAT detects a FAT12/16/32 volume at base. Every refusal names
// the offset and what the BPB held.
func OpenFAT(r io.ReaderAt, base int64) (*fatVol, error) {
	hdr := make([]byte, 512)
	if _, err := r.ReadAt(hdr, base); err != nil {
		return nil, fmt.Errorf("cannot read BPB at offset %d: %w", base, err)
	}
	u16 := func(off int) int64 {
		return int64(hdr[off]) | int64(hdr[off+1])<<8
	}
	u32 := func(off int) int64 {
		return int64(hdr[off]) | int64(hdr[off+1])<<8 | int64(hdr[off+2])<<16 | int64(hdr[off+3])<<24
	}
	bps := u16(11)
	switch bps {
	case 512, 1024, 2048, 4096:
	default:
		return nil, fmt.Errorf("no FAT at offset %d: bytes/sector %d", base, bps)
	}
	if bps > 512 {
		full := make([]byte, bps)
		if _, err := r.ReadAt(full, base); err != nil {
			return nil, fmt.Errorf("cannot read %d-byte BPB at offset %d: %w", bps, base, err)
		}
		copy(hdr, full[:512])
		// Re-read the signature from the true sector end below.
		hdr = full
	}
	if hdr[bps-2] != 0x55 || hdr[bps-1] != 0xAA {
		return nil, fmt.Errorf("no FAT at offset %d: missing 55AA signature", base)
	}
	spc := int64(hdr[13])
	switch spc {
	case 1, 2, 4, 8, 16, 32, 64, 128:
	default:
		return nil, fmt.Errorf("no FAT at offset %d: sectors/cluster %d", base, spc)
	}
	reserved := u16(14)
	if reserved == 0 {
		return nil, fmt.Errorf("no FAT at offset %d: zero reserved sectors", base)
	}
	numFATs := int64(hdr[16])
	if numFATs < 1 || numFATs > 2 {
		return nil, fmt.Errorf("no FAT at offset %d: %d FATs", base, numFATs)
	}
	if media := hdr[21]; media < 0xF0 {
		return nil, fmt.Errorf("no FAT at offset %d: media byte %#x", base, media)
	}
	total := u16(19)
	if total == 0 {
		total = u32(32)
	}
	if total <= 0 {
		return nil, fmt.Errorf("no FAT at offset %d: zero total sectors", base)
	}
	fatSecs := u16(22)
	if fatSecs == 0 {
		fatSecs = u32(36)
	}
	if fatSecs <= 0 {
		return nil, fmt.Errorf("no FAT at offset %d: zero FAT size", base)
	}
	rootEntries := u16(17)
	rootSecs := (rootEntries*32 + bps - 1) / bps
	dataSecs := total - (reserved + numFATs*fatSecs + rootSecs)
	if dataSecs <= 0 {
		return nil, fmt.Errorf("no FAT at offset %d: no data area", base)
	}
	clustCount := dataSecs / spc
	var fatType, wantStr string
	var strOff int
	switch {
	case clustCount < fat12MaxClust:
		fatType, wantStr, strOff = "fat12", "FAT12   ", 54
	case clustCount < fat16MaxClust:
		fatType, wantStr, strOff = "fat16", "FAT16   ", 54
	default:
		fatType, wantStr, strOff = "fat32", "FAT32   ", 82
	}
	if string(hdr[strOff:strOff+8]) != wantStr {
		return nil, fmt.Errorf("no FAT at offset %d: type string %q, want %q for %d clusters",
			base, hdr[strOff:strOff+8], wantStr, clustCount)
	}
	if (fatType == "fat32") == (rootEntries != 0) {
		return nil, fmt.Errorf("no FAT at offset %d: root entries %d inconsistent with %s", base, rootEntries, fatType)
	}
	v := &fatVol{
		r: r, base: base, fatType: fatType,
		bytesPerSec: bps, secPerClust: spc, clustBytes: spc * bps,
		fatStart:    base + reserved*bps,
		clustCount:  clustCount,
		rootEntries: rootEntries,
	}
	v.dataStart = base + (reserved+numFATs*fatSecs)*bps + rootSecs*bps
	if fatType == "fat32" {
		v.rootClust = u32(44)
		if v.rootClust < 2 {
			return nil, fmt.Errorf("no FAT at offset %d: root cluster %d", base, v.rootClust)
		}
	} else {
		v.rootStart = base + (reserved+numFATs*fatSecs)*bps
	}
	fatLen := fatSecs * bps
	if fatLen > 1<<29 {
		return nil, fmt.Errorf("no FAT at offset %d: implausible FAT size %d", base, fatLen)
	}
	v.fat = make([]byte, fatLen)
	if _, err := r.ReadAt(v.fat, v.fatStart); err != nil {
		return nil, fmt.Errorf("cannot read FAT at offset %d: %w", v.fatStart, err)
	}
	return v, nil
}

// fatEntry reads the FAT entry for cluster c (caller bounds-checks).
func (v *fatVol) fatEntry(c int64) int64 {
	switch v.fatType {
	case "fat12":
		off := c * 3 / 2
		if off+1 >= int64(len(v.fat)) {
			return 0
		}
		raw := int64(v.fat[off]) | int64(v.fat[off+1])<<8
		if c%2 == 0 {
			return raw & 0xFFF
		}
		return raw >> 4
	case "fat16":
		off := c * 2
		if off+1 >= int64(len(v.fat)) {
			return 0
		}
		return int64(v.fat[off]) | int64(v.fat[off+1])<<8
	default: // fat32
		off := c * 4
		if off+3 >= int64(len(v.fat)) {
			return 0
		}
		return (int64(v.fat[off]) | int64(v.fat[off+1])<<8 | int64(v.fat[off+2])<<16 | int64(v.fat[off+3])<<24) & 0x0FFFFFFF
	}
}

// fatEOC reports end-of-chain markers per FAT width.
func (v *fatVol) fatEOC(e int64) bool {
	switch v.fatType {
	case "fat12":
		return e >= 0xFF8
	case "fat16":
		return e >= 0xFFF8
	default:
		return e >= 0x0FFFFFF8
	}
}

// chain follows a cluster chain, stopping at EOC, free/bad/foreign
// entries, loops, or max clusters. Deleted files whose FAT entries
// were zeroed yield a prefix — honest partial recovery.
func (v *fatVol) chain(start int64, max int64) []int64 {
	var out []int64
	seen := map[int64]bool{}
	for c := start; c >= 2 && c < v.clustCount+2 && !seen[c] && int64(len(out)) < max; {
		seen[c] = true
		out = append(out, c)
		next := v.fatEntry(c)
		if v.fatEOC(next) {
			break
		}
		c = next
	}
	return out
}

const (
	fatAttrReadOnly = 0x01
	fatAttrHidden   = 0x02
	fatAttrSystem   = 0x04
	fatAttrVolume   = 0x08
	fatAttrDir      = 0x10
	fatAttrLFN      = 0x0F
)

// fatDirBlock reads one directory's raw slots: the fixed root region
// for FAT12/16, a cluster chain otherwise. dirClust < 0 selects root.
func (v *fatVol) fatDirBlock(dirClust int64) ([]byte, error) {
	if dirClust < 0 {
		if v.fatType == "fat32" {
			dirClust = v.rootClust
		} else {
			raw := make([]byte, v.rootEntries*32)
			if _, err := v.r.ReadAt(raw, v.rootStart); err != nil {
				return nil, err
			}
			return raw, nil
		}
	}
	var raw []byte
	for _, c := range v.chain(dirClust, v.clustCount+1) {
		buf := make([]byte, v.clustBytes)
		if _, err := v.r.ReadAt(buf, clustAbs(v, c)); err != nil {
			return nil, err
		}
		raw = append(raw, buf...)
	}
	return raw, nil
}

func clustAbs(v *fatVol, c int64) int64 {
	return v.dataStart + (c-2)*v.clustBytes
}

// fatName renders an 8.3 name; deleted entries lose their first byte.
func fatName(slot []byte, deleted bool) string {
	name := strings.TrimRight(string(slot[:8]), " ")
	ext := strings.TrimRight(string(slot[8:11]), " ")
	if deleted {
		if len(name) > 0 {
			name = "?" + name[1:]
		} else {
			name = "?"
		}
	} else if slot[0] == 0x05 {
		name = "\xe5" + name[1:]
	}
	if ext == "" {
		return name
	}
	return name + "." + ext
}

// lfnChars extracts the 13 UCS-2LE chars of an LFN slot.
func lfnChars(slot []byte) []uint16 {
	var out []uint16
	for _, off := range []int{1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30} {
		out = append(out, uint16(slot[off])|uint16(slot[off+1])<<8)
	}
	return out
}

// assembleLFN orders collected LFN parts (disk order is reverse) into
// a name; ok is false when the run is incomplete or mis-sequenced.
func assembleLFN(parts [][]byte) (name string, ok bool) {
	if len(parts) == 0 {
		return "", false
	}
	// Last-on-disk part carries the 0x40 flag with sequence 1...n.
	seq := func(p []byte) int { return int(p[0] & 0x1F) }
	if seq(parts[0]) != len(parts) || parts[0][0]&0x40 == 0 {
		return "", false
	}
	units := make([]uint16, 0, len(parts)*13)
	for i := len(parts) - 1; i >= 0; i-- {
		if seq(parts[i]) != len(parts)-i {
			return "", false
		}
		units = append(units, lfnChars(parts[i])...)
	}
	// Strip NUL terminator and filler.
	for i, u := range units {
		if u == 0x0000 {
			units = units[:i]
			break
		}
	}
	trimmed := units[:0]
	for _, u := range units {
		if u != 0xFFFF {
			trimmed = append(trimmed, u)
		}
	}
	if len(trimmed) == 0 {
		return "", false
	}
	return string(utf16.Decode(trimmed)), true
}

// Entries inventories files (live and deleted) with cluster-chain
// extents, following the ext convention: files only, directories
// traversed but not listed.
func (v *fatVol) Entries() ([]FSEntry, error) {
	var out []FSEntry
	seenDir := map[int64]bool{}
	var walk func(dirClust int64, where string, depth int)
	walk = func(dirClust int64, where string, depth int) {
		if depth > 32 {
			return
		}
		if dirClust >= 0 {
			if seenDir[dirClust] {
				return
			}
			seenDir[dirClust] = true
		}
		raw, err := v.fatDirBlock(dirClust)
		if err != nil {
			return
		}
		var lfn [][]byte
		for slot := 0; slot+32 <= len(raw); slot += 32 {
			s := raw[slot : slot+32]
			if s[0] == 0x00 {
				break // end of directory
			}
			attr := s[11]
			if attr == fatAttrLFN {
				lfn = append(lfn, append([]byte{}, s...))
				continue
			}
			deleted := s[0] == 0xE5
			if attr&fatAttrVolume != 0 {
				lfn = nil
				continue
			}
			name := ""
			if !deleted {
				if n, ok := assembleLFN(lfn); ok {
					name = n
				}
			}
			lfn = nil
			short := fatName(s, deleted)
			if name == "" {
				name = short
			}
			names := []string{name}
			if name != short {
				names = append(names, short)
			}
			first := int64(s[26]) | int64(s[27])<<8
			if v.fatType == "fat32" {
				first |= int64(s[20])<<16 | int64(s[21])<<24
			}
			size := int64(s[28]) | int64(s[29])<<8 | int64(s[30])<<16 | int64(s[31])<<24
			note := fmt.Sprintf("fat:%s:slot:%d", where, slot/32)
			if attr&fatAttrDir != 0 {
				if name == "." || name == ".." || short == "." || short == ".." {
					continue
				}
				if !deleted && first >= 2 {
					walk(first, fmt.Sprintf("clust:%d", first), depth+1)
				}
				continue
			}
			var ext []FSExtent
			if size > 0 && first >= 2 {
				need := (size + v.clustBytes - 1) / v.clustBytes
				left := size
				for _, c := range v.chain(first, need) {
					n := v.clustBytes
					if n > left {
						n = left
					}
					ext = append(ext, FSExtent{Start: clustAbs(v, c), Len: n})
					left -= n
				}
			}
			out = append(out, FSEntry{
				Name: name, Names: names, Size: size,
				Deleted: deleted, Extents: mergeExtents(ext), Note: note,
			})
		}
	}
	walk(-1, "root", 0)
	return out, nil
}

// Unallocated returns free-cluster byte ranges from zeroed FAT
// entries (clusters 2+). Bad/reserved/EOC entries are not free.
func (v *fatVol) Unallocated() ([]FSExtent, error) {
	var out []FSExtent
	var start = int64(-1)
	flush := func(end int64) {
		if start >= 0 && end >= start {
			out = append(out, FSExtent{
				Start: clustAbs(v, start),
				Len:   (end - start + 1) * v.clustBytes,
			})
		}
		start = -1
	}
	for c := int64(2); c < v.clustCount+2; c++ {
		if v.fatEntry(c) == 0 {
			if start < 0 {
				start = c
			}
			continue
		}
		flush(c - 1)
	}
	flush(v.clustCount + 1)
	return out, nil
}
