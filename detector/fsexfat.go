package detector

import (
	"fmt"
	"io"
	"unicode/utf16"
)

// exFAT reader (Goal 25): modern USB sticks and SD cards (exFAT is a
// different format family from FAT12/16/32, not an extension).
// Directory entry sets resolve to names + cluster runs; the cluster
// bitmap yields unallocated ranges. Deleted entries keep their names
// — exFAT delete only clears InUse bits — and contiguous files
// (NoFATChain) recover fully even with a zeroed FAT.
//
// Detection is strict (jump, "EXFAT" magic, signature, sane shifts
// and counts) so garbage refuses as non-volumes.

type exfatVol struct {
	r          io.ReaderAt
	base       int64
	clustBytes int64
	clustCount int64
	fatStart   int64 // absolute byte offset of FAT #1
	dataStart  int64 // absolute byte offset of the cluster heap
	rootClust  int64
	fat        []byte
	bitmap     []byte // loaded lazily by Unallocated
	bitmapOK   bool
}

// OpenExFAT detects an exFAT volume at base.
func OpenExFAT(r io.ReaderAt, base int64) (*exfatVol, error) {
	hdr := make([]byte, 512)
	if _, err := r.ReadAt(hdr, base); err != nil {
		return nil, fmt.Errorf("cannot read exFAT boot sector at offset %d: %w", base, err)
	}
	u32 := func(off int) int64 {
		return int64(hdr[off]) | int64(hdr[off+1])<<8 | int64(hdr[off+2])<<16 | int64(hdr[off+3])<<24
	}
	if hdr[0] != 0xEB && hdr[0] != 0xE9 {
		return nil, fmt.Errorf("no exFAT at offset %d: bad jump byte %#x", base, hdr[0])
	}
	if string(hdr[3:11]) != "EXFAT   " {
		return nil, fmt.Errorf("no exFAT at offset %d: bad magic %q", base, hdr[3:11])
	}
	if hdr[510] != 0x55 || hdr[511] != 0xAA {
		return nil, fmt.Errorf("no exFAT at offset %d: missing 55AA signature", base)
	}
	bpsShift, spcShift := hdr[108], hdr[109]
	if bpsShift < 9 || bpsShift > 12 {
		return nil, fmt.Errorf("no exFAT at offset %d: sector shift %d", base, bpsShift)
	}
	bps := int64(1) << bpsShift
	if bps != 512 {
		return nil, fmt.Errorf("no exFAT at offset %d: sector size %d (only 512 supported)", base, bps)
	}
	if spcShift > 25-bpsShift {
		return nil, fmt.Errorf("no exFAT at offset %d: cluster shift %d", base, spcShift)
	}
	if fats := hdr[110]; fats < 1 || fats > 2 {
		return nil, fmt.Errorf("no exFAT at offset %d: %d FATs", base, fats)
	}
	clustCount := u32(92)
	if clustCount <= 0 || clustCount > 1<<30 {
		return nil, fmt.Errorf("no exFAT at offset %d: cluster count %d", base, clustCount)
	}
	fatOff, heapOff := u32(80), u32(88)
	if fatOff <= 0 || heapOff <= fatOff {
		return nil, fmt.Errorf("no exFAT at offset %d: bad FAT/heap offsets", base)
	}
	rootClust := u32(96)
	if rootClust < 2 || rootClust >= clustCount+2 {
		return nil, fmt.Errorf("no exFAT at offset %d: root cluster %d", base, rootClust)
	}
	v := &exfatVol{
		r: r, base: base,
		clustBytes: (int64(1) << spcShift) * bps,
		clustCount: clustCount,
		fatStart:   base + fatOff*bps,
		dataStart:  base + heapOff*bps,
		rootClust:  rootClust,
	}
	// FAT #1 spans [FATOffset, ClusterHeapOffset).
	fatLen := (heapOff - fatOff) * bps
	if fatLen <= 0 || fatLen > 1<<29 {
		return nil, fmt.Errorf("no exFAT at offset %d: implausible FAT size %d", base, fatLen)
	}
	v.fat = make([]byte, fatLen)
	if _, err := r.ReadAt(v.fat, v.fatStart); err != nil {
		return nil, fmt.Errorf("cannot read exFAT FAT at offset %d: %w", v.fatStart, err)
	}
	return v, nil
}

func (v *exfatVol) fatEntry(c int64) int64 {
	off := c * 4
	if off+3 >= int64(len(v.fat)) {
		return 0xFFFFFFFF // treat truncation as EOC
	}
	return int64(v.fat[off]) | int64(v.fat[off+1])<<8 | int64(v.fat[off+2])<<16 | int64(v.fat[off+3])<<24
}

func exfatEOC(e int64) bool { return e >= 0xFFFFFFF8 }

// dirBytes reads a directory's cluster run: contiguous from first
// when noFATChain, else a FAT chain capped at the cluster count.
func (v *exfatVol) dirBytes(first int64, noFATChain bool) []byte {
	var raw []byte
	if noFATChain {
		// Size unknown up front: directories end at a 0x00 entry
		// type, so read ahead cluster by cluster to a sane cap.
		for i := int64(0); i < v.clustCount; i++ {
			c := first + i
			if c < 2 || c >= v.clustCount+2 {
				break
			}
			buf := make([]byte, v.clustBytes)
			if _, err := v.r.ReadAt(buf, clustAbsEx(v, c)); err != nil {
				break
			}
			raw = append(raw, buf...)
			if dirTerminated(buf) {
				break
			}
			if len(raw) > 64<<20 {
				break
			}
		}
		return raw
	}
	seen := map[int64]bool{}
	for c := first; c >= 2 && c < v.clustCount+2 && !seen[c]; {
		seen[c] = true
		buf := make([]byte, v.clustBytes)
		if _, err := v.r.ReadAt(buf, clustAbsEx(v, c)); err != nil {
			break
		}
		raw = append(raw, buf...)
		if dirTerminated(buf) {
			break
		}
		next := v.fatEntry(c)
		if exfatEOC(next) {
			break
		}
		c = next
	}
	return raw
}

func clustAbsEx(v *exfatVol, c int64) int64 {
	return v.dataStart + (c-2)*v.clustBytes
}

// dirTerminated reports a 0x00 entry type anywhere in the block.
func dirTerminated(buf []byte) bool {
	for off := 0; off+32 <= len(buf); off += 32 {
		if buf[off] == 0x00 {
			return true
		}
	}
	return false
}

const (
	exFileEntry   = 0x05 // +0x80 when in use
	exStreamEntry = 0x40
	exNameEntry   = 0x41
	exBitmapEntry = 0x01
)

// exEntrySet is one parsed File + Stream + Names group.
type exEntrySet struct {
	deleted bool
	isDir   bool
	name    string
	first   int64
	size    int64
	noFAT   bool
	slot    int // file-entry slot index within the directory
}

// parseExDir parses directory bytes into entry sets, skipping system
// entries (bitmap, upcase, label, GUID) and malformed sets.
func parseExDir(raw []byte) []exEntrySet {
	var out []exEntrySet
	nslots := len(raw) / 32
	for slot := 0; slot < nslots; {
		s := raw[slot*32 : (slot+1)*32]
		typ := s[0]
		if typ == 0x00 {
			break
		}
		if typ&0x7F != exFileEntry {
			slot++
			continue
		}
		nsec := int(s[1])
		if nsec < 1 || slot+1+nsec > nslots {
			slot++
			continue
		}
		set := raw[(slot+1)*32 : (slot+1+nsec)*32]
		stream := set[:32]
		if stream[0]&0x7F != exStreamEntry {
			slot++
			continue
		}
		nameLen := int(stream[3])
		first := int64(stream[20]) | int64(stream[21])<<8 | int64(stream[22])<<16 | int64(stream[23])<<24
		var size int64
		for i := 0; i < 8; i++ {
			size |= int64(stream[24+i]) << (8 * i)
		}
		var units []uint16
		okNames := 0
		for k := 1; k < nsec; k++ {
			n := set[k*32 : (k+1)*32]
			if n[0]&0x7F != exNameEntry {
				break
			}
			for off := 2; off+2 <= 32; off += 2 {
				units = append(units, uint16(n[off])|uint16(n[off+1])<<8)
			}
			okNames++
		}
		need := (nameLen + 14) / 15
		if okNames < need {
			slot += 1 + nsec
			continue
		}
		if len(units) > nameLen {
			units = units[:nameLen]
		}
		attr := int64(s[4]) | int64(s[5])<<8
		out = append(out, exEntrySet{
			deleted: typ&0x80 == 0,
			isDir:   attr&0x10 != 0,
			name:    string(utf16.Decode(units)),
			first:   first,
			size:    size,
			noFAT:   stream[1]&0x02 != 0,
			slot:    slot,
		})
		slot += 1 + nsec
	}
	return out
}

// fileExtents resolves a set to content extents: contiguous when the
// NoFATChain flag says so (survives FAT zeroing), else a capped FAT
// chain. Directories resolve nothing here (callers recurse).
func (v *exfatVol) fileExtents(first, size int64, noFAT bool) []FSExtent {
	if size <= 0 || first < 2 || first >= v.clustCount+2 {
		return nil
	}
	if noFAT {
		var out []FSExtent
		left := size
		for c := first; left > 0 && c < v.clustCount+2; c++ {
			n := v.clustBytes
			if n > left {
				n = left
			}
			out = append(out, FSExtent{Start: clustAbsEx(v, c), Len: n})
			left -= n
		}
		return mergeExtents(out)
	}
	var out []FSExtent
	left := size
	seen := map[int64]bool{}
	for c := first; left > 0 && c >= 2 && c < v.clustCount+2 && !seen[c]; {
		seen[c] = true
		n := v.clustBytes
		if n > left {
			n = left
		}
		out = append(out, FSExtent{Start: clustAbsEx(v, c), Len: n})
		left -= n
		next := v.fatEntry(c)
		if exfatEOC(next) {
			break
		}
		c = next
	}
	return mergeExtents(out)
}

// Entries inventories files (live and deleted); directories are
// traversed but, per the ext convention, not listed.
func (v *exfatVol) Entries() ([]FSEntry, error) {
	var out []FSEntry
	seenDir := map[int64]bool{}
	var walk func(first int64, noFAT bool, where string, depth int)
	walk = func(first int64, noFAT bool, where string, depth int) {
		if depth > 32 {
			return
		}
		if first >= 0 {
			if seenDir[first] {
				return
			}
			seenDir[first] = true
		}
		for _, set := range parseExDir(v.dirBytes(first, noFAT)) {
			note := fmt.Sprintf("exfat:%s:slot:%d", where, set.slot)
			if set.isDir {
				if !set.deleted && set.first >= 2 {
					walk(set.first, set.noFAT, fmt.Sprintf("clust:%d", set.first), depth+1)
				}
				continue
			}
			out = append(out, FSEntry{
				Name: set.name, Names: []string{set.name}, Size: set.size,
				Deleted: set.deleted,
				Extents: v.fileExtents(set.first, set.size, set.noFAT),
				Note:    note,
			})
		}
	}
	walk(v.rootClust, false, "root", 0)
	return out, nil
}

// loadBitmap locates the cluster bitmap through the root directory's
// Bitmap entry. A volume without one cannot report free space.
func (v *exfatVol) loadBitmap() error {
	if v.bitmapOK {
		return nil
	}
	raw := v.dirBytes(v.rootClust, false)
	for off := 0; off+32 <= len(raw); off += 32 {
		s := raw[off : off+32]
		if s[0] == 0x00 {
			break
		}
		if s[0]&0x7F != exBitmapEntry || s[0]&0x80 == 0 {
			continue
		}
		// Live bitmap entry required: a deleted one may point at
		// reused clusters.
		first := int64(s[20]) | int64(s[21])<<8 | int64(s[22])<<16 | int64(s[23])<<24
		var size int64
		for i := 0; i < 8; i++ {
			size |= int64(s[24+i]) << (8 * i)
		}
		need := (v.clustCount + 7) / 8
		if size < need || first < 2 {
			return fmt.Errorf("exFAT bitmap entry unusable (first %d, size %d)", first, size)
		}
		// Bitmaps are small; read contiguously with a FAT fallback.
		buf := make([]byte, need)
		if _, err := v.r.ReadAt(buf, clustAbsEx(v, first)); err != nil {
			return fmt.Errorf("cannot read exFAT bitmap: %w", err)
		}
		v.bitmap = buf
		v.bitmapOK = true
		return nil
	}
	return fmt.Errorf("exFAT volume has no live bitmap entry")
}

// Unallocated returns free-cluster byte ranges from the cluster
// bitmap (bit set = allocated; bit 0 covers cluster 2).
func (v *exfatVol) Unallocated() ([]FSExtent, error) {
	if err := v.loadBitmap(); err != nil {
		return nil, err
	}
	var out []FSExtent
	var start = int64(-1)
	flush := func(end int64) {
		if start >= 0 && end >= start {
			out = append(out, FSExtent{
				Start: clustAbsEx(v, start),
				Len:   (end - start + 1) * v.clustBytes,
			})
		}
		start = -1
	}
	for c := int64(2); c < v.clustCount+2; c++ {
		bit := c - 2
		alloc := v.bitmap[bit/8]&(1<<uint(bit%8)) != 0
		if !alloc && start < 0 {
			start = c
		}
		if alloc && start >= 0 {
			flush(c - 1)
		}
	}
	flush(v.clustCount + 1)
	return out, nil
}
