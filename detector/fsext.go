package detector

import (
	"encoding/binary"
	"fmt"
	"io"
)

// ext parsing for the filesystem layer: superblock, group descriptors,
// inode tables (live and unlinked), directory walks with residual deleted
// names, extent/direct block maps, and block-bitmap unallocated ranges.
//
// ext unlinks names and content separately: deleting a file zeroes its
// directory entry (the name bytes usually linger) and unlinks the inode
// (links=0, content blocks freed but intact). Recovery therefore yields
// two honest halves: residual names without content, and unlinked-inode
// content without names — associated only when an unlinked directory
// still references the inode. Inode-bitmap bits are ignored on purpose:
// deletion clears them while the table rows remain readable.

const (
	extMagic       = 0xEF53
	extExtentMagic = 0xF30A
	extExtentsFlag = 0x80000
	extFileTypeDir = 4
)

const (
	extModeFile = 0x8000
	extModeDir  = 0x4000
	extModeMask = 0xF000
)

// ExtVol is a parsed ext superblock plus its image reader.
type ExtVol struct {
	r         io.ReaderAt
	base      int64
	blockSize int64
	blocks    int64
	inodes    int64
	blocksPer int64
	inodesPer int64
	inodeSize int64
	firstIno  int64
	groups    int64
	gdtByte   int64 // image offset of the group descriptor table
	descSize  int64 // 32, or 64 with the 64bit feature
}

// OpenExt validates the superblock at base+1024 and returns the volume.
func OpenExt(r io.ReaderAt, base int64) (*ExtVol, error) {
	var sb [1024]byte
	if _, err := r.ReadAt(sb[:], base+1024); err != nil {
		return nil, fmt.Errorf("cannot read superblock: %w", err)
	}
	if binary.LittleEndian.Uint16(sb[56:58]) != extMagic {
		return nil, fmt.Errorf("no ext signature")
	}
	blockSize := int64(1024) << binary.LittleEndian.Uint32(sb[24:28])
	if blockSize != 1024 && blockSize != 2048 && blockSize != 4096 {
		return nil, fmt.Errorf("bad block size %d", blockSize)
	}
	blocks := int64(binary.LittleEndian.Uint32(sb[4:8]))
	blocksPer := int64(binary.LittleEndian.Uint32(sb[32:36]))
	inodesPer := int64(binary.LittleEndian.Uint32(sb[40:44]))
	inodeSize := int64(binary.LittleEndian.Uint16(sb[88:90]))
	if blocks <= 0 || blocksPer <= 0 || inodesPer <= 0 {
		return nil, fmt.Errorf("bad geometry")
	}
	if inodeSize != 128 && inodeSize != 256 {
		return nil, fmt.Errorf("bad inode size %d", inodeSize)
	}
	incompat := binary.LittleEndian.Uint32(sb[96:100])
	descSize := int64(32)
	if incompat&0x80 != 0 {
		if ds := int64(binary.LittleEndian.Uint16(sb[254:256])); ds == 64 {
			descSize = 64
		} else if ds != 32 {
			return nil, fmt.Errorf("bad descriptor size %d", ds)
		}
	}
	firstIno := int64(binary.LittleEndian.Uint32(sb[84:88]))
	if firstIno < 1 {
		firstIno = 11
	}
	groups := (blocks + blocksPer - 1) / blocksPer
	var gdtByte int64
	if blockSize == 1024 {
		gdtByte = base + 2048
	} else {
		gdtByte = base + blockSize
	}
	return &ExtVol{
		r: r, base: base, blockSize: blockSize,
		blocks: blocks, inodes: int64(binary.LittleEndian.Uint32(sb[0:4])),
		blocksPer: blocksPer, inodesPer: inodesPer, inodeSize: inodeSize,
		firstIno: firstIno, groups: groups, gdtByte: gdtByte, descSize: descSize,
	}, nil
}

// extGroup holds one group's bitmap and inode-table block numbers.
type extGroup struct {
	blockBitmap int64
	inodeTable  int64
}

func (v *ExtVol) group(g int64) (extGroup, bool) {
	raw := make([]byte, v.descSize)
	if _, err := v.r.ReadAt(raw, v.gdtByte+g*v.descSize); err != nil {
		return extGroup{}, false
	}
	grp := extGroup{
		blockBitmap: int64(binary.LittleEndian.Uint32(raw[0:4])),
		inodeTable:  int64(binary.LittleEndian.Uint32(raw[8:12])),
	}
	if v.descSize == 64 {
		grp.blockBitmap |= int64(binary.LittleEndian.Uint32(raw[32:36])) << 32
		grp.inodeTable |= int64(binary.LittleEndian.Uint32(raw[40:44])) << 32
	}
	if grp.blockBitmap >= v.blocks || grp.inodeTable >= v.blocks {
		return extGroup{}, false
	}
	return grp, true
}

// extInode is the decoded subset of an inode row.
type extInode struct {
	num    int64
	mode   uint16
	links  uint16
	size   int64
	blocks []int64 // file-logical data block numbers, in order
	isDir  bool
}

// readInode decodes inode num (1-based). Deleted rows decode identically;
// the caller decides liveness from links/mode.
func (v *ExtVol) readInode(num int64) (*extInode, bool) {
	if num < 1 || num > v.inodes {
		return nil, false
	}
	grp, ok := v.group((num - 1) / v.inodesPer)
	if !ok {
		return nil, false
	}
	off := v.base + grp.inodeTable*v.blockSize + ((num-1)%v.inodesPer)*v.inodeSize
	raw := make([]byte, v.inodeSize)
	if _, err := v.r.ReadAt(raw, off); err != nil {
		return nil, false
	}
	mode := binary.LittleEndian.Uint16(raw[0:2])
	if mode == 0 {
		return nil, false
	}
	in := &extInode{
		num:   num,
		mode:  mode,
		links: binary.LittleEndian.Uint16(raw[26:28]),
		size: int64(binary.LittleEndian.Uint32(raw[4:8])) |
			int64(binary.LittleEndian.Uint32(raw[108:112]))<<32,
		isDir: mode&extModeMask == extModeDir,
	}
	if in.size < 0 || in.size > v.blocks*v.blockSize {
		return nil, false
	}
	flags := binary.LittleEndian.Uint32(raw[32:36])
	iblock := raw[40:100]
	if flags&extExtentsFlag != 0 {
		in.blocks = v.extentBlocks(iblock, 0)
	} else {
		in.blocks = v.indirectBlocks(iblock)
	}
	// Trim to the file size: trailing blocks past EOF are stale.
	keep := (in.size + v.blockSize - 1) / v.blockSize
	if int64(len(in.blocks)) > keep {
		in.blocks = in.blocks[:keep]
	}
	return in, true
}

// extentBlocks walks an extent tree (depth-capped) to leaf block numbers.
func (v *ExtVol) extentBlocks(node []byte, depth int) []int64 {
	if len(node) < 12 || depth > 3 {
		return nil
	}
	if binary.LittleEndian.Uint16(node[0:2]) != extExtentMagic {
		return nil
	}
	entries := int(binary.LittleEndian.Uint16(node[2:4]))
	nodeDepth := int(binary.LittleEndian.Uint16(node[6:8]))
	if entries < 0 || entries > 340 {
		return nil
	}
	var out []int64
	if nodeDepth == 0 {
		if len(node) < 12+12*entries {
			return nil
		}
		for i := 0; i < entries; i++ {
			e := node[12+12*i : 24+12*i]
			n := int64(binary.LittleEndian.Uint16(e[4:6]))
			if n > 32768 {
				n -= 32768 // uninitialized extent still maps blocks
			}
			start := int64(binary.LittleEndian.Uint32(e[8:12])) |
				int64(binary.LittleEndian.Uint16(e[6:8]))<<32
			for k := int64(0); k < n; k++ {
				if start+k >= v.blocks {
					return out
				}
				out = append(out, start+k)
				if len(out) > 1<<24 {
					return out
				}
			}
		}
		return out
	}
	if len(node) < 12+12*entries {
		return nil
	}
	for i := 0; i < entries; i++ {
		e := node[12+12*i : 24+12*i]
		child := int64(binary.LittleEndian.Uint32(e[8:12])) |
			int64(binary.LittleEndian.Uint16(e[6:8]))<<32
		if child >= v.blocks {
			continue
		}
		buf := make([]byte, v.blockSize)
		if _, err := v.r.ReadAt(buf, v.base+child*v.blockSize); err != nil {
			continue
		}
		out = append(out, v.extentBlocks(buf, depth+1)...)
		if len(out) > 1<<24 {
			return out
		}
	}
	return out
}

// indirectBlocks maps classic direct + single-indirect block pointers.
func (v *ExtVol) indirectBlocks(iblock []byte) []int64 {
	if len(iblock) < 60 {
		return nil
	}
	var out []int64
	add := func(b int64) {
		if b > 0 && b < v.blocks {
			out = append(out, b)
		}
	}
	for i := 0; i < 12; i++ {
		add(int64(binary.LittleEndian.Uint32(iblock[4*i : 4*i+4])))
	}
	ind := int64(binary.LittleEndian.Uint32(iblock[48:52]))
	if ind > 0 && ind < v.blocks {
		buf := make([]byte, v.blockSize)
		if _, err := v.r.ReadAt(buf, v.base+ind*v.blockSize); err == nil {
			for i := 0; i+4 <= len(buf); i += 4 {
				add(int64(binary.LittleEndian.Uint32(buf[i : i+4])))
			}
		}
	}
	// Double/triple indirect are out of scope (multi-GB files whose
	// indirect trees rarely survive deletion intact).
	return out
}

// extDirent is one directory entry: live (inode != 0) or residual.
type extDirent struct {
	inode int64
	name  string
}

// dirEntries parses one directory data block. Malformed tails stop the
// scan. Unlinking merges the freed entry into its predecessor's rec_len,
// so each entry's slack is also scanned for residual names: accepted when
// 4-aligned with a plausible name and either a zeroed inode (classic
// unlink) or an inode the valid callback confirms (intact reference,
// which also re-associates the name). rec_len of residuals is stale and
// never trusted for bounds.
func dirEntries(block []byte, valid func(int64) bool) []extDirent {
	var out []extDirent
	for p := 0; p+8 <= len(block); {
		ino := int64(binary.LittleEndian.Uint32(block[p : p+4]))
		recLen := int(binary.LittleEndian.Uint16(block[p+4 : p+6]))
		nameLen := int(block[p+6])
		if recLen < 8 || recLen%4 != 0 || p+recLen > len(block) {
			break
		}
		if nameLen > 0 && nameLen <= recLen-8 && p+8+nameLen <= len(block) {
			name := string(block[p+8 : p+8+nameLen])
			if ino != 0 {
				out = append(out, extDirent{inode: ino, name: name})
			} else if plausibleName(name) {
				out = append(out, extDirent{inode: 0, name: name})
			}
			minLen := (8 + nameLen + 3) &^ 3
			out = append(out, slackEntries(block, p+minLen, p+recLen, valid)...)
		}
		if recLen == 0 {
			break
		}
		p += recLen
	}
	return out
}

// slackEntries scans [lo,hi) for 4-aligned residual entries.
func slackEntries(block []byte, lo, hi int, valid func(int64) bool) []extDirent {
	var out []extDirent
	if lo < 0 {
		lo = 0
	}
	if hi > len(block) {
		hi = len(block)
	}
	for q := lo + ((4 - lo%4) % 4); q+8 <= hi; q += 4 {
		ino := int64(binary.LittleEndian.Uint32(block[q : q+4]))
		nameLen := int(block[q+6])
		if nameLen <= 0 || nameLen > 255 || q+8+nameLen > hi {
			continue
		}
		name := string(block[q+8 : q+8+nameLen])
		if !plausibleName(name) {
			continue
		}
		if ino == 0 {
			out = append(out, extDirent{inode: 0, name: name})
		} else if valid != nil && valid(ino) {
			out = append(out, extDirent{inode: ino, name: name})
		}
	}
	return out
}

func plausibleName(name string) bool {
	if len(name) == 0 || len(name) > 255 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c < 0x20 || c == 0x7F || c == '/' {
			return false
		}
	}
	return true
}

// Entries enumerates files with names where known: live files via the
// directory tree from the root, unlinked inodes by table scan (content
// without names unless an unlinked directory still references them), and
// residual deleted names without content.
func (v *ExtVol) Entries() ([]FSEntry, error) {
	names := map[int64][]string{} // inode -> dir names
	var residual []string
	seenDir := map[int64]bool{}
	var walk func(ino int64, depth int)
	walk = func(ino int64, depth int) {
		if depth > 32 || seenDir[ino] {
			return
		}
		seenDir[ino] = true
		in, ok := v.readInode(ino)
		if !ok || !in.isDir {
			return
		}
		valid := func(ino int64) bool {
			_, ok := v.readInode(ino)
			return ok
		}
		for _, b := range in.blocks {
			buf := make([]byte, v.blockSize)
			if _, err := v.r.ReadAt(buf, v.base+b*v.blockSize); err != nil {
				continue
			}
			for _, de := range dirEntries(buf, valid) {
				if de.inode == 0 {
					residual = append(residual, de.name)
					continue
				}
				if de.name == "." || de.name == ".." {
					continue
				}
				names[de.inode] = append(names[de.inode], de.name)
				if child, ok := v.readInode(de.inode); ok && child.isDir {
					walk(de.inode, depth+1)
				}
			}
		}
	}
	walk(2, 0)
	// Unlinked directories are not reachable from the root; scan for them
	// so their deleted children keep names.
	for num := v.firstIno; num <= v.inodes; num++ {
		in, ok := v.readInode(num)
		if !ok || !in.isDir || in.links != 0 {
			continue
		}
		walk(num, 0)
	}

	var out []FSEntry
	for num := v.firstIno; num <= v.inodes; num++ {
		in, ok := v.readInode(num)
		if !ok || in.isDir {
			continue
		}
		var ext []FSExtent
		for _, b := range in.blocks {
			ext = append(ext, FSExtent{Start: v.base + b*v.blockSize, Len: v.blockSize})
		}
		ext = mergeExtents(ext)
		// Trim the final extent to the file size.
		if len(ext) > 0 && in.size < int64(len(in.blocks))*v.blockSize {
			want := in.size
			var trimmed []FSExtent
			for _, e := range ext {
				if want <= 0 {
					break
				}
				if e.Len > want {
					e.Len = want
				}
				trimmed = append(trimmed, e)
				want -= e.Len
			}
			ext = trimmed
		}
		out = append(out, FSEntry{
			Name:    firstName(names[num]),
			Names:   names[num],
			Size:    in.size,
			Deleted: in.links == 0,
			Extents: ext,
			Note:    fmt.Sprintf("inode:%d", num),
		})
	}
	seenRes := map[string]bool{}
	for _, name := range residual {
		if seenRes[name] {
			continue
		}
		seenRes[name] = true
		out = append(out, FSEntry{
			Name:    name,
			Names:   []string{name},
			Deleted: true,
			Note:    "residual dir entry",
		})
	}
	return out, nil
}

func firstName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

// Unallocated returns free-block byte ranges from the block bitmaps.
func (v *ExtVol) Unallocated() ([]FSExtent, error) {
	var out []FSExtent
	var start = int64(-1)
	flush := func(end int64) {
		if start >= 0 && end >= start {
			out = append(out, FSExtent{
				Start: v.base + start*v.blockSize,
				Len:   (end - start + 1) * v.blockSize,
			})
		}
		start = -1
	}
	for g := int64(0); g < v.groups; g++ {
		grp, ok := v.group(g)
		if !ok {
			return nil, fmt.Errorf("bad group %d", g)
		}
		bitmap := make([]byte, v.blockSize)
		if _, err := v.r.ReadAt(bitmap, v.base+grp.blockBitmap*v.blockSize); err != nil {
			return nil, fmt.Errorf("cannot read block bitmap: %w", err)
		}
		n := v.blocksPer
		if g == v.groups-1 {
			n = v.blocks - g*v.blocksPer
		}
		for i := int64(0); i < n; i++ {
			alloc := bitmap[i/8]&(1<<uint(i%8)) != 0
			b := g*v.blocksPer + i
			if !alloc && start < 0 {
				start = b
			}
			if alloc && start >= 0 {
				flush(b - 1)
			}
		}
	}
	if start >= 0 {
		flush(v.blocks - 1)
	}
	return out, nil
}
