package detector

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"strings"
	"unicode/utf16"
)

// Partition tables (Goal 12). Full-disk images bury filesystem volumes at
// partition offsets; this parser follows the common PC schemes (MBR with
// EBR-chained logicals, GPT behind a protective MBR) so `-fs` can seed
// itself without a hand-found `-fs-offset`.
//
// Assumptions are narrow and loud: 512-byte sectors, PC layouts. Anything
// else (hybrid MBR+GPT, corrupt GPT CRCs, EBR loops, unknown tables)
// errors with the layout described instead of guessing, because scanning
// the wrong bytes silently is worse than refusing.

// diskSector is the assumed sector size for partition addressing.
const diskSector = 512

// Partition is one entry of a partition table.
type Partition struct {
	// Scheme is "mbr" or "gpt".
	Scheme string
	// Index is the 1-based on-disk order (MBR slot or logical order,
	// GPT entry number).
	Index int
	// Start is the byte offset of the partition's first sector.
	Start int64
	// Size is the partition length in bytes.
	Size int64
	// Type is a short type label ("ntfs", "linux", "efi-system", ...).
	Type string
	// Name is the GPT partition name, or "" (MBR entries are unnamed).
	Name string
}

func (p Partition) String() string {
	s := fmt.Sprintf("%s #%d @%d size=%d type=%s", p.Scheme, p.Index, p.Start, p.Size, p.Type)
	if p.Name != "" {
		s += fmt.Sprintf(" %q", p.Name)
	}
	return s
}

func readSectorAt(r io.ReaderAt, lba int64) ([]byte, error) {
	sec := make([]byte, diskSector)
	if _, err := r.ReadAt(sec, lba*diskSector); err != nil {
		return nil, err
	}
	return sec, nil
}

// ScanPartitions reads the partition table at the start of r and returns
// every non-empty entry in on-disk order.
func ScanPartitions(r io.ReaderAt) ([]Partition, error) {
	mbr, err := readSectorAt(r, 0)
	if err != nil {
		return nil, fmt.Errorf("cannot read sector 0 (not a partitioned disk?): %v", err)
	}
	if mbr[510] != 0x55 || mbr[511] != 0xAA {
		return nil, fmt.Errorf("no partition table: missing 0x55AA boot signature at byte 510")
	}
	var entries [4]mbrEntry
	protective := false
	realEntries := false
	for i := 0; i < 4; i++ {
		e := mbr[446+i*16 : 446+(i+1)*16]
		entries[i] = mbrEntry{e[4], binary.LittleEndian.Uint32(e[8:12]), binary.LittleEndian.Uint32(e[12:16])}
		switch {
		case entries[i].typ == 0xEE:
			protective = true
		case entries[i].typ != 0x00:
			realEntries = true
		}
	}
	if protective {
		if realEntries {
			return nil, fmt.Errorf("hybrid MBR+GPT layout (protective 0xEE plus real MBR entries): refusing to guess; point -fs-offset at a volume boot sector")
		}
		parts, err := scanGPT(r)
		if err != nil {
			return nil, fmt.Errorf("protective MBR promises GPT but %v; refusing to guess", err)
		}
		return parts, nil
	}
	if !realEntries {
		return nil, fmt.Errorf("empty partition table (no MBR entries, no protective MBR for GPT)")
	}
	if hasGPTMagic(r) {
		return nil, fmt.Errorf("hybrid MBR+GPT layout (MBR entries plus GPT header at LBA 1): refusing to guess; point -fs-offset at a volume boot sector")
	}
	return scanMBR(r, entries)
}

// hasGPTMagic reports whether LBA 1 carries a GPT header signature. It is
// only a hybrid-tripwire; full validation happens in scanGPT.
func hasGPTMagic(r io.ReaderAt) bool {
	lba1, err := readSectorAt(r, 1)
	if err != nil {
		return false
	}
	return string(lba1[:8]) == "EFI PART"
}

var mbrTypeLabels = map[byte]string{
	0x01: "fat12", 0x04: "fat16", 0x06: "fat16", 0x07: "ntfs",
	0x0B: "fat32", 0x0C: "fat32", 0x0E: "fat16", 0x82: "linux-swap",
	0x83: "linux", 0x8E: "linux-lvm", 0xA5: "bsd", 0xAF: "hfs",
	0xEF: "efi-system",
}

func mbrTypeLabel(typ byte) string {
	if s, ok := mbrTypeLabels[typ]; ok {
		return s
	}
	return fmt.Sprintf("mbr-type-%02x", typ)
}

func isExtendedMBR(typ byte) bool {
	return typ == 0x05 || typ == 0x0F || typ == 0x85
}

// maxEBRChain caps EBR following; real chains are a handful deep.
const maxEBRChain = 64

// mbrEntry is one parsed MBR slot (type byte, start LBA, sector count).
type mbrEntry struct {
	typ   byte
	lba   uint32
	count uint32
}

func scanMBR(r io.ReaderAt, raw [4]mbrEntry) ([]Partition, error) {
	var parts []Partition
	index := 0
	emit := func(lba, count uint32, typ byte) {
		index++
		parts = append(parts, Partition{
			Scheme: "mbr", Index: index,
			Start: int64(lba) * diskSector, Size: int64(count) * diskSector,
			Type: mbrTypeLabel(typ),
		})
	}
	for _, e := range raw {
		if e.typ == 0x00 || e.count == 0 {
			continue
		}
		if !isExtendedMBR(e.typ) {
			emit(e.lba, e.count, e.typ)
			continue
		}
		logicals, err := scanEBR(r, e.lba)
		if err != nil {
			return nil, err
		}
		for _, lp := range logicals {
			index++
			lp.Index = index
			parts = append(parts, lp)
		}
	}
	if len(parts) == 0 {
		return nil, fmt.Errorf("MBR table holds only empty/extended entries with no logical volumes")
	}
	return parts, nil
}

// scanEBR follows one extended-partition chain starting at extBase (LBA).
// Link offsets are relative to extBase; logical offsets to their own EBR.
func scanEBR(r io.ReaderAt, extBase uint32) ([]Partition, error) {
	var parts []Partition
	visited := map[uint32]bool{}
	ebr := extBase
	for n := 0; n < maxEBRChain; n++ {
		if visited[ebr] {
			return nil, fmt.Errorf("EBR chain loops at LBA %d: corrupt table, refusing to guess", ebr)
		}
		visited[ebr] = true
		sec, err := readSectorAt(r, int64(ebr))
		if err != nil {
			return nil, fmt.Errorf("cannot read EBR at LBA %d: %v", ebr, err)
		}
		if sec[510] != 0x55 || sec[511] != 0xAA {
			return nil, fmt.Errorf("EBR at LBA %d lacks the 0x55AA signature: corrupt table, refusing to guess", ebr)
		}
		first := sec[446:462]
		second := sec[462:478]
		ftyp := first[4]
		if ftyp != 0x00 && !isExtendedMBR(ftyp) {
			start := uint32(ebr) + binary.LittleEndian.Uint32(first[8:12])
			count := binary.LittleEndian.Uint32(first[12:16])
			if count == 0 {
				return nil, fmt.Errorf("EBR at LBA %d has a zero-length logical partition: corrupt table", ebr)
			}
			parts = append(parts, Partition{
				Scheme: "mbr",
				Start:  int64(start) * diskSector, Size: int64(count) * diskSector,
				Type: mbrTypeLabel(ftyp),
			})
		}
		styp := second[4]
		if styp == 0x00 || binary.LittleEndian.Uint32(second[12:16]) == 0 {
			return parts, nil
		}
		if !isExtendedMBR(styp) {
			return nil, fmt.Errorf("EBR at LBA %d has non-link second entry (type 0x%02x): corrupt table", ebr, styp)
		}
		ebr = extBase + binary.LittleEndian.Uint32(second[8:12])
	}
	return nil, fmt.Errorf("EBR chain exceeds %d links: corrupt table, refusing to guess", maxEBRChain)
}

// Known GPT type GUIDs (raw little-endian field order as stored).
var gptTypeLabels = map[[16]byte]string{
	{0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7}: "basic-data",
	{0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4}: "linux-filesystem",
	{0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B}: "efi-system",
	{0x6D, 0xFD, 0x57, 0x06, 0xAB, 0xA4, 0xC4, 0x43, 0x84, 0xE5, 0x09, 0x33, 0xC8, 0x4B, 0x4F, 0x4F}: "linux-swap",
	{0x79, 0xD3, 0xD6, 0xE6, 0x07, 0xF5, 0xC2, 0x44, 0xA2, 0x3C, 0x23, 0x8F, 0x2A, 0xDF, 0xD9, 0x28}: "linux-lvm",
	{0x16, 0xE3, 0xC9, 0xE3, 0x5C, 0x0B, 0xB8, 0x4D, 0x81, 0x7D, 0xF9, 0x2D, 0xF0, 0x02, 0x15, 0xAE}: "ms-reserved",
	{0x48, 0x61, 0x68, 0x21, 0x49, 0x64, 0x6F, 0x6E, 0x74, 0x4E, 0x65, 0x65, 0x64, 0x45, 0x46, 0x49}: "bios-boot",
}

// maxGPTEntries and maxGPTArray cap the entry-array read.
const (
	maxGPTEntries = 4096
	maxGPTArray   = 1 << 24
)

func formatGUID(raw []byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		binary.LittleEndian.Uint32(raw[0:4]), binary.LittleEndian.Uint16(raw[4:6]),
		binary.LittleEndian.Uint16(raw[6:8]), raw[8], raw[9],
		raw[10], raw[11], raw[12], raw[13], raw[14], raw[15])
}

func gptTypeLabel(raw []byte) string {
	var key [16]byte
	copy(key[:], raw)
	if s, ok := gptTypeLabels[key]; ok {
		return s
	}
	return "gpt:" + formatGUID(raw)
}

func decodeGPTName(raw []byte) string {
	u16 := make([]uint16, 36)
	for i := 0; i < 36; i++ {
		u16[i] = binary.LittleEndian.Uint16(raw[i*2 : i*2+2])
	}
	return strings.TrimRight(string(utf16.Decode(u16)), "\x00 ")
}

func scanGPT(r io.ReaderAt) ([]Partition, error) {
	hdr, err := readSectorAt(r, 1)
	if err != nil {
		return nil, fmt.Errorf("cannot read GPT header at LBA 1: %v", err)
	}
	if string(hdr[:8]) != "EFI PART" {
		return nil, fmt.Errorf("missing GPT signature at LBA 1")
	}
	hdrSize := binary.LittleEndian.Uint32(hdr[12:16])
	if hdrSize < 92 || hdrSize > diskSector {
		return nil, fmt.Errorf("bogus GPT header size %d", hdrSize)
	}
	stored := binary.LittleEndian.Uint32(hdr[16:20])
	chk := make([]byte, hdrSize)
	copy(chk, hdr[:hdrSize])
	binary.LittleEndian.PutUint32(chk[16:20], 0)
	if crc32.ChecksumIEEE(chk) != stored {
		return nil, fmt.Errorf("GPT header CRC mismatch (corrupt table)")
	}
	arrayLBA := binary.LittleEndian.Uint64(hdr[72:80])
	numEntries := binary.LittleEndian.Uint32(hdr[80:84])
	entrySize := binary.LittleEndian.Uint32(hdr[84:88])
	arrayCRC := binary.LittleEndian.Uint32(hdr[88:92])
	if numEntries == 0 || numEntries > maxGPTEntries {
		return nil, fmt.Errorf("bogus GPT entry count %d", numEntries)
	}
	if entrySize < 128 || entrySize%8 != 0 {
		return nil, fmt.Errorf("bogus GPT entry size %d", entrySize)
	}
	total := uint64(numEntries) * uint64(entrySize)
	if total > maxGPTArray {
		return nil, fmt.Errorf("GPT entry array too large (%d bytes)", total)
	}
	array := make([]byte, total)
	if _, err := r.ReadAt(array, int64(arrayLBA)*diskSector); err != nil {
		return nil, fmt.Errorf("cannot read GPT entry array at LBA %d: %v", arrayLBA, err)
	}
	if crc32.ChecksumIEEE(array) != arrayCRC {
		return nil, fmt.Errorf("GPT entry-array CRC mismatch (corrupt table)")
	}
	var parts []Partition
	for i := uint32(0); i < numEntries; i++ {
		e := array[i*entrySize : (i+1)*entrySize]
		empty := true
		for _, b := range e[:16] {
			if b != 0 {
				empty = false
				break
			}
		}
		if empty {
			continue
		}
		first := binary.LittleEndian.Uint64(e[32:40])
		last := binary.LittleEndian.Uint64(e[40:48])
		if last < first {
			return nil, fmt.Errorf("GPT entry %d ends (LBA %d) before it starts (LBA %d): corrupt table", i+1, last, first)
		}
		name := ""
		if entrySize >= 128 {
			name = decodeGPTName(e[56:128])
		}
		parts = append(parts, Partition{
			Scheme: "gpt", Index: int(i + 1),
			Start: int64(first) * diskSector, Size: int64(last-first+1) * diskSector,
			Type: gptTypeLabel(e[:16]), Name: name,
		})
	}
	if len(parts) == 0 {
		return nil, fmt.Errorf("GPT table holds no used entries")
	}
	return parts, nil
}
