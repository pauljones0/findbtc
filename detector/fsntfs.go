package detector

import (
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf16"
)

// NTFS parsing for the filesystem layer: MFT record enumeration (live and
// deleted) with filenames and data runs, plus $Bitmap-driven unallocated
// ranges. Only what recovery needs is implemented: FILE records, $FILE_NAME
// and unnamed $DATA attributes, data-run decoding, and the update-sequence
// fixup. Extension records merge their data runs into the base entry;
// encrypted/compressed/sparse files parse structurally but their content
// reads back raw clusters.
//
// Deleted entries keep their FILE magic, names, and usually their runs:
// NTFS deletion clears the in-use flag and bitmap bits, leaving the rest
// for recovery until reuse.

// NTFS attribute types.
const (
	ntfsAttrFileName = 0x30
	ntfsAttrData     = 0x80
	ntfsAttrEnd      = 0xFFFFFFFF
)

// mftRecordCap bounds how many MFT records one volume scan parses.
const mftRecordCap = 1 << 20

// NTFSVol is a parsed NTFS volume boot sector plus its image reader.
type NTFSVol struct {
	r          io.ReaderAt
	base       int64 // image offset of the volume boot sector
	cluster    int64 // bytes per cluster
	recordSize int
	mftByte    int64 // image offset of MFT record 0
	totalClust int64
}

// OpenNTFS validates the boot sector at base and returns the volume.
func OpenNTFS(r io.ReaderAt, base int64) (*NTFSVol, error) {
	var boot [512]byte
	if _, err := r.ReadAt(boot[:], base); err != nil {
		return nil, fmt.Errorf("cannot read boot sector: %w", err)
	}
	if string(boot[3:11]) != "NTFS    " {
		return nil, fmt.Errorf("no NTFS signature")
	}
	bps := int64(binary.LittleEndian.Uint16(boot[11:13]))
	spc := int64(boot[13])
	if bps < 512 || bps > 4096 || spc < 1 || spc > 128 {
		return nil, fmt.Errorf("implausible geometry bps=%d spc=%d", bps, spc)
	}
	totalSectors := int64(binary.LittleEndian.Uint64(boot[40:48]))
	mftLCN := int64(binary.LittleEndian.Uint64(boot[48:56]))
	recRaw := int8(boot[64])
	var recSize int
	if recRaw < 0 {
		recSize = 1 << uint(-recRaw)
	} else {
		recSize = int(recRaw) * int(spc) * int(bps)
	}
	if recSize != 1024 && recSize != 2048 && recSize != 4096 {
		return nil, fmt.Errorf("implausible MFT record size %d", recSize)
	}
	cluster := bps * spc
	return &NTFSVol{
		r:          r,
		base:       base,
		cluster:    cluster,
		recordSize: recSize,
		mftByte:    base + mftLCN*cluster,
		totalClust: totalSectors / spc,
	}, nil
}

// mftRecord is one parsed FILE record.
type mftRecord struct {
	number      int64
	inUse       bool
	isDir       bool
	baseRef     int64 // -1 when this record is its own base
	names       []ntfsName
	dataRuns    [][2]int64 // (lcn, clusters) for unnamed $DATA
	resident    []byte     // unnamed $DATA when resident
	residentOK  bool
	residentPos int // record-relative offset of the resident value
	dataSize    int64
}

// readMFTRecord reads and fixups record number n via the MFT run mapping.
func (v *NTFSVol) readMFTRecord(runs [][2]int64, n int64) ([]byte, bool) {
	off := n * int64(v.recordSize)
	var abs int64 = -1
	if len(runs) == 0 {
		abs = v.mftByte + off
	} else {
		// Walk the $MFT data runs to the record's absolute offset.
		rest := off
		for _, rn := range runs {
			span := rn[1] * v.cluster
			if rest < span {
				abs = v.base + rn[0]*v.cluster + rest
				break
			}
			rest -= span
		}
		if abs < 0 {
			return nil, false
		}
	}
	raw := make([]byte, v.recordSize)
	if _, err := v.r.ReadAt(raw, abs); err != nil {
		return nil, false
	}
	if string(raw[:4]) != "FILE" {
		return nil, false
	}
	applyUSA(raw)
	return raw, true
}

// applyUSA performs the update-sequence fixup best-effort: on any mismatch
// (common for long-deleted records) the record is left as read.
func applyUSA(rec []byte) {
	if len(rec) < 8 {
		return
	}
	usaOff := int(binary.LittleEndian.Uint16(rec[4:6]))
	usaCount := int(binary.LittleEndian.Uint16(rec[6:8]))
	if usaOff < 8 || usaCount < 2 || usaOff+2*usaCount > len(rec) {
		return
	}
	sectors := usaCount - 1
	if len(rec)%sectors != 0 {
		return
	}
	size := len(rec) / sectors
	if size != 512 && size != 1024 && size != 2048 && size != 4096 {
		return
	}
	usn := binary.LittleEndian.Uint16(rec[usaOff : usaOff+2])
	for i := 0; i < sectors; i++ {
		end := (i+1)*size - 2
		if binary.LittleEndian.Uint16(rec[end:end+2]) != usn {
			return
		}
	}
	for i := 0; i < sectors; i++ {
		end := (i+1)*size - 2
		copy(rec[end:end+2], rec[usaOff+2+i*2:usaOff+4+i*2])
	}
}

// parseMFTRecord decodes names and the unnamed $DATA attribute.
func parseMFTRecord(n int64, rec []byte) *mftRecord {
	if len(rec) < 48 {
		return nil
	}
	attrOff := int(binary.LittleEndian.Uint16(rec[20:22]))
	flags := binary.LittleEndian.Uint16(rec[22:24])
	used := int(binary.LittleEndian.Uint32(rec[24:28]))
	if attrOff < 48 || attrOff >= len(rec) || used > len(rec) {
		return nil
	}
	baseRef := int64(binary.LittleEndian.Uint64(rec[32:40])) & 0xFFFFFFFFFFFF
	m := &mftRecord{number: n, baseRef: baseRef}
	m.inUse = flags&1 != 0
	m.isDir = flags&2 != 0
	for p := attrOff; p+8 <= used; {
		typ := binary.LittleEndian.Uint32(rec[p : p+4])
		if typ == ntfsAttrEnd {
			break
		}
		length := int(binary.LittleEndian.Uint32(rec[p+4 : p+8]))
		if length < 24 || p+length > used {
			break
		}
		nonRes := rec[p+8] != 0
		nameLen := int(rec[p+9])
		body := rec[p : p+length]
		switch typ {
		case ntfsAttrFileName:
			if !nonRes {
				if name, ns := parseFileName(body); name != "" {
					m.names = append(m.names, ntfsName{name: name, ns: ns})
				}
			}
		case ntfsAttrData:
			if nameLen != 0 {
				break // alternate stream, not file content
			}
			if nonRes {
				runs, size, ok := parseDataRuns(body)
				if ok {
					m.dataRuns = runs
					m.dataSize = size
				}
			} else if val, size, valOff, ok := parseResident(body); ok {
				m.resident = val
				m.residentOK = true
				m.dataSize = size
				m.residentPos = p + valOff // record-relative value offset
			}
		}
		if length == 0 {
			break
		}
		p += (length + 7) &^ 7
	}
	return m
}

// parseResident extracts a resident attribute value plus its body-relative
// offset, so callers can map the value back to image bytes.
func parseResident(body []byte) (val []byte, size int64, valOff int, ok bool) {
	if len(body) < 24 {
		return nil, 0, 0, false
	}
	valLen := int(binary.LittleEndian.Uint32(body[16:20]))
	valOff = int(binary.LittleEndian.Uint16(body[20:22]))
	if valOff < 0 || valLen < 0 || valOff+valLen > len(body) {
		return nil, 0, 0, false
	}
	out := make([]byte, valLen)
	copy(out, body[valOff:valOff+valLen])
	return out, int64(valLen), valOff, true
}

// parseDataRuns decodes a nonresident $DATA runlist into (lcn, clusters)
// pairs plus the real data size.
func parseDataRuns(body []byte) ([][2]int64, int64, bool) {
	if len(body) < 64 {
		return nil, 0, false
	}
	runOff := int(binary.LittleEndian.Uint16(body[32:34]))
	realSize := int64(binary.LittleEndian.Uint64(body[48:56]))
	if runOff <= 0 || runOff >= len(body) {
		return nil, 0, false
	}
	var runs [][2]int64
	var lcn int64
	for p := runOff; p < len(body); {
		head := body[p]
		p++
		if head == 0 {
			break
		}
		lenBytes := int(head & 0x0F)
		offBytes := int(head >> 4)
		if lenBytes == 0 || lenBytes > 8 || offBytes > 8 || p+lenBytes+offBytes > len(body) {
			return nil, 0, false
		}
		var clusters int64
		for i := 0; i < lenBytes; i++ {
			clusters |= int64(body[p+i]) << uint(8*i)
		}
		p += lenBytes
		var delta int64
		for i := 0; i < offBytes; i++ {
			delta |= int64(body[p+i]) << uint(8*i)
		}
		if offBytes > 0 && body[p+offBytes-1]&0x80 != 0 {
			delta |= -1 << uint(8*offBytes) // sign-extend
		}
		p += offBytes
		if offBytes == 0 {
			continue // sparse hole, no storage
		}
		lcn += delta
		if lcn < 0 || clusters <= 0 {
			return nil, 0, false
		}
		runs = append(runs, [2]int64{lcn, clusters})
		if len(runs) > 1<<20 {
			return nil, 0, false
		}
	}
	return runs, realSize, true
}

// ntfsName is a filename with its $FILE_NAME namespace: 0 POSIX, 1 Win32,
// 2 DOS (8.3 alias), 3 Win32+DOS.
type ntfsName struct {
	name string
	ns   byte
}

// parseFileName decodes a resident $FILE_NAME value to a string plus its
// namespace.
func parseFileName(body []byte) (string, byte) {
	val, _, _, ok := parseResident(body)
	if !ok || len(val) < 66 {
		return "", 0
	}
	nameLen := int(val[64])
	ns := val[65]
	if nameLen <= 0 || 66+2*nameLen > len(val) {
		return "", 0
	}
	u16 := make([]uint16, nameLen)
	for i := 0; i < nameLen; i++ {
		u16[i] = binary.LittleEndian.Uint16(val[66+2*i : 68+2*i])
	}
	name := string(utf16.Decode(u16))
	for _, r := range name {
		if r < 0x20 || r == 0x7F {
			return "", 0
		}
	}
	return name, ns
}

// Entries enumerates file records (live and deleted) with names, following
// the $MFT run mapping. Extension records merge into their base entry.
func (v *NTFSVol) Entries() ([]FSEntry, error) {
	runs := v.mftRuns()
	type accum struct {
		rec   *mftRecord
		order int
	}
	bases := map[int64]*accum{}
	var order []int64
	get := func(n int64) *accum {
		if a, ok := bases[n]; ok {
			return a
		}
		a := &accum{order: len(order)}
		bases[n] = a
		order = append(order, n)
		return a
	}
	badStreak := 0
	for n := int64(0); n < mftRecordCap; n++ {
		raw, ok := v.readMFTRecord(runs, n)
		if !ok {
			badStreak++
			if badStreak > 128 {
				break
			}
			continue
		}
		badStreak = 0
		rec := parseMFTRecord(n, raw)
		if rec == nil {
			continue
		}
		// Base records carry a null base reference (0); anything else
		// (other than a self reference, tolerated) is an extension
		// record whose runs merge into the base entry.
		if rec.baseRef != 0 && rec.baseRef != n {
			// Extension record: merge data runs into the base entry.
			a := get(rec.baseRef)
			if a.rec == nil {
				a.rec = &mftRecord{number: rec.baseRef, inUse: rec.inUse}
			}
			a.rec.dataRuns = append(a.rec.dataRuns, rec.dataRuns...)
			if rec.dataSize > a.rec.dataSize {
				a.rec.dataSize = rec.dataSize
			}
			continue
		}
		a := get(n)
		if a.rec == nil {
			a.rec = rec
		} else {
			a.rec.names = append(a.rec.names, rec.names...)
			a.rec.dataRuns = append(a.rec.dataRuns, rec.dataRuns...)
			if !rec.inUse {
				a.rec.inUse = false
			}
			if rec.dataSize > a.rec.dataSize {
				a.rec.dataSize = rec.dataSize
			}
			if rec.residentOK && !a.rec.residentOK {
				a.rec.resident = rec.resident
				a.rec.residentOK = true
				a.rec.residentPos = rec.residentPos
			}
		}
	}
	var out []FSEntry
	for _, n := range order {
		rec := bases[n].rec
		if rec == nil || rec.isDir || len(rec.names) == 0 {
			continue
		}
		e := FSEntry{
			Name:    pickName(rec.names),
			Names:   flatNames(rec.names),
			Size:    rec.dataSize,
			Deleted: !rec.inUse,
			Note:    fmt.Sprintf("mft:%d", n),
		}
		if rec.residentOK {
			// Resident content lives in the record; expose just the
			// value bytes so filename metadata is not scanned.
			if abs := v.mftAbs(runs, n); abs >= 0 && len(rec.resident) > 0 {
				e.Extents = []FSExtent{{Start: abs + int64(rec.residentPos), Len: int64(len(rec.resident))}}
			}
		} else {
			var ext []FSExtent
			for _, rn := range rec.dataRuns {
				ext = append(ext, FSExtent{
					Start: v.base + rn[0]*v.cluster,
					Len:   rn[1] * v.cluster,
				})
			}
			e.Extents = mergeExtents(ext)
		}
		out = append(out, e)
	}
	return out, nil
}

// mftRuns returns the $MFT unnamed-$DATA runlist from record 0, or nil to
// read the MFT contiguously from the boot-sector LCN.
func (v *NTFSVol) mftRuns() [][2]int64 {
	raw := make([]byte, v.recordSize)
	if _, err := v.r.ReadAt(raw, v.mftByte); err != nil {
		return nil
	}
	if string(raw[:4]) != "FILE" {
		return nil
	}
	applyUSA(raw)
	rec := parseMFTRecord(0, raw)
	if rec == nil || len(rec.dataRuns) == 0 {
		return nil
	}
	return rec.dataRuns
}

// mftAbs maps record n to its image-absolute offset via runs.
func (v *NTFSVol) mftAbs(runs [][2]int64, n int64) int64 {
	off := n * int64(v.recordSize)
	if len(runs) == 0 {
		return v.mftByte + off
	}
	rest := off
	for _, rn := range runs {
		span := rn[1] * v.cluster
		if rest < span {
			return v.base + rn[0]*v.cluster + rest
		}
		rest -= span
	}
	return -1
}

// pickName prefers Win32-namespace names over DOS aliases, then the
// longest name.
func pickName(names []ntfsName) string {
	best := names[0]
	better := func(n ntfsName) bool {
		if (best.ns == 1 || best.ns == 3) != (n.ns == 1 || n.ns == 3) {
			return n.ns == 1 || n.ns == 3
		}
		return len(n.name) > len(best.name)
	}
	for _, n := range names[1:] {
		if better(n) {
			best = n
		}
	}
	return best.name
}

func flatNames(names []ntfsName) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = n.name
	}
	return out
}

// Unallocated returns free-cluster byte ranges from $Bitmap (MFT record 6).
func (v *NTFSVol) Unallocated() ([]FSExtent, error) {
	runs := v.mftRuns()
	raw, ok := v.readMFTRecord(runs, 6)
	if !ok {
		return nil, fmt.Errorf("cannot read $Bitmap record")
	}
	rec := parseMFTRecord(6, raw)
	if rec == nil || len(rec.dataRuns) == 0 {
		return nil, fmt.Errorf("no $Bitmap runs")
	}
	need := (v.totalClust + 7) / 8
	if need <= 0 || need > 1<<31 {
		return nil, fmt.Errorf("implausible bitmap size %d", need)
	}
	bitmap := make([]byte, 0, need)
	for _, rn := range rec.dataRuns {
		if int64(len(bitmap)) >= need {
			break
		}
		chunk := rn[1] * v.cluster
		if int64(len(bitmap))+chunk > need {
			chunk = need - int64(len(bitmap))
		}
		buf := make([]byte, chunk)
		if _, err := v.r.ReadAt(buf, v.base+rn[0]*v.cluster); err != nil {
			return nil, fmt.Errorf("cannot read $Bitmap data: %w", err)
		}
		bitmap = append(bitmap, buf...)
	}
	if int64(len(bitmap)) < need {
		return nil, fmt.Errorf("short $Bitmap: %d of %d bytes", len(bitmap), need)
	}
	var out []FSExtent
	var start = int64(-1)
	for c := int64(0); c < v.totalClust; c++ {
		alloc := bitmap[c/8]&(1<<uint(c%8)) != 0
		if !alloc && start < 0 {
			start = c
		}
		if (alloc || c == v.totalClust-1) && start >= 0 {
			end := c
			if alloc {
				end = c - 1
			}
			if end >= start {
				out = append(out, FSExtent{
					Start: v.base + start*v.cluster,
					Len:   (end - start + 1) * v.cluster,
				})
			}
			start = -1
		}
	}
	return out, nil
}
