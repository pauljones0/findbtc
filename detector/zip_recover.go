package detector

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"io"
)

// Single-entry recovery for zip archives whose end-of-central-directory
// record is lost (truncated or partially overwritten files). Intact archives
// keep flowing through the ECD path; local-header candidates covered by an
// intact archive are dropped at flush time so members are never scanned twice.
//
// Collection is speculative and quiet: most magic hits are random bytes that
// fail header validation. Only entries with explicit sizes are recoverable;
// data-descriptor entries (flag bit 3) carry no sizes and are skipped.

// Magic preamble for a local file header.
var ZIP_LOCAL_HEADER = []byte{0x50, 0x4b, 0x03, 0x04}

const (
	zipLocalMethodStored   = 0
	zipLocalMethodDeflate  = 8
	zipLocalFlagEncrypted  = 0x1
	zipLocalFlagDescriptor = 0x8
)

// zipCandidate is one validated local file header awaiting flush.
type zipCandidate struct {
	source     scanTarget
	dataOff    int64
	compSize   int64
	uncompSize int64
	method     uint16
	name       string
}

// zipRange marks source bytes already claimed by an intact archive.
type zipRange struct {
	source     scanTarget
	start, end int64
}

// parseZipCandidate validates the local header at absolute offset hdrAbs,
// reading header bytes from the block when present and via ReadAt otherwise.
// Non-ReadAt sources (gzip members) only resolve block-contained headers.
func parseZipCandidate(source scanTarget, data []byte, hdrAbs, dataAbs int64, dataLen int64) (zipCandidate, bool) {
	raw, ok := headerBytes(source, data, hdrAbs, dataAbs, dataLen, 30)
	if !ok {
		return zipCandidate{}, false
	}
	flags := binary.LittleEndian.Uint16(raw[6:8])
	method := binary.LittleEndian.Uint16(raw[8:10])
	compSize := binary.LittleEndian.Uint32(raw[18:22])
	uncompSize := binary.LittleEndian.Uint32(raw[22:26])
	nameLen := binary.LittleEndian.Uint16(raw[26:28])
	extraLen := binary.LittleEndian.Uint16(raw[28:30])

	if raw[4] > 63 {
		return zipCandidate{}, false
	}
	if flags&zipLocalFlagEncrypted != 0 || flags&zipLocalFlagDescriptor != 0 {
		return zipCandidate{}, false
	}
	if method != zipLocalMethodStored && method != zipLocalMethodDeflate {
		return zipCandidate{}, false
	}
	if compSize == 0xFFFFFFFF || uncompSize == 0xFFFFFFFF {
		return zipCandidate{}, false // ZIP64 locators need the central directory
	}
	if compSize == 0 || nameLen == 0 || nameLen > 4096 {
		return zipCandidate{}, false
	}
	if method == zipLocalMethodStored && compSize != uncompSize {
		return zipCandidate{}, false
	}
	if method == zipLocalMethodDeflate && uncompSize == 0 {
		return zipCandidate{}, false
	}
	if int64(uncompSize) > maxZipMemberBytes {
		return zipCandidate{}, false
	}

	rest, ok := headerBytes(source, data, hdrAbs+30, dataAbs, dataLen, int64(nameLen)+int64(extraLen))
	if !ok {
		return zipCandidate{}, false
	}
	name := string(rest[:nameLen])
	if len(name) > 256 {
		name = name[:256]
	}
	return zipCandidate{
		source:     source,
		dataOff:    hdrAbs + 30 + int64(nameLen) + int64(extraLen),
		compSize:   int64(compSize),
		uncompSize: int64(uncompSize),
		method:     method,
		name:       name,
	}, true
}

// headerBytes returns n bytes at absolute offset, preferring the block copy.
func headerBytes(source scanTarget, data []byte, abs, dataAbs, dataLen int64, n int64) ([]byte, bool) {
	if abs >= dataAbs && abs+n <= dataAbs+dataLen {
		return data[abs-dataAbs : abs-dataAbs+n], true
	}
	f, err := source.Open()
	if err != nil {
		return nil, false
	}
	defer f.Close()
	raw := make([]byte, n)
	var have int64
	for have < n {
		m, err := f.ReadAt(raw[have:], abs+have)
		have += int64(m)
		if err != nil || m == 0 {
			return nil, false
		}
	}
	return raw, true
}

// flushZipCandidates publishes pending local-header entries not already
// covered by an intact archive, and reports how many were published.
func flushZipCandidates(pending *[]zipCandidate, published *[]zipRange, scanTargets chan scanTarget, log io.Writer, gate *pubGate) int {
	n := 0
	for _, c := range *pending {
		if c.source.Depth()+1 > maxArchiveDepth {
			logLinef(log, "[scan] Skipping archive nested past depth %d in %s\n", maxArchiveDepth, c.source.Describe())
			gate.notePolicySkip(c.source)
			continue
		}
		covered := false
		for _, r := range *published {
			if r.source == c.source && r.start <= c.dataOff && c.dataOff+c.compSize <= r.end {
				covered = true
				break
			}
		}
		if covered {
			continue
		}
		if !gatePublishFlush(gate, scanTargets, &zipEntryTarget{
			source:     c.source,
			name:       c.name,
			dataOff:    c.dataOff,
			compSize:   c.compSize,
			uncompSize: c.uncompSize,
			method:     c.method,
		}) {
			continue
		}
		n++
		*published = append(*published, zipRange{c.source, c.dataOff, c.dataOff + c.compSize})
	}
	return n
}

// zipEntryTarget scans one recovered local file header entry.
type zipEntryTarget struct {
	source     scanTarget
	name       string
	dataOff    int64
	compSize   int64
	uncompSize int64
	method     uint16
}

func (t *zipEntryTarget) Describe() string {
	return fmt.Sprintf("ZipEntry %q @ byte %d in [%s]", t.name, t.dataOff, t.source.Describe())
}
func (t *zipEntryTarget) StartOffset() int64 {
	return 0
}
func (t *zipEntryTarget) Size() (int64, error) {
	return t.uncompSize, nil
}
func (t *zipEntryTarget) Depth() int {
	return t.source.Depth() + 1
}
func (t *zipEntryTarget) Open() (TargetReader, error) {
	f, err := t.source.Open()
	if err != nil {
		return nil, err
	}
	if t.method == zipLocalMethodStored {
		return &sectionTargetReader{io.NewSectionReader(f, t.dataOff, t.compSize), f}, nil
	}
	defer f.Close()
	fr := flate.NewReader(io.NewSectionReader(f, t.dataOff, t.compSize))
	defer fr.Close()
	// Raw flate has no declared-size enforcement (unlike archive/zip),
	// so this cap is the only thing standing between a lying local
	// header and unbounded inflation.
	data, err := inflateCapped(fr, maxZipMemberBytes, "entry")
	if err != nil {
		return nil, err
	}
	return &closableBytesReader{bytes.NewReader(data)}, nil
}

type sectionTargetReader struct {
	*io.SectionReader
	closer io.Closer
}

func (r *sectionTargetReader) Close() error {
	return r.closer.Close()
}
