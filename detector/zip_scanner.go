package detector

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
)

// This implements a forensic system for discovering and decoding zipfiles
// Zipfiles have their main file metadata at the end, so the current system
// scans for a magic preamble for the end record, and determines the offsets to
// expect a full zipfile at from that metadata.
// Format for zipfiles from https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT

// Note that each entry in a zipfile has a little header as well; it could be that
// that's enough to decode a given entry. If so, we could rewrite this to look at just
// a single zip entry, making it able to decode parts of zipfiles even if the whole
// file is not intact.

// Magic preamble for the end-of-central-directory record
var ZIP_ECD_HEADER = []byte{0x50, 0x4b, 0x05, 0x06}

// Size of the central directory in bytes
const ZIP_ECD_FIELD_CENTRAL_DIRECTORY_SIZE = 12

// Offset in bytes from the start of the central directory to the start of the zip file
const ZIP_ECD_FIELD_START_ARCHIVE_OFFSET = 16

// Size of the variable-length comment field in the end-of-central-directory record
const ZIP_ECD_FIELD_COMMENT_SIZE = 20

type zipScanTarget struct {
	source               scanTarget
	zipOffset            int64
	fileIndex            int
	zipSize              int64
	uncompressedFileSize int64
}

func (t *zipScanTarget) Describe() string {
	return fmt.Sprintf("Zipfile #%d @ byte %d in [%s]", t.fileIndex, t.zipOffset, t.source.Describe())
}
func (t *zipScanTarget) StartOffset() int64 {
	return 0
}
func (t *zipScanTarget) Depth() int {
	return t.source.Depth() + 1
}
func (t *zipScanTarget) Size() (int64, error) {
	return t.uncompressedFileSize, nil
}
func (t *zipScanTarget) Open() (TargetReader, error) {
	f, err := t.source.Open()
	if err != nil {
		return nil, err
	}
	// The member is fully inflated below and served from memory, so the
	// parent handle must not outlive this call: every nested zip target
	// would otherwise leak an OS file handle (on Windows the source file
	// then cannot be deleted after Scan returns).
	defer f.Close()

	// Try to read the zipfile;
	// TODO: More resilient zip reading may be possible; handling things like partials and corrupted files
	zipReader, err := zip.NewReader(&offsetReaderAt{f, t.zipOffset}, t.zipSize)
	if err != nil {
		return nil, err
	}

	reader, err := zipReader.File[t.fileIndex].Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	// The declared size was already checked at publish; re-check actual
	// bytes because hostile headers lie (a zip bomb declares small).
	// archive/zip also enforces declared sizes on read, so this is
	// belt-and-braces here — and load-bearing wherever raw flate is
	// inflated (see zip_recover.go).
	data, err := inflateCapped(reader, maxZipMemberBytes, "zip member")
	if err != nil {
		return nil, err
	}

	return &closableBytesReader{bytes.NewReader(data)}, nil
}

// inflateCapped reads r fully, failing if it yields more than cap bytes.
func inflateCapped(r io.Reader, cap int64, what string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, cap+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > cap {
		return nil, fmt.Errorf("%s inflates past %d bytes", what, cap)
	}
	return data, nil
}

type offsetReaderAt struct {
	r      io.ReaderAt
	offset int64
}

func (r *offsetReaderAt) ReadAt(p []byte, off int64) (int, error) {
	return r.r.ReadAt(p, r.offset+off)
}

type closableBytesReader struct {
	*bytes.Reader
}

func (c *closableBytesReader) Close() error {
	return nil
}

func scanZipFiles(ctx context.Context, in, out chan *Block, scanTargets chan scanTarget, log io.Writer, gate *pubGate) {
	openedFiles := 0
	// Local-header candidates are speculative: they flush at each target's
	// end-of-stream, when intact archives have already claimed their bytes,
	// so recovery never double-scans a healthy member. Blocks arrive grouped
	// by target ahead of their EOF, which makes the pending set attributable.
	var pending []zipCandidate
	var published []zipRange
	for {
		var block *Block
		select {
		case <-ctx.Done():
			return
		case block = <-in:
		}

		if block.barrier != nil {
			// Drain barrier: forward untouched. Not a target
			// boundary, so pending candidates and EOF
			// accounting stay exactly as they are.
			select {
			case <-ctx.Done():
				return
			case out <- block:
			}
			continue
		}

		if block == EOF {
			openedFiles += flushZipCandidates(&pending, &published, scanTargets, log, gate)
			pending = nil
			if openedFiles > 0 {
				openedFiles -= 1
				continue
			}

			select {
			case <-ctx.Done():
				return
			case out <- EOF:
			}
			continue
		}

		data := block.data[:block.length]
		for i := 0; i+len(ZIP_ECD_HEADER) <= len(data); {
			j := bytes.Index(data[i:], ZIP_ECD_HEADER)
			if j == -1 {
				break
			}
			abs := i + j
			// Occurrences fully inside the overlap prefix were already
			// handled with the previous block.
			if abs+len(ZIP_ECD_HEADER) > block.overlap {
				openedFiles += scanZipFile(block.source, block.offset+int64(abs), scanTargets, &published, log, gate)
			}
			i = abs + 1
		}

		for i := 0; i+len(ZIP_LOCAL_HEADER) <= len(data); {
			j := bytes.Index(data[i:], ZIP_LOCAL_HEADER)
			if j == -1 {
				break
			}
			abs := i + j
			if abs+len(ZIP_LOCAL_HEADER) > block.overlap {
				if c, ok := parseZipCandidate(block.source, data, block.offset+int64(abs), block.offset, int64(len(data))); ok {
					pending = append(pending, c)
				}
			}
			i = abs + 1
		}

		// Forward the raw block for other scanners
		select {
		case <-ctx.Done():
			return
		case out <- block:
		}
	}
}

func scanZipFile(source scanTarget, endOfCentralDirectoryOffset int64, scanTargets chan scanTarget, published *[]zipRange, log io.Writer, gate *pubGate) int {
	if source.Depth()+1 > maxArchiveDepth {
		logLinef(log, "[scan] Skipping archive nested past depth %d in %s\n", maxArchiveDepth, source.Describe())
		gate.notePolicySkip(source)
		return 0
	}
	startOffset, size, err := readZipFileSize(source, endOfCentralDirectoryOffset)
	if err != nil {
		// If we can't read the header, silently ignore this zipfile
		return 0
	}

	// Try to read the zipfile; archives embedded in a larger target start
	// at an offset, and zip.NewReader uses absolute ReadAt positions, so the
	// offset must be applied explicitly (a plain Seek has no effect).
	f, err := source.Open()
	if err != nil {
		return 0
	}
	defer f.Close()

	offset := startOffset

	reader, err := zip.NewReader(&offsetReaderAt{f, offset}, size)
	if err != nil {
		return 0
	}

	*published = append(*published, zipRange{source, offset, offset + size})

	// Publish each file inside the compressed archive as a new scan target
	newScanTargets := 0
	for fileIndex, fileInfo := range reader.File {
		if fileInfo.UncompressedSize64 > uint64(maxZipMemberBytes) {
			logLinef(log, "[scan] Skipping %d-byte member %q: over the %d-byte inflation cap\n",
				fileInfo.UncompressedSize64, fileInfo.Name, maxZipMemberBytes)
			gate.notePolicySkip(source)
			continue
		}
		if gatePublish(gate, scanTargets, &zipScanTarget{
			source:               source,
			zipOffset:            offset,
			fileIndex:            fileIndex,
			zipSize:              size,
			uncompressedFileSize: int64(fileInfo.UncompressedSize64),
		}) {
			newScanTargets++
		}
	}

	return newScanTargets
}

// Determine the size of a zipfile by decoding the end-of-central-directory record
// Returns the offset of the file start relative to endOfCentralDirectoryOffset, the total file size,
// and any errors.
func readZipFileSize(source scanTarget, endOfCentralDirectoryOffset int64) (int64, int64, error) {
	f, err := source.Open()
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	intBuffer := make([]byte, 4)
	if _, err = f.ReadAt(intBuffer, endOfCentralDirectoryOffset+ZIP_ECD_FIELD_CENTRAL_DIRECTORY_SIZE); err != nil {
		return 0, 0, err
	}
	centralDirectorySize := int64(binary.LittleEndian.Uint32(intBuffer))

	if _, err = f.ReadAt(intBuffer, endOfCentralDirectoryOffset+ZIP_ECD_FIELD_START_ARCHIVE_OFFSET); err != nil {
		return 0, 0, err
	}
	archiveStartFromCentralDirectory := int64(binary.LittleEndian.Uint32(intBuffer))

	if _, err = f.ReadAt(intBuffer[:2], endOfCentralDirectoryOffset+ZIP_ECD_FIELD_COMMENT_SIZE); err != nil {
		return 0, 0, err
	}
	commentFieldSize := int64(binary.LittleEndian.Uint16(intBuffer[:2]))

	fileOffsetFromECD := archiveStartFromCentralDirectory + centralDirectorySize
	totalSize := fileOffsetFromECD + ZIP_ECD_FIELD_COMMENT_SIZE + 2 + commentFieldSize

	return endOfCentralDirectoryOffset - fileOffsetFromECD, totalSize, nil
}
