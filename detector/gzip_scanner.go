package detector

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
)

// GZIP format: https://tools.ietf.org/html/rfc1952

var GZIP_HEADER = []byte{0x1f, 0x8b}

type gzipScanTarget struct {
	source     scanTarget
	gzipOffset int64
}

func (t *gzipScanTarget) Describe() string {
	return fmt.Sprintf("Gzipfile @ byte %d in [%s]", t.gzipOffset, t.source.Describe())
}
func (t *gzipScanTarget) StartOffset() int64 {
	return 0
}
func (t *gzipScanTarget) Depth() int {
	return t.source.Depth() + 1
}
func (t *gzipScanTarget) Size() (int64, error) {
	return -1, nil
}
func (t *gzipScanTarget) Open() (TargetReader, error) {
	f, err := t.source.Open()
	if err != nil {
		return nil, err
	}

	if _, err := f.Seek(t.gzipOffset, 0); err != nil {
		f.Close()
		return nil, err
	}

	reader, err := gzip.NewReader(f)
	if err != nil {
		f.Close()
		return nil, err
	}

	return &gzipTargetReader{reader, f}, nil
}

type gzipTargetReader struct {
	r  *gzip.Reader
	fc io.Closer
}

func (r *gzipTargetReader) ReadAt(p []byte, off int64) (n int, err error) {
	return -1, fmt.Errorf("indexed reads of gzip files not yet implemented")
}
func (r *gzipTargetReader) Read(p []byte) (n int, err error) {
	return r.r.Read(p)
}
func (r *gzipTargetReader) Seek(offset int64, whence int) (int64, error) {
	if offset == 0 {
		return 0, nil
	}
	return 0, fmt.Errorf("seeking not implemented for gzip files")
}
func (r *gzipTargetReader) Close() error {
	defer r.fc.Close()
	return r.r.Close()
}

func scanGzipFiles(ctx context.Context, in, out chan *Block, scanTargets chan scanTarget, log io.Writer) {
	openedFiles := 0
	for {
		var block *Block
		select {
		case <-ctx.Done():
			return
		case block = <-in:
		}

		if block == EOF {
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
		for i := 0; i+len(GZIP_HEADER) <= len(data); {
			j := bytes.Index(data[i:], GZIP_HEADER)
			if j == -1 {
				break
			}
			abs := i + j
			// Occurrences fully inside the overlap prefix were already
			// handled with the previous block.
			if abs+len(GZIP_HEADER) > block.overlap && gzipHeaderPlausible(data[abs:]) {
				openedFiles += scanGzipFile(block.source, block.offset+int64(abs), scanTargets, log)
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

// gzipHeaderPlausible pre-filters 2-byte magic hits using the fixed
// header bytes already in hand: CM must be 8 (deflate) and the FLG
// reserved bits must be clear, exactly what gzip.NewReader demands. It
// returns true whenever it cannot decide (short tail), so the full
// check below stays authoritative. This matters because the full check
// opens the source, and opening a zip member inflates it whole —
// without the pre-filter every random 0x1f8b re-inflates megabytes.
func gzipHeaderPlausible(tail []byte) bool {
	if len(tail) < 4 {
		return true
	}
	return tail[2] == 8 && tail[3]&0xE0 == 0
}

func scanGzipFile(source scanTarget, gzipOffset int64, scanTargets chan scanTarget, log io.Writer) int {
	if source.Depth()+1 > maxArchiveDepth {
		logLinef(log, "[scan] Skipping archive nested past depth %d in %s\n", maxArchiveDepth, source.Describe())
		return 0
	}
	// Sanity check
	f, err := source.Open()
	if err != nil {
		return 0
	}
	defer f.Close()
	if _, err = f.Seek(gzipOffset, 0); err != nil {
		return 0
	}

	r, err := gzip.NewReader(f)
	if err != nil {
		return 0
	}
	defer r.Close()
	if _, err = r.Read(make([]byte, 1)); err != nil {
		return 0
	}

	scanTargets <- &gzipScanTarget{
		source:     source,
		gzipOffset: gzipOffset,
	}

	return 1
}
