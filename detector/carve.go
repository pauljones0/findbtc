package detector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
)

// CarveInfo classifies carved bytes so triage can tell a database page from
// filler without opening the file.
type CarveInfo struct {
	Class string `json:"class"`
	// MagicOffset is the carve-file offset of the identifying magic, if any.
	MagicOffset *int64  `json:"magic_offset,omitempty"`
	Size        int64   `json:"size"`
	Entropy     float64 `json:"entropy_bits"`
}

// carveMagics maps identifying byte sequences to classes. The BDB magics come
// from db.in (DB_BTREEMAGIC 0x053162, DB_HASHMAGIC 0x061561, little-endian);
// the btree value is confirmed against test_wallet.dat's page header.
var carveMagics = []struct {
	class string
	magic []byte
}{
	{"sqlite", []byte("SQLite format 3\x00")},
	{"bdb", []byte{0x62, 0x31, 0x05, 0x00}},
	{"bdb", []byte{0x61, 0x15, 0x06, 0x00}},
	{"bbolt", []byte{0xED, 0x0C, 0xDA, 0xED}},
	{"gzip", []byte{0x1f, 0x8b}},
	{"zip", []byte{0x50, 0x4b, 0x03, 0x04}},
}

// carveConfig is the detector-internal form of the Options carving settings.
type carveConfig struct {
	dir          string
	contextBytes int64
	seqStart     int
}

// carveTempPrefix marks atomic-write staging files in carve
// directories. Staging names never match hit-NNNNNN.*, so carve
// numbering scans ignore them; CleanCarveTemps reaps them.
const carveTempPrefix = ".findbtc-tmp-"

// commitTempFile publishes a staged file at its final name: the
// old file (if any) is removed first so the rename works on
// Windows too. A kill can leave the old file, a missing file,
// or the new file — never torn bytes.
func commitTempFile(tmp *os.File, final string) error {
	name := tmp.Name()
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	os.Remove(final)
	if err := os.Rename(name, final); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

// writeFileAtomic writes data to dir/name via staging plus
// commit, so a kill never leaves torn bytes behind.
func writeFileAtomic(dir, name string, data []byte) error {
	tmp, err := os.CreateTemp(dir, carveTempPrefix+"*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	return commitTempFile(tmp, filepath.Join(dir, name))
}

// CleanCarveTemps removes staged atomic-write files left by
// killed runs. Best-effort: it reports how many it reaped and
// never fails the caller.
func CleanCarveTemps(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	reaped := 0
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), carveTempPrefix) || e.IsDir() {
			continue
		}
		if os.Remove(filepath.Join(dir, e.Name())) == nil {
			reaped++
		}
	}
	return reaped
}

// carveDetection writes the bytes surrounding a hit to dir as hit-NNNNNN.bin
// plus a JSON sidecar, and records the file on d. Carving is best-effort: a
// failure is returned but the caller still reports the detection. Bytes are
// streamed so large contexts never sit fully in memory. Every output
// commits atomically (staging plus rename), so a killed run leaves
// complete carves, missing carves, or at most one pair missing
// its sidecar — never torn bytes a resume would inherit.
func carveDetection(source scanTarget, d *Detection, dir string, contextBytes int64, seq int, log io.Writer) error {
	if contextBytes < 0 {
		contextBytes = 0
	}
	start := d.Offset - contextBytes
	if start < 0 {
		start = 0
	}
	size := d.Offset + int64(d.MatchLen) + contextBytes - start

	r, err := openRangeReader(source, start)
	if err != nil {
		return err
	}
	defer r.Close()

	binPath := filepath.Join(dir, fmt.Sprintf("hit-%06d.bin", seq))
	out, err := os.CreateTemp(dir, carveTempPrefix+"*")
	if err != nil {
		return err
	}
	written, copyErr := io.CopyN(out, r, size)
	if copyErr != nil && copyErr != io.EOF && copyErr != io.ErrUnexpectedEOF && written == 0 {
		out.Close()
		os.Remove(out.Name())
		return copyErr
	}
	// Partial carves (target ended, or a nested stream error
	// after N good bytes) still hold real target data, so they
	// are kept.
	if err := commitTempFile(out, binPath); err != nil {
		return err
	}

	d.CarvePath = binPath

	if info, err := classifyCarve(binPath, d.Offset-start, d.Offset-start+int64(d.MatchLen), written); err != nil {
		logLinef(log, "[carve] warning: could not classify %s: %s\n", binPath, err.Error())
	} else {
		d.Carve = info
	}

	// Best-effort crack-material extraction: the carve often holds the mkey
	// record or keystore the hit points at. The re-read is bounded; anything
	// unusable is skipped, never emitted as a bogus hash.
	d.Hashes = carveHashes(binPath, start)

	// Best-effort salvage: reassemble database pages from the carve into a
	// .salvage.db file with a page map, when at least two pages stitch.
	d.Salvage = carveSalvage(binPath, start, dir, seq, log)

	sidecar, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(dir, strings.TrimSuffix(filepath.Base(binPath), ".bin")+".json", append(sidecar, '\n'))
}

// sidecarPathFor names the JSON sidecar for a carve file. Patch
// attribution reuses it to re-marshal sidecars with commit/path
// after its post-pass.
func sidecarPathFor(binPath string) string {
	return strings.TrimSuffix(binPath, ".bin") + ".json"
}

// classifyCarve reads a bounded window around the hit from the carved file
// and classifies it. hitStart/hitEnd are carve-file offsets of the match;
// size is the carved byte count.
func classifyCarve(path string, hitStart, hitEnd, size int64) (*CarveInfo, error) {
	info := &CarveInfo{Size: size}
	if size == 0 {
		info.Class = "empty"
		return info, nil
	}
	wstart := hitStart - 4096
	if wstart < 0 {
		wstart = 0
	}
	wend := hitEnd + 4096
	if wend > size {
		wend = size
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	window := make([]byte, wend-wstart)
	if _, err := io.ReadFull(io.NewSectionReader(f, wstart, wend-wstart), window); err != nil {
		return nil, err
	}

	best := int64(-1)
	class := ""
	for _, m := range carveMagics {
		for i := 0; i+len(m.magic) <= len(window); {
			j := bytes.Index(window[i:], m.magic)
			if j == -1 {
				break
			}
			off := wstart + int64(i+j)
			if best < 0 || abs64(off-hitStart) < abs64(best-hitStart) {
				best, class = off, m.class
			}
			i += j + 1
		}
	}
	if best >= 0 {
		info.Class, info.MagicOffset = class, &best
	} else if printableRatio(window) >= 0.9 {
		info.Class = "text"
	} else if shannon(window) >= 7.0 {
		info.Class = "high-entropy"
	} else {
		info.Class = "unknown"
	}
	info.Entropy = math.Round(shannon(window)*100) / 100
	return info, nil
}

func abs64(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

func printableRatio(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	printable := 0
	for _, c := range b {
		if c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c <= 0x7e) {
			printable++
		}
	}
	return float64(printable) / float64(len(b))
}

func shannon(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	var h float64
	for _, n := range counts {
		if n == 0 {
			continue
		}
		p := float64(n) / float64(len(b))
		h -= p * math.Log2(p)
	}
	return h
}

// openRangeReader opens source positioned at absolute offset off. Streams
// without seeking (gzip members) are reopened and discarded through.
func openRangeReader(source scanTarget, off int64) (TargetReader, error) {
	r, err := source.Open()
	if err != nil {
		return nil, err
	}
	if _, err := r.Seek(off, io.SeekStart); err != nil {
		r.Close()
		r, err = source.Open()
		if err != nil {
			return nil, err
		}
		if _, err := io.CopyN(io.Discard, r, off); err != nil {
			r.Close()
			return nil, err
		}
	}
	return r, nil
}

// carveHashes re-reads a carved file (bounded) and extracts crack-ready
// password material. baseAbs is the target offset of the carve's first byte.
func carveHashes(binPath string, baseAbs int64) []CrackHash {
	f, err := os.Open(binPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || st.Size() > HashScanMaxBytes {
		return nil
	}
	buf, err := io.ReadAll(f)
	if err != nil {
		return nil
	}
	return ExtractHashes(buf, baseAbs)
}

// carveSalvage re-reads a carved file (bounded) and attempts database
// salvage, writing hit-NNNNNN.salvage.db beside the carve on success.
// baseAbs is the target offset of the carve's first byte.
func carveSalvage(binPath string, baseAbs int64, dir string, seq int, log io.Writer) *SalvageInfo {
	f, err := os.Open(binPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || st.Size() > SalvageMaxBytes {
		return nil
	}
	buf, err := io.ReadAll(f)
	if err != nil {
		return nil
	}
	r := Salvage(buf, baseAbs)
	if r == nil {
		return nil
	}
	salvName := fmt.Sprintf("hit-%06d.salvage.db", seq)
	salvPath := filepath.Join(dir, salvName)
	if err := writeFileAtomic(dir, salvName, r.Image); err != nil {
		logLinef(log, "[carve] warning: could not write salvage %s: %s\n", salvPath, err.Error())
		return nil
	}
	r.Info.Path = salvPath
	return &r.Info
}
