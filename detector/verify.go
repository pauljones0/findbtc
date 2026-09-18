// Case-log verification: re-hash the source bytes behind each record so a
// reviewer can confirm the evidence is unchanged since the scan. Any
// mismatch — tampered source, edited log, unreadable bytes — fails loud.
package detector

import (
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
)

// VerifyCaseLog re-hashes every record in a JSONL case log, reporting one
// line per record to out. It returns an error when any record fails to
// verify, after checking the rest.
func VerifyCaseLog(logPath string, out io.Writer) error {
	f, err := os.Open(logPath)
	if err != nil {
		return fmt.Errorf("cannot open case log %s: %w", logPath, err)
	}
	defer f.Close()
	var failed int
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		n++
		var rec CaseLog
		if err := json.Unmarshal(line, &rec); err != nil {
			fmt.Fprintf(out, "record %d: BAD RECORD: %s\n", n, err)
			failed++
			continue
		}
		if err := verifyRecord(rec); err != nil {
			fmt.Fprintf(out, "record %d: MISMATCH %s: %s\n", n, rec.Source.Path, err)
			failed++
			continue
		}
		fmt.Fprintf(out, "record %d: OK %s (%d bytes hashed)\n", n, rec.Source.Path, rec.Hash.BytesHashed)
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("cannot read case log %s: %w", logPath, err)
	}
	if n == 0 {
		return fmt.Errorf("case log %s holds no records", logPath)
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d case-log records failed verification", failed, n)
	}
	return nil
}

// verifyRecord re-hashes [start_offset, size) minus skipped_ranges.
func verifyRecord(rec CaseLog) error {
	r, cleanup, err := openVerifySource(rec)
	if err != nil {
		return err
	}
	defer cleanup()
	skipped := append([]CaseSkipped(nil), rec.Skipped...)
	sort.Slice(skipped, func(i, j int) bool { return skipped[i].Start < skipped[j].Start })
	sha := sha256.New()
	md5h := md5.New()
	var hashed int64
	pos := rec.Source.StartOffset
	skipIdx := 0
	buf := make([]byte, 1<<20)
	for pos < rec.Source.Size {
		end := rec.Source.Size
		if skipIdx < len(skipped) && skipped[skipIdx].Start < end {
			end = skipped[skipIdx].Start
		}
		for pos < end {
			n := int64(len(buf))
			if pos+n > end {
				n = end - pos
			}
			m, rerr := r.ReadAt(buf[:n], pos)
			if m > 0 {
				sha.Write(buf[:m])
				md5h.Write(buf[:m])
				hashed += int64(m)
				pos += int64(m)
			}
			if rerr != nil {
				if rerr == io.EOF && m > 0 {
					continue
				}
				return fmt.Errorf("cannot re-read source at offset %d: %w", pos, rerr)
			}
			if m == 0 {
				return fmt.Errorf("cannot re-read source at offset %d: no bytes", pos)
			}
		}
		if skipIdx < len(skipped) && pos >= skipped[skipIdx].Start {
			if pos < skipped[skipIdx].End {
				pos = skipped[skipIdx].End
			}
			skipIdx++
		} else if pos >= end {
			break
		}
	}
	if hashed != rec.Hash.BytesHashed {
		return fmt.Errorf("re-read %d bytes, log says %d", hashed, rec.Hash.BytesHashed)
	}
	if got := hex.EncodeToString(sha.Sum(nil)); got != rec.Hash.SHA256 {
		return fmt.Errorf("sha256 %s, log says %s", got, rec.Hash.SHA256)
	}
	if got := hex.EncodeToString(md5h.Sum(nil)); got != rec.Hash.MD5 {
		return fmt.Errorf("md5 %s, log says %s", got, rec.Hash.MD5)
	}
	if rec.EWF != nil {
		layout, err := openEWFLayout(rec.Source.Path)
		if err != nil {
			return fmt.Errorf("cannot re-parse EWF set: %w", err)
		}
		if !layout.hasMD5 {
			return fmt.Errorf("EWF set has no stored MD5")
		}
		if got := hex.EncodeToString(layout.md5[:]); got != rec.EWF.StoredMD5 {
			return fmt.Errorf("stored md5 %s, log says %s", got, rec.EWF.StoredMD5)
		}
	}
	return nil
}

// openVerifySource opens the record's source for absolute-offset reads.
func openVerifySource(rec CaseLog) (io.ReaderAt, func(), error) {
	switch rec.Source.Kind {
	case "ewf", "split":
		tgt, err := detectScanTarget(rec.Source.Path, 0)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot open source: %w", err)
		}
		r, err := tgt.Open()
		if err != nil {
			return nil, nil, fmt.Errorf("cannot open source: %w", err)
		}
		return r, func() { r.Close() }, nil
	case "raw", "range":
		f, err := os.Open(rec.Source.Path)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot open source: %w", err)
		}
		return f, func() { f.Close() }, nil
	default:
		return nil, nil, fmt.Errorf("unknown source kind %q", rec.Source.Kind)
	}
}
