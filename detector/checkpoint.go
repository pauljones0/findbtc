package detector

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Checkpoint records scan progress so an interrupted scan can resume without
// re-scanning completed bytes. Ranges == nil is a legacy single-target
// journal (Offset is an absolute file offset); otherwise Offset is an
// absolute offset within Ranges[RangeIndex].
type Checkpoint struct {
	Path    string    `json:"path"`
	Offset  int64     `json:"offset"`
	Updated time.Time `json:"updated"`
	// Ranges and RangeIndex appear only on range-scan journals (-fs,
	// -unallocated-only). Absent fields mean a legacy journal.
	Ranges     []FSExtent `json:"ranges,omitempty"`
	RangeIndex int        `json:"range_index,omitempty"`
}

// Journal the root target every N blocks (256 x 4kB = 1MB).
const checkpointBlockInterval = 256

// writeCheckpoint atomically records that path is scanned up to offset.
// Journal failures warn; they must never fail the scan itself.
func writeCheckpoint(log io.Writer, file, path string, offset int64) {
	writeCheckpointData(log, file, Checkpoint{Path: path, Offset: offset, Updated: time.Now().UTC()})
}

// writeCheckpointRange atomically records range-scan progress: ranges is
// the full range list (for resume validation), index the range in flight,
// offset the absolute file offset scanned up to within it.
func writeCheckpointRange(log io.Writer, file, path string, ranges []FSExtent, index int, offset int64) {
	writeCheckpointData(log, file, Checkpoint{Path: path, Offset: offset, Updated: time.Now().UTC(), Ranges: ranges, RangeIndex: index})
}

func writeCheckpointData(log io.Writer, file string, cp Checkpoint) {
	raw, err := json.Marshal(cp)
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(file), ".findbtc-checkpoint-*")
	if err != nil {
		logLinef(log, "[checkpoint] warning: %s\n", err.Error())
		return
	}
	tmpName := tmp.Name()
	_, werr := tmp.Write(append(raw, '\n'))
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Rename(tmpName, file) != nil {
		os.Remove(tmpName)
		logLinef(log, "[checkpoint] warning: cannot write %s\n", file)
	}
}

// ReadCheckpoint loads a journal written by writeCheckpoint.
func ReadCheckpoint(file string) (Checkpoint, error) {
	var cp Checkpoint
	raw, err := os.ReadFile(file)
	if err != nil {
		return cp, err
	}
	if err := json.Unmarshal(raw, &cp); err != nil {
		return cp, fmt.Errorf("bad checkpoint %s: %w", file, err)
	}
	if cp.Path == "" || cp.Offset < 0 || cp.RangeIndex < 0 {
		return cp, fmt.Errorf("bad checkpoint %s: missing path or negative offset", file)
	}
	for i, r := range cp.Ranges {
		if r.Start < 0 || r.Len <= 0 {
			return cp, fmt.Errorf("bad checkpoint %s: range %d has non-positive geometry", file, i)
		}
	}
	return cp, nil
}
