package detector

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Checkpoint records scan progress so an interrupted scan can resume without
// re-scanning completed bytes.
type Checkpoint struct {
	Path    string    `json:"path"`
	Offset  int64     `json:"offset"`
	Updated time.Time `json:"updated"`
}

// Journal the root target every N blocks (256 x 4kB = 1MB).
const checkpointBlockInterval = 256

// writeCheckpoint atomically records that path is scanned up to offset.
// Journal failures warn; they must never fail the scan itself.
func writeCheckpoint(file, path string, offset int64) {
	raw, err := json.Marshal(Checkpoint{Path: path, Offset: offset, Updated: time.Now().UTC()})
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(file), ".findbtc-checkpoint-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[checkpoint] warning: %s\n", err.Error())
		return
	}
	tmpName := tmp.Name()
	_, werr := tmp.Write(append(raw, '\n'))
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Rename(tmpName, file) != nil {
		os.Remove(tmpName)
		fmt.Fprintf(os.Stderr, "[checkpoint] warning: cannot write %s\n", file)
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
	if cp.Path == "" || cp.Offset < 0 {
		return cp, fmt.Errorf("bad checkpoint %s: missing path or negative offset", file)
	}
	return cp, nil
}
