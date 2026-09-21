package detector

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanFSVolumesEmptyResumeRejectsChangedList(t *testing.T) {
	disk, starts := composeMixedDisk(t, "mbr")
	dir := t.TempDir()
	checkpoint := filepath.Join(dir, "journal.json")
	opts := Options{CheckpointPath: checkpoint, Log: io.Discard}
	if _, err := ScanFSVolumes(disk, 0, true, opts, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	cp, err := ReadCheckpoint(checkpoint)
	if err != nil || len(cp.Ranges) == 0 {
		t.Fatalf("initial scan must file nonempty ranges: %+v, %v", cp, err)
	}
	before, err := os.ReadFile(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(disk)
	if err != nil {
		t.Fatal(err)
	}
	// Make the deleted-entry list empty in both actual filesystems.
	for _, num := range []int64{13, 14, 15, 16} {
		at := starts[1] + 4*extTestBlock + (num-1)*128 + 26
		raw[at], raw[at+1] = 1, 0
	}
	g := fat32Geometry()
	root := starts[0] + g.clustOff(2)
	for slot := int64(0); ; slot++ {
		s := raw[root+slot*32 : root+(slot+1)*32]
		if s[0] == 0x00 {
			break
		}
		if s[0] == 0xE5 {
			s[0] = 0x00
			break
		}
	}
	if err := os.WriteFile(disk, raw, 0600); err != nil {
		t.Fatal(err)
	}
	targets, err := resolveVolumes(disk, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	_, ranges, _, err := flattenDeletedRanges(disk, targets, nil)
	if err != nil || len(ranges) != 0 {
		t.Fatalf("fixture still has %d ranges: %v", len(ranges), err)
	}
	opts.Resume = true
	opts.CaseLogPath = filepath.Join(dir, "case.jsonl")
	if _, err := ScanFSVolumes(disk, 0, true, opts, nil, nil, nil); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("nonempty-to-empty resume must reject the changed list: %v", err)
	}
	after, err := os.ReadFile(checkpoint)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("refused resume changed its checkpoint: %v", err)
	}
	if recs := readCaseLog(t, opts.CaseLogPath); len(recs) != 1 || recs[0].Status != "error" {
		t.Fatalf("refused resume must record an error: %+v", recs)
	}

	// No existing journal means the documented fresh-start policy still
	// applies, even when the current filesystem has nothing to scan.
	opts.CheckpointPath = filepath.Join(dir, "missing.json")
	opts.CaseLogPath = ""
	if _, err := ScanFSVolumes(disk, 0, true, opts, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(opts.CheckpointPath); !os.IsNotExist(err) {
		t.Fatalf("fresh empty run created a journal: %v", err)
	}
}
