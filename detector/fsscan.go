package detector

import (
	"fmt"
	"io"
	"os"
)

// FSVol abstracts the filesystem layer: named entries plus unallocated
// ranges. NTFSVol and ExtVol both satisfy it.
type FSVol interface {
	Entries() ([]FSEntry, error)
	Unallocated() ([]FSExtent, error)
}

// OpenFS detects the filesystem at base (NTFS, then ext) and returns its
// kind label ("ntfs", "ext") plus the volume.
func OpenFS(r io.ReaderAt, base int64) (string, FSVol, error) {
	if vol, err := OpenNTFS(r, base); err == nil {
		return "ntfs", vol, nil
	}
	if vol, err := OpenExt(r, base); err == nil {
		return "ext", vol, nil
	}
	return "", nil, fmt.Errorf("no NTFS or ext filesystem at offset %d (point -fs-offset at the volume boot sector; partition tables are not followed)", base)
}

// ScanFS enumerates the filesystem at base and scans every deleted entry's
// content ranges, stamping each detection with its filename (or metadata
// note when the name is lost). Live entries are inventoried but not
// scanned: raw scanning already covers live content. onEntry observes
// every entry for the inventory; onDetection observes content hits.
func ScanFS(path string, base int64, opts Options, onDetection func(Detection), onProgress func(ProgressInfo), onEntry func(kind string, e FSEntry)) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("cannot open %s: %w", path, err)
	}
	kind, vol, err := OpenFS(f, base)
	if err != nil {
		f.Close()
		return "", err
	}
	entries, err := vol.Entries()
	if err != nil {
		f.Close()
		return "", err
	}
	f.Close()
	for _, e := range entries {
		if onEntry != nil {
			onEntry(kind, e)
		}
	}
	for _, e := range entries {
		if !e.Deleted || len(e.Extents) == 0 {
			continue
		}
		label := e.Name
		if label == "" {
			label = e.Note
		}
		name := label
		err := ScanRangesWithOptions(path, e.Extents, opts, func(d Detection) {
			d.FileName = name
			onDetection(d)
		}, onProgress)
		if err != nil {
			return kind, fmt.Errorf("scanning %s: %w", label, err)
		}
	}
	return kind, nil
}

// UnallocatedRanges returns the free-space extents of the filesystem at
// base for --unallocated-only scans.
func UnallocatedRanges(path string, base int64) (string, []FSExtent, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", nil, fmt.Errorf("cannot open %s: %w", path, err)
	}
	defer f.Close()
	kind, vol, err := OpenFS(f, base)
	if err != nil {
		return "", nil, err
	}
	free, err := vol.Unallocated()
	if err != nil {
		return "", nil, err
	}
	return kind, free, nil
}
