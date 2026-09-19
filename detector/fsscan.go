package detector

import (
	"fmt"
	"io"
	"os"
	"strings"
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
	return "", nil, fmt.Errorf("no NTFS or ext filesystem at offset %d (for a full-disk image, omit -fs-offset to follow its partition table)", base)
}

// volumeTarget is one filesystem to scan: its base offset and kind.
type volumeTarget struct {
	base int64
	kind string
}

// resolveVolumes returns the scan targets for path. With autoSeed and no
// volume at base, the partition table is followed and every partition
// that opens as NTFS/ext becomes a target. Every failure names the path,
// the offset tried, and what the layout held, so a wrong-bytes scan is
// impossible: unknown layouts error, never guess.
func resolveVolumes(path string, base int64, autoSeed bool) ([]volumeTarget, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s: %w", path, err)
	}
	defer f.Close()
	if kind, _, err := OpenFS(f, base); err == nil {
		return []volumeTarget{{base: base, kind: kind}}, nil
	} else if !autoSeed {
		return nil, fmt.Errorf("%s: %v", path, err)
	} else {
		parts, perr := ScanPartitions(f)
		if perr != nil {
			return nil, fmt.Errorf("%s: no NTFS or ext filesystem at offset %d, and no usable partition table (%v); point -fs-offset at a volume boot sector", path, base, perr)
		}
		var targets []volumeTarget
		var descs []string
		var firstProbeErr error
		for _, p := range parts {
			descs = append(descs, p.String())
			kind, _, err := OpenFS(f, p.Start)
			if err != nil {
				if firstProbeErr == nil {
					firstProbeErr = fmt.Errorf("partition %d @%d: %v", p.Index, p.Start, err)
				}
				continue
			}
			targets = append(targets, volumeTarget{base: p.Start, kind: kind})
		}
		if len(targets) == 0 {
			return nil, fmt.Errorf("%s: partition table holds %d entries (%s) but none opens as NTFS/ext (first: %v); point -fs-offset at a volume boot sector", path, len(parts), strings.Join(descs, "; "), firstProbeErr)
		}
		return targets, nil
	}
}

// ScanFS enumerates the filesystem at base and scans every deleted entry's
// content ranges, stamping each detection with its filename (or metadata
// note when the name is lost). Live entries are inventoried but not
// scanned: raw scanning already covers live content. onEntry observes
// every entry for the inventory; onDetection observes content hits.
func ScanFS(path string, base int64, opts Options, onDetection func(Detection), onProgress func(ProgressInfo), onEntry func(kind string, e FSEntry)) (string, error) {
	kinds, err := ScanFSVolumes(path, base, false, opts, onDetection, onProgress, onEntry)
	if err != nil {
		return "", err
	}
	return kinds[0], nil
}

// ScanFSVolumes scans one volume (autoSeed false, at base) or every
// NTFS/ext volume found by following the partition table (autoSeed true,
// falling back to the volume at base when one opens there). It returns
// the kind label of each volume scanned, in scan order.
func ScanFSVolumes(path string, base int64, autoSeed bool, opts Options, onDetection func(Detection), onProgress func(ProgressInfo), onEntry func(kind string, e FSEntry)) ([]string, error) {
	targets, err := resolveVolumes(path, base, autoSeed)
	if err != nil {
		return nil, err
	}
	var kinds []string
	for _, t := range targets {
		kind, err := scanOneVolume(path, t.base, opts, onDetection, onProgress, onEntry)
		if err != nil {
			return kinds, err
		}
		kinds = append(kinds, kind)
	}
	return kinds, nil
}

// scanOneVolume inventories and scans the single volume at base.
func scanOneVolume(path string, base int64, opts Options, onDetection func(Detection), onProgress func(ProgressInfo), onEntry func(kind string, e FSEntry)) (string, error) {
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
	kinds, free, err := UnallocatedRangesAuto(path, base, false)
	if err != nil {
		return "", nil, err
	}
	return kinds[0], free, nil
}

// UnallocatedRangesAuto returns the merged free-space extents of one
// volume (autoSeed false, at base) or of every NTFS/ext volume found by
// following the partition table (autoSeed true), plus each kind label.
func UnallocatedRangesAuto(path string, base int64, autoSeed bool) ([]string, []FSExtent, error) {
	targets, err := resolveVolumes(path, base, autoSeed)
	if err != nil {
		return nil, nil, err
	}
	var kinds []string
	var all []FSExtent
	for _, t := range targets {
		f, err := os.Open(path)
		if err != nil {
			return kinds, nil, fmt.Errorf("cannot open %s: %w", path, err)
		}
		kind, vol, err := OpenFS(f, t.base)
		if err != nil {
			f.Close()
			return kinds, nil, err
		}
		free, err := vol.Unallocated()
		f.Close()
		if err != nil {
			return kinds, nil, err
		}
		kinds = append(kinds, kind)
		all = append(all, free...)
	}
	return kinds, mergeExtents(all), nil
}
