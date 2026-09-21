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

// OpenFS detects the filesystem at base (NTFS, ext, FAT12/16/32, exFAT)
// and returns its kind label plus the volume.
func OpenFS(r io.ReaderAt, base int64) (string, FSVol, error) {
	if vol, err := OpenNTFS(r, base); err == nil {
		return "ntfs", vol, nil
	}
	if vol, err := OpenExt(r, base); err == nil {
		return "ext", vol, nil
	}
	if vol, err := OpenFAT(r, base); err == nil {
		return "fat", vol, nil
	}
	if vol, err := OpenExFAT(r, base); err == nil {
		return "exfat", vol, nil
	}
	return "", nil, fmt.Errorf("no NTFS, ext, FAT, or exFAT filesystem at offset %d (for a full-disk image, omit -fs-offset to follow its partition table)", base)
}

// volumeTarget is one filesystem to scan: its base offset and kind.
type volumeTarget struct {
	base int64
	kind string
}

// resolveVolumes returns the scan targets for path. With autoSeed and no
// volume at base, the partition table is followed and every partition
// that opens as a supported filesystem (NTFS/ext/FAT/exFAT) becomes a
// target. Every failure names the path,
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
			return nil, fmt.Errorf("%s: no NTFS, ext, FAT, or exFAT filesystem at offset %d, and no usable partition table (%v); point -fs-offset at a volume boot sector", path, base, perr)
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
			return nil, fmt.Errorf("%s: partition table holds %d entries (%s) but none opens as NTFS/ext/FAT/exFAT (first: %v); point -fs-offset at a volume boot sector", path, len(parts), strings.Join(descs, "; "), firstProbeErr)
		}
		return targets, nil
	}
}

// ScanFS enumerates the filesystem at base and scans every deleted entry's
// content ranges, stamping each detection with its filename (or metadata
// note when the name is lost). Live entries are inventoried but not
// scanned: raw scanning already covers live content. onEntry observes
// every entry for the inventory; onDetection observes content hits. Any
// callback may be nil.
func ScanFS(path string, base int64, opts Options, onDetection func(Detection), onProgress func(ProgressInfo), onEntry func(kind string, e FSEntry)) (string, error) {
	kinds, err := ScanFSVolumes(path, base, false, opts, onDetection, onProgress, onEntry)
	if err != nil {
		return "", err
	}
	return kinds[0], nil
}

// ScanFSVolumes scans one volume (autoSeed false, at base) or every
// supported volume (NTFS/ext/FAT/exFAT) found by following the
// partition table (autoSeed true,
// falling back to the volume at base when one opens there). It returns
// the kind label of each volume scanned, in scan order. Any callback may
// be nil.
func ScanFSVolumes(path string, base int64, autoSeed bool, opts Options, onDetection func(Detection), onProgress func(ProgressInfo), onEntry func(kind string, e FSEntry)) ([]string, error) {
	onDetection, onProgress = withDefaultCallbacks(onDetection, onProgress)
	targets, err := resolveVolumes(path, base, autoSeed)
	if err != nil {
		return nil, recordAttempt(opts, path, err)
	}
	// One flattened deleted-entry range list spans every volume (the
	// unallocated precedent): a single (range_index, offset) journal
	// covers the whole run and resume validates the full list, so a
	// range list changed in ANY volume refuses loudly.
	kinds, ranges, owners, err := flattenDeletedRanges(path, targets, onEntry)
	if err != nil {
		return kinds, recordAttempt(opts, path, err)
	}
	// A fresh empty run needs no pipeline; a resume must still validate its
	// existing journal against the current list, including an empty list.
	if len(ranges) == 0 && !opts.Resume {
		return kinds, nil
	}
	// Stamping follows the range index, not an offset search: the
	// driver reports each range as its pipeline starts, so a hit is
	// owned by the range being scanned however the list overlaps.
	ro := &rangeOwner{ranges: ranges, owners: owners, cur: -1}
	opts.onRange = ro.onRange

	err = ScanRangesWithOptions(path, ranges, opts, func(d Detection) {
		d.FileName = ro.ownerOf(d.Offset)
		onDetection(d)
	}, onProgress)
	if err != nil {
		return kinds, err
	}
	return kinds, nil
}

// rangeOwner stamps detections with the filename owning the range
// being scanned. The index (reported by the range driver as each
// pipeline starts) wins over offset containment, so overlapping
// ranges attribute exactly; the offset search survives only as a
// fallback for detections that arrive with no range started.
type rangeOwner struct {
	ranges []FSExtent
	owners []string
	cur    int
}

func (o *rangeOwner) onRange(index int) {
	o.cur = index
}

func (o *rangeOwner) ownerOf(offset int64) string {
	if o.cur >= 0 && o.cur < len(o.owners) {
		return o.owners[o.cur]
	}
	for i, r := range o.ranges {
		if offset >= r.Start && offset < r.Start+r.Len {
			return o.owners[i]
		}
	}
	return ""
}

// flattenDeletedRanges inventories every target in scan order (firing
// onEntry per volume as it goes) and flattens the volumes'
// deleted-entry content extents into one range list with per-range
// filename owners. kinds[i] is the filesystem label of targets[i].
// A single volume flattens to exactly the list it always journaled,
// so single-volume runs are byte-identical to before.
func flattenDeletedRanges(path string, targets []volumeTarget, onEntry func(kind string, e FSEntry)) ([]string, []FSExtent, []string, error) {
	var kinds []string
	var ranges []FSExtent
	var owners []string
	for _, t := range targets {
		f, err := os.Open(path)
		if err != nil {
			return kinds, nil, nil, fmt.Errorf("cannot open %s: %w", path, err)
		}
		kind, vol, err := OpenFS(f, t.base)
		if err != nil {
			f.Close()
			return kinds, nil, nil, err
		}
		entries, err := vol.Entries()
		f.Close()
		if err != nil {
			return kinds, nil, nil, err
		}
		for _, e := range entries {
			if onEntry != nil {
				onEntry(kind, e)
			}
		}
		kinds = append(kinds, kind)
		for _, e := range entries {
			if !e.Deleted || len(e.Extents) == 0 {
				continue
			}
			label := e.Name
			if label == "" {
				label = e.Note
			}
			ranges = append(ranges, e.Extents...)
			for range e.Extents {
				owners = append(owners, label)
			}
		}
	}
	return kinds, ranges, owners, nil
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
// volume (autoSeed false, at base) or of every supported volume found
// by following the partition table (autoSeed true), plus each kind
// label.
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
