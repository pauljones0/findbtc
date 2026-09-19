package detector

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Guided mode (Goal 27): -advise inspects a target and recommends the
// documented-best command with reasons. It never scans content and
// never runs anything: inspection reads at most boot sectors and
// partition tables (Stat, OpenFS probes, ScanPartitions).
//
// Routing table (target shape → command):
//
//	directory            → -walk (sweep every file)
//	volume at offset 0   → -fs (deleted entries with filenames)
//	partitioned disk     → -fs (auto-seed, no -fs-offset needed)
//	anything else        → raw scan (every byte, no filenames)
//	empty / unreadable   → no command, reasons say why
//
// Filesystem targets also get an -unallocated-only follow-up; large
// raw targets get a -checkpoint follow-up. Follow-ups print under
// "Also consider" and never auto-run.

// Advice is a routing recommendation for one target.
type Advice struct {
	Target   string   // path as given
	Command  string   // recommended command line ("" when nothing to run)
	Reasons  []string // why this command (or why none)
	Also     []string // follow-up commands worth knowing
	scheme   string   // partition scheme for tests ("mbr"/"gpt"/"")
	partKind []string // probed volume kinds for tests
}

// Advise inspects path and recommends the documented-best command.
// It reads at most boot sectors and partition tables: content is
// never scanned and nothing is run.
func Advise(path string) (Advice, error) {
	ad := Advice{Target: path}
	fi, err := os.Stat(path)
	if err != nil {
		return ad, fmt.Errorf("cannot advise on %s: %w", path, err)
	}
	if fi.IsDir() {
		return adviseDir(path)
	}
	f, err := os.Open(path)
	if err != nil {
		return ad, fmt.Errorf("cannot advise on %s: %w", path, err)
	}
	defer f.Close()
	if kind, _, err := OpenFS(f, 0); err == nil {
		ad.Command = fmt.Sprintf("findbtc -fs %s", shellQuote(path))
		ad.Reasons = []string{
			fmt.Sprintf("%s opens as %s at offset 0", path, kind),
			"deleted entries recover with filenames; live content scans raw anyway",
		}
		ad.Also = []string{
			fmt.Sprintf("findbtc -unallocated-only %s  (free space only, no filenames)", shellQuote(path)),
		}
		return ad, nil
	}
	if parts, perr := ScanPartitions(f); perr == nil && len(parts) > 0 {
		ad.scheme = parts[0].Scheme
		var kinds []string
		for _, p := range parts {
			if kind, _, err := OpenFS(f, p.Start); err == nil {
				kinds = append(kinds, kind)
			}
		}
		if len(kinds) > 0 {
			ad.partKind = kinds
			ad.Command = fmt.Sprintf("findbtc -fs %s", shellQuote(path))
			ad.Reasons = []string{
				fmt.Sprintf("%s table with %d partitions (%s)", strings.ToUpper(ad.scheme), len(parts), strings.Join(kinds, "+")),
				"auto-seed scans every supported volume; no -fs-offset needed",
			}
			ad.Also = []string{
				fmt.Sprintf("findbtc -unallocated-only %s  (free space only, no filenames)", shellQuote(path)),
			}
			return ad, nil
		}
		var descs []string
		for _, p := range parts {
			descs = append(descs, p.String())
		}
		sort.Strings(descs)
		return adviseRaw(path, fi, fmt.Sprintf("partition table holds %d entries (%s) but none opens as a supported filesystem", len(parts), strings.Join(descs, "; ")))
	}
	return adviseRaw(path, fi, "no partition table or filesystem found")
}

// adviseDir routes directories to -walk.
func adviseDir(path string) (Advice, error) {
	ad := Advice{Target: path}
	d, err := os.Open(path)
	if err != nil {
		return ad, fmt.Errorf("cannot advise on %s: %w", path, err)
	}
	defer d.Close()
	names, err := d.Readdirnames(1)
	if err != nil || len(names) == 0 {
		ad.Reasons = []string{fmt.Sprintf("%s is an empty directory: nothing to scan", path)}
		return ad, nil
	}
	ad.Command = fmt.Sprintf("findbtc -walk %s", shellQuote(path))
	ad.Reasons = []string{
		fmt.Sprintf("%s is a directory", path),
		"sweeps every regular file with the standard detectors (symlinks not followed unless -walk-follow-symlinks)",
	}
	return ad, nil
}

// adviseRaw routes files and devices without usable filesystem
// structure to a raw scan.
func adviseRaw(path string, fi os.FileInfo, why string) (Advice, error) {
	ad := Advice{Target: path}
	size := fi.Size()
	if size == 0 && fi.Mode().IsRegular() {
		ad.Reasons = []string{fmt.Sprintf("%s is empty (0 bytes): nothing to scan", path)}
		return ad, nil
	}
	sizeNote := ""
	if size > 0 {
		sizeNote = fmt.Sprintf(" (%s)", humanBytes(size))
	} else if sz, err := FileSize(path); err == nil && sz > 0 {
		sizeNote = fmt.Sprintf(" (%s)", humanBytes(sz))
		size = sz
	}
	ad.Command = fmt.Sprintf("findbtc %s", shellQuote(path))
	ad.Reasons = []string{
		fmt.Sprintf("%s%s: %s", path, sizeNote, why),
		"raw scan covers every byte; hits lack filenames",
	}
	if size >= 1<<30 {
		ad.Also = []string{
			fmt.Sprintf("findbtc -checkpoint resume.journal %s  (interruptible: resume with -resume)", shellQuote(path)),
		}
	}
	return ad, nil
}

// shellQuote quotes path only when it needs it.
func shellQuote(path string) string {
	if !strings.ContainsAny(path, " \t\"'\\$`!()[]{}<>|;&*#?~") {
		return path
	}
	return strconv.Quote(path)
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for n/div >= unit && exp < 3 {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}
