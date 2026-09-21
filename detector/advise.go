package detector

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
)

// Guided mode (Goal 27): -advise inspects a target and recommends the
// documented-best command with reasons. It never scans content and
// never runs anything: inspection reads at most boot sectors,
// partition tables (Stat, OpenFS probes, ScanPartitions), and the
// first kilobyte for magic sniffing (Goal 43).
//
// Routing table (target shape → command):
//
//	directory            → -walk (sweep every file)
//	volume at offset 0   → -fs (deleted entries with filenames)
//	partitioned disk     → -fs (auto-seed, no -fs-offset needed)
//	EWF v1 container     → raw scan (pass the image; decodes itself)
//	EWF2 container       → no command (libewf conversion pointer)
//	wallet copy (mkey, complete keystore)
//	                     → -hashes (crack-ready export, no scan)
//	key file (xpubs)     → -watch (local address derivation)
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
// It reads at most boot sectors, partition tables, and the first
// kilobyte for magic sniffing: content is never scanned and nothing
// is run.
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
	head := adviseHead(f)
	// Container magic is decisive (8 exact bytes): no filesystem or
	// partition table can start with it, so it routes before the
	// shape probes. EWF2 has no findbtc path — the reasons carry
	// the libewf conversion pointer with no command.
	if len(head) >= len(ewf2Signature) && bytes.Equal(head[:len(ewf2Signature)], ewf2Signature) {
		return adviseEWF2(path)
	}
	// EWF v1 scans as today (detectScanTarget decodes the set);
	// only the reason changes, to name the sniffed magic.
	if len(head) >= len(ewfSignature) && bytes.Equal(head[:len(ewfSignature)], ewfSignature) {
		return adviseRaw(path, fi, "starts with EnCase EWF magic: pass the image file itself — chunks decode and verify automatically (multi-segment sets: pass .E01/.s01)")
	}
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
	return adviseFollowupOrRaw(path, fi, head)
}

// adviseSniffBytes bounds follow-up magic sniffing to the first
// kilobyte: enough for container magic, a wallet record, a keystore,
// or a key line — never a scan, never a run.
const adviseSniffBytes = 1024

// adviseHead reads up to the first adviseSniffBytes of f at offset
// 0. Short files yield a short head; read errors yield what was
// read. Callers treat a head with no match as ambiguous, which
// routes to the raw default.
func adviseHead(f *os.File) []byte {
	buf := make([]byte, adviseSniffBytes)
	n, _ := f.ReadAt(buf, 0)
	return buf[:n]
}

// adviseFollowupOrRaw routes shapeless targets: follow-up inputs
// with decisive first-kilobyte evidence go to their mode (-hashes,
// -watch); everything ambiguous keeps the raw default, since a
// false route strands a scan-worthy target worse than raw does.
// Volumes and partitioned disks never reach here, so the shape
// table is unchanged.
func adviseFollowupOrRaw(path string, fi os.FileInfo, head []byte) (Advice, error) {
	if len(head) > 0 {
		if mkeys := FindMasterKeys(head, 0); len(mkeys) > 0 {
			return adviseHashes(path, fmt.Sprintf("%s: first %d bytes hold a Bitcoin Core mkey record at offset %d (%d iterations, method 0)", path, len(head), mkeys[0].Offset(), mkeys[0].Iterations()))
		}
		if stores := findKeystores(head, 0); len(stores) > 0 {
			return adviseHashes(path, fmt.Sprintf("%s: first %d bytes hold a complete Ethereum keystore object at offset %d (address + crypto envelope)", path, len(head), stores[0].startAbs))
		}
		// Private-only input stays raw: -watch would refuse it,
		// so routing there strands the target.
		if pubs, _ := ExtractXpubs(head); len(pubs) > 0 {
			return adviseWatch(path, len(head), pubs)
		}
	}
	return adviseRaw(path, fi, "no partition table or filesystem found")
}

// adviseHashes routes an encrypted-wallet copy to -hashes.
func adviseHashes(path, evidence string) (Advice, error) {
	return Advice{
		Target:  path,
		Command: fmt.Sprintf("findbtc -hashes %s", shellQuote(path)),
		Reasons: []string{
			evidence,
			"-hashes exports the crack-ready hash without scanning (runbook docs/PASSWORD_RECOVERY.md)",
		},
	}, nil
}

// adviseWatch routes a key file to -watch. Labels name the sniffed
// key versions; the keys themselves stay out of the reasons.
func adviseWatch(path string, headLen int, pubs []string) (Advice, error) {
	var labels []string
	seen := map[string]bool{}
	for _, s := range pubs {
		if x, err := ParseXPub(s); err == nil && !seen[x.Label] {
			seen[x.Label] = true
			labels = append(labels, x.Label)
		}
	}
	keysWord := "extended public keys"
	if len(pubs) == 1 {
		keysWord = "extended public key"
	}
	evidence := fmt.Sprintf("%s: first %d bytes hold %d checksum-valid %s", path, headLen, len(pubs), keysWord)
	if len(labels) > 0 {
		evidence += fmt.Sprintf(" (%s)", strings.Join(labels, "+"))
	}
	return Advice{
		Target:  path,
		Command: fmt.Sprintf("findbtc -watch %s", shellQuote(path)),
		Reasons: []string{
			evidence,
			"-watch derives watch-only addresses locally with no network calls",
		},
	}, nil
}

// adviseEWF2 answers an EWF2 container with the documented
// conversion pointer and no command: there is no findbtc path for
// Ex01/Lx01, so a "Recommended" line would be a lie.
func adviseEWF2(path string) (Advice, error) {
	return Advice{
		Target: path,
		Reasons: []string{
			fmt.Sprintf("%s starts with EWF2 (Ex01/Lx01) magic: only EWF v1 (E01) and SMART (S01) scan directly", path),
			fmt.Sprintf("convert first with libewf (ewfexport -u -t out -f raw %s) and scan the raw output", shellQuote(path)),
		},
	}, nil
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
// shellQuote renders path for paste into the platform's interactive
// shell. Advice is copy/paste output, so the quoting must survive a
// real shell round-trip — never Go syntax (whose doubled
// backslashes no shell unpicks).
func shellQuote(path string) string {
	if runtime.GOOS == "windows" {
		return quotePowerShell(path)
	}
	return quoteUnix(path)
}

// quoteUnix single-quotes paths holding shell-special characters,
// escaping embedded single quotes. Backslashes, dollars, and
// backticks are literal inside single quotes in sh, bash, zsh, and
// fish alike, and so is a newline — which must still trigger
// quoting, since a bare newline is a command separator (a bare CR
// round-trips, but quoting only the true boundary keeps output
// readable).
func quoteUnix(path string) string {
	if !strings.ContainsAny(path, " \t\n\"'\\$`!()[]{}<>|;&*#?~") {
		return path
	}
	return "'" + strings.ReplaceAll(path, "'", `'\''`) + "'"
}

// quotePowerShell renders path for paste into PowerShell (the
// labeled Windows shell; cmd.exe would take the quotes literally).
// Single-quoted strings are fully literal in PowerShell — no $,
// backtick, %, or wildcard expansion — per about_Quoting_Rules, so
// over-quoting is always safe and the trigger set stays broad.
//
// Two repairs from real powershell.exe evidence (Goal 40):
//   - A trailing backslash is stripped (roots like C:\ kept): the
//     separator is insignificant to the target, but PowerShell's
//     native command-line rebuild wraps spaced args in "..." without
//     escaping it, so argv would end in a literal quote. Stripping is
//     version-proof; doubling would differ between 5.1 and 7.3+.
//   - LF/CR (illegal in Win32 names, but quotable input) use the
//     double-quote form with backtick escapes: a literal newline
//     inside single quotes would start a new PowerShell statement —
//     a paste-time command injection — while `"a`nb"` parses to the
//     exact string.
func quotePowerShell(path string) string {
	if path == "" {
		return "''"
	}
	if len(path) > 3 {
		path = strings.TrimRight(path, `\`)
		if path == "" {
			return "''"
		}
	}
	if strings.ContainsAny(path, "\r\n") {
		var b strings.Builder
		b.WriteByte('"')
		for _, r := range path {
			switch r {
			case '`':
				b.WriteString("``")
			case '$':
				b.WriteString("`$")
			case '"':
				b.WriteString("`\"")
			case '\r':
				b.WriteString("`r")
			case '\n':
				b.WriteString("`n")
			default:
				b.WriteRune(r)
			}
		}
		b.WriteByte('"')
		return b.String()
	}
	if !strings.ContainsAny(path, " \t'\"$`&|<>(){}[];,@#%*?!^=+") {
		return path
	}
	return "'" + strings.ReplaceAll(path, "'", "''") + "'"
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
