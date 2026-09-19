package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/pauljones0/findbtc/detector"
)

// version is stamped by GoReleaser; dev builds report "dev".
var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "Print version and exit")
	startOffset := flag.Int64("s", 0, "Start at byte offset")
	jsonOut := flag.Bool("json", false, "Print detections as JSON lines instead of human text")
	extractDir := flag.String("extract-dir", "", "Carve bytes around each hit into DIR/hit-NNNNNN.bin plus a .json sidecar (never on the scanned device itself)")
	contextBytes := flag.Int64("context", 1<<20, "Bytes carved before and after each hit (only with -extract-dir)")
	checkpointPath := flag.String("checkpoint", "", "Journal scan progress to FILE every 1MB for crash recovery")
	resume := flag.Bool("resume", false, "Resume from -checkpoint instead of scanning from the start")
	reportPath := flag.String("report", "", "Summarize a -json hits file (or - for stdin) instead of scanning")
	dfxmlPath := flag.String("dfxml", "", "Convert a -json hits file (or - for stdin) to DFXML on stdout instead of scanning")
	verifyLogPath := flag.String("verify-case-log", "", "Re-hash the sources behind each record in case-log FILE and report match/mismatch instead of scanning")
	hashesPath := flag.String("hashes", "", "Extract crack-ready password hashes from FILE (or - for stdin) instead of scanning")
	salvagePath := flag.String("salvage", "", "Analyze FILE for salvageable database pages instead of scanning")
	salvageOut := flag.String("salvage-out", "", "Write the salvaged database image to PATH (only with -salvage)")
	watchPath := flag.String("watch", "", "Derive watch-only addresses from extended public keys in FILE (a carve, a key file, or hits.jsonl with carves) instead of scanning")
	watchOut := flag.String("watch-out", "", "Write the address list to PATH instead of stdout (only with -watch)")
	watchFormat := flag.String("watch-format", "csv", "Address-list format: csv or json (only with -watch)")
	watchCount := flag.Int("watch-count", detector.WatchDefaultCount, "Addresses to derive per chain, external and change (only with -watch)")
	balanceEndpoint := flag.String("balance-endpoint", "", "Opt-in: query ADDRESS balances from this Esplora-compatible base URL (only with -watch; leaks addresses to that server)")
	fsPath := flag.String("fs", "", "Filesystem-aware mode: recover deleted entries with names from the NTFS/ext volume in FILE and scan their content")
	fsOffset := flag.Int64("fs-offset", 0, "Byte offset of the volume boot sector inside FILE (only with -fs and -unallocated-only)")
	unallocatedOnly := flag.Bool("unallocated-only", false, "Scan only unallocated filesystem space (NTFS/ext at -fs-offset); skips live data")
	reveal := flag.Bool("reveal", false, "Print seed words for BIP39 hits (owner recovery only; NEVER share this output)")
	caseLog := flag.String("case-log", "", "Append a JSON case-log record per scan to FILE (source identity, streaming hashes, skipped ranges, counts)")
	flag.Parse()
	if *showVersion {
		fmt.Printf("findbtc %s\n", version)
		return
	}
	if *reveal {
		fmt.Fprintln(os.Stderr, "WARNING: --reveal prints seed words to stdout. Owner recovery only: keep this output secret, never share or paste it anywhere.")
	}
	if *reportPath != "" {
		runReport(*reportPath, *jsonOut)
		return
	}
	if *dfxmlPath != "" {
		runDFXML(*dfxmlPath)
		return
	}
	if *verifyLogPath != "" {
		if err := detector.VerifyCaseLog(*verifyLogPath, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "[verify] Exiting due to error: %s\n", err.Error())
			os.Exit(1)
		}
		return
	}
	if *hashesPath != "" {
		runHashes(*hashesPath, *jsonOut)
		return
	}
	if *salvagePath != "" {
		runSalvage(*salvagePath, *salvageOut, *jsonOut)
		return
	}
	if *watchPath != "" {
		runWatch(*watchPath, *watchOut, *watchFormat, *watchCount, *balanceEndpoint)
		return
	}
	if *balanceEndpoint != "" {
		fmt.Fprintln(os.Stderr, "[watch] Exiting due to error: -balance-endpoint needs -watch")
		os.Exit(1)
	}
	if *fsPath != "" {
		if *resume || *checkpointPath != "" {
			fmt.Fprintln(os.Stderr, "[fs] Exiting due to error: -checkpoint and -resume are not supported with -fs")
			os.Exit(1)
		}
		runFS(*fsPath, *fsOffset, *jsonOut, *extractDir, *contextBytes, *reveal, *caseLog)
		return
	}
	path := flag.Arg(0)

	if path == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s [-s OFFSET] [-json] [-extract-dir DIR [-context BYTES]] [-checkpoint FILE [-resume]] [-unallocated-only [-fs-offset OFF]] [-case-log FILE] DEVICE\n   or: %s -report hits.jsonl [-json]\n   or: %s -hashes FILE [-json]\n   or: %s -salvage FILE [-salvage-out PATH] [-json]\n   or: %s -watch FILE [-watch-out PATH] [-watch-format csv|json] [-watch-count N] [-balance-endpoint URL]\n   or: %s -fs FILE [-fs-offset OFF] [-json] [-extract-dir DIR [-context BYTES]]\n   or: %s -dfxml hits.jsonl\n   or: %s -verify-case-log case.jsonl\n\n", os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
		flag.PrintDefaults()
		os.Exit(2)
	}

	start := *startOffset
	if *resume {
		if *checkpointPath == "" {
			fmt.Fprintln(os.Stderr, "[main] Exiting due to error: -resume requires -checkpoint")
			os.Exit(1)
		}
		cp, err := detector.ReadCheckpoint(*checkpointPath)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "[main] No checkpoint at %s, starting from the beginning\n", *checkpointPath)
			} else {
				fmt.Fprintf(os.Stderr, "[main] Exiting due to error: %s\n", err.Error())
				os.Exit(1)
			}
		} else {
			if cp.Path != path {
				fmt.Fprintf(os.Stderr, "[main] Exiting due to error: checkpoint is for %s, not %s\n", cp.Path, path)
				os.Exit(1)
			}
			start = cp.Offset
			fmt.Fprintf(os.Stderr, "[main] Resuming %s at byte offset %d\n", path, start)
		}
	}

	opts := detector.Options{CarveDir: *extractDir, CarveContextBytes: *contextBytes, CheckpointPath: *checkpointPath, Reveal: *reveal, CaseLogPath: *caseLog, ToolVersion: version, Flags: os.Args[1:]}
	printDetection := func(detection detector.Detection) {
		if *jsonOut {
			line, err := json.Marshal(detection)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[main] cannot encode detection: %s\n", err.Error())
				return
			}
			fmt.Println(string(line))
		} else {
			fmt.Printf(
				"[main] Found possible wallet trace:\n"+
					"  %s\n", detection.Description)
			if detection.FileName != "" {
				fmt.Printf("  file: %s\n", detection.FileName)
			}
			if len(detection.Words) > 0 {
				fmt.Printf("  words: %s\n", strings.Join(detection.Words, " "))
			}
			if detection.CarvePath != "" {
				class := ""
				if detection.Carve != nil {
					class = fmt.Sprintf(" [%s]", detection.Carve.Class)
				}
				fmt.Printf("  carved to: %s%s\n", detection.CarvePath, class)
			}
		}
	}
	var err error
	if *unallocatedOnly {
		err = runUnallocated(path, *fsOffset, start, opts, printDetection)
	} else {
		err = detector.ScanWithOptions(start, path, opts, printDetection, newProgressReporter().onProgress)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "[main] Exiting due to error: %s\n", err.Error())
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "[COMPLETE]")
}

// runUnallocated implements --unallocated-only: scan just the free space
// of the NTFS/ext volume at fsOffset. Checkpointing is refused: a single
// offset cannot resume a range list.
func runUnallocated(path string, fsOffset, start int64, opts detector.Options, onDetection func(detector.Detection)) error {
	if opts.CheckpointPath != "" {
		return fmt.Errorf("-checkpoint and -resume are not supported with -unallocated-only")
	}
	kind, free, err := detector.UnallocatedRanges(path, fsOffset)
	if err != nil {
		return err
	}
	var ranges []detector.FSExtent
	var total int64
	for _, r := range free {
		if r.Start+r.Len <= start {
			continue
		}
		if r.Start < start {
			r.Len -= start - r.Start
			r.Start = start
		}
		ranges = append(ranges, r)
		total += r.Len
	}
	if len(ranges) == 0 {
		fmt.Fprintln(os.Stderr, "[main] No unallocated space to scan.")
		return nil
	}
	fmt.Fprintf(os.Stderr, "[main] Scanning %d unallocated ranges (%d bytes) of %s volume %s.\n",
		len(ranges), total, kind, path)
	return detector.ScanRangesWithOptions(path, ranges, opts, onDetection, newProgressReporter().onProgress)
}

// runFS implements filesystem-aware mode: inventory live and deleted
// entries with names, then scan deleted entries' content with filenames
// stamped on every hit.
func runFS(path string, fsOffset int64, jsonOut bool, carveDir string, contextBytes int64, reveal bool, caseLog string) {
	opts := detector.Options{CarveDir: carveDir, CarveContextBytes: contextBytes, Reveal: reveal, CaseLogPath: caseLog, ToolVersion: version, Flags: os.Args[1:]}
	_, err := detector.ScanFS(path, fsOffset, opts, func(detection detector.Detection) {
		if jsonOut {
			line, err := json.Marshal(detection)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[fs] cannot encode detection: %s\n", err.Error())
				return
			}
			fmt.Println(string(line))
			return
		}
		fmt.Printf("[fs] Found possible wallet trace:\n  %s\n", detection.Description)
		if detection.FileName != "" {
			fmt.Printf("  file: %s\n", detection.FileName)
		}
		if len(detection.Words) > 0 {
			fmt.Printf("  words: %s\n", strings.Join(detection.Words, " "))
		}
		if detection.CarvePath != "" {
			fmt.Printf("  carved to: %s\n", detection.CarvePath)
		}
	}, newProgressReporter().onProgress, func(kind string, e detector.FSEntry) {
		state := "live"
		if e.Deleted {
			state = "deleted"
		}
		name := e.Name
		if name == "" {
			name = e.Note
		}
		fmt.Fprintf(os.Stderr, "[fs] %s %s %s (%d bytes, %d extents)\n",
			kind, state, name, e.Size, len(e.Extents))
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[fs] Exiting due to error: %s\n", err.Error())
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "[COMPLETE]")
}

// runReport implements triage mode: summarize saved -json hits offline.
func runReport(path string, jsonOut bool) {
	f := os.Stdin
	if path != "-" {
		var err error
		f, err = os.Open(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[report] Exiting due to error: %s\n", err.Error())
			os.Exit(1)
		}
		defer f.Close()
	}
	dets, err := detector.ReadDetections(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[report] Exiting due to error: %s\n", err.Error())
		os.Exit(1)
	}
	rep := detector.Summarize(dets)
	if jsonOut {
		raw, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "[report] Exiting due to error: %s\n", err.Error())
			os.Exit(1)
		}
		fmt.Println(string(raw))
		return
	}
	fmt.Print(rep.Text())
}

// runDFXML implements DFXML-export mode: convert saved -json hits to a
// DFXML 1.1.1 document on stdout for case-tool ingest.
func runDFXML(path string) {
	f := os.Stdin
	if path != "-" {
		var err error
		f, err = os.Open(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[dfxml] Exiting due to error: %s\n", err.Error())
			os.Exit(1)
		}
		defer f.Close()
	}
	dets, err := detector.ReadDetections(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[dfxml] Exiting due to error: %s\n", err.Error())
		os.Exit(1)
	}
	if err := detector.WriteDFXML(os.Stdout, version, dets); err != nil {
		fmt.Fprintf(os.Stderr, "[dfxml] Exiting due to error: %s\n", err.Error())
		os.Exit(1)
	}
}

// runHashes implements hash-export mode: pull crack-ready password material
// out of a file (a carve, a wallet copy — never the scanned device itself).
func runHashes(path string, jsonOut bool) {
	f := os.Stdin
	if path != "-" {
		var err error
		f, err = os.Open(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[hashes] Exiting due to error: %s\n", err.Error())
			os.Exit(1)
		}
		defer f.Close()
	}
	buf, err := io.ReadAll(io.LimitReader(f, detector.HashScanMaxBytes+1))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[hashes] Exiting due to error: %s\n", err.Error())
		os.Exit(1)
	}
	if len(buf) > detector.HashScanMaxBytes {
		fmt.Fprintf(os.Stderr, "[hashes] Exiting due to error: input exceeds %d bytes; carve the hit region first\n", detector.HashScanMaxBytes)
		os.Exit(1)
	}
	hashes := detector.ExtractHashes(buf, 0)
	if hashes == nil {
		hashes = []detector.CrackHash{}
	}
	if jsonOut {
		raw, err := json.MarshalIndent(hashes, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "[hashes] Exiting due to error: %s\n", err.Error())
			os.Exit(1)
		}
		fmt.Println(string(raw))
		return
	}
	if len(hashes) == 0 {
		fmt.Printf("No crack material found in %s (need an mkey record or a complete keystore object).\n", path)
		return
	}
	hashWord := "hashes"
	if len(hashes) == 1 {
		hashWord = "hash"
	}
	fmt.Printf("%d crack-ready %s in %s\n", len(hashes), hashWord, path)
	for _, h := range hashes {
		fmt.Printf("[%s @%d] kdf=%s iters=%d\n%s\n", h.Format, h.Offset, h.KDF, h.Iterations, h.Hash)
	}
	fmt.Println("Next: save the $...$ lines above to hashes.txt, then:")
	for _, cmd := range hashCommands(hashes) {
		fmt.Printf("  %s\n", cmd)
	}
	fmt.Println("Full runbook (hashcat, John, BTCRecover): docs/PASSWORD_RECOVERY.md")
}

// hashCommands returns one follow-up command per hash kind present.
func hashCommands(hashes []detector.CrackHash) []string {
	var cmds []string
	seen := map[string]bool{}
	add := func(key, cmd string) {
		if !seen[key] {
			seen[key] = true
			cmds = append(cmds, cmd)
		}
	}
	for _, h := range hashes {
		switch h.Format {
		case "bitcoin-core-mkey":
			add("core", "hashcat -m 11300 hashes.txt passwords.txt")
		case "ethereum-keystore":
			if h.KDF == "scrypt" {
				add("eth-s", "hashcat -m 15700 hashes.txt passwords.txt")
			} else {
				add("eth-p", "hashcat -m 15600 hashes.txt passwords.txt")
			}
		}
	}
	return cmds
}

// runSalvage implements salvage mode: analyze a file for database pages and
// optionally write the reassembled image.
func runSalvage(path, outPath string, jsonOut bool) {
	f := os.Stdin
	if path != "-" {
		var err error
		f, err = os.Open(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[salvage] Exiting due to error: %s\n", err.Error())
			os.Exit(1)
		}
		defer f.Close()
	}
	buf, err := io.ReadAll(io.LimitReader(f, detector.SalvageMaxBytes+1))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[salvage] Exiting due to error: %s\n", err.Error())
		os.Exit(1)
	}
	if len(buf) > detector.SalvageMaxBytes {
		fmt.Fprintf(os.Stderr, "[salvage] Exiting due to error: input exceeds %d bytes\n", detector.SalvageMaxBytes)
		os.Exit(1)
	}
	r := detector.Salvage(buf, 0)
	if r == nil {
		fmt.Printf("No salvageable database pages in %s (need 2+ pages of one database).\n", path)
		return
	}
	if outPath != "" {
		if err := os.WriteFile(outPath, r.Image, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "[salvage] Exiting due to error: %s\n", err.Error())
			os.Exit(1)
		}
		r.Info.Path = outPath
	}
	if jsonOut {
		raw, err := json.MarshalIndent(r.Info, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "[salvage] Exiting due to error: %s\n", err.Error())
			os.Exit(1)
		}
		fmt.Println(string(raw))
		return
	}
	info := r.Info
	fmt.Printf("Salvage: %s, %d pages (%dB each)", info.Kind, len(info.Pages), info.PageSize)
	if info.Complete {
		fmt.Printf(", complete")
	} else {
		fmt.Printf(", partial")
	}
	if info.Ordered {
		fmt.Printf(", ordered\n")
	} else {
		fmt.Printf(", unordered (page map only)\n")
	}
	for _, p := range info.Pages {
		if info.Kind == "bdb" {
			fmt.Printf("  pgno %d @%d %s\n", p.PgNo, p.Offset, p.Kind)
		} else {
			fmt.Printf("  @%d %s\n", p.Offset, p.Kind)
		}
	}
	if outPath != "" {
		fmt.Printf("Wrote %s (%d bytes)\n", outPath, len(r.Image))
		if info.Kind == "sqlite" {
			fmt.Println("Next: sqlite3", outPath, "'PRAGMA quick_check'")
		} else {
			fmt.Println("Next: inspect with db_dump (Berkeley DB utilities) or strings")
		}
	} else {
		fmt.Println("No output written (use -salvage-out PATH to save the image).")
	}
}

// runWatch implements watch-only mode: derive addresses locally from extended
// public keys found in a file (a carve, a pasted key, or hits.jsonl whose
// carves are then searched), and optionally look up balances at an explicit
// endpoint. The default path performs zero network I/O.
func runWatch(path, outPath, format string, count int, endpoint string) {
	if format != "csv" && format != "json" {
		fmt.Fprintf(os.Stderr, "[watch] Exiting due to error: -watch-format must be csv or json\n")
		os.Exit(1)
	}
	if count < 1 || count > detector.WatchMaxCount {
		fmt.Fprintf(os.Stderr, "[watch] Exiting due to error: -watch-count must be 1-%d\n", detector.WatchMaxCount)
		os.Exit(1)
	}
	f := os.Stdin
	if path != "-" {
		var err error
		f, err = os.Open(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[watch] Exiting due to error: %s\n", err.Error())
			os.Exit(1)
		}
		defer f.Close()
	}
	buf, err := io.ReadAll(io.LimitReader(f, detector.WatchScanMaxBytes+1))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[watch] Exiting due to error: %s\n", err.Error())
		os.Exit(1)
	}
	if len(buf) > detector.WatchScanMaxBytes {
		fmt.Fprintf(os.Stderr, "[watch] Exiting due to error: input exceeds %d bytes\n", detector.WatchScanMaxBytes)
		os.Exit(1)
	}
	pubs, privFound := watchInputKeys(buf, path)
	if len(pubs) == 0 {
		if privFound {
			fmt.Fprintf(os.Stderr, "[watch] Exiting due to error: found only private extended keys — findbtc never derives from private material (move the key to an offline machine and sweep to a fresh wallet)\n")
		} else {
			fmt.Fprintf(os.Stderr, "[watch] Exiting due to error: no extended public keys in %s\n", path)
		}
		os.Exit(1)
	}
	entries, err := detector.CollectWatchAddrs(pubs, count)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[watch] Exiting due to error: %s\n", err.Error())
		os.Exit(1)
	}
	if endpoint != "" {
		fmt.Fprintf(os.Stderr, "WARNING: -balance-endpoint sends %d derived addresses to %s. Anyone running that server learns exactly which wallet you are watching. Prefer your own node (see docs/WATCH_ONLY.md).\n", len(entries), endpoint)
		addrs := make([]string, len(entries))
		for i, e := range entries {
			addrs[i] = e.Address
		}
		client := &http.Client{Timeout: 30 * time.Second}
		balances, err := detector.LookupBalances(client, endpoint, addrs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[watch] warning: %s\n", err.Error())
		}
		for i := range entries {
			if b, ok := balances[entries[i].Address]; ok {
				b := b
				entries[i].BalanceSats = &b
			}
		}
	}
	out := os.Stdout
	if outPath != "" {
		var err error
		out, err = os.Create(outPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[watch] Exiting due to error: %s\n", err.Error())
			os.Exit(1)
		}
		defer out.Close()
	}
	if format == "json" {
		err = detector.WriteWatchJSON(out, entries)
	} else {
		err = detector.WriteWatchCSV(out, entries)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[watch] Exiting due to error: %s\n", err.Error())
		os.Exit(1)
	}
	fps := map[string]bool{}
	for _, s := range pubs {
		if x, err := detector.ParseXPub(s); err == nil {
			fps[x.Fingerprint()] = true
		}
	}
	var fpList []string
	for fp := range fps {
		fpList = append(fpList, fp)
	}
	sort.Strings(fpList)
	netNote := ""
	if endpoint != "" {
		netNote = " except balance lookups"
	}
	fmt.Fprintf(os.Stderr, "[watch] Derived %d addresses from %d keys (fingerprints: %s); no network calls were made%s.\n",
		len(entries), len(pubs), strings.Join(fpList, ", "), netNote)
}

// watchInputKeys extracts extended public keys from -watch input: if the
// input parses as hits.jsonl, each hit's carve file is searched; otherwise
// the input bytes are searched directly.
func watchInputKeys(buf []byte, path string) ([]string, bool) {
	if dets, err := detector.ReadDetections(bytes.NewReader(buf)); err == nil && len(dets) > 0 {
		var pubs []string
		seen := map[string]bool{}
		privFound := false
		carves := 0
		for _, d := range dets {
			if d.CarvePath == "" {
				continue
			}
			carves++
			carve, err := os.ReadFile(d.CarvePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[watch] warning: cannot read carve %s: %s\n", d.CarvePath, err.Error())
				continue
			}
			found, priv := detector.ExtractXpubs(carve)
			privFound = privFound || priv
			for _, s := range found {
				if !seen[s] {
					seen[s] = true
					pubs = append(pubs, s)
				}
			}
		}
		if carves == 0 {
			fmt.Fprintf(os.Stderr, "[watch] Exiting due to error: %s has hits but no carve paths — rescan with -extract-dir, or run -watch on a file holding the key\n", path)
			os.Exit(1)
		}
		return pubs, privFound
	}
	return detector.ExtractXpubs(buf)
}

const PROGRESS_REPORT_INTERVAL = 10

type progressReporter struct {
	lastReport int64
	interval   int64
	started    bool
	startTime  time.Time
	startBytes int64
}

func newProgressReporter() *progressReporter {
	return &progressReporter{interval: PROGRESS_REPORT_INTERVAL}
}

func (p *progressReporter) onProgress(pg detector.ProgressInfo) {
	now := time.Now()
	if !p.started {
		p.started = true
		p.startTime = now
		p.startBytes = pg.ScannedBytes
	}
	if now.Unix()-p.interval > p.lastReport {
		p.lastReport = now.Unix()
		additionalTargets := ""
		if pg.UnscannedTargets > 0 {
			additionalTargets = fmt.Sprintf(" (%d additional targets)", pg.UnscannedTargets)
		}

		rate := ""
		eta := ""
		if elapsed := now.Sub(p.startTime).Seconds(); elapsed > 0 {
			mbps := float64(pg.ScannedBytes-p.startBytes) / elapsed / (1024 * 1024)
			rate = fmt.Sprintf(" %.1fMB/s", mbps)
			if pg.TotalBytes > 0 && mbps > 0 {
				remaining := float64(pg.TotalBytes-pg.ScannedBytes) / (mbps * 1024 * 1024)
				eta = fmt.Sprintf(" ETA %s", formatETA(time.Duration(remaining)*time.Second))
			}
		}

		if pg.TotalBytes <= 0 {
			fmt.Fprintf(os.Stderr, "[%dmb/??mb%s]%s\n", pg.ScannedBytes/(1024*1024), rate, additionalTargets)
		} else {
			fmt.Fprintf(os.Stderr, "[%.2f%%%s%s]%s\n", (float64(pg.ScannedBytes)/float64(pg.TotalBytes))*100, rate, eta, additionalTargets)
		}
	}
}

func formatETA(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	h, m, s := int(d.Hours()), int(d.Minutes())%60, int(d.Seconds())%60
	if h > 0 {
		return fmt.Sprintf("%dh%dm", h, m)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
