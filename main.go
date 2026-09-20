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

// Exit codes are a consumer contract (see README): 0 the run
// completed and covered its target (hits or not), 1 runtime error
// or zero coverage, 2 bad flags/usage, and exitHitsFound only with
// -fail-on-hit when anything matched.
const exitHitsFound = 3

// gateOnHits trips the CI gate: with failOnHit set and n > 0 it says
// so on stderr and exits exitHitsFound. Otherwise it returns quietly.
func gateOnHits(tag string, n int, failOnHit bool) {
	if !failOnHit || n <= 0 {
		return
	}
	hitWord := "detections"
	if n == 1 {
		hitWord = "detection"
	}
	fmt.Fprintf(os.Stderr, "[%s] %d %s found (-fail-on-hit): exiting %d\n", tag, n, hitWord, exitHitsFound)
	os.Exit(exitHitsFound)
}

func main() {
	showVersion := flag.Bool("version", false, "Print version and exit")
	startOffset := flag.Int64("s", 0, "Start at byte offset")
	jsonOut := flag.Bool("json", false, "Print detections as JSON lines instead of human text")
	extractDir := flag.String("extract-dir", "", "Carve bytes around each hit into DIR/hit-NNNNNN.bin plus a .json sidecar (never on the scanned device itself)")
	contextBytes := flag.Int64("context", 1<<20, "Bytes carved before and after each hit (only with -extract-dir)")
	checkpointPath := flag.String("checkpoint", "", "Journal scan progress to FILE every 1MB for crash recovery")
	resume := flag.Bool("resume", false, "Resume from -checkpoint instead of scanning from the start")
	reportPath := flag.String("report", "", "Summarize a -json hits file (or - for stdin) instead of scanning")
	complete := flag.Bool("complete", false, "With -report: enumerate checksum-valid completions for partial-seed (near-miss) hits (needs --reveal; local terminal only)")
	completeOut := flag.String("complete-out", "", "With -report -complete: write candidate account keys (watch-only) to PATH for -watch (only with -complete)")
	completeMax := flag.Int("complete-max", detector.CompleteDefaultMax, "With -report -complete: candidates shown per hit, most-likely first (only with -complete)")
	dfxmlPath := flag.String("dfxml", "", "Convert a -json hits file (or - for stdin) to DFXML on stdout instead of scanning")
	verifyLogPath := flag.String("verify-case-log", "", "Re-hash the sources behind each record in case-log FILE and report match/mismatch instead of scanning")
	advisePath := flag.String("advise", "", "Inspect TARGET and print the recommended scan command with reasons (never scans, never runs anything)")
	baselinePath := flag.String("baseline", "", "Suppress -walk/-patch findings fingerprinted in baseline FILE (a reviewed hits.jsonl from an earlier sweep)")
	patchMode := flag.Bool("patch", false, "Parse input as a patch series (git log -p): attribute hits to commit+path with history fingerprints for -baseline")
	hashesPath := flag.String("hashes", "", "Extract crack-ready password hashes from FILE (or - for stdin) instead of scanning")
	tokenlistPath := flag.String("tokenlist", "", "Build a BTCRecover tokenlist from the words in FILE, a carve, or hits.jsonl with carves (or - for stdin) instead of scanning")
	tokenlistOut := flag.String("tokenlist-out", "", "Write the tokenlist to PATH instead of stdout (only with -tokenlist)")
	tokenlistMax := flag.Int("tokenlist-max", detector.TokenlistDefaultMax, "Emit at most N token lines, first-seen first (only with -tokenlist)")
	salvagePath := flag.String("salvage", "", "Analyze FILE for salvageable database pages instead of scanning")
	salvageOut := flag.String("salvage-out", "", "Write the salvaged database image to PATH (only with -salvage)")
	watchPath := flag.String("watch", "", "Derive watch-only addresses from extended public keys in FILE (a carve, a key file, or hits.jsonl with carves) instead of scanning")
	watchOut := flag.String("watch-out", "", "Write the address list to PATH instead of stdout (only with -watch)")
	watchFormat := flag.String("watch-format", "csv", "Address-list format: csv or json (only with -watch)")
	watchCount := flag.Int("watch-count", detector.WatchDefaultCount, "Addresses to derive per chain, external and change (only with -watch)")
	balanceEndpoint := flag.String("balance-endpoint", "", "Opt-in: query ADDRESS balances from this Esplora-compatible base URL (only with -watch; leaks addresses to that server)")
	fsPath := flag.String("fs", "", "Filesystem-aware mode: recover deleted entries with names from the NTFS/ext/FAT/exFAT volume in FILE and scan their content")
	fsOffset := flag.Int64("fs-offset", 0, "Byte offset of the volume boot sector inside FILE (only with -fs and -unallocated-only); when omitted, the partition table is followed automatically")
	unallocatedOnly := flag.Bool("unallocated-only", false, "Scan only unallocated filesystem space (volume at -fs-offset); skips live data")
	walkPath := flag.String("walk", "", "Sweep every regular file under DIR with the standard detectors (symlinks not followed unless -walk-follow-symlinks)")
	walkFollow := flag.Bool("walk-follow-symlinks", false, "Follow symlinks during -walk (loops fail safe per link)")
	walkDepth := flag.Int("walk-maxdepth", 0, "Descend at most N levels below DIR during -walk (0 = unlimited)")
	reveal := flag.Bool("reveal", false, "Print seed words for BIP39 hits (owner recovery only; NEVER share this output)")
	caseLog := flag.String("case-log", "", "Append a JSON case-log record per scan to FILE (source identity, streaming hashes, skipped ranges, counts)")
	profile := flag.String("profile", "", "Detector set: empty (wallet matchers) or secrets (adds private-key blocks and credential shapes; see docs/SECRETS_PROFILE.md)")
	failOnHit := flag.Bool("fail-on-hit", false, "Exit 3 when the scan or report finds anything (for CI gates and pre-commit hooks); without it, finding hits still exits 0")
	flag.Parse()
	switch *profile {
	case "", "default", "secrets":
	default:
		fmt.Fprintf(os.Stderr, "[main] Exiting due to error: unknown -profile %q (want \"\" or \"secrets\")\n", *profile)
		os.Exit(1)
	}
	// An explicit -fs-offset pins the volume; otherwise -fs and
	// -unallocated-only follow the partition table (Goal 12).
	fsOffsetSet := false
	completeMaxSet := false
	tokenlistMaxSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "fs-offset" {
			fsOffsetSet = true
		}
		if f.Name == "complete-max" {
			completeMaxSet = true
		}
		if f.Name == "tokenlist-max" {
			tokenlistMaxSet = true
		}
	})
	if *showVersion {
		fmt.Printf("findbtc %s\n", version)
		return
	}
	if *reveal {
		fmt.Fprintln(os.Stderr, "WARNING: --reveal prints seed words to stdout. Owner recovery only: keep this output secret, never share or paste it anywhere.")
	}
	if *complete || *completeOut != "" || completeMaxSet {
		if *reportPath == "" {
			fmt.Fprintln(os.Stderr, "[complete] Exiting due to error: -complete is a -report follow-up: findbtc -report hits.jsonl -complete --reveal")
			os.Exit(2)
		}
		if !*complete {
			fmt.Fprintln(os.Stderr, "[complete] Exiting due to error: -complete-out and -complete-max need -complete")
			os.Exit(2)
		}
		if *jsonOut {
			fmt.Fprintln(os.Stderr, "[complete] Exiting due to error: -complete prints candidate seeds for humans on this terminal; drop -json (machine output gets saved and logged)")
			os.Exit(2)
		}
		if !*reveal {
			fmt.Fprintln(os.Stderr, "[complete] Exiting due to error: -complete prints candidate seed phrases — re-run with --reveal on your own machine, local terminal only, and never share the output")
			os.Exit(2)
		}
		if *completeMax < 1 || *completeMax > detector.CompleteHardMax {
			fmt.Fprintf(os.Stderr, "[complete] Exiting due to error: -complete-max must be 1-%d\n", detector.CompleteHardMax)
			os.Exit(2)
		}
	}
	if *reportPath != "" {
		runReport(*reportPath, *jsonOut, *failOnHit, *complete, *completeOut, *completeMax)
		return
	}
	if *dfxmlPath != "" {
		runDFXML(*dfxmlPath)
		return
	}
	if *advisePath != "" {
		runAdvise(*advisePath)
		return
	}
	if *verifyLogPath != "" {
		if err := detector.VerifyCaseLog(*verifyLogPath, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "[verify] Exiting due to error: %s\n", err.Error())
			os.Exit(1)
		}
		return
	}
	if *tokenlistPath != "" || *tokenlistOut != "" || tokenlistMaxSet {
		if *tokenlistPath == "" {
			fmt.Fprintln(os.Stderr, "[tokenlist] Exiting due to error: -tokenlist-out and -tokenlist-max need -tokenlist FILE")
			os.Exit(2)
		}
		if *tokenlistMax < 1 || *tokenlistMax > detector.TokenlistHardMax {
			fmt.Fprintf(os.Stderr, "[tokenlist] Exiting due to error: -tokenlist-max must be 1-%d\n", detector.TokenlistHardMax)
			os.Exit(2)
		}
		runTokenlist(*tokenlistPath, *tokenlistOut, *tokenlistMax)
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
		if *fsPath == "-" {
			fmt.Fprintln(os.Stderr, "[fs] Exiting due to error: -fs needs a seekable FILE with filesystem offsets; pipes cannot provide them")
			os.Exit(1)
		}
		if *patchMode {
			fmt.Fprintln(os.Stderr, "[fs] Exiting due to error: -patch attributes raw patch bytes; it has no meaning for -fs entry scans")
			os.Exit(1)
		}
		if *baselinePath != "" {
			fmt.Fprintln(os.Stderr, "[fs] Exiting due to error: -baseline suppresses -walk and -patch findings only; it has no meaning for -fs")
			os.Exit(2)
		}
		runFS(*fsPath, *fsOffset, !fsOffsetSet, *jsonOut, *extractDir, *contextBytes, *reveal, *caseLog, *checkpointPath, *resume, *profile, *failOnHit)
		return
	}
	if *walkPath != "" {
		if *walkPath == "-" {
			fmt.Fprintln(os.Stderr, "[walk] Exiting due to error: -walk needs a directory to sweep; pipes cannot provide one")
			os.Exit(1)
		}
		if *patchMode {
			fmt.Fprintln(os.Stderr, "[walk] Exiting due to error: -patch attributes one patch stream; -walk sweeps files that are not patches")
			os.Exit(1)
		}
		if *resume || *checkpointPath != "" {
			fmt.Fprintln(os.Stderr, "[walk] Exiting due to error: -checkpoint and -resume are not supported with -walk")
			os.Exit(1)
		}
		if *startOffset != 0 {
			fmt.Fprintln(os.Stderr, "[walk] Exiting due to error: -s has no meaning for a file sweep")
			os.Exit(1)
		}
		runWalk(*walkPath, *walkFollow, *walkDepth, *jsonOut, *extractDir, *contextBytes, *reveal, *caseLog, *profile, *failOnHit, *baselinePath)
		return
	}
	if *baselinePath != "" && !*patchMode {
		fmt.Fprintln(os.Stderr, "[walk] Exiting due to error: -baseline suppresses -walk and -patch findings only; it has no meaning for other modes")
		os.Exit(2)
	}
	path := flag.Arg(0)

	if path == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s [-s OFFSET] [-json] [-profile NAME] [-fail-on-hit] [-extract-dir DIR [-context BYTES]] [-checkpoint FILE [-resume]] [-unallocated-only [-fs-offset OFF]] [-case-log FILE] [-patch [-baseline FILE]] DEVICE|-\n   or: %s -report hits.jsonl [-json] [-fail-on-hit] [-complete --reveal [-complete-out PATH] [-complete-max N]]\n   or: %s -hashes FILE [-json]\n   or: %s -tokenlist FILE [-tokenlist-out PATH] [-tokenlist-max N]\n   or: %s -salvage FILE [-salvage-out PATH] [-json]\n   or: %s -watch FILE [-watch-out PATH] [-watch-format csv|json] [-watch-count N] [-balance-endpoint URL]\n   or: %s -fs FILE [-fs-offset OFF] [-json] [-profile NAME] [-fail-on-hit] [-extract-dir DIR [-context BYTES]] [-checkpoint FILE [-resume]]\n   or: %s -walk DIR [-walk-follow-symlinks] [-walk-maxdepth N] [-json] [-profile NAME] [-fail-on-hit] [-baseline FILE] [-extract-dir DIR [-context BYTES]]\n   or: %s -dfxml hits.jsonl\n   or: %s -verify-case-log case.jsonl\n   or: %s -advise TARGET\n\n", os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
		flag.PrintDefaults()
		os.Exit(2)
	}

	// Pipes scan through a bounded spill (Goal 35): byte-identical
	// detections, but no resume and no range modes — a journaled
	// offset into a deleted temp file could never resume, and
	// ranges need filesystem offsets pipes cannot provide.
	if path == "-" {
		if *unallocatedOnly {
			fmt.Fprintln(os.Stderr, "[main] Exiting due to error: -unallocated-only needs filesystem offsets; pipes cannot provide them")
			os.Exit(1)
		}
		if *resume || *checkpointPath != "" {
			fmt.Fprintln(os.Stderr, "[main] Exiting due to error: -checkpoint and -resume are not supported with stdin (pipes cannot resume)")
			os.Exit(1)
		}
	}

	if *patchMode && *unallocatedOnly {
		fmt.Fprintln(os.Stderr, "[main] Exiting due to error: -patch attributes whole patch streams; range scans would misattribute")
		os.Exit(1)
	}
	if *patchMode && (*checkpointPath != "" || *resume) {
		fmt.Fprintln(os.Stderr, "[main] Exiting due to error: -checkpoint and -resume are not supported with -patch (buffered findings would be lost on crash+resume)")
		os.Exit(1)
	}

	start := *startOffset
	if *resume && *checkpointPath == "" {
		fmt.Fprintln(os.Stderr, "[main] Exiting due to error: -resume requires -checkpoint")
		os.Exit(1)
	}
	// Range scans (-unallocated-only) resume inside the detector, which
	// validates the range list; only single-target scans resume here.
	if *resume && !*unallocatedOnly {
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
			if len(cp.Ranges) > 0 {
				fmt.Fprintf(os.Stderr, "[main] Exiting due to error: checkpoint is a range-scan journal; resume it with -fs or -unallocated-only\n")
				os.Exit(1)
			}
			start = cp.Offset
			msg := fmt.Sprintf("[main] Resuming %s at byte offset %d", path, start)
			// Percent needs a known size; without one the byte
			// offset stands alone (unchanged legacy shape).
			if fi, serr := os.Stat(path); serr == nil && fi.Size() > 0 && start >= 0 && start <= fi.Size() {
				msg += fmt.Sprintf(" (continuing at %d%%)", start*100/fi.Size())
			}
			fmt.Fprintln(os.Stderr, msg)
		}
	}

	opts := detector.Options{CarveDir: *extractDir, CarveContextBytes: *contextBytes, CheckpointPath: *checkpointPath, Reveal: *reveal, CaseLogPath: *caseLog, ToolVersion: version, Flags: os.Args[1:], Resume: *resume, Profile: *profile, Patch: *patchMode}
	// History baselines suppress accepted history findings the way
	// -walk baselines suppress accepted sweep findings; anything
	// unfingerprinted always reports.
	var baselineKeys map[string]bool
	if *baselinePath != "" {
		keys, err := detector.LoadBaselineFingerprints(*baselinePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[main] Exiting due to error: %s\n", err.Error())
			os.Exit(1)
		}
		baselineKeys = keys
		fmt.Fprintf(os.Stderr, "[main] baseline %s: %d known findings will stay silent\n", *baselinePath, len(keys))
	}
	var hits, suppressed int
	printDetection := func(detection detector.Detection) {
		if baselineKeys != nil && detection.Fingerprint != "" && baselineKeys[detection.Fingerprint] {
			suppressed++
			return
		}
		hits++
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
			if detection.Commit != "" {
				loc := detection.Commit
				if detection.Path != "" {
					loc += " " + detection.Path
					if detection.Line > 0 {
						loc += fmt.Sprintf(":%d", detection.Line)
					}
				}
				fmt.Printf("  commit: %s\n", loc)
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
		err = runUnallocated(path, *fsOffset, !fsOffsetSet, start, opts, printDetection)
	} else if path == "-" {
		err = detector.ScanStdinWithOptions(os.Stdin, start, opts, printDetection, newProgressReporter().onProgress)
	} else {
		err = detector.ScanWithOptions(start, path, opts, printDetection, newProgressReporter().onProgress)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "[main] Exiting due to error: %s\n", err.Error())
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "[COMPLETE]")
	if suppressed > 0 {
		fmt.Fprintf(os.Stderr, "[main] %d suppressed by baseline\n", suppressed)
	}
	gateOnHits("main", hits, *failOnHit)
}

// runUnallocated implements --unallocated-only: scan just the free space
// of the volume at fsOffset, or of every supported volume on the
// disk when autoSeed follows the partition table. The merged range list
// journals (range_index, offset); resume validates the list still matches.
func runUnallocated(path string, fsOffset int64, autoSeed bool, start int64, opts detector.Options, onDetection func(detector.Detection)) error {
	kinds, free, err := detector.UnallocatedRangesAuto(path, fsOffset, autoSeed)
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
	fmt.Fprintf(os.Stderr, "[main] Scanning %d unallocated ranges (%d bytes) of %s volume(s) %s.\n",
		len(ranges), total, strings.Join(kinds, "+"), path)
	return detector.ScanRangesWithOptions(path, ranges, opts, onDetection, newProgressReporter().onProgress)
}

// runFS implements filesystem-aware mode: inventory live and deleted
// entries with names, then scan deleted entries' content with filenames
// stamped on every hit.
func runFS(path string, fsOffset int64, autoSeed bool, jsonOut bool, carveDir string, contextBytes int64, reveal bool, caseLog string, checkpointPath string, resume bool, profile string, failOnHit bool) {
	opts := detector.Options{CarveDir: carveDir, CarveContextBytes: contextBytes, Reveal: reveal, CaseLogPath: caseLog, ToolVersion: version, Flags: os.Args[1:], CheckpointPath: checkpointPath, Resume: resume, Profile: profile}
	var hits int
	_, err := detector.ScanFSVolumes(path, fsOffset, autoSeed, opts, func(detection detector.Detection) {
		hits++
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
	gateOnHits("fs", hits, failOnHit)
}

// runWalk implements directory-sweep mode: every regular file under root
// gets the standard detectors, one unreadable file never aborts the
// sweep, and each file appends its own case-log record.
func runWalk(root string, follow bool, maxdepth int, jsonOut bool, carveDir string, contextBytes int64, reveal bool, caseLog string, profile string, failOnHit bool, baselinePath string) {
	opts := detector.WalkOptions{
		Scan:           detector.Options{CarveDir: carveDir, CarveContextBytes: contextBytes, Reveal: reveal, CaseLogPath: caseLog, ToolVersion: version, Flags: os.Args[1:], Profile: profile},
		MaxDepth:       maxdepth,
		FollowSymlinks: follow,
	}
	if baselinePath != "" {
		keys, err := detector.LoadBaselineFingerprints(baselinePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[walk] Exiting due to error: %s\n", err.Error())
			os.Exit(1)
		}
		opts.Baseline = keys
		fmt.Fprintf(os.Stderr, "[walk] baseline %s: %d known findings will stay silent\n", baselinePath, len(keys))
	}
	stats, err := detector.Walk(root, opts, func(detection detector.Detection) {
		if jsonOut {
			line, err := json.Marshal(detection)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[walk] cannot encode detection: %s\n", err.Error())
				return
			}
			fmt.Println(string(line))
			return
		}
		fmt.Printf("[walk] Found possible wallet trace:\n  %s\n", detection.Description)
		if detection.FileName != "" {
			fmt.Printf("  file: %s\n", detection.FileName)
		}
		if len(detection.Words) > 0 {
			fmt.Printf("  words: %s\n", strings.Join(detection.Words, " "))
		}
		if detection.CarvePath != "" {
			fmt.Printf("  carved to: %s\n", detection.CarvePath)
		}
	}, newProgressReporter().onProgress)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[walk] Exiting due to error: %s\n", err.Error())
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "[walk] swept %d files: %d detections, %d skipped symlinks, %d skipped special, %d skipped own-output, %d failures",
		stats.Files, stats.Detections, stats.SkippedSymlinks, stats.SkippedSpecial, stats.SkippedOwn, stats.FailedTotal)
	if stats.SuppressedBaseline > 0 {
		fmt.Fprintf(os.Stderr, ", %d suppressed by baseline", stats.SuppressedBaseline)
	}
	fmt.Fprintln(os.Stderr, ".")
	for _, f := range stats.Failed {
		fmt.Fprintf(os.Stderr, "[walk] failed: %s: %s\n", f.Path, f.Err)
	}
	if stats.FailedTotal > int64(len(stats.Failed)) {
		fmt.Fprintf(os.Stderr, "[walk] ... and %d more failures (capped in this summary; -case-log holds the per-file records).\n",
			stats.FailedTotal-int64(len(stats.Failed)))
	}
	if stats.FailedTotal > 0 {
		fmt.Fprintf(os.Stderr, "[walk] WARNING: %d file(s) could not be scanned; coverage is incomplete.\n", stats.FailedTotal)
	}
	if stats.Files == 0 {
		// Zero coverage: nothing was scanned, so 0 would certify a
		// clean tree the sweep never saw. Skips are policy (counted
		// above); failures carry the reasons.
		skipped := stats.SkippedSymlinks + stats.SkippedSpecial + stats.SkippedDepth + stats.SkippedOwn
		fmt.Fprintf(os.Stderr, "[walk] Exiting due to error: scanned 0 files, nothing was covered (%d failures, %d skipped)\n",
			stats.FailedTotal, skipped)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "[COMPLETE]")
	gateOnHits("walk", int(stats.Detections), failOnHit)
}

// runReport implements triage mode: summarize saved -json hits offline.
func runAdvise(path string) {
	ad, err := detector.Advise(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[advise] Exiting due to error: %s\n", err.Error())
		os.Exit(1)
	}
	fmt.Printf("Target: %s\n", ad.Target)
	if ad.Command == "" {
		for _, r := range ad.Reasons {
			fmt.Printf("  %s\n", r)
		}
		return
	}
	fmt.Printf("Recommended: %s\n", ad.Command)
	fmt.Printf("Why:\n")
	for _, r := range ad.Reasons {
		fmt.Printf("  - %s\n", r)
	}
	for _, a := range ad.Also {
		fmt.Printf("Also consider: %s\n", a)
	}
}

func runReport(path string, jsonOut bool, failOnHit, complete bool, completeOut string, completeMax int) {
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
	} else {
		fmt.Print(rep.Text())
	}
	if complete {
		runSeedComplete(dets, path, completeOut, completeMax)
	}
	gateOnHits("report", rep.Unique, failOnHit)
}

// runSeedComplete implements the -report -complete follow-up: enumerate
// checksum-valid completions for partial-seed (near-miss) hits carrying
// --reveal words, most-likely first, with a "did you mean" correction
// and an optional watch-only handoff file. Always exits 0: refusals and
// empty inputs are completed triage answers, not failures.
func runSeedComplete(dets []detector.Detection, path, outPath string, max int) {
	fmt.Fprintln(os.Stderr, detector.SeedCompleteWarning())
	var near []detector.Detection
	unordered := 0
	for _, d := range dets {
		switch {
		case strings.Contains(d.Needle, "near-miss"):
			near = append(near, d)
		case d.Needle == "bip39-unordered":
			unordered++
		}
	}
	if len(near) == 0 {
		fmt.Printf("Seed completion: no partial-seed (near-miss) hits to complete in %s.\n", path)
		fmt.Println("Two usual reasons:")
		fmt.Println("  1. The hits were scanned without --reveal, so no words are attached. Rescan the carve on your own machine: findbtc --reveal -json CARVE > hits2.jsonl")
		fmt.Println("  2. Three or more words are missing or garbled: billions of tries, beyond offline enumeration. Take the carve to BTCRecover with GPU tokenlists (see docs/WHAT_NEXT.md).")
		if unordered > 0 {
			fmt.Printf("  (%d unordered word-pile hits are not completable either: reordering is BTCRecover's job, not enumeration.)\n", unordered)
		}
		return
	}
	var out *os.File
	if outPath != "" {
		var err error
		out, err = os.Create(outPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[complete] Exiting due to error: %s\n", err.Error())
			os.Exit(1)
		}
		defer out.Close()
		fmt.Fprintln(out, "# findbtc -complete handoff: watch-only account keys (3 per candidate).")
		fmt.Fprintln(out, "# Candidate numbers match the terminal listing above; phrases never land in this file.")
	}
	wordless := 0
	completed := 0
	totalKeys := 0
	fmt.Printf("Seed completion (offline; %d partial-seed hits in %s):\n", len(near), path)
	for i, d := range near {
		tag := fmt.Sprintf("[hit %d] %s @%d (%s)", i+1, d.Needle, d.Offset, d.Target)
		if len(d.Words) == 0 {
			fmt.Printf("%s — no words attached (scanned without --reveal); rescan the carve with --reveal to complete it.\n", tag)
			wordless++
			continue
		}
		res, err := detector.CompleteSeed(d.Words, max)
		if err != nil {
			fmt.Printf("%s REFUSED: %s\n", tag, err.Error())
			continue
		}
		completed++
		fmt.Printf("%s gaps=%v\n", tag, res.Partial.Gaps)
		for _, c := range res.Corrections {
			fmt.Printf("  did you mean %q at position %d? (gap was %q; checksum-valid)\n",
				c.Suggest[0], c.Position, c.Token)
			for _, alt := range c.Suggest[1:] {
				fmt.Printf("  ... or %q at position %d? (checksum-valid)\n", alt, c.Position)
			}
		}
		showing := "showing all"
		if res.Truncated {
			showing = fmt.Sprintf("showing %d most-likely first", len(res.Shown))
		}
		fmt.Printf("  %d checksum-valid completions (%s):\n", res.Total, showing)
		for k, s := range res.Shown {
			fmt.Printf("  candidate %d: %s\n", k+1, strings.Join(s.Words, " "))
			if out != nil {
				accts, err := detector.SeedToAccounts(s.Words)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[complete] Exiting due to error: %s\n", err.Error())
					os.Exit(1)
				}
				fmt.Fprintf(out, "# candidate %d (hit %d %s @%d)\n", k+1, i+1, d.Needle, d.Offset)
				fmt.Fprintln(out, accts.XPub44)
				fmt.Fprintln(out, accts.YPub49)
				fmt.Fprintln(out, accts.ZPub84)
				totalKeys += 3
			}
		}
		if res.Truncated {
			fmt.Printf("  ... %d more not shown. Narrow the gaps (fix a typo) or raise -complete-max (max %d).\n",
				res.Total-len(res.Shown), detector.CompleteHardMax)
		}
	}
	if wordless > 0 {
		fmt.Printf("%d of %d near-miss hits carry no words: rescan with --reveal on your own machine, then re-run -complete.\n", wordless, len(near))
	}
	if out != nil {
		fmt.Printf("Wrote %d watch-only account keys to %s (3 per candidate: m/44'/0'/0' xpub, m/49'/0'/0' ypub, m/84'/0'/0' zpub).\n", totalKeys, outPath)
		fmt.Printf("Next: findbtc -watch %s -watch-out addrs.csv — then check those addresses from your own node (see docs/WATCH_ONLY.md). Match the funded candidate number back to the phrase above and restore it in wallet software, offline.\n", outPath)
	} else if completed > 0 {
		fmt.Println("Next: re-run with -complete-out keys.txt to derive watch-only account keys for these candidates, then findbtc -watch keys.txt -watch-out addrs.csv.")
	}
	fmt.Println("When to stop: a candidate whose addresses are all empty on every path is the wrong phrase — delete the output. If no candidate funds, the missing words were never findable this way; see docs/WHAT_NEXT.md.")
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
	hashes, skips := detector.ExtractHashesWithSkips(buf, 0)
	if hashes == nil {
		hashes = []detector.CrackHash{}
	}
	// Skips ride stderr in both modes: stdout stays a pure hash list
	// (or JSON array) while the user still learns WHY a wallet-shaped
	// record produced nothing.
	for _, s := range skips {
		fmt.Fprintf(os.Stderr, "[hashes] skipped %s @%d: %s\n", s.Kind, s.Offset, s.Reason)
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

// runTokenlist implements tokenlist mode: turn hit-context bytes (a carve,
// a notes file, or hits.jsonl whose carves are then read) into a
// BTCRecover tokenlist — one line per distinct nearby word with case
// mutations. Always exits 0: empty input is a completed answer, like
// "No crack material found".
func runTokenlist(path, outPath string, max int) {
	f := os.Stdin
	if path != "-" {
		var err error
		f, err = os.Open(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[tokenlist] Exiting due to error: %s\n", err.Error())
			os.Exit(1)
		}
		defer f.Close()
	}
	buf, err := io.ReadAll(io.LimitReader(f, detector.TokenlistMaxBytes+1))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[tokenlist] Exiting due to error: %s\n", err.Error())
		os.Exit(1)
	}
	if len(buf) > detector.TokenlistMaxBytes {
		fmt.Fprintf(os.Stderr, "[tokenlist] Exiting due to error: input exceeds %d bytes\n", detector.TokenlistMaxBytes)
		os.Exit(1)
	}
	data := tokenlistInputBytes(buf, path)
	text, stats := detector.BuildTokenlist(data, max)
	if text == "" {
		fmt.Printf("No token words found in %s (need 3+ letter/digit runs).\n", path)
		return
	}
	if outPath != "" {
		if err := os.WriteFile(outPath, []byte(text), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "[tokenlist] Exiting due to error: %s\n", err.Error())
			os.Exit(1)
		}
	}
	if stats.Truncated {
		fmt.Fprintf(os.Stderr, "[tokenlist] warning: %d words found, showing first %d (raise -tokenlist-max)\n",
			stats.Words, stats.Lines)
	}
	if outPath == "" {
		fmt.Print(text)
		return
	}
	fmt.Printf("Wrote %d token lines (%d base words) to %s\n", stats.Lines, stats.Words, outPath)
	// The example filename is split so this file stays needle-free:
	// TestWalkSelfScanRepo scans the repo and the joined name is a
	// filename needle.
	fmt.Println("Next: trim to the words you recognize, then: python3 btcrecover.py --wallet "+"wallet"+".dat --tokenlist", outPath, "--max-tokens 3")
	fmt.Println("Full runbook (tokenlists, wildcards, typos): docs/PASSWORD_RECOVERY.md")
}

// tokenlistInputBytes resolves -tokenlist input: hits.jsonl with carve
// paths reads through to the carve bytes (like -watch); anything else is
// used verbatim.
func tokenlistInputBytes(buf []byte, path string) []byte {
	dets, err := detector.ReadDetections(bytes.NewReader(buf))
	if err != nil || len(dets) == 0 || !hitsShaped(dets) {
		return buf
	}
	var data []byte
	carves := 0
	readOK := 0
	capped := false
	for _, d := range dets {
		if d.CarvePath == "" {
			continue
		}
		carves++
		// Carve bytes bypass the initial input cap, so each carve
		// is read against the remaining budget — never whole:
		// carves are consumed in hit order up to
		// TokenlistMaxBytes, the carve that crosses the line is
		// truncated to what remains, and further carves are not
		// opened at all. At most one byte over budget is ever
		// allocated (the overflow probe).
		room := detector.TokenlistMaxBytes - len(data) - 1 // room for the '\n' separator
		if room <= 0 {
			capped = true
			break
		}
		carve, overflow, err := readCarveCapped(d.CarvePath, room)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[tokenlist] warning: cannot read carve %s: %s\n", d.CarvePath, err.Error())
			continue
		}
		readOK++
		data = append(data, carve...)
		data = append(data, '\n')
		if overflow {
			capped = true
			break
		}
	}
	if carves == 0 {
		fmt.Fprintf(os.Stderr, "[tokenlist] Exiting due to error: %s has hits but no carve paths — rescan with -extract-dir, or run -tokenlist on a file holding the context\n", path)
		os.Exit(1)
	}
	// Zero bytes scanned is blindness, not cleanliness: like -walk's
	// all-failed rule, carves that all fail to read fail the run
	// instead of falling through to the empty-data message.
	if readOK == 0 {
		fmt.Fprintf(os.Stderr, "[tokenlist] Exiting due to error: %s names carve paths but none could be read\n", path)
		os.Exit(1)
	}
	if capped {
		fmt.Fprintf(os.Stderr, "[tokenlist] warning: carve bytes exceed %d; using the first %d\n", detector.TokenlistMaxBytes, len(data))
	}
	return data
}

// hitsShaped tells real hits.jsonl from JSON that merely parses:
// Detection has no required fields, so a foreign object like {"a": 1}
// would otherwise be misread as one carveless hit and refused. Real
// hits always carry description/needle/target; input with all three
// empty on every record is used verbatim.
func hitsShaped(dets []detector.Detection) bool {
	for _, d := range dets {
		if d.Description != "" || d.Needle != "" || d.Target != "" {
			return true
		}
	}
	return false
}

// readCarveCapped reads at most max bytes from path (plus one probe
// byte to detect overflow); it reports the bytes kept, whether the
// file held more, and any read error. A single oversized carve can
// never allocate past max+1.
func readCarveCapped(path string, max int) (kept []byte, overflow bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	buf, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return nil, false, err
	}
	if len(buf) > max {
		return buf[:max], true, nil
	}
	return buf, false, nil
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
		fmt.Printf(", ordered")
	} else {
		fmt.Printf(", unordered (page map only)")
	}
	fmt.Printf(", %s\n", info.Verdict)
	for _, reason := range info.Reasons {
		fmt.Printf("  suspect: %s\n", reason)
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

// progressWarmup is how long a target scans before its progress lines
// show throughput and ETA: sub-second averages are noise (0.0MB/s,
// wild ETAs), so early lines show percent/bytes only.
const progressWarmup = 5 * time.Second

type progressReporter struct {
	lastReport  int64
	interval    int64
	started     bool
	startTime   time.Time
	startBytes  int64
	lastTarget  string
	lastScanned int64
	lastTotal   int64
	now         func() time.Time
}

func newProgressReporter() *progressReporter {
	return &progressReporter{interval: PROGRESS_REPORT_INTERVAL, now: time.Now}
}

func (p *progressReporter) onProgress(pg detector.ProgressInfo) {
	now := time.Now()
	if p.now != nil {
		now = p.now()
	}
	if !p.started {
		p.started = true
		p.startTime = now
		p.startBytes = pg.ScannedBytes
	}
	// A new target restarts the baseline: walk reuses one reporter
	// across files, and same-size (or unknown-size) targets share a
	// TotalBytes, so identity and counter resets — not the total
	// alone — mark the switch. Without this a new file inherits the
	// old file's timing and prints garbage like negative rates.
	retargeted := pg.CurrentTarget != p.lastTarget ||
		pg.ScannedBytes < p.lastScanned ||
		pg.TotalBytes != p.lastTotal
	p.lastTarget, p.lastScanned, p.lastTotal = pg.CurrentTarget, pg.ScannedBytes, pg.TotalBytes
	if retargeted {
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
		if elapsed := now.Sub(p.startTime); elapsed >= progressWarmup {
			mbps := float64(pg.ScannedBytes-p.startBytes) / elapsed.Seconds() / (1024 * 1024)
			rate = fmt.Sprintf(" %.1fMB/s", mbps)
			// Honest ETA: the cumulative average, which rises when
			// the scan slows. Clamping it down would print a time
			// the reporter's own rate contradicts.
			if pg.TotalBytes > 0 && mbps > 0 {
				remaining := time.Duration(float64(pg.TotalBytes-pg.ScannedBytes)/(mbps*1024*1024)) * time.Second
				if remaining < 0 {
					remaining = 0
				}
				eta = fmt.Sprintf(" ETA %s", formatETA(remaining))
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
