package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jakewins/findbtc/detector"
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
	flag.Parse()
	if *showVersion {
		fmt.Printf("findbtc %s\n", version)
		return
	}
	path := flag.Arg(0)

	if path == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s [-s OFFSET] [-json] [-extract-dir DIR [-context BYTES]] [-checkpoint FILE [-resume]] DEVICE\n\n", os.Args[0])
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

	opts := detector.Options{CarveDir: *extractDir, CarveContextBytes: *contextBytes, CheckpointPath: *checkpointPath}
	err := detector.ScanWithOptions(start, path, opts, func(detection detector.Detection) {
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
			if detection.CarvePath != "" {
				class := ""
				if detection.Carve != nil {
					class = fmt.Sprintf(" [%s]", detection.Carve.Class)
				}
				fmt.Printf("  carved to: %s%s\n", detection.CarvePath, class)
			}
		}
	}, newProgressReporter().onProgress)

	if err != nil {
		fmt.Fprintf(os.Stderr, "[main] Exiting due to error: %s\n", err.Error())
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "[COMPLETE]")
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
