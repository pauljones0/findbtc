package detector_test

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pauljones0/findbtc/detector"
)

// ExampleScanWithOptions scans a file end to end: write bytes, collect
// detections through a closure, print them.
func ExampleScanWithOptions() {
	dir, err := os.MkdirTemp("", "findbtc-example")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "wallet.bin")
	buf := make([]byte, 8192)
	copy(buf[5000:], "bestblock")
	if err := os.WriteFile(path, buf, 0644); err != nil {
		panic(err)
	}
	var hits []string
	err = detector.ScanWithOptions(0, path, detector.Options{},
		func(d detector.Detection) {
			hits = append(hits, fmt.Sprintf("%s@%d", d.Needle, d.Offset))
		},
		nil, // no progress reporting needed
	)
	if err != nil {
		panic(err)
	}
	fmt.Println(hits)
	// Output: [bestblock@5000]
}
