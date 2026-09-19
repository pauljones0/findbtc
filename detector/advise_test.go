package detector

// Guided-mode routing tests (Goal 27): each target shape routes to
// its documented-best command, with reasons. One test also proves
// Advise never scans: a needle-bearing target yields advice only,
// never a detection.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdviseDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.bin"), []byte("bestblock"), 0644); err != nil {
		t.Fatal(err)
	}
	ad, err := Advise(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ad.Command, "findbtc -walk ") || !strings.Contains(ad.Command, dir) {
		t.Errorf("command %q, want findbtc -walk <dir>", ad.Command)
	}
	if joined := strings.Join(ad.Reasons, "; "); !strings.Contains(joined, "is a directory") {
		t.Errorf("reasons %q must name the directory", joined)
	}
}

func TestAdviseEmptyDirectory(t *testing.T) {
	ad, err := Advise(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if ad.Command != "" {
		t.Errorf("command %q, want none for an empty directory", ad.Command)
	}
}

func TestAdvisePartitionedDisk(t *testing.T) {
	for _, scheme := range []string{"mbr", "gpt"} {
		path, _ := composeDisk(t, scheme)
		ad, err := Advise(path)
		if err != nil {
			t.Fatal(err)
		}
		if ad.Command != "findbtc -fs "+path {
			t.Errorf("%s: command %q, want findbtc -fs", scheme, ad.Command)
		}
		joined := strings.Join(ad.Reasons, "; ")
		if !strings.Contains(joined, strings.ToUpper(scheme)) || !strings.Contains(joined, "auto-seed") {
			t.Errorf("%s: reasons %q must cite the table and auto-seed", scheme, joined)
		}
		if len(ad.Also) != 1 || !strings.Contains(ad.Also[0], "-unallocated-only") {
			t.Errorf("%s: also %v, want the free-space follow-up", scheme, ad.Also)
		}
	}
}

func TestAdviseVolumeImage(t *testing.T) {
	for name, build := range map[string]func(*testing.T) string{
		"ext":   buildTestExt,
		"ntfs":  buildTestNTFS,
		"fat32": buildTestFAT32,
		"exfat": buildTestExFAT,
	} {
		ad, err := Advise(build(t))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(ad.Command, "findbtc -fs ") {
			t.Errorf("%s: command %q, want findbtc -fs", name, ad.Command)
		}
		if joined := strings.Join(ad.Reasons, "; "); !strings.Contains(joined, "at offset 0") {
			t.Errorf("%s: reasons %q must cite the volume", name, joined)
		}
	}
}

func TestAdviseRawFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "raw.bin")
	raw := make([]byte, 1<<20)
	for i := range raw {
		raw[i] = byte(i*31 + 7)
	}
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	ad, err := Advise(path)
	if err != nil {
		t.Fatal(err)
	}
	if ad.Command != "findbtc "+path {
		t.Errorf("command %q, want a raw scan", ad.Command)
	}
	if joined := strings.Join(ad.Reasons, "; "); !strings.Contains(joined, "no partition table or filesystem") {
		t.Errorf("reasons %q must explain the fallback", joined)
	}
}

// Advise must not scan: needles in the target produce advice, never
// detection lines.
func TestAdviseNeverScans(t *testing.T) {
	path := filepath.Join(t.TempDir(), "needle.bin")
	blob := append([]byte("prefix "), append([]byte("bestblock"), []byte(" suffix")...)...)
	if err := os.WriteFile(path, bytesRepeat(blob, 100), 0644); err != nil {
		t.Fatal(err)
	}
	ad, err := Advise(path)
	if err != nil {
		t.Fatal(err)
	}
	text := ad.Command + "\n" + strings.Join(ad.Reasons, "\n") + "\n" + strings.Join(ad.Also, "\n")
	if strings.Contains(text, "Found '") || strings.Contains(text, "bestblock") {
		t.Errorf("advice leaks detections:\n%s", text)
	}
	if ad.Command == "" {
		t.Error("needle-bearing raw file still deserves a command")
	}
}

func bytesRepeat(b []byte, n int) []byte {
	var out []byte
	for range n {
		out = append(out, b...)
	}
	return out
}

func TestAdviseEmptyAndMissing(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty.bin")
	if err := os.WriteFile(empty, nil, 0644); err != nil {
		t.Fatal(err)
	}
	ad, err := Advise(empty)
	if err != nil {
		t.Fatal(err)
	}
	if ad.Command != "" {
		t.Errorf("command %q, want none for an empty file", ad.Command)
	}
	if _, err := Advise(filepath.Join(t.TempDir(), "nope.bin")); err == nil {
		t.Error("missing path must error")
	}
}

func TestAdviseUnsupportedPartitionsFallBackToRaw(t *testing.T) {
	disk := make([]byte, 8*1024)
	putMBRSlot(disk, 0, 0xDA, 1, 8)
	putMBRSlot(disk, 1, 0x83, 9, 4)
	path := filepath.Join(t.TempDir(), "odd.img")
	if err := os.WriteFile(path, disk, 0644); err != nil {
		t.Fatal(err)
	}
	ad, err := Advise(path)
	if err != nil {
		t.Fatal(err)
	}
	if ad.Command != "findbtc "+path {
		t.Errorf("command %q, want a raw scan", ad.Command)
	}
	if joined := strings.Join(ad.Reasons, "; "); !strings.Contains(joined, "none opens as a supported filesystem") {
		t.Errorf("reasons %q must name the layout", joined)
	}
}
