package detector

// PowerShell paste proof (Goal 40 + Supervisor 019): the advice
// output labels PowerShell as the supported Windows shell, so the
// emitted quoting must survive a real powershell.exe end to end —
// PowerShell parse plus PowerShell's native command-line rebuild —
// not merely match expected strings.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestMain doubles as a harmless native argv probe: with
// FINDBTC_ARGV_PROBE=1 the test binary writes argv[1] byte-exact to
// FINDBTC_ARGV_OUT and exits before running any test. The
// round-trip test relaunches os.Args[0] through a real
// powershell.exe, so the chain under proof is the real consumer
// chain: quotePowerShell output -> PowerShell parse -> native
// command-line rebuild -> Go argv. No quote reimplementation.
func TestMain(m *testing.M) {
	if os.Getenv("FINDBTC_ARGV_PROBE") == "1" {
		arg := ""
		if len(os.Args) > 1 {
			arg = os.Args[1]
		}
		if err := os.WriteFile(os.Getenv("FINDBTC_ARGV_OUT"), []byte(arg), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "argv probe write: %v\n", err)
			os.Exit(2)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// Every quoted nasty path round-trips through a real powershell.exe
// into a native process argv byte-identical, and quoted names of
// real on-disk files resolve with Test-Path -LiteralPath.
func TestQuotePowerShellNativeRoundTrip(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("powershell native round-trip; windows only")
	}
	ps, err := exec.LookPath("powershell")
	if err != nil {
		if ps, err = exec.LookPath("pwsh"); err != nil {
			t.Fatal("no powershell or pwsh available: cannot prove the labeled Windows shell")
		}
	}
	dir := t.TempDir()
	// Real files: every name is legal to Win32 (which forbids
	// control characters, so LF/CR stay argv-only below).
	names := []string{
		"spaced name.img",
		"dollar$literal.img",
		"back`tick`.img",
		"o'clock.img",
		"pct%100.img",
		"semi;colon.img",
		"paren(a)[b].img",
		"amp&amp.img",
		"hash#at.img",
		"eq=plus.img",
		"caf\u00e9.img",
		"plain.img",
	}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	trailDir := filepath.Join(dir, "spaced dir")
	if err := os.Mkdir(trailDir, 0755); err != nil {
		t.Fatal(err)
	}
	// Real paths resolve AND round-trip; argv-only entries (LF/CR:
	// illegal in Win32 names) round-trip through the native probe.
	var real, argvOnly []string
	for _, n := range names {
		real = append(real, filepath.Join(dir, n))
	}
	real = append(real, trailDir+string(os.PathSeparator))
	argvOnly = []string{
		filepath.Join(dir, "line\nbreak.img"),
		filepath.Join(dir, "carriage\rreturn.img"),
	}
	for i, p := range append(append([]string{}, real...), argvOnly...) {
		quoted := quotePowerShell(p)
		out := filepath.Join(dir, fmt.Sprintf("argv%d.bin", i))
		script := "& $env:FINDBTC_PS_BIN " + quoted
		cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", script)
		cmd.Env = append(os.Environ(),
			"FINDBTC_PS_BIN="+os.Args[0],
			"FINDBTC_ARGV_PROBE=1",
			"FINDBTC_ARGV_OUT="+out,
		)
		if combined, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("powershell native round-trip of %q failed: %v\n%s", p, err, combined)
		}
		got, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("powershell native round-trip of %q produced no argv file: %v", p, err)
		}
		if string(got) != p {
			t.Errorf("powershell native round-trip of %q gave %q", p, string(got))
		}
	}
	for _, p := range real {
		script := "if (Test-Path -LiteralPath " + quotePowerShell(p) + ") { exit 0 } else { exit 1 }"
		if combined, err := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput(); err != nil {
			t.Errorf("Test-Path cannot resolve real path %q: %v\n%s", p, err, combined)
		}
	}
}
