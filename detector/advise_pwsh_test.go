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
	plainDir := filepath.Join(dir, "dollar$dir")
	if err := os.Mkdir(plainDir, 0755); err != nil {
		t.Fatal(err)
	}
	// Each pair is (advised input, exact argv the real chain must
	// deliver). Trailing separators strip — the want is the known
	// dir variable, not a re-trim — while LF/CR (illegal in Win32
	// names, argv-only) must arrive byte-exact via the escape form.
	var pairs [][2]string
	for _, n := range names {
		p := filepath.Join(dir, n)
		pairs = append(pairs, [2]string{p, p})
	}
	sep := string(os.PathSeparator)
	pairs = append(pairs, [2]string{trailDir + sep, trailDir})
	pairs = append(pairs, [2]string{plainDir + sep, plainDir})
	pairs = append(pairs, [2]string{filepath.Join(dir, "line\nbreak.img"), filepath.Join(dir, "line\nbreak.img")})
	pairs = append(pairs, [2]string{filepath.Join(dir, "carriage\rreturn.img"), filepath.Join(dir, "carriage\rreturn.img")})
	for i, pair := range pairs {
		p, want := pair[0], pair[1]
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
		if string(got) != want {
			t.Errorf("powershell native round-trip of %q gave %q, want %q", p, string(got), want)
		}
	}
	// The quoted emission of every real path (files and both
	// trailing-separator dirs) still resolves to that path.
	real := []string{trailDir + sep, plainDir + sep}
	for _, n := range names {
		real = append(real, filepath.Join(dir, n))
	}
	for _, p := range real {
		script := "if (Test-Path -LiteralPath " + quotePowerShell(p) + ") { exit 0 } else { exit 1 }"
		if combined, err := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput(); err != nil {
			t.Errorf("Test-Path cannot resolve real path %q: %v\n%s", p, err, combined)
		}
	}
}
