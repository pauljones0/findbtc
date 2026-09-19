package detector

// Salvage validation tests (Goal 26): verdict unit coverage plus
// oracle agreement — every salvaged image's verdict must match what
// the real database tools say (SQLite quick_check via python3,
// BDB via db_verify), on both the valid and suspect sides.

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// shuffleSQLiteWallet replays the shuffled-pages salvage baseline.
func shuffleSQLiteWallet(t *testing.T) *SalvageResult {
	t.Helper()
	raw := readSQLiteWallet(t)
	var buf []byte
	buf = append(buf, bytes.Repeat([]byte{0}, 100)...)
	for _, p := range []int{2, 0, 4, 1, 3} {
		buf = append(buf, raw[p*4096:(p+1)*4096]...)
		buf = append(buf, bytes.Repeat([]byte{0}, 500)...)
	}
	r := Salvage(buf, 0)
	if r == nil {
		t.Fatal("no salvage result")
	}
	return r
}

// shuffleSQLiteWalletLed shuffles with page 1 first: magic, count,
// and per-page checks all pass, so only the order check can convict.
func shuffleSQLiteWalletLed(t *testing.T) *SalvageResult {
	t.Helper()
	raw := readSQLiteWallet(t)
	var buf []byte
	buf = append(buf, bytes.Repeat([]byte{0}, 100)...)
	for _, p := range []int{0, 3, 1, 4, 2} {
		buf = append(buf, raw[p*4096:(p+1)*4096]...)
		buf = append(buf, bytes.Repeat([]byte{0}, 500)...)
	}
	r := Salvage(buf, 0)
	if r == nil {
		t.Fatal("no salvage result")
	}
	return r
}

// completeBDBInfo mirrors a perfect scan: every page present in file
// order as one run. The validator recomputes completeness from the
// image; the info carries the assembly shape.
func completeBDBInfo(image []byte, pageSize int) SalvageInfo {
	info := SalvageInfo{Kind: "bdb", PageSize: pageSize, Complete: true, Ordered: true}
	for o := 0; o+pageSize <= len(image); o += pageSize {
		kind := "bdb-page"
		if o == 0 {
			kind = "bdb-meta"
		}
		info.Pages = append(info.Pages, SalvagePage{Offset: int64(o), Size: pageSize, Kind: kind})
	}
	info.Runs = []SalvageRun{{StartOffset: 0, Pages: len(info.Pages)}}
	return info
}

func TestValidateSalvageVerdicts(t *testing.T) {
	raw := readSQLiteWallet(t)
	if r := Salvage(raw, 500); r == nil {
		t.Fatal("intact sqlite: no salvage")
	} else if r.Info.Verdict != SalvageValid || len(r.Info.Reasons) != 0 {
		t.Errorf("intact sqlite: verdict=%q reasons=%v, want valid", r.Info.Verdict, r.Info.Reasons)
	}
	if r := shuffleSQLiteWallet(t); r.Info.Verdict != SalvageSuspect {
		t.Errorf("shuffled sqlite: verdict=%q, want suspect", r.Info.Verdict)
	}
	// Page-1-first shuffle: every byte-level check passes, yet the
	// image cannot open — only the provenance order check catches it.
	led := shuffleSQLiteWalletLed(t)
	if led.Info.Verdict != SalvageSuspect {
		t.Errorf("led shuffle: verdict=%q, want suspect", led.Info.Verdict)
	} else if joined := strings.Join(led.Info.Reasons, "; "); !strings.Contains(joined, "runs") {
		t.Errorf("led shuffle reasons %q must cite page order", joined)
	}
	noHeader := Salvage(raw[4096:], 0)
	if noHeader == nil {
		t.Fatal("headerless sqlite: no salvage")
	}
	if noHeader.Info.Verdict != SalvageSuspect {
		t.Errorf("headerless sqlite: verdict=%q, want suspect", noHeader.Info.Verdict)
	}
	trunc := Salvage(raw[:3*4096], 0)
	if trunc == nil {
		t.Fatal("truncated sqlite: no salvage")
	}
	if trunc.Info.Verdict != SalvageSuspect {
		t.Errorf("truncated sqlite: verdict=%q, want suspect", trunc.Info.Verdict)
	} else if joined := strings.Join(trunc.Info.Reasons, "; "); !strings.Contains(joined, "header says 5") {
		t.Errorf("truncated sqlite reasons %q must cite the count", joined)
	}

	wallet, err := os.ReadFile("testdata/test_wallet.dat")
	if err != nil {
		t.Fatal(err)
	}
	if v, reasons := ValidateSalvage(completeBDBInfo(wallet, 4096), wallet); v != SalvageValid {
		t.Errorf("intact wallet: verdict=%q reasons=%v, want valid", v, reasons)
	}
	if r := Salvage(wallet, 0); r == nil {
		t.Fatal("wallet salvage: no result")
	} else if r.Info.Verdict != SalvageSuspect {
		t.Errorf("wallet salvage (2 of 22 pages): verdict=%q, want suspect", r.Info.Verdict)
	}
	synth := buildBDB(t, 1024, 6)
	if v, reasons := ValidateSalvage(completeBDBInfo(synth, 1024), synth); v != SalvageSuspect {
		t.Errorf("synthetic BDB: verdict=%q, want suspect (filler is not a database)", v)
	} else if joined := strings.Join(reasons, "; "); !strings.Contains(joined, "last_pgno") {
		t.Errorf("synthetic BDB reasons %q must cite last_pgno", joined)
	}
	gapped := bytes.Clone(synth)
	for i := 3 * 1024; i < 4*1024; i++ {
		gapped[i] = 0
	}
	if v, _ := ValidateSalvage(completeBDBInfo(gapped, 1024), gapped); v != SalvageSuspect {
		t.Error("zero-gapped BDB accepted as valid")
	}
	if v, reasons := ValidateSalvage(SalvageInfo{Kind: "bdb"}, nil); v != SalvageSuspect || len(reasons) == 0 {
		t.Error("empty image must be suspect with reasons")
	}
	if v, _ := ValidateSalvage(SalvageInfo{Kind: "mdb"}, []byte{1, 2}); v != SalvageSuspect {
		t.Error("unknown kind must be suspect")
	}
}

// sqliteOracle runs a real SQLite quick_check via python3 (present on
// every CI runner): "ok" means the image opens clean.
func sqliteOracle(t *testing.T, path string) string {
	t.Helper()
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("needs python3 for the SQLite oracle")
	}
	script := "import sqlite3, sys\n" +
		"try:\n" +
		"    c = sqlite3.connect('file:' + sys.argv[1] + '?mode=ro', uri=True)\n" +
		"    r = c.execute('PRAGMA quick_check').fetchall()\n" +
		"    print('ok' if r == [('ok',)] else 'corrupt')\n" +
		"except Exception:\n" +
		"    print('open-fail')\n"
	scriptPath := filepath.Join(t.TempDir(), "quickcheck.py")
	if err := os.WriteFile(scriptPath, []byte(script), 0644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(py, scriptPath, path).CombinedOutput()
	if err != nil {
		t.Fatalf("oracle failed: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestSalvageValidatorOracleSQLite(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("needs python3 for the SQLite oracle")
	}
	raw := readSQLiteWallet(t)
	cases := []struct {
		name  string
		image func() *SalvageResult
	}{
		{"intact", func() *SalvageResult { return Salvage(bytes.Clone(raw), 0) }},
		{"shuffled", func() *SalvageResult { return shuffleSQLiteWallet(t) }},
		{"led-shuffled", func() *SalvageResult { return shuffleSQLiteWalletLed(t) }},
		{"truncated", func() *SalvageResult { return Salvage(bytes.Clone(raw[:3*4096]), 0) }},
		{"two-page", func() *SalvageResult { return Salvage(bytes.Clone(raw[:2*4096]), 0) }},
	}
	for _, c := range cases {
		r := c.image()
		if r == nil {
			t.Fatalf("%s: no salvage result", c.name)
		}
		path := filepath.Join(t.TempDir(), c.name+".db")
		if err := os.WriteFile(path, r.Image, 0644); err != nil {
			t.Fatal(err)
		}
		oracle := sqliteOracle(t, path)
		valid := r.Info.Verdict == SalvageValid
		if valid != (oracle == "ok") {
			t.Errorf("%s: verdict=%q but oracle says %s (reasons: %v)",
				c.name, r.Info.Verdict, oracle, r.Info.Reasons)
		} else {
			t.Logf("%s: verdict=%q agrees with oracle (%s)", c.name, r.Info.Verdict, oracle)
		}
	}
}

// bdbOraclePath finds db_verify (or the versioned Debian name).
func bdbOraclePath(t *testing.T) string {
	t.Helper()
	for _, tool := range []string{"db_verify", "db5.3_verify", "db5.1_verify", "db4.8_verify"} {
		if p, err := exec.LookPath(tool); err == nil {
			return p
		}
	}
	t.Skip("needs db_verify (db5.3-util on Debian) for the BDB oracle")
	return ""
}

func TestSalvageValidatorOracleBDB(t *testing.T) {
	verify := bdbOraclePath(t)
	wallet, err := os.ReadFile("testdata/test_wallet.dat")
	if err != nil {
		t.Fatal(err)
	}
	synth := buildBDB(t, 1024, 6)
	trunc := bytes.Clone(wallet[:10*4096])
	zeroed := bytes.Clone(wallet)
	for i := 5 * 4096; i < 6*4096; i++ {
		zeroed[i] = 0
	}
	type oracleCase struct {
		name      string
		info      SalvageInfo
		image     []byte
		fromSalv  bool // image+info come from Salvage, not hand-built
		salvInput []byte
	}
	cases := []oracleCase{
		{name: "intact", info: completeBDBInfo(wallet, 4096), image: wallet},
		{name: "synthetic", info: completeBDBInfo(synth, 1024), image: synth},
		{name: "truncated", info: completeBDBInfo(trunc, 4096), image: trunc},
		{name: "zeroed-page", info: completeBDBInfo(zeroed, 4096), image: zeroed},
		{name: "salvaged-wallet", fromSalv: true, salvInput: bytes.Clone(wallet)},
		{name: "salvaged-synth", fromSalv: true, salvInput: bytes.Clone(synth)},
	}
	for _, c := range cases {
		info, image := c.info, c.image
		if c.fromSalv {
			r := Salvage(c.salvInput, 0)
			if r == nil {
				t.Fatalf("%s: no salvage result", c.name)
			}
			info, image = r.Info, r.Image
		}
		verdict, reasons := ValidateSalvage(info, image)
		path := filepath.Join(t.TempDir(), c.name+".db")
		if err := os.WriteFile(path, image, 0644); err != nil {
			t.Fatal(err)
		}
		err := exec.Command(verify, path).Run()
		oracleOK := err == nil
		if valid := verdict == SalvageValid; valid != oracleOK {
			t.Errorf("%s: verdict=%q reasons=%v but db_verify exit=%v", c.name, verdict, reasons, err)
		} else {
			t.Logf("%s: verdict=%q agrees with db_verify (ok=%v)", c.name, verdict, oracleOK)
		}
	}
}
