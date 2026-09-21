package detector

// Guided-mode routing tests (Goal 27): each target shape routes to
// its documented-best command, with reasons. One test also proves
// Advise never scans: a needle-bearing target yields advice only,
// never a detection.

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

// Follow-up routing (Goal 43): bounded first-kilobyte magic sends
// containers, wallet copies, and key files to their documented
// mode; everything ambiguous keeps the raw default.

// EWF v1 images scan as today — only the reason changes, to name
// the sniffed magic.
func TestAdviseEWFImageScansAsToday(t *testing.T) {
	synth := append(bytes.Clone(ewfSignature), make([]byte, 2040)...)
	synthPath := filepath.Join(t.TempDir(), "synth.E01")
	if err := os.WriteFile(synthPath, synth, 0644); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"synthetic": synthPath,
		"real E01":  "testdata/ewf-real.E01",
		"real S01":  "testdata/ewf-real.S01",
	} {
		ad, err := Advise(path)
		if err != nil {
			t.Fatal(err)
		}
		if ad.Command != "findbtc "+path {
			t.Errorf("%s: command %q, want a scan of the image itself", name, ad.Command)
		}
		if joined := strings.Join(ad.Reasons, "; "); !strings.Contains(joined, "EnCase EWF magic") {
			t.Errorf("%s: reasons %q must name the sniffed magic", name, joined)
		}
	}
}

// EWF2 has no findbtc path: advice carries the libewf conversion
// pointer with no command, never a scan that would refuse.
func TestAdviseEWF2PointsAtLibewf(t *testing.T) {
	synth := append(bytes.Clone(ewf2Signature), make([]byte, 2040)...)
	synthPath := filepath.Join(t.TempDir(), "synth.Ex01")
	if err := os.WriteFile(synthPath, synth, 0644); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"synthetic": synthPath,
		"real Ex01": "testdata/ewf-real.Ex01",
	} {
		ad, err := Advise(path)
		if err != nil {
			t.Fatal(err)
		}
		if ad.Command != "" {
			t.Errorf("%s: command %q, want none (nothing runs EWF2)", name, ad.Command)
		}
		joined := strings.Join(ad.Reasons, "; ")
		for _, want := range []string{"EWF2", "libewf", "ewfexport"} {
			if !strings.Contains(joined, want) {
				t.Errorf("%s: reasons %q must name %s", name, joined, want)
			}
		}
	}
}

// synthMKeyValue builds a structural CMasterKey value (fixed
// synthetic bytes — FindMasterKeys checks layout, not crypto).
func synthMKeyValue() []byte {
	v := []byte{mkeyCryptedLen}
	ct := make([]byte, mkeyCryptedLen)
	for i := range ct {
		ct[i] = byte(i*3 + 1)
	}
	v = append(v, ct...)
	v = append(v, mkeySaltLen, 1, 2, 3, 4, 5, 6, 7, 8)
	var tmp [8]byte
	binary.LittleEndian.PutUint32(tmp[0:4], 0)
	binary.LittleEndian.PutUint32(tmp[4:8], 50000)
	return append(v, tmp[:]...)
}

func TestAdviseWalletCopyRoutesToHashes(t *testing.T) {
	dir := t.TempDir()
	mkeyPath := filepath.Join(dir, "wallet-copy.bin")
	pad := bytes.Repeat([]byte("frag-"), 40)
	blob := append(append(bytes.Clone(pad), synthMKeyValue()...), pad...)
	if err := os.WriteFile(mkeyPath, blob, 0644); err != nil {
		t.Fatal(err)
	}
	keystorePath := filepath.Join(dir, "wallet.json")
	if err := os.WriteFile(keystorePath, []byte(keystoreScryptJSON), 0644); err != nil {
		t.Fatal(err)
	}
	capitalPath := filepath.Join(dir, "legacy.json")
	if err := os.WriteFile(capitalPath, []byte(keystorePBKDF2JSON), 0644); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		path string
		want string
	}{
		"mkey record":        {mkeyPath, "mkey record at offset 200"},
		"keystore":           {keystorePath, "complete Ethereum keystore object at offset 0"},
		"capitalized Crypto": {capitalPath, "complete Ethereum keystore object at offset 0"},
	}
	for name, tc := range cases {
		ad, err := Advise(tc.path)
		if err != nil {
			t.Fatal(err)
		}
		if ad.Command != "findbtc -hashes "+tc.path {
			t.Errorf("%s: command %q, want findbtc -hashes", name, ad.Command)
		}
		if joined := strings.Join(ad.Reasons, "; "); !strings.Contains(joined, tc.want) {
			t.Errorf("%s: reasons %q must name %s", name, joined, tc.want)
		}
	}
}

func TestAdviseKeysFileRoutesToWatch(t *testing.T) {
	handoff := "# findbtc -complete handoff: watch-only account keys.\n" +
		"# phrases never land in this file.\n" +
		bip44MainXPub + "\n" + bip84MainZPub + "\n"
	path := filepath.Join(t.TempDir(), "keys.txt")
	if err := os.WriteFile(path, []byte(handoff), 0644); err != nil {
		t.Fatal(err)
	}
	ad, err := Advise(path)
	if err != nil {
		t.Fatal(err)
	}
	if ad.Command != "findbtc -watch "+path {
		t.Errorf("command %q, want findbtc -watch", ad.Command)
	}
	joined := strings.Join(ad.Reasons, "; ")
	if !strings.Contains(joined, "2 checksum-valid extended public keys (xpub+zpub)") {
		t.Errorf("reasons %q must name the count and key versions", joined)
	}
	text := ad.Command + "\n" + joined
	if strings.Contains(text, bip44MainXPub) || strings.Contains(text, bip84MainZPub) {
		t.Errorf("advice must not echo the keys:\n%s", text)
	}
}

// The sniff reads the first kilobyte only: decisive evidence past
// the bound still routes raw.
func TestAdviseFirstKilobyteBound(t *testing.T) {
	dir := t.TempDir()
	pad := make([]byte, 2000)
	cases := map[string][]byte{
		"mkey past 1KB":     append(bytes.Clone(pad), synthMKeyValue()...),
		"keystore past 1KB": append(bytes.Clone(pad), keystoreScryptJSON...),
		"xpub past 1KB":     append(bytes.Clone(pad), bip44MainXPub...),
	}
	for name, blob := range cases {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".bin")
		if err := os.WriteFile(path, blob, 0644); err != nil {
			t.Fatal(err)
		}
		ad, err := Advise(path)
		if err != nil {
			t.Fatal(err)
		}
		if ad.Command != "findbtc "+path {
			t.Errorf("%s: command %q, want the raw default", name, ad.Command)
		}
	}
}

// Ambiguous input keeps the raw default: false routing strands a
// scan-worthy target worse than raw does.
func TestAdviseAmbiguousStaysRaw(t *testing.T) {
	dir := t.TempDir()
	rng := rand.New(rand.NewSource(7))
	noise := make([]byte, 4096)
	if _, err := rng.Read(noise); err != nil {
		t.Fatal(err)
	}
	prose := []byte("Field notes, Tuesday: the drive spins up but the " +
		"partition table looks wrong. Owner says the backup lived on a USB stick, " +
		"maybe FAT, maybe exFAT — will image before anything else.\n")
	truncated := []byte(`{"address":"de0b295669a9fd93d5f28d9ec85e40f4cb697bae",` +
		`"crypto":{"cipher":"aes-128-ctr","ciphertext":"ab`)
	badAddr := []byte(`{"address":"not-an-address",` +
		`"crypto":{"cipher":"aes-128-ctr","ciphertext":"abcd","kdf":"scrypt"}}`)
	// Published BIP32 test-vector master private key, not wallet
	// material: -watch would refuse it, so advise must not route it.
	privOnly := []byte("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi\n")
	looseEVF2 := []byte("EVF2dummyheader-not-the-real-8-byte-magic")
	cases := map[string][]byte{
		"random":             noise,
		"prose":              prose,
		"truncated keystore": truncated,
		"bad-address JSON":   badAddr,
		"private-only keys":  privOnly,
		"loose EVF2 prefix":  looseEVF2,
	}
	for name, blob := range cases {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".bin")
		if err := os.WriteFile(path, blob, 0644); err != nil {
			t.Fatal(err)
		}
		ad, err := Advise(path)
		if err != nil {
			t.Fatal(err)
		}
		if ad.Command != "findbtc "+path {
			t.Errorf("%s: command %q, want the raw default", name, ad.Command)
		}
		joined := strings.Join(ad.Reasons, "; ")
		if !strings.Contains(joined, "no partition table or filesystem") {
			t.Errorf("%s: reasons %q must explain the fallback", name, joined)
		}
		if strings.Contains(joined, "-hashes") || strings.Contains(joined, "-watch") || strings.Contains(joined, "EWF") {
			t.Errorf("%s: reasons %q must not name a follow-up", name, joined)
		}
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

// Quoting forms, hand-verified against shell manuals (not against
// each other): Unix single-quotes with '-escaping, PowerShell
// single-quotes with ”-doubling. The real-shell round-trip tests
// below are the proof; this table pins the documented form.
func TestShellQuoteForms(t *testing.T) {
	unix := map[string]string{
		`/tmp/plain.img`:      `/tmp/plain.img`,
		`/tmp/my dir/img.E01`: `'/tmp/my dir/img.E01'`,
		`/tmp/$price/x`:       `'/tmp/$price/x'`,
		"/tmp/o'clock/x":      "'" + `/tmp/o` + `'\''` + `clock/x'`,
		"/tmp/back\\slash/x":  `'/tmp/back\slash/x'`,
		"/tmp/a`b`/x":         "'/tmp/a`b`/x'",
		`/tmp/semi;colon/x`:   `'/tmp/semi;colon/x'`,
		`/tmp/star*/q?.bin`:   `'/tmp/star*/q?.bin'`,
		`/tmp/paren(a)/[b]/x`: `'/tmp/paren(a)/[b]/x'`,
		`/tmp/say"hi"/x`:      `'/tmp/say"hi"/x'`,
		`/tmp/bang!hist/x`:    `'/tmp/bang!hist/x'`,
		`/tmp/tilde~/user/x`:  `'/tmp/tilde~/user/x'`,
		`/tmp/amp&amp/x`:      `'/tmp/amp&amp/x'`,
		`/tmp/pipe|lt<gt>/x`:  `'/tmp/pipe|lt<gt>/x'`,
		`/tmp/hash#at@eq=/x`:  `'/tmp/hash#at@eq=/x'`,
		`/tmp/tab	sepx`:       "'/tmp/tab\tsepx'",
		// A newline is a command separator, so it must trigger
		// quoting (single-quoted LF is literal in sh, bash, zsh,
		// fish); a bare CR round-trips and stays unquoted.
		"/tmp/line\nbreak.img":      "'/tmp/line\nbreak.img'",
		"/tmp/carriage\rreturn.img": "/tmp/carriage\rreturn.img",
		"/tmp/a'b\nc$d/x":           "'" + `/tmp/a` + `'\''` + "b\nc$d/x'",
		`C:\notwindows\plain`:       `'C:\notwindows\plain'`,
	}
	for in, want := range unix {
		if got := quoteUnix(in); got != want {
			t.Errorf("quoteUnix(%q) = %q, want %q", in, got, want)
		}
	}
	windows := map[string]string{
		`C:\plain\path.img`:        `C:\plain\path.img`,
		`C:\my dir\img.E01`:        `'C:\my dir\img.E01'`,
		`C:\trailing\slash\`:       `C:\trailing\slash`,
		`C:\trailing spaced\`:      `'C:\trailing spaced'`,
		`C:\`:                      `C:\`,
		`\\srv\share\`:             `\\srv\share`,
		`\\\\`:                     `''`,
		"C:\\line\nbreak.img":      "\"C:\\line`nbreak.img\"",
		"C:\\carriage\rreturn.img": "\"C:\\carriage`rreturn.img\"",
		"C:\\a$b`c\nd\\x":          "\"C:\\a`$b``c`nd\\x\"",
		`C:\dollar$dir\x`:          `'C:\dollar$dir\x'`,
		`C:\backtick` + "`" + `x`:  `'C:\backtick` + "`" + `x'`,
		`C:\pct%100\x`:             `'C:\pct%100\x'`,
		`C:\amp&amp\x`:             `'C:\amp&amp\x'`,
		`C:\semi;scomma,y\x`:       `'C:\semi;scomma,y\x'`,
		`C:\paren(a)\[b\]\x`:       `'C:\paren(a)\[b\]\x'`,
		`C:\caret^tick\x`:          `'C:\caret^tick\x'`,
		`C:\hash#at@bang!x`:        `'C:\hash#at@bang!x'`,
		`C:\star*\q?\x`:            `'C:\star*\q?\x'`,
		`C:\brace{a}\pipe|x`:       `'C:\brace{a}\pipe|x'`,
		`C:\squote'o\x`:            `'C:\squote''o\x'`,
		`C:\eq=plus+\x`:            `'C:\eq=plus+\x'`,
		`C:\say"hi"\x`:             `'C:\say"hi"\x'`,
		`\\srv\share\img.E01`:      `\\srv\share\img.E01`,
		`\\srv\spaced share\x`:     `'\\srv\spaced share\x'`,
		``:                         `''`,
	}
	for in, want := range windows {
		if got := quotePowerShell(in); got != want {
			t.Errorf("quotePowerShell(%q) = %q, want %q", in, got, want)
		}
	}
	// shellQuote dispatches on the build platform.
	if runtime.GOOS == "windows" {
		if got := shellQuote(`C:\x`); got != `C:\x` {
			t.Errorf("shellQuote dispatches wrong: %q", got)
		}
	} else if got := shellQuote(`/x`); got != `/x` {
		t.Errorf("shellQuote dispatches wrong: %q", got)
	}
}

// Unix paste proof: every quoted nasty path round-trips through
// each available real shell byte-identical, and quoted names of
// real on-disk files (including an LF name) resolve with test -e.
// The shells are the oracle; nothing here mirrors quoteUnix.
func TestShellQuoteUnixRoundTrip(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix round-trip; unix only")
	}
	var shells []string
	for _, name := range []string{"sh", "bash", "zsh"} {
		if path, err := exec.LookPath(name); err == nil {
			shells = append(shells, path)
		}
	}
	if len(shells) == 0 {
		t.Skip("no unix shell available")
	}
	paths := []string{
		"/tmp/my dir/img.E01",
		"/tmp/$price/`tick`/x",
		"/tmp/o'clock/say\"hi\"/x",
		"/tmp/back\\slash/x",
		"/tmp/semi;colon/amp&amp/pipe|x",
		"/tmp/star*/q?.bin",
		"/tmp/paren(a)/[b]/{c}/x",
		"/tmp/bang!hist/tilde~/hash#/x",
		"/tmp/tab\tsep/x",
		"/tmp/line\nbreak.img",
		"/tmp/a'b\nc$d/x",
		"/tmp/carriage\rreturn.img",
		"/tmp/plain.img",
	}
	for _, sh := range shells {
		for _, p := range paths {
			cmd := exec.Command(sh, "-c", "printf '%s' "+quoteUnix(p))
			var out bytes.Buffer
			cmd.Stdout = &out
			if err := cmd.Run(); err != nil {
				t.Fatalf("%s round-trip of %q failed: %v", sh, p, err)
			}
			if out.String() != p {
				t.Errorf("%s round-trip of %q gave %q", sh, p, out.String())
			}
		}
	}
	// Real files: the shell must resolve each quoted name to the
	// file created under exactly that name.
	dir := t.TempDir()
	names := []string{
		"spaced name.img",
		"dollar$literal.img",
		"o'clock.img",
		"back`tick`.img",
		"line\nbreak.img",
		"tab\tsep.img",
		"star*.img",
		"semi;colon.img",
		"plain.img",
	}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	for _, sh := range shells {
		for _, n := range names {
			p := filepath.Join(dir, n)
			if out, err := exec.Command(sh, "-c", "test -e "+quoteUnix(p)).CombinedOutput(); err != nil {
				t.Errorf("%s cannot resolve real file %q: %v\n%s", sh, p, err, out)
			}
			cmd := exec.Command(sh, "-c", "printf '%s' "+quoteUnix(p))
			var out bytes.Buffer
			cmd.Stdout = &out
			if err := cmd.Run(); err != nil {
				t.Fatalf("%s round-trip of real file %q failed: %v", sh, p, err)
			}
			if out.String() != p {
				t.Errorf("%s round-trip of real file %q gave %q", sh, p, out.String())
			}
		}
	}
}
