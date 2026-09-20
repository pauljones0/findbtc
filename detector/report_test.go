package detector

import (
	"encoding/json"
	"strings"
	"testing"
)

func reportFixtureDetection(needle, target string, offset int64) Detection {
	return Detection{
		Description: "SECRETWORD marker must never reach the report",
		Needle:      needle,
		Offset:      offset,
		Target:      target,
		BlockOffset: offset,
		MatchLen:    len(needle),
	}
}

func TestClassifyNeedle(t *testing.T) {
	cases := map[string]walletClass{
		"crypted_key":        {"bitcoin-core-legacy", "high", true},
		"hdseed":             {"bitcoin-core-legacy", "high", false},
		"keymeta":            {"bitcoin-core-legacy", "high", false},
		"bestblock":          {"bitcoin-core-legacy", "medium", false},
		"defaultkey":         {"bitcoin-core-legacy", "medium", false},
		"orderposnext":       {"bitcoin-core-legacy", "medium", false},
		"addrIncoming":       {"bitcoin-core-legacy", "medium", false},
		"acentry":            {"bitcoin-core-legacy", "medium", false},
		"walletdescriptor":   {"bitcoin-core-descriptor", "high", false},
		"activeblock":        {"bitcoin-core-descriptor", "medium", false},
		"wallet.dat":         {"wallet-filename", "low", false},
		"bip39-12":           {"bip39-seed", "high", false},
		"bip39-24":           {"bip39-seed", "high", false},
		"bip39-12-near-miss": {"bip39-seed", "medium", false},
		"bip39-24-near-miss": {"bip39-seed", "medium", false},
		"bip39-unordered":    {"bip39-seed", "low", false},
		"wif":                {"private-key-wif", "high", false},
		"wif-testnet":        {"private-key-wif", "high", false},
		"xprv":               {"extended-private-key", "high", false},
		"tprv":               {"extended-private-key", "high", false},
		"yprv":               {"extended-private-key", "high", false},
		"zprv":               {"extended-private-key", "high", false},
		"uprv":               {"extended-private-key", "high", false},
		"vprv":               {"extended-private-key", "high", false},
		"xpub":               {"extended-public-key", "high", false},
		"tpub":               {"extended-public-key", "high", false},
		"ypub":               {"extended-public-key", "high", false},
		"zpub":               {"extended-public-key", "high", false},
		"upub":               {"extended-public-key", "high", false},
		"vpub":               {"extended-public-key", "high", false},
		"eth-keystore":       {"ethereum-keystore", "high", true},
		"electrum-seed":      {"electrum-seed", "high", false},
		"electrum-file":      {"electrum-file", "high", false},
		"descriptor":         {"descriptor", "high", false},
		"slip39-20":          {"slip39-share", "high", false},
		"slip39-33":          {"slip39-share", "high", false},
		"open-chan-bucket":   {"lightning-lnd", "medium", false},
		"closed-chan-bucket": {"lightning-lnd", "medium", false},
		"channel.backup":     {"lightning-lnd", "low", false},
		"channel.db":         {"lightning-lnd", "low", false},
		"metamask-vault":     {"metamask-vault", "high", true},
		"pem-private-key":    {"pem-private-key", "high", false},
		"aws-access-key":     {"aws-access-key", "high", false},
		"github-token":       {"github-token", "high", false},
		"something-new":      {"unknown", "low", false},
	}
	for needle, want := range cases {
		if got := classifyNeedle(needle); got != want {
			t.Errorf("classifyNeedle(%q) = %+v, want %+v", needle, got, want)
		}
	}
}

func TestSummarizeDedupesCountsAndOrders(t *testing.T) {
	dets := []Detection{
		reportFixtureDetection("bestblock", "/dev/sda", 9000),
		reportFixtureDetection("crypted_key", "/dev/sda", 1000),
		reportFixtureDetection("bestblock", "/dev/sda", 9000), // exact dupe
		reportFixtureDetection("bip39-12", "/dev/sdb", 50),
		reportFixtureDetection("eth-keystore", "/dev/sda", 5000),
		reportFixtureDetection("wallet.dat", "/dev/sdb", 70),
	}
	rep := Summarize(dets)
	if rep.Total != 6 || rep.Unique != 5 || rep.Duplicates != 1 {
		t.Fatalf("totals = %d/%d/%d, want 6/5/1", rep.Total, rep.Unique, rep.Duplicates)
	}
	wantCounts := map[string]int{
		"bitcoin-core-legacy": 2,
		"bip39-seed":          1,
		"ethereum-keystore":   1,
		"wallet-filename":     1,
	}
	if len(rep.Counts) != len(wantCounts) {
		t.Fatalf("counts = %v, want %v", rep.Counts, wantCounts)
	}
	for k, v := range wantCounts {
		if rep.Counts[k] != v {
			t.Fatalf("counts = %v, want %v", rep.Counts, wantCounts)
		}
	}
	if rep.EncryptedHits != 2 {
		t.Errorf("encrypted hits = %d, want 2 (crypted_key + keystore)", rep.EncryptedHits)
	}
	if len(rep.Targets) != 2 || rep.Targets[0] != "/dev/sda" || rep.Targets[1] != "/dev/sdb" {
		t.Errorf("targets = %v, want sorted [/dev/sda /dev/sdb]", rep.Targets)
	}
	if sp := rep.Spans["/dev/sda"]; sp.Min != 1000 || sp.Max != 9000 {
		t.Errorf("sda span = %+v, want {1000 9000}", sp)
	}
	// Hits sorted by target, then offset.
	wantOrder := []int64{1000, 5000, 9000, 50, 70}
	for i, want := range wantOrder {
		if rep.Hits[i].Offset != want {
			t.Fatalf("hit order offsets = %v, want %v",
				[]int64{rep.Hits[0].Offset, rep.Hits[1].Offset, rep.Hits[2].Offset, rep.Hits[3].Offset, rep.Hits[4].Offset}, wantOrder)
		}
	}
	if rep.Hits[0].Confidence != "high" || rep.Hits[0].Type != "bitcoin-core-legacy" {
		t.Errorf("first hit = %+v, want high bitcoin-core-legacy", rep.Hits[0])
	}
	foundPasswordNote := false
	for _, s := range rep.Playbook {
		if strings.Contains(s, "password") {
			foundPasswordNote = true
		}
	}
	if !foundPasswordNote {
		t.Errorf("playbook %v should flag the password requirement", rep.Playbook)
	}
}

func TestReportPointsAtWhatsNext(t *testing.T) {
	rep := Summarize([]Detection{reportFixtureDetection("bestblock", "/dev/sda", 10)})
	if !strings.Contains(rep.Text(), "docs/WHAT_NEXT.md") {
		t.Errorf("report text must point new owners at the what's-next guide:\n%s", rep.Text())
	}
}

func TestSummarizeEmpty(t *testing.T) {
	rep := Summarize(nil)
	if rep.Total != 0 || rep.Unique != 0 || rep.Duplicates != 0 {
		t.Errorf("empty totals = %d/%d/%d, want 0/0/0", rep.Total, rep.Unique, rep.Duplicates)
	}
	if len(rep.Playbook) != 1 || !strings.Contains(rep.Playbook[0], "nothing to pursue") {
		t.Errorf("empty playbook = %v", rep.Playbook)
	}
	if !strings.Contains(rep.Text(), "nothing to pursue") {
		t.Errorf("empty text:\n%s", rep.Text())
	}
}

func TestSummarizeEmptyNamesCoverage(t *testing.T) {
	rep := Summarize(nil)
	if !strings.Contains(rep.Text(), "nothing was scanned") {
		t.Errorf("empty text must name the nothing-scanned ambiguity:\n%s", rep.Text())
	}
	if rep.CoverageNote == "" || !strings.Contains(rep.CoverageNote, "nothing was scanned") {
		t.Errorf("empty report must carry a machine-readable coverage note: %+v", rep)
	}
	nonempty := Summarize([]Detection{reportFixtureDetection("bestblock", "/dev/sda", 10)})
	if nonempty.CoverageNote != "" {
		t.Errorf("non-empty report must not carry a coverage note: %q", nonempty.CoverageNote)
	}
}

func TestReportDropsDescriptions(t *testing.T) {
	d := reportFixtureDetection("wif", "/dev/sda", 10)
	d.Words = []string{"abandon", "about", "zoo"}
	rep := Summarize([]Detection{d})
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{"SECRETWORD", "description", "abandon", "about", "zoo", "words"} {
		if strings.Contains(string(raw), leaked) {
			t.Errorf("report JSON leaks %q:\n%s", leaked, raw)
		}
		if strings.Contains(rep.Text(), leaked) {
			t.Errorf("report text leaks %q:\n%s", leaked, rep.Text())
		}
	}
}

func TestReadDetections(t *testing.T) {
	in := "{\"description\":\"a\",\"needle\":\"wif\",\"offset\":1,\"target\":\"t\",\"block_offset\":0,\"match_length\":3}\n\n" +
		"{\"description\":\"b\",\"needle\":\"hdseed\",\"offset\":9,\"target\":\"t\",\"block_offset\":0,\"match_length\":6}\n"
	dets, err := ReadDetections(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(dets) != 2 || dets[0].Needle != "wif" || dets[1].Offset != 9 {
		t.Fatalf("parsed = %+v", dets)
	}
	_, err = ReadDetections(strings.NewReader("{}\nnot json\n"))
	if err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("bad input error = %v, want line 2 complaint", err)
	}
}

func TestReportTextCapsLongHitLists(t *testing.T) {
	var dets []Detection
	for i := 0; i < 70; i++ {
		dets = append(dets, reportFixtureDetection("bestblock", "/dev/sda", int64(i)))
	}
	text := Summarize(dets).Text()
	if !strings.Contains(text, "and 20 more") {
		t.Errorf("expected capped hit list, got:\n%s", text)
	}
}

func TestSummarizeCountsCrackReady(t *testing.T) {
	d := reportFixtureDetection("crypted_key", "/dev/sda", 10)
	d.Hashes = []CrackHash{{Format: "bitcoin-core-mkey",
		Hash: "$bitcoin$64$aa$16$bb$1$2$00$2$00", KDF: "pbkdf2-hmac-sha512"}}
	rep := Summarize([]Detection{d, reportFixtureDetection("bestblock", "/dev/sda", 20)})
	if rep.CrackReady != 1 {
		t.Errorf("crack-ready = %d, want 1", rep.CrackReady)
	}
	if joined := strings.Join(rep.Playbook, "\n"); !strings.Contains(joined, "PASSWORD_RECOVERY") {
		t.Errorf("playbook lacks recovery pointer:\n%s", joined)
	}
	if !strings.Contains(rep.Text(), "Crack-ready hashes: 1") {
		t.Errorf("text lacks crack line:\n%s", rep.Text())
	}
}

func TestSummarizeCountsSalvaged(t *testing.T) {
	d := reportFixtureDetection("bestblock", "/dev/sda", 10)
	d.Salvage = &SalvageInfo{Kind: "bdb", PageSize: 4096, Complete: true, Ordered: true, Verdict: SalvageValid}
	rep := Summarize([]Detection{d})
	if rep.Salvaged != 1 {
		t.Errorf("salvaged = %d, want 1", rep.Salvaged)
	}
	if joined := strings.Join(rep.Playbook, "\n"); !strings.Contains(joined, ".salvage.db") {
		t.Errorf("playbook lacks salvage pointer:\n%s", joined)
	}
	if !strings.Contains(rep.Text(), "Stitched databases: 1") {
		t.Errorf("text lacks salvage line:\n%s", rep.Text())
	}
}

func TestSummarizeCountsSuspectSalvage(t *testing.T) {
	ok := reportFixtureDetection("bestblock", "/dev/sda", 10)
	ok.Salvage = &SalvageInfo{Kind: "sqlite", Complete: true, Ordered: true, Verdict: SalvageValid}
	bad := reportFixtureDetection("bestblock", "/dev/sda", 20)
	bad.Salvage = &SalvageInfo{Kind: "bdb", Complete: false, Ordered: true,
		Verdict: SalvageSuspect, Reasons: []string{"meta last_pgno 21, image holds 3 pages"}}
	legacy := reportFixtureDetection("bestblock", "/dev/sda", 30)
	legacy.Salvage = &SalvageInfo{Kind: "bdb", Complete: true, Ordered: true}
	rep := Summarize([]Detection{ok, bad, legacy})
	if rep.Salvaged != 3 || rep.SalvagedSuspect != 2 {
		t.Errorf("salvaged = %d/%d suspect, want 3/2 (verdict-less fails closed)",
			rep.Salvaged, rep.SalvagedSuspect)
	}
	if !strings.Contains(rep.Text(), "Stitched databases: 3") || !strings.Contains(rep.Text(), "[2 suspect]") {
		t.Errorf("text lacks suspect split:\n%s", rep.Text())
	}
	if joined := strings.Join(rep.Playbook, "\n"); !strings.Contains(joined, "treat those as leads") {
		t.Errorf("playbook lacks suspect guidance:\n%s", joined)
	}
}

func TestSummarizeWatchPlaybook(t *testing.T) {
	rep := Summarize([]Detection{reportFixtureDetection("zpub", "/dev/sda", 10)})
	joined := strings.Join(rep.Playbook, "\n")
	if !strings.Contains(joined, "-watch") || !strings.Contains(joined, "WATCH_ONLY") {
		t.Errorf("playbook lacks watch-only pointer:\n%s", joined)
	}
}

func TestSummarizeGoal6Playbook(t *testing.T) {
	dets := []Detection{
		reportFixtureDetection("electrum-seed", "/dev/sda", 10),
		reportFixtureDetection("electrum-file", "/dev/sda", 20),
		reportFixtureDetection("descriptor", "/dev/sda", 30),
		reportFixtureDetection("slip39-20", "/dev/sda", 40),
		reportFixtureDetection("open-chan-bucket", "/dev/sda", 50),
		reportFixtureDetection("channel.backup", "/dev/sda", 60),
		reportFixtureDetection("metamask-vault", "/dev/sda", 70),
	}
	rep := Summarize(dets)
	joined := strings.Join(rep.Playbook, "\n")
	for _, want := range []string{"Electrum seed", "Electrum wallet file", "Output descriptor",
		"SLIP39 Shamir share", "Lightning (lnd)", "MetaMask vault"} {
		if !strings.Contains(joined, want) {
			t.Errorf("playbook lacks %q:\n%s", want, joined)
		}
	}
	if rep.EncryptedHits != 1 {
		t.Errorf("encrypted hits = %d, want 1 (the vault)", rep.EncryptedHits)
	}
}

func TestSummarizeSecretsPlaybook(t *testing.T) {
	dets := []Detection{
		reportFixtureDetection("pem-private-key", "/repo/id_rsa", 10),
		reportFixtureDetection("aws-access-key", "/repo/env", 20),
		reportFixtureDetection("github-token", "/repo/env", 30),
	}
	rep := Summarize(dets)
	joined := strings.Join(rep.Playbook, "\n")
	for _, want := range []string{"Private-key block", "AWS access key", "GitHub token"} {
		if !strings.Contains(joined, want) {
			t.Errorf("playbook lacks %q:\n%s", want, joined)
		}
	}
	if rep.EncryptedHits != 0 {
		t.Errorf("encrypted hits = %d, want 0 (secrets are not wallets)", rep.EncryptedHits)
	}
}

// Report text groups hits by target (Goal 38): one sorted section
// per image with its full hit count and offset span, hits beneath
// their own header in offset order.
func TestReportTextGroupsByTarget(t *testing.T) {
	dets := []Detection{
		reportFixtureDetection("bestblock", "b.img", 300),
		reportFixtureDetection("wif", "a.img", 50),
		reportFixtureDetection("bestblock", "b.img", 100),
	}
	text := Summarize(dets).Text()
	aHead := strings.Index(text, "a.img (1 hit, offsets 50-50)")
	bHead := strings.Index(text, "b.img (2 hits, offsets 100-300)")
	if aHead < 0 || bHead < 0 {
		t.Fatalf("want per-target headers with counts and spans, got:\n%s", text)
	}
	if aHead > bHead {
		t.Errorf("target sections must sort by target, got:\n%s", text)
	}
	// Bracketed anchors skip the Types: header, which names the
	// same types before the grouped sections.
	wif := strings.Index(text, "[high] private-key-wif")
	best := strings.Index(text, "[medium] bitcoin-core-legacy")
	if wif < 0 || best < 0 {
		t.Fatalf("hits missing from grouped text, got:\n%s", text)
	}
	if !(aHead < wif && wif < bHead && bHead < best) {
		t.Errorf("each hit must sit under its own target header, got:\n%s", text)
	}
	for _, h := range strings.Split(text, "\n") {
		if strings.HasPrefix(h, "    [") && (strings.Contains(h, "a.img") || strings.Contains(h, "b.img")) {
			t.Errorf("grouped hit lines must not repeat the target: %q", h)
		}
	}
}
