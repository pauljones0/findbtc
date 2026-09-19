package detector

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Triage report. Raw detections answer "what bytes matched where"; the report
// answers "is there anything here worth pursuing?" It is built offline from
// saved -json output, so triage never needs a rescan.
//
// Privacy discipline matches the scanner: only type labels, offsets, counts,
// and carve paths leave this module. Detection descriptions are dropped and
// never copied into hits, text, or JSON.

// ReportHit is one deduplicated detection with its triage classification.
type ReportHit struct {
	Type       string `json:"type"`
	Needle     string `json:"needle"`
	Target     string `json:"target"`
	Offset     int64  `json:"offset"`
	MatchLen   int    `json:"match_length"`
	Confidence string `json:"confidence"` // high, medium, or low
	Encrypted  bool   `json:"encrypted"`
	CarvePath  string `json:"carve_path,omitempty"`
	FileName   string `json:"file_name,omitempty"`
}

// OffsetSpan is the lowest–highest hit offset within one target.
type OffsetSpan struct {
	Min int64 `json:"min"`
	Max int64 `json:"max"`
}

// Report is the full triage summary of a detection set.
type Report struct {
	Total         int                   `json:"total_detections"`
	Unique        int                   `json:"unique_detections"`
	Duplicates    int                   `json:"duplicates_merged"`
	Counts        map[string]int        `json:"counts_by_type"`
	EncryptedHits int                   `json:"encrypted_hits"`
	CrackReady    int                   `json:"crack_ready_hashes"`
	Salvaged      int                   `json:"salvaged"`
	Targets       []string              `json:"targets"`
	Spans         map[string]OffsetSpan `json:"spans_by_target"`
	Hits          []ReportHit           `json:"hits"`
	Playbook      []string              `json:"playbook"`
}

type walletClass struct {
	walletType string
	confidence string
	encrypted  bool
}

// classifyNeedle maps a detection label to a wallet type and confidence.
//
// Confidence rationale: checksum- or structure-validated hits (keys, seed
// phrases, keystores, descriptor markers, crypted_key/hdseed/keymeta,
// secrets-profile PEM/token shapes) are high — random data effectively
// never produces them. Distinctive but
// unvalidated legacy keys are medium: they appear in documentation and
// source (including this repo's own README), so prose can match. The bare
// wallet.dat filename is low for the same reason, and unknown labels stay
// low so future detectors fail safe.
func classifyNeedle(needle string) walletClass {
	switch {
	case needle == "crypted_key":
		return walletClass{"bitcoin-core-legacy", "high", true}
	case needle == "hdseed" || needle == "keymeta":
		return walletClass{"bitcoin-core-legacy", "high", false}
	case needle == "orderposnext" || needle == "addrIncoming" ||
		needle == "bestblock" || needle == "defaultkey" ||
		needle == "acentry":
		return walletClass{"bitcoin-core-legacy", "medium", false}
	case needle == "walletdescriptor":
		return walletClass{"bitcoin-core-descriptor", "high", false}
	case needle == "activeblock":
		return walletClass{"bitcoin-core-descriptor", "medium", false}
	case needle == "wallet.dat":
		return walletClass{"wallet-filename", "low", false}
	case strings.HasPrefix(needle, "bip39-"):
		if strings.Contains(needle, "near-miss") {
			return walletClass{"bip39-seed", "medium", false}
		}
		if strings.Contains(needle, "unordered") {
			return walletClass{"bip39-seed", "low", false}
		}
		return walletClass{"bip39-seed", "high", false}
	case needle == "wif" || needle == "wif-testnet":
		return walletClass{"private-key-wif", "high", false}
	case needle == "xprv" || needle == "tprv" ||
		needle == "yprv" || needle == "zprv" ||
		needle == "uprv" || needle == "vprv":
		return walletClass{"extended-private-key", "high", false}
	case needle == "xpub" || needle == "tpub" ||
		needle == "ypub" || needle == "zpub" ||
		needle == "upub" || needle == "vpub":
		return walletClass{"extended-public-key", "high", false}
	case needle == "eth-keystore":
		return walletClass{"ethereum-keystore", "high", true}
	case needle == "electrum-seed":
		return walletClass{"electrum-seed", "high", false}
	case needle == "electrum-file":
		return walletClass{"electrum-file", "high", false}
	case needle == "descriptor":
		return walletClass{"descriptor", "high", false}
	case needle == "slip39-20" || needle == "slip39-33":
		return walletClass{"slip39-share", "high", false}
	case needle == "open-chan-bucket" || needle == "closed-chan-bucket":
		return walletClass{"lightning-lnd", "medium", false}
	case needle == "channel.backup" || needle == "channel.db":
		return walletClass{"lightning-lnd", "low", false}
	case needle == "metamask-vault":
		return walletClass{"metamask-vault", "high", true}
	case needle == "pem-private-key":
		return walletClass{"pem-private-key", "high", false}
	case needle == "aws-access-key":
		return walletClass{"aws-access-key", "high", false}
	case needle == "github-token":
		return walletClass{"github-token", "high", false}
	default:
		return walletClass{"unknown", "low", false}
	}
}

// playbookOrder keeps next steps stable regardless of hit order.
var playbookOrder = []string{
	"bitcoin-core-legacy",
	"bitcoin-core-descriptor",
	"bip39-seed",
	"private-key-wif",
	"extended-private-key",
	"extended-public-key",
	"ethereum-keystore",
	"electrum-seed",
	"electrum-file",
	"descriptor",
	"slip39-share",
	"lightning-lnd",
	"metamask-vault",
	"pem-private-key",
	"aws-access-key",
	"github-token",
	"wallet-filename",
	"unknown",
}

var playbookSteps = map[string]string{
	"bitcoin-core-legacy":     "Bitcoin Core legacy traces: carve around the hits (-extract-dir on a different drive) and open a salvaged copy in Bitcoin Core on an offline machine.",
	"bitcoin-core-descriptor": "Descriptor-wallet traces: salvage the SQLite database from the carve and inspect it with sqlite3; descriptors list the wallet's addresses.",
	"bip39-seed":              "Seed-phrase-shaped hit: treat any carve as a live secret, move it to encrypted storage, and restore on an offline machine.",
	"private-key-wif":         "Private-key hit: handle the carve as funds — sweep to a fresh wallet from an offline machine, then discard the exposed key.",
	"extended-private-key":    "Extended private key: it controls a whole wallet — sweep to a fresh wallet from an offline machine.",
	"extended-public-key":     "Extended public key (watch-only): run `findbtc -watch carve.bin -watch-out addrs.csv` to derive its addresses locally, then check those addresses anywhere — never paste the key into a website (see docs/WATCH_ONLY.md).",
	"ethereum-keystore":       "Ethereum keystore: it imports into any Web3 wallet once you supply its password.",
	"electrum-seed":           "Electrum seed: restore it in Electrum on an offline machine (standard/segwit follows automatically); treat any carve as a live secret.",
	"electrum-file":           "Electrum wallet file: open a copy in Electrum on an offline machine; if it asks for a password, recovering that password is the remaining work.",
	"descriptor":              "Output descriptor with a valid checksum: import it into Bitcoin Core (importdescriptors) on an offline machine to watch its addresses.",
	"slip39-share":            "SLIP39 Shamir share: one share alone recovers nothing — gather the threshold number of shares, then combine them in a hardware wallet or compatible tool on an offline machine.",
	"lightning-lnd":           "Lightning (lnd) traces: recover with channel.backup plus the seed via lnd's recovery flow on an offline machine; database fragments alone hold no funds without the seed.",
	"metamask-vault":          "MetaMask vault (encrypted): it needs its password — run the offline vault decryptor once you have it.",
	"pem-private-key":         "Private-key block: treat any carve as a live secret — move it to encrypted storage, rotate the key, and purge it from the repo or image it leaked from.",
	"aws-access-key":          "AWS access key ID: revoke it in IAM unless you own it and it is still needed, then check CloudTrail for misuse between leak and revocation.",
	"github-token":            "GitHub token: revoke it at github.com/settings/tokens, audit what it touched, and rotate anything it could reach.",
	"wallet-filename":         "Only the wallet.dat name matched: a weak signal — look for nearby key hits before spending effort.",
	"unknown":                 "Unclassified hits: inspect the offsets manually.",
}

func buildPlaybook(counts map[string]int, encrypted, crackReady, salvaged int) []string {
	if len(counts) == 0 {
		return []string{"No wallet traces in this input — nothing to pursue."}
	}
	var steps []string
	for _, t := range playbookOrder {
		if counts[t] > 0 {
			steps = append(steps, playbookSteps[t])
		}
	}
	if encrypted > 0 {
		hitWord := "hits"
		if encrypted == 1 {
			hitWord = "hit"
		}
		note := fmt.Sprintf("Encrypted markers present (%d %s): the wallet needs its password — follow the password-recovery runbook instead of guessing on the scanned device.", encrypted, hitWord)
		steps = append([]string{note}, steps...)
	}
	if crackReady > 0 {
		note := fmt.Sprintf("%d crack-ready password hashes extracted (see `hashes` in hits.jsonl) — start recovery there; see docs/PASSWORD_RECOVERY.md.", crackReady)
		steps = append(steps, note)
	}
	if salvaged > 0 {
		note := fmt.Sprintf("%d carves stitched into database images (see `salvage` in hits.jsonl) — try opening the .salvage.db files.", salvaged)
		steps = append(steps, note)
	}
	return steps
}

// Summarize deduplicates detections, classifies them, and builds the triage
// report. Exact duplicates (same target, needle, offset) merge: they arise
// when JSONL from overlapping runs is concatenated.
func Summarize(dets []Detection) Report {
	rep := Report{
		Total:   len(dets),
		Counts:  map[string]int{},
		Targets: []string{},
		Spans:   map[string]OffsetSpan{},
		Hits:    []ReportHit{},
	}
	type dedupeKey struct {
		target string
		needle string
		offset int64
	}
	seen := map[dedupeKey]bool{}
	spans := map[string]*OffsetSpan{}
	targetSet := map[string]bool{}
	for _, d := range dets {
		k := dedupeKey{d.Target, d.Needle, d.Offset}
		if seen[k] {
			continue
		}
		seen[k] = true
		c := classifyNeedle(d.Needle)
		rep.Hits = append(rep.Hits, ReportHit{
			Type:       c.walletType,
			Needle:     d.Needle,
			Target:     d.Target,
			Offset:     d.Offset,
			MatchLen:   d.MatchLen,
			Confidence: c.confidence,
			Encrypted:  c.encrypted,
			CarvePath:  d.CarvePath,
			FileName:   d.FileName,
		})
		rep.Counts[c.walletType]++
		if c.encrypted {
			rep.EncryptedHits++
		}
		rep.CrackReady += len(d.Hashes)
		if d.Salvage != nil {
			rep.Salvaged++
		}
		targetSet[d.Target] = true
		sp, ok := spans[d.Target]
		if !ok {
			sp = &OffsetSpan{Min: d.Offset, Max: d.Offset}
			spans[d.Target] = sp
		} else {
			if d.Offset < sp.Min {
				sp.Min = d.Offset
			}
			if d.Offset > sp.Max {
				sp.Max = d.Offset
			}
		}
	}
	rep.Unique = len(rep.Hits)
	rep.Duplicates = rep.Total - rep.Unique
	sort.Slice(rep.Hits, func(i, j int) bool {
		if rep.Hits[i].Target != rep.Hits[j].Target {
			return rep.Hits[i].Target < rep.Hits[j].Target
		}
		return rep.Hits[i].Offset < rep.Hits[j].Offset
	})
	for t := range targetSet {
		rep.Targets = append(rep.Targets, t)
	}
	sort.Strings(rep.Targets)
	for t, sp := range spans {
		rep.Spans[t] = *sp
	}
	rep.Playbook = buildPlaybook(rep.Counts, rep.EncryptedHits, rep.CrackReady, rep.Salvaged)
	return rep
}

// maxTextHits caps the human-readable hit list; the full list is in -json.
const maxTextHits = 50

// Text renders the report for humans.
func (r Report) Text() string {
	var b strings.Builder
	if r.Unique == 0 {
		b.WriteString("Triage: no detections in this input — nothing to pursue.\n")
		return b.String()
	}
	targetWord := "targets"
	if len(r.Targets) == 1 {
		targetWord = "target"
	}
	dupeWord := fmt.Sprintf("%d duplicates merged", r.Duplicates)
	if r.Duplicates == 1 {
		dupeWord = "1 duplicate merged"
	}
	fmt.Fprintf(&b, "Triage: %d detections (%d unique, %s) across %d %s\n",
		r.Total, r.Unique, dupeWord, len(r.Targets), targetWord)
	types := make([]string, 0, len(r.Counts))
	for t := range r.Counts {
		types = append(types, t)
	}
	sort.Strings(types)
	parts := make([]string, 0, len(types))
	for _, t := range types {
		parts = append(parts, fmt.Sprintf("%s=%d", t, r.Counts[t]))
	}
	fmt.Fprintf(&b, "Types: %s\n", strings.Join(parts, ", "))
	if r.EncryptedHits > 0 {
		hitWord := "hits"
		if r.EncryptedHits == 1 {
			hitWord = "hit"
		}
		fmt.Fprintf(&b, "Encrypted markers: %d %s — password will be needed\n", r.EncryptedHits, hitWord)
	} else {
		b.WriteString("Encrypted markers: none\n")
	}
	if r.CrackReady > 0 {
		fmt.Fprintf(&b, "Crack-ready hashes: %d (see `hashes` in hits.jsonl)\n", r.CrackReady)
	}
	if r.Salvaged > 0 {
		fmt.Fprintf(&b, "Stitched databases: %d (see `salvage` in hits.jsonl)\n", r.Salvaged)
	}
	for _, t := range r.Targets {
		sp := r.Spans[t]
		fmt.Fprintf(&b, "Offsets %s: %d-%d\n", t, sp.Min, sp.Max)
	}
	b.WriteString("Hits:\n")
	shown := r.Hits
	more := 0
	if len(shown) > maxTextHits {
		more = len(shown) - maxTextHits
		shown = shown[:maxTextHits]
	}
	for _, h := range shown {
		carve := ""
		if h.CarvePath != "" {
			carve = " carve=" + h.CarvePath
		}
		name := ""
		if h.FileName != "" {
			name = " file=" + h.FileName
		}
		fmt.Fprintf(&b, "  [%s] %s (%s) %s @%d%s%s\n",
			h.Confidence, h.Type, h.Needle, h.Target, h.Offset, carve, name)
	}
	if more > 0 {
		fmt.Fprintf(&b, "  ... and %d more (see -json for the full list)\n", more)
	}
	b.WriteString("Next steps:\n")
	for i, s := range r.Playbook {
		fmt.Fprintf(&b, "  %d. %s\n", i+1, s)
	}
	b.WriteString("New here? Start with docs/WHAT_NEXT.md — what each hit type means and what to do next.\n")
	return b.String()
}

// ReadDetections parses -json scan output (one Detection per line), skipping
// blank lines. Failures name the offending line.
func ReadDetections(r io.Reader) ([]Detection, error) {
	var dets []Detection
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		var d Detection
		if err := json.Unmarshal([]byte(raw), &d); err != nil {
			return nil, fmt.Errorf("line %d: cannot parse detection: %w", line, err)
		}
		dets = append(dets, d)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("cannot read detections: %w", err)
	}
	return dets, nil
}
