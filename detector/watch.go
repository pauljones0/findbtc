package detector

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
)

// Watch-only address derivation from extended public keys (BIP32/49/84,
// SLIP132 versions). Everything here is local and offline: child public keys
// come from CKDpub, addresses from HASH160 plus base58check/bech32 encoding.
// Private extended keys are refused outright — findbtc never derives from,
// stores, or prints private material.
//
// Only key fingerprints (HASH160(pubkey)[:4], the descriptor convention)
// leave this module; full extended keys never appear in exports or logs.

// Address derivation limits.
const (
	// WatchDefaultCount is the addresses derived per chain (external and
	// change): the BIP44 gap limit.
	WatchDefaultCount = 20
	// WatchMaxCount bounds -watch-count so a typo cannot queue millions
	// of elliptic-curve derivations.
	WatchMaxCount = 10000
	// WatchScanMaxBytes caps -watch input scanning, matching the hash and
	// salvage extractors.
	WatchScanMaxBytes = 256 << 20
)

// xpubKey describes one extended-public-key version: its address script and
// network. SLIP132 (ypub/zpub/upub/vpub) versions pin the segwit script;
// plain xpub/tpub versions mean legacy P2PKH.
type xpubKey struct {
	script  string // p2pkh, p2sh-p2wpkh, or p2wpkh
	testnet bool
}

var xpubScripts = map[string]xpubKey{
	"xpub": {script: "p2pkh", testnet: false},
	"ypub": {script: "p2sh-p2wpkh", testnet: false},
	"zpub": {script: "p2wpkh", testnet: false},
	"tpub": {script: "p2pkh", testnet: true},
	"upub": {script: "p2sh-p2wpkh", testnet: true},
	"vpub": {script: "p2wpkh", testnet: true},
}

// xprvLabels names the private versions, refused with a dedicated error.
var xprvLabels = map[string]bool{
	"xprv": true, "tprv": true, "yprv": true,
	"zprv": true, "uprv": true, "vprv": true,
}

// XPub is a parsed extended public key (BIP32 serialization).
type XPub struct {
	Label     string // xpub, ypub, zpub, tpub, upub, or vpub
	Version   uint32
	Depth     byte
	ParentFP  [4]byte
	ChildNum  uint32
	ChainCode [32]byte
	Key       [33]byte // compressed public key
	Testnet   bool
	Script    string
}

// ParseXPub decodes a base58check extended public key, validating its
// version, compressed key encoding, and curve membership. Private versions
// and unknown versions are rejected.
func ParseXPub(s string) (*XPub, error) {
	payload, ok := base58CheckDecode(strings.TrimSpace(s))
	if !ok {
		return nil, errors.New("not base58check")
	}
	if len(payload) != 78 {
		return nil, fmt.Errorf("extended key payload is %d bytes, want 78", len(payload))
	}
	label, ok := xkeyVersions[binary.BigEndian.Uint32(payload[:4])]
	if !ok {
		return nil, fmt.Errorf("unknown extended-key version 0x%08x", binary.BigEndian.Uint32(payload[:4]))
	}
	if xprvLabels[label] {
		return nil, fmt.Errorf("refusing private extended key (%s): findbtc never derives from private material", label)
	}
	ks, ok := xpubScripts[label]
	if !ok {
		return nil, fmt.Errorf("unsupported extended public key %s", label)
	}
	if payload[45] != 0x02 && payload[45] != 0x03 {
		return nil, errors.New("extended public key is not compressed")
	}
	var key [33]byte
	copy(key[:], payload[45:78])
	if _, err := secpParseCompressed(key[:]); err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}
	x := &XPub{
		Label:    label,
		Version:  binary.BigEndian.Uint32(payload[:4]),
		Depth:    payload[4],
		ChildNum: binary.BigEndian.Uint32(payload[9:13]),
		Testnet:  ks.testnet,
		Script:   ks.script,
	}
	copy(x.ParentFP[:], payload[5:9])
	copy(x.ChainCode[:], payload[13:45])
	copy(x.Key[:], payload[45:78])
	if x.Depth == 0 && (x.ParentFP != [4]byte{} || x.ChildNum != 0) {
		return nil, errors.New("depth-0 key must have zero fingerprint and child number")
	}
	return x, nil
}

// Serialize returns the 78-byte BIP32 encoding of the key.
func (x *XPub) Serialize() []byte {
	out := make([]byte, 78)
	binary.BigEndian.PutUint32(out[:4], x.Version)
	out[4] = x.Depth
	copy(out[5:9], x.ParentFP[:])
	binary.BigEndian.PutUint32(out[9:13], x.ChildNum)
	copy(out[13:45], x.ChainCode[:])
	copy(out[45:78], x.Key[:])
	return out
}

// String re-encodes the key in base58check. Callers must treat the result
// as sensitive: it is used for tests and round-trips, never for output.
func (x *XPub) String() string {
	return base58CheckEncode(x.Serialize())
}

// Fingerprint returns the key's descriptor-style fingerprint:
// hex(HASH160(pubkey)[:4]). This is the only key-derived value exports carry.
func (x *XPub) Fingerprint() string {
	h := hash160(x.Key[:])
	return hex.EncodeToString(h[:4])
}

// errInvalidChild marks the astronomically rare CKDpub index whose
// intermediate key is invalid; BIP32 says to skip to the next index.
var errInvalidChild = errors.New("invalid child index, skipped per BIP32")

// DeriveChild applies BIP32 non-hardened derivation (CKDpub) at index i,
// which must be below the hardened range: public derivation cannot cross it.
func DeriveChild(x *XPub, i uint32) (*XPub, error) {
	if i >= 0x80000000 {
		return nil, errors.New("cannot derive hardened index from a public key")
	}
	if x.Depth == 255 {
		return nil, errors.New("cannot derive past depth 255")
	}
	var data [37]byte
	copy(data[:33], x.Key[:])
	binary.BigEndian.PutUint32(data[33:], i)
	mac := hmac.New(sha512.New, x.ChainCode[:])
	mac.Write(data[:])
	I := mac.Sum(nil)
	il := new(big.Int).SetBytes(I[:32])
	if il.Cmp(secpN) >= 0 {
		return nil, errInvalidChild
	}
	parent, err := secpParseCompressed(x.Key[:])
	if err != nil {
		return nil, err
	}
	child := secpAdd(secpMul(il, secpGenerator()), parent)
	if child.isInfinity() {
		return nil, errInvalidChild
	}
	raw, err := secpSerializeCompressed(child)
	if err != nil {
		return nil, err
	}
	c := &XPub{
		Label:    x.Label,
		Version:  x.Version,
		Depth:    x.Depth + 1,
		ChildNum: i,
		Testnet:  x.Testnet,
		Script:   x.Script,
	}
	ph := hash160(x.Key[:])
	copy(c.ParentFP[:], ph[:4])
	copy(c.ChainCode[:], I[32:])
	copy(c.Key[:], raw)
	return c, nil
}

// hash160 returns RIPEMD160(SHA256(b)), the Bitcoin short key hash.
func hash160(b []byte) [20]byte {
	s := sha256.Sum256(b)
	return ripemd160Sum(s[:])
}

// Address renders the key's address for its version's script type.
func (x *XPub) Address() (string, error) {
	h := hash160(x.Key[:])
	switch x.Script {
	case "p2pkh":
		ver := byte(0x00)
		if x.Testnet {
			ver = 0x6f
		}
		return base58CheckEncode(append([]byte{ver}, h[:]...)), nil
	case "p2wpkh":
		hrp := "bc"
		if x.Testnet {
			hrp = "tb"
		}
		return bech32SegwitEncode(hrp, 0, h[:])
	case "p2sh-p2wpkh":
		var redeem [22]byte
		redeem[0], redeem[1] = 0x00, 0x14
		copy(redeem[2:], h[:])
		rh := hash160(redeem[:])
		ver := byte(0x05)
		if x.Testnet {
			ver = 0xc4
		}
		return base58CheckEncode(append([]byte{ver}, rh[:]...)), nil
	default:
		return "", fmt.Errorf("unsupported script %q", x.Script)
	}
}

// ExtractXpubs scans arbitrary bytes (a carve, a pasted key file) for
// checksum-valid extended public keys, deduplicated in first-seen order.
// privFound reports whether private extended keys were also present, so the
// caller can explain the refusal instead of claiming nothing was there.
func ExtractXpubs(data []byte) (pubs []string, privFound bool) {
	if len(data) > WatchScanMaxBytes {
		return nil, false
	}
	seen := map[string]bool{}
	for i := 0; i < len(data); {
		if !isBase58Char(data[i]) {
			i++
			continue
		}
		j := i
		for j < len(data) && isBase58Char(data[j]) {
			j++
		}
		run := data[i:j]
		for k := 0; k+111 <= len(run); k++ {
			if !isXKeyPrefix(run[k:]) {
				continue
			}
			payload, ok := base58CheckDecode(string(run[k : k+111]))
			if !ok {
				continue
			}
			label, ok := classifyXKey(payload)
			if !ok {
				continue
			}
			if xprvLabels[label] {
				privFound = true
				continue
			}
			if _, ok := xpubScripts[label]; !ok {
				continue
			}
			s := string(run[k : k+111])
			if !seen[s] {
				seen[s] = true
				pubs = append(pubs, s)
			}
		}
		i = j
	}
	return pubs, privFound
}

// WatchEntry is one derived watch-only address plus its provenance.
type WatchEntry struct {
	Fingerprint string `json:"fingerprint"`
	Version     string `json:"version"`
	Chain       uint32 `json:"chain"` // 0 = external, 1 = change
	Index       uint32 `json:"index"`
	Path        string `json:"path"` // "chain/index" below the account key
	Address     string `json:"address"`
	Script      string `json:"script"`
	BalanceSats *int64 `json:"balance_sats,omitempty"`
}

// CollectWatchAddrs derives perChain addresses on each of the external (0)
// and change (1) chains for every extended public key.
func CollectWatchAddrs(xpubs []string, perChain int) ([]WatchEntry, error) {
	if perChain < 1 || perChain > WatchMaxCount {
		return nil, fmt.Errorf("count %d out of range 1-%d", perChain, WatchMaxCount)
	}
	var out []WatchEntry
	for _, s := range xpubs {
		acct, err := ParseXPub(s)
		if err != nil {
			return nil, fmt.Errorf("bad extended public key: %w", err)
		}
		fp := acct.Fingerprint()
		for _, chain := range []uint32{0, 1} {
			chainKey, err := DeriveChild(acct, chain)
			if err != nil {
				return nil, fmt.Errorf("cannot derive chain %d: %w", chain, err)
			}
			for idx := 0; idx < perChain; idx++ {
				child, err := DeriveChild(chainKey, uint32(idx))
				if err == errInvalidChild {
					continue // per BIP32, skip the index
				}
				if err != nil {
					return nil, fmt.Errorf("cannot derive %d/%d: %w", chain, idx, err)
				}
				addr, err := child.Address()
				if err != nil {
					return nil, err
				}
				out = append(out, WatchEntry{
					Fingerprint: fp,
					Version:     acct.Label,
					Chain:       chain,
					Index:       uint32(idx),
					Path:        fmt.Sprintf("%d/%d", chain, idx),
					Address:     addr,
					Script:      acct.Script,
				})
			}
		}
	}
	return out, nil
}

// WriteWatchCSV writes entries with a header row; balance_sats cells stay
// empty when no lookup ran or an address lookup failed.
func WriteWatchCSV(w io.Writer, entries []WatchEntry) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"fingerprint", "version", "chain", "index", "path", "address", "script", "balance_sats"}); err != nil {
		return err
	}
	for _, e := range entries {
		bal := ""
		if e.BalanceSats != nil {
			bal = strconv.FormatInt(*e.BalanceSats, 10)
		}
		if err := cw.Write([]string{e.Fingerprint, e.Version,
			strconv.FormatUint(uint64(e.Chain), 10),
			strconv.FormatUint(uint64(e.Index), 10),
			e.Path, e.Address, e.Script, bal}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// WriteWatchJSON writes entries as an indented JSON array.
func WriteWatchJSON(w io.Writer, entries []WatchEntry) error {
	if entries == nil {
		entries = []WatchEntry{}
	}
	raw, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(raw))
	return err
}

// esploraStats is the funded/spent subset of an Esplora address response.
type esploraStats struct {
	FundedTxoSum int64 `json:"funded_txo_sum"`
	SpentTxoSum  int64 `json:"spent_txo_sum"`
}

// esploraAddress is the subset of GET /address/:addr this client reads.
type esploraAddress struct {
	ChainStats   esploraStats `json:"chain_stats"`
	MempoolStats esploraStats `json:"mempool_stats"`
}

// LookupBalances queries an Esplora-compatible endpoint
// (GET {endpoint}/address/:addr) for each address and returns confirmed plus
// mempool balances in sats. Per-address failures are collected into one
// error; successes are still returned. The client performs network I/O — it
// is only constructed on the explicit opt-in path, never by default.
func LookupBalances(client *http.Client, endpoint string, addrs []string) (map[string]int64, error) {
	base := strings.TrimSuffix(strings.TrimSpace(endpoint), "/")
	if base == "" {
		return nil, errors.New("empty balance endpoint")
	}
	if client == nil {
		return nil, errors.New("no HTTP client")
	}
	balances := map[string]int64{}
	var failures []string
	seen := map[string]bool{}
	for _, addr := range addrs {
		if seen[addr] {
			continue
		}
		seen[addr] = true
		resp, err := client.Get(base + "/address/" + addr)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %s", addr, err.Error()))
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %s", addr, err.Error()))
			continue
		}
		if resp.StatusCode != 200 {
			failures = append(failures, fmt.Sprintf("%s: HTTP %d", addr, resp.StatusCode))
			continue
		}
		var ea esploraAddress
		if err := json.Unmarshal(body, &ea); err != nil {
			failures = append(failures, fmt.Sprintf("%s: bad response: %s", addr, err.Error()))
			continue
		}
		funded := ea.ChainStats.FundedTxoSum + ea.MempoolStats.FundedTxoSum
		spent := ea.ChainStats.SpentTxoSum + ea.MempoolStats.SpentTxoSum
		balances[addr] = funded - spent
	}
	if len(failures) > 0 {
		return balances, fmt.Errorf("%d of %d lookups failed: %s",
			len(failures), len(seen), strings.Join(failures, "; "))
	}
	return balances, nil
}
