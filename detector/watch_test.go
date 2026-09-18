package detector

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Oracle fixtures: account keys derived by btcsuite (hdkeychain) from the
// BIP39 test mnemonic "abandon ... about" (/tmp/xpub-oracle, kept out of the
// repo so findbtc stays dependency-free). SLIP132 ypub/zpub/upub/vpub forms
// re-encode the same keys; addresses below are btcsuite's for both forms.

// bip44MainXPub is m/44'/0'/0' (P2PKH).
const bip44MainXPub = "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj"

// bip49MainYSub is m/49'/0'/0' (P2SH-P2WPKH).
const bip49MainYPub = "ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP"

// bip84MainZPub is m/84'/0'/0' (P2WPKH).
const bip84MainZPub = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"

// bip44TestTPub is m/44'/1'/0' (testnet P2PKH).
const bip44TestTPub = "tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba"

// bip49TestUPub is m/49'/1'/0' (testnet P2SH-P2WPKH).
const bip49TestUPub = "upub5EFU65HtV5TeiSHmZZm7FUffBGy8UKeqp7vw43jYbvZPpoVsgU93oac7Wk3u6moKegAEWtGNF8DehrnHtv21XXEMYRUocHqguyjknFHYfgY"

// bip84TestVPub is m/84'/1'/0' (testnet P2WPKH).
const bip84TestVPub = "vpub5Y6cjg78GGuNLsaPhmYsiw4gYX3HoQiRBiSwDaBXKUafCt9bNwWQiitDk5VZ5BVxYnQdwoTyXSs2JHRPAgjAvtbBrf8ZhDYe2jWAqvZVnsc"

func TestRipemd160Vectors(t *testing.T) {
	long := []byte("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
	millionA := bytes.Repeat([]byte("a"), 1000000)
	range32 := make([]byte, 32)
	for i := range range32 {
		range32[i] = byte(i)
	}
	range100 := make([]byte, 100)
	for i := range range100 {
		range100[i] = byte(i)
	}
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"empty", []byte{}, "9c1185a5c5e9fc54612808977ee8f548b2258d31"},
		{"abc", []byte("abc"), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"},
		{"long", long, "12a053384a9c0c88e405a06c27dcf49ada62eb2b"},
		{"million-a", millionA, "52783243c1697bdbe16d37f97f68f08325dc1528"},
		{"range32", range32, "e6babb9619d7a81272711fc546a16b211dd93957"},
		{"range100", range100, "8ae5d2e6b1f3a514257f2469b637454931844aeb"},
	}
	for _, c := range cases {
		if got := fmt.Sprintf("%x", ripemd160Sum(c.in)); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

// TestCKDPubVectors replays non-hardened steps from the published BIP32 test
// vectors: the full child xpub must match, which pins the EC math, HMAC
// chaining, fingerprinting, and base58 encoding all at once.
func TestCKDPubVectors(t *testing.T) {
	cases := []struct {
		name   string
		parent string
		index  uint32
		child  string
	}{
		{"v2 m/0",
			"xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
			0,
			"xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"},
		{"v1 m/0H/1/2H/2",
			"xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
			2,
			"xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"},
		{"v1 m/0H/1/2H/2/1000000000",
			"xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
			1000000000,
			"xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"},
	}
	for _, c := range cases {
		p, err := ParseXPub(c.parent)
		if err != nil {
			t.Fatalf("%s: parse parent: %s", c.name, err)
		}
		k, err := DeriveChild(p, c.index)
		if err != nil {
			t.Fatalf("%s: derive: %s", c.name, err)
		}
		if got := k.String(); got != c.child {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.child)
		}
	}
	if _, err := DeriveChild(mustParseXPub(t, bip44MainXPub), 0x80000000); err == nil {
		t.Error("hardened derivation from public key must fail")
	}
}

// TestWatchAddressesOracle checks every script/network combination against
// the btcsuite oracle's addresses.
func TestWatchAddressesOracle(t *testing.T) {
	cases := []struct {
		name   string
		xpub   string
		fp     string
		script string
		ext    []string
		change []string
	}{
		{"bip44 main P2PKH", bip44MainXPub, "6cc9f252", "p2pkh",
			[]string{"1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA", "1Ak8PffB2meyfYnbXZR9EGfLfFZVpzJvQP", "1MNF5RSaabFwcbtJirJwKnDytsXXEsVsNb"},
			[]string{"1J3J6EvPrv8q6AC3VCjWV45Uf3nssNMRtH", "13vKxXzHXXd8HquAYdpkJoi9ULVXUgfpS5", "1M21Wx1nGrHMPaz52N2En7c624nzL4MYTk"}},
		{"bip49 main P2SH-P2WPKH", bip49MainYPub, "3a161284", "p2sh-p2wpkh",
			[]string{"37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf", "3LtMnn87fqUeHBUG414p9CWwnoV6E2pNKS", "3B4cvWGR8X6Xs8nvTxVUoMJV77E4f7oaia"},
			[]string{"34K56kSjgUCUSD8GTtuF7c9Zzwokbs6uZ7", "3516F2wmK51jVRrggEJsTUBNWMSLLjzvJ2", "3Grd7y95JEDTSh9uiVF5q7z2qGzmkP19CV"}},
		{"bip84 main P2WPKH", bip84MainZPub, "fd13aac9", "p2wpkh",
			[]string{"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g", "bc1qp59yckz4ae5c4efgw2s5wfyvrz0ala7rgvuz8z"},
			[]string{"bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el", "bc1qggnasd834t54yulsep6fta8lpjekv4zj6gv5rf", "bc1qn8alfh45rlsj44pcdt0f2cadtztgnz4gq3h3uf"}},
		{"bip44 testnet P2PKH", bip44TestTPub, "4334c988", "p2pkh",
			[]string{"mkpZhYtJu2r87Js3pDiWJDmPte2NRZ8bJV", "mzpbWabUQm1w8ijuJnAof5eiSTep27deVH", "mnTkxhNkgx7TsZrEdRcPti564yQTzynGJp"},
			[]string{"mi8nhzZgGZQthq6DQHbru9crMDerUdTKva", "mz9HfS6y833A8HP8bfpLikzCbjonJXaAGW", "mnmhr8Z31n8GEN6ky4jp4h8VJjCRpRfzQW"}},
		{"bip49 testnet P2SH-P2WPKH", bip49TestUPub, "0a55db61", "p2sh-p2wpkh",
			[]string{"2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2", "2N55m54k8vr95ggehfUcNkdbUuQvaqG2GxK", "2N9LKph9TKtv1WLDfaUJp4D8EKwsyASYnGX"},
			[]string{"2MvdUi5o3f2tnEFh9yGvta6FzptTZtkPJC8", "2NCtHHE9TjYrYnUWfZv79w9ktk1f2uPUzqu", "2N9vVCnXmavTBmxRjoPjoHZ9q9ujEKXXGXe"}},
		{"bip84 testnet P2WPKH", bip84TestVPub, "e99b8628", "p2wpkh",
			[]string{"tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl", "tb1qd7spv5q28348xl4myc8zmh983w5jx32cjhkn97", "tb1qxdyjf6h5d6qxap4n2dap97q4j5ps6ua8sll0ct"},
			[]string{"tb1q9u62588spffmq4dzjxsr5l297znf3z6j5p2688", "tb1qkwgskuzmmwwvqajnyr7yp9hgvh5y45kg8wvdmd", "tb1q2vma00td2g9llw8hwa8ny3r774rtt7aenfn5zu"}},
	}
	for _, c := range cases {
		entries, err := CollectWatchAddrs([]string{c.xpub}, 3)
		if err != nil {
			t.Fatalf("%s: %s", c.name, err)
		}
		if len(entries) != 6 {
			t.Fatalf("%s: got %d entries, want 6", c.name, len(entries))
		}
		for i, e := range entries {
			var want string
			if e.Chain == 0 {
				want = c.ext[e.Index]
			} else {
				want = c.change[e.Index]
			}
			if e.Address != want {
				t.Errorf("%s entry %d (%s): got %s, want %s", c.name, i, e.Path, e.Address, want)
			}
			if e.Fingerprint != c.fp {
				t.Errorf("%s entry %d: fingerprint %s, want %s", c.name, i, e.Fingerprint, c.fp)
			}
			if e.Script != c.script {
				t.Errorf("%s entry %d: script %s, want %s", c.name, i, e.Script, c.script)
			}
			if e.Path != fmt.Sprintf("%d/%d", e.Chain, e.Index) {
				t.Errorf("%s entry %d: path %q inconsistent", c.name, i, e.Path)
			}
		}
	}
}

func mustParseXPub(t *testing.T, s string) *XPub {
	t.Helper()
	x, err := ParseXPub(s)
	if err != nil {
		t.Fatalf("parse xpub: %s", err)
	}
	return x
}

func TestParseXPubRefusals(t *testing.T) {
	// A valid xprv (BIP32 vector 1 chain m) must be refused, not parsed.
	if _, err := ParseXPub("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"); err == nil {
		t.Error("xprv must be refused")
	} else if !strings.Contains(err.Error(), "private") {
		t.Errorf("xprv error should say private, got: %s", err)
	}
	for _, bad := range []string{"", "xpub661MyMwAqRbc", "not a key at all!!"} {
		if _, err := ParseXPub(bad); err == nil {
			t.Errorf("input %q must fail", bad)
		}
	}
	// Flipped checksum byte.
	corrupt := bip44MainXPub[:100] + "1" + bip44MainXPub[101:]
	if _, err := ParseXPub(corrupt); err == nil {
		t.Error("corrupted checksum must fail")
	}
	// Unknown version bytes, re-checksummed.
	raw, _ := base58CheckDecode(bip44MainXPub)
	mut := append([]byte(nil), raw...)
	binary.BigEndian.PutUint32(mut[:4], 0xdeadbeef)
	if _, err := ParseXPub(base58CheckEncode(mut)); err == nil {
		t.Error("unknown version must fail")
	}
	// Uncompressed key marker, re-checksummed.
	mut2 := append([]byte(nil), raw...)
	mut2[45] = 0x04
	if _, err := ParseXPub(base58CheckEncode(mut2)); err == nil {
		t.Error("uncompressed key must fail")
	}
	// Depth-0 master with nonzero fingerprint.
	mut3 := append([]byte(nil), raw...)
	mut3[4] = 0
	mut3[5] = 0x01
	if _, err := ParseXPub(base58CheckEncode(mut3)); err == nil {
		t.Error("depth-0 key with nonzero fingerprint must fail")
	}
	// Off-curve compressed key: x = p (out of range).
	mut4 := append([]byte(nil), raw...)
	for i := 46; i < 78; i++ {
		mut4[i] = 0xff
	}
	if _, err := ParseXPub(base58CheckEncode(mut4)); err == nil {
		t.Error("out-of-range key must fail")
	}
}

func TestBase58Roundtrip(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	// Empty input is rejected by the pre-existing decoder; everything else
	// must round-trip.
	bufs := [][]byte{{0}, {0, 0, 0}, {1, 2, 3}}
	for i := 0; i < 50; i++ {
		b := make([]byte, 1+rng.Intn(90))
		rng.Read(b)
		if i%3 == 0 {
			b[0] = 0 // leading-zero runs exercise the '1' prefix
		}
		bufs = append(bufs, b)
	}
	for i, b := range bufs {
		enc := base58Encode(b)
		dec, ok := base58Decode(enc)
		if !ok {
			t.Fatalf("case %d: decode failed", i)
		}
		if !bytes.Equal(dec, b) {
			t.Fatalf("case %d: roundtrip mismatch", i)
		}
	}
	// The oracle xpubs survive a decode/re-encode round trip byte for byte.
	for _, x := range []string{bip44MainXPub, bip49MainYPub, bip84MainZPub, bip44TestTPub, bip49TestUPub, bip84TestVPub} {
		raw, ok := base58Decode(x)
		if !ok || base58Encode(raw) != x {
			t.Errorf("%s... roundtrip failed", x[:8])
		}
	}
}

func TestExtractXpubs(t *testing.T) {
	xprv := "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
	var buf bytes.Buffer
	buf.WriteString("\x00binary\xff noise ")
	buf.WriteString(bip84MainZPub)
	buf.WriteString(" middle ")
	buf.WriteString(xprv) // private: noted, never returned
	buf.WriteString(" ")
	buf.WriteString(bip84MainZPub) // duplicate
	buf.WriteString(" tail ")
	buf.WriteString(bip44TestTPub)
	pubs, priv := ExtractXpubs(buf.Bytes())
	if !priv {
		t.Error("xprv presence must be reported")
	}
	if len(pubs) != 2 || pubs[0] != bip84MainZPub || pubs[1] != bip44TestTPub {
		t.Errorf("got %d pubs, want [zpub tpub] deduplicated", len(pubs))
	}
	if pubs, priv := ExtractXpubs([]byte("nothing but noise here")); len(pubs) != 0 || priv {
		t.Error("noise must yield nothing")
	}
	if pubs, _ := ExtractXpubs(make([]byte, WatchScanMaxBytes+1)); pubs != nil {
		t.Error("oversized input must be skipped")
	}
}

func TestCollectWatchAddrsShape(t *testing.T) {
	entries, err := CollectWatchAddrs([]string{bip44MainXPub}, WatchDefaultCount)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2*WatchDefaultCount {
		t.Fatalf("got %d entries, want %d", len(entries), 2*WatchDefaultCount)
	}
	if entries[0].Path != "0/0" || entries[WatchDefaultCount].Path != "1/0" {
		t.Errorf("chain ordering wrong: %s, %s", entries[0].Path, entries[WatchDefaultCount].Path)
	}
	for _, n := range []int{0, -1, WatchMaxCount + 1} {
		if _, err := CollectWatchAddrs([]string{bip44MainXPub}, n); err == nil {
			t.Errorf("count %d must fail", n)
		}
	}
	if _, err := CollectWatchAddrs([]string{"bogus"}, 3); err == nil {
		t.Error("bogus key must fail")
	}
}

func TestWatchExportGolden(t *testing.T) {
	entries, err := CollectWatchAddrs([]string{bip44MainXPub}, 1)
	if err != nil {
		t.Fatal(err)
	}
	var csvBuf bytes.Buffer
	if err := WriteWatchCSV(&csvBuf, entries); err != nil {
		t.Fatal(err)
	}
	wantCSV := "fingerprint,version,chain,index,path,address,script,balance_sats\n" +
		"6cc9f252,xpub,0,0,0/0,1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA,p2pkh,\n" +
		"6cc9f252,xpub,1,0,1/0,1J3J6EvPrv8q6AC3VCjWV45Uf3nssNMRtH,p2pkh,\n"
	if csvBuf.String() != wantCSV {
		t.Errorf("CSV mismatch:\n got:\n%s\nwant:\n%s", csvBuf.String(), wantCSV)
	}
	var jsonBuf bytes.Buffer
	if err := WriteWatchJSON(&jsonBuf, entries); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(jsonBuf.String(), `"address": "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"`) ||
		!strings.Contains(jsonBuf.String(), `"fingerprint": "6cc9f252"`) {
		t.Errorf("JSON missing entries:\n%s", jsonBuf.String())
	}
	// Privacy: the extended key itself appears in neither export.
	for name, out := range map[string]string{"csv": csvBuf.String(), "json": jsonBuf.String()} {
		if strings.Contains(out, bip44MainXPub) {
			t.Errorf("%s export leaks the xpub", name)
		}
	}
}

func TestWatchFingerprintOracle(t *testing.T) {
	// Fingerprints verified with Python hashlib (independent implementation).
	for xpub, want := range map[string]string{
		bip44MainXPub: "6cc9f252", bip49MainYPub: "3a161284",
		bip84MainZPub: "fd13aac9", bip44TestTPub: "4334c988",
		bip49TestUPub: "0a55db61", bip84TestVPub: "e99b8628",
	} {
		if got := mustParseXPub(t, xpub).Fingerprint(); got != want {
			t.Errorf("%s...: fingerprint %s, want %s", xpub[:8], got, want)
		}
	}
}

// TestLookupBalances exercises the opt-in endpoint client against a local
// Esplora-shaped stub: success, mempool inclusion, and partial failure.
func TestLookupBalances(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimPrefix(r.URL.Path, "/address/") {
		case "addr-funded":
			fmt.Fprint(w, `{"chain_stats":{"funded_txo_sum":50000,"spent_txo_sum":10000},"mempool_stats":{"funded_txo_sum":2000,"spent_txo_sum":0}}`)
		case "addr-empty":
			fmt.Fprint(w, `{"chain_stats":{"funded_txo_sum":0,"spent_txo_sum":0},"mempool_stats":{"funded_txo_sum":0,"spent_txo_sum":0}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	client := srv.Client()
	bal, err := LookupBalances(client, srv.URL, []string{"addr-funded", "addr-empty"})
	if err != nil {
		t.Fatalf("lookup: %s", err)
	}
	if bal["addr-funded"] != 42000 {
		t.Errorf("funded balance %d, want 42000", bal["addr-funded"])
	}
	if bal["addr-empty"] != 0 {
		t.Errorf("empty balance %d, want 0", bal["addr-empty"])
	}
	// Partial failure: successes kept, one combined error.
	bal, err = LookupBalances(client, srv.URL, []string{"addr-funded", "addr-missing"})
	if err == nil {
		t.Fatal("missing address must produce an error")
	}
	if bal["addr-funded"] != 42000 {
		t.Errorf("partial success lost: %v", bal)
	}
	if _, err := LookupBalances(nil, srv.URL, []string{"addr-funded"}); err == nil {
		t.Error("nil client must fail")
	}
	if _, err := LookupBalances(client, "", []string{"addr-funded"}); err == nil {
		t.Error("empty endpoint must fail")
	}
}

// TestWatchDefaultOffline pins the Goal 5 invariant: the default
// derive-and-export path completes with a nil HTTP client, i.e. it cannot
// perform network I/O because it has no transport to do it with.
func TestWatchDefaultOffline(t *testing.T) {
	var noClient *http.Client
	entries, err := CollectWatchAddrs([]string{bip84TestVPub}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if noClient != nil {
		t.Fatal("unreachable")
	}
	var csvBuf, jsonBuf bytes.Buffer
	if err := WriteWatchCSV(&csvBuf, entries); err != nil {
		t.Fatal(err)
	}
	if err := WriteWatchJSON(&jsonBuf, entries); err != nil {
		t.Fatal(err)
	}
	if csvBuf.Len() == 0 || jsonBuf.Len() == 0 {
		t.Error("default export produced no output")
	}
}

// TestScannerFindsSLIP132Versions keeps detector coverage aligned with the
// watch parser: every version ParseXPub accepts must also scan.
func TestScannerFindsSLIP132Versions(t *testing.T) {
	buf := []byte("pad " + bip49TestUPub + " pad " + bip84TestVPub + " pad")
	matches := findKeys(buf, 1000, true, true)
	got := map[string]bool{}
	for _, m := range matches {
		got[m.label] = true
	}
	if !got["upub"] || !got["vpub"] {
		t.Errorf("scanner missed SLIP132 testnet keys: %v", got)
	}
	// The classifier (version bytes only) and report agree on the new
	// testnet-segwit versions.
	for ver, label := range map[uint32]string{0x044A4E28: "uprv", 0x044A5262: "upub", 0x045F18BC: "vprv", 0x045F1CF6: "vpub"} {
		payload := make([]byte, 78)
		binary.BigEndian.PutUint32(payload, ver)
		gotLabel, ok := classifyXKey(payload)
		if !ok || gotLabel != label {
			t.Errorf("version 0x%08x: got %q,%v want %q", ver, gotLabel, ok, label)
		}
	}
	if c := classifyNeedle("upub"); c.walletType != "extended-public-key" {
		t.Errorf("upub report class %q", c.walletType)
	}
	if c := classifyNeedle("vprv"); c.walletType != "extended-private-key" {
		t.Errorf("vprv report class %q", c.walletType)
	}
}

func TestWatchDerivationSpeed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing test in short mode")
	}
	start := time.Now()
	if _, err := CollectWatchAddrs([]string{bip84MainZPub}, WatchDefaultCount); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Errorf("default derivation took %s, want under 30s", elapsed)
	}
}
