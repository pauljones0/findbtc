package detector

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Real CMasterKey values, independent oracles in comments.

// From BTCRecover's bitcoincore-0.21.1-wallet.dat (SQLite), SELECT value FROM
// main WHERE key LIKE '%mkey%'. Trailing 00 is the empty otherParams string
// newer wallets append; the parser ignores it. The real bitcoin2john.py emits
// for this wallet:
// $bitcoin$64$d57eb66f53d15a0b95cb3514518ef83ce87b743ccafef31e1953a7fef0f88f42$16$11a9673bb6d75428$267488$2$00$2$00
const realMKeySQLiteHex = "30fd43fb19505f4d200ee82c0c196520dad57eb66f53d15a0b95cb3514518ef83ce87b743ccafef31e1953a7fef0f88f420811a9673bb6d7542800000000e014040000"

const realMKeySQLiteHash = "$bitcoin$64$d57eb66f53d15a0b95cb3514518ef83ce87b743ccafef31e1953a7fef0f88f42$16$11a9673bb6d75428$267488$2$00$2$00"

// From BTCRecover's bitcoincore-wallet.dat (BDB) at file offset 53327: the
// only pattern match in the whole file, and its fields equal pywallet's dump
// of the same wallet (salt 4593aff5639179c7, 67908 iterations, method 0).
const realMKeyBDBHex = "302e2c3b9b58e9b33c9799b4472e83c136e6246120c45e390daa6a57476e7fbe4f57d83f79d75f9b4c1db680fe5a846cb8084593aff5639179c70000000044090100"

const realMKeyBDBHash = "$bitcoin$64$e6246120c45e390daa6a57476e7fbe4f57d83f79d75f9b4c1db680fe5a846cb8$16$4593aff5639179c7$67908$2$00$2$00"

// testPBKDF2 is a minimal PBKDF2-HMAC-SHA512 for building fixtures. Test-only:
// production code never derives keys.
func testPBKDF2(password, salt []byte, iters, keyLen int) []byte {
	var out []byte
	for block := 1; len(out) < keyLen; block++ {
		mac := hmac.New(sha512.New, password)
		mac.Write(salt)
		mac.Write([]byte{0, 0, 0, byte(block)})
		u := mac.Sum(nil)
		t := bytes.Clone(u)
		for i := 1; i < iters; i++ {
			mac = hmac.New(sha512.New, password)
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

// buildSyntheticMKey serializes a CMasterKey value exactly as Bitcoin Core
// does: a random 32-byte key AES-256-CBC-encrypted under a PBKDF2-derived
// key (64 bytes: 32 key + 16 IV, the layout hashcat mode 11300 verifies),
// PKCS7-padded to 48 bytes. Returns the value and the known plaintext key.
func buildSyntheticMKey(t *testing.T, password string, iters uint32) (value, key []byte) {
	t.Helper()
	rng := rand.New(rand.NewSource(42))
	salt := make([]byte, mkeySaltLen)
	if _, err := rng.Read(salt); err != nil {
		t.Fatal(err)
	}
	key = make([]byte, 32)
	if _, err := rng.Read(key); err != nil {
		t.Fatal(err)
	}
	derived := testPBKDF2([]byte(password), salt, int(iters), 64)
	block, err := aes.NewCipher(derived[:32])
	if err != nil {
		t.Fatal(err)
	}
	padded := append(bytes.Clone(key), bytes.Repeat([]byte{16}, 16)...)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, derived[32:48]).CryptBlocks(ct, padded)
	value = []byte{mkeyCryptedLen}
	value = append(value, ct...)
	value = append(value, mkeySaltLen)
	value = append(value, salt...)
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], 0)
	value = append(value, tmp[:]...)
	binary.LittleEndian.PutUint32(tmp[:], iters)
	value = append(value, tmp[:]...)
	return value, key
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestFindMasterKeysRealVectors(t *testing.T) {
	for _, tc := range []struct {
		name  string
		hex   string
		hash  string
		iters uint32
		salt  string
	}{
		{"sqlite", realMKeySQLiteHex, realMKeySQLiteHash, 267488, "11a9673bb6d75428"},
		{"bdb", realMKeyBDBHex, realMKeyBDBHash, 67908, "4593aff5639179c7"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := mustHex(t, tc.hex)
			// Pad with noise so the parser must locate the record, not the buffer.
			data := append(append([]byte("noise-prefix-"), raw...), []byte("-noise-suffix")...)
			found := FindMasterKeys(data, 1000)
			if len(found) != 1 {
				t.Fatalf("found %d records, want 1", len(found))
			}
			m := found[0]
			if m.Offset() != 1000+int64(len("noise-prefix-")) {
				t.Errorf("offset = %d", m.Offset())
			}
			if m.Iterations() != tc.iters || m.SaltHex() != tc.salt {
				t.Errorf("iters/salt = %d/%s, want %d/%s", m.Iterations(), m.SaltHex(), tc.iters, tc.salt)
			}
			h, err := m.Hash()
			if err != nil {
				t.Fatal(err)
			}
			if h.Hash != tc.hash {
				t.Errorf("hash = %s\nwant %s", h.Hash, tc.hash)
			}
			if h.KDF != "pbkdf2-hmac-sha512" || h.Format != "bitcoin-core-mkey" {
				t.Errorf("metadata = %+v", h)
			}
		})
	}
}

// The emitted hash must carry sufficient material for a real crack: re-derive
// from the parsed salt/iterations with the known password and decrypt.
func TestMasterKeyHashSelfCheck(t *testing.T) {
	const password = "test-only-password-7hX9" // fixture secret, never logged
	value, key := buildSyntheticMKey(t, password, 25000)
	data := append(append(bytes.Repeat([]byte{0xAB}, 100), value...), bytes.Repeat([]byte{0xCD}, 100)...)
	found := FindMasterKeys(data, 0)
	if len(found) != 1 {
		t.Fatalf("found %d records, want 1", len(found))
	}
	m := found[0]
	h, err := m.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h.Hash, "$bitcoin$64$") || !strings.Contains(h.Hash, "$2$00$2$00") {
		t.Fatalf("unexpected hash shape: %s", h.Hash)
	}
	// Cracker's verify path (hashcat 11300): PBKDF2, CBC-decrypt, padding check.
	derived := testPBKDF2([]byte(password), m.salt, int(m.iterations), 64)
	block, err := aes.NewCipher(derived[:32])
	if err != nil {
		t.Fatal(err)
	}
	pt := make([]byte, len(m.crypted))
	cipher.NewCBCDecrypter(block, derived[32:48]).CryptBlocks(pt, m.crypted)
	if !bytes.Equal(pt[:32], key) {
		t.Fatal("re-derived key does not match the fixture key")
	}
	if !bytes.Equal(pt[32:], bytes.Repeat([]byte{16}, 16)) {
		t.Fatal("decrypted padding invalid")
	}
}

func TestFindMasterKeysRejects(t *testing.T) {
	good := mustHex(t, realMKeyBDBHex)[:mkeyValueLen]
	// Every truncation must yield nothing, never a partial record.
	for cut := 0; cut < mkeyValueLen; cut++ {
		if found := FindMasterKeys(good[:cut], 0); len(found) != 0 {
			t.Fatalf("truncated to %d bytes: found %d records", cut, len(found))
		}
	}
	mutate := func(i int, v byte) []byte {
		b := bytes.Clone(good)
		b[i] = v
		return b
	}
	cases := map[string][]byte{
		"short crypted len": mutate(0, 47),
		"long crypted len":  mutate(0, 49),
		"short salt len":    mutate(49, 7),
		"long salt len":     mutate(49, 9),
		"method nonzero":    mutate(58, 1),
	}
	for name, data := range cases {
		if found := FindMasterKeys(data, 0); len(found) != 0 {
			t.Errorf("%s: found %d records, want 0", name, len(found))
		}
	}
	// Iteration bounds.
	for _, iters := range []uint32{999, 100_000_001} {
		b := bytes.Clone(good)
		binary.LittleEndian.PutUint32(b[62:], iters)
		if found := FindMasterKeys(b, 0); len(found) != 0 {
			t.Errorf("iters %d: found %d records, want 0", iters, len(found))
		}
	}
	for _, iters := range []uint32{1000, 100_000_000} {
		b := bytes.Clone(good)
		binary.LittleEndian.PutUint32(b[62:], iters)
		if found := FindMasterKeys(b, 0); len(found) != 1 {
			t.Errorf("iters %d: found %d records, want 1", iters, len(found))
		}
	}
	if found := FindMasterKeys(nil, 0); len(found) != 0 {
		t.Errorf("nil input: found %d records", len(found))
	}
}

func TestMasterKeyHashValidates(t *testing.T) {
	if _, err := (MasterKey{}).Hash(); err == nil {
		t.Error("zero MasterKey hashed without error")
	}
	m := MasterKey{crypted: make([]byte, 32), salt: make([]byte, 8)}
	if _, err := m.Hash(); err == nil {
		t.Error("short crypted hashed without error")
	}
}

func TestFindMasterKeysNoise(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	noise := make([]byte, 1<<20)
	if _, err := rng.Read(noise); err != nil {
		t.Fatal(err)
	}
	if found := FindMasterKeys(noise, 0); len(found) != 0 {
		t.Errorf("1MB noise: found %d records, want 0", len(found))
	}
}

// End to end: a scan hit whose carve holds a real mkey value must surface
// the reference cracker hash on the detection and in the sidecar.
func TestScanCarveExtractsHashes(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "disk.img")
	payload := bytes.Repeat([]byte{0}, 8192)
	copy(payload[100:], "crypted_key")
	copy(payload[2000:], mustHex(t, realMKeyBDBHex))
	if err := os.WriteFile(img, payload, 0644); err != nil {
		t.Fatal(err)
	}
	carveDir := filepath.Join(dir, "carve")
	var dets []Detection
	err := ScanWithOptions(0, img, Options{CarveDir: carveDir, CarveContextBytes: 4096},
		func(d Detection) { dets = append(dets, d) },
		func(ProgressInfo) {})
	if err != nil {
		t.Fatal(err)
	}
	if len(dets) != 1 {
		t.Fatalf("detections = %d, want 1", len(dets))
	}
	if len(dets[0].Hashes) != 1 || dets[0].Hashes[0].Hash != realMKeyBDBHash {
		t.Fatalf("hashes = %+v, want [%s]", dets[0].Hashes, realMKeyBDBHash)
	}
	sidecar, err := os.ReadFile(filepath.Join(carveDir, "hit-000001.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sidecar), realMKeyBDBHash) {
		t.Errorf("sidecar lacks the hash:\n%s", sidecar)
	}
}

func TestExtractHashesDedupes(t *testing.T) {
	val := mustHex(t, realMKeyBDBHex)
	data := append(append(bytes.Clone(val), bytes.Repeat([]byte{0}, 100)...), val...)
	hashes := ExtractHashes(data, 100)
	if len(hashes) != 1 {
		t.Fatalf("hashes = %d, want 1", len(hashes))
	}
	if hashes[0].Hash != realMKeyBDBHash || hashes[0].Offset != 100 {
		t.Errorf("hash = %+v", hashes[0])
	}
}
