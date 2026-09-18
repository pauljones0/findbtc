package detector

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// Bitcoin Core master-key (mkey) extraction for offline password recovery.
//
// Encrypted Core wallets — BDB and SQLite alike — store a CMasterKey record
// whose serialized value is:
//
//	compactSize + vchCryptedKey (48 bytes: a 32-byte key AES-256-CBC-encrypted
//	  with PKCS7 padding, i.e. three blocks)
//	compactSize + vchSalt (8 bytes)
//	nDerivationMethod uint32LE (0 = PBKDF2-HMAC-SHA512)
//	nDerivationIterations uint32LE
//	[optional trailing otherParams on newer wallets, ignored here]
//
// (wallet/crypter.h CMasterKey; the same layout bitcoin2john.py parses.)
// The container (BDB page, SQLite cell) only wraps these value bytes, so
// extraction scans raw bytes for the value pattern instead of parsing
// database pages — which also makes it work on carved fragments. A match
// requires the exact lengths plus method 0 plus sane iterations, so random
// data is effectively silent (about 2^-48 per position before the
// iterations check).

const (
	mkeyCryptedLen = 48
	mkeySaltLen    = 8
	// mkeyValueLen is the fixed span of a standard CMasterKey value without
	// trailing params: 1+48+1+8+4+4.
	mkeyValueLen = 66
	// Iteration bounds for plausible KDF work. Real Core wallets calibrate
	// in the tens-to-hundreds of thousands; anything outside [1k, 100M] is
	// treated as a coincidental byte pattern rather than risk a bogus hash.
	mkeyMinIterations = 1000
	mkeyMaxIterations = 100_000_000
)

// CrackHash is crack-ready password-recovery material plus its KDF metadata.
// It carries everything a cracker needs and nothing that decrypts anything
// on its own.
type CrackHash struct {
	// Format is "bitcoin-core-mkey" or "ethereum-keystore".
	Format string `json:"format"`
	// Hash is the cracker input string ($bitcoin$...), or "" when only
	// structured params are available.
	Hash string `json:"hash,omitempty"`
	// KDF names the derivation ("pbkdf2-hmac-sha512", "scrypt", ...).
	KDF string `json:"kdf"`
	// Iterations, SaltHex and Method describe the KDF; keystores carry
	// their fuller parameter set in Params instead.
	Iterations uint32            `json:"iterations,omitempty"`
	SaltHex    string            `json:"salt_hex,omitempty"`
	Method     uint32            `json:"method,omitempty"`
	Params     map[string]string `json:"params,omitempty"`
	// Offset is the absolute offset of the source record in the scanned bytes.
	Offset int64 `json:"offset"`
}

// MasterKey is one parsed CMasterKey record. Raw ciphertext stays out of
// JSON: Hash renders the cracker string, which holds only the blocks a
// cracker verifies.
type MasterKey struct {
	crypted    []byte
	salt       []byte
	method     uint32
	iterations uint32
	offset     int64
}

// Iterations returns the KDF iteration count.
func (m MasterKey) Iterations() uint32 { return m.iterations }

// SaltHex returns the hex-encoded KDF salt.
func (m MasterKey) SaltHex() string { return hex.EncodeToString(m.salt) }

// Offset returns the absolute offset of the record value.
func (m MasterKey) Offset() int64 { return m.offset }

// FindMasterKeys returns every standard CMasterKey value fully contained in
// data. baseAbs is the absolute offset of data[0].
func FindMasterKeys(data []byte, baseAbs int64) []MasterKey {
	var out []MasterKey
	for i := 0; i+mkeyValueLen <= len(data); i++ {
		if data[i] != mkeyCryptedLen {
			continue
		}
		if data[i+1+mkeyCryptedLen] != mkeySaltLen {
			continue
		}
		method := binary.LittleEndian.Uint32(data[i+58:])
		iters := binary.LittleEndian.Uint32(data[i+62:])
		if method != 0 || iters < mkeyMinIterations || iters > mkeyMaxIterations {
			continue
		}
		out = append(out, MasterKey{
			crypted:    bytes.Clone(data[i+1 : i+1+mkeyCryptedLen]),
			salt:       bytes.Clone(data[i+50 : i+50+mkeySaltLen]),
			method:     method,
			iterations: iters,
			offset:     baseAbs + int64(i),
		})
	}
	return out
}

// Hash renders the hashcat/John `bitcoin` input exactly as bitcoin2john.py
// does: the last two AES blocks of the encrypted key (the only blocks a
// cracker verifies), the full salt, and the iteration count:
//
//	$bitcoin$64$<last-32-bytes-hex>$16$<salt-hex>$<iters>$2$00$2$00
//
// The length fields count hex characters. Anything but a standard record
// errors instead of producing a hash no cracker could use.
func (m MasterKey) Hash() (CrackHash, error) {
	if len(m.crypted) != mkeyCryptedLen || len(m.salt) != mkeySaltLen || m.method != 0 {
		return CrackHash{}, fmt.Errorf("not a standard bitcoin-core master key (crypted %d bytes, salt %d bytes, method %d)",
			len(m.crypted), len(m.salt), m.method)
	}
	tail := hex.EncodeToString(m.crypted[len(m.crypted)-32:])
	salt := hex.EncodeToString(m.salt)
	return CrackHash{
		Format:     "bitcoin-core-mkey",
		Hash:       fmt.Sprintf("$bitcoin$%d$%s$%d$%s$%d$2$00$2$00", len(tail), tail, len(salt), salt, m.iterations),
		KDF:        "pbkdf2-hmac-sha512",
		Iterations: m.iterations,
		SaltHex:    salt,
		Offset:     m.offset,
	}, nil
}
