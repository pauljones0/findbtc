package detector

import (
	"errors"
	"math/big"
)

// Minimal secp256k1 for BIP32 public child derivation (CKDpub). Only what
// watch-only derivation needs: compressed-point parsing, point addition, and
// scalar multiplication. Verified against the published BIP32 test vectors
// (see TestCKDPubVectors); no private-key operations exist in this file.

// Field prime p = 2^256 - 2^32 - 977.
var secpP = func() *big.Int {
	p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	return p
}()

// Curve order n.
var secpN = func() *big.Int {
	n, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	return n
}()

// Generator G (compressed 0279BE667E...).
var secpGx = func() *big.Int {
	x, _ := new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	return x
}()

var secpGy = func() *big.Int {
	y, _ := new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
	return y
}()

// secpPoint is an affine curve point; nil x,y is the point at infinity.
type secpPoint struct {
	x, y *big.Int
}

func secpInfinity() secpPoint { return secpPoint{} }

func (p secpPoint) isInfinity() bool { return p.x == nil }

// secpAdd returns p+q on the curve (a=0, so doubling needs no a term).
func secpAdd(p, q secpPoint) secpPoint {
	if p.isInfinity() {
		return q
	}
	if q.isInfinity() {
		return p
	}
	var lambda *big.Int
	if p.x.Cmp(q.x) == 0 {
		if p.y.Cmp(q.y) != 0 {
			return secpInfinity()
		}
		// Doubling: lambda = 3x^2 / 2y.
		num := new(big.Int).Mul(p.x, p.x)
		num.Mul(num, big.NewInt(3))
		num.Mod(num, secpP)
		den := new(big.Int).Lsh(p.y, 1)
		den.Mod(den, secpP)
		lambda = new(big.Int).ModInverse(den, secpP)
		if lambda == nil {
			return secpInfinity()
		}
		lambda.Mul(lambda, num)
		lambda.Mod(lambda, secpP)
	} else {
		// Addition: lambda = (qy-py) / (qx-px).
		num := new(big.Int).Sub(q.y, p.y)
		num.Mod(num, secpP)
		den := new(big.Int).Sub(q.x, p.x)
		den.Mod(den, secpP)
		lambda = new(big.Int).ModInverse(den, secpP)
		if lambda == nil {
			return secpInfinity()
		}
		lambda.Mul(lambda, num)
		lambda.Mod(lambda, secpP)
	}
	x := new(big.Int).Mul(lambda, lambda)
	x.Sub(x, p.x)
	x.Sub(x, q.x)
	x.Mod(x, secpP)
	y := new(big.Int).Sub(p.x, x)
	y.Mul(y, lambda)
	y.Sub(y, p.y)
	y.Mod(y, secpP)
	return secpPoint{x, y}
}

// secpMul returns k*p by double-and-add. k is reduced mod n first.
func secpMul(k *big.Int, p secpPoint) secpPoint {
	k = new(big.Int).Mod(k, secpN)
	r := secpInfinity()
	for i := k.BitLen() - 1; i >= 0; i-- {
		r = secpAdd(r, r)
		if k.Bit(i) == 1 {
			r = secpAdd(r, p)
		}
	}
	return r
}

// secpGenerator returns the base point G.
func secpGenerator() secpPoint {
	return secpPoint{new(big.Int).Set(secpGx), new(big.Int).Set(secpGy)}
}

// secpParseCompressed decodes a 33-byte compressed public key, verifying it
// lies on the curve (p = 3 mod 4, so sqrt is a^((p+1)/4)).
func secpParseCompressed(key []byte) (secpPoint, error) {
	if len(key) != 33 || (key[0] != 0x02 && key[0] != 0x03) {
		return secpPoint{}, errors.New("not a compressed public key")
	}
	x := new(big.Int).SetBytes(key[1:])
	if x.Cmp(secpP) >= 0 {
		return secpPoint{}, errors.New("public key x out of range")
	}
	// y^2 = x^3 + 7.
	y2 := new(big.Int).Mul(x, x)
	y2.Mod(y2, secpP)
	y2.Mul(y2, x)
	y2.Add(y2, big.NewInt(7))
	y2.Mod(y2, secpP)
	exp := new(big.Int).Add(secpP, big.NewInt(1))
	exp.Rsh(exp, 2)
	y := new(big.Int).Exp(y2, exp, secpP)
	// Verify the root (invalid keys fail here).
	check := new(big.Int).Mul(y, y)
	check.Mod(check, secpP)
	if check.Cmp(y2) != 0 {
		return secpPoint{}, errors.New("public key not on curve")
	}
	if y.Bit(0) != uint(key[0]&1) {
		y.Sub(secpP, y)
	}
	return secpPoint{x, y}, nil
}

// secpSerializeCompressed encodes a curve point in 33-byte compressed form.
func secpSerializeCompressed(p secpPoint) ([]byte, error) {
	if p.isInfinity() {
		return nil, errors.New("cannot serialize point at infinity")
	}
	out := make([]byte, 33)
	out[0] = 0x02 | byte(p.y.Bit(0))
	xb := p.x.Bytes()
	copy(out[33-len(xb):], xb)
	return out, nil
}
