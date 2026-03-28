package mlkem

import (
	"crypto/subtle"
	"errors"
	"io"

	"github.com/liviuepure/PQC-Standards-Implementation/go/internal/hash"
	"github.com/liviuepure/PQC-Standards-Implementation/go/internal/params"
)

// KeyGen implements ML-KEM.KeyGen (FIPS 203 Algorithm 16).
// It generates an encapsulation key and decapsulation key using randomness from rng.
func KeyGen(p params.ParameterSet, rng io.Reader) (ek []byte, dk []byte, err error) {
	var d, z [32]byte
	if _, err = io.ReadFull(rng, d[:]); err != nil {
		return nil, nil, errors.New("mlkem: failed to read random bytes for d")
	}
	if _, err = io.ReadFull(rng, z[:]); err != nil {
		return nil, nil, errors.New("mlkem: failed to read random bytes for z")
	}

	ek, dk = KeyGenInternal(p, d, z)
	return ek, dk, nil
}

// KeyGenInternal is a deterministic version of KeyGen for testing.
// Given seeds d and z, it produces the same keys every time.
func KeyGenInternal(p params.ParameterSet, d, z [32]byte) (ek []byte, dk []byte) {
	ekPKE, dkPKE := KPKEKeyGen(p, d)

	// ek = ekPKE
	ek = ekPKE

	// dk = dkPKE || ekPKE || H(ekPKE) || z
	hEk := hash.H(ekPKE)
	dk = make([]byte, 0, len(dkPKE)+len(ekPKE)+32+32)
	dk = append(dk, dkPKE...)
	dk = append(dk, ekPKE...)
	dk = append(dk, hEk[:]...)
	dk = append(dk, z[:]...)

	return ek, dk
}

// Encapsulate implements ML-KEM.Encaps (FIPS 203 Algorithm 17).
// It produces a shared secret and ciphertext from an encapsulation key.
func Encapsulate(p params.ParameterSet, ek []byte, rng io.Reader) (sharedSecret [32]byte, ct []byte, err error) {
	var m [32]byte
	if _, err = io.ReadFull(rng, m[:]); err != nil {
		return [32]byte{}, nil, errors.New("mlkem: failed to read random bytes for m")
	}

	sharedSecret, ct = EncapsulateInternal(p, ek, m)
	return sharedSecret, ct, nil
}

// EncapsulateInternal is a deterministic version of Encapsulate for testing.
func EncapsulateInternal(p params.ParameterSet, ek []byte, m [32]byte) (sharedSecret [32]byte, ct []byte) {
	// (K, r) = G(m || H(ek))
	hEk := hash.H(ek)
	gInput := make([]byte, 64)
	copy(gInput[:32], m[:])
	copy(gInput[32:], hEk[:])

	K, r := hash.G(gInput)

	// ct = KPKEEncrypt(ek, m, r)
	ct = KPKEEncrypt(p, ek, m, r)

	sharedSecret = K
	return sharedSecret, ct
}

// Decapsulate implements ML-KEM.Decaps (FIPS 203 Algorithm 18).
// It recovers the shared secret from a ciphertext using the decapsulation key.
func Decapsulate(p params.ParameterSet, dk []byte, ct []byte) [32]byte {
	k := p.K

	// Parse dk = dkPKE || ekPKE || h || z
	dkPKELen := 384 * k
	ekPKELen := 384*k + 32

	dkPKE := dk[:dkPKELen]
	ekPKE := dk[dkPKELen : dkPKELen+ekPKELen]
	h := dk[dkPKELen+ekPKELen : dkPKELen+ekPKELen+32]
	z := dk[dkPKELen+ekPKELen+32 : dkPKELen+ekPKELen+64]

	// m' = KPKEDecrypt(dkPKE, ct)
	mPrime := KPKEDecrypt(p, dkPKE, ct)

	// (K', r') = G(m' || h)
	gInput := make([]byte, 64)
	copy(gInput[:32], mPrime[:])
	copy(gInput[32:], h)

	KPrime, rPrime := hash.G(gInput)

	// K_bar = J(z || ct)
	jInput := make([]byte, 32+len(ct))
	copy(jInput[:32], z)
	copy(jInput[32:], ct)
	KBar := hash.J(jInput)

	// ct' = KPKEEncrypt(ekPKE, m', r')
	ctPrime := KPKEEncrypt(p, ekPKE, mPrime, rPrime)

	// Constant-time comparison: if ct == ct' return K' else return K_bar
	match := subtle.ConstantTimeCompare(ct, ctPrime)

	// Constant-time select: result = K' if match == 1, else K_bar
	var result [32]byte
	for i := 0; i < 32; i++ {
		result[i] = byte(subtle.ConstantTimeSelect(match, int(KPrime[i]), int(KBar[i])))
	}

	return result
}
