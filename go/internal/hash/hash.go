// Package hash implements the hash functions G, H, and J from FIPS 203 (ML-KEM).
package hash

import (
	"golang.org/x/crypto/sha3"
)

// G computes SHA3-512 of input and splits the result into two 32-byte arrays.
func G(input []byte) ([32]byte, [32]byte) {
	h := sha3.New512()
	h.Write(input)
	digest := h.Sum(nil)

	var a, b [32]byte
	copy(a[:], digest[:32])
	copy(b[:], digest[32:64])
	return a, b
}

// H computes SHA3-256 of input and returns the 32-byte digest.
func H(input []byte) [32]byte {
	h := sha3.New256()
	h.Write(input)
	digest := h.Sum(nil)

	var out [32]byte
	copy(out[:], digest[:32])
	return out
}

// J computes SHAKE-256 of input and returns the first 32 bytes.
func J(input []byte) [32]byte {
	h := sha3.NewShake256()
	h.Write(input)

	var out [32]byte
	h.Read(out[:])
	return out
}
