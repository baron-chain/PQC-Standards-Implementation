// Package sampling implements the sampling algorithms from FIPS 203 (ML-KEM).
package sampling

import (
	"github.com/liviuepure/PQC-Standards-Implementation/go/internal/field"
	"golang.org/x/crypto/sha3"
)

// SamplePolyCBD implements FIPS 203 Algorithm 8 (SamplePolyCBD_eta).
// It samples a polynomial from the centered binomial distribution.
// The input bytes must have length 64*eta.
func SamplePolyCBD(eta int, bytes []byte) [256]field.Element {
	var f [256]field.Element

	switch eta {
	case 2:
		// Each coefficient uses 2*eta = 4 bits total: 2 bits for x, 2 bits for y.
		// Process byte by byte; each byte yields 2 coefficients.
		for i := 0; i < 256; i += 2 {
			b := bytes[i/2]
			// First coefficient: bits 0,1 for x; bits 2,3 for y
			x := int16((b >> 0) & 1) + int16((b>>1)&1)
			y := int16((b >> 2) & 1) + int16((b>>3)&1)
			f[i] = field.FromI16(x - y)

			// Second coefficient: bits 4,5 for x; bits 6,7 for y
			x = int16((b >> 4) & 1) + int16((b>>5)&1)
			y = int16((b >> 6) & 1) + int16((b>>7)&1)
			f[i+1] = field.FromI16(x - y)
		}
	case 3:
		// Each coefficient uses 2*eta = 6 bits total: 3 bits for x, 3 bits for y.
		// We work at the bit level.
		bits := bytesToBits(bytes)
		for i := 0; i < 256; i++ {
			var x, y int16
			for j := 0; j < eta; j++ {
				x += int16(bits[6*i+j])
				y += int16(bits[6*i+eta+j])
			}
			f[i] = field.FromI16(x - y)
		}
	}

	return f
}

// bytesToBits converts a byte slice into a slice of individual bits (LSB first).
func bytesToBits(data []byte) []byte {
	bits := make([]byte, len(data)*8)
	for i, b := range data {
		for j := 0; j < 8; j++ {
			bits[i*8+j] = (b >> uint(j)) & 1
		}
	}
	return bits
}

// SampleNTT implements FIPS 203 Algorithm 7 (SampleNTT).
// It performs rejection sampling from SHAKE-128 output to produce
// a polynomial in NTT representation with coefficients in [0, q).
func SampleNTT(seed [34]byte) [256]field.Element {
	var a [256]field.Element

	h := sha3.NewShake128()
	h.Write(seed[:])

	buf := make([]byte, 3)
	j := 0
	for j < 256 {
		h.Read(buf)
		d1 := uint16(buf[0]) | (uint16(buf[1]&0x0F) << 8)
		d2 := uint16(buf[1]>>4) | (uint16(buf[2]) << 4)

		if d1 < field.Q {
			a[j] = field.Element(d1)
			j++
		}
		if d2 < field.Q && j < 256 {
			a[j] = field.Element(d2)
			j++
		}
	}

	return a
}

// PRF computes SHAKE-256(seed || nonce) and returns the first length bytes.
func PRF(seed [32]byte, nonce byte, length int) []byte {
	h := sha3.NewShake256()
	h.Write(seed[:])
	h.Write([]byte{nonce})

	out := make([]byte, length)
	h.Read(out)
	return out
}
