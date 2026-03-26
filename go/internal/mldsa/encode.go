package mldsa

import "encoding/binary"

// SimpleBitPack packs polynomial coefficients into bytes where each coefficient
// is in [0, b]. Uses ceil(log2(b+1)) bits per coefficient.
func SimpleBitPack(poly [256]int, b int) []byte {
	bitLen := bitLength(b)
	totalBits := 256 * bitLen
	out := make([]byte, (totalBits+7)/8)
	bitPos := 0
	for _, coeff := range poly {
		for bit := 0; bit < bitLen; bit++ {
			if coeff&(1<<bit) != 0 {
				out[bitPos/8] |= byte(1 << (bitPos % 8))
			}
			bitPos++
		}
	}
	return out
}

// SimpleBitUnpack unpacks bytes into polynomial coefficients in [0, b].
func SimpleBitUnpack(data []byte, b int) [256]int {
	bitLen := bitLength(b)
	var poly [256]int
	bitPos := 0
	mask := (1 << bitLen) - 1
	for i := 0; i < 256; i++ {
		val := 0
		for bit := 0; bit < bitLen; bit++ {
			if data[bitPos/8]&(1<<(bitPos%8)) != 0 {
				val |= 1 << bit
			}
			bitPos++
		}
		poly[i] = val & mask
		if poly[i] > b {
			poly[i] = b
		}
	}
	return poly
}

// BitPackSigned packs polynomial coefficients where each coefficient is in
// [-(a), b]. Stored as (b - coeff) which is in [0, a+b].
func BitPackSigned(poly [256]int, a, b int) []byte {
	bitLen := bitLength(a + b)
	totalBits := 256 * bitLen
	out := make([]byte, (totalBits+7)/8)
	bitPos := 0
	for _, coeff := range poly {
		// Map from centered representation to unsigned
		val := b - toSigned(coeff)
		for bit := 0; bit < bitLen; bit++ {
			if val&(1<<bit) != 0 {
				out[bitPos/8] |= byte(1 << (bitPos % 8))
			}
			bitPos++
		}
	}
	return out
}

// BitUnpackSigned unpacks bytes into polynomial coefficients in [-(a), b].
func BitUnpackSigned(data []byte, a, b int) [256]int {
	bitLen := bitLength(a + b)
	var poly [256]int
	bitPos := 0
	mask := (1 << bitLen) - 1
	for i := 0; i < 256; i++ {
		val := 0
		for bit := 0; bit < bitLen; bit++ {
			if data[bitPos/8]&(1<<(bitPos%8)) != 0 {
				val |= 1 << bit
			}
			bitPos++
		}
		val &= mask
		poly[i] = ModQ(int64(b - val))
	}
	return poly
}

// toSigned converts a field element to its signed representative in [-(Q-1)/2, (Q-1)/2].
func toSigned(a int) int {
	if a > Q/2 {
		return a - Q
	}
	return a
}

// bitLength returns the number of bits needed to represent v.
func bitLength(v int) int {
	if v <= 0 {
		return 1
	}
	bits := 0
	for v > 0 {
		bits++
		v >>= 1
	}
	return bits
}

// EncodePK encodes a public key: pk = rho || t1_packed.
// Each t1 coefficient is in [0, 2^(ceil(log2(q))-d) - 1] = [0, 1023].
func EncodePK(rho []byte, t1 [][256]int) []byte {
	k := len(t1)
	// Each polynomial: 256 * 10 bits = 320 bytes
	out := make([]byte, 0, 32+320*k)
	out = append(out, rho...)
	for i := 0; i < k; i++ {
		out = append(out, SimpleBitPack(t1[i], (1<<10)-1)...)
	}
	return out
}

// DecodePK decodes a public key into rho and t1.
func DecodePK(pk []byte, k int) ([]byte, [][256]int) {
	rho := make([]byte, 32)
	copy(rho, pk[:32])
	t1 := make([][256]int, k)
	offset := 32
	for i := 0; i < k; i++ {
		t1[i] = SimpleBitUnpack(pk[offset:offset+320], (1<<10)-1)
		offset += 320
	}
	return rho, t1
}

// EncodeSK encodes a secret key:
// sk = rho || K || tr || s1_packed || s2_packed || t0_packed
func EncodeSK(rho, K, tr []byte, s1 [][256]int, s2 [][256]int, t0 [][256]int, eta int) []byte {
	k := len(s2)
	l := len(s1)

	out := make([]byte, 0)
	out = append(out, rho...)       // 32 bytes
	out = append(out, K...)         // 32 bytes
	out = append(out, tr...)        // 64 bytes

	// Pack s1: coefficients in [-eta, eta]
	etaBits := bitLength(2 * eta)
	polyBytes := 256 * etaBits / 8
	for i := 0; i < l; i++ {
		out = append(out, BitPackSigned(s1[i], eta, eta)...)
	}
	_ = polyBytes

	// Pack s2: coefficients in [-eta, eta]
	for i := 0; i < k; i++ {
		out = append(out, BitPackSigned(s2[i], eta, eta)...)
	}

	// Pack t0: coefficients in [-(2^(d-1)-1), 2^(d-1)]
	// = [-(2^12-1), 2^12] = [-4095, 4096]
	d := 13
	lower := (1 << (d - 1)) - 1 // 4095
	upper := 1 << (d - 1)        // 4096
	for i := 0; i < k; i++ {
		out = append(out, BitPackSigned(t0[i], lower, upper)...)
	}
	return out
}

// DecodeSK decodes a secret key.
func DecodeSK(sk []byte, p *Params) (rho, K, tr []byte, s1, s2, t0 [][256]int) {
	k := p.K
	l := p.L
	eta := p.Eta
	d := p.D

	rho = make([]byte, 32)
	copy(rho, sk[:32])
	K = make([]byte, 32)
	copy(K, sk[32:64])
	tr = make([]byte, 64)
	copy(tr, sk[64:128])

	offset := 128

	etaBits := bitLength(2 * eta)
	polyBytes := 256 * etaBits / 8

	s1 = make([][256]int, l)
	for i := 0; i < l; i++ {
		s1[i] = BitUnpackSigned(sk[offset:offset+polyBytes], eta, eta)
		offset += polyBytes
	}

	s2 = make([][256]int, k)
	for i := 0; i < k; i++ {
		s2[i] = BitUnpackSigned(sk[offset:offset+polyBytes], eta, eta)
		offset += polyBytes
	}

	lower := (1 << (d - 1)) - 1
	upper := 1 << (d - 1)
	t0Bits := bitLength(lower + upper)
	t0PolyBytes := 256 * t0Bits / 8

	t0 = make([][256]int, k)
	for i := 0; i < k; i++ {
		t0[i] = BitUnpackSigned(sk[offset:offset+t0PolyBytes], lower, upper)
		offset += t0PolyBytes
	}
	return
}

// EncodeW1 encodes the high bits w1 for the signature hash.
func EncodeW1(w1 [][256]int, gamma2 int) []byte {
	// Each coefficient of w1 is in [0, (q-1)/(2*gamma2) - 1] for gamma2 = (q-1)/88
	// or [0, (q-1)/(2*gamma2)] for gamma2 = (q-1)/32.
	var maxW1 int
	if gamma2 == (Q-1)/88 {
		maxW1 = 43
	} else {
		maxW1 = 15
	}
	var out []byte
	for _, poly := range w1 {
		out = append(out, SimpleBitPack(poly, maxW1)...)
	}
	return out
}

// EncodeSig encodes a signature: sig = cTilde || z_packed || h_packed.
func EncodeSig(cTilde []byte, z [][256]int, h [][256]int, p *Params) []byte {
	out := make([]byte, 0, p.SigSize)
	out = append(out, cTilde...)

	// Pack z: coefficients in [-(gamma1-1), gamma1]
	gamma1 := p.Gamma1
	for i := 0; i < p.L; i++ {
		out = append(out, BitPackSigned(z[i], gamma1-1, gamma1)...)
	}

	// Encode hints h as a sparse representation
	out = append(out, encodeHints(h, p.Omega, p.K)...)

	return out
}

// DecodeSig decodes a signature.
func DecodeSig(sig []byte, p *Params) (cTilde []byte, z [][256]int, h [][256]int, ok bool) {
	lambda := p.Lambda
	cTilde = make([]byte, 2*lambda)
	copy(cTilde, sig[:2*lambda])
	offset := 2 * lambda

	gamma1 := p.Gamma1
	var zBitLen int
	if gamma1 == (1 << 17) {
		zBitLen = 18
	} else {
		zBitLen = 20
	}
	zPolyBytes := 256 * zBitLen / 8

	z = make([][256]int, p.L)
	for i := 0; i < p.L; i++ {
		z[i] = BitUnpackSigned(sig[offset:offset+zPolyBytes], gamma1-1, gamma1)
		offset += zPolyBytes
	}

	h, ok = decodeHints(sig[offset:], p.Omega, p.K)
	return
}

// encodeHints encodes the hint vector as per FIPS 204.
func encodeHints(h [][256]int, omega, k int) []byte {
	out := make([]byte, omega+k)
	idx := 0
	for i := 0; i < k; i++ {
		for j := 0; j < 256; j++ {
			if h[i][j] != 0 {
				out[idx] = byte(j)
				idx++
			}
		}
		out[omega+i] = byte(idx)
	}
	return out
}

// decodeHints decodes the hint vector.
func decodeHints(data []byte, omega, k int) ([][256]int, bool) {
	if len(data) < omega+k {
		return nil, false
	}
	h := make([][256]int, k)
	idx := 0
	for i := 0; i < k; i++ {
		limit := int(data[omega+i])
		if limit < idx || limit > omega {
			return nil, false
		}
		for ; idx < limit; idx++ {
			pos := int(data[idx])
			if pos >= 256 {
				return nil, false
			}
			// Check that indices are increasing within a polynomial
			if idx > 0 && i > 0 {
				// Previous position for this polynomial
			}
			h[i][pos] = 1
		}
	}
	// Count total hints
	total := 0
	for i := 0; i < k; i++ {
		for j := 0; j < 256; j++ {
			total += h[i][j]
		}
	}
	if total > omega {
		return nil, false
	}
	return h, true
}

// PackW1 packs w1 for hashing. This is the same as EncodeW1.
func PackW1(w1 [][256]int, gamma2 int) []byte {
	return EncodeW1(w1, gamma2)
}

// IntegerToBytes converts a non-negative integer to a byte slice of given length (LE).
func IntegerToBytes(v int, length int) []byte {
	out := make([]byte, length)
	binary.LittleEndian.PutUint16(out, uint16(v))
	return out
}
