package mldsa

// BitRev8 reverses the 8 least significant bits of n.
func BitRev8(n int) int {
	var r int
	for i := 0; i < 8; i++ {
		r = (r << 1) | (n & 1)
		n >>= 1
	}
	return r
}

// Zetas contains the precomputed twiddle factors for the ML-DSA NTT.
// Zetas[i] = 1753^BitRev8(i) mod Q.
var Zetas [256]int

func init() {
	for i := 0; i < 256; i++ {
		Zetas[i] = FieldPow(1753, BitRev8(i))
	}
}

// NTT performs the in-place forward Number Theoretic Transform.
// FIPS 204 Algorithm 41 (NTT).
func NTT(f *[256]int) {
	k := 0
	for length := 128; length >= 1; length >>= 1 {
		for start := 0; start < 256; start += 2 * length {
			k++
			zeta := Zetas[k]
			for j := start; j < start+length; j++ {
				t := FieldMul(zeta, f[j+length])
				f[j+length] = FieldSub(f[j], t)
				f[j] = FieldAdd(f[j], t)
			}
		}
	}
}

// NTTInverse performs the in-place inverse NTT.
// FIPS 204 Algorithm 42 (NTT^{-1}).
func NTTInverse(f *[256]int) {
	k := 256
	for length := 1; length <= 128; length <<= 1 {
		for start := 0; start < 256; start += 2 * length {
			k--
			zeta := Zetas[k]
			for j := start; j < start+length; j++ {
				t := f[j]
				f[j] = FieldAdd(t, f[j+length])
				f[j+length] = FieldMul(zeta, FieldSub(f[j+length], t))
			}
		}
	}
	// Multiply by N^{-1} = 256^{-1} mod Q = 8347681.
	const invN = 8347681
	for i := 0; i < 256; i++ {
		f[i] = FieldMul(f[i], invN)
	}
}

// PointwiseMul computes the element-wise product of two NTT-domain polynomials.
func PointwiseMul(a, b [256]int) [256]int {
	var c [256]int
	for i := 0; i < 256; i++ {
		c[i] = FieldMul(a[i], b[i])
	}
	return c
}
