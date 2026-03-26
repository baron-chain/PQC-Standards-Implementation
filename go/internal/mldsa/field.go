// Package mldsa implements internal functions for ML-DSA (FIPS 204).
package mldsa

// Q is the ML-DSA prime modulus.
const Q = 8380417

// ModQ reduces a (possibly negative) int64 to [0, Q).
func ModQ(a int64) int {
	r := int(a % int64(Q))
	if r < 0 {
		r += Q
	}
	return r
}

// FieldAdd returns (a + b) mod Q with inputs in [0, Q).
func FieldAdd(a, b int) int {
	r := a + b
	if r >= Q {
		r -= Q
	}
	return r
}

// FieldSub returns (a - b) mod Q with inputs in [0, Q).
func FieldSub(a, b int) int {
	r := a - b
	if r < 0 {
		r += Q
	}
	return r
}

// FieldMul returns (a * b) mod Q. Uses int64 intermediates to avoid overflow.
func FieldMul(a, b int) int {
	return int(int64(a) * int64(b) % int64(Q))
}

// FieldPow returns a^e mod Q by repeated squaring.
func FieldPow(a, e int) int {
	result := int64(1)
	base := int64(a) % int64(Q)
	exp := e
	for exp > 0 {
		if exp&1 == 1 {
			result = result * base % int64(Q)
		}
		exp >>= 1
		base = base * base % int64(Q)
	}
	return int(result)
}

// FieldInv returns the modular inverse of a mod Q using Fermat's little theorem.
func FieldInv(a int) int {
	return FieldPow(a, Q-2)
}
