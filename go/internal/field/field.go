// Package field implements finite field arithmetic over Z_q where q = 3329.
//
// Used by ML-KEM (FIPS 203) and ML-DSA (FIPS 204).
package field

// Q is the ML-KEM prime modulus.
const Q = 3329

// Element represents a field element in Z_q.
// Values are always in the canonical range [0, q).
type Element uint16

// New creates a field element, reducing modulo q.
func New(v uint16) Element {
	return Element(v % Q)
}

// FromI16 creates a field element from a potentially negative value.
func FromI16(v int16) Element {
	r := int32(v) % Q
	if r < 0 {
		r += Q
	}
	return Element(r)
}

// Value returns the canonical representative in [0, q).
func (a Element) Value() uint16 {
	return uint16(a)
}

// Add returns a + b mod q.
func (a Element) Add(b Element) Element {
	sum := uint16(a) + uint16(b)
	if sum >= Q {
		sum -= Q
	}
	return Element(sum)
}

// Sub returns a - b mod q.
func (a Element) Sub(b Element) Element {
	if uint16(a) >= uint16(b) {
		return Element(uint16(a) - uint16(b))
	}
	return Element(uint16(a) + Q - uint16(b))
}

// Mul returns a * b mod q.
func (a Element) Mul(b Element) Element {
	product := uint32(a) * uint32(b)
	return Element(product % Q)
}

// Neg returns -a mod q.
func (a Element) Neg() Element {
	if a == 0 {
		return 0
	}
	return Element(Q - uint16(a))
}
