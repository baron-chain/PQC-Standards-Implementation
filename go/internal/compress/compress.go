// Package compress implements Compress and Decompress per FIPS 203 Equations 4.7 and 4.8.
package compress

import (
	"github.com/liviuepure/PQC-Standards-Implementation/go/internal/field"
)

// Compress computes Compress_d(x) = round((2^d / q) * x) mod 2^d.
// FIPS 203 Eq 4.7.
func Compress(d int, x field.Element) uint16 {
	// round((2^d * x) / q) mod 2^d
	// = ((2^d * x + q/2) / q) mod 2^d  (using integer division for rounding)
	shifted := (uint64(x.Value()) << d) + uint64(field.Q)/2
	result := shifted / uint64(field.Q)
	return uint16(result) & ((1 << d) - 1)
}

// Decompress computes Decompress_d(y) = round((q / 2^d) * y).
// FIPS 203 Eq 4.8.
func Decompress(d int, y uint16) field.Element {
	// round((q * y) / 2^d) = (q * y + 2^(d-1)) / 2^d  (integer division for rounding)
	val := (uint64(field.Q)*uint64(y) + (1 << (d - 1))) >> d
	return field.New(uint16(val))
}
