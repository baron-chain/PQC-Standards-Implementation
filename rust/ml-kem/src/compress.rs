//! Compression and decompression for ML-KEM.
//!
//! FIPS 203, Section 4.2.1.
//!
//! Compression reduces the bit-width of field elements for ciphertext
//! compactness. Decompression approximately recovers the original value.
//! This is lossy: Decompress(Compress(x)) ≈ x but not exactly.

use pqc_common::field::{FieldElement, Q};

/// Compress a field element to d bits.
///
/// Computes: round((2^d / q) * x) mod 2^d
/// FIPS 203, Equation 4.7.
#[inline]
pub fn compress<const D: usize>(x: FieldElement) -> u16 {
    let x = x.value() as u64;
    let shifted = (x << D) + (Q as u64 / 2); // add q/2 for rounding
    let result = shifted / Q as u64;
    (result & ((1u64 << D) - 1)) as u16
}

/// Decompress a d-bit value back to a field element.
///
/// Computes: round((q / 2^d) * y)
/// FIPS 203, Equation 4.8.
#[inline]
pub fn decompress<const D: usize>(y: u16) -> FieldElement {
    let y = y as u64;
    let result = (y * Q as u64 + (1u64 << (D - 1))) >> D;
    FieldElement::new(result as u16)
}

/// Compress a polynomial (256 coefficients) to d bits each.
pub fn compress_poly<const D: usize>(f: &[FieldElement; 256]) -> [u16; 256] {
    let mut out = [0u16; 256];
    for i in 0..256 {
        out[i] = compress::<D>(f[i]);
    }
    out
}

/// Decompress a polynomial (256 compressed values) back to field elements.
pub fn decompress_poly<const D: usize>(c: &[u16; 256]) -> [FieldElement; 256] {
    let mut out = [FieldElement::ZERO; 256];
    for i in 0..256 {
        out[i] = decompress::<D>(c[i]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_d1() {
        assert_eq!(compress::<1>(FieldElement::new(0)), 0);
        // q/2 ≈ 1665 rounds to 1
        assert_eq!(compress::<1>(FieldElement::new(1665)), 1);
    }

    #[test]
    fn test_compress_range() {
        for x in 0..Q {
            let c10 = compress::<10>(FieldElement::new(x));
            assert!(c10 < 1024, "compress<10>({x}) = {c10} out of range");
            let c4 = compress::<4>(FieldElement::new(x));
            assert!(c4 < 16, "compress<4>({x}) = {c4} out of range");
            let c11 = compress::<11>(FieldElement::new(x));
            assert!(c11 < 2048, "compress<11>({x}) = {c11} out of range");
            let c5 = compress::<5>(FieldElement::new(x));
            assert!(c5 < 32, "compress<5>({x}) = {c5} out of range");
        }
    }

    #[test]
    fn test_roundtrip_d4() {
        for x in 0..Q {
            let c = compress::<4>(FieldElement::new(x));
            let d = decompress::<4>(c);
            let diff = if d.value() > x {
                d.value() - x
            } else {
                x - d.value()
            };
            let diff = core::cmp::min(diff, Q - diff);
            // Maximum rounding error for d=4: q/(2^5) ≈ 104
            assert!(diff <= 105, "too much error at x={x}: diff={diff}");
        }
    }

    #[test]
    fn test_roundtrip_d10() {
        for x in 0..Q {
            let c = compress::<10>(FieldElement::new(x));
            let d = decompress::<10>(c);
            let diff = if d.value() > x {
                d.value() - x
            } else {
                x - d.value()
            };
            let diff = core::cmp::min(diff, Q - diff);
            // Maximum rounding error for d=10: q/(2^11) ≈ 2
            assert!(diff <= 2, "too much error at x={x}: diff={diff}");
        }
    }
}
