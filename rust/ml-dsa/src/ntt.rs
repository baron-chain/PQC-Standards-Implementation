//! Number Theoretic Transform (NTT) for ML-DSA (FIPS 204).
//!
//! Uses the primitive 512th root of unity zeta = 1753 (mod q = 8380417).
//! Since 512 divides (q - 1), the NTT reduces degree-255 polynomials all the
//! way down to individual coefficients, so pointwise multiplication in the NTT
//! domain is simple element-by-element multiplication.

use crate::field::{self, Q};

/// Primitive 512th root of unity modulo q.
/// 1753^256 ≡ -1 (mod q) and 1753^512 ≡ 1 (mod q).
const ZETA: u32 = 1753;

/// Bit-reverse an 8-bit integer.
const fn bitrev8(x: u8) -> u8 {
    let mut r = 0u8;
    let mut v = x;
    let mut i = 0;
    while i < 8 {
        r = (r << 1) | (v & 1);
        v >>= 1;
        i += 1;
    }
    r
}

/// Modular exponentiation at compile time.
const fn pow_mod(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    let mut result = 1u64;
    base %= modulus;
    while exp > 0 {
        if exp & 1 == 1 {
            result = result * base % modulus;
        }
        exp >>= 1;
        base = base * base % modulus;
    }
    result
}

/// Precomputed table of zeta powers used by the NTT.
///
/// `ZETAS[i] = zeta^{bitrev8(i)} mod q` for i in 0..256.
///
/// Entry 0 (= zeta^0 = 1) is included but not actually used
/// in the butterfly loop; the NTT loop starts its zeta index at 1.
const ZETAS: [u32; 256] = {
    let mut table = [0u32; 256];
    let q = Q as u64;
    let z = ZETA as u64;
    let mut i = 0usize;
    while i < 256 {
        let br = bitrev8(i as u8) as u64;
        table[i] = pow_mod(z, br, q) as u32;
        i += 1;
    }
    table
};

/// In-place forward NTT (Cooley-Tukey butterfly).
///
/// Input: polynomial coefficients f[0..256] in normal order, each in [0, q).
/// Output: NTT representation in place.
///
/// This follows the ML-DSA / Dilithium reference NTT structure.
pub fn ntt(f: &mut [u32; 256]) {
    let mut k: usize = 0; // index into ZETAS, starts at 0 and increments
    let mut len: usize = 128;

    while len >= 1 {
        let mut start: usize = 0;
        while start < 256 {
            k += 1;
            let zeta = ZETAS[k] as u64;
            let mut j = start;
            while j < start + len {
                let t = ((zeta * f[j + len] as u64) % Q as u64) as u32;
                f[j + len] = field::field_sub(f[j], t);
                f[j] = field::field_add(f[j], t);
                j += 1;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// In-place inverse NTT (Gentleman-Sande butterfly).
///
/// Input: NTT-domain representation f[0..256], each in [0, q).
/// Output: polynomial coefficients in normal order, each in [0, q).
///
/// Multiplies every coefficient by n^{-1} = 256^{-1} mod q at the end.
pub fn ntt_inverse(f: &mut [u32; 256]) {
    let mut k: usize = 256; // index into ZETAS, decrements
    let mut len: usize = 1;

    while len < 256 {
        let mut start: usize = 0;
        while start < 256 {
            k -= 1;
            let zeta = (Q - ZETAS[k]) as u64;
            let mut j = start;
            while j < start + len {
                let t = f[j];
                f[j] = field::field_add(t, f[j + len]);
                f[j + len] = field::field_sub(t, f[j + len]);
                f[j + len] = ((zeta * f[j + len] as u64) % Q as u64) as u32;
                j += 1;
            }
            start += 2 * len;
        }
        len <<= 1;
    }

    // Multiply every coefficient by 256^{-1} mod q.
    let inv = field::INV_256 as u64;
    let q64 = Q as u64;
    for coeff in f.iter_mut() {
        *coeff = ((inv * (*coeff as u64)) % q64) as u32;
    }
}

/// Pointwise (coefficient-wise) multiplication in the NTT domain.
///
/// Since the ML-DSA NTT fully reduces to individual elements (512 | (q-1)),
/// multiplication is simply element-by-element mod q.
pub fn pointwise_mul(a: &[u32; 256], b: &[u32; 256]) -> [u32; 256] {
    let mut c = [0u32; 256];
    for i in 0..256 {
        c[i] = field::field_mul(a[i], b[i]);
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zetas_range() {
        // Every zeta value must be in [0, q).
        for (i, &z) in ZETAS.iter().enumerate() {
            assert!(z < Q, "ZETAS[{i}] = {z} is out of range");
        }
    }

    #[test]
    fn test_zetas_first_entries() {
        // ZETAS[0] = zeta^bitrev8(0) = zeta^0 = 1
        assert_eq!(ZETAS[0], 1);
        // ZETAS[1] = zeta^bitrev8(1) = zeta^128
        let expected = field::field_pow(ZETA, 128);
        assert_eq!(ZETAS[1], expected);
    }

    #[test]
    fn test_zeta_is_512th_root() {
        // zeta^512 = 1 mod q
        assert_eq!(field::field_pow(ZETA, 512), 1);
        // zeta^256 = q - 1 = -1 mod q
        assert_eq!(field::field_pow(ZETA, 256), Q - 1);
    }

    #[test]
    fn test_ntt_roundtrip_zero() {
        let mut f = [0u32; 256];
        ntt(&mut f);
        ntt_inverse(&mut f);
        for &c in f.iter() {
            assert_eq!(c, 0);
        }
    }

    #[test]
    fn test_ntt_roundtrip_constant() {
        // A constant polynomial: f(x) = 42
        let mut f = [0u32; 256];
        f[0] = 42;
        let original = f;

        ntt(&mut f);
        ntt_inverse(&mut f);

        for i in 0..256 {
            assert_eq!(f[i], original[i], "mismatch at index {i}");
        }
    }

    #[test]
    fn test_ntt_roundtrip_arbitrary() {
        // Fill with arbitrary values in [0, q)
        let mut f = [0u32; 256];
        for i in 0..256 {
            f[i] = ((i as u64 * 7 + 13) % Q as u64) as u32;
        }
        let original = f;

        ntt(&mut f);
        ntt_inverse(&mut f);

        for i in 0..256 {
            assert_eq!(f[i], original[i], "mismatch at index {i}");
        }
    }

    #[test]
    fn test_pointwise_mul_identity() {
        // Multiplying NTT(1, 0, 0, ...) by NTT(a) should give NTT(a)
        let mut one = [0u32; 256];
        one[0] = 1;
        ntt(&mut one);

        let mut a = [0u32; 256];
        for i in 0..256 {
            a[i] = ((i as u64 * 3 + 5) % Q as u64) as u32;
        }
        let a_copy = a;
        ntt(&mut a);

        let mut result = pointwise_mul(&one, &a);
        ntt_inverse(&mut result);

        for i in 0..256 {
            assert_eq!(result[i], a_copy[i], "mismatch at index {i}");
        }
    }

    #[test]
    fn test_ntt_convolution() {
        // Verify that pointwise multiplication in NTT domain corresponds to
        // polynomial multiplication modulo x^256 + 1.
        //
        // Use small polynomials: a(x) = 1 + x, b(x) = 1 + x
        // a*b mod (x^256 + 1) = 1 + 2x + x^2 (since x^2 doesn't wrap)
        let mut a = [0u32; 256];
        a[0] = 1;
        a[1] = 1;
        let mut b = [0u32; 256];
        b[0] = 1;
        b[1] = 1;

        ntt(&mut a);
        ntt(&mut b);
        let mut c = pointwise_mul(&a, &b);
        ntt_inverse(&mut c);

        assert_eq!(c[0], 1); // constant term
        assert_eq!(c[1], 2); // x coefficient
        assert_eq!(c[2], 1); // x^2 coefficient
        for i in 3..256 {
            assert_eq!(c[i], 0, "unexpected nonzero at index {i}");
        }
    }

    #[test]
    fn test_ntt_convolution_wrapping() {
        // Test wrapping: a(x) = x^255, b(x) = x
        // a*b = x^256 ≡ -1 mod (x^256 + 1)
        // So result should be (q-1, 0, 0, ..., 0).
        let mut a = [0u32; 256];
        a[255] = 1;
        let mut b = [0u32; 256];
        b[1] = 1;

        ntt(&mut a);
        ntt(&mut b);
        let mut c = pointwise_mul(&a, &b);
        ntt_inverse(&mut c);

        assert_eq!(c[0], Q - 1, "constant term should be -1 mod q");
        for i in 1..256 {
            assert_eq!(c[i], 0, "nonzero at index {i}");
        }
    }
}
