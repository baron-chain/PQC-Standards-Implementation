//! Sampling functions for ML-KEM.
//!
//! FIPS 203, Algorithms 7 (SampleNTT) and 8 (SamplePolyCBD).
//!
//! - SampleNTT: rejection sampling from SHAKE-128 to produce a polynomial
//!   in NTT domain with all coefficients < q.
//! - SamplePolyCBD: centered binomial distribution sampling for secret
//!   and error polynomials.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use pqc_common::field::{FieldElement, Q};
use sha3::{Shake128, Shake256, digest::{Update, ExtendableOutput, XofReader}};

/// Sample a polynomial from the Centered Binomial Distribution.
/// FIPS 203, Algorithm 8.
///
/// Input: byte array of length 64*eta.
/// Output: polynomial with coefficients in [-eta, eta] (mod q).
///
/// Each coefficient is computed as the difference of two sums of `eta`
/// random bits, producing values uniformly in [-eta, eta].
pub fn sample_poly_cbd<const ETA: usize>(bytes: &[u8]) -> [FieldElement; 256] {
    debug_assert_eq!(bytes.len(), 64 * ETA);
    let mut f = [FieldElement::ZERO; 256];

    for i in 0..256 {
        let mut x = 0u16;
        let mut y = 0u16;
        for j in 0..ETA {
            let bit_idx = 2 * i * ETA + j;
            let bit = (bytes[bit_idx / 8] >> (bit_idx % 8)) & 1;
            x += bit as u16;
        }
        for j in 0..ETA {
            let bit_idx = 2 * i * ETA + ETA + j;
            let bit = (bytes[bit_idx / 8] >> (bit_idx % 8)) & 1;
            y += bit as u16;
        }
        if x >= y {
            f[i] = FieldElement::new(x - y);
        } else {
            f[i] = FieldElement::new(Q - (y - x));
        }
    }
    f
}

/// Sample a polynomial in NTT domain via rejection sampling from SHAKE-128.
/// FIPS 203, Algorithm 7.
///
/// Input: 34-byte seed (rho || j || i).
/// Output: polynomial in NTT domain with all coefficients in [0, q).
///
/// Reads 3 bytes at a time from SHAKE-128, extracts two 12-bit candidates,
/// and accepts those < q. Typically needs ~575 bytes of SHAKE output.
pub fn sample_ntt(seed: &[u8; 34]) -> [FieldElement; 256] {
    let mut hasher = Shake128::default();
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();

    let mut a_hat = [FieldElement::ZERO; 256];
    let mut j = 0usize;
    let mut buf = [0u8; 3];

    while j < 256 {
        reader.read(&mut buf);
        let d1 = (buf[0] as u16) | (((buf[1] & 0x0F) as u16) << 8);
        let d2 = ((buf[1] >> 4) as u16) | ((buf[2] as u16) << 4);

        if d1 < Q {
            a_hat[j] = FieldElement::new(d1);
            j += 1;
        }
        if d2 < Q && j < 256 {
            a_hat[j] = FieldElement::new(d2);
            j += 1;
        }
    }
    a_hat
}

/// PRF: SHAKE-256(seed || nonce), producing `len` output bytes.
///
/// Used to generate deterministic randomness for CBD sampling.
pub fn prf(seed: &[u8; 32], nonce: u8, len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    hasher.update(&[nonce]);
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; len];
    reader.read(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cbd_eta2_range() {
        let bytes = [0xABu8; 128]; // 64 * 2 = 128 bytes
        let poly = sample_poly_cbd::<2>(&bytes);
        for i in 0..256 {
            let v = poly[i].value();
            assert!(
                v <= 2 || v >= Q - 2,
                "CBD(2) produced {v} at index {i}, out of [-2, 2] range"
            );
        }
    }

    #[test]
    fn test_cbd_eta3_range() {
        let bytes = [0xCDu8; 192]; // 64 * 3 = 192 bytes
        let poly = sample_poly_cbd::<3>(&bytes);
        for i in 0..256 {
            let v = poly[i].value();
            assert!(
                v <= 3 || v >= Q - 3,
                "CBD(3) produced {v} at index {i}, out of [-3, 3] range"
            );
        }
    }

    #[test]
    fn test_cbd_deterministic() {
        let bytes = [42u8; 128];
        let a = sample_poly_cbd::<2>(&bytes);
        let b = sample_poly_cbd::<2>(&bytes);
        for i in 0..256 {
            assert_eq!(a[i].value(), b[i].value());
        }
    }

    #[test]
    fn test_sample_ntt_range() {
        let seed = [0u8; 34];
        let poly = sample_ntt(&seed);
        for i in 0..256 {
            assert!(poly[i].value() < Q, "SampleNTT produced value >= q at {i}");
        }
    }

    #[test]
    fn test_sample_ntt_deterministic() {
        let seed = [1u8; 34];
        let a = sample_ntt(&seed);
        let b = sample_ntt(&seed);
        for i in 0..256 {
            assert_eq!(a[i].value(), b[i].value());
        }
    }

    #[test]
    fn test_sample_ntt_different_seeds() {
        let seed_a = [0u8; 34];
        let mut seed_b = [0u8; 34];
        seed_b[33] = 1;
        let a = sample_ntt(&seed_a);
        let b = sample_ntt(&seed_b);
        let mut same = true;
        for i in 0..256 {
            if a[i].value() != b[i].value() {
                same = false;
                break;
            }
        }
        assert!(!same, "Different seeds should produce different polynomials");
    }

    #[test]
    fn test_prf_deterministic() {
        let seed = [7u8; 32];
        let a = prf(&seed, 0, 128);
        let b = prf(&seed, 0, 128);
        assert_eq!(a, b);
    }

    #[test]
    fn test_prf_different_nonces() {
        let seed = [7u8; 32];
        let a = prf(&seed, 0, 128);
        let b = prf(&seed, 1, 128);
        assert_ne!(a, b);
    }
}
