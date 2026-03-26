//! Utility functions for SLH-DSA (FIPS 205).
//!
//! Provides byte-to-integer conversions and the base-2^b decomposition
//! used by WOTS+ and FORS.

use alloc::vec;
use alloc::vec::Vec;

/// Convert a big-endian byte string to an unsigned integer.
///
/// Algorithm 1 in FIPS 205: toInt(X, n).
pub fn to_int(x: &[u8]) -> u64 {
    let mut total: u64 = 0;
    for &b in x {
        total = (total << 8) | (b as u64);
    }
    total
}

/// Convert an unsigned integer to an `n`-byte big-endian byte string.
///
/// Algorithm 2 in FIPS 205: toByte(x, n).
pub fn to_byte(x: u64, n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    let mut val = x;
    for i in (0..n).rev() {
        out[i] = (val & 0xFF) as u8;
        val >>= 8;
    }
    out
}

/// Decompose a byte string `x` into `out_len` values, each in the range
/// \[0, 2^b).
///
/// Algorithm 3 in FIPS 205: base\_2b(X, b, out\_len).
///
/// Reads bits from `x` in big-endian order, extracting `b`-bit chunks.
pub fn base_2b(x: &[u8], b: u32, out_len: usize) -> Vec<u32> {
    let mut result = vec![0u32; out_len];
    let mut in_idx = 0usize;
    let mut bits: u32 = 0;
    let mut total: u64 = 0;
    let mask: u64 = (1u64 << b) - 1;

    for out in result.iter_mut() {
        while bits < b {
            if in_idx < x.len() {
                total = (total << 8) | (x[in_idx] as u64);
                in_idx += 1;
                bits += 8;
            } else {
                break;
            }
        }
        bits -= b;
        *out = ((total >> bits) & mask) as u32;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_int_empty() {
        assert_eq!(to_int(&[]), 0);
    }

    #[test]
    fn test_to_int_single_byte() {
        assert_eq!(to_int(&[0x42]), 0x42);
    }

    #[test]
    fn test_to_int_multi_byte() {
        assert_eq!(to_int(&[0x01, 0x02, 0x03]), 0x010203);
    }

    #[test]
    fn test_to_byte_basic() {
        assert_eq!(to_byte(0x0102, 4), vec![0, 0, 1, 2]);
    }

    #[test]
    fn test_to_byte_zero() {
        assert_eq!(to_byte(0, 4), vec![0, 0, 0, 0]);
    }

    #[test]
    fn test_to_byte_roundtrip() {
        let val: u64 = 0xDEADBEEF;
        let bytes = to_byte(val, 8);
        assert_eq!(to_int(&bytes), val);
    }

    #[test]
    fn test_base_2b_nibbles() {
        // b=4: each byte yields two nibbles
        let x = &[0xAB, 0xCD];
        let result = base_2b(x, 4, 4);
        assert_eq!(result, vec![0xA, 0xB, 0xC, 0xD]);
    }

    #[test]
    fn test_base_2b_bytes() {
        // b=8: each value is one byte
        let x = &[0x01, 0x02, 0x03];
        let result = base_2b(x, 8, 3);
        assert_eq!(result, vec![1, 2, 3]);
    }

    #[test]
    fn test_base_2b_bits() {
        // b=1: bit decomposition
        let x = &[0b10110000];
        let result = base_2b(x, 1, 8);
        assert_eq!(result, vec![1, 0, 1, 1, 0, 0, 0, 0]);
    }
}
