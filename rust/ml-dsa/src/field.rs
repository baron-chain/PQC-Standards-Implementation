//! Field arithmetic for ML-DSA (FIPS 204).
//!
//! All operations are over Z_q where q = 8380417.

/// The ML-DSA prime modulus: q = 2^23 - 2^13 + 1.
pub const Q: u32 = 8380417;

/// q as i32 for signed arithmetic.
pub const Q_I32: i32 = Q as i32;

/// (q - 1) / 2 = 4190208, used for centered representation checks.
pub const Q_HALF: u32 = (Q - 1) / 2;

/// Montgomery parameter: R = 2^32 mod q.
pub const MONT_R: u32 = 4193792; // 2^32 mod 8380417

/// Inverse of 256 modulo q, used in inverse NTT.
/// 256^{-1} mod q = 8347681.
pub const INV_256: u32 = 8347681;

/// Reduce an i64 value to [0, q).
///
/// Handles both positive and negative inputs.
#[inline]
pub fn mod_q(a: i64) -> u32 {
    let q = Q as i64;
    let r = a % q;
    if r < 0 {
        (r + q) as u32
    } else {
        r as u32
    }
}

/// Add two field elements: (a + b) mod q.
///
/// Both inputs must be in [0, q).
#[inline]
pub fn field_add(a: u32, b: u32) -> u32 {
    let sum = a + b;
    if sum >= Q {
        sum - Q
    } else {
        sum
    }
}

/// Subtract two field elements: (a - b) mod q.
///
/// Both inputs must be in [0, q).
#[inline]
pub fn field_sub(a: u32, b: u32) -> u32 {
    if a >= b {
        a - b
    } else {
        Q - b + a
    }
}

/// Multiply two field elements: (a * b) mod q.
///
/// Both inputs must be in [0, q). Uses u64 intermediate to avoid overflow.
#[inline]
pub fn field_mul(a: u32, b: u32) -> u32 {
    let prod = (a as u64) * (b as u64);
    (prod % (Q as u64)) as u32
}

/// Compute base^exp mod q using binary exponentiation.
///
/// `base` must be in [0, q).
pub fn field_pow(base: u32, exp: u32) -> u32 {
    if exp == 0 {
        return 1;
    }

    let mut result: u64 = 1;
    let mut b: u64 = base as u64;
    let mut e = exp;
    let q = Q as u64;

    while e > 0 {
        if e & 1 == 1 {
            result = (result * b) % q;
        }
        b = (b * b) % q;
        e >>= 1;
    }

    result as u32
}

/// Compute the modular inverse: a^{-1} mod q using Fermat's little theorem.
///
/// Since q is prime, a^{-1} = a^{q-2} mod q.
/// Returns 0 if a == 0 (which is technically undefined).
#[inline]
pub fn field_inv(a: u32) -> u32 {
    field_pow(a, Q - 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_q_properties() {
        // q = 2^23 - 2^13 + 1
        assert_eq!(Q, (1u32 << 23) - (1u32 << 13) + 1);
        // q ≡ 1 mod 512
        assert_eq!(Q % 512, 1);
    }

    #[test]
    fn test_mod_q_positive() {
        assert_eq!(mod_q(0), 0);
        assert_eq!(mod_q(1), 1);
        assert_eq!(mod_q(Q as i64), 0);
        assert_eq!(mod_q(Q as i64 + 1), 1);
        assert_eq!(mod_q(2 * Q as i64), 0);
    }

    #[test]
    fn test_mod_q_negative() {
        assert_eq!(mod_q(-1), Q - 1);
        assert_eq!(mod_q(-(Q as i64)), 0);
        assert_eq!(mod_q(-(Q as i64) - 1), Q - 1);
    }

    #[test]
    fn test_field_add() {
        assert_eq!(field_add(0, 0), 0);
        assert_eq!(field_add(1, 2), 3);
        assert_eq!(field_add(Q - 1, 1), 0);
        assert_eq!(field_add(Q - 1, Q - 1), Q - 2);
    }

    #[test]
    fn test_field_sub() {
        assert_eq!(field_sub(3, 2), 1);
        assert_eq!(field_sub(0, 0), 0);
        assert_eq!(field_sub(0, 1), Q - 1);
        assert_eq!(field_sub(1, Q - 1), 2);
    }

    #[test]
    fn test_field_mul() {
        assert_eq!(field_mul(0, 12345), 0);
        assert_eq!(field_mul(1, 12345), 12345);
        assert_eq!(field_mul(2, 3), 6);
        // Test large multiplication doesn't overflow
        let a = Q - 1;
        let b = Q - 1;
        let expected = mod_q((a as i64) * (b as i64));
        assert_eq!(field_mul(a, b), expected);
    }

    #[test]
    fn test_field_pow() {
        assert_eq!(field_pow(2, 0), 1);
        assert_eq!(field_pow(2, 1), 2);
        assert_eq!(field_pow(2, 10), 1024);
        // 2^23 mod q = 2^23 mod (2^23 - 2^13 + 1) = 2^13 - 1 = 8191
        assert_eq!(field_pow(2, 23), 8191);
        // Fermat's little theorem: a^{q-1} = 1 mod q for a != 0
        assert_eq!(field_pow(1753, Q - 1), 1);
        assert_eq!(field_pow(42, Q - 1), 1);
    }

    #[test]
    fn test_field_inv() {
        // a * a^{-1} = 1 mod q
        let a = 1753u32;
        let a_inv = field_inv(a);
        assert_eq!(field_mul(a, a_inv), 1);

        let b = 42u32;
        let b_inv = field_inv(b);
        assert_eq!(field_mul(b, b_inv), 1);
    }

    #[test]
    fn test_inv_256_constant() {
        // Verify the precomputed constant
        assert_eq!(field_mul(256, INV_256), 1);
    }

    #[test]
    fn test_add_sub_inverse() {
        // (a + b) - b = a
        let a = 123456u32;
        let b = 7654321u32;
        assert_eq!(field_sub(field_add(a, b), b), a);
    }

    #[test]
    fn test_mul_distributive() {
        // a * (b + c) = a*b + a*c
        let a = 1000u32;
        let b = 2000u32;
        let c = 3000u32;
        let lhs = field_mul(a, field_add(b, c));
        let rhs = field_add(field_mul(a, b), field_mul(a, c));
        assert_eq!(lhs, rhs);
    }
}
