//! Encoding and decoding functions for ML-DSA (FIPS 204).
//!
//! Provides bit-packing for polynomials, public keys, and signatures.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

/// Pack 256 coefficients, each `bits` bits wide, into a byte vector.
pub fn bit_pack(poly: &[u32; 256], bits: u32) -> Vec<u8> {
    let total_bits = 256 * bits as usize;
    let total_bytes = (total_bits + 7) / 8;
    let mut out = vec![0u8; total_bytes];

    for i in 0..256 {
        let val = poly[i];
        let bit_offset = i * bits as usize;
        let byte_idx = bit_offset / 8;
        let bit_idx = bit_offset % 8;

        // Write value across multiple bytes
        let mut v = (val as u64) << bit_idx;
        let bytes_needed = (bit_idx + bits as usize + 7) / 8;
        for b in 0..bytes_needed {
            if byte_idx + b < total_bytes {
                out[byte_idx + b] |= (v & 0xFF) as u8;
                v >>= 8;
            }
        }
    }
    out
}

/// Unpack 256 coefficients of `bits` bits each from a byte slice.
pub fn bit_unpack(data: &[u8], bits: u32) -> [u32; 256] {
    let mut poly = [0u32; 256];
    let mask = (1u32 << bits) - 1;

    for i in 0..256 {
        let bit_offset = i * bits as usize;
        let byte_idx = bit_offset / 8;
        let bit_idx = bit_offset % 8;

        let mut val: u64 = 0;
        let bytes_needed = (bit_idx + bits as usize + 7) / 8;
        for b in (0..bytes_needed).rev() {
            if byte_idx + b < data.len() {
                val = (val << 8) | data[byte_idx + b] as u64;
            } else {
                val <<= 8;
            }
        }
        poly[i] = ((val >> bit_idx) as u32) & mask;
    }
    poly
}

/// Pack a signed coefficient z in range [-(bound-1), bound] using `bits` bits.
/// Encodes as gamma1 - z (mod 2^bits), i.e., maps [-gamma1+1, gamma1] to [0, 2*gamma1-1].
pub fn bit_pack_signed(poly: &[u32; 256], gamma1: u32, bits: u32) -> Vec<u8> {
    let mut mapped = [0u32; 256];
    for i in 0..256 {
        // poly[i] is in [0, gamma1] union [q - gamma1 + 1, q - 1]
        // Map to [0, 2*gamma1 - 1]: val = gamma1 - coeff (mod q, then mod 2^bits)
        mapped[i] = map_signed_to_unsigned(poly[i], gamma1);
    }
    bit_pack(&mapped, bits)
}

/// Unpack signed coefficients: reverse the gamma1 mapping.
pub fn bit_unpack_signed(data: &[u8], gamma1: u32, bits: u32) -> [u32; 256] {
    let unsigned = bit_unpack(data, bits);
    let mut poly = [0u32; 256];
    for i in 0..256 {
        poly[i] = map_unsigned_to_signed(unsigned[i], gamma1);
    }
    poly
}

/// Map a signed field element (mod q) to unsigned for packing.
/// gamma1 - coeff if coeff <= gamma1, else gamma1 + (q - coeff).
#[inline]
fn map_signed_to_unsigned(coeff: u32, gamma1: u32) -> u32 {
    if coeff <= gamma1 {
        gamma1 - coeff
    } else {
        gamma1 + (crate::field::Q - coeff)
    }
}

/// Map unsigned packed value back to signed field element (mod q).
#[inline]
fn map_unsigned_to_signed(val: u32, gamma1: u32) -> u32 {
    if val <= gamma1 {
        gamma1 - val
    } else {
        crate::field::Q - (val - gamma1)
    }
}

/// Encode a public key: pk = rho || bit_pack(t1[0], 10) || bit_pack(t1[1], 10) || ...
pub fn encode_pk(rho: &[u8; 32], t1: &[[u32; 256]]) -> Vec<u8> {
    let mut pk = Vec::with_capacity(32 + t1.len() * 320);
    pk.extend_from_slice(rho);
    for poly in t1 {
        pk.extend_from_slice(&bit_pack(poly, 10));
    }
    pk
}

/// Decode a public key into (rho, t1).
pub fn decode_pk(pk: &[u8], k: usize) -> ([u8; 32], Vec<[u32; 256]>) {
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&pk[..32]);

    let mut t1 = Vec::with_capacity(k);
    for i in 0..k {
        let start = 32 + i * 320;
        let poly = bit_unpack(&pk[start..start + 320], 10);
        t1.push(poly);
    }
    (rho, t1)
}

/// Pack a secret key polynomial with coefficients in [-eta, eta] using eta_bits bits.
/// Maps eta - coeff to unsigned: 0 -> eta, 1 -> eta-1, ..., eta -> 0,
/// q-1 -> eta+1, q-2 -> eta+2, ..., q-eta -> 2*eta.
pub fn pack_eta(poly: &[u32; 256], eta: u32, eta_bits: u32) -> Vec<u8> {
    let mut mapped = [0u32; 256];
    for i in 0..256 {
        mapped[i] = map_signed_to_unsigned(poly[i], eta);
    }
    bit_pack(&mapped, eta_bits)
}

/// Unpack a secret key polynomial packed with pack_eta.
pub fn unpack_eta(data: &[u8], eta: u32, eta_bits: u32) -> [u32; 256] {
    let unsigned = bit_unpack(data, eta_bits);
    let mut poly = [0u32; 256];
    for i in 0..256 {
        poly[i] = map_unsigned_to_signed(unsigned[i], eta);
    }
    poly
}

/// Encode a secret key.
/// sk = rho(32) || K(32) || tr(64) || s1_packed || s2_packed || t0_packed
pub fn encode_sk(
    rho: &[u8; 32],
    k_seed: &[u8; 32],
    tr: &[u8; 64],
    s1: &[[u32; 256]],
    s2: &[[u32; 256]],
    t0: &[[u32; 256]],
    eta: u32,
    eta_bits: u32,
) -> Vec<u8> {
    let mut sk = Vec::new();
    sk.extend_from_slice(rho);
    sk.extend_from_slice(k_seed);
    sk.extend_from_slice(tr);

    for poly in s1 {
        sk.extend_from_slice(&pack_eta(poly, eta, eta_bits));
    }
    for poly in s2 {
        sk.extend_from_slice(&pack_eta(poly, eta, eta_bits));
    }
    for poly in t0 {
        // t0 has coefficients in [-(2^(d-1)-1), 2^(d-1)]
        // Pack with d=13 bits, mapping: 2^(d-1) - coeff
        let packed = bit_pack_t0(poly);
        sk.extend_from_slice(&packed);
    }
    sk
}

/// Pack t0 polynomial: coefficients in [-(2^12-1), 2^12], stored as 2^12 - coeff.
fn bit_pack_t0(poly: &[u32; 256]) -> Vec<u8> {
    let d_half = 1u32 << 12; // 2^(d-1) = 4096
    let mut mapped = [0u32; 256];
    for i in 0..256 {
        let c = poly[i];
        if c <= d_half {
            mapped[i] = d_half - c;
        } else {
            // c is negative (c >= Q - d_half + 1), so |c| = Q - c
            mapped[i] = d_half + (crate::field::Q - c);
        }
    }
    bit_pack(&mapped, 13)
}

/// Unpack t0 polynomial.
fn bit_unpack_t0(data: &[u8]) -> [u32; 256] {
    let unsigned = bit_unpack(data, 13);
    let d_half = 1u32 << 12;
    let mut poly = [0u32; 256];
    for i in 0..256 {
        let val = unsigned[i];
        if val <= d_half {
            poly[i] = d_half - val;
        } else {
            poly[i] = crate::field::Q - (val - d_half);
        }
    }
    poly
}

/// Decode a secret key.
pub fn decode_sk(
    sk: &[u8],
    k: usize,
    l: usize,
    eta: u32,
    eta_bits: u32,
) -> ([u8; 32], [u8; 32], [u8; 64], Vec<[u32; 256]>, Vec<[u32; 256]>, Vec<[u32; 256]>) {
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&sk[..32]);

    let mut k_seed = [0u8; 32];
    k_seed.copy_from_slice(&sk[32..64]);

    let mut tr = [0u8; 64];
    tr.copy_from_slice(&sk[64..128]);

    let eta_poly_bytes = 256 * eta_bits as usize / 8;
    let t0_poly_bytes = 256 * 13 / 8;

    let mut offset = 128;

    let mut s1 = Vec::with_capacity(l);
    for _ in 0..l {
        s1.push(unpack_eta(&sk[offset..offset + eta_poly_bytes], eta, eta_bits));
        offset += eta_poly_bytes;
    }

    let mut s2 = Vec::with_capacity(k);
    for _ in 0..k {
        s2.push(unpack_eta(&sk[offset..offset + eta_poly_bytes], eta, eta_bits));
        offset += eta_poly_bytes;
    }

    let mut t0 = Vec::with_capacity(k);
    for _ in 0..k {
        t0.push(bit_unpack_t0(&sk[offset..offset + t0_poly_bytes]));
        offset += t0_poly_bytes;
    }

    (rho, k_seed, tr, s1, s2, t0)
}

/// Encode a signature.
/// sig = c_tilde || z_packed || h_packed
/// c_tilde: c_tilde_size bytes (lambda/4)
/// z: l polynomials, each coefficient in [-(gamma1-1), gamma1], packed as gamma1_bits bits
/// h: encoded as omega + k bytes (FIPS 204 hint encoding)
pub fn encode_sig(
    c_tilde: &[u8],
    z: &[[u32; 256]],
    h: &[Vec<bool>],
    gamma1: u32,
    omega: usize,
    k: usize,
) -> Vec<u8> {
    let gamma1_bits = if gamma1 == (1 << 17) { 18u32 } else { 20u32 };
    let mut sig = Vec::new();

    // c_tilde
    sig.extend_from_slice(c_tilde);

    // z packed
    for poly in z {
        sig.extend_from_slice(&bit_pack_signed(poly, gamma1, gamma1_bits));
    }

    // h packed: omega + k bytes
    // For each of the k polynomials, list the indices where h[i][j] = true,
    // then pad, and store the count boundaries.
    let mut h_bytes = vec![0u8; omega + k];
    let mut idx = 0;
    for i in 0..k {
        for j in 0..256 {
            if h[i][j] {
                h_bytes[idx] = j as u8;
                idx += 1;
            }
        }
        h_bytes[omega + i] = idx as u8;
    }
    sig.extend_from_slice(&h_bytes);

    sig
}

/// Decode a signature. Returns None if malformed.
pub fn decode_sig(
    sig: &[u8],
    l: usize,
    k: usize,
    gamma1: u32,
    omega: usize,
    c_tilde_size: usize,
) -> Option<(Vec<u8>, Vec<[u32; 256]>, Vec<Vec<bool>>)> {
    let gamma1_bits = if gamma1 == (1 << 17) { 18u32 } else { 20u32 };
    let z_poly_bytes = 256 * gamma1_bits as usize / 8;

    let expected_len = c_tilde_size + l * z_poly_bytes + omega + k;
    if sig.len() != expected_len {
        return None;
    }

    // c_tilde
    let c_tilde = sig[..c_tilde_size].to_vec();

    // z
    let mut z = Vec::with_capacity(l);
    let mut offset = c_tilde_size;
    for _ in 0..l {
        let poly = bit_unpack_signed(&sig[offset..offset + z_poly_bytes], gamma1, gamma1_bits);
        z.push(poly);
        offset += z_poly_bytes;
    }

    // h
    let h_bytes = &sig[offset..];
    let mut h = vec![vec![false; 256]; k];
    let mut prev_bound = 0usize;
    for i in 0..k {
        let bound = h_bytes[omega + i] as usize;
        if bound < prev_bound || bound > omega {
            return None;
        }
        for j in prev_bound..bound {
            let index = h_bytes[j] as usize;
            if index >= 256 {
                return None;
            }
            // Check indices are sorted (strictly increasing within each poly)
            if j > prev_bound && h_bytes[j] <= h_bytes[j - 1] {
                return None;
            }
            h[i][index] = true;
        }
        prev_bound = bound;
    }

    // Check unused positions are zero
    for j in prev_bound..omega {
        if h_bytes[j] != 0 {
            return None;
        }
    }

    Some((c_tilde, z, h))
}

/// Encode w1 (high bits) for hashing. Each coefficient needs ceil(log2((q-1)/alpha)) bits.
/// For alpha = 190464 (ML-DSA-44): (q-1)/alpha = 44, need 6 bits.
/// For alpha = 523776 (ML-DSA-65/87): (q-1)/alpha = 16, need 4 bits.
pub fn encode_w1(w1: &[[u32; 256]], alpha: u32) -> Vec<u8> {
    let bits = if alpha == 190464 { 6u32 } else { 4u32 };
    let mut out = Vec::new();
    for poly in w1 {
        out.extend_from_slice(&bit_pack(poly, bits));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bit_pack_unpack_10bit() {
        let mut poly = [0u32; 256];
        for i in 0..256 {
            poly[i] = (i as u32 * 3 + 7) % 1024; // 10-bit values
        }
        let packed = bit_pack(&poly, 10);
        let unpacked = bit_unpack(&packed, 10);
        assert_eq!(poly, unpacked);
    }

    #[test]
    fn test_bit_pack_unpack_13bit() {
        let mut poly = [0u32; 256];
        for i in 0..256 {
            poly[i] = (i as u32 * 17 + 42) % 8192; // 13-bit values
        }
        let packed = bit_pack(&poly, 13);
        let unpacked = bit_unpack(&packed, 13);
        assert_eq!(poly, unpacked);
    }

    #[test]
    fn test_bit_pack_unpack_18bit() {
        let mut poly = [0u32; 256];
        for i in 0..256 {
            poly[i] = (i as u32 * 1001 + 5) % (1 << 18);
        }
        let packed = bit_pack(&poly, 18);
        let unpacked = bit_unpack(&packed, 18);
        assert_eq!(poly, unpacked);
    }

    #[test]
    fn test_encode_decode_pk() {
        let rho = [42u8; 32];
        let mut t1 = [[0u32; 256]; 4];
        for i in 0..4 {
            for j in 0..256 {
                t1[i][j] = ((i * 256 + j) as u32 * 3) % 1024;
            }
        }
        let pk = encode_pk(&rho, &t1);
        assert_eq!(pk.len(), 32 + 4 * 320);

        let (rho2, t1_decoded) = decode_pk(&pk, 4);
        assert_eq!(rho, rho2);
        assert_eq!(t1_decoded.len(), 4);
        for i in 0..4 {
            assert_eq!(t1[i], t1_decoded[i]);
        }
    }

    #[test]
    fn test_signed_pack_roundtrip() {
        let gamma1 = 1u32 << 17;
        let mut poly = [0u32; 256];
        // Fill with values in valid range: positive [0, 127] and negative [-1, -128] mod q
        for i in 0..128 {
            poly[i] = i as u32; // positive: [0, 127]
        }
        for i in 128..256 {
            let neg_val = (i - 127) as u32; // 1..129
            poly[i] = crate::field::Q - neg_val; // -1, -2, ..., -128 mod q
        }
        let packed = bit_pack_signed(&poly, gamma1, 18);
        let unpacked = bit_unpack_signed(&packed, gamma1, 18);
        assert_eq!(poly, unpacked);
    }

    #[test]
    fn test_encode_decode_sig_basic() {
        let c_tilde = vec![0xABu8; 32];
        let gamma1 = 1u32 << 17;
        let l = 4;
        let k = 4;
        let omega = 80;

        let z: Vec<[u32; 256]> = (0..l)
            .map(|_| {
                let mut p = [0u32; 256];
                for j in 0..256 {
                    p[j] = j as u32 % (gamma1 / 2);
                }
                p
            })
            .collect();

        let h: Vec<Vec<bool>> = (0..k)
            .map(|i| {
                let mut v = vec![false; 256];
                v[i] = true; // One hint per poly
                v
            })
            .collect();

        let sig = encode_sig(&c_tilde, &z, &h, gamma1, omega, k);
        let decoded = decode_sig(&sig, l, k, gamma1, omega, 32);
        assert!(decoded.is_some());
        let (ct, z2, h2) = decoded.unwrap();
        assert_eq!(ct, c_tilde);
        assert_eq!(z2.len(), l);
        assert_eq!(h2.len(), k);
        for i in 0..k {
            assert_eq!(h[i], h2[i]);
        }
    }
}
