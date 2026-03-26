//! Top-level ML-DSA (FIPS 204) key generation, signing, and verification.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use rand_core::{CryptoRng, RngCore};

use crate::decompose;
use crate::encode;
use crate::field::{self, Q};
use crate::hash;
use crate::ntt;
use crate::params::{ParamSet, D};

/// ML-DSA key generation.
///
/// Returns (public_key, secret_key).
pub fn keygen<P: ParamSet>(rng: &mut (impl CryptoRng + RngCore)) -> (Vec<u8>, Vec<u8>) {
    let k = P::K;
    let l = P::L;
    let eta = P::ETA as u32;
    let eta_bits = P::ETA_BITS as u32;

    // Step 1: random seed
    let mut xi = [0u8; 32];
    rng.fill_bytes(&mut xi);

    // Step 2: expand seed -> (rho, rho_prime, K)
    let expanded = hash::h(&xi, 128);
    let mut rho = [0u8; 32];
    let mut rho_prime = [0u8; 64];
    let mut k_seed = [0u8; 32];
    rho.copy_from_slice(&expanded[..32]);
    rho_prime.copy_from_slice(&expanded[32..96]);
    k_seed.copy_from_slice(&expanded[96..128]);

    // Step 3: generate matrix A in NTT domain
    let a_hat = hash::expand_a(&rho, k, l);

    // Step 4: generate secret vectors
    let (s1, s2) = hash::expand_s(&rho_prime, eta, k, l);

    // Step 5: compute t = A * NTT(s1) + s2  (in normal domain)
    let mut s1_hat: Vec<[u32; 256]> = s1.clone();
    for poly in s1_hat.iter_mut() {
        ntt::ntt(poly);
    }

    let mut t = vec![[0u32; 256]; k];
    for i in 0..k {
        // t[i] = sum_j(A[i][j] * s1_hat[j])
        let mut acc_hat = [0u32; 256];
        for j in 0..l {
            let prod = ntt::pointwise_mul(&a_hat[i][j], &s1_hat[j]);
            for c in 0..256 {
                acc_hat[c] = field::field_add(acc_hat[c], prod[c]);
            }
        }
        ntt::ntt_inverse(&mut acc_hat);
        for c in 0..256 {
            t[i][c] = field::field_add(acc_hat[c], s2[i][c]);
        }
    }

    // Step 6: power2_round each coefficient of t
    let mut t1 = vec![[0u32; 256]; k];
    let mut t0 = vec![[0u32; 256]; k];
    for i in 0..k {
        for c in 0..256 {
            let (hi, lo) = decompose::power2_round(t[i][c]);
            t1[i][c] = hi;
            t0[i][c] = lo;
        }
    }

    // Step 7: encode public key
    let pk = encode::encode_pk(&rho, &t1);

    // Step 8: tr = H(pk, 64)
    let tr_vec = hash::h(&pk, 64);
    let mut tr = [0u8; 64];
    tr.copy_from_slice(&tr_vec);

    // Step 9: encode secret key
    let sk = encode::encode_sk(&rho, &k_seed, &tr, &s1, &s2, &t0, eta, eta_bits);

    (pk, sk)
}

/// ML-DSA signing (deterministic).
///
/// Returns the signature bytes.
pub fn sign<P: ParamSet>(sk: &[u8], msg: &[u8]) -> Vec<u8> {
    let k = P::K;
    let l = P::L;
    let eta = P::ETA as u32;
    let eta_bits = P::ETA_BITS as u32;
    let gamma1 = P::GAMMA1;
    let gamma2 = P::GAMMA2;
    let beta = P::BETA;
    let tau = P::TAU;
    let omega = P::OMEGA;
    let alpha = 2 * gamma2;

    // Step 1: unpack secret key
    let (rho, k_seed, tr, s1, s2, t0) = encode::decode_sk(sk, k, l, eta, eta_bits);

    // Step 2: generate A
    let a_hat = hash::expand_a(&rho, k, l);

    // Step 3: mu = H(tr || msg, 64)
    let mut mu = [0u8; 64];
    let mu_vec = hash::h_two(&tr, msg, 64);
    mu.copy_from_slice(&mu_vec);

    // Step 4: rho_prime = H(K || mu, 64) (deterministic)
    let mut rho_prime = [0u8; 64];
    let rp_vec = hash::h_two(&k_seed, &mu, 64);
    rho_prime.copy_from_slice(&rp_vec);

    // Step 5: precompute NTT forms
    let mut s1_hat: Vec<[u32; 256]> = s1.clone();
    for poly in s1_hat.iter_mut() {
        ntt::ntt(poly);
    }
    let mut s2_hat: Vec<[u32; 256]> = s2.clone();
    for poly in s2_hat.iter_mut() {
        ntt::ntt(poly);
    }
    let mut t0_hat: Vec<[u32; 256]> = t0.clone();
    for poly in t0_hat.iter_mut() {
        ntt::ntt(poly);
    }

    // Step 6-7: rejection sampling loop
    let mut kappa: u16 = 0;
    loop {
        // (a) y = expand_mask
        let y = hash::expand_mask(&rho_prime, gamma1, l, kappa);

        // (b) w = A * NTT(y) (then INTT)
        let mut y_hat: Vec<[u32; 256]> = y.clone();
        for poly in y_hat.iter_mut() {
            ntt::ntt(poly);
        }

        let mut w = vec![[0u32; 256]; k];
        for i in 0..k {
            let mut acc = [0u32; 256];
            for j in 0..l {
                let prod = ntt::pointwise_mul(&a_hat[i][j], &y_hat[j]);
                for c in 0..256 {
                    acc[c] = field::field_add(acc[c], prod[c]);
                }
            }
            ntt::ntt_inverse(&mut acc);
            w[i] = acc;
        }

        // (c) w1 = high_bits(w)
        let mut w1 = vec![[0u32; 256]; k];
        for i in 0..k {
            for c in 0..256 {
                w1[i][c] = decompose::high_bits(w[i][c], alpha);
            }
        }

        // (d) c_tilde = H(mu || encode(w1), lambda/4)
        let c_tilde_size = P::C_TILDE_SIZE;
        let w1_encoded = encode::encode_w1(&w1, alpha);
        let mut hash_input = Vec::with_capacity(64 + w1_encoded.len());
        hash_input.extend_from_slice(&mu);
        hash_input.extend_from_slice(&w1_encoded);
        let c_tilde = hash::h(&hash_input, c_tilde_size);

        // (e) c = sample_in_ball(c_tilde)
        let c_poly = hash::sample_in_ball(&c_tilde, tau);
        let mut c_hat = c_poly;
        ntt::ntt(&mut c_hat);

        // (g) z = y + NTT_inv(c_hat * s1_hat)
        let mut z = vec![[0u32; 256]; l];
        for j in 0..l {
            let mut cs1 = ntt::pointwise_mul(&c_hat, &s1_hat[j]);
            ntt::ntt_inverse(&mut cs1);
            for c in 0..256 {
                z[j][c] = field::field_add(y[j][c], cs1[c]);
            }
        }

        // (h) Check ||z||_inf < gamma1 - beta
        if !check_norm_bound(&z, gamma1 - beta) {
            kappa += l as u16;
            continue;
        }

        // (i) r0 = low_bits(w - NTT_inv(c_hat * s2_hat))
        let mut w_minus_cs2 = vec![[0u32; 256]; k];
        for i in 0..k {
            let mut cs2 = ntt::pointwise_mul(&c_hat, &s2_hat[i]);
            ntt::ntt_inverse(&mut cs2);
            for c in 0..256 {
                w_minus_cs2[i][c] = field::field_sub(w[i][c], cs2[c]);
            }
        }

        let mut r0_reject = false;
        for i in 0..k {
            for c in 0..256 {
                let r0 = decompose::low_bits(w_minus_cs2[i][c], alpha);
                if !coeff_in_range(r0, gamma2 - beta) {
                    r0_reject = true;
                    break;
                }
            }
            if r0_reject {
                break;
            }
        }
        if r0_reject {
            kappa += l as u16;
            continue;
        }

        // (k) ct0 = NTT_inv(c_hat * t0_hat)
        let mut ct0 = vec![[0u32; 256]; k];
        for i in 0..k {
            ct0[i] = ntt::pointwise_mul(&c_hat, &t0_hat[i]);
            ntt::ntt_inverse(&mut ct0[i]);
        }

        // (l) Check ||ct0||_inf < gamma2
        if !check_norm_bound_single(&ct0, gamma2) {
            kappa += l as u16;
            continue;
        }

        // (m) h = make_hint(-ct0, w - cs2 + ct0)
        let mut h = vec![vec![false; 256]; k];
        let mut hint_ones = 0usize;
        for i in 0..k {
            for c in 0..256 {
                // -ct0
                let neg_ct0 = if ct0[i][c] == 0 { 0 } else { Q - ct0[i][c] };
                // w - cs2 + ct0
                let val = field::field_add(w_minus_cs2[i][c], ct0[i][c]);
                h[i][c] = decompose::make_hint(neg_ct0, val, alpha);
                if h[i][c] {
                    hint_ones += 1;
                }
            }
        }

        // (n) Check hint count
        if hint_ones > omega {
            kappa += l as u16;
            continue;
        }

        // Success - encode and return
        return encode::encode_sig(&c_tilde, &z, &h, gamma1, omega, k);
    }
}

/// ML-DSA verification.
///
/// Returns true if the signature is valid.
pub fn verify<P: ParamSet>(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let k = P::K;
    let l = P::L;
    let gamma1 = P::GAMMA1;
    let gamma2 = P::GAMMA2;
    let beta = P::BETA;
    let tau = P::TAU;
    let omega = P::OMEGA;
    let alpha = 2 * gamma2;

    // Step 1-2: decode pk and sig
    if pk.len() != P::PK_SIZE {
        return false;
    }
    let (rho, t1) = encode::decode_pk(pk, k);

    let decoded = match encode::decode_sig(sig, l, k, gamma1, omega, P::C_TILDE_SIZE) {
        Some(d) => d,
        None => return false,
    };
    let (c_tilde, z, h) = decoded;

    // Step 3: check ||z||_inf < gamma1 - beta
    if !check_norm_bound(&z, gamma1 - beta) {
        return false;
    }

    // Check hint count
    let hint_ones: usize = h.iter().map(|v| v.iter().filter(|&&b| b).count()).sum();
    if hint_ones > omega {
        return false;
    }

    // Step 4: A = expand_a
    let a_hat = hash::expand_a(&rho, k, l);

    // Step 5-6: tr = H(pk, 64), mu = H(tr || msg, 64)
    let tr = hash::h(pk, 64);
    let mu = hash::h_two(&tr, msg, 64);

    // Step 7: c = sample_in_ball
    let c_poly = hash::sample_in_ball(&c_tilde, tau);
    let mut c_hat = c_poly;
    ntt::ntt(&mut c_hat);

    // Step 8: w_approx = NTT_inv(A * NTT(z) - c_hat * NTT(t1 * 2^d))
    let mut z_hat: Vec<[u32; 256]> = z.clone();
    for poly in z_hat.iter_mut() {
        ntt::ntt(poly);
    }

    // Compute NTT(t1 * 2^d)
    let two_d = 1u32 << D; // 2^13
    let mut t1_scaled_hat = Vec::with_capacity(k);
    for i in 0..k {
        let mut poly = [0u32; 256];
        for c in 0..256 {
            poly[c] = field::field_mul(t1[i][c], two_d);
        }
        ntt::ntt(&mut poly);
        t1_scaled_hat.push(poly);
    }

    let mut w_approx = vec![[0u32; 256]; k];
    for i in 0..k {
        let mut acc = [0u32; 256];
        // A * z_hat
        for j in 0..l {
            let prod = ntt::pointwise_mul(&a_hat[i][j], &z_hat[j]);
            for c in 0..256 {
                acc[c] = field::field_add(acc[c], prod[c]);
            }
        }
        // - c_hat * t1_scaled_hat
        let ct1 = ntt::pointwise_mul(&c_hat, &t1_scaled_hat[i]);
        for c in 0..256 {
            acc[c] = field::field_sub(acc[c], ct1[c]);
        }
        ntt::ntt_inverse(&mut acc);
        w_approx[i] = acc;
    }

    // Step 9: w1' = use_hint(h, w_approx)
    let mut w1_prime = vec![[0u32; 256]; k];
    for i in 0..k {
        for c in 0..256 {
            w1_prime[i][c] = decompose::use_hint(h[i][c], w_approx[i][c], alpha);
        }
    }

    // Step 10: c_tilde' = H(mu || encode(w1'), lambda/4)
    let w1_encoded = encode::encode_w1(&w1_prime, alpha);
    let mut hash_input = Vec::with_capacity(mu.len() + w1_encoded.len());
    hash_input.extend_from_slice(&mu);
    hash_input.extend_from_slice(&w1_encoded);
    let c_tilde_prime = hash::h(&hash_input, P::C_TILDE_SIZE);

    // Step 11: check c_tilde == c_tilde'
    c_tilde == c_tilde_prime
}

/// Check that all coefficients of a vector of polynomials have centered
/// infinity norm strictly less than `bound`.
fn check_norm_bound(polys: &[[u32; 256]], bound: u32) -> bool {
    for poly in polys {
        for &c in poly.iter() {
            if !coeff_in_range(c, bound) {
                return false;
            }
        }
    }
    true
}

/// Same as check_norm_bound for a vector.
fn check_norm_bound_single(polys: &[[u32; 256]], bound: u32) -> bool {
    check_norm_bound(polys, bound)
}

/// Check that a coefficient (mod q) has |coeff| < bound in centered representation.
/// coeff is in [0, q). The centered value is coeff if coeff <= (q-1)/2, else coeff - q.
/// We need |centered| < bound, i.e., centered in (-(bound), bound).
#[inline]
fn coeff_in_range(coeff: u32, bound: u32) -> bool {
    // Positive range: [0, bound-1]
    // Negative range: [q-bound+1, q-1]
    coeff < bound || coeff > Q - bound
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{MlDsa44, MlDsa65, MlDsa87};

    #[test]
    fn test_keygen_pk_sk_sizes_44() {
        let mut rng = rand::thread_rng();
        let (pk, sk) = keygen::<MlDsa44>(&mut rng);
        assert_eq!(pk.len(), MlDsa44::PK_SIZE);
        assert_eq!(sk.len(), MlDsa44::SK_SIZE);
    }

    #[test]
    fn test_keygen_pk_sk_sizes_65() {
        let mut rng = rand::thread_rng();
        let (pk, sk) = keygen::<MlDsa65>(&mut rng);
        assert_eq!(pk.len(), MlDsa65::PK_SIZE);
        assert_eq!(sk.len(), MlDsa65::SK_SIZE);
    }

    #[test]
    fn test_keygen_pk_sk_sizes_87() {
        let mut rng = rand::thread_rng();
        let (pk, sk) = keygen::<MlDsa87>(&mut rng);
        assert_eq!(pk.len(), MlDsa87::PK_SIZE);
        assert_eq!(sk.len(), MlDsa87::SK_SIZE);
    }

    #[test]
    fn test_sign_verify_roundtrip_44() {
        let mut rng = rand::thread_rng();
        let (pk, sk) = keygen::<MlDsa44>(&mut rng);
        let msg = b"Hello, ML-DSA-44!";
        let sig = sign::<MlDsa44>(&sk, msg);
        assert_eq!(sig.len(), MlDsa44::SIG_SIZE);
        assert!(verify::<MlDsa44>(&pk, msg, &sig));
    }

    #[test]
    fn test_sign_verify_roundtrip_65() {
        let mut rng = rand::thread_rng();
        let (pk, sk) = keygen::<MlDsa65>(&mut rng);
        let msg = b"Hello, ML-DSA-65!";
        let sig = sign::<MlDsa65>(&sk, msg);
        assert_eq!(sig.len(), MlDsa65::SIG_SIZE);
        assert!(verify::<MlDsa65>(&pk, msg, &sig));
    }

    #[test]
    fn test_sign_verify_roundtrip_87() {
        let mut rng = rand::thread_rng();
        let (pk, sk) = keygen::<MlDsa87>(&mut rng);
        let msg = b"Hello, ML-DSA-87!";
        let sig = sign::<MlDsa87>(&sk, msg);
        assert_eq!(sig.len(), MlDsa87::SIG_SIZE);
        assert!(verify::<MlDsa87>(&pk, msg, &sig));
    }

    #[test]
    fn test_verify_rejects_tampered_signature() {
        let mut rng = rand::thread_rng();
        let (pk, sk) = keygen::<MlDsa44>(&mut rng);
        let msg = b"Test message";
        let mut sig = sign::<MlDsa44>(&sk, msg);
        // Tamper with one byte
        sig[50] ^= 0xFF;
        assert!(!verify::<MlDsa44>(&pk, msg, &sig));
    }

    #[test]
    fn test_verify_rejects_wrong_message() {
        let mut rng = rand::thread_rng();
        let (pk, sk) = keygen::<MlDsa44>(&mut rng);
        let msg = b"Original message";
        let sig = sign::<MlDsa44>(&sk, msg);
        let wrong_msg = b"Wrong message";
        assert!(!verify::<MlDsa44>(&pk, wrong_msg, &sig));
    }

    #[test]
    fn test_deterministic_signing() {
        let mut rng = rand::thread_rng();
        let (_pk, sk) = keygen::<MlDsa44>(&mut rng);
        let msg = b"Deterministic test";
        let sig1 = sign::<MlDsa44>(&sk, msg);
        let sig2 = sign::<MlDsa44>(&sk, msg);
        assert_eq!(sig1, sig2, "deterministic signing should produce same signature");
    }

    #[test]
    fn test_different_messages_different_sigs() {
        let mut rng = rand::thread_rng();
        let (_, sk) = keygen::<MlDsa44>(&mut rng);
        let sig1 = sign::<MlDsa44>(&sk, b"Message 1");
        let sig2 = sign::<MlDsa44>(&sk, b"Message 2");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_empty_message() {
        let mut rng = rand::thread_rng();
        let (pk, sk) = keygen::<MlDsa44>(&mut rng);
        let msg = b"";
        let sig = sign::<MlDsa44>(&sk, msg);
        assert!(verify::<MlDsa44>(&pk, msg, &sig));
    }
}
