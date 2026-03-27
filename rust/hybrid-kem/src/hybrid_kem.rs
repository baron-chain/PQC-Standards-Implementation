//! Hybrid KEM implementation combining classical ECDH with ML-KEM.
//!
//! The combiner follows:
//! - KeyGen: generate both classical and PQ key pairs
//! - Encaps: run both encapsulations, combine ciphertexts and derive shared secret
//! - Decaps: split ciphertext, run both decapsulations, combine shared secrets
//!
//! Combined shared secret = SHA3-256(ss_classical || ss_pq || label)

extern crate alloc;
use alloc::vec::Vec;
use rand_core::{CryptoRng, RngCore};
use sha3::{Sha3_256, Digest};

use ml_kem::kem::{keygen as mlkem_keygen, encapsulate as mlkem_encaps, decapsulate as mlkem_decaps};
use ml_kem::params::{MlKem768, MlKem1024};

// ─── Types ───────────────────────────────────────────────────────────────────

/// A hybrid key pair containing both classical and post-quantum keys.
pub struct HybridKeyPair {
    /// Combined encapsulation key (classical_ek || pq_ek).
    pub ek: Vec<u8>,
    /// Combined decapsulation key (classical_dk || pq_dk).
    pub dk: Vec<u8>,
    /// Size of the classical encapsulation key portion.
    pub classical_ek_size: usize,
    /// Size of the classical decapsulation key portion.
    pub classical_dk_size: usize,
}

/// Result of hybrid encapsulation.
pub struct HybridEncapsResult {
    /// Combined shared secret (32 bytes, output of SHA3-256).
    pub shared_secret: [u8; 32],
    /// Combined ciphertext (classical_ct || pq_ct).
    pub ciphertext: Vec<u8>,
    /// Size of the classical ciphertext portion.
    pub classical_ct_size: usize,
}

// ─── Trait ───────────────────────────────────────────────────────────────────

/// Trait defining a hybrid KEM scheme.
pub trait HybridKemScheme {
    /// Human-readable label for the KDF domain separation.
    const LABEL: &'static [u8];

    /// Generate a hybrid key pair.
    fn keygen(rng: &mut (impl CryptoRng + RngCore)) -> HybridKeyPair;

    /// Encapsulate: produce a shared secret and ciphertext.
    fn encaps(ek: &[u8], rng: &mut (impl CryptoRng + RngCore)) -> HybridEncapsResult;

    /// Decapsulate: recover the shared secret from the ciphertext.
    fn decaps(dk: &[u8], ct: &[u8], classical_dk_size: usize, classical_ct_size: usize) -> [u8; 32];
}

// ─── KDF combiner ────────────────────────────────────────────────────────────

/// Combine two shared secrets with a label using SHA3-256.
fn combine_secrets(ss_classical: &[u8], ss_pq: &[u8], label: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(ss_classical);
    hasher.update(ss_pq);
    hasher.update(label);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// ─── X25519 helpers ──────────────────────────────────────────────────────────

fn x25519_keygen(rng: &mut (impl CryptoRng + RngCore)) -> ([u8; 32], [u8; 32]) {
    use x25519_dalek::{StaticSecret, PublicKey};
    let secret = StaticSecret::random_from_rng(rng);
    let public = PublicKey::from(&secret);
    (*public.as_bytes(), secret.to_bytes())
}

/// X25519 KEM encapsulation: generate ephemeral keypair, DH with peer.
/// Returns (shared_secret, ephemeral_public_key_as_ciphertext).
fn x25519_encaps(peer_pk: &[u8; 32], rng: &mut (impl CryptoRng + RngCore)) -> ([u8; 32], [u8; 32]) {
    use x25519_dalek::{StaticSecret, PublicKey};
    let eph_secret = StaticSecret::random_from_rng(rng);
    let eph_public = PublicKey::from(&eph_secret);
    let peer = PublicKey::from(*peer_pk);
    let shared = eph_secret.diffie_hellman(&peer);
    (*shared.as_bytes(), *eph_public.as_bytes())
}

/// X25519 KEM decapsulation: DH with our secret and the ephemeral public key.
fn x25519_decaps(sk: &[u8; 32], ct: &[u8; 32]) -> [u8; 32] {
    use x25519_dalek::{StaticSecret, PublicKey};
    let secret = StaticSecret::from(*sk);
    let peer = PublicKey::from(*ct);
    let shared = secret.diffie_hellman(&peer);
    *shared.as_bytes()
}

// ─── NIST curve ECDH helpers ─────────────────────────────────────────────────

fn p256_keygen(rng: &mut (impl CryptoRng + RngCore)) -> (Vec<u8>, Vec<u8>) {
    let secret = p256::SecretKey::random(rng);
    let public = secret.public_key();
    let pk_bytes = public.to_sec1_bytes().to_vec();
    let sk_bytes = secret.to_bytes().to_vec();
    (pk_bytes, sk_bytes)
}

fn p256_encaps(peer_pk_bytes: &[u8], rng: &mut (impl CryptoRng + RngCore)) -> (Vec<u8>, Vec<u8>) {
    use p256::ecdh::EphemeralSecret;
    let secret = EphemeralSecret::random(rng);
    let eph_public = p256::PublicKey::from(&secret);
    let peer = p256::PublicKey::from_sec1_bytes(peer_pk_bytes).expect("invalid P-256 public key");
    let shared = secret.diffie_hellman(&peer);
    (shared.raw_secret_bytes().to_vec(), eph_public.to_sec1_bytes().to_vec())
}

fn p256_decaps(sk_bytes: &[u8], ct_bytes: &[u8]) -> Vec<u8> {
    let sk = p256::SecretKey::from_slice(sk_bytes).expect("invalid P-256 secret key");
    let peer = p256::PublicKey::from_sec1_bytes(ct_bytes).expect("invalid P-256 public key");
    let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
    shared.raw_secret_bytes().to_vec()
}

fn p384_keygen(rng: &mut (impl CryptoRng + RngCore)) -> (Vec<u8>, Vec<u8>) {
    let secret = p384::SecretKey::random(rng);
    let public = secret.public_key();
    let pk_bytes = public.to_sec1_bytes().to_vec();
    let sk_bytes = secret.to_bytes().to_vec();
    (pk_bytes, sk_bytes)
}

fn p384_encaps(peer_pk_bytes: &[u8], rng: &mut (impl CryptoRng + RngCore)) -> (Vec<u8>, Vec<u8>) {
    use p384::ecdh::EphemeralSecret;
    let secret = EphemeralSecret::random(rng);
    let eph_public = p384::PublicKey::from(&secret);
    let peer = p384::PublicKey::from_sec1_bytes(peer_pk_bytes).expect("invalid P-384 public key");
    let shared = secret.diffie_hellman(&peer);
    (shared.raw_secret_bytes().to_vec(), eph_public.to_sec1_bytes().to_vec())
}

fn p384_decaps(sk_bytes: &[u8], ct_bytes: &[u8]) -> Vec<u8> {
    let sk = p384::SecretKey::from_slice(sk_bytes).expect("invalid P-384 secret key");
    let peer = p384::PublicKey::from_sec1_bytes(ct_bytes).expect("invalid P-384 public key");
    let shared = p384::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
    shared.raw_secret_bytes().to_vec()
}

// ─── Scheme: X25519 + ML-KEM-768 ────────────────────────────────────────────

/// X25519 + ML-KEM-768 hybrid KEM (IETF standard hybrid for TLS).
pub struct X25519MlKem768;

const X25519_PK_SIZE: usize = 32;
const X25519_SK_SIZE: usize = 32;
const X25519_CT_SIZE: usize = 32;

impl HybridKemScheme for X25519MlKem768 {
    const LABEL: &'static [u8] = b"X25519-MLKEM768";

    fn keygen(rng: &mut (impl CryptoRng + RngCore)) -> HybridKeyPair {
        let (classical_pk, classical_sk) = x25519_keygen(rng);
        let (pq_ek, pq_dk) = mlkem_keygen::<MlKem768>(rng);

        let mut ek = Vec::with_capacity(X25519_PK_SIZE + pq_ek.len());
        ek.extend_from_slice(&classical_pk);
        ek.extend_from_slice(&pq_ek);

        let mut dk = Vec::with_capacity(X25519_SK_SIZE + pq_dk.len());
        dk.extend_from_slice(&classical_sk);
        dk.extend_from_slice(&pq_dk);

        HybridKeyPair {
            ek,
            dk,
            classical_ek_size: X25519_PK_SIZE,
            classical_dk_size: X25519_SK_SIZE,
        }
    }

    fn encaps(ek: &[u8], rng: &mut (impl CryptoRng + RngCore)) -> HybridEncapsResult {
        let classical_pk: &[u8; 32] = ek[..X25519_PK_SIZE].try_into().unwrap();
        let pq_ek = &ek[X25519_PK_SIZE..];

        let (ss_classical, ct_classical) = x25519_encaps(classical_pk, rng);
        let (ss_pq, ct_pq) = mlkem_encaps::<MlKem768>(pq_ek, rng);

        let combined_ss = combine_secrets(&ss_classical, &ss_pq, Self::LABEL);

        let mut ciphertext = Vec::with_capacity(X25519_CT_SIZE + ct_pq.len());
        ciphertext.extend_from_slice(&ct_classical);
        ciphertext.extend_from_slice(&ct_pq);

        HybridEncapsResult {
            shared_secret: combined_ss,
            ciphertext,
            classical_ct_size: X25519_CT_SIZE,
        }
    }

    fn decaps(dk: &[u8], ct: &[u8], _classical_dk_size: usize, classical_ct_size: usize) -> [u8; 32] {
        let classical_sk: &[u8; 32] = dk[..X25519_SK_SIZE].try_into().unwrap();
        let pq_dk = &dk[X25519_SK_SIZE..];

        let ct_classical: &[u8; 32] = ct[..classical_ct_size].try_into().unwrap();
        let ct_pq = &ct[classical_ct_size..];

        let ss_classical = x25519_decaps(classical_sk, ct_classical);
        let ss_pq = mlkem_decaps::<MlKem768>(pq_dk, ct_pq);

        combine_secrets(&ss_classical, &ss_pq, Self::LABEL)
    }
}

// ─── Scheme: ECDH-P256 + ML-KEM-768 ─────────────────────────────────────────

/// ECDH-P256 + ML-KEM-768 hybrid KEM for NIST curve users.
pub struct EcdhP256MlKem768;

impl HybridKemScheme for EcdhP256MlKem768 {
    const LABEL: &'static [u8] = b"ECDHP256-MLKEM768";

    fn keygen(rng: &mut (impl CryptoRng + RngCore)) -> HybridKeyPair {
        let (classical_pk, classical_sk) = p256_keygen(rng);
        let (pq_ek, pq_dk) = mlkem_keygen::<MlKem768>(rng);

        let classical_pk_size = classical_pk.len();
        let classical_sk_size = classical_sk.len();

        let mut ek = Vec::with_capacity(classical_pk.len() + pq_ek.len());
        ek.extend_from_slice(&classical_pk);
        ek.extend_from_slice(&pq_ek);

        let mut dk = Vec::with_capacity(classical_sk.len() + pq_dk.len());
        dk.extend_from_slice(&classical_sk);
        dk.extend_from_slice(&pq_dk);

        HybridKeyPair {
            ek,
            dk,
            classical_ek_size: classical_pk_size,
            classical_dk_size: classical_sk_size,
        }
    }

    fn encaps(ek: &[u8], rng: &mut (impl CryptoRng + RngCore)) -> HybridEncapsResult {
        // Determine P-256 public key size from encoding prefix
        let pk_size = if ek[0] == 0x04 { 65 } else { 33 };
        let classical_pk = &ek[..pk_size];
        let pq_ek = &ek[pk_size..];

        let (ss_classical, ct_classical) = p256_encaps(classical_pk, rng);
        let (ss_pq, ct_pq) = mlkem_encaps::<MlKem768>(pq_ek, rng);

        let ct_classical_size = ct_classical.len();
        let combined_ss = combine_secrets(&ss_classical, &ss_pq, Self::LABEL);

        let mut ciphertext = Vec::with_capacity(ct_classical.len() + ct_pq.len());
        ciphertext.extend_from_slice(&ct_classical);
        ciphertext.extend_from_slice(&ct_pq);

        HybridEncapsResult {
            shared_secret: combined_ss,
            ciphertext,
            classical_ct_size: ct_classical_size,
        }
    }

    fn decaps(dk: &[u8], ct: &[u8], classical_dk_size: usize, classical_ct_size: usize) -> [u8; 32] {
        let classical_sk = &dk[..classical_dk_size];
        let pq_dk = &dk[classical_dk_size..];

        let ct_classical = &ct[..classical_ct_size];
        let ct_pq = &ct[classical_ct_size..];

        let ss_classical = p256_decaps(classical_sk, ct_classical);
        let ss_pq = mlkem_decaps::<MlKem768>(pq_dk, ct_pq);

        combine_secrets(&ss_classical, &ss_pq, Self::LABEL)
    }
}

// ─── Scheme: X25519 + ML-KEM-1024 ───────────────────────────────────────────

/// X25519 + ML-KEM-1024 hybrid KEM (higher security variant).
pub struct X25519MlKem1024;

impl HybridKemScheme for X25519MlKem1024 {
    const LABEL: &'static [u8] = b"X25519-MLKEM1024";

    fn keygen(rng: &mut (impl CryptoRng + RngCore)) -> HybridKeyPair {
        let (classical_pk, classical_sk) = x25519_keygen(rng);
        let (pq_ek, pq_dk) = mlkem_keygen::<MlKem1024>(rng);

        let mut ek = Vec::with_capacity(X25519_PK_SIZE + pq_ek.len());
        ek.extend_from_slice(&classical_pk);
        ek.extend_from_slice(&pq_ek);

        let mut dk = Vec::with_capacity(X25519_SK_SIZE + pq_dk.len());
        dk.extend_from_slice(&classical_sk);
        dk.extend_from_slice(&pq_dk);

        HybridKeyPair {
            ek,
            dk,
            classical_ek_size: X25519_PK_SIZE,
            classical_dk_size: X25519_SK_SIZE,
        }
    }

    fn encaps(ek: &[u8], rng: &mut (impl CryptoRng + RngCore)) -> HybridEncapsResult {
        let classical_pk: &[u8; 32] = ek[..X25519_PK_SIZE].try_into().unwrap();
        let pq_ek = &ek[X25519_PK_SIZE..];

        let (ss_classical, ct_classical) = x25519_encaps(classical_pk, rng);
        let (ss_pq, ct_pq) = mlkem_encaps::<MlKem1024>(pq_ek, rng);

        let combined_ss = combine_secrets(&ss_classical, &ss_pq, Self::LABEL);

        let mut ciphertext = Vec::with_capacity(X25519_CT_SIZE + ct_pq.len());
        ciphertext.extend_from_slice(&ct_classical);
        ciphertext.extend_from_slice(&ct_pq);

        HybridEncapsResult {
            shared_secret: combined_ss,
            ciphertext,
            classical_ct_size: X25519_CT_SIZE,
        }
    }

    fn decaps(dk: &[u8], ct: &[u8], _classical_dk_size: usize, classical_ct_size: usize) -> [u8; 32] {
        let classical_sk: &[u8; 32] = dk[..X25519_SK_SIZE].try_into().unwrap();
        let pq_dk = &dk[X25519_SK_SIZE..];

        let ct_classical: &[u8; 32] = ct[..classical_ct_size].try_into().unwrap();
        let ct_pq = &ct[classical_ct_size..];

        let ss_classical = x25519_decaps(classical_sk, ct_classical);
        let ss_pq = mlkem_decaps::<MlKem1024>(pq_dk, ct_pq);

        combine_secrets(&ss_classical, &ss_pq, Self::LABEL)
    }
}

// ─── Scheme: ECDH-P384 + ML-KEM-1024 ────────────────────────────────────────

/// ECDH-P384 + ML-KEM-1024 hybrid KEM (higher security with NIST curves).
pub struct EcdhP384MlKem1024;

impl HybridKemScheme for EcdhP384MlKem1024 {
    const LABEL: &'static [u8] = b"ECDHP384-MLKEM1024";

    fn keygen(rng: &mut (impl CryptoRng + RngCore)) -> HybridKeyPair {
        let (classical_pk, classical_sk) = p384_keygen(rng);
        let (pq_ek, pq_dk) = mlkem_keygen::<MlKem1024>(rng);

        let classical_pk_size = classical_pk.len();
        let classical_sk_size = classical_sk.len();

        let mut ek = Vec::with_capacity(classical_pk.len() + pq_ek.len());
        ek.extend_from_slice(&classical_pk);
        ek.extend_from_slice(&pq_ek);

        let mut dk = Vec::with_capacity(classical_sk.len() + pq_dk.len());
        dk.extend_from_slice(&classical_sk);
        dk.extend_from_slice(&pq_dk);

        HybridKeyPair {
            ek,
            dk,
            classical_ek_size: classical_pk_size,
            classical_dk_size: classical_sk_size,
        }
    }

    fn encaps(ek: &[u8], rng: &mut (impl CryptoRng + RngCore)) -> HybridEncapsResult {
        // P-384: uncompressed=97 bytes (0x04 prefix), compressed=49 bytes
        let pk_size = if ek[0] == 0x04 { 97 } else { 49 };
        let classical_pk = &ek[..pk_size];
        let pq_ek = &ek[pk_size..];

        let (ss_classical, ct_classical) = p384_encaps(classical_pk, rng);
        let (ss_pq, ct_pq) = mlkem_encaps::<MlKem1024>(pq_ek, rng);

        let ct_classical_size = ct_classical.len();
        let combined_ss = combine_secrets(&ss_classical, &ss_pq, Self::LABEL);

        let mut ciphertext = Vec::with_capacity(ct_classical.len() + ct_pq.len());
        ciphertext.extend_from_slice(&ct_classical);
        ciphertext.extend_from_slice(&ct_pq);

        HybridEncapsResult {
            shared_secret: combined_ss,
            ciphertext,
            classical_ct_size: ct_classical_size,
        }
    }

    fn decaps(dk: &[u8], ct: &[u8], classical_dk_size: usize, classical_ct_size: usize) -> [u8; 32] {
        let classical_sk = &dk[..classical_dk_size];
        let pq_dk = &dk[classical_dk_size..];

        let ct_classical = &ct[..classical_ct_size];
        let ct_pq = &ct[classical_ct_size..];

        let ss_classical = p384_decaps(classical_sk, ct_classical);
        let ss_pq = mlkem_decaps::<MlKem1024>(pq_dk, ct_pq);

        combine_secrets(&ss_classical, &ss_pq, Self::LABEL)
    }
}

// ─── Convenience functions ───────────────────────────────────────────────────

/// Generate a hybrid key pair for any scheme.
pub fn hybrid_keygen<S: HybridKemScheme>(rng: &mut (impl CryptoRng + RngCore)) -> HybridKeyPair {
    S::keygen(rng)
}

/// Encapsulate using a hybrid scheme.
pub fn hybrid_encaps<S: HybridKemScheme>(ek: &[u8], rng: &mut (impl CryptoRng + RngCore)) -> HybridEncapsResult {
    S::encaps(ek, rng)
}

/// Decapsulate using a hybrid scheme.
pub fn hybrid_decaps<S: HybridKemScheme>(
    dk: &[u8],
    ct: &[u8],
    classical_dk_size: usize,
    classical_ct_size: usize,
) -> [u8; 32] {
    S::decaps(dk, ct, classical_dk_size, classical_ct_size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn roundtrip_test<S: HybridKemScheme>(name: &str) {
        let kp = S::keygen(&mut OsRng);
        let enc = S::encaps(&kp.ek, &mut OsRng);
        let ss = S::decaps(
            &kp.dk,
            &enc.ciphertext,
            kp.classical_dk_size,
            enc.classical_ct_size,
        );
        assert_eq!(enc.shared_secret, ss, "{name} roundtrip failed");
    }

    #[test]
    fn test_x25519_mlkem768_roundtrip() {
        roundtrip_test::<X25519MlKem768>("X25519+ML-KEM-768");
    }

    #[test]
    fn test_ecdh_p256_mlkem768_roundtrip() {
        roundtrip_test::<EcdhP256MlKem768>("ECDH-P256+ML-KEM-768");
    }

    #[test]
    fn test_x25519_mlkem1024_roundtrip() {
        roundtrip_test::<X25519MlKem1024>("X25519+ML-KEM-1024");
    }

    #[test]
    fn test_ecdh_p384_mlkem1024_roundtrip() {
        roundtrip_test::<EcdhP384MlKem1024>("ECDH-P384+ML-KEM-1024");
    }

    #[test]
    fn test_different_keys_different_secrets() {
        let kp1 = X25519MlKem768::keygen(&mut OsRng);
        let kp2 = X25519MlKem768::keygen(&mut OsRng);
        let enc1 = X25519MlKem768::encaps(&kp1.ek, &mut OsRng);
        let enc2 = X25519MlKem768::encaps(&kp2.ek, &mut OsRng);
        assert_ne!(enc1.shared_secret, enc2.shared_secret);
    }

    #[test]
    fn test_shared_secret_is_32_bytes() {
        let kp = X25519MlKem768::keygen(&mut OsRng);
        let enc = X25519MlKem768::encaps(&kp.ek, &mut OsRng);
        assert_eq!(enc.shared_secret.len(), 32);
    }

    #[test]
    fn test_multiple_encaps_same_key_different_secrets() {
        let kp = X25519MlKem768::keygen(&mut OsRng);
        let enc1 = X25519MlKem768::encaps(&kp.ek, &mut OsRng);
        let enc2 = X25519MlKem768::encaps(&kp.ek, &mut OsRng);
        // Each encapsulation should produce a different shared secret
        assert_ne!(enc1.shared_secret, enc2.shared_secret);
        // But both should roundtrip correctly
        let ss1 = X25519MlKem768::decaps(&kp.dk, &enc1.ciphertext, kp.classical_dk_size, enc1.classical_ct_size);
        let ss2 = X25519MlKem768::decaps(&kp.dk, &enc2.ciphertext, kp.classical_dk_size, enc2.classical_ct_size);
        assert_eq!(enc1.shared_secret, ss1);
        assert_eq!(enc2.shared_secret, ss2);
    }
}
