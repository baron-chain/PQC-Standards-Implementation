//! PQC Signature Algorithms for TLS 1.3.
//!
//! Defines PQC and composite signature algorithms for the `signature_algorithms`
//! extension (CertificateVerify), along with sign/verify helpers.

extern crate alloc;
use alloc::vec::Vec;
use rand_core::{CryptoRng, RngCore};

use ml_dsa::dsa::{keygen as mldsa_keygen, sign as mldsa_sign, verify as mldsa_verify};
use ml_dsa::params::{MlDsa44, MlDsa65, MlDsa87};
use composite_sig::composite_sig::{
    CompositeScheme, CompositeKeyPair, CompositeSig,
    key_gen as composite_keygen, sign as composite_sign, verify as composite_verify,
    MLDSA65_ED25519, MLDSA87_ED25519,
};

/// TLS 1.3 signature algorithm identifiers for PQC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SignatureAlgorithm {
    /// ML-DSA-44 (code point 0x0904).
    MlDsa44 = 0x0904,
    /// ML-DSA-65 (code point 0x0905).
    MlDsa65 = 0x0905,
    /// ML-DSA-87 (code point 0x0906).
    MlDsa87 = 0x0906,
    /// ML-DSA-65 + Ed25519 composite (code point 0x0907).
    MlDsa65Ed25519 = 0x0907,
    /// ML-DSA-87 + Ed25519 composite (code point 0x0908).
    MlDsa87Ed25519 = 0x0908,
}

impl SignatureAlgorithm {
    /// Return the code point as a u16.
    pub fn code_point(self) -> u16 {
        self as u16
    }

    /// Look up a signature algorithm by its TLS code point.
    pub fn from_code_point(cp: u16) -> Option<Self> {
        match cp {
            0x0904 => Some(Self::MlDsa44),
            0x0905 => Some(Self::MlDsa65),
            0x0906 => Some(Self::MlDsa87),
            0x0907 => Some(Self::MlDsa65Ed25519),
            0x0908 => Some(Self::MlDsa87Ed25519),
            _ => None,
        }
    }

    /// All defined signature algorithms.
    pub const ALL: [SignatureAlgorithm; 5] = [
        Self::MlDsa44,
        Self::MlDsa65,
        Self::MlDsa87,
        Self::MlDsa65Ed25519,
        Self::MlDsa87Ed25519,
    ];

    /// Human-readable name.
    pub fn name(self) -> &'static str {
        match self {
            Self::MlDsa44 => "MLDSA44",
            Self::MlDsa65 => "MLDSA65",
            Self::MlDsa87 => "MLDSA87",
            Self::MlDsa65Ed25519 => "MLDSA65_ED25519",
            Self::MlDsa87Ed25519 => "MLDSA87_ED25519",
        }
    }

    /// Whether this is a composite (hybrid) signature algorithm.
    pub fn is_composite(self) -> bool {
        matches!(self, Self::MlDsa65Ed25519 | Self::MlDsa87Ed25519)
    }
}

fn composite_scheme(alg: SignatureAlgorithm) -> CompositeScheme {
    match alg {
        SignatureAlgorithm::MlDsa65Ed25519 => MLDSA65_ED25519,
        SignatureAlgorithm::MlDsa87Ed25519 => MLDSA87_ED25519,
        _ => panic!("not a composite algorithm"),
    }
}

/// A signing key pair for a PQC signature algorithm.
pub struct SigningKeyPair {
    /// Public key bytes.
    pub pk: Vec<u8>,
    /// Secret key bytes.
    pub sk: Vec<u8>,
    /// The algorithm this key pair is for.
    pub algorithm: SignatureAlgorithm,
}

/// Generate a signing key pair for the given signature algorithm.
pub fn generate_signing_key(
    alg: SignatureAlgorithm,
    rng: &mut (impl CryptoRng + RngCore),
) -> SigningKeyPair {
    match alg {
        SignatureAlgorithm::MlDsa44 => {
            let (pk, sk) = mldsa_keygen::<MlDsa44>(rng);
            SigningKeyPair { pk, sk, algorithm: alg }
        }
        SignatureAlgorithm::MlDsa65 => {
            let (pk, sk) = mldsa_keygen::<MlDsa65>(rng);
            SigningKeyPair { pk, sk, algorithm: alg }
        }
        SignatureAlgorithm::MlDsa87 => {
            let (pk, sk) = mldsa_keygen::<MlDsa87>(rng);
            SigningKeyPair { pk, sk, algorithm: alg }
        }
        SignatureAlgorithm::MlDsa65Ed25519 | SignatureAlgorithm::MlDsa87Ed25519 => {
            let scheme = composite_scheme(alg);
            let kp = composite_keygen(scheme, rng);
            SigningKeyPair { pk: kp.pk, sk: kp.sk, algorithm: alg }
        }
    }
}

/// Sign a TLS 1.3 CertificateVerify handshake hash.
///
/// The `handshake_hash` is the transcript hash that forms the content
/// of the CertificateVerify message.
pub fn sign_handshake(
    alg: SignatureAlgorithm,
    sk: &[u8],
    handshake_hash: &[u8],
) -> Vec<u8> {
    match alg {
        SignatureAlgorithm::MlDsa44 => mldsa_sign::<MlDsa44>(sk, handshake_hash),
        SignatureAlgorithm::MlDsa65 => mldsa_sign::<MlDsa65>(sk, handshake_hash),
        SignatureAlgorithm::MlDsa87 => mldsa_sign::<MlDsa87>(sk, handshake_hash),
        SignatureAlgorithm::MlDsa65Ed25519 | SignatureAlgorithm::MlDsa87Ed25519 => {
            let scheme = composite_scheme(alg);
            let kp = CompositeKeyPair {
                pk: Vec::new(),
                sk: sk.to_vec(),
                scheme,
            };
            let sig = composite_sign(&kp, handshake_hash);
            sig.bytes
        }
    }
}

/// Verify a TLS 1.3 CertificateVerify signature.
pub fn verify_handshake(
    alg: SignatureAlgorithm,
    pk: &[u8],
    handshake_hash: &[u8],
    signature: &[u8],
) -> bool {
    match alg {
        SignatureAlgorithm::MlDsa44 => mldsa_verify::<MlDsa44>(pk, handshake_hash, signature),
        SignatureAlgorithm::MlDsa65 => mldsa_verify::<MlDsa65>(pk, handshake_hash, signature),
        SignatureAlgorithm::MlDsa87 => mldsa_verify::<MlDsa87>(pk, handshake_hash, signature),
        SignatureAlgorithm::MlDsa65Ed25519 | SignatureAlgorithm::MlDsa87Ed25519 => {
            let scheme = composite_scheme(alg);
            let sig = CompositeSig { bytes: signature.to_vec() };
            composite_verify(scheme, pk, handshake_hash, &sig)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_signature_algorithm_code_points() {
        assert_eq!(SignatureAlgorithm::MlDsa44.code_point(), 0x0904);
        assert_eq!(SignatureAlgorithm::MlDsa65.code_point(), 0x0905);
        assert_eq!(SignatureAlgorithm::MlDsa87.code_point(), 0x0906);
        assert_eq!(SignatureAlgorithm::MlDsa65Ed25519.code_point(), 0x0907);
        assert_eq!(SignatureAlgorithm::MlDsa87Ed25519.code_point(), 0x0908);
    }

    #[test]
    fn test_signature_algorithm_from_code_point() {
        assert_eq!(
            SignatureAlgorithm::from_code_point(0x0905),
            Some(SignatureAlgorithm::MlDsa65)
        );
        assert_eq!(SignatureAlgorithm::from_code_point(0xFFFF), None);
    }

    #[test]
    fn test_mldsa65_sign_verify() {
        let kp = generate_signing_key(SignatureAlgorithm::MlDsa65, &mut OsRng);
        let hash = b"test handshake transcript hash for CertificateVerify";
        let sig = sign_handshake(SignatureAlgorithm::MlDsa65, &kp.sk, hash);
        assert!(verify_handshake(SignatureAlgorithm::MlDsa65, &kp.pk, hash, &sig));
    }

    #[test]
    fn test_composite_mldsa65_ed25519_sign_verify() {
        let kp = generate_signing_key(SignatureAlgorithm::MlDsa65Ed25519, &mut OsRng);
        let hash = b"composite signature handshake hash";
        let sig = sign_handshake(SignatureAlgorithm::MlDsa65Ed25519, &kp.sk, hash);
        assert!(verify_handshake(SignatureAlgorithm::MlDsa65Ed25519, &kp.pk, hash, &sig));
    }

    #[test]
    fn test_wrong_key_fails_verification() {
        let kp1 = generate_signing_key(SignatureAlgorithm::MlDsa65, &mut OsRng);
        let kp2 = generate_signing_key(SignatureAlgorithm::MlDsa65, &mut OsRng);
        let hash = b"test hash";
        let sig = sign_handshake(SignatureAlgorithm::MlDsa65, &kp1.sk, hash);
        assert!(!verify_handshake(SignatureAlgorithm::MlDsa65, &kp2.pk, hash, &sig));
    }
}
