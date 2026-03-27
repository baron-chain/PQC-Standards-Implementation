//! TLS 1.3 PQC Cipher Suite definitions.
//!
//! Combines AEAD algorithm, key exchange named group, and signature algorithm
//! into cipher suite definitions suitable for TLS 1.3.

use crate::named_groups::NamedGroup;
use crate::sig_algorithms::SignatureAlgorithm;

/// AEAD algorithms used in TLS 1.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AeadAlgorithm {
    /// AES-128-GCM with SHA-256.
    Aes128GcmSha256,
    /// AES-256-GCM with SHA-384.
    Aes256GcmSha384,
    /// ChaCha20-Poly1305 with SHA-256.
    ChaCha20Poly1305Sha256,
}

impl AeadAlgorithm {
    /// Human-readable name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Aes128GcmSha256 => "TLS_AES_128_GCM_SHA256",
            Self::Aes256GcmSha384 => "TLS_AES_256_GCM_SHA384",
            Self::ChaCha20Poly1305Sha256 => "TLS_CHACHA20_POLY1305_SHA256",
        }
    }

    /// Key length in bytes.
    pub fn key_length(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            Self::Aes256GcmSha384 => 32,
            Self::ChaCha20Poly1305Sha256 => 32,
        }
    }

    /// Hash output length used for HKDF.
    pub fn hash_length(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 32,
            Self::Aes256GcmSha384 => 48,
            Self::ChaCha20Poly1305Sha256 => 32,
        }
    }
}

/// A TLS 1.3 PQC cipher suite combining AEAD, key exchange, and signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CipherSuite {
    /// Unique identifier for this cipher suite.
    pub id: u32,
    /// Human-readable name.
    pub name: &'static str,
    /// The AEAD algorithm.
    pub aead: AeadAlgorithm,
    /// The PQC named group for key exchange.
    pub key_exchange: NamedGroup,
    /// The default signature algorithm.
    pub signature: SignatureAlgorithm,
}

/// TLS_AES_128_GCM_SHA256 with ML-KEM-768 key exchange and ML-DSA-65 signatures.
pub const TLS_AES_128_GCM_SHA256_MLKEM768: CipherSuite = CipherSuite {
    id: 0x1301_0768,
    name: "TLS_AES_128_GCM_SHA256_MLKEM768",
    aead: AeadAlgorithm::Aes128GcmSha256,
    key_exchange: NamedGroup::MlKem768,
    signature: SignatureAlgorithm::MlDsa65,
};

/// TLS_AES_256_GCM_SHA384 with X25519+ML-KEM-768 hybrid key exchange and
/// ML-DSA-65+Ed25519 composite signatures.
pub const TLS_AES_256_GCM_SHA384_X25519MLKEM768: CipherSuite = CipherSuite {
    id: 0x1302_6399,
    name: "TLS_AES_256_GCM_SHA384_X25519MLKEM768",
    aead: AeadAlgorithm::Aes256GcmSha384,
    key_exchange: NamedGroup::X25519MlKem768,
    signature: SignatureAlgorithm::MlDsa65Ed25519,
};

/// All defined PQC cipher suites.
pub const ALL_CIPHER_SUITES: [CipherSuite; 2] = [
    TLS_AES_128_GCM_SHA256_MLKEM768,
    TLS_AES_256_GCM_SHA384_X25519MLKEM768,
];

/// Look up a cipher suite by its id.
pub fn cipher_suite_by_id(id: u32) -> Option<CipherSuite> {
    ALL_CIPHER_SUITES.iter().find(|cs| cs.id == id).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_suite_definitions() {
        let cs = TLS_AES_128_GCM_SHA256_MLKEM768;
        assert_eq!(cs.aead, AeadAlgorithm::Aes128GcmSha256);
        assert_eq!(cs.key_exchange, NamedGroup::MlKem768);
        assert_eq!(cs.signature, SignatureAlgorithm::MlDsa65);
    }

    #[test]
    fn test_cipher_suite_lookup_by_id() {
        let cs = cipher_suite_by_id(0x1301_0768);
        assert!(cs.is_some());
        assert_eq!(cs.unwrap().name, "TLS_AES_128_GCM_SHA256_MLKEM768");

        let cs2 = cipher_suite_by_id(0x1302_6399);
        assert!(cs2.is_some());
        assert_eq!(cs2.unwrap().name, "TLS_AES_256_GCM_SHA384_X25519MLKEM768");

        assert!(cipher_suite_by_id(0xDEAD_BEEF).is_none());
    }

    #[test]
    fn test_aead_properties() {
        assert_eq!(AeadAlgorithm::Aes128GcmSha256.key_length(), 16);
        assert_eq!(AeadAlgorithm::Aes256GcmSha384.key_length(), 32);
        assert_eq!(AeadAlgorithm::Aes128GcmSha256.hash_length(), 32);
        assert_eq!(AeadAlgorithm::Aes256GcmSha384.hash_length(), 48);
    }
}
