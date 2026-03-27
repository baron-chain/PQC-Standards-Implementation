//! PQC Named Groups for TLS 1.3 key exchange.
//!
//! Defines PQC and hybrid named groups for the `supported_groups` extension
//! (ClientHello/ServerHello), along with key share generation and exchange
//! completion helpers.

extern crate alloc;
use alloc::vec::Vec;
use rand_core::{CryptoRng, RngCore};

use ml_kem::kem::{keygen as mlkem_keygen, encapsulate as mlkem_encaps, decapsulate as mlkem_decaps};
use ml_kem::params::{MlKem768, MlKem1024, ParameterSet};
use hybrid_kem::{
    X25519MlKem768, EcdhP256MlKem768,
    HybridKemScheme,
};

/// TLS 1.3 named group identifiers for PQC key exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum NamedGroup {
    /// Pure ML-KEM-768 (IANA code point 0x0768).
    MlKem768 = 0x0768,
    /// Pure ML-KEM-1024 (IANA code point 0x1024).
    MlKem1024 = 0x1024,
    /// X25519 + ML-KEM-768 hybrid (Chrome/Firefox default, code point 0x6399).
    X25519MlKem768 = 0x6399,
    /// P-256 + ML-KEM-768 hybrid (code point 0x639A).
    SecP256r1MlKem768 = 0x639A,
}

impl NamedGroup {
    /// Return the code point as a u16.
    pub fn code_point(self) -> u16 {
        self as u16
    }

    /// Look up a named group by its TLS code point.
    pub fn from_code_point(cp: u16) -> Option<Self> {
        match cp {
            0x0768 => Some(Self::MlKem768),
            0x1024 => Some(Self::MlKem1024),
            0x6399 => Some(Self::X25519MlKem768),
            0x639A => Some(Self::SecP256r1MlKem768),
            _ => None,
        }
    }

    /// All defined named groups.
    pub const ALL: [NamedGroup; 4] = [
        Self::MlKem768,
        Self::MlKem1024,
        Self::X25519MlKem768,
        Self::SecP256r1MlKem768,
    ];

    /// Human-readable name.
    pub fn name(self) -> &'static str {
        match self {
            Self::MlKem768 => "MLKEM768",
            Self::MlKem1024 => "MLKEM1024",
            Self::X25519MlKem768 => "X25519MLKEM768",
            Self::SecP256r1MlKem768 => "SecP256r1MLKEM768",
        }
    }
}

/// Result of generating a key share for a named group.
pub struct KeyShareResult {
    /// Private key material (kept secret; used in `complete_key_exchange`).
    pub private_key: Vec<u8>,
    /// Public key share bytes to include in the TLS ClientHello/ServerHello.
    pub public_key_share: Vec<u8>,
    /// For hybrid groups: the classical EK size boundary in `public_key_share`.
    pub classical_ek_size: usize,
    /// For hybrid groups: the classical DK size boundary in `private_key`.
    pub classical_dk_size: usize,
}

/// Generate a key share for the given named group.
///
/// Returns private key material and the public key share bytes
/// suitable for inclusion in a TLS 1.3 `key_share` extension entry.
pub fn generate_key_share(
    group: NamedGroup,
    rng: &mut (impl CryptoRng + RngCore),
) -> KeyShareResult {
    match group {
        NamedGroup::MlKem768 => {
            let (ek, dk) = mlkem_keygen::<MlKem768>(rng);
            KeyShareResult {
                private_key: dk,
                public_key_share: ek,
                classical_ek_size: 0,
                classical_dk_size: 0,
            }
        }
        NamedGroup::MlKem1024 => {
            let (ek, dk) = mlkem_keygen::<MlKem1024>(rng);
            KeyShareResult {
                private_key: dk,
                public_key_share: ek,
                classical_ek_size: 0,
                classical_dk_size: 0,
            }
        }
        NamedGroup::X25519MlKem768 => {
            let kp = X25519MlKem768::keygen(rng);
            KeyShareResult {
                classical_ek_size: kp.classical_ek_size,
                classical_dk_size: kp.classical_dk_size,
                private_key: kp.dk,
                public_key_share: kp.ek,
            }
        }
        NamedGroup::SecP256r1MlKem768 => {
            let kp = EcdhP256MlKem768::keygen(rng);
            KeyShareResult {
                classical_ek_size: kp.classical_ek_size,
                classical_dk_size: kp.classical_dk_size,
                private_key: kp.dk,
                public_key_share: kp.ek,
            }
        }
    }
}

/// Result of a completed key exchange.
pub struct KeyExchangeResult {
    /// The derived shared secret (32 bytes).
    pub shared_secret: [u8; 32],
    /// The ciphertext / key share response to send to the peer.
    pub response_key_share: Vec<u8>,
    /// Classical ciphertext size (for hybrid groups).
    pub classical_ct_size: usize,
}

/// Complete a key exchange as the responder (ServerHello side).
///
/// Given our private key and the peer's public key share, produce
/// the shared secret and the response key share (ciphertext).
pub fn complete_key_exchange(
    group: NamedGroup,
    peer_key_share: &[u8],
    rng: &mut (impl CryptoRng + RngCore),
) -> KeyExchangeResult {
    match group {
        NamedGroup::MlKem768 => {
            let (ss, ct) = mlkem_encaps::<MlKem768>(peer_key_share, rng);
            KeyExchangeResult {
                shared_secret: ss,
                response_key_share: ct,
                classical_ct_size: 0,
            }
        }
        NamedGroup::MlKem1024 => {
            let (ss, ct) = mlkem_encaps::<MlKem1024>(peer_key_share, rng);
            KeyExchangeResult {
                shared_secret: ss,
                response_key_share: ct,
                classical_ct_size: 0,
            }
        }
        NamedGroup::X25519MlKem768 => {
            let enc = X25519MlKem768::encaps(peer_key_share, rng);
            KeyExchangeResult {
                shared_secret: enc.shared_secret,
                response_key_share: enc.ciphertext,
                classical_ct_size: enc.classical_ct_size,
            }
        }
        NamedGroup::SecP256r1MlKem768 => {
            let enc = EcdhP256MlKem768::encaps(peer_key_share, rng);
            KeyExchangeResult {
                shared_secret: enc.shared_secret,
                response_key_share: enc.ciphertext,
                classical_ct_size: enc.classical_ct_size,
            }
        }
    }
}

/// Recover the shared secret as the initiator (ClientHello side).
///
/// Given our private key (from `generate_key_share`) and the peer's
/// response key share (ciphertext from `complete_key_exchange`),
/// recover the shared secret.
pub fn recover_shared_secret(
    group: NamedGroup,
    private_key: &[u8],
    peer_response: &[u8],
    classical_dk_size: usize,
    classical_ct_size: usize,
) -> [u8; 32] {
    match group {
        NamedGroup::MlKem768 => {
            mlkem_decaps::<MlKem768>(private_key, peer_response)
        }
        NamedGroup::MlKem1024 => {
            mlkem_decaps::<MlKem1024>(private_key, peer_response)
        }
        NamedGroup::X25519MlKem768 => {
            X25519MlKem768::decaps(private_key, peer_response, classical_dk_size, classical_ct_size)
        }
        NamedGroup::SecP256r1MlKem768 => {
            EcdhP256MlKem768::decaps(private_key, peer_response, classical_dk_size, classical_ct_size)
        }
    }
}

/// Expected public key share size for a named group.
pub fn key_share_size(group: NamedGroup) -> usize {
    match group {
        NamedGroup::MlKem768 => MlKem768::EK_SIZE,
        NamedGroup::MlKem1024 => MlKem1024::EK_SIZE,
        // X25519 (32) + ML-KEM-768 EK (1184) = 1216
        NamedGroup::X25519MlKem768 => 32 + MlKem768::EK_SIZE,
        // P-256 uncompressed (65) + ML-KEM-768 EK (1184) = 1249
        NamedGroup::SecP256r1MlKem768 => 65 + MlKem768::EK_SIZE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_named_group_code_points() {
        assert_eq!(NamedGroup::MlKem768.code_point(), 0x0768);
        assert_eq!(NamedGroup::MlKem1024.code_point(), 0x1024);
        assert_eq!(NamedGroup::X25519MlKem768.code_point(), 0x6399);
        assert_eq!(NamedGroup::SecP256r1MlKem768.code_point(), 0x639A);
    }

    #[test]
    fn test_named_group_from_code_point() {
        assert_eq!(NamedGroup::from_code_point(0x0768), Some(NamedGroup::MlKem768));
        assert_eq!(NamedGroup::from_code_point(0x6399), Some(NamedGroup::X25519MlKem768));
        assert_eq!(NamedGroup::from_code_point(0xFFFF), None);
    }

    #[test]
    fn test_mlkem768_key_exchange_roundtrip() {
        let ks = generate_key_share(NamedGroup::MlKem768, &mut OsRng);
        assert_eq!(ks.public_key_share.len(), MlKem768::EK_SIZE);
        let resp = complete_key_exchange(NamedGroup::MlKem768, &ks.public_key_share, &mut OsRng);
        let ss = recover_shared_secret(
            NamedGroup::MlKem768,
            &ks.private_key,
            &resp.response_key_share,
            ks.classical_dk_size,
            resp.classical_ct_size,
        );
        assert_eq!(resp.shared_secret, ss);
    }

    #[test]
    fn test_x25519_mlkem768_key_exchange_roundtrip() {
        let ks = generate_key_share(NamedGroup::X25519MlKem768, &mut OsRng);
        assert_eq!(ks.public_key_share.len(), key_share_size(NamedGroup::X25519MlKem768));
        let resp = complete_key_exchange(NamedGroup::X25519MlKem768, &ks.public_key_share, &mut OsRng);
        let ss = recover_shared_secret(
            NamedGroup::X25519MlKem768,
            &ks.private_key,
            &resp.response_key_share,
            ks.classical_dk_size,
            resp.classical_ct_size,
        );
        assert_eq!(resp.shared_secret, ss);
    }

    #[test]
    fn test_all_groups_key_share_sizes() {
        for &group in &NamedGroup::ALL {
            let ks = generate_key_share(group, &mut OsRng);
            assert_eq!(
                ks.public_key_share.len(),
                key_share_size(group),
                "Key share size mismatch for {:?}",
                group
            );
        }
    }
}
