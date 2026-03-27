//! Hybrid KEM: combining classical key exchange with ML-KEM.
//!
//! Hybrid KEMs ensure security holds if **either** the classical or
//! post-quantum component remains secure.
//!
//! # Schemes
//!
//! | Scheme                  | Classical | Post-Quantum  | Security Level |
//! |------------------------|-----------|---------------|----------------|
//! | X25519+ML-KEM-768      | X25519    | ML-KEM-768    | ~128-bit       |
//! | ECDH-P256+ML-KEM-768   | P-256     | ML-KEM-768    | ~128-bit       |
//! | X25519+ML-KEM-1024     | X25519    | ML-KEM-1024   | ~192-bit       |
//! | ECDH-P384+ML-KEM-1024  | P-384     | ML-KEM-1024   | ~192-bit       |
//!
//! # KEM Combiner
//!
//! ```text
//! combined_ss = SHA3-256(ss_classical || ss_pq || label)
//! ```

pub mod hybrid_kem;

pub use hybrid_kem::{
    HybridKemScheme, HybridKeyPair, HybridEncapsResult,
    X25519MlKem768, EcdhP256MlKem768,
    X25519MlKem1024, EcdhP384MlKem1024,
};
