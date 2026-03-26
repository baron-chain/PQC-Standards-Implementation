#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Pure Rust implementation of ML-KEM (FIPS 203).
//!
//! ML-KEM is a key encapsulation mechanism based on the Module Learning
//! With Errors (MLWE) problem, standardized by NIST as FIPS 203.
//! It provides IND-CCA2 security through the Fujisaki-Okamoto transform.
//!
//! # Parameter Sets
//!
//! | Parameter Set | Security Level | Encaps Key | Ciphertext | Shared Secret |
//! |---------------|---------------|------------|------------|---------------|
//! | ML-KEM-512    | 1 (128-bit)   | 800 bytes  | 768 bytes  | 32 bytes      |
//! | ML-KEM-768    | 3 (192-bit)   | 1184 bytes | 1088 bytes | 32 bytes      |
//! | ML-KEM-1024   | 5 (256-bit)   | 1568 bytes | 1568 bytes | 32 bytes      |
//!
//! ML-KEM-768 is recommended for most applications.
//!
//! # Security Properties
//!
//! - All secret-dependent operations are constant-time (via `subtle` crate)
//! - Implicit rejection on decapsulation failure (no error oracle)
//! - Randomness sourced from caller-provided CSPRNG
//! - No `unsafe` code
//!
//! # Usage
//!
//! ```
//! use ml_kem::kem::{keygen, encapsulate, decapsulate};
//! use ml_kem::params::MlKem768;
//! use rand::rngs::OsRng;
//!
//! // Key generation
//! let (encapsulation_key, decapsulation_key) = keygen::<MlKem768>(&mut OsRng);
//!
//! // Encapsulation (sender)
//! let (shared_secret, ciphertext) = encapsulate::<MlKem768>(&encapsulation_key, &mut OsRng);
//!
//! // Decapsulation (receiver)
//! let recovered_secret = decapsulate::<MlKem768>(&decapsulation_key, &ciphertext);
//!
//! assert_eq!(shared_secret, recovered_secret);
//! ```

#[cfg(feature = "alloc")]
extern crate alloc;

// Internal modules
pub mod ntt;
pub mod params;
pub mod encode;
pub mod compress;
pub mod sampling;
pub mod hash;
pub mod kpke;

// Public API
pub mod kem;

// Re-exports for convenience
pub use params::{MlKem512, MlKem768, MlKem1024, ParameterSet};
pub use kem::{keygen, encapsulate, decapsulate};
