//! PQC cipher suite / named group integration layer for TLS 1.3.
//!
//! This crate provides the PQC key exchange and signature components
//! ready for use in TLS 1.3 handshakes. It is NOT a full TLS implementation,
//! but rather the cryptographic building blocks that plug into one.
//!
//! # Named Groups (Key Exchange)
//!
//! PQC and hybrid named groups for `supported_groups` / `key_share`:
//!
//! | Named Group          | Code Point | Description                    |
//! |---------------------|------------|--------------------------------|
//! | MLKEM768            | 0x0768     | Pure ML-KEM-768                |
//! | MLKEM1024           | 0x1024     | Pure ML-KEM-1024               |
//! | X25519MLKEM768      | 0x6399     | X25519 + ML-KEM-768 hybrid     |
//! | SecP256r1MLKEM768   | 0x639A     | P-256 + ML-KEM-768 hybrid      |
//!
//! # Signature Algorithms (CertificateVerify)
//!
//! | Algorithm           | Code Point | Description                    |
//! |---------------------|------------|--------------------------------|
//! | MLDSA44             | 0x0904     | ML-DSA-44                      |
//! | MLDSA65             | 0x0905     | ML-DSA-65                      |
//! | MLDSA87             | 0x0906     | ML-DSA-87                      |
//! | MLDSA65_ED25519     | 0x0907     | ML-DSA-65 + Ed25519 composite  |
//! | MLDSA87_ED25519     | 0x0908     | ML-DSA-87 + Ed25519 composite  |

extern crate alloc;

pub mod named_groups;
pub mod sig_algorithms;
pub mod cipher_suites;

pub use named_groups::{NamedGroup, generate_key_share, complete_key_exchange, recover_shared_secret, key_share_size};
pub use sig_algorithms::{SignatureAlgorithm, generate_signing_key, sign_handshake, verify_handshake};
pub use cipher_suites::{CipherSuite, AeadAlgorithm, cipher_suite_by_id, ALL_CIPHER_SUITES};
