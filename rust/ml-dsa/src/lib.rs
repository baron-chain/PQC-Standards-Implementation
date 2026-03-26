//! ML-DSA (FIPS 204) — Module-Lattice-Based Digital Signature Algorithm.
//!
//! This crate provides a pure Rust implementation of ML-DSA, the NIST
//! post-quantum digital signature standard (formerly known as CRYSTALS-Dilithium).
//!
//! # Modules
//!
//! - [`field`] — Arithmetic over Z_q (q = 8380417).
//! - [`ntt`]   — Number Theoretic Transform for fast polynomial multiplication.
//! - [`params`] — Parameter sets for ML-DSA-44, ML-DSA-65, and ML-DSA-87.

#![no_std]

pub mod field;
pub mod ntt;
pub mod params;
