//! Known Answer Tests (KAT) using C2SP/CCTV intermediate test vectors.
//!
//! These vectors include all intermediate values from FIPS 203 algorithms,
//! enabling validation of KeyGen, Encaps, and Decaps.

use ml_kem::kem::{keygen_internal, encapsulate_internal, decapsulate};
use ml_kem::params::{MlKem512, MlKem768, MlKem1024, ParameterSet};

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// Parse a CCTV intermediate vector file and extract the key fields.
struct CctvVector {
    d: [u8; 32],
    z: [u8; 32],
    ek: Vec<u8>,
    dk: Vec<u8>,
    m: [u8; 32],
    k: [u8; 32],
}

fn parse_cctv_vector(text: &str) -> CctvVector {
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    let mut ek = Vec::new();
    let mut dk = Vec::new();
    let mut m = [0u8; 32];
    let mut k = [0u8; 32];

    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("d = ") && !line.starts_with("dk") {
            let hex = &line[4..];
            let bytes = hex_to_bytes(hex);
            d.copy_from_slice(&bytes);
        } else if line.starts_with("z = ") {
            let hex = &line[4..];
            let bytes = hex_to_bytes(hex);
            z.copy_from_slice(&bytes);
        } else if line.starts_with("ek = ") {
            let hex = &line[5..];
            ek = hex_to_bytes(hex);
        } else if line.starts_with("dk = ") {
            let hex = &line[5..];
            dk = hex_to_bytes(hex);
        } else if line.starts_with("m = ") {
            let hex = &line[4..];
            let bytes = hex_to_bytes(hex);
            m.copy_from_slice(&bytes);
        } else if line.starts_with("K = ") {
            let hex = &line[4..];
            let bytes = hex_to_bytes(hex);
            k.copy_from_slice(&bytes);
        }
    }

    CctvVector { d, z, ek, dk, m, k }
}

fn run_kat_test<P: ParameterSet>(vector_text: &str) {
    let v = parse_cctv_vector(vector_text);

    // Test KeyGen
    let (ek, dk) = keygen_internal::<P>(&v.d, &v.z);
    assert_eq!(ek.len(), P::EK_SIZE, "ek size mismatch");
    assert_eq!(dk.len(), P::DK_SIZE, "dk size mismatch");
    assert_eq!(ek, v.ek, "encapsulation key mismatch");
    assert_eq!(dk, v.dk, "decapsulation key mismatch");

    // Test Encaps
    let (shared_secret, ct) = encapsulate_internal::<P>(&ek, &v.m);
    assert_eq!(shared_secret, v.k, "shared secret mismatch");
    assert_eq!(ct.len(), P::CT_SIZE, "ciphertext size mismatch");

    // Test Decaps
    let recovered_ss = decapsulate::<P>(&dk, &ct);
    assert_eq!(recovered_ss, v.k, "decapsulated shared secret mismatch");
}

#[test]
fn test_kat_mlkem768() {
    let vector_text = include_str!("../../../test-vectors/ml-kem/ML-KEM-768-intermediate.txt");
    run_kat_test::<MlKem768>(vector_text);
}

#[test]
fn test_kat_mlkem512() {
    let vector_text = include_str!("../../../test-vectors/ml-kem/ML-KEM-512-intermediate.txt");
    run_kat_test::<MlKem512>(vector_text);
}

#[test]
fn test_kat_mlkem1024() {
    let vector_text = include_str!("../../../test-vectors/ml-kem/ML-KEM-1024-intermediate.txt");
    run_kat_test::<MlKem1024>(vector_text);
}
