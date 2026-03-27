//! verify_rust.rs -- Verify ML-DSA-65 interop test vectors using the Rust implementation.
//!
//! This file is intended to be used as an integration test in the ml-dsa crate.
//!
//! Usage (from the repository root):
//!
//!     # Copy or symlink this file into the Rust test directory:
//!     cp interop/verify_rust.rs rust/ml-dsa/tests/interop_test.rs
//!
//!     # Then run:
//!     cd rust && cargo test --package ml-dsa --test interop_test -- --nocapture
//!
//! Alternatively, run via the interop shell script:
//!     bash interop/run_interop.sh

extern crate ml_dsa;

use std::fs;
use std::path::PathBuf;

use ml_dsa::dsa;
use ml_dsa::params::MlDsa65;

/// Decode a hex string to bytes.
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// Simple JSON string value extractor (no serde dependency required).
fn extract_json_string<'a>(json: &'a str, key: &str) -> &'a str {
    let search = format!("\"{}\"", key);
    let idx = json.find(&search).expect("key not found");
    let rest = &json[idx + search.len()..];
    // Skip to the colon, then to the opening quote
    let colon = rest.find(':').expect("missing colon");
    let after_colon = &rest[colon + 1..];
    let open = after_colon.find('"').expect("missing open quote");
    let value_start = &after_colon[open + 1..];
    let close = value_start.find('"').expect("missing close quote");
    &value_start[..close]
}

#[test]
fn verify_interop_vectors() {
    println!("=== ML-DSA-65 verification (Rust) ===");

    // Locate vectors file -- try several relative paths
    let candidates = [
        PathBuf::from("../../interop/mldsa65_vectors.json"),   // from rust/ml-dsa/
        PathBuf::from("interop/mldsa65_vectors.json"),          // from repo root
        PathBuf::from("../interop/mldsa65_vectors.json"),       // from rust/
    ];

    let mut content = String::new();
    for path in &candidates {
        if let Ok(c) = fs::read_to_string(path) {
            content = c;
            break;
        }
    }
    if content.is_empty() {
        panic!("Cannot find mldsa65_vectors.json -- run generate_vectors.py first");
    }

    let alg = extract_json_string(&content, "algorithm");
    let pk_hex = extract_json_string(&content, "pk");
    let msg_hex = extract_json_string(&content, "msg");
    let sig_hex = extract_json_string(&content, "sig");

    let pk = hex_to_bytes(pk_hex);
    let msg = hex_to_bytes(msg_hex);
    let sig = hex_to_bytes(sig_hex);

    println!("  algorithm : {}", alg);
    println!("  pk size   : {} bytes", pk.len());
    println!("  msg size  : {} bytes", msg.len());
    println!("  sig size  : {} bytes", sig.len());

    let ok = dsa::verify::<MlDsa65>(&pk, &msg, &sig);

    if ok {
        println!("  result    : PASS");
    } else {
        panic!("  result    : FAIL");
    }
}
