//! interop-verify — Comprehensive Rust cross-language PQC verifier.
//!
//! Reads all JSON vector files from VECTORS_DIR and verifies:
//!   ML-KEM:  decapsulate(dk, ct) == ss
//!   ML-DSA:  verify(pk, msg, sig) == true
//!   SLH-DSA: verify(pk, msg, sig) == true
//!
//! Output lines (parseable by orchestrator):
//!   RESULT:ML-KEM-512:PASS
//!   RESULT:ML-DSA-44:FAIL:verification returned false
//!
//! Usage:
//!   cargo build --release
//!   ./target/release/interop-verify [VECTORS_DIR]
//!
//! VECTORS_DIR defaults to ../../interop/vectors (relative to rust/).

use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

// ML-KEM
use ml_kem::kem;
use ml_kem::params::{MlKem512, MlKem768, MlKem1024};

// ML-DSA
use ml_dsa::dsa;
use ml_dsa::params::{MlDsa44, MlDsa65, MlDsa87};

// SLH-DSA
use slh_dsa::slhdsa;
use slh_dsa::params::{Shake_128f, Shake_128s, Shake_192f, Shake_192s, Shake_256f, Shake_256s};
use slh_dsa::hash::ShakeHash;

// ---------------------------------------------------------------------------
// JSON schemas
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AlgHeader {
    algorithm: String,
}

#[derive(Deserialize)]
struct MlKemVector {
    algorithm: String,
    #[serde(with = "hex")]
    dk: Vec<u8>,
    #[serde(with = "hex")]
    ct: Vec<u8>,
    #[serde(with = "hex")]
    ss: Vec<u8>,
}

#[derive(Deserialize)]
struct MlDsaVector {
    algorithm: String,
    #[serde(with = "hex")]
    pk: Vec<u8>,
    #[serde(with = "hex")]
    msg: Vec<u8>,
    #[serde(with = "hex")]
    sig: Vec<u8>,
}

#[derive(Deserialize)]
struct SlhDsaVector {
    algorithm: String,
    #[serde(with = "hex")]
    pk: Vec<u8>,
    #[serde(with = "hex")]
    msg: Vec<u8>,
    #[serde(with = "hex")]
    sig: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Verification functions
// ---------------------------------------------------------------------------

fn verify_mlkem(alg: &str, content: &str) -> Result<(), String> {
    let v: MlKemVector = serde_json::from_str(content)
        .map_err(|e| format!("JSON parse error: {e}"))?;

    let ss_got: [u8; 32] = match alg {
        "ML-KEM-512"  => kem::decapsulate::<MlKem512>(&v.dk, &v.ct),
        "ML-KEM-768"  => kem::decapsulate::<MlKem768>(&v.dk, &v.ct),
        "ML-KEM-1024" => kem::decapsulate::<MlKem1024>(&v.dk, &v.ct),
        _ => return Err(format!("unknown parameter set: {alg}")),
    };

    if ss_got.as_ref() != v.ss.as_slice() {
        return Err("decapsulated shared secret does not match expected".into());
    }
    Ok(())
}

fn verify_mldsa(alg: &str, content: &str) -> Result<(), String> {
    let v: MlDsaVector = serde_json::from_str(content)
        .map_err(|e| format!("JSON parse error: {e}"))?;

    let ok = match alg {
        "ML-DSA-44" => dsa::verify::<MlDsa44>(&v.pk, &v.msg, &v.sig),
        "ML-DSA-65" => dsa::verify::<MlDsa65>(&v.pk, &v.msg, &v.sig),
        "ML-DSA-87" => dsa::verify::<MlDsa87>(&v.pk, &v.msg, &v.sig),
        _ => return Err(format!("unknown parameter set: {alg}")),
    };

    if !ok {
        return Err("signature verification returned false".into());
    }
    Ok(())
}

fn verify_slhdsa(alg: &str, content: &str) -> Result<(), String> {
    let v: SlhDsaVector = serde_json::from_str(content)
        .map_err(|e| format!("JSON parse error: {e}"))?;

    let ok = match alg {
        "SLH-DSA-SHAKE-128f" => slhdsa::verify::<Shake_128f, ShakeHash>(&v.pk, &v.msg, &v.sig),
        "SLH-DSA-SHAKE-128s" => slhdsa::verify::<Shake_128s, ShakeHash>(&v.pk, &v.msg, &v.sig),
        "SLH-DSA-SHAKE-192f" => slhdsa::verify::<Shake_192f, ShakeHash>(&v.pk, &v.msg, &v.sig),
        "SLH-DSA-SHAKE-192s" => slhdsa::verify::<Shake_192s, ShakeHash>(&v.pk, &v.msg, &v.sig),
        "SLH-DSA-SHAKE-256f" => slhdsa::verify::<Shake_256f, ShakeHash>(&v.pk, &v.msg, &v.sig),
        "SLH-DSA-SHAKE-256s" => slhdsa::verify::<Shake_256s, ShakeHash>(&v.pk, &v.msg, &v.sig),
        _ => return Err(format!("unknown parameter set: {alg}")),
    };

    if !ok {
        return Err("signature verification returned false".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let vectors_dir: PathBuf = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("../../interop/vectors"));

    let entries = match fs::read_dir(&vectors_dir) {
        Ok(e) => e,
        Err(err) => {
            eprintln!("ERROR: cannot read vectors dir {:?}: {err}", vectors_dir);
            std::process::exit(1);
        }
    };

    let mut paths: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map_or(false, |ext| ext == "json"))
        .collect();
    paths.sort();

    let mut failed = 0usize;

    for path in &paths {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(err) => {
                eprintln!("ERROR: cannot read {:?}: {err}", path);
                failed += 1;
                continue;
            }
        };

        let header: AlgHeader = match serde_json::from_str(&content) {
            Ok(h) => h,
            Err(err) => {
                eprintln!("ERROR: bad JSON in {:?}: {err}", path);
                failed += 1;
                continue;
            }
        };
        let alg = &header.algorithm;

        let result = if alg.starts_with("ML-KEM") {
            verify_mlkem(alg, &content)
        } else if alg.starts_with("ML-DSA") {
            verify_mldsa(alg, &content)
        } else if alg.starts_with("SLH-DSA") {
            verify_slhdsa(alg, &content)
        } else {
            Err(format!("unknown algorithm family: {alg}"))
        };

        match result {
            Ok(()) => println!("RESULT:{alg}:PASS"),
            Err(msg) => {
                println!("RESULT:{alg}:FAIL:{msg}");
                failed += 1;
            }
        }
    }

    if failed > 0 {
        std::process::exit(1);
    }
}
