# ML-DSA-65 Cross-Language Interoperability Tests

This directory contains scripts that prove all ML-DSA-65 implementations in
this repository produce compatible outputs.

## How it works

1. **Python generates** an ML-DSA-65 key pair, signs a test message, and
   writes `{pk, msg, sig}` to `mldsa65_vectors.json`.
2. **Each language reads** the JSON and verifies the signature using its own
   ML-DSA-65 implementation.
3. If every language accepts the signature, the implementations are
   interoperable.

## Quick start

From the repository root:

```bash
bash interop/run_interop.sh
```

The script auto-detects which toolchains are installed and skips unavailable
languages.

## Running individual verifiers

```bash
# Generate vectors (required first)
PYTHONPATH=python python3 interop/generate_vectors.py

# Python (sanity check)
PYTHONPATH=python python3 interop/verify_python.py

# Go
cd go && go run ../interop/verify_go.go

# JavaScript (Node.js >= 20)
node interop/verify_js.mjs

# Java (after mvn compile in java/)
cd java && mvn compile -q && cd ..
javac -cp java/target/classes -d interop/out interop/verify_java.java
java  -cp java/target/classes:interop/out interop.VerifyJava

# Rust
cp interop/verify_rust.rs rust/ml-dsa/tests/interop_test.rs
cd rust && cargo test --package ml-dsa --test interop_test -- --nocapture
```

## Files

| File | Purpose |
|---|---|
| `generate_vectors.py` | Generate test vectors with Python ML-DSA-65 |
| `mldsa65_vectors.json` | Generated test vectors (not committed) |
| `verify_python.py` | Verify in Python (sanity check) |
| `verify_go.go` | Verify in Go |
| `verify_js.mjs` | Verify in JavaScript (Node.js) |
| `verify_java.java` | Verify in Java |
| `verify_rust.rs` | Verify in Rust (copied into crate as integration test) |
| `run_interop.sh` | Automated runner for all languages |
