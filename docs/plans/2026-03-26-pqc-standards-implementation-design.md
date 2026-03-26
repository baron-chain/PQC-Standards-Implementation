# PQC Standards Implementation — Design Document

**Date:** 2026-03-26
**Author:** Liviu Epure
**Status:** Approved

---

## 1. Overview

Pure implementations of NIST Post-Quantum Cryptography standards across five programming languages, plus hybrid schemes and TLS 1.3 integration. Designed as production-grade, auditable cryptographic libraries with comprehensive documentation mapping code to FIPS specifications.

### Goals
- **Production alternative**: Correct, performant, secure implementations competing with existing libraries
- **Portfolio showcase**: Clean code, comprehensive tests, thorough documentation
- **Cross-language consistency**: Shared test vectors, identical behavior across all implementations

### Non-Goals
- FIPS 140-3 formal validation (requires NIST CMVP process)
- FN-DSA / FIPS 206 (not yet finalized)
- HQC (not yet standardized)

---

## 2. Scope

### 2.1 Core Standards

#### ML-KEM (FIPS 203) — Key Encapsulation Mechanism
Based on Module-Lattice-Based Key-Encapsulation Mechanism (formerly CRYSTALS-Kyber).

| Parameter Set | Security Level | Encapsulation Key | Decapsulation Key | Ciphertext | Shared Secret |
|---------------|---------------|-------------------|-------------------|------------|---------------|
| ML-KEM-512   | 1             | 800 bytes         | 1632 bytes        | 768 bytes  | 32 bytes      |
| ML-KEM-768   | 3             | 1184 bytes        | 2400 bytes        | 1088 bytes | 32 bytes      |
| ML-KEM-1024  | 5             | 1568 bytes        | 3168 bytes        | 1568 bytes | 32 bytes      |

Operations: KeyGen, Encapsulate, Decapsulate

#### ML-DSA (FIPS 204) — Digital Signature Algorithm
Based on Module-Lattice-Based Digital Signature Algorithm (formerly CRYSTALS-Dilithium).

| Parameter Set | Security Level | Public Key | Private Key | Signature |
|---------------|---------------|------------|-------------|-----------|
| ML-DSA-44     | 2             | 1312 bytes | 2560 bytes  | 2420 bytes|
| ML-DSA-65     | 3             | 1952 bytes | 4032 bytes  | 3309 bytes|
| ML-DSA-87     | 5             | 2592 bytes | 4896 bytes  | 4627 bytes|

Operations: KeyGen, Sign, Verify

#### SLH-DSA (FIPS 205) — Stateless Hash-Based Digital Signature Algorithm
Based on SPHINCS+. All 12 parameter sets:

| Parameter Set         | Security Level | Public Key | Private Key | Signature    |
|-----------------------|---------------|------------|-------------|--------------|
| SLH-DSA-SHA2-128f     | 1             | 32 bytes   | 64 bytes    | 17,088 bytes |
| SLH-DSA-SHA2-128s     | 1             | 32 bytes   | 64 bytes    | 7,856 bytes  |
| SLH-DSA-SHA2-192f     | 3             | 48 bytes   | 96 bytes    | 35,664 bytes |
| SLH-DSA-SHA2-192s     | 3             | 48 bytes   | 96 bytes    | 16,224 bytes |
| SLH-DSA-SHA2-256f     | 5             | 64 bytes   | 128 bytes   | 49,856 bytes |
| SLH-DSA-SHA2-256s     | 5             | 64 bytes   | 128 bytes   | 29,792 bytes |
| SLH-DSA-SHAKE-128f    | 1             | 32 bytes   | 64 bytes    | 17,088 bytes |
| SLH-DSA-SHAKE-128s    | 1             | 32 bytes   | 64 bytes    | 7,856 bytes  |
| SLH-DSA-SHAKE-192f    | 3             | 48 bytes   | 96 bytes    | 35,664 bytes |
| SLH-DSA-SHAKE-192s    | 3             | 48 bytes   | 96 bytes    | 16,224 bytes |
| SLH-DSA-SHAKE-256f    | 5             | 64 bytes   | 128 bytes   | 49,856 bytes |
| SLH-DSA-SHAKE-256s    | 5             | 64 bytes   | 128 bytes   | 29,792 bytes |

Operations: KeyGen, Sign, Verify
Modes: Deterministic signing, randomized signing, pre-hash signing

### 2.2 Hybrid Schemes

#### Hybrid KEMs (for TLS 1.3 Key Exchange)
| Scheme               | Components                    | IETF Reference                        |
|----------------------|-------------------------------|---------------------------------------|
| X25519MLKEM768       | X25519 + ML-KEM-768          | draft-ietf-tls-ecdhe-mlkem-04        |
| SecP256r1MLKEM768    | ECDH P-256 + ML-KEM-768      | draft-ietf-tls-ecdhe-mlkem-04        |
| SecP384r1MLKEM1024   | ECDH P-384 + ML-KEM-1024     | draft-ietf-tls-ecdhe-mlkem-04        |
| X-Wing               | X25519 + ML-KEM-768 (standalone) | draft-connolly-cfrg-xwing-kem-09 |

#### Composite Signatures (for TLS 1.3 Authentication)
| Scheme                          | Components                  | IETF Reference                      |
|---------------------------------|-----------------------------|--------------------------------------|
| ML-DSA-44 + Ed25519             | Composite PQ/T signature    | draft-reddy-tls-composite-mldsa     |
| ML-DSA-65 + ECDSA-P256          | Composite PQ/T signature    | draft-ietf-lamps-pq-composite-sigs  |
| ML-DSA-87 + ECDSA-P384          | Composite PQ/T signature    | draft-ietf-lamps-pq-composite-sigs  |

### 2.3 TLS 1.3 Integration
Per-language TLS provider/integration layer:
- **Go**: `crypto/tls`-compatible config provider
- **Rust**: `rustls`-compatible crypto provider
- **JavaScript**: Node.js `tls` module hooks
- **Python**: `ssl` module integration
- **Java**: JCA/JCE Security Provider

---

## 3. Languages

| Language   | Min Version | Package Manager | Build System |
|------------|-------------|-----------------|--------------|
| Go         | 1.22+       | Go modules      | `go build`   |
| Rust       | 1.75+       | crates.io       | Cargo workspace |
| JavaScript | ES2020+     | npm             | TypeScript → ESM + CJS |
| Python     | 3.10+       | PyPI            | pyproject.toml (hatchling) |
| Java       | 17+         | Maven Central   | Maven multi-module |

---

## 4. Repository Structure

```
PQC-Standards-Implementation/
├── README.md
├── LICENSE                          # MIT
├── SECURITY.md                      # Vulnerability disclosure policy
├── CONTRIBUTING.md
├── .github/
│   └── workflows/                   # CI per language
│       ├── go.yml
│       ├── rust.yml
│       ├── js.yml
│       ├── python.yml
│       └── java.yml
├── docs/
│   ├── plans/                       # Design docs
│   ├── spec-mapping/                # Code ↔ FIPS section mapping
│   └── benchmarks/                  # Performance results
├── test-vectors/                    # Shared NIST KAT vectors (JSON)
│   ├── ml-kem/
│   │   ├── ml-kem-512.json
│   │   ├── ml-kem-768.json
│   │   └── ml-kem-1024.json
│   ├── ml-dsa/
│   │   ├── ml-dsa-44.json
│   │   ├── ml-dsa-65.json
│   │   └── ml-dsa-87.json
│   └── slh-dsa/
│       ├── slh-dsa-sha2-128f.json
│       ├── ... (all 12)
│       └── slh-dsa-shake-256s.json
├── go/
│   ├── go.mod
│   ├── go.sum
│   ├── mlkem/                       # ML-KEM-512, 768, 1024
│   │   ├── mlkem.go                 # Public API
│   │   ├── mlkem_test.go
│   │   ├── mlkem512.go
│   │   ├── mlkem768.go
│   │   └── mlkem1024.go
│   ├── mldsa/                       # ML-DSA-44, 65, 87
│   ├── slhdsa/                      # All 12 SLH-DSA parameter sets
│   ├── hybrid/                      # X25519MLKEM768, etc.
│   ├── tls/                         # crypto/tls integration
│   └── internal/                    # NTT, polynomial, hash utils
│       ├── ntt/
│       ├── poly/
│       └── hash/
├── rust/
│   ├── Cargo.toml                   # Workspace root
│   ├── ml-kem/                      # ml-kem crate
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── kem512.rs
│   │       ├── kem768.rs
│   │       ├── kem1024.rs
│   │       ├── ntt.rs
│   │       ├── poly.rs
│   │       └── params.rs
│   ├── ml-dsa/                      # ml-dsa crate
│   ├── slh-dsa/                     # slh-dsa crate
│   ├── pqc-hybrid/                  # hybrid KEM crate
│   ├── pqc-tls/                     # rustls provider
│   └── pqc-common/                  # shared primitives
├── js/
│   ├── package.json                 # Workspace root
│   ├── tsconfig.json
│   ├── packages/
│   │   ├── ml-kem/                  # @pqc/ml-kem
│   │   ├── ml-dsa/                  # @pqc/ml-dsa
│   │   ├── slh-dsa/                 # @pqc/slh-dsa
│   │   ├── hybrid/                  # @pqc/hybrid
│   │   └── tls/                     # @pqc/tls
│   └── shared/                      # Shared utilities
├── python/
│   ├── pyproject.toml
│   ├── src/
│   │   ├── pqc_mlkem/
│   │   ├── pqc_mldsa/
│   │   ├── pqc_slhdsa/
│   │   ├── pqc_hybrid/
│   │   └── pqc_tls/
│   └── tests/
└── java/
    ├── pom.xml                      # Parent POM
    ├── ml-kem/
    │   ├── pom.xml
    │   └── src/main/java/com/pqc/mlkem/
    ├── ml-dsa/
    ├── slh-dsa/
    ├── hybrid/
    └── tls-provider/                # JCA/JCE Provider
```

---

## 5. Architecture

### 5.1 Core Math Primitives (shared within each language)

**For ML-KEM and ML-DSA (lattice-based):**
- Polynomial arithmetic over Zq (q = 3329 for ML-KEM, q = 8380417 for ML-DSA)
- Number Theoretic Transform (NTT) and inverse NTT
- Polynomial sampling (CBD for ML-KEM, rejection sampling for ML-DSA)
- Compression/decompression (ML-KEM)
- Bit packing/unpacking

**For SLH-DSA (hash-based):**
- WOTS+ (Winternitz One-Time Signature)
- XMSS trees (eXtended Merkle Signature Scheme)
- FORS (Forest of Random Subsets)
- Hypertree construction
- Hash function abstraction (SHA-256, SHA-512, SHAKE-128, SHAKE-256)

### 5.2 API Design Principles

Each language gets an idiomatic API. Example patterns:

**Go:**
```go
// ML-KEM
dk, ek := mlkem.GenerateKey768()
ct, ss := ek.Encapsulate()
ss2 := dk.Decapsulate(ct)

// ML-DSA
sk, pk := mldsa.GenerateKey65()
sig := sk.Sign(message)
valid := pk.Verify(message, sig)
```

**Rust:**
```rust
// ML-KEM
let (dk, ek) = MlKem768::generate(&mut rng);
let (ct, ss) = ek.encapsulate(&mut rng);
let ss2 = dk.decapsulate(&ct);

// ML-DSA
let (sk, pk) = MlDsa65::generate(&mut rng);
let sig = sk.sign(message);
assert!(pk.verify(message, &sig).is_ok());
```

**JavaScript/TypeScript:**
```typescript
// ML-KEM
const { decapsulationKey, encapsulationKey } = await mlKem768.generateKey();
const { ciphertext, sharedSecret } = await encapsulationKey.encapsulate();
const sharedSecret2 = await decapsulationKey.decapsulate(ciphertext);
```

**Python:**
```python
# ML-KEM
dk, ek = ml_kem_768.generate_key()
ct, ss = ek.encapsulate()
ss2 = dk.decapsulate(ct)
```

**Java:**
```java
// ML-KEM
MlKem768.KeyPair kp = MlKem768.generateKey();
MlKem768.Encapsulation enc = kp.encapsulationKey().encapsulate();
byte[] ss = kp.decapsulationKey().decapsulate(enc.ciphertext());
```

### 5.3 Hybrid Scheme Architecture

Hybrid KEMs compose two sub-KEMs:
1. Traditional KEM (X25519 or ECDH)
2. Post-quantum KEM (ML-KEM)
3. KDF combiner (per IETF spec)

```
HybridKEM.Encapsulate():
  (ct1, ss1) = TraditionalKEM.Encapsulate(pk_trad)
  (ct2, ss2) = MLKEM.Encapsulate(pk_pq)
  ss = KDF(ss1 || ss2 || ct1 || ct2)  // combiner per spec
  ct = ct1 || ct2
  return (ct, ss)
```

X-Wing uses a specific SHA3-256 combiner defined in its IETF draft.

### 5.4 TLS Integration Architecture

Each language provides a TLS adapter layer:
- Registers PQC key exchange groups and signature algorithms
- Hooks into the language's TLS library extension points
- Does NOT reimplement TLS — only provides crypto primitives to existing TLS stacks

---

## 6. Security Requirements

### 6.1 Constant-Time Operations
All operations on secret data MUST be constant-time:
- No secret-dependent branches
- No secret-dependent memory access patterns
- Constant-time comparison for verification
- Use bitwise operations for conditional selection

### 6.2 Memory Safety
- Rust: leverage ownership system, no unsafe blocks in crypto code
- Go: explicit zeroing of secret key material after use
- JS: use TypedArrays, zero buffers when possible (limited by GC)
- Python: use `ctypes` or `memoryview` for zeroing where possible
- Java: use `Arrays.fill()` for key material, minimize GC exposure

### 6.3 Randomness
- OS CSPRNG only (`crypto/rand` in Go, `OsRng` in Rust, `crypto.getRandomValues` in JS, `secrets` in Python, `SecureRandom` in Java)
- No user-supplied RNG in production APIs (test-only seeded RNG for KAT validation)

### 6.4 Input Validation
- Validate all public inputs per spec (key sizes, ciphertext sizes, signature sizes)
- Reject malformed inputs with clear error types
- No panics/exceptions on malformed input — return errors

---

## 7. Testing Strategy

### 7.1 NIST Known Answer Tests (KAT)
- Extract official KAT vectors from NIST submissions
- Convert to shared JSON format in `/test-vectors/`
- Every parameter set must pass all KAT vectors in all 5 languages

### 7.2 Cross-Language Interoperability
- Generate key pairs in language A, encapsulate/sign in language B, decapsulate/verify in language C
- Automated CI matrix testing across all language pairs

### 7.3 Property-Based Testing
- Round-trip: `Decapsulate(Encapsulate(pk)) == shared_secret`
- Round-trip: `Verify(pk, Sign(sk, msg), msg) == true`
- Negative: tampered ciphertext/signature must fail
- Edge cases: empty messages, maximum-length messages

### 7.4 Security Testing
- Constant-time verification using tools (e.g., `dudect` for Rust, timing tests)
- Fuzzing with random/malformed inputs
- Known-bad-input rejection tests

### 7.5 Benchmarks
- Per-operation benchmarks (KeyGen, Encapsulate/Sign, Decapsulate/Verify)
- Comparison against existing implementations (circl, RustCrypto, noble)
- Memory allocation profiling
- Results published in `/docs/benchmarks/`

---

## 8. Documentation

### 8.1 Per-Algorithm Documentation
- README with usage examples
- API reference (generated: godoc, rustdoc, typedoc, sphinx, javadoc)
- Spec mapping: each function/module maps to its FIPS section number

### 8.2 Educational Documentation
- Algorithm overview with diagrams
- Step-by-step walkthrough of core operations (NTT, WOTS+, FORS)
- Security considerations and threat model

---

## 9. Implementation Phases

| Phase | Scope | Languages | Est. Complexity |
|-------|-------|-----------|-----------------|
| **1** | ML-KEM (3 param sets) | Rust → Go → JS → Python → Java | High (NTT, polynomial math) |
| **2** | ML-DSA (3 param sets) | All 5 (reuses NTT/poly from Phase 1) | High (rejection sampling, hints) |
| **3** | SLH-DSA (12 param sets) | All 5 | Very High (WOTS+, XMSS, FORS, hypertree) |
| **4** | Hybrid KEMs (4 schemes) | All 5 | Medium (composing existing primitives) |
| **5** | Composite Signatures (3 schemes) | All 5 | Medium |
| **6** | TLS 1.3 Integration | All 5 | High (per-language TLS stack knowledge) |

### Implementation Order Within Each Phase
1. **Rust first** — strongest type system catches design errors early
2. **Go second** — similar systems language, validates portability
3. **JavaScript third** — tests the design in a dynamic language
4. **Python fourth** — highest community demand for a new impl
5. **Java last** — most boilerplate, benefits from all prior learnings

---

## 10. CI/CD

- GitHub Actions workflows per language
- Matrix testing: all parameter sets × all supported OS (Linux, macOS, Windows)
- KAT vector validation on every PR
- Benchmark regression tracking
- Code coverage targets: >95% line coverage for crypto code
- Linting: `golangci-lint`, `clippy`, `eslint`, `ruff`, `checkstyle`

---

## 11. Existing Implementations (Competitive Landscape)

| Language | Library | Our Differentiator |
|----------|---------|-------------------|
| Go | `crypto/mlkem` (stdlib) + `cloudflare/circl` | Unified API across all 3 standards + hybrid + TLS |
| Rust | RustCrypto `ml-kem`/`ml-dsa`/`slh-dsa` | More complete (hybrid + TLS), spec-mapped docs |
| JS | `@noble/post-quantum` | Comparable scope, with TLS integration |
| Python | `liboqs-python` (C wrapper) | Pure Python, no C dependency |
| Java | Bouncy Castle | Lighter weight, modern Java API, MIT licensed |

---

## 12. License

MIT License — maximum adoption, attribution required.

---

## 13. Git Configuration

- **user.name**: Liviu Epure
- **user.email**: liviu.etty@gmail.com
- **No co-author** on any commits, merges, pushes, or PRs
