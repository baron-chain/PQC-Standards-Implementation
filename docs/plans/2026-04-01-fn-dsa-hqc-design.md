# FN-DSA (FIPS 206) + HQC Design

**Date:** 2026-04-01
**Scope:** Add FN-DSA (FALCON, FIPS 206) and HQC (Round 4 / future FIPS 207) to all 8 languages, completing the NIST PQC primitive suite.

---

## 1. Motivation

The repo currently implements all finalized NIST PQC standards except one:

| Standard | Algorithm | Status |
|----------|-----------|--------|
| FIPS 203 | ML-KEM | ✅ 8 languages |
| FIPS 204 | ML-DSA | ✅ 8 languages |
| FIPS 205 | SLH-DSA | ✅ 8 languages |
| **FIPS 206** | **FN-DSA (FALCON)** | ❌ not implemented |
| **FIPS 207 (draft)** | **HQC** | ❌ not implemented |

FN-DSA was finalized August 2024. HQC was selected as the backup KEM in March 2025; its FIPS draft is in progress. Both will be implemented from spec across all 8 languages with NIST KAT validation and cross-language interop vectors.

---

## 2. Architecture

New packages follow the exact same structure as existing primitives:

```
go/fndsa/
  fndsa.go                  # KeyGen, Sign, SignInternal, Verify
go/internal/fndsa/
  params.go                 # FNDSA512, FNDSA1024, FNDSAPadded512, FNDSAPadded1024
  fft.go                    # Complex FFT + NTT mod 12289
  gaussian.go               # RCDT discrete Gaussian sampler (σ₀ = 1.8205)
  ntru.go                   # NTRU key generation, ffTree, Gram-Schmidt
  sign.go                   # ffSampling, signature compression
  verify.go                 # norm check, HashToPoint
  encode.go                 # compressed integer encoding for keys/signatures

go/hqc/
  hqc.go                    # KeyGen, Encapsulate, Decapsulate
go/internal/hqc/
  params.go                 # HQC128, HQC192, HQC256
  gf2poly.go                # GF(2) quasi-cyclic polynomial ring (word-level rotation)
  rs.go                     # Reed-Solomon over GF(2^m): Berlekamp-Massey + Chien + Forney
  rm.go                     # Reed-Muller encoder/decoder (Fast Walsh-Hadamard Transform)
  fo.go                     # Fujisaki-Okamoto transform (SHAKE-256)
```

All 7 remaining languages (Rust, Python, Java, JS, .NET, Swift, PHP) get equivalent structures. Go is the reference implementation.

Test vectors:
```
test-vectors/fn-dsa/
  fn-dsa-512.json           # {pk, sk, msg, sig}
  fn-dsa-1024.json
  fn-dsa-padded-512.json
  fn-dsa-padded-1024.json
  kat/                      # NIST FIPS 206 KAT files (converted from .rsp)

test-vectors/hqc/
  hqc-128.json              # {pk, dk, ct, ss}
  hqc-192.json
  hqc-256.json
  kat/                      # NIST Round 4 KAT files (replaced when FIPS 207 drops)
```

---

## 3. FN-DSA Algorithm (FIPS 206)

**Ring:** `Z[x]/(xⁿ + 1)`, `n ∈ {512, 1024}`, `q = 12289`

### Parameter Sets

| Name | n | σ | sig bytes | pk bytes | sk bytes |
|------|---|---|-----------|----------|----------|
| FN-DSA-512 | 512 | 165.74 | 666 | 897 | 1281 |
| FN-DSA-1024 | 1024 | 168.39 | 1280 | 1793 | 2305 |
| FN-DSA-PADDED-512 | 512 | 165.74 | 809 | 897 | 1281 |
| FN-DSA-PADDED-1024 | 1024 | 168.39 | 1473 | 1793 | 2305 |

PADDED variants pad signatures to a constant size, eliminating a length side-channel.

### Key Operations

```
KeyGen:
  1. Sample (f, g) with small coefficients from D_{Z,σ}
  2. Solve NTRU equation: fG - gF = q (extended GCD over polynomial ring)
  3. h = g · f⁻¹ mod q  (public key)
  4. Encode: pk = h, sk = (f, g, F, G)

Sign(sk, msg):
  1. r = random 40 bytes (salt)
  2. c = HashToPoint(r ‖ msg, q, n)  [SHAKE-256 to NTT domain]
  3. Build ffTree(B) from sk once per key (or per-sign if memory-constrained)
  4. (s1, s2) = ffSampling(c, ffTree)  [recursive Gaussian sampling]
  5. If ||(s1, s2)||² > β²: retry with new randomness
  6. Output (r, compress(s1))

Verify(pk, msg, sig):
  1. Decode s1 from compressed form
  2. s2 = HashToPoint(r ‖ msg) - s1 · h
  3. Check ||(s1, s2)||² ≤ β²
  4. Accept
```

### Hard Components

**1. Discrete Gaussian sampler (`gaussian.go`)**
- RCDT (Rejection Cumulative Distribution Table) per FIPS 206 Appendix A
- σ₀ = 1.8205, table size = 18 entries of 72-bit integers
- Must be constant-time: use `subtle.ConstantTimeCompare`-style selection, no branches on secret data
- Each language must implement its own RCDT — this is the primary side-channel risk

**2. ffSampling / Fast Fourier Tree (`ntru.go`, `sign.go`)**
- Works in `ℂ[x]/(xⁿ + 1)` using 64-bit IEEE 754 doubles (per FIPS 206 spec)
- Recursive split: `f = f_even(x²) + x·f_odd(x²)` down to degree-1 base case
- Float64 rounding must match Go's `math` package exactly for cross-language consistency
- PHP and JS: verify that `float64` / `Number` round-trips match Go before declaring interop passing

**3. NTRU key generation (`ntru.go`)**
- Sample `(f, g)` until `f` is invertible mod `q` and mod `2`
- Use extended Euclidean algorithm over `Z[x]/(xⁿ + 1)` for NTRU equation solver
- Gram-Schmidt norm check: `||B̃||² ≤ 1.17² · q` (reject and resample if not)
- Key generation retry loop is expected; average ~3 attempts for n=512

---

## 4. HQC Algorithm (Round 4 Spec)

**Structure:** Quasi-cyclic code-based KEM over GF(2)

### Parameter Sets

| Name | n | w | pk bytes | ct bytes | ss bytes |
|------|---|---|----------|----------|----------|
| HQC-128 | 17669 | 66 | 2249 | 4481 | 64 |
| HQC-192 | 35851 | 100 | 4522 | 9026 | 64 |
| HQC-256 | 57637 | 131 | 7245 | 14469 | 64 |

Note: ciphertexts are 4–14 KB vs ML-KEM's 768–1568 bytes. This is inherent to code-based constructions.

### Key Operations

```
KeyGen:
  1. h = random element of GF(2)[x]/(xⁿ - 1)   [public random]
  2. (x, y) = sparse weight-w polynomials        [secret key]
  3. s = x + h·y                                 [public key component]
  4. pk = (h, s),  sk = (x, y, pk, seed)

Encapsulate(pk):
  1. m = random 256-bit message seed
  2. (r1, r2, e) = PRF(m) → sparse weight-w polynomials
  3. u = r1 + h·r2
  4. v = m·G_concat + s·r2 + e     [G_concat = RM(RS(·)) generator]
  5. K = SHAKE256(m ‖ u ‖ v ‖ salt)
  6. ct = (u, v, salt)

Decapsulate(sk, ct):
  1. v' = v - u·y = m·G_concat + noise_term
  2. m' = RS_Decode(RM_Decode(v'))
  3. Re-encapsulate with m' → ct'
  4. K = SHAKE256(m' ‖ u ‖ v ‖ salt)  if ct' == ct
       = SHAKE256(⊥  ‖ u ‖ v ‖ salt)  otherwise  [implicit rejection]
```

### Hard Components

**1. GF(2) quasi-cyclic polynomial multiplication (`gf2poly.go`)**
- Polynomials in `GF(2)[x]/(xⁿ - 1)` with n prime (17669, 35851, 57637)
- Representation: `ceil(n/64)` 64-bit words
- Multiplication: shift-and-XOR with word-level rotation (no NTT applicable)
- HQC-256: 57637 bits = 901 words per polynomial; a naive O(n²) implementation will be too slow for tests — use Karatsuba at minimum

**2. Reed-Solomon decoder (`rs.go`)**
- Code over `GF(2^m)` where m is chosen per parameter set
- Berlekamp-Massey for error locator polynomial
- Chien search for error locations
- Forney formula for error values
- GF(2^m) arithmetic: implement as lookup tables (log/exp tables from primitive polynomial)

**3. Reed-Muller decoder (`rm.go`)**
- First-order Reed-Muller code R(1, r) over GF(2)
- Decoder: Fast Walsh-Hadamard Transform (FWHT) — O(r·2^r) vs O(4^r) naive
- Output: best-fit codeword by maximum correlation

**4. Spec stability (`fo.go`)**
- Isolate all SHAKE-256 domain separation strings behind `hqcKDF()` and `hqcPRF()`
- When FIPS 207 drops, only these functions need updating — not the polynomial arithmetic

---

## 5. Validation Strategy

### FN-DSA

| Layer | Method | Location |
|-------|--------|----------|
| Size correctness | Assert key/sig byte lengths match spec table | Each language test |
| NIST KAT | Run all 4 parameter sets against FIPS 206 KAT `.rsp` files | `test-vectors/fn-dsa/kat/` |
| Internal invariant | `||(s1,s2)||² ≤ β²` for every generated signature | `fndsa_test` in each language |
| Round-trip | `Verify(pk, msg, Sign(sk, msg)) == true` × 100 random msgs | Each language test |
| Cross-language | Go generates 4 vectors; all 8 languages verify | `interop/vectors/fn-dsa*.json` |

### HQC

| Layer | Method | Location |
|-------|--------|----------|
| Size correctness | Assert pk/ct/ss byte lengths match spec table | Each language test |
| NIST KAT | Run HQC-128/192/256 against Round 4 KAT files | `test-vectors/hqc/kat/` |
| Round-trip | `Decapsulate(sk, Encapsulate(pk)) == ss` × 50 per param set | Each language test |
| Implicit rejection | Tamper ct → verify different key returned, not panic | Each language test |
| Cross-language | Go generates 3 vectors; all 8 languages verify | `interop/vectors/hqc*.json` |

---

## 6. Rollout Sequence

```
Phase 1 — FN-DSA Go reference
  params → encode → fft → gaussian → ntru → sign → verify → fndsa.go
  Gate: FIPS 206 KAT all-pass

Phase 2 — FN-DSA fan-out (Rust → Python → Java → JS → .NET → Swift → PHP)
  Risk: float64 ffSampling consistency in PHP/JS
  Gate: each language passes KAT + round-trip tests

Phase 3 — FN-DSA interop vectors + CI green
  Go generates 4 vectors; 8/8 languages verify
  Gate: CI all-green before Phase 4

Phase 4 — HQC Go reference
  params → gf2poly → rm → rs → fo → hqc.go
  Gate: Round 4 KAT all-pass

Phase 5 — HQC fan-out (same language order)
  Risk: Karatsuba GF(2) poly mul performance in interpreted languages
  Gate: each language passes KAT + round-trip + implicit rejection tests

Phase 6 — HQC interop vectors + CI green
  Go generates 3 vectors; 8/8 languages verify
  Total interop count: 96 → ~160+
```

---

## 7. Decisions and Constraints

- **Float64 for ffSampling:** FIPS 206 specifies IEEE 754 double precision. All languages must use native 64-bit doubles. If any language produces divergent results due to FPU rounding, that language's ffSampling must be validated coefficient-by-coefficient against Go's output before declaring interop passing.
- **No Gaussian sampler reuse across languages:** Each language implements its own RCDT sampler from the FIPS 206 Appendix A table. No FFI or native bindings to a shared C library.
- **HQC KDF isolation:** All SHAKE-256 calls in HQC go through named functions (`hqcKDF`, `hqcPRF`, `hqcHashG`) so FIPS 207 domain separator changes require a single-function update per language.
- **HQC performance floor:** Tests must complete in under 60 seconds per language on CI `ubuntu-latest`. If naive GF(2) multiplication is too slow for HQC-256, Karatsuba is the approved optimization (not CLMUL intrinsics, which aren't portable across all 8 languages).
- **Implicit rejection:** HQC decapsulation must return a deterministic garbage key (not an error) on ciphertext tampering. This is tested explicitly.
