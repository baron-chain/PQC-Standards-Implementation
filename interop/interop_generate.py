#!/usr/bin/env python3
"""
interop_generate.py — Comprehensive cross-language PQC interoperability vector generator.

Generates JSON test vector files for:
  ML-KEM:   ML-KEM-512, ML-KEM-768, ML-KEM-1024
  ML-DSA:   ML-DSA-44, ML-DSA-65, ML-DSA-87
  SLH-DSA:  SLH-DSA-SHAKE-128f, -128s, -192f, -192s, -256f, -256s

Each file is written to VECTORS_DIR (default: interop/vectors/).

Output format per algorithm:
  ML-KEM:  { algorithm, ek, dk, ct, ss }          (all hex)
  ML-DSA:  { algorithm, pk, sk, msg, sig }         (all hex)
  SLH-DSA: { algorithm, pk, sk, msg, sig }         (all hex)

Usage:
    cd PQC-Standards-Implementation
    PYTHONPATH=python python interop/interop_generate.py
    # or with custom output dir:
    PYTHONPATH=python python interop/interop_generate.py --vectors-dir /tmp/pqc-vectors
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

# ---------------------------------------------------------------------------
# Path setup — make python/ importable regardless of invocation directory
# ---------------------------------------------------------------------------
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_REPO_ROOT, "python"))

from mlkem import (  # noqa: E402
    keygen as mlkem_keygen,
    encaps as mlkem_encaps,
    decaps as mlkem_decaps,
    ML_KEM_512, ML_KEM_768, ML_KEM_1024,
)
from mldsa import (  # noqa: E402
    keygen as mldsa_keygen,
    sign as mldsa_sign,
    verify as mldsa_verify,
    ML_DSA_44, ML_DSA_65, ML_DSA_87,
)
from slhdsa import (  # noqa: E402
    keygen as slh_keygen,
    sign as slh_sign,
    verify as slh_verify,
    SLH_DSA_SHAKE_128f, SLH_DSA_SHAKE_128s,
    SLH_DSA_SHAKE_192f, SLH_DSA_SHAKE_192s,
    SLH_DSA_SHAKE_256f, SLH_DSA_SHAKE_256s,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
TEST_MESSAGE = b"PQC cross-language interoperability test vector"
_INTEROP_DIR = os.path.dirname(os.path.abspath(__file__))


def _vector_filename(algorithm: str) -> str:
    """Map algorithm name to a JSON filename (lower-case, hyphens)."""
    return algorithm.lower().replace(" ", "-").replace("_", "-") + ".json"


# ---------------------------------------------------------------------------
# ML-KEM vectors
# ---------------------------------------------------------------------------

_MLKEM_PARAMS = [
    ("ML-KEM-512",  ML_KEM_512),
    ("ML-KEM-768",  ML_KEM_768),
    ("ML-KEM-1024", ML_KEM_1024),
]


def generate_mlkem(params_name: str, params, vectors_dir: str) -> dict:
    """Generate and write one ML-KEM test vector file. Returns status dict."""
    t0 = time.monotonic()
    print(f"  [{params_name}] keygen ...", end=" ", flush=True)
    ek, dk = mlkem_keygen(params)

    print("encaps ...", end=" ", flush=True)
    ss, ct = mlkem_encaps(ek, params)

    print("decaps (self-check) ...", end=" ", flush=True)
    ss_recovered = mlkem_decaps(dk, ct, params)

    if ss != ss_recovered:
        elapsed = time.monotonic() - t0
        print(f"SELF-CHECK FAILED ({elapsed:.1f}s)")
        return {"algorithm": params_name, "status": "FAIL", "error": "self-check: decaps ss mismatch"}

    vector = {
        "algorithm": params_name,
        "ek": ek.hex(),
        "dk": dk.hex(),
        "ct": ct.hex(),
        "ss": ss.hex(),
    }
    outfile = os.path.join(vectors_dir, _vector_filename(params_name))
    with open(outfile, "w") as f:
        json.dump(vector, f, indent=2)

    elapsed = time.monotonic() - t0
    print(f"PASS  ({elapsed:.1f}s)  →  {os.path.basename(outfile)}")
    return {"algorithm": params_name, "status": "PASS"}


# ---------------------------------------------------------------------------
# ML-DSA vectors
# ---------------------------------------------------------------------------

_MLDSA_PARAMS = [
    ("ML-DSA-44", ML_DSA_44),
    ("ML-DSA-65", ML_DSA_65),
    ("ML-DSA-87", ML_DSA_87),
]


def generate_mldsa(params_name: str, params, vectors_dir: str) -> dict:
    """Generate and write one ML-DSA test vector file. Returns status dict."""
    t0 = time.monotonic()
    print(f"  [{params_name}] keygen ...", end=" ", flush=True)
    pk, sk = mldsa_keygen(params)

    print("sign ...", end=" ", flush=True)
    sig = mldsa_sign(sk, TEST_MESSAGE, params)

    print("verify (self-check) ...", end=" ", flush=True)
    ok = mldsa_verify(pk, TEST_MESSAGE, sig, params)
    if not ok:
        elapsed = time.monotonic() - t0
        print(f"SELF-CHECK FAILED ({elapsed:.1f}s)")
        return {"algorithm": params_name, "status": "FAIL", "error": "self-check: verify returned False"}

    vector = {
        "algorithm": params_name,
        "pk":  pk.hex(),
        "sk":  sk.hex(),
        "msg": TEST_MESSAGE.hex(),
        "sig": sig.hex(),
    }
    outfile = os.path.join(vectors_dir, _vector_filename(params_name))
    with open(outfile, "w") as f:
        json.dump(vector, f, indent=2)

    elapsed = time.monotonic() - t0
    print(f"PASS  ({elapsed:.1f}s)  →  {os.path.basename(outfile)}")
    return {"algorithm": params_name, "status": "PASS"}


# ---------------------------------------------------------------------------
# SLH-DSA vectors
# ---------------------------------------------------------------------------

_SLHDSA_PARAMS = [
    ("SLH-DSA-SHAKE-128f", SLH_DSA_SHAKE_128f),
    ("SLH-DSA-SHAKE-128s", SLH_DSA_SHAKE_128s),
    ("SLH-DSA-SHAKE-192f", SLH_DSA_SHAKE_192f),
    ("SLH-DSA-SHAKE-192s", SLH_DSA_SHAKE_192s),
    ("SLH-DSA-SHAKE-256f", SLH_DSA_SHAKE_256f),
    ("SLH-DSA-SHAKE-256s", SLH_DSA_SHAKE_256s),
]


def generate_slhdsa(params_name: str, params, vectors_dir: str) -> dict:
    """Generate and write one SLH-DSA test vector file. Returns status dict."""
    t0 = time.monotonic()
    print(f"  [{params_name}] keygen ...", end=" ", flush=True)
    pk, sk = slh_keygen(params)

    print("sign ...", end=" ", flush=True)
    # Use randomize=False for fully deterministic vectors (opt_rand = pk_seed)
    sig = slh_sign(sk, TEST_MESSAGE, params, randomize=False)

    print("verify (self-check) ...", end=" ", flush=True)
    ok = slh_verify(pk, TEST_MESSAGE, sig, params)
    if not ok:
        elapsed = time.monotonic() - t0
        print(f"SELF-CHECK FAILED ({elapsed:.1f}s)")
        return {"algorithm": params_name, "status": "FAIL", "error": "self-check: verify returned False"}

    vector = {
        "algorithm": params_name,
        "pk":  pk.hex(),
        "sk":  sk.hex(),
        "msg": TEST_MESSAGE.hex(),
        "sig": sig.hex(),
    }
    outfile = os.path.join(vectors_dir, _vector_filename(params_name))
    with open(outfile, "w") as f:
        json.dump(vector, f, indent=2)

    elapsed = time.monotonic() - t0
    print(f"PASS  ({elapsed:.1f}s)  →  {os.path.basename(outfile)}")
    return {"algorithm": params_name, "status": "PASS"}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Generate PQC interop test vectors")
    parser.add_argument(
        "--vectors-dir",
        default=os.path.join(_INTEROP_DIR, "vectors"),
        help="Output directory for JSON vector files (default: interop/vectors/)",
    )
    args = parser.parse_args()
    vectors_dir: str = os.path.abspath(args.vectors_dir)
    os.makedirs(vectors_dir, exist_ok=True)

    print("=" * 60)
    print(" PQC Cross-Language Interoperability Vector Generator")
    print(f" Output directory: {vectors_dir}")
    print(f" Test message:     {TEST_MESSAGE.decode()!r}")
    print("=" * 60)

    results = []
    total_t0 = time.monotonic()

    # ML-KEM
    print("\n── ML-KEM (FIPS 203) ──────────────────────────────────")
    for name, params in _MLKEM_PARAMS:
        results.append(generate_mlkem(name, params, vectors_dir))

    # ML-DSA
    print("\n── ML-DSA (FIPS 204) ──────────────────────────────────")
    for name, params in _MLDSA_PARAMS:
        results.append(generate_mldsa(name, params, vectors_dir))

    # SLH-DSA
    print("\n── SLH-DSA (FIPS 205) — SHAKE variants ────────────────")
    print("   (SLH-DSA signing is compute-intensive; please wait)")
    for name, params in _SLHDSA_PARAMS:
        results.append(generate_slhdsa(name, params, vectors_dir))

    total_elapsed = time.monotonic() - total_t0
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")

    print(f"\n{'=' * 60}")
    print(f" Generated {len(results)} vector files in {total_elapsed:.1f}s")
    print(f" PASS: {passed}   FAIL: {failed}")
    print(f"{'=' * 60}\n")

    if failed:
        for r in results:
            if r["status"] == "FAIL":
                print(f" FAILED: {r['algorithm']}: {r.get('error', 'unknown')}")
        sys.exit(1)


if __name__ == "__main__":
    main()
