#!/usr/bin/env python3
"""
PQC Benchmark Suite -- Python

Benchmarks ML-KEM-768, ML-DSA-65, and SLH-DSA-SHAKE-128f.

Run with: python -m benchmarks.bench   (from the python/ directory)

Note: Pure-Python implementations are expected to be significantly slower
than compiled languages. These benchmarks are useful for profiling and
relative comparisons, not absolute performance numbers.
"""

import sys
import time

# Ensure the package root is on the path
sys.path.insert(0, ".")

from mlkem import keygen as kem_keygen, encaps, decaps, ML_KEM_768
from mldsa import keygen as dsa_keygen, sign as dsa_sign, verify as dsa_verify, ML_DSA_65
from slhdsa import (
    keygen as slh_keygen,
    sign as slh_sign,
    verify as slh_verify,
    SLH_DSA_SHAKE_128f,
)


def bench(name: str, fn, iterations: int = 1) -> float:
    """Run fn `iterations` times and print the average time."""
    start = time.perf_counter()
    for _ in range(iterations):
        fn()
    elapsed = time.perf_counter() - start
    avg = elapsed / iterations
    unit = "s" if avg >= 1.0 else "ms"
    display = avg if avg >= 1.0 else avg * 1000
    print(f"  {name}: {display:.3f} {unit} avg ({iterations} iterations, {elapsed:.3f} s total)")
    return avg


def main():
    sep = "=" * 70
    print(sep)
    print("PQC Benchmark Suite -- Python")
    print(sep)
    print()

    # ------------------------------------------------------------------
    # ML-KEM-768
    # ------------------------------------------------------------------
    print("--- ML-KEM-768 ---")
    iters = 10

    bench("KeyGen", lambda: kem_keygen(ML_KEM_768), iters)

    ek, dk = kem_keygen(ML_KEM_768)
    bench("Encaps", lambda: encaps(ek, ML_KEM_768), iters)

    ss, ct = encaps(ek, ML_KEM_768)
    bench("Decaps", lambda: decaps(dk, ct, ML_KEM_768), iters)

    print()

    # ------------------------------------------------------------------
    # ML-DSA-65
    # ------------------------------------------------------------------
    print("--- ML-DSA-65 ---")
    iters = 5

    bench("KeyGen", lambda: dsa_keygen(ML_DSA_65), iters)

    pk, sk = dsa_keygen(ML_DSA_65)
    msg = b"PQC benchmark message for performance testing"

    bench("Sign", lambda: dsa_sign(sk, msg, ML_DSA_65), iters)

    sig = dsa_sign(sk, msg, ML_DSA_65)
    bench("Verify", lambda: dsa_verify(pk, msg, sig, ML_DSA_65), iters)

    print()

    # ------------------------------------------------------------------
    # SLH-DSA-SHAKE-128f
    # ------------------------------------------------------------------
    print("--- SLH-DSA-SHAKE-128f ---")
    slh_iters = 1  # SLH-DSA in Python is very slow

    bench("KeyGen", lambda: slh_keygen(SLH_DSA_SHAKE_128f), slh_iters)

    pk, sk = slh_keygen(SLH_DSA_SHAKE_128f)
    bench("Sign", lambda: slh_sign(sk, msg, SLH_DSA_SHAKE_128f), slh_iters)

    sig = slh_sign(sk, msg, SLH_DSA_SHAKE_128f)
    bench("Verify", lambda: slh_verify(pk, msg, sig, SLH_DSA_SHAKE_128f), slh_iters)

    print()
    print(sep)
    print("Benchmark complete.")


if __name__ == "__main__":
    main()
