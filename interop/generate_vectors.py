#!/usr/bin/env python3
"""Generate ML-DSA-65 interoperability test vectors.

Generates a key pair, signs a test message, and writes the public key,
message, and signature to mldsa65_vectors.json.  Any conformant ML-DSA-65
implementation should be able to verify the signature using the public key.

Usage:
    cd PQC-Standards-Implementation
    python -m interop.generate_vectors          # as a package
    # or
    PYTHONPATH=python python interop/generate_vectors.py   # standalone
"""

import json
import os
import sys

# ---------------------------------------------------------------------------
# Make sure the Python ML-DSA package is importable regardless of how the
# script is invoked.
# ---------------------------------------------------------------------------
_repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_repo_root, "python"))

from mldsa import keygen, sign, verify, ML_DSA_65  # noqa: E402

INTEROP_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(INTEROP_DIR, "mldsa65_vectors.json")

TEST_MESSAGE = b"PQC interoperability test"


def main() -> None:
    print("=== ML-DSA-65 interop vector generation ===")

    # 1. Key generation
    print("[1/4] Generating ML-DSA-65 key pair ...")
    pk, sk = keygen(ML_DSA_65)
    print(f"       pk size: {len(pk)} bytes")
    print(f"       sk size: {len(sk)} bytes")

    # 2. Sign the test message
    print("[2/4] Signing test message ...")
    sig = sign(sk, TEST_MESSAGE, ML_DSA_65)
    print(f"       sig size: {len(sig)} bytes")

    # 3. Sanity-check: verify our own signature
    print("[3/4] Self-verifying ...")
    ok = verify(pk, TEST_MESSAGE, sig, ML_DSA_65)
    if not ok:
        print("ERROR: self-verification failed!")
        sys.exit(1)
    print("       OK")

    # 4. Write test vectors to JSON
    vectors = {
        "algorithm": "ML-DSA-65",
        "description": "Cross-language interoperability test vectors",
        "pk": pk.hex(),
        "msg": TEST_MESSAGE.hex(),
        "sig": sig.hex(),
    }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(vectors, f, indent=2)
    print(f"[4/4] Vectors written to {OUTPUT_FILE}")
    print()
    print("Verify with:")
    print("  python  interop/verify_python.py")
    print("  go run  interop/verify_go.go")
    print("  node    interop/verify_js.mjs")
    print("  java    (see interop/verify_java.java)")
    print("  cargo   (see interop/verify_rust.rs)")


if __name__ == "__main__":
    main()
