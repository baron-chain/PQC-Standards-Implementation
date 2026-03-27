"""PQC Signature Algorithms for TLS 1.3.

Defines PQC and composite signature algorithms for the signature_algorithms
extension (CertificateVerify), along with sign/verify helpers.
"""

import sys
import os
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mldsa.dsa import keygen as mldsa_keygen, sign as mldsa_sign, verify as mldsa_verify
from mldsa.params import ML_DSA_44, ML_DSA_65, ML_DSA_87
from composite.composite_sig import (
    CompositeScheme, CompositeKeyPair,
    MLDSA65_ED25519, MLDSA87_ED25519,
    key_gen as composite_keygen,
    sign as composite_sign,
    verify as composite_verify,
)


class SignatureAlgorithm(IntEnum):
    """TLS 1.3 signature algorithm identifiers for PQC."""
    MLDSA44 = 0x0904
    MLDSA65 = 0x0905
    MLDSA87 = 0x0906
    MLDSA65_ED25519 = 0x0907
    MLDSA87_ED25519 = 0x0908


ALL_SIGNATURE_ALGORITHMS = list(SignatureAlgorithm)


def signature_algorithm_from_code_point(cp: int) -> Optional[SignatureAlgorithm]:
    """Look up a signature algorithm by its TLS code point."""
    try:
        return SignatureAlgorithm(cp)
    except ValueError:
        return None


def _mldsa_params(alg: SignatureAlgorithm):
    if alg == SignatureAlgorithm.MLDSA44:
        return ML_DSA_44
    elif alg == SignatureAlgorithm.MLDSA65:
        return ML_DSA_65
    elif alg == SignatureAlgorithm.MLDSA87:
        return ML_DSA_87
    raise ValueError(f"Not a pure ML-DSA algorithm: {alg}")


def _composite_scheme(alg: SignatureAlgorithm) -> CompositeScheme:
    if alg == SignatureAlgorithm.MLDSA65_ED25519:
        return MLDSA65_ED25519
    elif alg == SignatureAlgorithm.MLDSA87_ED25519:
        return MLDSA87_ED25519
    raise ValueError(f"Not a composite algorithm: {alg}")


def is_composite(alg: SignatureAlgorithm) -> bool:
    """Whether the algorithm is a composite (hybrid) signature."""
    return alg in (SignatureAlgorithm.MLDSA65_ED25519, SignatureAlgorithm.MLDSA87_ED25519)


@dataclass
class SigningKeyPair:
    """A signing key pair for a PQC signature algorithm."""
    pk: bytes
    sk: bytes
    algorithm: SignatureAlgorithm


def generate_signing_key(alg: SignatureAlgorithm) -> SigningKeyPair:
    """Generate a signing key pair for the given signature algorithm."""
    if is_composite(alg):
        scheme = _composite_scheme(alg)
        kp = composite_keygen(scheme)
        return SigningKeyPair(pk=kp.pk, sk=kp.sk, algorithm=alg)
    params = _mldsa_params(alg)
    pk, sk = mldsa_keygen(params)
    return SigningKeyPair(pk=pk, sk=sk, algorithm=alg)


def sign_handshake(alg: SignatureAlgorithm, sk: bytes, handshake_hash: bytes) -> bytes:
    """Sign a TLS 1.3 CertificateVerify handshake hash."""
    if is_composite(alg):
        scheme = _composite_scheme(alg)
        kp = CompositeKeyPair(pk=b"", sk=sk, scheme=scheme)
        return composite_sign(kp, handshake_hash)
    params = _mldsa_params(alg)
    return mldsa_sign(sk, handshake_hash, params)


def verify_handshake(
    alg: SignatureAlgorithm,
    pk: bytes,
    handshake_hash: bytes,
    signature: bytes,
) -> bool:
    """Verify a TLS 1.3 CertificateVerify signature."""
    if is_composite(alg):
        scheme = _composite_scheme(alg)
        return composite_verify(scheme, pk, handshake_hash, signature)
    params = _mldsa_params(alg)
    return mldsa_verify(pk, handshake_hash, signature, params)
