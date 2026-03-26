"""Decomposition functions for ML-DSA (FIPS 204).

Implements Power2Round, Decompose, HighBits, LowBits, MakeHint, UseHint.
"""

from mldsa.field import Q


def power2_round(r: int) -> tuple[int, int]:
    """Power2Round: decompose r into (r1, r0) where r = r1*2^d + r0.

    Per FIPS 204, d=13.
    Returns (r1, r0) with r0 in [-(2^(d-1)-1), 2^(d-1)].
    """
    r = r % Q
    d = 13
    r0 = r % (1 << d)
    if r0 > (1 << (d - 1)):
        r0 -= (1 << d)
    r1 = (r - r0) >> d
    return r1, r0


def decompose(r: int, alpha: int) -> tuple[int, int]:
    """Decompose r into (r1, r0) such that r = r1*alpha + r0.

    Per FIPS 204 Algorithm 35 (Decompose).
    alpha is 2*gamma2.
    r0 is in [-alpha/2, alpha/2).
    """
    r = r % Q
    r0 = r % alpha
    if r0 > alpha // 2:
        r0 -= alpha
    if r - r0 == Q - 1:
        r1 = 0
        r0 = r0 - 1
    else:
        r1 = (r - r0) // alpha
    return r1, r0


def high_bits(r: int, alpha: int) -> int:
    """Extract high bits: the r1 component from Decompose."""
    r1, _ = decompose(r, alpha)
    return r1


def low_bits(r: int, alpha: int) -> int:
    """Extract low bits: the r0 component from Decompose."""
    _, r0 = decompose(r, alpha)
    return r0


def make_hint(z: int, r: int, alpha: int) -> int:
    """MakeHint: returns 1 if HighBits(r) != HighBits(r + z), else 0.

    Per FIPS 204 Algorithm 37.
    """
    r1 = high_bits(r, alpha)
    v1 = high_bits((r + z) % Q, alpha)
    return int(r1 != v1)


def use_hint(hint: int, r: int, alpha: int) -> int:
    """UseHint: adjust high bits of r using the hint.

    Per FIPS 204 Algorithm 38.
    If hint=0, return r1. If hint=1, adjust r1 based on r0.
    """
    m = (Q - 1) // alpha
    r1, r0 = decompose(r, alpha)
    if hint == 0:
        return r1
    if r0 > 0:
        return (r1 + 1) % m
    else:
        return (r1 - 1) % m
