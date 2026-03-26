"""Compression and decompression per FIPS 203."""

from mlkem.field import Q


def compress(d: int, x: int) -> int:
    """Compress: round((2^d / Q) * x) mod 2^d."""
    # Use integer arithmetic: round((2^d * x) / Q) mod 2^d
    # round(a/b) = (2*a + b) // (2*b) for non-negative a, b
    two_d = 1 << d
    numerator = two_d * x
    result = (2 * numerator + Q) // (2 * Q)
    return result % two_d


def decompress(d: int, y: int) -> int:
    """Decompress: round((Q / 2^d) * y)."""
    two_d = 1 << d
    numerator = Q * y
    return (2 * numerator + two_d) // (2 * two_d)


def compress_poly(d: int, poly: list[int]) -> list[int]:
    """Compress all coefficients of a polynomial."""
    return [compress(d, c) for c in poly]


def decompress_poly(d: int, poly: list[int]) -> list[int]:
    """Decompress all coefficients of a polynomial."""
    return [decompress(d, c) for c in poly]
