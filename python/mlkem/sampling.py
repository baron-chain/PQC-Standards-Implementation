"""Sampling algorithms per FIPS 203.

Implements Algorithms 7 and 8.
"""

from mlkem.field import Q


def sample_ntt(xof_bytes: bytes) -> list[int]:
    """Algorithm 7: Rejection sampling from XOF output.

    Input: byte stream from XOF.
    Output: array of 256 elements in Z_Q (NTT domain).
    """
    coeffs = []
    i = 0
    while len(coeffs) < 256:
        if i + 3 > len(xof_bytes):
            raise ValueError("Insufficient XOF bytes for sampling")
        b0 = xof_bytes[i]
        b1 = xof_bytes[i + 1]
        b2 = xof_bytes[i + 2]
        i += 3

        d1 = b0 + 256 * (b1 % 16)
        d2 = (b1 >> 4) + 16 * b2

        if d1 < Q:
            coeffs.append(d1)
        if d2 < Q and len(coeffs) < 256:
            coeffs.append(d2)

    return coeffs


def sample_poly_cbd(prf_bytes: bytes, eta: int) -> list[int]:
    """Algorithm 8: Sample from centered binomial distribution.

    Input: PRF output bytes, parameter eta.
    Output: polynomial with 256 coefficients in Z_Q.
    """
    # Extract all bits
    bits = []
    for byte_val in prf_bytes:
        for j in range(8):
            bits.append((byte_val >> j) & 1)

    coeffs = []
    for i in range(256):
        x = sum(bits[2 * i * eta + j] for j in range(eta))
        y = sum(bits[2 * i * eta + eta + j] for j in range(eta))
        coeffs.append((x - y) % Q)
    return coeffs
