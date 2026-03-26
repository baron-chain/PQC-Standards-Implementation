"""Hash functions and extendable-output functions for ML-DSA (FIPS 204).

Uses hashlib SHAKE-128 and SHAKE-256 for XOF operations.
"""

import hashlib
import struct

from mldsa.field import Q


def h(data: bytes, out_len: int) -> bytes:
    """SHAKE-256 hash with specified output length."""
    return hashlib.shake_256(data).digest(out_len)


def h_sha3_256(data: bytes) -> bytes:
    """SHA3-256 hash, returns 32 bytes."""
    return hashlib.sha3_256(data).digest()


def h_sha3_512(data: bytes) -> bytes:
    """SHA3-512 hash, returns 64 bytes."""
    return hashlib.sha3_512(data).digest()


def _rejection_sample_ntt(stream: bytes) -> list[int]:
    """Sample a polynomial in NTT domain by rejection from a byte stream.

    Each coefficient is sampled from 3 bytes (23 bits) and accepted if < Q.
    """
    coeffs = []
    i = 0
    while len(coeffs) < 256:
        if i + 3 > len(stream):
            raise ValueError("Stream exhausted during rejection sampling")
        b0 = stream[i]
        b1 = stream[i + 1]
        b2 = stream[i + 2]
        i += 3
        # Extract 23-bit value
        val = b0 | (b1 << 8) | ((b2 & 0x7F) << 16)
        if val < Q:
            coeffs.append(val)
    return coeffs


def expand_a(rho: bytes, k: int, l: int) -> list[list[list[int]]]:
    """Expand the public matrix A_hat from seed rho.

    Returns a k x l matrix of polynomials in NTT domain.
    Each polynomial is sampled by rejection from SHAKE-128(rho || IntegerToBytes(s, 2))
    where s encodes the row and column indices.
    """
    A_hat = []
    for r in range(k):
        row = []
        for s in range(l):
            # FIPS 204 specifies: SHAKE-128(rho || IntegerToBytes(s, 1) || IntegerToBytes(r, 1))
            seed = rho + bytes([s, r])
            stream = hashlib.shake_128(seed).digest(256 * 3 + 512)
            poly = _rejection_sample_ntt(stream)
            row.append(poly)
        A_hat.append(row)
    return A_hat


def _coef_from_half_byte(eta: int, b: int):
    """CoefFromHalfByte per FIPS 204 Algorithm 29.

    Returns a coefficient in [-eta, eta] or None if rejected.
    """
    if eta == 2:
        if b < 15:
            return 2 - (b % 5)
        return None
    elif eta == 4:
        if b < 9:
            return 4 - b
        return None
    return None


def _sample_eta(stream: bytes, eta: int, n: int = 256) -> list[int]:
    """Sample polynomial with coefficients in [-eta, eta].

    Per FIPS 204: uses CoefFromHalfByte on each nibble of the stream.
    """
    coeffs = []
    i = 0
    while len(coeffs) < n:
        if i >= len(stream):
            raise ValueError("Stream exhausted during eta sampling")
        b = stream[i]
        i += 1
        # Extract two half-bytes
        z0 = _coef_from_half_byte(eta, b & 0x0F)
        z1 = _coef_from_half_byte(eta, (b >> 4) & 0x0F)
        if z0 is not None and len(coeffs) < n:
            coeffs.append(z0)
        if z1 is not None and len(coeffs) < n:
            coeffs.append(z1)
    return coeffs


def expand_s(rho_prime: bytes, l: int, k: int, eta: int) -> tuple[list[list[int]], list[list[int]]]:
    """Expand secret vectors s1 (length l) and s2 (length k).

    Each polynomial has coefficients in [-eta, eta].
    Uses SHAKE-256(rho_prime || counter) for each polynomial.
    """
    s1 = []
    for i in range(l):
        seed = rho_prime + struct.pack('<H', i)
        stream = hashlib.shake_256(seed).digest(256 * 4)
        poly = _sample_eta(stream, eta)
        s1.append(poly)

    s2 = []
    for i in range(k):
        seed = rho_prime + struct.pack('<H', l + i)
        stream = hashlib.shake_256(seed).digest(256 * 4)
        poly = _sample_eta(stream, eta)
        s2.append(poly)

    return s1, s2


def expand_mask(rho_prime: bytes, kappa: int, l: int, gamma1: int) -> list[list[int]]:
    """Expand mask vector y of length l.

    Each coefficient is in [-(gamma1-1), gamma1].
    Uses SHAKE-256(rho_prime || counter).
    """
    gamma1_bits = 18 if gamma1 == (1 << 17) else 20
    byte_count = 256 * gamma1_bits // 8  # 576 or 640 bytes per poly

    y = []
    for i in range(l):
        seed = rho_prime + struct.pack('<H', kappa + i)
        stream = hashlib.shake_256(seed).digest(byte_count)
        poly = _decode_gamma1(stream, gamma1, gamma1_bits)
        y.append(poly)
    return y


def _decode_gamma1(stream: bytes, gamma1: int, gamma1_bits: int) -> list[int]:
    """Decode a polynomial with coefficients in [-(gamma1-1), gamma1] from bytes."""
    coeffs = []
    if gamma1_bits == 18:
        # 18 bits per coefficient, 4 coefficients from 9 bytes
        for i in range(64):
            offset = i * 9
            b = int.from_bytes(stream[offset:offset + 9], 'little')
            for j in range(4):
                val = (b >> (18 * j)) & 0x3FFFF
                val = gamma1 - val
                coeffs.append(val % Q)
    else:
        # 20 bits per coefficient, 4 coefficients from 10 bytes
        for i in range(64):
            offset = i * 10
            b = int.from_bytes(stream[offset:offset + 10], 'little')
            for j in range(4):
                val = (b >> (20 * j)) & 0xFFFFF
                val = gamma1 - val
                coeffs.append(val % Q)
    return coeffs


def sample_in_ball(seed: bytes, tau: int) -> list[int]:
    """Sample a polynomial c with exactly tau +/-1 coefficients.

    Per FIPS 204 Algorithm 30 (SampleInBall).
    Uses SHAKE-256 to generate randomness.
    """
    c = [0] * 256
    # Request generous amount of bytes for rejection sampling
    stream = hashlib.shake_256(seed).digest(8 + 272)

    # First 8 bytes provide sign bits
    sign_bits = int.from_bytes(stream[:8], 'little')

    pos = 8
    for i in range(256 - tau, 256):
        # Sample j uniform in [0, i]
        while True:
            if pos >= len(stream):
                # Extend stream if needed
                stream = hashlib.shake_256(seed).digest(len(stream) * 2)
            j = stream[pos]
            pos += 1
            if j <= i:
                break
        c[i] = c[j]
        sign = (sign_bits >> (i - (256 - tau))) & 1
        c[j] = 1 - 2 * sign  # +1 or -1
    return c
