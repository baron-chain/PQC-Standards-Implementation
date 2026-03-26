"""Byte encoding and decoding per FIPS 203.

Implements Algorithms 5 and 6.
"""


def byte_encode(d: int, F: list[int]) -> bytes:
    """Algorithm 5: Encode 256 d-bit integers into 32*d bytes.

    Input: array F of 256 integers in [0, 2^d) (or [0, Q) for d=12).
    Output: byte array of length 32*d.
    """
    if len(F) != 256:
        raise ValueError(f"Expected 256 coefficients, got {len(F)}")

    # Bit-packing: pack 256 d-bit values into a bit stream
    bits = []
    for a in F:
        for j in range(d):
            bits.append((a >> j) & 1)

    # Convert bits to bytes (LSB first within each byte)
    total_bytes = 32 * d
    result = bytearray(total_bytes)
    for i in range(total_bytes):
        val = 0
        for j in range(8):
            bit_idx = i * 8 + j
            if bit_idx < len(bits):
                val |= bits[bit_idx] << j
        result[i] = val
    return bytes(result)


def byte_decode(d: int, B: bytes) -> list[int]:
    """Algorithm 6: Decode 32*d bytes into 256 d-bit integers.

    Input: byte array B of length 32*d.
    Output: array of 256 integers.

    For d=12, does NOT reduce mod Q (caller handles validation).
    """
    expected_len = 32 * d
    if len(B) != expected_len:
        raise ValueError(f"Expected {expected_len} bytes, got {len(B)}")

    m = (1 << d) if d < 12 else (1 << 12)

    # Extract bits from bytes (LSB first)
    bits = []
    for byte_val in B:
        for j in range(8):
            bits.append((byte_val >> j) & 1)

    # Reconstruct d-bit integers
    F = []
    for i in range(256):
        val = 0
        for j in range(d):
            val |= bits[i * d + j] << j
        if d < 12:
            val %= m
        F.append(val)
    return F
