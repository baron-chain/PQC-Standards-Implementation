"""Encoding and decoding functions for ML-DSA (FIPS 204).

Handles bit-packing of polynomials, public keys, secret keys, and signatures.
"""

from mldsa.field import Q
from mldsa.params import MLDSAParams


def bit_pack(poly: list[int], a: int, b: int) -> bytes:
    """Pack polynomial coefficients that are in range [-a, b] into bytes.

    Each coefficient is mapped to [0, a+b] then packed with ceil(log2(a+b+1)) bits.
    """
    total = a + b
    if total == 0:
        return b''
    bits_per_coeff = total.bit_length()
    result_bits = []
    for c in poly:
        # Map coefficient: val = a + coeff (shift range from [-a, b] to [0, a+b])
        val = a + c
        for j in range(bits_per_coeff):
            result_bits.append((val >> j) & 1)
    # Convert bits to bytes
    num_bytes = (len(result_bits) + 7) // 8
    result = bytearray(num_bytes)
    for i in range(len(result_bits)):
        result[i // 8] |= result_bits[i] << (i % 8)
    return bytes(result)


def bit_unpack(data: bytes, a: int, b: int, n: int = 256) -> list[int]:
    """Unpack bytes into polynomial coefficients in range [-a, b].

    Inverse of bit_pack.
    """
    total = a + b
    if total == 0:
        return [0] * n
    bits_per_coeff = total.bit_length()
    # Extract bits from bytes
    bits = []
    for byte_val in data:
        for j in range(8):
            bits.append((byte_val >> j) & 1)
    coeffs = []
    for i in range(n):
        val = 0
        for j in range(bits_per_coeff):
            idx = i * bits_per_coeff + j
            if idx < len(bits):
                val |= bits[idx] << j
        coeffs.append(val - a)
    return coeffs


def simple_bit_pack(poly: list[int], b: int) -> bytes:
    """Pack polynomial with coefficients in [0, b] into bytes.

    Each coefficient packed with ceil(log2(b+1)) bits.
    """
    if b == 0:
        return b''
    bits_per_coeff = b.bit_length()
    result_bits = []
    for c in poly:
        for j in range(bits_per_coeff):
            result_bits.append((c >> j) & 1)
    num_bytes = (len(result_bits) + 7) // 8
    result = bytearray(num_bytes)
    for i in range(len(result_bits)):
        result[i // 8] |= result_bits[i] << (i % 8)
    return bytes(result)


def simple_bit_unpack(data: bytes, b: int, n: int = 256) -> list[int]:
    """Unpack bytes into polynomial with coefficients in [0, b]."""
    if b == 0:
        return [0] * n
    bits_per_coeff = b.bit_length()
    bits = []
    for byte_val in data:
        for j in range(8):
            bits.append((byte_val >> j) & 1)
    coeffs = []
    for i in range(n):
        val = 0
        for j in range(bits_per_coeff):
            idx = i * bits_per_coeff + j
            if idx < len(bits):
                val |= bits[idx] << j
        coeffs.append(val)
    return coeffs


def encode_pk(rho: bytes, t1: list[list[int]], params: MLDSAParams) -> bytes:
    """Encode public key: rho || encode(t1).

    t1 coefficients are in [0, 2^(bitlen(q-1)-d) - 1] = [0, 1023].
    Each coefficient uses 10 bits.
    """
    result = bytearray(rho)
    for poly in t1:
        result.extend(simple_bit_pack(poly, (1 << 10) - 1))
    return bytes(result)


def decode_pk(pk: bytes, params: MLDSAParams) -> tuple[bytes, list[list[int]]]:
    """Decode public key into rho and t1."""
    rho = pk[:32]
    t1 = []
    # 10 bits per coeff, 256 coeffs = 320 bytes per poly
    poly_bytes = 320
    offset = 32
    for i in range(params.k):
        data = pk[offset:offset + poly_bytes]
        poly = simple_bit_unpack(data, (1 << 10) - 1)
        t1.append(poly)
        offset += poly_bytes
    return rho, t1


def encode_sk(rho: bytes, K: bytes, tr: bytes,
              s1: list[list[int]], s2: list[list[int]],
              t0: list[list[int]], params: MLDSAParams) -> bytes:
    """Encode secret key: rho || K || tr || encode(s1) || encode(s2) || encode(t0)."""
    result = bytearray(rho)  # 32 bytes
    result.extend(K)  # 32 bytes
    result.extend(tr)  # 64 bytes

    # Encode s1: coefficients in [-eta, eta]
    for poly in s1:
        result.extend(bit_pack(poly, params.eta, params.eta))

    # Encode s2: coefficients in [-eta, eta]
    for poly in s2:
        result.extend(bit_pack(poly, params.eta, params.eta))

    # Encode t0: coefficients in [-(2^(d-1)-1), 2^(d-1)]
    d = params.d
    for poly in t0:
        result.extend(bit_pack(poly, (1 << (d - 1)) - 1, 1 << (d - 1)))

    return bytes(result)


def decode_sk(sk: bytes, params: MLDSAParams) -> tuple[bytes, bytes, bytes,
                                                         list[list[int]],
                                                         list[list[int]],
                                                         list[list[int]]]:
    """Decode secret key into components."""
    offset = 0
    rho = sk[offset:offset + 32]; offset += 32
    K = sk[offset:offset + 32]; offset += 32
    tr = sk[offset:offset + 64]; offset += 64

    eta = params.eta
    eta_bits = (2 * eta).bit_length()
    eta_bytes = 256 * eta_bits // 8

    s1 = []
    for _ in range(params.l):
        data = sk[offset:offset + eta_bytes]
        poly = bit_unpack(data, eta, eta)
        s1.append(poly)
        offset += eta_bytes

    s2 = []
    for _ in range(params.k):
        data = sk[offset:offset + eta_bytes]
        poly = bit_unpack(data, eta, eta)
        s2.append(poly)
        offset += eta_bytes

    d = params.d
    t0_a = (1 << (d - 1)) - 1
    t0_b = 1 << (d - 1)
    t0_total = t0_a + t0_b
    t0_bits = t0_total.bit_length()
    t0_bytes = 256 * t0_bits // 8

    t0 = []
    for _ in range(params.k):
        data = sk[offset:offset + t0_bytes]
        poly = bit_unpack(data, t0_a, t0_b)
        t0.append(poly)
        offset += t0_bytes

    return rho, K, tr, s1, s2, t0


def encode_w1(w1: list[list[int]], params: MLDSAParams) -> bytes:
    """Encode w1 vector for hashing.

    w1 coefficients are in [0, (q-1)/(2*gamma2) - 1].
    """
    alpha = 2 * params.gamma2
    m = (Q - 1) // alpha  # number of possible high-bits values
    max_val = m - 1  # maximum w1 coefficient value
    result = bytearray()
    for poly in w1:
        result.extend(simple_bit_pack(poly, max_val))
    return bytes(result)


def encode_sig(c_tilde: bytes, z: list[list[int]], h: list[list[int]],
               params: MLDSAParams) -> bytes:
    """Encode signature: c_tilde || encode(z) || encode(h).

    z coefficients are in [-(gamma1-1), gamma1].
    h is encoded as a list of hint positions.
    """
    result = bytearray(c_tilde)

    # Encode z: coefficients in [-(gamma1-1), gamma1]
    gamma1 = params.gamma1
    for poly in z:
        result.extend(bit_pack(poly, gamma1 - 1, gamma1))

    # Encode hints h using omega + k bytes
    hint_bytes = bytearray(params.omega + params.k)
    idx = 0
    for i in range(params.k):
        for j in range(256):
            if h[i][j] == 1:
                hint_bytes[idx] = j
                idx += 1
        hint_bytes[params.omega + i] = idx
    result.extend(hint_bytes)

    return bytes(result)


def decode_sig(sig: bytes, params: MLDSAParams) -> tuple[bytes, list[list[int]], list[list[int]]]:
    """Decode signature into c_tilde, z, h."""
    c_tilde_len = params.lambda_ // 4
    c_tilde = sig[:c_tilde_len]
    offset = c_tilde_len

    gamma1 = params.gamma1
    gamma1_a = gamma1 - 1
    gamma1_b = gamma1
    gamma1_total = gamma1_a + gamma1_b
    gamma1_bits = gamma1_total.bit_length()
    z_poly_bytes = 256 * gamma1_bits // 8

    z = []
    for _ in range(params.l):
        data = sig[offset:offset + z_poly_bytes]
        poly = bit_unpack(data, gamma1_a, gamma1_b)
        z.append(poly)
        offset += z_poly_bytes

    # Decode hints
    hint_data = sig[offset:offset + params.omega + params.k]
    h = [[0] * 256 for _ in range(params.k)]
    idx = 0
    for i in range(params.k):
        end_idx = hint_data[params.omega + i]
        while idx < end_idx:
            h[i][hint_data[idx]] = 1
            idx += 1

    return c_tilde, z, h
