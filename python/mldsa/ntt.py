"""Number Theoretic Transform (NTT) operations for ML-DSA (FIPS 204).

ML-DSA uses the same NTT structure as ML-KEM but with Q = 8380417
and primitive root of unity zeta = 1753.
"""

from mldsa.field import Q, field_mul, field_sub, field_add


def bit_rev8(n: int) -> int:
    """Reverse the 8 least significant bits of n."""
    result = 0
    for _ in range(8):
        result = (result << 1) | (n & 1)
        n >>= 1
    return result


def _precompute_zetas() -> list[int]:
    """Precompute zeta values: ZETAS[i] = 1753^(bitrev8(i)) mod Q.

    Per FIPS 204, the root of unity is 1753.
    """
    zetas = []
    for i in range(256):
        zetas.append(pow(1753, bit_rev8(i), Q))
    return zetas


ZETAS: list[int] = _precompute_zetas()


def ntt(f: list[int]) -> list[int]:
    """Forward NTT for ML-DSA.

    Input: polynomial f with 256 coefficients in Z_Q.
    Output: NTT representation f_hat.
    """
    f_hat = list(f)
    k = 0
    length = 128
    while length >= 1:
        start = 0
        while start < 256:
            k += 1
            zeta = ZETAS[k]
            for j in range(start, start + length):
                t = field_mul(zeta, f_hat[j + length])
                f_hat[j + length] = field_sub(f_hat[j], t)
                f_hat[j] = field_add(f_hat[j], t)
            start += 2 * length
        length //= 2
    return f_hat


def ntt_inverse(f_hat: list[int]) -> list[int]:
    """Inverse NTT for ML-DSA.

    Input: NTT representation f_hat.
    Output: polynomial f with 256 coefficients in Z_Q.
    """
    f = list(f_hat)
    k = 256
    length = 1
    while length <= 128:
        start = 0
        while start < 256:
            k -= 1
            zeta = Q - ZETAS[k]  # negated zeta for Gentleman-Sande inverse
            for j in range(start, start + length):
                t = f[j]
                f[j] = field_add(t, f[j + length])
                f[j + length] = field_mul(zeta, field_sub(t, f[j + length]))
            start += 2 * length
        length *= 2
    # Multiply by n^{-1} mod Q where n=256.
    # 256^{-1} mod 8380417 = 8347681
    inv256 = 8347681
    f = [field_mul(c, inv256) for c in f]
    return f


def pointwise_mul(a: list[int], b: list[int]) -> list[int]:
    """Pointwise multiplication of two NTT-domain polynomials.

    In ML-DSA the NTT splits into 256 degree-0 slots,
    so pointwise multiply is simply coefficient-wise.
    """
    return [field_mul(a[i], b[i]) for i in range(256)]
