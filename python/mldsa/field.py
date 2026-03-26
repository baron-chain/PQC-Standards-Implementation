"""Finite field arithmetic modulo Q = 8380417 for ML-DSA (FIPS 204)."""

Q = 8380417


def mod_q(a: int) -> int:
    """Reduce a modulo Q into range [0, Q)."""
    return a % Q


def field_add(a: int, b: int) -> int:
    """Add two field elements modulo Q."""
    return (a + b) % Q


def field_sub(a: int, b: int) -> int:
    """Subtract two field elements modulo Q."""
    return (a - b) % Q


def field_mul(a: int, b: int) -> int:
    """Multiply two field elements modulo Q."""
    return (a * b) % Q


def field_pow(base: int, exp: int) -> int:
    """Raise a field element to a power modulo Q."""
    return pow(base, exp, Q)


def field_inv(a: int) -> int:
    """Compute the modular inverse of a modulo Q using Fermat's little theorem."""
    if a % Q == 0:
        raise ValueError("Cannot invert zero")
    return pow(a, Q - 2, Q)
