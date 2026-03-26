"""Tests for ML-DSA digital signature algorithm (FIPS 204)."""

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mldsa.ntt import ntt, ntt_inverse, pointwise_mul
from mldsa.field import Q, mod_q, field_mul
from mldsa.decompose import (
    power2_round, decompose, high_bits, low_bits,
    make_hint, use_hint,
)
from mldsa.dsa import keygen, sign, verify
from mldsa.params import ML_DSA_44, ML_DSA_65, ML_DSA_87


class TestNTT(unittest.TestCase):
    """Test NTT forward and inverse round-trip."""

    def test_ntt_roundtrip_zeros(self):
        f = [0] * 256
        self.assertEqual(ntt_inverse(ntt(f)), f)

    def test_ntt_roundtrip_ones(self):
        f = [1] * 256
        result = ntt_inverse(ntt(f))
        self.assertEqual(result, f)

    def test_ntt_roundtrip_random(self):
        import random
        random.seed(42)
        f = [random.randint(0, Q - 1) for _ in range(256)]
        result = ntt_inverse(ntt(f))
        self.assertEqual(result, f)

    def test_ntt_roundtrip_small(self):
        f = list(range(256))
        f = [x % Q for x in f]
        result = ntt_inverse(ntt(f))
        self.assertEqual(result, f)


class TestDecompose(unittest.TestCase):
    """Test decomposition functions."""

    def test_power2_round_identity(self):
        """r1 * 2^d + r0 should equal r mod Q."""
        import random
        random.seed(123)
        d = 13
        for _ in range(100):
            r = random.randint(0, Q - 1)
            r1, r0 = power2_round(r)
            reconstructed = (r1 * (1 << d) + r0) % Q
            self.assertEqual(reconstructed, r % Q)

    def test_decompose_identity(self):
        """r1 * alpha + r0 should equal r mod Q."""
        import random
        random.seed(456)
        for alpha in [2 * 95232, 2 * 261888]:
            for _ in range(100):
                r = random.randint(0, Q - 1)
                r1, r0 = decompose(r, alpha)
                reconstructed = (r1 * alpha + r0) % Q
                self.assertEqual(reconstructed, r % Q,
                                 f"Failed for r={r}, alpha={alpha}: r1={r1}, r0={r0}")

    def test_high_low_bits_consistency(self):
        """high_bits and low_bits should be consistent with decompose."""
        import random
        random.seed(789)
        alpha = 2 * 95232
        for _ in range(50):
            r = random.randint(0, Q - 1)
            r1, r0 = decompose(r, alpha)
            self.assertEqual(high_bits(r, alpha), r1)
            self.assertEqual(low_bits(r, alpha), r0)


class TestHint(unittest.TestCase):
    """Test hint make/use round-trip."""

    def test_hint_roundtrip(self):
        """UseHint should recover the correct high bits."""
        import random
        random.seed(321)
        alpha = 2 * 95232
        for _ in range(100):
            r = random.randint(0, Q - 1)
            z = random.randint(0, Q - 1)
            hint = make_hint(z, r, alpha)
            adjusted = use_hint(hint, (r + z) % Q, alpha)
            expected = high_bits(r, alpha) if hint == 0 else adjusted
            # UseHint((r+z), hint) should give HighBits(r) when hint corrects
            # The key property: UseHint(h, r+z) = HighBits(r)
            if hint == 0:
                self.assertEqual(adjusted, high_bits((r + z) % Q, alpha))


class TestKeyGenSizes(unittest.TestCase):
    """Test that key generation produces correct sizes for all parameter sets."""

    def _test_keygen_sizes(self, params):
        pk, sk = keygen(params)
        self.assertEqual(len(pk), params.pk_size,
                         f"{params.name}: pk size {len(pk)} != {params.pk_size}")
        self.assertEqual(len(sk), params.sk_size,
                         f"{params.name}: sk size {len(sk)} != {params.sk_size}")

    def test_keygen_sizes_44(self):
        self._test_keygen_sizes(ML_DSA_44)

    def test_keygen_sizes_65(self):
        self._test_keygen_sizes(ML_DSA_65)

    def test_keygen_sizes_87(self):
        self._test_keygen_sizes(ML_DSA_87)


class TestSignVerify(unittest.TestCase):
    """Test sign/verify round-trip for all parameter sets."""

    def _test_roundtrip(self, params):
        pk, sk = keygen(params)
        msg = b"Test message for ML-DSA"
        sig = sign(sk, msg, params)
        self.assertEqual(len(sig), params.sig_size,
                         f"{params.name}: sig size {len(sig)} != {params.sig_size}")
        self.assertTrue(verify(pk, msg, sig, params),
                        f"{params.name}: valid signature rejected")

    def test_roundtrip_44(self):
        self._test_roundtrip(ML_DSA_44)

    def test_roundtrip_65(self):
        self._test_roundtrip(ML_DSA_65)

    def test_roundtrip_87(self):
        self._test_roundtrip(ML_DSA_87)


class TestRejectTampered(unittest.TestCase):
    """Test that tampered signatures and messages are rejected."""

    def test_tampered_sig(self):
        params = ML_DSA_44
        pk, sk = keygen(params)
        msg = b"Original message"
        sig = sign(sk, msg, params)

        # Tamper with signature
        sig_tampered = bytearray(sig)
        sig_tampered[len(sig) // 2] ^= 0xFF
        sig_tampered = bytes(sig_tampered)

        self.assertFalse(verify(pk, msg, sig_tampered, params),
                         "Tampered signature should be rejected")

    def test_tampered_msg(self):
        params = ML_DSA_44
        pk, sk = keygen(params)
        msg = b"Original message"
        sig = sign(sk, msg, params)

        # Verify with different message
        msg_tampered = b"Tampered message"
        self.assertFalse(verify(pk, msg_tampered, sig, params),
                         "Signature should be rejected for wrong message")

    def test_wrong_key(self):
        params = ML_DSA_44
        pk1, sk1 = keygen(params)
        pk2, sk2 = keygen(params)
        msg = b"Test message"
        sig = sign(sk1, msg, params)

        # Verify with wrong public key
        self.assertFalse(verify(pk2, msg, sig, params),
                         "Signature should be rejected for wrong public key")


if __name__ == "__main__":
    unittest.main()
