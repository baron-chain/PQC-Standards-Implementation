"""Tests for the PQC TLS 1.3 integration layer."""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pqctls.named_groups import (
    NamedGroup, ALL_NAMED_GROUPS, named_group_from_code_point,
    generate_key_share, complete_key_exchange, recover_shared_secret,
    key_share_size,
)
from pqctls.sig_algorithms import (
    SignatureAlgorithm, ALL_SIGNATURE_ALGORITHMS,
    signature_algorithm_from_code_point,
    generate_signing_key, sign_handshake, verify_handshake,
)
from pqctls.cipher_suites import (
    AeadAlgorithm, CipherSuite,
    TLS_AES_128_GCM_SHA256_MLKEM768,
    TLS_AES_256_GCM_SHA384_X25519MLKEM768,
    ALL_CIPHER_SUITES, cipher_suite_by_id,
)


class TestNamedGroups(unittest.TestCase):
    def test_code_points(self):
        self.assertEqual(NamedGroup.MLKEM768, 0x0768)
        self.assertEqual(NamedGroup.MLKEM1024, 0x1024)
        self.assertEqual(NamedGroup.X25519MLKEM768, 0x6399)
        self.assertEqual(NamedGroup.SecP256r1MLKEM768, 0x639A)

    def test_from_code_point(self):
        self.assertEqual(named_group_from_code_point(0x6399), NamedGroup.X25519MLKEM768)
        self.assertIsNone(named_group_from_code_point(0xFFFF))


class TestMLKEM768KeyExchange(unittest.TestCase):
    def test_roundtrip(self):
        ks = generate_key_share(NamedGroup.MLKEM768)
        self.assertEqual(len(ks.public_key_share), key_share_size(NamedGroup.MLKEM768))

        resp = complete_key_exchange(NamedGroup.MLKEM768, ks.public_key_share)
        ss = recover_shared_secret(
            NamedGroup.MLKEM768,
            ks.private_key,
            resp.response_key_share,
        )
        self.assertEqual(resp.shared_secret, ss)


class TestX25519MLKEM768KeyExchange(unittest.TestCase):
    def test_roundtrip(self):
        ks = generate_key_share(NamedGroup.X25519MLKEM768)
        self.assertEqual(len(ks.public_key_share), key_share_size(NamedGroup.X25519MLKEM768))

        resp = complete_key_exchange(
            NamedGroup.X25519MLKEM768,
            ks.public_key_share,
            ks.classical_ek_size,
        )
        ss = recover_shared_secret(
            NamedGroup.X25519MLKEM768,
            ks.private_key,
            resp.response_key_share,
            ks.classical_dk_size,
            resp.classical_ct_size,
        )
        self.assertEqual(resp.shared_secret, ss)


class TestAllGroupsKeyShareSizes(unittest.TestCase):
    def test_all_groups(self):
        for group in ALL_NAMED_GROUPS:
            ks = generate_key_share(group)
            self.assertEqual(
                len(ks.public_key_share),
                key_share_size(group),
                f"Key share size mismatch for {group.name}",
            )


class TestSignatureAlgorithms(unittest.TestCase):
    def test_code_points(self):
        self.assertEqual(SignatureAlgorithm.MLDSA44, 0x0904)
        self.assertEqual(SignatureAlgorithm.MLDSA65, 0x0905)
        self.assertEqual(SignatureAlgorithm.MLDSA87, 0x0906)
        self.assertEqual(SignatureAlgorithm.MLDSA65_ED25519, 0x0907)
        self.assertEqual(SignatureAlgorithm.MLDSA87_ED25519, 0x0908)

    def test_from_code_point(self):
        self.assertEqual(
            signature_algorithm_from_code_point(0x0905),
            SignatureAlgorithm.MLDSA65,
        )
        self.assertIsNone(signature_algorithm_from_code_point(0xFFFF))


class TestMLDSA65SignVerify(unittest.TestCase):
    def test_sign_verify(self):
        kp = generate_signing_key(SignatureAlgorithm.MLDSA65)
        hash_data = b"test handshake transcript hash for CertificateVerify"
        sig = sign_handshake(SignatureAlgorithm.MLDSA65, kp.sk, hash_data)
        self.assertTrue(verify_handshake(SignatureAlgorithm.MLDSA65, kp.pk, hash_data, sig))

    def test_wrong_key_fails(self):
        kp1 = generate_signing_key(SignatureAlgorithm.MLDSA65)
        kp2 = generate_signing_key(SignatureAlgorithm.MLDSA65)
        hash_data = b"test hash"
        sig = sign_handshake(SignatureAlgorithm.MLDSA65, kp1.sk, hash_data)
        self.assertFalse(verify_handshake(SignatureAlgorithm.MLDSA65, kp2.pk, hash_data, sig))


class TestCompositeMlDsa65Ed25519(unittest.TestCase):
    def test_sign_verify(self):
        kp = generate_signing_key(SignatureAlgorithm.MLDSA65_ED25519)
        hash_data = b"composite handshake hash"
        sig = sign_handshake(SignatureAlgorithm.MLDSA65_ED25519, kp.sk, hash_data)
        self.assertTrue(
            verify_handshake(SignatureAlgorithm.MLDSA65_ED25519, kp.pk, hash_data, sig)
        )


class TestCipherSuites(unittest.TestCase):
    def test_definitions(self):
        cs = TLS_AES_128_GCM_SHA256_MLKEM768
        self.assertEqual(cs.aead, AeadAlgorithm.AES_128_GCM_SHA256)
        self.assertEqual(cs.key_exchange, NamedGroup.MLKEM768)
        self.assertEqual(cs.signature, SignatureAlgorithm.MLDSA65)

    def test_lookup_by_id(self):
        cs = cipher_suite_by_id(0x13010768)
        self.assertIsNotNone(cs)
        self.assertEqual(cs.name, "TLS_AES_128_GCM_SHA256_MLKEM768")

        cs2 = cipher_suite_by_id(0x13026399)
        self.assertIsNotNone(cs2)
        self.assertEqual(cs2.name, "TLS_AES_256_GCM_SHA384_X25519MLKEM768")

        self.assertIsNone(cipher_suite_by_id(0xDEADBEEF))


if __name__ == "__main__":
    unittest.main()
