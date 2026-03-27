package com.pqc.hybrid;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for Hybrid KEM schemes.
 */
class HybridKEMTest {

    @ParameterizedTest
    @EnumSource(HybridKEM.Scheme.class)
    void testRoundtrip(HybridKEM.Scheme scheme) {
        HybridKEM.HybridKeyPair kp = HybridKEM.keyGen(scheme);
        HybridKEM.EncapsResult enc = HybridKEM.encaps(scheme, kp.ek(), kp.classicalEkSize());
        byte[] ss = HybridKEM.decaps(scheme, kp.dk(), enc.ciphertext(),
                kp.classicalDkSize(), enc.classicalCtSize());

        assertEquals(32, enc.sharedSecret().length,
                scheme.name() + ": shared secret should be 32 bytes");
        assertArrayEquals(enc.sharedSecret(), ss,
                scheme.name() + ": roundtrip failed");
    }

    @Test
    void testDifferentKeysDifferentSecrets() {
        HybridKEM.Scheme scheme = HybridKEM.Scheme.X25519_MLKEM768;
        HybridKEM.HybridKeyPair kp1 = HybridKEM.keyGen(scheme);
        HybridKEM.HybridKeyPair kp2 = HybridKEM.keyGen(scheme);

        HybridKEM.EncapsResult enc1 = HybridKEM.encaps(scheme, kp1.ek(), kp1.classicalEkSize());
        HybridKEM.EncapsResult enc2 = HybridKEM.encaps(scheme, kp2.ek(), kp2.classicalEkSize());

        assertFalse(java.util.Arrays.equals(enc1.sharedSecret(), enc2.sharedSecret()),
                "different keys should produce different shared secrets");
    }

    @Test
    void testMultipleEncapsSameKey() {
        HybridKEM.Scheme scheme = HybridKEM.Scheme.X25519_MLKEM768;
        HybridKEM.HybridKeyPair kp = HybridKEM.keyGen(scheme);

        HybridKEM.EncapsResult enc1 = HybridKEM.encaps(scheme, kp.ek(), kp.classicalEkSize());
        HybridKEM.EncapsResult enc2 = HybridKEM.encaps(scheme, kp.ek(), kp.classicalEkSize());

        assertFalse(java.util.Arrays.equals(enc1.sharedSecret(), enc2.sharedSecret()),
                "multiple encapsulations should produce different shared secrets");

        byte[] ss1 = HybridKEM.decaps(scheme, kp.dk(), enc1.ciphertext(),
                kp.classicalDkSize(), enc1.classicalCtSize());
        byte[] ss2 = HybridKEM.decaps(scheme, kp.dk(), enc2.ciphertext(),
                kp.classicalDkSize(), enc2.classicalCtSize());

        assertArrayEquals(enc1.sharedSecret(), ss1, "first encaps roundtrip failed");
        assertArrayEquals(enc2.sharedSecret(), ss2, "second encaps roundtrip failed");
    }

    @Test
    void testSharedSecretLength() {
        for (HybridKEM.Scheme scheme : HybridKEM.Scheme.values()) {
            HybridKEM.HybridKeyPair kp = HybridKEM.keyGen(scheme);
            HybridKEM.EncapsResult enc = HybridKEM.encaps(scheme, kp.ek(), kp.classicalEkSize());
            assertEquals(32, enc.sharedSecret().length,
                    scheme.name() + ": shared secret should be 32 bytes");
        }
    }
}
