package com.pqc.composite;

import com.pqc.composite.CompositeSig.CompositeKeyPair;
import com.pqc.composite.CompositeSig.Scheme;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for composite signature schemes.
 */
class CompositeSigTest {

    @ParameterizedTest
    @EnumSource(Scheme.class)
    void testRoundtrip(Scheme scheme) {
        CompositeKeyPair kp = CompositeSig.keyGen(scheme);
        byte[] msg = ("Hello " + scheme.name()).getBytes();
        byte[] sig = CompositeSig.sign(kp, msg);
        assertTrue(CompositeSig.verify(scheme, kp.pk(), msg, sig),
            scheme.name() + ": valid signature must verify");
    }

    @ParameterizedTest
    @EnumSource(Scheme.class)
    void testWrongMessage(Scheme scheme) {
        CompositeKeyPair kp = CompositeSig.keyGen(scheme);
        byte[] msg = "Original".getBytes();
        byte[] sig = CompositeSig.sign(kp, msg);
        assertFalse(CompositeSig.verify(scheme, kp.pk(), "Tampered".getBytes(), sig),
            scheme.name() + ": wrong message must fail");
    }

    @ParameterizedTest
    @EnumSource(Scheme.class)
    void testTamperClassical(Scheme scheme) {
        CompositeKeyPair kp = CompositeSig.keyGen(scheme);
        byte[] msg = "Tamper classical".getBytes();
        byte[] sig = CompositeSig.sign(kp, msg);
        byte[] tampered = Arrays.copyOf(sig, sig.length);
        if (tampered.length > 4) {
            tampered[4] ^= (byte) 0xFF;
        }
        assertFalse(CompositeSig.verify(scheme, kp.pk(), msg, tampered),
            scheme.name() + ": tampered classical sig must fail");
    }

    @ParameterizedTest
    @EnumSource(Scheme.class)
    void testTamperPQ(Scheme scheme) {
        CompositeKeyPair kp = CompositeSig.keyGen(scheme);
        byte[] msg = "Tamper PQ".getBytes();
        byte[] sig = CompositeSig.sign(kp, msg);
        byte[] tampered = Arrays.copyOf(sig, sig.length);
        tampered[tampered.length - 1] ^= (byte) 0xFF;
        assertFalse(CompositeSig.verify(scheme, kp.pk(), msg, tampered),
            scheme.name() + ": tampered PQ sig must fail");
    }

    @Test
    void testMlDsa65Ed25519KeySizes() {
        Scheme scheme = Scheme.MLDSA65_ED25519;
        CompositeKeyPair kp = CompositeSig.keyGen(scheme);
        // pk = 32 (Ed25519) + 1952 (ML-DSA-65)
        assertEquals(32 + scheme.pqParams.pkSize, kp.pk().length,
            "composite pk size");
        // sk = 32 (Ed25519 seed) + 4032 (ML-DSA-65)
        assertEquals(32 + scheme.pqParams.skSize, kp.sk().length,
            "composite sk size");
    }

    @Test
    void testShortSigRejects() {
        assertFalse(CompositeSig.verify(
            Scheme.MLDSA65_ED25519, new byte[1984], "msg".getBytes(), new byte[2]));
    }
}
