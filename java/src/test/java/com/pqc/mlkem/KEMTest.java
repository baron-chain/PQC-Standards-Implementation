package com.pqc.mlkem;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.SecureRandom;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class KEMTest {

    static Stream<Params> allParams() {
        return Stream.of(Params.ML_KEM_512, Params.ML_KEM_768, Params.ML_KEM_1024);
    }

    @ParameterizedTest
    @MethodSource("allParams")
    void testKeyGenSizes(Params params) {
        MLKEM.KeyPair kp = MLKEM.keyGen(params);
        assertEquals(params.ekSize, kp.ek().length,
                params.name + " ek size");
        assertEquals(params.dkSize, kp.dk().length,
                params.name + " dk size");
    }

    @ParameterizedTest
    @MethodSource("allParams")
    void testRoundTrip(Params params) {
        MLKEM.KeyPair kp = MLKEM.keyGen(params);
        MLKEM.EncapsResult encaps = MLKEM.encaps(kp.ek(), params);
        byte[] decapsKey = MLKEM.decaps(kp.dk(), encaps.ciphertext(), params);

        assertArrayEquals(encaps.sharedSecret(), decapsKey,
                params.name + " round-trip: shared secrets must match");
        assertEquals(32, encaps.sharedSecret().length,
                params.name + " shared secret must be 32 bytes");
        assertEquals(params.ctSize, encaps.ciphertext().length,
                params.name + " ciphertext size");
    }

    @ParameterizedTest
    @MethodSource("allParams")
    void testImplicitRejection(Params params) {
        MLKEM.KeyPair kp = MLKEM.keyGen(params);
        MLKEM.EncapsResult encaps = MLKEM.encaps(kp.ek(), params);

        // Tamper with ciphertext
        byte[] badCiphertext = encaps.ciphertext().clone();
        badCiphertext[0] ^= 0xFF;

        byte[] decapsKey = MLKEM.decaps(kp.dk(), badCiphertext, params);

        // Decaps should NOT return the real shared secret (implicit rejection)
        assertFalse(java.util.Arrays.equals(encaps.sharedSecret(), decapsKey),
                params.name + " implicit rejection: tampered ciphertext should not yield correct key");
        // But it should still return a 32-byte key (not throw)
        assertEquals(32, decapsKey.length,
                params.name + " implicit rejection should still return 32-byte key");
    }

    @Test
    void testEkValidation() {
        // Wrong length
        assertThrows(IllegalArgumentException.class,
                () -> MLKEM.encaps(new byte[100], Params.ML_KEM_512));
    }

    @Test
    void testEkValidationBadCoefficient() {
        MLKEM.KeyPair kp = MLKEM.keyGen(Params.ML_KEM_512);
        byte[] badEk = kp.ek().clone();
        // Corrupt a byte in the polynomial encoding to make a coefficient >= Q
        // Set 12 bits starting at position 0 to all 1s (value 4095 > 3329)
        badEk[0] = (byte) 0xFF;
        badEk[1] = (byte) (badEk[1] | 0x0F);
        assertThrows(IllegalArgumentException.class,
                () -> MLKEM.encaps(badEk, Params.ML_KEM_512));
    }

    @ParameterizedTest
    @MethodSource("allParams")
    void testMultipleRoundTrips(Params params) {
        // Run multiple round-trips to check consistency
        for (int trial = 0; trial < 3; trial++) {
            MLKEM.KeyPair kp = MLKEM.keyGen(params);
            MLKEM.EncapsResult encaps = MLKEM.encaps(kp.ek(), params);
            byte[] decapsKey = MLKEM.decaps(kp.dk(), encaps.ciphertext(), params);
            assertArrayEquals(encaps.sharedSecret(), decapsKey,
                    params.name + " round-trip trial " + trial);
        }
    }
}
