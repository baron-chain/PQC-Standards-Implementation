package com.pqc.mlkem;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.pqc.mlkem.Field.*;

class NTTTest {

    @Test
    void testBitRev7() {
        assertEquals(0, NTT.bitRev7(0));
        assertEquals(64, NTT.bitRev7(1));  // 0000001 -> 1000000 = 64
        assertEquals(32, NTT.bitRev7(2));  // 0000010 -> 0100000 = 32
        assertEquals(127, NTT.bitRev7(127)); // 1111111 -> 1111111 = 127
    }

    @Test
    void testZetasRange() {
        for (int i = 0; i < 128; i++) {
            assertTrue(NTT.ZETAS[i] >= 0 && NTT.ZETAS[i] < Q,
                    "ZETA[" + i + "] = " + NTT.ZETAS[i] + " out of range");
        }
        // zetas[0] = 17^(bitRev7(0)) = 17^0 = 1
        assertEquals(1, NTT.ZETAS[0]);
        // zetas[1] = 17^(bitRev7(1)) = 17^64 mod Q
        assertEquals(fieldPow(17, 64), NTT.ZETAS[1]);
    }

    @Test
    void testNTTRoundTrip() {
        int[] f = new int[256];
        for (int i = 0; i < 256; i++) {
            f[i] = mod(i * 13 + 7, Q);
        }
        int[] fHat = NTT.ntt(f);
        int[] recovered = NTT.nttInverse(fHat);
        assertArrayEquals(f, recovered, "NTT round-trip failed");
    }

    @Test
    void testNTTRoundTripZero() {
        int[] f = new int[256];
        int[] fHat = NTT.ntt(f);
        int[] recovered = NTT.nttInverse(fHat);
        assertArrayEquals(f, recovered, "NTT round-trip for zero polynomial failed");
    }

    @Test
    void testMultiplyCommutativity() {
        int[] f = new int[256];
        int[] g = new int[256];
        for (int i = 0; i < 256; i++) {
            f[i] = mod(i * 7 + 3, Q);
            g[i] = mod(i * 11 + 5, Q);
        }
        int[] fHat = NTT.ntt(f);
        int[] gHat = NTT.ntt(g);

        int[] fg = NTT.multiplyNTTs(fHat, gHat);
        int[] gf = NTT.multiplyNTTs(gHat, fHat);
        assertArrayEquals(fg, gf, "NTT multiplication is not commutative");
    }

    @Test
    void testMultiplyByOne() {
        // Multiply by the NTT of (1, 0, 0, ..., 0), which in NTT domain is all 1s
        int[] one = new int[256];
        one[0] = 1;
        int[] f = new int[256];
        for (int i = 0; i < 256; i++) {
            f[i] = mod(i * 3, Q);
        }

        int[] oneHat = NTT.ntt(one);
        int[] fHat = NTT.ntt(f);
        int[] result = NTT.multiplyNTTs(fHat, oneHat);
        int[] recovered = NTT.nttInverse(result);
        assertArrayEquals(f, recovered, "Multiplication by 1 polynomial should be identity");
    }
}
