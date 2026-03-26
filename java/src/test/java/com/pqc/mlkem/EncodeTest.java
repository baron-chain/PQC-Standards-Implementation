package com.pqc.mlkem;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class EncodeTest {

    @Test
    void testRoundTripD1() {
        int[] f = new int[256];
        for (int i = 0; i < 256; i++) {
            f[i] = i % 2;
        }
        byte[] encoded = Encode.byteEncode(1, f);
        int[] decoded = Encode.byteDecode(1, encoded);
        assertArrayEquals(f, decoded);
    }

    @Test
    void testRoundTripD4() {
        int[] f = new int[256];
        for (int i = 0; i < 256; i++) {
            f[i] = i % 16;
        }
        byte[] encoded = Encode.byteEncode(4, f);
        int[] decoded = Encode.byteDecode(4, encoded);
        assertArrayEquals(f, decoded);
    }

    @Test
    void testRoundTripD10() {
        int[] f = new int[256];
        for (int i = 0; i < 256; i++) {
            f[i] = i % 1024;
        }
        byte[] encoded = Encode.byteEncode(10, f);
        int[] decoded = Encode.byteDecode(10, encoded);
        assertArrayEquals(f, decoded);
    }

    @Test
    void testRoundTripD12() {
        int[] f = new int[256];
        for (int i = 0; i < 256; i++) {
            f[i] = i % Field.Q;  // values in [0, Q)
        }
        byte[] encoded = Encode.byteEncode(12, f);
        int[] decoded = Encode.byteDecode(12, encoded);
        assertArrayEquals(f, decoded);
    }

    @Test
    void testEncodeDecodeLength() {
        for (int d : new int[]{1, 4, 10, 12}) {
            int[] f = new int[256];
            byte[] encoded = Encode.byteEncode(d, f);
            assertEquals(32 * d, encoded.length, "Encoded length for d=" + d);
        }
    }
}
