package com.pqc.mlkem;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.pqc.mlkem.Field.Q;

class CompressTest {

    @Test
    void testCompressRange() {
        for (int d : new int[]{1, 4, 10, 11}) {
            int max = 1 << d;
            for (int x = 0; x < Q; x++) {
                int c = Compress.compress(d, x);
                assertTrue(c >= 0 && c < max,
                        "compress(" + d + ", " + x + ") = " + c + " out of range [0, " + max + ")");
            }
        }
    }

    @Test
    void testDecompressRange() {
        for (int d : new int[]{1, 4, 10, 11}) {
            int max = 1 << d;
            for (int y = 0; y < max; y++) {
                int val = Compress.decompress(d, y);
                assertTrue(val >= 0 && val < Q,
                        "decompress(" + d + ", " + y + ") = " + val + " out of range [0, Q)");
            }
        }
    }

    @Test
    void testCompressDecompressErrorBound() {
        // The error |decompress(compress(x)) - x| should be at most Q/(2^(d+1))
        for (int d : new int[]{1, 4, 10, 11}) {
            double maxError = (double) Q / (1 << (d + 1));
            for (int x = 0; x < Q; x++) {
                int c = Compress.compress(d, x);
                int dc = Compress.decompress(d, c);
                int error = Math.abs(dc - x);
                // Take minimum of error and Q - error (wrap-around)
                error = Math.min(error, Q - error);
                assertTrue(error <= maxError + 1,
                        "Error too large for d=" + d + ", x=" + x
                                + ": error=" + error + ", maxError=" + maxError);
            }
        }
    }

    @Test
    void testCompressZero() {
        for (int d : new int[]{1, 4, 10, 11}) {
            assertEquals(0, Compress.compress(d, 0));
        }
    }

    @Test
    void testPolyCompressDecompress() {
        int[] poly = new int[256];
        for (int i = 0; i < 256; i++) {
            poly[i] = i % Q;
        }
        int[] compressed = Compress.compressPoly(4, poly);
        int[] decompressed = Compress.decompressPoly(4, compressed);
        for (int i = 0; i < 256; i++) {
            assertTrue(decompressed[i] >= 0 && decompressed[i] < Q);
        }
    }
}
