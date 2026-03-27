package com.pqc.slhdsa;

/**
 * Utility functions for SLH-DSA per FIPS 205 Section 4.1.
 */
public final class SlhUtils {

    private SlhUtils() {}

    /**
     * toInt(X, n): Converts a byte string X of length n to a non-negative integer
     * using big-endian byte order (Algorithm 1 in FIPS 205).
     */
    public static int toInt(byte[] x, int offset, int len) {
        int result = 0;
        for (int i = 0; i < len; i++) {
            result = (result << 8) | (x[offset + i] & 0xFF);
        }
        return result;
    }

    /**
     * toLong(X, n): Like toInt but for long values.
     */
    public static long toLong(byte[] x, int offset, int len) {
        long result = 0;
        for (int i = 0; i < len; i++) {
            result = (result << 8) | (x[offset + i] & 0xFF);
        }
        return result;
    }

    /**
     * toByte(x, n): Converts integer x to a byte string of length n
     * using big-endian byte order (Algorithm 2 in FIPS 205).
     */
    public static byte[] toByte(long x, int n) {
        byte[] result = new byte[n];
        for (int i = n - 1; i >= 0; i--) {
            result[i] = (byte)(x & 0xFF);
            x >>= 8;
        }
        return result;
    }

    /**
     * base_2b(X, b, out_len): Takes a byte string X and splits it into
     * out_len base-2^b integers (Algorithm 3 in FIPS 205).
     */
    public static int[] base2b(byte[] x, int b, int outLen) {
        int[] result = new int[outLen];
        int in = 0;
        int bits = 0;
        int buffer = 0;
        int mask = (1 << b) - 1;

        for (int out = 0; out < outLen; out++) {
            while (bits < b) {
                buffer = (buffer << 8) | (x[in++] & 0xFF);
                bits += 8;
            }
            bits -= b;
            result[out] = (buffer >> bits) & mask;
        }
        return result;
    }

    /**
     * Concatenate multiple byte arrays.
     */
    public static byte[] concat(byte[]... arrays) {
        int totalLen = 0;
        for (byte[] a : arrays) totalLen += a.length;
        byte[] result = new byte[totalLen];
        int offset = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, result, offset, a.length);
            offset += a.length;
        }
        return result;
    }

    /**
     * Extract a subarray.
     */
    public static byte[] slice(byte[] src, int offset, int length) {
        byte[] result = new byte[length];
        System.arraycopy(src, offset, result, 0, length);
        return result;
    }
}
