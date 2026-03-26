package com.pqc.mldsa;

import static com.pqc.mldsa.DsaField.*;

/**
 * Number Theoretic Transform for ML-DSA (FIPS 204).
 * Works over Z_q with q = 8380417, primitive 512th root of unity zeta = 1753.
 */
public final class DsaNTT {

    private DsaNTT() {}

    /**
     * Bit-reverse an 8-bit integer.
     */
    public static int bitRev8(int n) {
        int r = 0;
        for (int i = 0; i < 8; i++) {
            r = (r << 1) | (n & 1);
            n >>= 1;
        }
        return r;
    }

    /**
     * Precomputed zetas: ZETAS[i] = 1753^(bitRev8(i)) mod Q for i in [0, 256).
     */
    public static final int[] ZETAS = new int[256];

    static {
        for (int i = 0; i < 256; i++) {
            ZETAS[i] = fieldPow(1753, bitRev8(i));
        }
    }

    /**
     * NTT (in-place Number Theoretic Transform).
     * Input/output: polynomial with 256 coefficients in Z_q.
     */
    public static int[] ntt(int[] f) {
        int[] fHat = f.clone();
        int k = 1;
        for (int len = 128; len >= 1; len /= 2) {
            for (int start = 0; start < 256; start += 2 * len) {
                int zeta = ZETAS[k++];
                for (int j = start; j < start + len; j++) {
                    long t = ((long)zeta * fHat[j + len]) % Q;
                    if (t < 0) t += Q;
                    int ti = (int) t;
                    fHat[j + len] = fieldSub(fHat[j], ti);
                    fHat[j] = fieldAdd(fHat[j], ti);
                }
            }
        }
        return fHat;
    }

    /**
     * NTT Inverse.
     */
    public static int[] nttInverse(int[] fHat) {
        int[] f = fHat.clone();
        int k = 255;
        for (int len = 1; len <= 128; len *= 2) {
            for (int start = 0; start < 256; start += 2 * len) {
                int zeta = ZETAS[k--];
                for (int j = start; j < start + len; j++) {
                    int t = f[j];
                    f[j] = fieldAdd(t, f[j + len]);
                    long diff = ((long)f[j + len] - t + Q) % Q;
                    f[j + len] = modQ(diff * zeta);
                }
            }
        }
        // Multiply by n^{-1} mod q = 256^{-1} mod q
        int nInv = fieldInv(256);
        for (int i = 0; i < 256; i++) {
            f[i] = fieldMul(f[i], nInv);
        }
        return f;
    }

    /**
     * Pointwise multiplication of two NTT-domain polynomials.
     */
    public static int[] pointwiseMul(int[] a, int[] b) {
        int[] c = new int[256];
        for (int i = 0; i < 256; i++) {
            c[i] = fieldMul(a[i], b[i]);
        }
        return c;
    }
}
