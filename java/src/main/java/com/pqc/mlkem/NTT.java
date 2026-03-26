package com.pqc.mlkem;

import static com.pqc.mlkem.Field.*;

/**
 * Number Theoretic Transform for ML-KEM (FIPS 203).
 * Algorithms 9-12.
 */
public final class NTT {

    private NTT() {}

    /**
     * Bit-reverse a 7-bit integer.
     */
    public static int bitRev7(int n) {
        int r = 0;
        for (int i = 0; i < 7; i++) {
            r = (r << 1) | (n & 1);
            n >>= 1;
        }
        return r;
    }

    /**
     * Precomputed zetas: zeta[i] = 17^(bitRev7(i)) mod Q for i in [0,128).
     */
    public static final int[] ZETAS = new int[128];

    static {
        for (int i = 0; i < 128; i++) {
            ZETAS[i] = fieldPow(17, bitRev7(i));
        }
    }

    /**
     * Algorithm 9: NTT (in-place Number Theoretic Transform).
     * Input: polynomial f with 256 coefficients.
     * Output: NTT representation fHat with 256 coefficients.
     */
    public static int[] ntt(int[] f) {
        int[] fHat = f.clone();
        int k = 1;
        for (int len = 128; len >= 2; len /= 2) {
            for (int start = 0; start < 256; start += 2 * len) {
                int zeta = ZETAS[k++];
                for (int j = start; j < start + len; j++) {
                    int t = fieldMul(zeta, fHat[j + len]);
                    fHat[j + len] = fieldSub(fHat[j], t);
                    fHat[j] = fieldAdd(fHat[j], t);
                }
            }
        }
        return fHat;
    }

    /**
     * Algorithm 10: NTT Inverse.
     * Input: NTT representation fHat with 256 coefficients.
     * Output: polynomial f with 256 coefficients.
     */
    public static int[] nttInverse(int[] fHat) {
        int[] f = fHat.clone();
        int k = 127;
        for (int len = 2; len <= 128; len *= 2) {
            for (int start = 0; start < 256; start += 2 * len) {
                int zeta = ZETAS[k--];
                for (int j = start; j < start + len; j++) {
                    int t = f[j];
                    f[j] = fieldAdd(t, f[j + len]);
                    f[j + len] = fieldMul(zeta, fieldSub(f[j + len], t));
                }
            }
        }
        // Multiply all coefficients by 3303 = 128^{-1} mod Q
        for (int i = 0; i < 256; i++) {
            f[i] = fieldMul(f[i], 3303);
        }
        return f;
    }

    /**
     * Algorithm 11: Multiplication of two NTT representations.
     */
    public static int[] multiplyNTTs(int[] fHat, int[] gHat) {
        int[] hHat = new int[256];
        for (int i = 0; i < 64; i++) {
            int gamma = ZETAS[64 + i];
            int[] ab0 = baseCaseMultiply(
                    fHat[4 * i], fHat[4 * i + 1],
                    gHat[4 * i], gHat[4 * i + 1],
                    gamma);
            hHat[4 * i] = ab0[0];
            hHat[4 * i + 1] = ab0[1];

            int[] ab1 = baseCaseMultiply(
                    fHat[4 * i + 2], fHat[4 * i + 3],
                    gHat[4 * i + 2], gHat[4 * i + 3],
                    fieldSub(0, gamma));
            hHat[4 * i + 2] = ab1[0];
            hHat[4 * i + 3] = ab1[1];
        }
        return hHat;
    }

    /**
     * Algorithm 12: Base-case multiply for degree-1 polynomials in NTT domain.
     * Returns [c0, c1] where (a0+a1*X)*(b0+b1*X) mod (X^2 - gamma).
     */
    public static int[] baseCaseMultiply(int a0, int a1, int b0, int b1, int gamma) {
        int c0 = fieldAdd(fieldMul(a0, b0), fieldMul(fieldMul(a1, b1), gamma));
        int c1 = fieldAdd(fieldMul(a0, b1), fieldMul(a1, b0));
        return new int[]{c0, c1};
    }
}
