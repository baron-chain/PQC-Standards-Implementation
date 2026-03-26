package com.pqc.mldsa;

/**
 * Finite field arithmetic modulo Q = 8380417 for ML-DSA (FIPS 204).
 * Uses long intermediates to avoid overflow during multiplication.
 */
public final class DsaField {

    public static final int Q = 8380417;

    private DsaField() {}

    /**
     * Reduce a long value mod Q into [0, Q).
     */
    public static int modQ(long a) {
        int r = (int)(a % Q);
        return r < 0 ? r + Q : r;
    }

    public static int fieldAdd(int a, int b) {
        return modQ((long)a + b);
    }

    public static int fieldSub(int a, int b) {
        return modQ((long)a - b);
    }

    public static int fieldMul(int a, int b) {
        return modQ((long)a * b);
    }

    /**
     * Modular exponentiation: base^exp mod Q using repeated squaring.
     */
    public static int fieldPow(int base, int exp) {
        long result = 1;
        long b = modQ(base);
        int e = exp;
        while (e > 0) {
            if ((e & 1) == 1) {
                result = (result * b) % Q;
            }
            b = (b * b) % Q;
            e >>= 1;
        }
        return (int) result;
    }

    /**
     * Modular inverse via Fermat's little theorem: a^{-1} = a^{Q-2} mod Q.
     */
    public static int fieldInv(int a) {
        return fieldPow(a, Q - 2);
    }
}
