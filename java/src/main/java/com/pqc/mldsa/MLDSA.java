package com.pqc.mldsa;

import com.pqc.common.Keccak;

import java.security.SecureRandom;
import java.util.Arrays;

import static com.pqc.mldsa.DsaField.*;
import static com.pqc.mldsa.DsaNTT.*;
import static com.pqc.mldsa.Decompose.*;
import static com.pqc.mldsa.DsaEncode.*;
import static com.pqc.mldsa.DsaHash.*;

/**
 * ML-DSA public API (FIPS 204).
 * Implements KeyGen, Sign, and Verify.
 */
public final class MLDSA {

    private MLDSA() {}

    public record KeyPair(byte[] pk, byte[] sk) {}

    // ========================================================================
    // KeyGen (FIPS 204 Algorithm 1)
    // ========================================================================

    public static KeyPair keyGen(DsaParams params) {
        SecureRandom rng = new SecureRandom();
        byte[] xi = new byte[32]; // random seed
        rng.nextBytes(xi);
        return keyGenInternal(xi, params);
    }

    /**
     * Deterministic key generation from seed (for testing).
     */
    public static KeyPair keyGenInternal(byte[] xi, DsaParams params) {
        int k = params.k;
        int l = params.l;

        // H(xi || k || l) -> rho, rhoPrime, K
        // FIPS 204: (rho, rho', K) = H(xi, 128) where H = SHAKE-256
        // Actually: expand xi with SHAKE-256 to get rho(32), rhoPrime(64), K(32)
        byte[] expanded = Keccak.shake256(xi, 128);
        byte[] rho = Arrays.copyOfRange(expanded, 0, 32);
        byte[] rhoPrime = Arrays.copyOfRange(expanded, 32, 96);
        byte[] K = Arrays.copyOfRange(expanded, 96, 128);

        // Generate matrix A (in NTT domain)
        int[][] aHat = expandA(rho, k, l);

        // Generate secret vectors s1, s2
        int[][] sAll = expandS(rhoPrime, k, l, params.eta);
        int[][] s1 = new int[l][];
        int[][] s2 = new int[k][];
        for (int i = 0; i < l; i++) s1[i] = sAll[i];
        for (int i = 0; i < k; i++) s2[i] = sAll[l + i];

        // NTT(s1)
        int[][] s1Hat = new int[l][];
        for (int i = 0; i < l; i++) {
            s1Hat[i] = ntt(s1[i]);
        }

        // t = A * s1 + s2
        int[][] t = new int[k][];
        for (int i = 0; i < k; i++) {
            int[] ti = new int[256]; // accumulator in NTT domain
            for (int j = 0; j < l; j++) {
                int[] product = pointwiseMul(aHat[i * l + j], s1Hat[j]);
                for (int c = 0; c < 256; c++) {
                    ti[c] = fieldAdd(ti[c], product[c]);
                }
            }
            ti = nttInverse(ti);
            // Add s2[i]
            t[i] = new int[256];
            for (int c = 0; c < 256; c++) {
                t[i][c] = fieldAdd(ti[c], s2[i][c]);
            }
        }

        // Power2Round: t -> (t1, t0)
        int[][] t1 = new int[k][256];
        int[][] t0 = new int[k][256];
        for (int i = 0; i < k; i++) {
            for (int j = 0; j < 256; j++) {
                int[] parts = power2Round(t[i][j]);
                t1[i][j] = parts[0];
                t0[i][j] = modQ(parts[1]);
            }
        }

        // Encode public key
        byte[] pk = encodePK(rho, t1, k);

        // tr = H(pk) = SHAKE-256(pk, 64)
        byte[] tr = Keccak.shake256(pk, 64);

        // Encode secret key
        byte[] sk = encodeSK(rho, K, tr, s1, s2, t0, params);

        return new KeyPair(pk, sk);
    }

    // ========================================================================
    // Sign (FIPS 204 Algorithm 2)
    // ========================================================================

    public static byte[] sign(byte[] sk, byte[] msg, DsaParams params) {
        // Decode secret key
        Object[] skParts = decodeSK(sk, params);
        byte[] rho = (byte[]) skParts[0];
        byte[] K = (byte[]) skParts[1];
        byte[] tr = (byte[]) skParts[2];
        int[][] s1 = (int[][]) skParts[3];
        int[][] s2 = (int[][]) skParts[4];
        int[][] t0 = (int[][]) skParts[5];

        int k = params.k;
        int l = params.l;

        // NTT of secret vectors
        int[][] s1Hat = new int[l][];
        for (int i = 0; i < l; i++) s1Hat[i] = ntt(s1[i]);
        int[][] s2Hat = new int[k][];
        for (int i = 0; i < k; i++) s2Hat[i] = ntt(s2[i]);
        int[][] t0Hat = new int[k][];
        for (int i = 0; i < k; i++) t0Hat[i] = ntt(t0[i]);

        // Expand A
        int[][] aHat = expandA(rho, k, l);

        // mu = H(tr || msg, 64) = SHAKE-256(tr || msg, 64)
        byte[] trMsg = concat(tr, msg);
        byte[] mu = Keccak.shake256(trMsg, 64);

        // rho'' = H(K || mu, 64) - for deterministic signing (no rnd)
        byte[] rhoPrimePrime = Keccak.shake256(concat(K, mu), 64);

        int kappa = 0;
        while (true) {
            // y = ExpandMask(rho'', kappa)
            int[][] y = expandMask(rhoPrimePrime, kappa, l, params.gamma1);

            // w = A * NTT(y)
            int[][] yHat = new int[l][];
            for (int i = 0; i < l; i++) yHat[i] = ntt(y[i]);

            int[][] w = new int[k][];
            for (int i = 0; i < k; i++) {
                int[] wi = new int[256];
                for (int j = 0; j < l; j++) {
                    int[] product = pointwiseMul(aHat[i * l + j], yHat[j]);
                    for (int c = 0; c < 256; c++) {
                        wi[c] = fieldAdd(wi[c], product[c]);
                    }
                }
                w[i] = nttInverse(wi);
            }

            // Decompose w into (w1, w0) where w1 = HighBits, w0 = LowBits
            int[][] w1 = new int[k][256];
            int[][] w0 = new int[k][256];
            for (int i = 0; i < k; i++) {
                for (int j = 0; j < 256; j++) {
                    int[] parts = decompose(w[i][j], params.gamma2);
                    w1[i][j] = parts[0];
                    w0[i][j] = parts[1];
                }
            }

            // c_tilde = H(mu || w1Encode, lambda/4)
            byte[] w1Encoded = encodeW1(w1, k, params.gamma2);
            byte[] hashInput = concat(mu, w1Encoded);
            int cTildeLen = params.lambda / 4;
            byte[] cTilde = Keccak.shake256(hashInput, cTildeLen);

            // c = SampleInBall(c_tilde)
            int[] cPoly = sampleInBall(cTilde, params.tau);
            int[] cHat = ntt(cPoly);

            // z = y + c * s1
            int[][] z = new int[l][];
            for (int i = 0; i < l; i++) {
                int[] cs1 = nttInverse(pointwiseMul(cHat, s1Hat[i]));
                z[i] = new int[256];
                for (int j = 0; j < 256; j++) {
                    z[i][j] = fieldAdd(y[i][j], cs1[j]);
                }
            }

            // Check z norm: ||z||_inf < gamma1 - beta
            if (polyVecNormExceeds(z, l, params.gamma1 - params.beta)) {
                kappa += l;
                continue;
            }

            // Compute cs2 and modify w0
            int[][] cs2 = new int[k][];
            for (int i = 0; i < k; i++) {
                cs2[i] = nttInverse(pointwiseMul(cHat, s2Hat[i]));
            }

            // w0 = w0 - cs2 (modify low bits)
            boolean reject = false;
            for (int i = 0; i < k; i++) {
                for (int j = 0; j < 256; j++) {
                    w0[i][j] = toSigned(fieldSub(w0[i][j] < 0 ? modQ(w0[i][j]) : w0[i][j], cs2[i][j]));
                }
            }

            // Check |w0 - cs2| < gamma2 - beta
            for (int i = 0; i < k; i++) {
                for (int j = 0; j < 256; j++) {
                    if (w0[i][j] >= params.gamma2 - params.beta || w0[i][j] <= -(params.gamma2 - params.beta)) {
                        reject = true;
                        break;
                    }
                }
                if (reject) break;
            }
            if (reject) {
                kappa += l;
                continue;
            }

            // Compute ct0
            int[][] ct0 = new int[k][];
            for (int i = 0; i < k; i++) {
                ct0[i] = nttInverse(pointwiseMul(cHat, t0Hat[i]));
            }

            // Check ct0 norm
            if (polyVecNormExceeds(ct0, k, params.gamma2)) {
                kappa += l;
                continue;
            }

            // w0 = w0 + ct0 (add ct0 to modified low bits)
            for (int i = 0; i < k; i++) {
                for (int j = 0; j < 256; j++) {
                    w0[i][j] = w0[i][j] + toSigned(ct0[i][j]);
                }
            }

            // Make hints: make_hint(w0, w1) per reference implementation
            int[][] hints = new int[k][256];
            int hintCount = 0;
            for (int i = 0; i < k; i++) {
                for (int j = 0; j < 256; j++) {
                    hints[i][j] = makeHint(w0[i][j], w1[i][j], params.gamma2);
                    hintCount += hints[i][j];
                }
            }

            if (hintCount > params.omega) {
                kappa += l;
                continue;
            }

            // Success - encode signature
            return encodeSig(cTilde, z, hints, params);
        }
    }

    // ========================================================================
    // Verify (FIPS 204 Algorithm 3)
    // ========================================================================

    public static boolean verify(byte[] pk, byte[] msg, byte[] sig, DsaParams params) {
        if (sig.length != params.sigSize) return false;
        if (pk.length != params.pkSize) return false;

        int k = params.k;
        int l = params.l;

        // Decode public key
        Object[] pkParts = decodePK(pk, k);
        byte[] rho = (byte[]) pkParts[0];
        int[][] t1 = (int[][]) pkParts[1];

        // Decode signature
        Object[] sigParts = decodeSig(sig, params);
        byte[] cTilde = (byte[]) sigParts[0];
        int[][] z = (int[][]) sigParts[1];
        int[][] h = (int[][]) sigParts[2];

        // Check z norm
        if (polyVecNormExceeds(z, l, params.gamma1 - params.beta)) {
            return false;
        }

        // Check hint count
        int hintCount = 0;
        for (int i = 0; i < k; i++) {
            for (int j = 0; j < 256; j++) {
                hintCount += h[i][j];
            }
        }
        if (hintCount > params.omega) return false;

        // Expand A
        int[][] aHat = expandA(rho, k, l);

        // tr = H(pk)
        byte[] tr = Keccak.shake256(pk, 64);
        byte[] mu = Keccak.shake256(concat(tr, msg), 64);

        // c = SampleInBall(cTilde)
        int[] cPoly = sampleInBall(cTilde, params.tau);
        int[] cHat = ntt(cPoly);

        // NTT(z)
        int[][] zHat = new int[l][];
        for (int i = 0; i < l; i++) zHat[i] = ntt(z[i]);

        // w'_approx = A*z - c*t1*2^d (all in NTT domain)
        // t1 * 2^d in NTT: ntt(t1[i] << 13)
        int[][] w1Prime = new int[k][256];
        for (int i = 0; i < k; i++) {
            // A[i]*z
            int[] azHat = new int[256];
            for (int j = 0; j < l; j++) {
                int[] product = pointwiseMul(aHat[i * l + j], zHat[j]);
                for (int c = 0; c < 256; c++) {
                    azHat[c] = fieldAdd(azHat[c], product[c]);
                }
            }

            // c * t1[i] * 2^d in NTT
            int[] t1Scaled = new int[256];
            for (int j = 0; j < 256; j++) {
                t1Scaled[j] = fieldMul(t1[i][j], 1 << 13);
            }
            int[] t1ScaledHat = ntt(t1Scaled);
            int[] ct1Hat = pointwiseMul(cHat, t1ScaledHat);

            // w_approx = A*z - c*t1*2^d
            int[] wApprox = new int[256];
            for (int c = 0; c < 256; c++) {
                wApprox[c] = fieldSub(azHat[c], ct1Hat[c]);
            }
            int[] wApproxTime = nttInverse(wApprox);

            // UseHint to recover w1
            for (int j = 0; j < 256; j++) {
                w1Prime[i][j] = useHint(h[i][j], wApproxTime[j], params.gamma2);
            }
        }

        // Recompute c_tilde
        byte[] w1Encoded = encodeW1(w1Prime, k, params.gamma2);
        byte[] hashInput = concat(mu, w1Encoded);
        int cTildeLen = params.lambda / 4;
        byte[] cTildeCheck = Keccak.shake256(hashInput, cTildeLen);

        return Arrays.equals(cTilde, cTildeCheck);
    }

    // ========================================================================
    // Utility functions
    // ========================================================================

    /**
     * Check if any coefficient in the polynomial vector exceeds the bound.
     */
    private static boolean polyVecNormExceeds(int[][] v, int len, int bound) {
        for (int i = 0; i < len; i++) {
            for (int j = 0; j < 256; j++) {
                int val = toSigned(v[i][j]);
                if (val <= -bound || val >= bound) {
                    return true;
                }
            }
        }
        return false;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}
