package com.pqc.mldsa;

import java.util.Arrays;

import static com.pqc.mldsa.DsaField.*;

/**
 * Bit packing, encoding, and decoding for ML-DSA (FIPS 204).
 */
public final class DsaEncode {

    private DsaEncode() {}

    // ========================================================================
    // Generic bit packing / unpacking
    // ========================================================================

    /**
     * Pack 256 coefficients, each with 'bits' bits, into a byte array.
     * Values are unsigned (already adjusted if needed).
     */
    public static byte[] bitPack(int[] poly, int bits) {
        byte[] out = new byte[256 * bits / 8];
        for (int i = 0; i < 256; i++) {
            int val = poly[i];
            int bitStart = i * bits;
            for (int b = 0; b < bits; b++) {
                int bitIdx = bitStart + b;
                int byteIdx = bitIdx / 8;
                int bitOff = bitIdx % 8;
                out[byteIdx] |= (byte)(((val >> b) & 1) << bitOff);
            }
        }
        return out;
    }

    /**
     * Unpack byte array into 256 coefficients of 'bits' bits each.
     */
    public static int[] bitUnpack(byte[] data, int offset, int bits) {
        int[] poly = new int[256];
        for (int i = 0; i < 256; i++) {
            int val = 0;
            int bitStart = i * bits;
            for (int b = 0; b < bits; b++) {
                int bitIdx = bitStart + b;
                int byteIdx = offset + bitIdx / 8;
                int bitOff = bitIdx % 8;
                val |= ((data[byteIdx] >> bitOff) & 1) << b;
            }
            poly[i] = val;
        }
        return poly;
    }

    // ========================================================================
    // Public key encoding: pk = rho || t1_encoded
    // t1 has coefficients in [0, 2^10 - 1] = [0, 1023], packed as 10 bits
    // ========================================================================

    public static byte[] encodePK(byte[] rho, int[][] t1, int k) {
        byte[] pk = new byte[32 + k * 320]; // 10 bits * 256 / 8 = 320 bytes per poly
        System.arraycopy(rho, 0, pk, 0, 32);
        for (int i = 0; i < k; i++) {
            byte[] packed = bitPack(t1[i], 10);
            System.arraycopy(packed, 0, pk, 32 + i * 320, 320);
        }
        return pk;
    }

    public static Object[] decodePK(byte[] pk, int k) {
        byte[] rho = Arrays.copyOfRange(pk, 0, 32);
        int[][] t1 = new int[k][];
        for (int i = 0; i < k; i++) {
            t1[i] = bitUnpack(pk, 32 + i * 320, 10);
        }
        return new Object[]{rho, t1};
    }

    // ========================================================================
    // Secret key encoding:
    // sk = rho (32) || K (32) || tr (64) || s1 || s2 || t0
    // s1/s2: coefficients in [-eta, eta] -> stored as eta - coeff for unsigned packing
    // t0: coefficients in [-(2^12), 2^12 - 1] -> stored as 2^12 - coeff for unsigned 13-bit packing
    // ========================================================================

    public static byte[] encodeSK(byte[] rho, byte[] K, byte[] tr,
                                   int[][] s1, int[][] s2, int[][] t0,
                                   DsaParams params) {
        int eta = params.eta;
        int etaBits = (eta == 2) ? 3 : 4;
        int etaPolyBytes = 256 * etaBits / 8;
        int k = params.k;
        int l = params.l;

        byte[] sk = new byte[params.skSize];
        int off = 0;

        System.arraycopy(rho, 0, sk, off, 32); off += 32;
        System.arraycopy(K, 0, sk, off, 32); off += 32;
        System.arraycopy(tr, 0, sk, off, 64); off += 64;

        // Encode s1 (l polynomials)
        for (int i = 0; i < l; i++) {
            int[] packed = new int[256];
            for (int j = 0; j < 256; j++) {
                // Map from [-eta, eta] to [0, 2*eta]: store eta - coeff
                packed[j] = eta - toSigned(s1[i][j]);
            }
            byte[] bytes = bitPack(packed, etaBits);
            System.arraycopy(bytes, 0, sk, off, etaPolyBytes);
            off += etaPolyBytes;
        }

        // Encode s2 (k polynomials)
        for (int i = 0; i < k; i++) {
            int[] packed = new int[256];
            for (int j = 0; j < 256; j++) {
                packed[j] = eta - toSigned(s2[i][j]);
            }
            byte[] bytes = bitPack(packed, etaBits);
            System.arraycopy(bytes, 0, sk, off, etaPolyBytes);
            off += etaPolyBytes;
        }

        // Encode t0 (k polynomials), 13 bits each
        // t0 coefficients in [-(2^(d-1)-1), 2^(d-1)] = [-4095, 4096]
        // Store as (1 << 12) - coeff  -> unsigned in [0, 2^13 - 1]
        for (int i = 0; i < k; i++) {
            int[] packed = new int[256];
            for (int j = 0; j < 256; j++) {
                packed[j] = (1 << 12) - toSigned(t0[i][j]);
            }
            byte[] bytes = bitPack(packed, 13);
            System.arraycopy(bytes, 0, sk, off, 416); // 256*13/8 = 416
            off += 416;
        }

        return sk;
    }

    public static Object[] decodeSK(byte[] sk, DsaParams params) {
        int eta = params.eta;
        int etaBits = (eta == 2) ? 3 : 4;
        int etaPolyBytes = 256 * etaBits / 8;
        int k = params.k;
        int l = params.l;

        int off = 0;
        byte[] rho = Arrays.copyOfRange(sk, off, off + 32); off += 32;
        byte[] K = Arrays.copyOfRange(sk, off, off + 32); off += 32;
        byte[] tr = Arrays.copyOfRange(sk, off, off + 64); off += 64;

        int[][] s1 = new int[l][];
        for (int i = 0; i < l; i++) {
            int[] raw = bitUnpack(sk, off, etaBits);
            s1[i] = new int[256];
            for (int j = 0; j < 256; j++) {
                s1[i][j] = modQ(eta - raw[j]);
            }
            off += etaPolyBytes;
        }

        int[][] s2 = new int[k][];
        for (int i = 0; i < k; i++) {
            int[] raw = bitUnpack(sk, off, etaBits);
            s2[i] = new int[256];
            for (int j = 0; j < 256; j++) {
                s2[i][j] = modQ(eta - raw[j]);
            }
            off += etaPolyBytes;
        }

        int[][] t0 = new int[k][];
        for (int i = 0; i < k; i++) {
            int[] raw = bitUnpack(sk, off, 13);
            t0[i] = new int[256];
            for (int j = 0; j < 256; j++) {
                t0[i][j] = modQ((1 << 12) - raw[j]);
            }
            off += 416;
        }

        return new Object[]{rho, K, tr, s1, s2, t0};
    }

    // ========================================================================
    // Signature encoding:
    // sig = c_tilde (lambda/4 bytes) || z (l polys, gamma1 bits each) || h (hint encoding)
    // ========================================================================

    public static byte[] encodeSig(byte[] cTilde, int[][] z, int[][] h,
                                    DsaParams params) {
        int gamma1Bits = (params.gamma1 == 131072) ? 17 : 19;
        // Correction: gamma1 is 2^17 or 2^19. Coefficients of z are in
        // [-(gamma1-1), gamma1]. We store gamma1 - coeff as unsigned value
        // needing gamma1Bits+1 bits? No - per FIPS 204, z is packed with
        // gamma1Bits + 1 bits? Let me check: for gamma1 = 2^17, max coeff is
        // gamma1-1 = 131071. Range is [-131071, 131071]. Stored as gamma1 - coeff
        // in [1, 2*gamma1-1] = [1, 262143]. That's 18 bits.
        // Actually: gamma1 - z_coeff in [gamma1 - (gamma1-1), gamma1 + (gamma1-1)] = [1, 2*gamma1-1]
        // For gamma1=2^17: [1, 2^18-1], need 18 bits.
        // For gamma1=2^19: [1, 2^20-1], need 20 bits.
        int zBits = gamma1Bits + 1; // 18 or 20 bits per coefficient
        int zPolyBytes = 256 * zBits / 8;
        int cTildeLen = params.lambda / 4; // lambda bits / 8 * 2 = lambda/4 bytes

        byte[] sig = new byte[params.sigSize];
        int off = 0;

        // c_tilde
        System.arraycopy(cTilde, 0, sig, off, cTildeLen);
        off += cTildeLen;

        // z: l polynomials
        for (int i = 0; i < params.l; i++) {
            int[] packed = new int[256];
            for (int j = 0; j < 256; j++) {
                packed[j] = params.gamma1 - toSigned(z[i][j]);
            }
            byte[] bytes = bitPack(packed, zBits);
            System.arraycopy(bytes, 0, sig, off, zPolyBytes);
            off += zPolyBytes;
        }

        // h: hint encoding using omega+k bytes
        // Format: for each polynomial i, list the indices where h[i][j]=1,
        // then store the count prefix.
        // FIPS 204: omega + k bytes for hint
        encodeHint(sig, off, h, params.k, params.omega);

        return sig;
    }

    private static void encodeHint(byte[] sig, int off, int[][] h, int k, int omega) {
        int idx = 0;
        for (int i = 0; i < k; i++) {
            for (int j = 0; j < 256; j++) {
                if (h[i][j] == 1) {
                    sig[off + idx] = (byte) j;
                    idx++;
                }
            }
            sig[off + omega + i] = (byte) idx;
        }
    }

    public static Object[] decodeSig(byte[] sig, DsaParams params) {
        int gamma1Bits = (params.gamma1 == 131072) ? 17 : 19;
        int zBits = gamma1Bits + 1;
        int zPolyBytes = 256 * zBits / 8;
        int cTildeLen = params.lambda / 4;

        int off = 0;

        byte[] cTilde = Arrays.copyOfRange(sig, off, off + cTildeLen);
        off += cTildeLen;

        int[][] z = new int[params.l][];
        for (int i = 0; i < params.l; i++) {
            int[] raw = bitUnpack(sig, off, zBits);
            z[i] = new int[256];
            for (int j = 0; j < 256; j++) {
                z[i][j] = modQ(params.gamma1 - raw[j]);
            }
            off += zPolyBytes;
        }

        int[][] h = decodeHint(sig, off, params.k, params.omega);

        return new Object[]{cTilde, z, h};
    }

    private static int[][] decodeHint(byte[] sig, int off, int k, int omega) {
        int[][] h = new int[k][256];
        int prev = 0;
        for (int i = 0; i < k; i++) {
            int limit = sig[off + omega + i] & 0xFF;
            for (int j = prev; j < limit; j++) {
                int idx = sig[off + j] & 0xFF;
                h[i][idx] = 1;
            }
            prev = limit;
        }
        return h;
    }

    // ========================================================================
    // w1 encoding: each coefficient is in [0, (q-1)/(2*gamma2) - 1]
    // For gamma2=95232: (q-1)/(2*gamma2) = 8380416/190464 = 44, needs 6 bits
    // For gamma2=261888: (q-1)/(2*gamma2) = 8380416/523776 = 16, needs 4 bits
    // ========================================================================

    public static byte[] encodeW1(int[][] w1, int k, int gamma2) {
        int w1Bits;
        if (gamma2 == 95232) {
            w1Bits = 6; // coefficients in [0, 43]
        } else {
            w1Bits = 4; // coefficients in [0, 15]
        }
        int polyBytes = 256 * w1Bits / 8;
        byte[] out = new byte[k * polyBytes];
        for (int i = 0; i < k; i++) {
            byte[] packed = bitPack(w1[i], w1Bits);
            System.arraycopy(packed, 0, out, i * polyBytes, polyBytes);
        }
        return out;
    }

    // ========================================================================
    // Utility
    // ========================================================================

    /**
     * Convert from mod-Q representation to signed value in [-(Q-1)/2, (Q-1)/2].
     */
    public static int toSigned(int a) {
        int r = ((a % Q) + Q) % Q;
        if (r > Q / 2) return r - Q;
        return r;
    }
}
