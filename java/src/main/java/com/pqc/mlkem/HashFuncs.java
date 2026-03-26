package com.pqc.mlkem;

import com.pqc.common.Keccak;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Hash functions for ML-KEM (FIPS 203).
 * G = SHA3-512, H = SHA3-256, J = SHAKE-256(32 bytes).
 * XOF = SHAKE-128, PRF = SHAKE-256.
 *
 * Delegates to com.pqc.common.Keccak for the sponge construction.
 */
public final class HashFuncs {

    private HashFuncs() {}

    /** SHAKE-128: XOF with 168-byte rate. */
    public static byte[] shake128(byte[] input, int outputLen) {
        return Keccak.shake128(input, outputLen);
    }

    /** SHAKE-256: XOF with 136-byte rate. */
    public static byte[] shake256(byte[] input, int outputLen) {
        return Keccak.shake256(input, outputLen);
    }

    /** G: SHA3-512. Returns [rho (32 bytes), sigma (32 bytes)]. */
    public static byte[][] G(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA3-512");
            byte[] hash = md.digest(input);
            byte[] rho = Arrays.copyOfRange(hash, 0, 32);
            byte[] sigma = Arrays.copyOfRange(hash, 32, 64);
            return new byte[][]{rho, sigma};
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA3-512 not available", e);
        }
    }

    /** H: SHA3-256. */
    public static byte[] H(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA3-256");
            return md.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA3-256 not available", e);
        }
    }

    /** J: SHAKE-256 with 32-byte output. */
    public static byte[] J(byte[] input) {
        return shake256(input, 32);
    }

    /** XOF: SHAKE-128. Input is rho || i || j; output 672 bytes. */
    public static byte[] xof(byte[] rho, int i, int j) {
        byte[] input = new byte[rho.length + 2];
        System.arraycopy(rho, 0, input, 0, rho.length);
        input[rho.length] = (byte) i;
        input[rho.length + 1] = (byte) j;
        return shake128(input, 672);
    }

    /** PRF: SHAKE-256. Input is s || b; output 'length' bytes. */
    public static byte[] prf(byte[] s, int b, int length) {
        byte[] input = new byte[s.length + 1];
        System.arraycopy(s, 0, input, 0, s.length);
        input[s.length] = (byte) b;
        return shake256(input, length);
    }
}
