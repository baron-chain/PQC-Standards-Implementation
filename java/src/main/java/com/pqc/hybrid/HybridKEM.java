package com.pqc.hybrid;

import com.pqc.mlkem.MLKEM;
import com.pqc.mlkem.Params;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Arrays;

/**
 * Hybrid KEM combining classical ECDH with ML-KEM.
 *
 * <p>Ensures security holds if either the classical or post-quantum
 * component remains secure.</p>
 *
 * <p>Supported schemes:</p>
 * <ul>
 *   <li>X25519 + ML-KEM-768 (IETF standard hybrid for TLS)</li>
 *   <li>ECDH-P256 + ML-KEM-768</li>
 *   <li>X25519 + ML-KEM-1024</li>
 *   <li>ECDH-P384 + ML-KEM-1024</li>
 * </ul>
 *
 * <p>KDF: SHA3-256(ss_classical || ss_pq || label)</p>
 */
public final class HybridKEM {

    private HybridKEM() {}

    // ─── Records ─────────────────────────────────────────────────────────────

    public record HybridKeyPair(
        byte[] ek,
        byte[] dk,
        int classicalEkSize,
        int classicalDkSize
    ) {}

    public record EncapsResult(
        byte[] sharedSecret,
        byte[] ciphertext,
        int classicalCtSize
    ) {}

    // ─── Scheme definitions ──────────────────────────────────────────────────

    public enum Scheme {
        X25519_MLKEM768("X25519", Params.ML_KEM_768, "X25519-MLKEM768"),
        ECDHP256_MLKEM768("EC:secp256r1", Params.ML_KEM_768, "ECDHP256-MLKEM768"),
        X25519_MLKEM1024("X25519", Params.ML_KEM_1024, "X25519-MLKEM1024"),
        ECDHP384_MLKEM1024("EC:secp384r1", Params.ML_KEM_1024, "ECDHP384-MLKEM1024");

        public final String classicalAlgorithm;
        public final Params mlkemParams;
        public final byte[] label;

        Scheme(String classicalAlgorithm, Params mlkemParams, String label) {
            this.classicalAlgorithm = classicalAlgorithm;
            this.mlkemParams = mlkemParams;
            this.label = label.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }
    }

    // ─── SHA3-256 combiner ───────────────────────────────────────────────────

    private static byte[] combineSecrets(byte[] ssClassical, byte[] ssPQ, byte[] label) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA3-256");
            md.update(ssClassical);
            md.update(ssPQ);
            md.update(label);
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA3-256 not available", e);
        }
    }

    // ─── X25519 helpers ──────────────────────────────────────────────────────

    private static KeyPair x25519KeyGen() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
            return kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("X25519 not available (requires Java 11+)", e);
        }
    }

    private static byte[] x25519GetPublicBytes(PublicKey pk) {
        // X25519 public key in X.509 DER: last 32 bytes
        byte[] encoded = pk.getEncoded();
        return Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
    }

    private static byte[] x25519GetPrivateBytes(PrivateKey sk) {
        // PKCS#8 encoded: last 32 bytes
        byte[] encoded = sk.getEncoded();
        return Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
    }

    private static PublicKey x25519PublicFromBytes(byte[] raw) {
        try {
            // Build X.509 SubjectPublicKeyInfo DER for X25519
            byte[] prefix = new byte[] {
                0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e,
                0x03, 0x21, 0x00
            };
            byte[] spki = new byte[prefix.length + 32];
            System.arraycopy(prefix, 0, spki, 0, prefix.length);
            System.arraycopy(raw, 0, spki, prefix.length, 32);
            KeyFactory kf = KeyFactory.getInstance("X25519");
            return kf.generatePublic(new X509EncodedKeySpec(spki));
        } catch (Exception e) {
            throw new RuntimeException("Failed to reconstruct X25519 public key", e);
        }
    }

    private static PrivateKey x25519PrivateFromBytes(byte[] raw) {
        try {
            // Build PKCS#8 DER for X25519
            byte[] prefix = new byte[] {
                0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03,
                0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20
            };
            byte[] pkcs8 = new byte[prefix.length + 32];
            System.arraycopy(prefix, 0, pkcs8, 0, prefix.length);
            System.arraycopy(raw, 0, pkcs8, prefix.length, 32);
            KeyFactory kf = KeyFactory.getInstance("X25519");
            return kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        } catch (Exception e) {
            throw new RuntimeException("Failed to reconstruct X25519 private key", e);
        }
    }

    private static byte[] x25519DH(PrivateKey sk, PublicKey pk) {
        try {
            KeyAgreement ka = KeyAgreement.getInstance("X25519");
            ka.init(sk);
            ka.doPhase(pk, true);
            return ka.generateSecret();
        } catch (Exception e) {
            throw new RuntimeException("X25519 DH failed", e);
        }
    }

    // ─── NIST curve ECDH helpers ─────────────────────────────────────────────

    private static KeyPair ecKeyGen(String curveName) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec(curveName));
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("EC keygen failed for " + curveName, e);
        }
    }

    private static byte[] ecGetPublicBytes(PublicKey pk) {
        ECPublicKey ecPk = (ECPublicKey) pk;
        ECPoint w = ecPk.getW();
        int fieldSize = (ecPk.getParams().getCurve().getField().getFieldSize() + 7) / 8;
        // Uncompressed point: 0x04 || x || y
        byte[] result = new byte[1 + 2 * fieldSize];
        result[0] = 0x04;
        byte[] x = w.getAffineX().toByteArray();
        byte[] y = w.getAffineY().toByteArray();
        // Copy x (pad/trim to fieldSize)
        copyFixedLength(x, result, 1, fieldSize);
        // Copy y
        copyFixedLength(y, result, 1 + fieldSize, fieldSize);
        return result;
    }

    private static void copyFixedLength(byte[] src, byte[] dst, int dstOff, int len) {
        if (src.length >= len) {
            System.arraycopy(src, src.length - len, dst, dstOff, len);
        } else {
            System.arraycopy(src, 0, dst, dstOff + len - src.length, src.length);
        }
    }

    private static byte[] ecGetPrivateBytes(PrivateKey sk) {
        ECPrivateKey ecSk = (ECPrivateKey) sk;
        int fieldSize = (ecSk.getParams().getCurve().getField().getFieldSize() + 7) / 8;
        byte[] s = ecSk.getS().toByteArray();
        byte[] result = new byte[fieldSize];
        copyFixedLength(s, result, 0, fieldSize);
        return result;
    }

    private static PublicKey ecPublicFromBytes(byte[] raw, String curveName) {
        try {
            KeyFactory kf = KeyFactory.getInstance("EC");
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec(curveName));
            ECParameterSpec ecSpec = params.getParameterSpec(ECParameterSpec.class);

            int fieldSize = (ecSpec.getCurve().getField().getFieldSize() + 7) / 8;
            // Parse uncompressed point: 0x04 || x || y
            byte[] xBytes = Arrays.copyOfRange(raw, 1, 1 + fieldSize);
            byte[] yBytes = Arrays.copyOfRange(raw, 1 + fieldSize, 1 + 2 * fieldSize);
            ECPoint w = new ECPoint(
                new java.math.BigInteger(1, xBytes),
                new java.math.BigInteger(1, yBytes)
            );
            return kf.generatePublic(new ECPublicKeySpec(w, ecSpec));
        } catch (Exception e) {
            throw new RuntimeException("Failed to reconstruct EC public key", e);
        }
    }

    private static PrivateKey ecPrivateFromBytes(byte[] raw, String curveName) {
        try {
            KeyFactory kf = KeyFactory.getInstance("EC");
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec(curveName));
            ECParameterSpec ecSpec = params.getParameterSpec(ECParameterSpec.class);

            java.math.BigInteger s = new java.math.BigInteger(1, raw);
            return kf.generatePrivate(new ECPrivateKeySpec(s, ecSpec));
        } catch (Exception e) {
            throw new RuntimeException("Failed to reconstruct EC private key", e);
        }
    }

    private static byte[] ecDH(PrivateKey sk, PublicKey pk) {
        try {
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(sk);
            ka.doPhase(pk, true);
            return ka.generateSecret();
        } catch (Exception e) {
            throw new RuntimeException("ECDH failed", e);
        }
    }

    // ─── Generic classical helpers ───────────────────────────────────────────

    private static String getCurveName(String algorithm) {
        return algorithm.substring("EC:".length());
    }

    private static boolean isX25519(String algorithm) {
        return algorithm.equals("X25519");
    }

    // ─── Public API ──────────────────────────────────────────────────────────

    /**
     * Generate a hybrid key pair.
     */
    public static HybridKeyPair keyGen(Scheme scheme) {
        byte[] classicalPk, classicalSk;

        if (isX25519(scheme.classicalAlgorithm)) {
            KeyPair kp = x25519KeyGen();
            classicalPk = x25519GetPublicBytes(kp.getPublic());
            classicalSk = x25519GetPrivateBytes(kp.getPrivate());
        } else {
            String curveName = getCurveName(scheme.classicalAlgorithm);
            KeyPair kp = ecKeyGen(curveName);
            classicalPk = ecGetPublicBytes(kp.getPublic());
            classicalSk = ecGetPrivateBytes(kp.getPrivate());
        }

        MLKEM.KeyPair pqKp = MLKEM.keyGen(scheme.mlkemParams);

        byte[] ek = new byte[classicalPk.length + pqKp.ek().length];
        System.arraycopy(classicalPk, 0, ek, 0, classicalPk.length);
        System.arraycopy(pqKp.ek(), 0, ek, classicalPk.length, pqKp.ek().length);

        byte[] dk = new byte[classicalSk.length + pqKp.dk().length];
        System.arraycopy(classicalSk, 0, dk, 0, classicalSk.length);
        System.arraycopy(pqKp.dk(), 0, dk, classicalSk.length, pqKp.dk().length);

        return new HybridKeyPair(ek, dk, classicalPk.length, classicalSk.length);
    }

    /**
     * Encapsulate using the hybrid scheme.
     */
    public static EncapsResult encaps(Scheme scheme, byte[] ek, int classicalEkSize) {
        byte[] classicalPk = Arrays.copyOfRange(ek, 0, classicalEkSize);
        byte[] pqEk = Arrays.copyOfRange(ek, classicalEkSize, ek.length);

        byte[] ssClassical, ctClassical;

        if (isX25519(scheme.classicalAlgorithm)) {
            KeyPair ephKp = x25519KeyGen();
            PublicKey peerPk = x25519PublicFromBytes(classicalPk);
            ssClassical = x25519DH(ephKp.getPrivate(), peerPk);
            ctClassical = x25519GetPublicBytes(ephKp.getPublic());
        } else {
            String curveName = getCurveName(scheme.classicalAlgorithm);
            KeyPair ephKp = ecKeyGen(curveName);
            PublicKey peerPk = ecPublicFromBytes(classicalPk, curveName);
            ssClassical = ecDH(ephKp.getPrivate(), peerPk);
            ctClassical = ecGetPublicBytes(ephKp.getPublic());
        }

        MLKEM.EncapsResult pqResult = MLKEM.encaps(pqEk, scheme.mlkemParams);

        byte[] combinedSS = combineSecrets(ssClassical, pqResult.sharedSecret(), scheme.label);

        byte[] ct = new byte[ctClassical.length + pqResult.ciphertext().length];
        System.arraycopy(ctClassical, 0, ct, 0, ctClassical.length);
        System.arraycopy(pqResult.ciphertext(), 0, ct, ctClassical.length, pqResult.ciphertext().length);

        return new EncapsResult(combinedSS, ct, ctClassical.length);
    }

    /**
     * Decapsulate using the hybrid scheme.
     */
    public static byte[] decaps(Scheme scheme, byte[] dk, byte[] ct,
                                int classicalDkSize, int classicalCtSize) {
        byte[] classicalSk = Arrays.copyOfRange(dk, 0, classicalDkSize);
        byte[] pqDk = Arrays.copyOfRange(dk, classicalDkSize, dk.length);

        byte[] ctClassical = Arrays.copyOfRange(ct, 0, classicalCtSize);
        byte[] ctPQ = Arrays.copyOfRange(ct, classicalCtSize, ct.length);

        byte[] ssClassical;

        if (isX25519(scheme.classicalAlgorithm)) {
            PrivateKey sk = x25519PrivateFromBytes(classicalSk);
            PublicKey ephPk = x25519PublicFromBytes(ctClassical);
            ssClassical = x25519DH(sk, ephPk);
        } else {
            String curveName = getCurveName(scheme.classicalAlgorithm);
            PrivateKey sk = ecPrivateFromBytes(classicalSk, curveName);
            PublicKey ephPk = ecPublicFromBytes(ctClassical, curveName);
            ssClassical = ecDH(sk, ephPk);
        }

        byte[] ssPQ = MLKEM.decaps(pqDk, ctPQ, scheme.mlkemParams);

        return combineSecrets(ssClassical, ssPQ, scheme.label);
    }
}
