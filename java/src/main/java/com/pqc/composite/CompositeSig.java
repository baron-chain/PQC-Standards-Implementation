package com.pqc.composite;

import com.pqc.mldsa.DsaParams;
import com.pqc.mldsa.MLDSA;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;

/**
 * Composite Signature Schemes — ML-DSA + Ed25519 / ECDSA-P256.
 * <p>
 * Security holds as long as either the classical or PQ component is secure.
 * <p>
 * Signature format: len(sig_classical) [4 bytes LE] || sig_classical || sig_pq
 */
public final class CompositeSig {

    private CompositeSig() {}

    // -----------------------------------------------------------------------
    // Scheme definitions
    // -----------------------------------------------------------------------

    public enum Scheme {
        MLDSA65_ED25519("Ed25519", null, DsaParams.ML_DSA_65),
        MLDSA65_ECDSA_P256("SHA256withECDSA", "secp256r1", DsaParams.ML_DSA_65),
        MLDSA87_ED25519("Ed25519", null, DsaParams.ML_DSA_87),
        MLDSA44_ED25519("Ed25519", null, DsaParams.ML_DSA_44);

        public final String classicalAlgo;
        public final String curveName; // null for Ed25519
        public final DsaParams pqParams;

        Scheme(String classicalAlgo, String curveName, DsaParams pqParams) {
            this.classicalAlgo = classicalAlgo;
            this.curveName = curveName;
            this.pqParams = pqParams;
        }

        public boolean isEd25519() {
            return "Ed25519".equals(classicalAlgo);
        }
    }

    // -----------------------------------------------------------------------
    // Key pair
    // -----------------------------------------------------------------------

    public record CompositeKeyPair(
        byte[] pk,    // pk_classical || pk_pq
        byte[] sk,    // sk_classical || sk_pq
        Scheme scheme,
        KeyPair classicalKeyPair // kept for signing with JCA
    ) {}

    // -----------------------------------------------------------------------
    // Key generation
    // -----------------------------------------------------------------------

    public static CompositeKeyPair keyGen(Scheme scheme) {
        try {
            KeyPair classicalKP = genClassical(scheme);
            byte[] classicalPK = encodeClassicalPK(scheme, classicalKP);
            byte[] classicalSK = encodeClassicalSK(scheme, classicalKP);

            MLDSA.KeyPair pqKP = MLDSA.keyGen(scheme.pqParams);

            byte[] pk = concat(classicalPK, pqKP.pk());
            byte[] sk = concat(classicalSK, pqKP.sk());

            return new CompositeKeyPair(pk, sk, scheme, classicalKP);
        } catch (Exception e) {
            throw new RuntimeException("Composite keyGen failed", e);
        }
    }

    private static KeyPair genClassical(Scheme scheme) throws Exception {
        if (scheme.isEd25519()) {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
            return kpg.generateKeyPair();
        } else {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec(scheme.curveName));
            return kpg.generateKeyPair();
        }
    }

    private static byte[] encodeClassicalPK(Scheme scheme, KeyPair kp) throws Exception {
        // Use raw encoding for consistent sizes
        if (scheme.isEd25519()) {
            // Ed25519 raw public key is 32 bytes
            return rawEd25519PK(kp.getPublic());
        } else {
            // ECDSA: X.509 encoded (variable, but we store entire encoding)
            return kp.getPublic().getEncoded();
        }
    }

    private static byte[] encodeClassicalSK(Scheme scheme, KeyPair kp) throws Exception {
        if (scheme.isEd25519()) {
            return rawEd25519SK(kp.getPrivate());
        } else {
            return kp.getPrivate().getEncoded();
        }
    }

    private static byte[] rawEd25519PK(PublicKey pk) {
        // Ed25519 public key X.509 DER: 12-byte prefix + 32-byte key
        byte[] encoded = pk.getEncoded();
        return Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
    }

    private static byte[] rawEd25519SK(PrivateKey sk) {
        // Ed25519 PKCS#8 DER: prefix + 34 bytes (04 20 + 32-byte seed)
        byte[] encoded = sk.getEncoded();
        return Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
    }

    static int classicalPKSize(Scheme scheme) {
        if (scheme.isEd25519()) return 32;
        // For ECDSA, we store the full X.509 encoded key
        // Typical P-256 X.509 DER is 91 bytes
        return -1; // variable — use stored length
    }

    // -----------------------------------------------------------------------
    // Signing
    // -----------------------------------------------------------------------

    /**
     * Sign a message with the composite scheme.
     */
    public static byte[] sign(CompositeKeyPair kp, byte[] msg) {
        try {
            byte[] sigClassical = signClassical(kp, msg);
            byte[] skPQ = extractPQSK(kp);
            byte[] sigPQ = MLDSA.sign(skPQ, msg, kp.scheme().pqParams);

            ByteBuffer buf = ByteBuffer.allocate(4 + sigClassical.length + sigPQ.length);
            buf.order(ByteOrder.LITTLE_ENDIAN);
            buf.putInt(sigClassical.length);
            buf.put(sigClassical);
            buf.put(sigPQ);
            return buf.array();
        } catch (Exception e) {
            throw new RuntimeException("Composite sign failed", e);
        }
    }

    private static byte[] signClassical(CompositeKeyPair kp, byte[] msg) throws Exception {
        Signature sig;
        if (kp.scheme().isEd25519()) {
            sig = Signature.getInstance("Ed25519");
        } else {
            sig = Signature.getInstance(kp.scheme().classicalAlgo);
        }
        sig.initSign(kp.classicalKeyPair().getPrivate());
        sig.update(msg);
        return sig.sign();
    }

    private static byte[] extractPQSK(CompositeKeyPair kp) {
        int classicalSKLen;
        if (kp.scheme().isEd25519()) {
            classicalSKLen = 32;
        } else {
            classicalSKLen = kp.classicalKeyPair().getPrivate().getEncoded().length;
        }
        return Arrays.copyOfRange(kp.sk(), classicalSKLen, kp.sk().length);
    }

    // -----------------------------------------------------------------------
    // Verification
    // -----------------------------------------------------------------------

    /**
     * Verify a composite signature. Returns true only if BOTH components verify.
     */
    public static boolean verify(Scheme scheme, byte[] pk, byte[] msg, byte[] sig) {
        try {
            if (sig.length < 4) return false;
            ByteBuffer buf = ByteBuffer.wrap(sig).order(ByteOrder.LITTLE_ENDIAN);
            int classicalSigLen = buf.getInt();
            if (sig.length < 4 + classicalSigLen) return false;

            byte[] sigClassical = Arrays.copyOfRange(sig, 4, 4 + classicalSigLen);
            byte[] sigPQ = Arrays.copyOfRange(sig, 4 + classicalSigLen, sig.length);

            int classicalPKLen;
            if (scheme.isEd25519()) {
                classicalPKLen = 32;
            } else {
                // For ECDSA, find the boundary by subtracting PQ pk size
                classicalPKLen = pk.length - scheme.pqParams.pkSize;
            }

            byte[] pkClassical = Arrays.copyOfRange(pk, 0, classicalPKLen);
            byte[] pkPQ = Arrays.copyOfRange(pk, classicalPKLen, pk.length);

            boolean classicalOK = verifyClassical(scheme, pkClassical, msg, sigClassical);
            boolean pqOK = MLDSA.verify(pkPQ, msg, sigPQ, scheme.pqParams);

            return classicalOK && pqOK;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean verifyClassical(Scheme scheme, byte[] pk, byte[] msg, byte[] sig)
            throws Exception {
        PublicKey pubKey;
        if (scheme.isEd25519()) {
            // Reconstruct Ed25519 public key from raw 32 bytes
            // X.509 DER prefix for Ed25519: 302a300506032b6570032100
            byte[] prefix = hexToBytes("302a300506032b6570032100");
            byte[] der = concat(prefix, pk);
            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            pubKey = kf.generatePublic(new X509EncodedKeySpec(der));
        } else {
            // ECDSA: pk is already X.509 DER encoded
            KeyFactory kf = KeyFactory.getInstance("EC");
            pubKey = kf.generatePublic(new X509EncodedKeySpec(pk));
        }

        Signature verifier;
        if (scheme.isEd25519()) {
            verifier = Signature.getInstance("Ed25519");
        } else {
            verifier = Signature.getInstance(scheme.classicalAlgo);
        }
        verifier.initVerify(pubKey);
        verifier.update(msg);
        return verifier.verify(sig);
    }

    // -----------------------------------------------------------------------
    // Utilities
    // -----------------------------------------------------------------------

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
