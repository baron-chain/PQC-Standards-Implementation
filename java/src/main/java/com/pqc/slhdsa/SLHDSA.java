package com.pqc.slhdsa;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) per FIPS 205.
 * Public API: keyGen, sign, verify.
 */
public final class SLHDSA {

    private SLHDSA() {}

    /**
     * Key pair: (secretKey, publicKey).
     */
    public record KeyPair(byte[] secretKey, byte[] publicKey) {}

    /**
     * slh_keygen(params): Generate an SLH-DSA key pair
     * (Algorithm 17 in FIPS 205).
     */
    public static KeyPair keyGen(SlhParams params) {
        return keyGen(params, new SecureRandom());
    }

    /**
     * slh_keygen with explicit random source (for testing).
     */
    public static KeyPair keyGen(SlhParams params, SecureRandom random) {
        int n = params.n;
        SlhHash hash = SlhHash.create(params);

        byte[] skSeed = new byte[n];
        byte[] skPrf = new byte[n];
        byte[] pkSeed = new byte[n];
        random.nextBytes(skSeed);
        random.nextBytes(skPrf);
        random.nextBytes(pkSeed);

        Address adrs = new Address();
        adrs.setLayerAddress(params.d - 1);
        adrs.setTreeAddress(0);

        byte[] pkRoot = Xmss.node(skSeed, 0, params.hPrime, pkSeed, adrs, params, hash);

        byte[] sk = SlhUtils.concat(skSeed, skPrf, pkSeed, pkRoot);
        byte[] pk = SlhUtils.concat(pkSeed, pkRoot);

        return new KeyPair(sk, pk);
    }

    /**
     * slh_sign(M, SK, params): Generate an SLH-DSA signature
     * (Algorithm 18 in FIPS 205, hedged variant).
     */
    public static byte[] sign(byte[] msg, byte[] sk, SlhParams params) {
        return sign(msg, sk, params, new SecureRandom());
    }

    /**
     * slh_sign with explicit random source.
     */
    public static byte[] sign(byte[] msg, byte[] sk, SlhParams params, SecureRandom random) {
        int n = params.n;
        SlhHash hash = SlhHash.create(params);

        // Parse secret key
        byte[] skSeed = SlhUtils.slice(sk, 0, n);
        byte[] skPrf  = SlhUtils.slice(sk, n, n);
        byte[] pkSeed = SlhUtils.slice(sk, 2 * n, n);
        byte[] pkRoot = SlhUtils.slice(sk, 3 * n, n);

        // Generate randomizer (hedged signing)
        byte[] optRand = new byte[n];
        random.nextBytes(optRand);

        // Generate randomized message digest
        byte[] r = hash.prfMsg(skPrf, optRand, msg, n);

        // Compute message digest
        byte[] digest = hash.hMsg(r, pkSeed, pkRoot, msg, params.m);

        // Split digest into md (FORS message) and tree/leaf indices
        // md = first floor(k*a / 8) bytes
        int mdBytes = (params.k * params.a + 7) / 8;
        byte[] md = SlhUtils.slice(digest, 0, mdBytes);

        // Compute tree index and leaf index from remaining digest bytes
        int treeBits = params.h - params.hPrime;
        int leafBits = params.hPrime;
        int treeBytes = (treeBits + 7) / 8;
        int leafBytes = (leafBits + 7) / 8;

        byte[] treeIdxBytes = SlhUtils.slice(digest, mdBytes, treeBytes);
        byte[] leafIdxBytes = SlhUtils.slice(digest, mdBytes + treeBytes, leafBytes);

        long idxTree = SlhUtils.toLong(treeIdxBytes, 0, treeBytes);
        idxTree &= ((1L << treeBits) - 1); // mask to treeBits
        int idxLeaf = SlhUtils.toInt(leafIdxBytes, 0, leafBytes);
        idxLeaf &= ((1 << leafBits) - 1); // mask to leafBits

        // Generate FORS signature
        Address adrs = new Address();
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(idxTree);
        adrs.setType(Address.FORS_TREE);
        adrs.setKeyPairAddress(idxLeaf);

        byte[] sigFors = Fors.sign(md, skSeed, pkSeed, adrs, params, hash);

        // Get FORS public key for hypertree signing
        byte[] pkFors = Fors.pkFromSig(sigFors, md, pkSeed, adrs, params, hash);

        // Generate hypertree signature
        byte[] sigHt = Hypertree.sign(pkFors, skSeed, pkSeed, idxTree, idxLeaf, params, hash);

        // SIG = R || SIG_FORS || SIG_HT
        return SlhUtils.concat(r, sigFors, sigHt);
    }

    /**
     * slh_verify(M, SIG, PK, params): Verify an SLH-DSA signature
     * (Algorithm 19 in FIPS 205).
     */
    public static boolean verify(byte[] msg, byte[] sig, byte[] pk, SlhParams params) {
        int n = params.n;
        SlhHash hash = SlhHash.create(params);

        // Check signature length
        if (sig.length != params.sigSize()) {
            return false;
        }

        // Parse public key
        byte[] pkSeed = SlhUtils.slice(pk, 0, n);
        byte[] pkRoot = SlhUtils.slice(pk, n, n);

        // Parse signature: R || SIG_FORS || SIG_HT
        int offset = 0;
        byte[] r = SlhUtils.slice(sig, offset, n);
        offset += n;

        int forsSigSize = params.k * (params.a + 1) * n;
        byte[] sigFors = SlhUtils.slice(sig, offset, forsSigSize);
        offset += forsSigSize;

        byte[] sigHt = SlhUtils.slice(sig, offset, sig.length - offset);

        // Compute message digest
        byte[] digest = hash.hMsg(r, pkSeed, pkRoot, msg, params.m);

        // Split digest
        int mdBytes = (params.k * params.a + 7) / 8;
        byte[] md = SlhUtils.slice(digest, 0, mdBytes);

        int treeBits = params.h - params.hPrime;
        int leafBits = params.hPrime;
        int treeBytes = (treeBits + 7) / 8;
        int leafBytes = (leafBits + 7) / 8;

        byte[] treeIdxBytes = SlhUtils.slice(digest, mdBytes, treeBytes);
        byte[] leafIdxBytes = SlhUtils.slice(digest, mdBytes + treeBytes, leafBytes);

        long idxTree = SlhUtils.toLong(treeIdxBytes, 0, treeBytes);
        idxTree &= ((1L << treeBits) - 1);
        int idxLeaf = SlhUtils.toInt(leafIdxBytes, 0, leafBytes);
        idxLeaf &= ((1 << leafBits) - 1);

        // Compute FORS public key from signature
        Address adrs = new Address();
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(idxTree);
        adrs.setType(Address.FORS_TREE);
        adrs.setKeyPairAddress(idxLeaf);

        byte[] pkFors = Fors.pkFromSig(sigFors, md, pkSeed, adrs, params, hash);

        // Verify hypertree signature
        return Hypertree.verify(pkFors, sigHt, pkSeed, idxTree, idxLeaf, pkRoot, params, hash);
    }
}
