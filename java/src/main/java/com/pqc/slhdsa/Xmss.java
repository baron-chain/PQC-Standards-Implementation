package com.pqc.slhdsa;

/**
 * XMSS tree operations per FIPS 205 Section 6.
 */
public final class Xmss {

    private Xmss() {}

    /**
     * xmss_node(SK.seed, i, z, PK.seed, ADRS): Compute the root of a
     * Merkle subtree of height z with leftmost leaf index i
     * (Algorithm 8 in FIPS 205).
     */
    public static byte[] node(byte[] skSeed, int i, int z, byte[] pkSeed, Address adrs,
                               SlhParams params, SlhHash hash) {
        int n = params.n;
        if (z == 0) {
            adrs.setType(Address.WOTS_HASH);
            adrs.setKeyPairAddress(i);
            return Wots.pkGen(skSeed, pkSeed, adrs, params, hash);
        }

        byte[] lNode = node(skSeed, 2 * i, z - 1, pkSeed, adrs, params, hash);
        byte[] rNode = node(skSeed, 2 * i + 1, z - 1, pkSeed, adrs, params, hash);

        adrs.setType(Address.TREE);
        adrs.setTreeHeight(z);
        adrs.setTreeIndex(i);

        return hash.h(pkSeed, adrs, SlhUtils.concat(lNode, rNode), n);
    }

    /**
     * xmss_sign(M, SK.seed, idx, PK.seed, ADRS): Generate an XMSS signature
     * (Algorithm 9 in FIPS 205).
     * Returns WOTS+ signature || auth path.
     */
    public static byte[] sign(byte[] m, byte[] skSeed, int idx, byte[] pkSeed, Address adrs,
                               SlhParams params, SlhHash hash) {
        int n = params.n;
        int hPrime = params.hPrime;

        // Generate authentication path
        byte[] auth = new byte[hPrime * n];
        for (int j = 0; j < hPrime; j++) {
            int k = (idx >>> j) ^ 1; // sibling index at height j
            byte[] authNode = node(skSeed, k, j, pkSeed, adrs, params, hash);
            System.arraycopy(authNode, 0, auth, j * n, n);
        }

        // Generate WOTS+ signature
        adrs.setType(Address.WOTS_HASH);
        adrs.setKeyPairAddress(idx);
        byte[] sig = Wots.sign(m, skSeed, pkSeed, adrs, params, hash);

        return SlhUtils.concat(sig, auth);
    }

    /**
     * xmss_PKFromSig(idx, sig_xmss, M, PK.seed, ADRS): Compute an XMSS
     * public key from a signature (Algorithm 10 in FIPS 205).
     */
    public static byte[] pkFromSig(int idx, byte[] sigXmss, byte[] m, byte[] pkSeed,
                                    Address adrs, SlhParams params, SlhHash hash) {
        int n = params.n;
        int hPrime = params.hPrime;

        // Parse sig_xmss = WOTS+ sig || auth path
        byte[] sigWots = SlhUtils.slice(sigXmss, 0, params.wotsLen * n);
        // Auth path starts after WOTS+ sig
        int authOffset = params.wotsLen * n;

        adrs.setType(Address.WOTS_HASH);
        adrs.setKeyPairAddress(idx);
        byte[] node0 = Wots.pkFromSig(sigWots, m, pkSeed, adrs, params, hash);

        adrs.setType(Address.TREE);

        for (int k = 0; k < hPrime; k++) {
            adrs.setTreeHeight(k + 1);
            int parentIdx = idx >>> (k + 1);
            adrs.setTreeIndex(parentIdx);
            byte[] authK = SlhUtils.slice(sigXmss, authOffset + k * n, n);

            if (((idx >>> k) & 1) == 0) {
                node0 = hash.h(pkSeed, adrs, SlhUtils.concat(node0, authK), n);
            } else {
                node0 = hash.h(pkSeed, adrs, SlhUtils.concat(authK, node0), n);
            }
        }
        return node0;
    }
}
