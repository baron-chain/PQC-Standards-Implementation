package com.pqc.slhdsa;

/**
 * Hypertree operations per FIPS 205 Section 7.
 */
public final class Hypertree {

    private Hypertree() {}

    /**
     * ht_sign(M, SK.seed, PK.seed, idx_tree, idx_leaf):
     * Generate a hypertree signature (Algorithm 15 in FIPS 205).
     */
    public static byte[] sign(byte[] m, byte[] skSeed, byte[] pkSeed,
                               long idxTree, int idxLeaf,
                               SlhParams params, SlhHash hash) {
        int n = params.n;

        Address adrs = new Address();
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(idxTree);

        byte[] sigXmss = Xmss.sign(m, skSeed, idxLeaf, pkSeed, adrs, params, hash);
        byte[] sigHt = sigXmss;

        byte[] root = Xmss.pkFromSig(idxLeaf, sigXmss, m, pkSeed, adrs, params, hash);

        for (int j = 1; j < params.d; j++) {
            idxLeaf = (int)(idxTree & ((1L << params.hPrime) - 1));
            idxTree = idxTree >>> params.hPrime;

            adrs.setLayerAddress(j);
            adrs.setTreeAddress(idxTree);

            sigXmss = Xmss.sign(root, skSeed, idxLeaf, pkSeed, adrs, params, hash);
            sigHt = SlhUtils.concat(sigHt, sigXmss);

            if (j < params.d - 1) {
                root = Xmss.pkFromSig(idxLeaf, sigXmss, root, pkSeed, adrs, params, hash);
            }
        }
        return sigHt;
    }

    /**
     * ht_verify(M, sig_ht, PK.seed, idx_tree, idx_leaf, PK.root):
     * Verify a hypertree signature (Algorithm 16 in FIPS 205).
     */
    public static boolean verify(byte[] m, byte[] sigHt, byte[] pkSeed,
                                  long idxTree, int idxLeaf, byte[] pkRoot,
                                  SlhParams params, SlhHash hash) {
        int n = params.n;
        int xmssSigSize = (params.hPrime + params.wotsLen) * n;

        Address adrs = new Address();
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(idxTree);

        byte[] sigXmss = SlhUtils.slice(sigHt, 0, xmssSigSize);
        byte[] node = Xmss.pkFromSig(idxLeaf, sigXmss, m, pkSeed, adrs, params, hash);

        for (int j = 1; j < params.d; j++) {
            idxLeaf = (int)(idxTree & ((1L << params.hPrime) - 1));
            idxTree = idxTree >>> params.hPrime;

            adrs.setLayerAddress(j);
            adrs.setTreeAddress(idxTree);

            sigXmss = SlhUtils.slice(sigHt, j * xmssSigSize, xmssSigSize);
            node = Xmss.pkFromSig(idxLeaf, sigXmss, node, pkSeed, adrs, params, hash);
        }

        return java.util.Arrays.equals(node, pkRoot);
    }
}
