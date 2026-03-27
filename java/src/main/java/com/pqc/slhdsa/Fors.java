package com.pqc.slhdsa;

/**
 * FORS (Forest of Random Subsets) per FIPS 205 Section 8.
 */
public final class Fors {

    private Fors() {}

    /**
     * fors_SKgen(SK.seed, PK.seed, ADRS, idx): Generate a FORS private key value
     * (Algorithm 11 in FIPS 205).
     */
    public static byte[] skGen(byte[] skSeed, byte[] pkSeed, Address adrs, int idx,
                                SlhHash hash, int n) {
        Address skAdrs = new Address(adrs);
        skAdrs.setType(Address.FORS_PRF);
        skAdrs.setKeyPairAddress(adrs.getKeyPairAddress());
        skAdrs.setTreeIndex(idx);
        return hash.prf(pkSeed, skSeed, skAdrs, n);
    }

    /**
     * fors_node(SK.seed, i, z, PK.seed, ADRS): Compute the root of a
     * Merkle subtree in FORS (Algorithm 12 in FIPS 205).
     */
    public static byte[] node(byte[] skSeed, int i, int z, byte[] pkSeed, Address adrs,
                               SlhParams params, SlhHash hash) {
        int n = params.n;

        if (z == 0) {
            byte[] sk = skGen(skSeed, pkSeed, adrs, i, hash, n);
            Address leafAdrs = new Address(adrs);
            leafAdrs.setType(Address.FORS_TREE);
            leafAdrs.setKeyPairAddress(adrs.getKeyPairAddress());
            leafAdrs.setTreeHeight(0);
            leafAdrs.setTreeIndex(i);
            return hash.f(pkSeed, leafAdrs, sk, n);
        }

        byte[] lNode = node(skSeed, 2 * i, z - 1, pkSeed, adrs, params, hash);
        byte[] rNode = node(skSeed, 2 * i + 1, z - 1, pkSeed, adrs, params, hash);

        Address treeAdrs = new Address(adrs);
        treeAdrs.setType(Address.FORS_TREE);
        treeAdrs.setKeyPairAddress(adrs.getKeyPairAddress());
        treeAdrs.setTreeHeight(z);
        treeAdrs.setTreeIndex(i);

        return hash.h(pkSeed, treeAdrs, SlhUtils.concat(lNode, rNode), n);
    }

    /**
     * fors_sign(md, SK.seed, PK.seed, ADRS): Generate a FORS signature
     * (Algorithm 13 in FIPS 205).
     */
    public static byte[] sign(byte[] md, byte[] skSeed, byte[] pkSeed, Address adrs,
                               SlhParams params, SlhHash hash) {
        int n = params.n;
        int k = params.k;
        int a = params.a;

        // Split md into k a-bit unsigned integers
        int[] indices = SlhUtils.base2b(md, a, k);

        byte[] sigFors = new byte[k * (a + 1) * n];
        int offset = 0;

        for (int i = 0; i < k; i++) {
            int idx = indices[i];

            // Private key value
            byte[] sk = skGen(skSeed, pkSeed, adrs, i * (1 << a) + idx, hash, n);
            System.arraycopy(sk, 0, sigFors, offset, n);
            offset += n;

            // Authentication path
            for (int j = 0; j < a; j++) {
                int s = (idx >>> j) ^ 1;
                byte[] authNode = node(skSeed, i * (1 << (a - j)) + s, j, pkSeed, adrs, params, hash);
                System.arraycopy(authNode, 0, sigFors, offset, n);
                offset += n;
            }
        }
        return sigFors;
    }

    /**
     * fors_pkFromSig(sig_fors, md, PK.seed, ADRS): Derive the FORS public key
     * from a FORS signature (Algorithm 14 in FIPS 205).
     */
    public static byte[] pkFromSig(byte[] sigFors, byte[] md, byte[] pkSeed, Address adrs,
                                    SlhParams params, SlhHash hash) {
        int n = params.n;
        int k = params.k;
        int a = params.a;

        int[] indices = SlhUtils.base2b(md, a, k);

        byte[] roots = new byte[k * n];
        int sigOffset = 0;

        for (int i = 0; i < k; i++) {
            int idx = indices[i];

            // Retrieve sk value from signature
            byte[] sk = SlhUtils.slice(sigFors, sigOffset, n);
            sigOffset += n;

            // Compute leaf node
            Address leafAdrs = new Address(adrs);
            leafAdrs.setType(Address.FORS_TREE);
            leafAdrs.setKeyPairAddress(adrs.getKeyPairAddress());
            leafAdrs.setTreeHeight(0);
            leafAdrs.setTreeIndex(i * (1 << a) + idx);
            byte[] node0 = hash.f(pkSeed, leafAdrs, sk, n);

            // Walk authentication path
            for (int j = 0; j < a; j++) {
                byte[] authJ = SlhUtils.slice(sigFors, sigOffset, n);
                sigOffset += n;

                Address treeAdrs = new Address(adrs);
                treeAdrs.setType(Address.FORS_TREE);
                treeAdrs.setKeyPairAddress(adrs.getKeyPairAddress());
                treeAdrs.setTreeHeight(j + 1);

                if (((idx >>> j) & 1) == 0) {
                    treeAdrs.setTreeIndex(i * (1 << (a - j - 1)) + (idx >>> (j + 1)));
                    node0 = hash.h(pkSeed, treeAdrs, SlhUtils.concat(node0, authJ), n);
                } else {
                    treeAdrs.setTreeIndex(i * (1 << (a - j - 1)) + (idx >>> (j + 1)));
                    node0 = hash.h(pkSeed, treeAdrs, SlhUtils.concat(authJ, node0), n);
                }
            }
            System.arraycopy(node0, 0, roots, i * n, n);
        }

        // Compute FORS public key as T_k(PK.seed, ADRS, root_0 || ... || root_{k-1})
        Address forsPkAdrs = new Address(adrs);
        forsPkAdrs.setType(Address.FORS_ROOTS);
        forsPkAdrs.setKeyPairAddress(adrs.getKeyPairAddress());

        return hash.tl(pkSeed, forsPkAdrs, roots, n);
    }
}
