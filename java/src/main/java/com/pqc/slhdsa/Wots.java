package com.pqc.slhdsa;

/**
 * WOTS+ one-time signature scheme per FIPS 205 Section 5.
 */
public final class Wots {

    private Wots() {}

    /**
     * chain(X, i, s, PK.seed, ADRS): Apply the chaining function s times
     * starting from index i (Algorithm 4 in FIPS 205).
     */
    public static byte[] chain(byte[] x, int i, int s, byte[] pkSeed, Address adrs,
                                SlhHash hash, int n) {
        byte[] tmp = x.clone();
        for (int j = i; j < i + s; j++) {
            adrs.setHashAddress(j);
            tmp = hash.f(pkSeed, adrs, tmp, n);
        }
        return tmp;
    }

    /**
     * wots_PKgen(SK.seed, PK.seed, ADRS): Generate a WOTS+ public key
     * (Algorithm 5 in FIPS 205).
     */
    public static byte[] pkGen(byte[] skSeed, byte[] pkSeed, Address adrs,
                                SlhParams params, SlhHash hash) {
        int n = params.n;
        Address skAdrs = new Address(adrs);
        skAdrs.setType(Address.WOTS_PRF);
        skAdrs.setKeyPairAddress(adrs.getKeyPairAddress());

        Address wotsAdrs = new Address(adrs);
        wotsAdrs.setType(Address.WOTS_HASH);
        wotsAdrs.setKeyPairAddress(adrs.getKeyPairAddress());

        byte[] tmp = new byte[params.wotsLen * n];
        for (int i = 0; i < params.wotsLen; i++) {
            skAdrs.setChainAddress(i);
            byte[] sk = hash.prf(pkSeed, skSeed, skAdrs, n);
            wotsAdrs.setChainAddress(i);
            byte[] ci = chain(sk, 0, params.w - 1, pkSeed, wotsAdrs, hash, n);
            System.arraycopy(ci, 0, tmp, i * n, n);
        }

        Address wotsPkAdrs = new Address(adrs);
        wotsPkAdrs.setType(Address.WOTS_PK);
        wotsPkAdrs.setKeyPairAddress(adrs.getKeyPairAddress());

        return hash.tl(pkSeed, wotsPkAdrs, tmp, n);
    }

    /**
     * wots_sign(M, SK.seed, PK.seed, ADRS): Sign an n-byte message M
     * (Algorithm 6 in FIPS 205).
     */
    public static byte[] sign(byte[] m, byte[] skSeed, byte[] pkSeed, Address adrs,
                               SlhParams params, SlhHash hash) {
        int n = params.n;
        int w = params.w;

        // Convert message to base-w
        int[] msg = SlhUtils.base2b(m, params.lgW, params.wotsLen1);

        // Compute checksum
        int csum = 0;
        for (int i = 0; i < params.wotsLen1; i++) {
            csum += (w - 1) - msg[i];
        }
        csum <<= (8 - ((params.wotsLen2 * params.lgW) % 8)) % 8;
        int csumBytes = (params.wotsLen2 * params.lgW + 7) / 8;
        byte[] csumByteArr = SlhUtils.toByte(csum, csumBytes);
        int[] csumBaseW = SlhUtils.base2b(csumByteArr, params.lgW, params.wotsLen2);

        // Combine message and checksum digits
        int[] allMsg = new int[params.wotsLen];
        System.arraycopy(msg, 0, allMsg, 0, params.wotsLen1);
        System.arraycopy(csumBaseW, 0, allMsg, params.wotsLen1, params.wotsLen2);

        Address skAdrs = new Address(adrs);
        skAdrs.setType(Address.WOTS_PRF);
        skAdrs.setKeyPairAddress(adrs.getKeyPairAddress());

        Address wotsAdrs = new Address(adrs);
        wotsAdrs.setType(Address.WOTS_HASH);
        wotsAdrs.setKeyPairAddress(adrs.getKeyPairAddress());

        byte[] sig = new byte[params.wotsLen * n];
        for (int i = 0; i < params.wotsLen; i++) {
            skAdrs.setChainAddress(i);
            byte[] sk = hash.prf(pkSeed, skSeed, skAdrs, n);
            wotsAdrs.setChainAddress(i);
            byte[] ci = chain(sk, 0, allMsg[i], pkSeed, wotsAdrs, hash, n);
            System.arraycopy(ci, 0, sig, i * n, n);
        }
        return sig;
    }

    /**
     * wots_PKFromSig(sig, M, PK.seed, ADRS): Compute a WOTS+ public key
     * from a signature (Algorithm 7 in FIPS 205).
     */
    public static byte[] pkFromSig(byte[] sig, byte[] m, byte[] pkSeed, Address adrs,
                                    SlhParams params, SlhHash hash) {
        int n = params.n;
        int w = params.w;

        // Convert message to base-w
        int[] msg = SlhUtils.base2b(m, params.lgW, params.wotsLen1);

        // Compute checksum
        int csum = 0;
        for (int i = 0; i < params.wotsLen1; i++) {
            csum += (w - 1) - msg[i];
        }
        csum <<= (8 - ((params.wotsLen2 * params.lgW) % 8)) % 8;
        int csumBytes = (params.wotsLen2 * params.lgW + 7) / 8;
        byte[] csumByteArr = SlhUtils.toByte(csum, csumBytes);
        int[] csumBaseW = SlhUtils.base2b(csumByteArr, params.lgW, params.wotsLen2);

        int[] allMsg = new int[params.wotsLen];
        System.arraycopy(msg, 0, allMsg, 0, params.wotsLen1);
        System.arraycopy(csumBaseW, 0, allMsg, params.wotsLen1, params.wotsLen2);

        Address wotsAdrs = new Address(adrs);
        wotsAdrs.setType(Address.WOTS_HASH);
        wotsAdrs.setKeyPairAddress(adrs.getKeyPairAddress());

        byte[] tmp = new byte[params.wotsLen * n];
        for (int i = 0; i < params.wotsLen; i++) {
            wotsAdrs.setChainAddress(i);
            byte[] si = SlhUtils.slice(sig, i * n, n);
            byte[] ci = chain(si, allMsg[i], w - 1 - allMsg[i], pkSeed, wotsAdrs, hash, n);
            System.arraycopy(ci, 0, tmp, i * n, n);
        }

        Address wotsPkAdrs = new Address(adrs);
        wotsPkAdrs.setType(Address.WOTS_PK);
        wotsPkAdrs.setKeyPairAddress(adrs.getKeyPairAddress());

        return hash.tl(pkSeed, wotsPkAdrs, tmp, n);
    }
}
