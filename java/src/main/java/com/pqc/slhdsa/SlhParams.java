package com.pqc.slhdsa;

/**
 * SLH-DSA parameter sets per FIPS 205.
 * All 12 parameter sets: {SHAKE,SHA2} x {128,192,256} x {f,s}.
 */
public enum SlhParams {

    // SHAKE-based parameter sets (FIPS 205 Table 1)
    // Constructor: (name, n, w, m_unused, hPrime, d, a, k, lgT_unused, hashFamily)
    SHAKE_128F("SLH-DSA-SHAKE-128f", 16, 16, 0,  3, 22,  6, 33, 0, HashFamily.SHAKE),
    SHAKE_128S("SLH-DSA-SHAKE-128s", 16, 16, 0,  9,  7, 12, 14, 0, HashFamily.SHAKE),
    SHAKE_192F("SLH-DSA-SHAKE-192f", 24, 16, 0,  3, 22,  8, 33, 0, HashFamily.SHAKE),
    SHAKE_192S("SLH-DSA-SHAKE-192s", 24, 16, 0,  9,  7, 14, 17, 0, HashFamily.SHAKE),
    SHAKE_256F("SLH-DSA-SHAKE-256f", 32, 16, 0,  4, 17,  9, 35, 0, HashFamily.SHAKE),
    SHAKE_256S("SLH-DSA-SHAKE-256s", 32, 16, 0,  8,  8, 14, 22, 0, HashFamily.SHAKE),

    // SHA2-based parameter sets (FIPS 205 Table 1)
    SHA2_128F("SLH-DSA-SHA2-128f", 16, 16, 0,  3, 22,  6, 33, 0, HashFamily.SHA2),
    SHA2_128S("SLH-DSA-SHA2-128s", 16, 16, 0,  9,  7, 12, 14, 0, HashFamily.SHA2),
    SHA2_192F("SLH-DSA-SHA2-192f", 24, 16, 0,  3, 22,  8, 33, 0, HashFamily.SHA2),
    SHA2_192S("SLH-DSA-SHA2-192s", 24, 16, 0,  9,  7, 14, 17, 0, HashFamily.SHA2),
    SHA2_256F("SLH-DSA-SHA2-256f", 32, 16, 0,  4, 17,  9, 35, 0, HashFamily.SHA2),
    SHA2_256S("SLH-DSA-SHA2-256s", 32, 16, 0,  8,  8, 14, 22, 0, HashFamily.SHA2);

    public enum HashFamily { SHAKE, SHA2 }

    public final String name;
    /** Security parameter (bytes): n */
    public final int n;
    /** Winternitz parameter w (always 16 for FIPS 205) */
    public final int w;
    /** FORS message length in bits: a * k */
    public final int m;
    /** Height of each XMSS tree: hPrime */
    public final int hPrime;
    /** Number of XMSS layers: d */
    public final int d;
    /** Total tree height: h = hPrime * d */
    public final int h;
    /** FORS trees: k */
    public final int k;
    /** FORS tree height: a */
    public final int a;
    /** Hash family */
    public final HashFamily hashFamily;

    /** WOTS+ chain length: w - 1 = 15 */
    public final int wotsLen1;
    /** WOTS+ checksum length */
    public final int wotsLen2;
    /** WOTS+ total length: len1 + len2 */
    public final int wotsLen;
    /** log2(w) = 4 */
    public final int lgW;

    SlhParams(String name, int n, int w, int m, int hPrime, int d, int a, int k, int lgT,
              HashFamily hashFamily) {
        // m here is unused in the enum spec; we compute from a, k
        this.name = name;
        this.n = n;
        this.w = w;
        this.hPrime = hPrime;
        this.d = d;
        this.h = hPrime * d;
        this.a = a;
        this.k = k;
        this.hashFamily = hashFamily;
        this.lgW = 4; // log2(16) = 4

        // WOTS+ parameters per FIPS 205 Section 5
        this.wotsLen1 = (8 * n + lgW - 1) / lgW; // ceil(8n / lgW)
        // len2 = floor(log_w(len1 * (w-1))) + 1
        int maxChecksum = wotsLen1 * (w - 1);
        int tmp = 0;
        int val = maxChecksum;
        while (val > 0) {
            val /= w;
            tmp++;
        }
        this.wotsLen2 = tmp;
        this.wotsLen = wotsLen1 + wotsLen2;
        this.m = a * k;
    }

    /** Signature size in bytes. */
    public int sigSize() {
        // SLH-DSA sig = (randomizer n) + (FORS sig: k*(a+1)*n) + (HT sig: d*(hPrime + wotsLen)*n)
        return n + (k * (a + 1) * n) + (d * (hPrime + wotsLen) * n);
    }

    /** Public key size = 2n bytes (PK.seed || PK.root). */
    public int pkSize() {
        return 2 * n;
    }

    /** Secret key size = 4n bytes (SK.seed || SK.prf || PK.seed || PK.root). */
    public int skSize() {
        return 4 * n;
    }

    public static SlhParams fromName(String name) {
        for (SlhParams p : values()) {
            if (p.name.equalsIgnoreCase(name)) return p;
        }
        throw new IllegalArgumentException("Unknown SLH-DSA parameter set: " + name);
    }
}
