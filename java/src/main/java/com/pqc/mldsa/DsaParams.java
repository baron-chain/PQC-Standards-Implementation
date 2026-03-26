package com.pqc.mldsa;

/**
 * ML-DSA parameter sets (FIPS 204 Table 1).
 */
public final class DsaParams {

    public final String name;
    public final int k;
    public final int l;
    public final int eta;
    public final int tau;
    public final int beta;
    public final int gamma1;
    public final int gamma2;
    public final int omega;
    public final int lambda; // collision strength in bits
    public final int sigSize;

    // Derived sizes
    public final int pkSize;
    public final int skSize;

    private DsaParams(String name, int k, int l, int eta, int tau, int beta,
                      int gamma1, int gamma2, int omega, int lambda, int sigSize) {
        this.name = name;
        this.k = k;
        this.l = l;
        this.eta = eta;
        this.tau = tau;
        this.beta = beta;
        this.gamma1 = gamma1;
        this.gamma2 = gamma2;
        this.omega = omega;
        this.lambda = lambda;
        this.sigSize = sigSize;

        // pk = rho (32 bytes) + t1 encoded (k * 320 bytes = k * 32 * 10 bits / 8)
        this.pkSize = 32 + k * 320;
        // sk = rho (32) + K (32) + tr (64) + s1 (l * encodedEtaSize) + s2 (k * encodedEtaSize) + t0 (k * 416)
        int etaBlockSize = (eta == 2) ? 96 : 128; // 32*bitlen(2*eta) per polynomial: eta=2 -> 3 bits -> 96; eta=4 -> 4 bits -> 128
        this.skSize = 32 + 32 + 64 + l * etaBlockSize + k * etaBlockSize + k * 416;
    }

    public static final DsaParams ML_DSA_44 = new DsaParams(
        "ML-DSA-44", 4, 4, 2, 39, 78, 131072, 95232, 80, 128, 2420);

    public static final DsaParams ML_DSA_65 = new DsaParams(
        "ML-DSA-65", 6, 5, 4, 49, 196, 524288, 261888, 55, 192, 3309);

    public static final DsaParams ML_DSA_87 = new DsaParams(
        "ML-DSA-87", 8, 7, 2, 60, 120, 524288, 261888, 75, 256, 4627);

    public static final DsaParams[] ALL = { ML_DSA_44, ML_DSA_65, ML_DSA_87 };
}
