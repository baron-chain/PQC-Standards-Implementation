package com.pqc.bench;

import com.pqc.mlkem.MLKEM;
import com.pqc.mlkem.Params;
import com.pqc.mldsa.DsaParams;
import com.pqc.mldsa.MLDSA;
import com.pqc.slhdsa.SLHDSA;
import com.pqc.slhdsa.SlhParams;

import org.junit.jupiter.api.Test;

/**
 * Simple benchmark suite for ML-KEM, ML-DSA, and SLH-DSA.
 *
 * Uses System.nanoTime() for timing (no JMH dependency required).
 * Results are approximate -- JVM warm-up and GC may affect timings.
 *
 * Run with: mvn test -Dtest=com.pqc.bench.BenchmarkTest
 */
public class BenchmarkTest {

    private static final byte[] MSG = "PQC benchmark message for performance testing".getBytes();
    private static final int WARMUP = 3;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    @FunctionalInterface
    interface BenchRunnable {
        void run();
    }

    private static void bench(String name, BenchRunnable fn, int iterations) {
        // Warm-up
        for (int i = 0; i < WARMUP; i++) {
            fn.run();
        }

        long start = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            fn.run();
        }
        long elapsed = System.nanoTime() - start;
        double avgMs = (elapsed / 1_000_000.0) / iterations;
        double totalMs = elapsed / 1_000_000.0;
        System.out.printf("  %-35s %10.3f ms avg  (%d iters, %.1f ms total)%n",
                name, avgMs, iterations, totalMs);
    }

    // -----------------------------------------------------------------------
    // ML-KEM benchmarks
    // -----------------------------------------------------------------------

    @Test
    public void benchmarkMlKem() {
        System.out.println();
        System.out.println("--- ML-KEM-768 ---");
        int iters = 100;

        bench("KeyGen", () -> MLKEM.keyGen(Params.ML_KEM_768), iters);

        MLKEM.KeyPair kp = MLKEM.keyGen(Params.ML_KEM_768);
        bench("Encaps", () -> MLKEM.encaps(kp.ek(), Params.ML_KEM_768), iters);

        MLKEM.EncapsResult enc = MLKEM.encaps(kp.ek(), Params.ML_KEM_768);
        bench("Decaps", () -> MLKEM.decaps(kp.dk(), enc.ciphertext(), Params.ML_KEM_768), iters);

        System.out.println();
    }

    // -----------------------------------------------------------------------
    // ML-DSA benchmarks
    // -----------------------------------------------------------------------

    @Test
    public void benchmarkMlDsa() {
        System.out.println("--- ML-DSA ---");
        int iters = 20;

        for (DsaParams params : DsaParams.ALL) {
            System.out.println("  [" + params.name + "]");

            bench("  KeyGen", () -> MLDSA.keyGen(params), iters);

            MLDSA.KeyPair kp = MLDSA.keyGen(params);
            bench("  Sign", () -> MLDSA.sign(kp.sk(), MSG, params), iters);

            byte[] sig = MLDSA.sign(kp.sk(), MSG, params);
            bench("  Verify", () -> MLDSA.verify(kp.pk(), MSG, sig, params), iters);
        }

        System.out.println();
    }

    // -----------------------------------------------------------------------
    // SLH-DSA benchmarks
    // -----------------------------------------------------------------------

    @Test
    public void benchmarkSlhDsa() {
        System.out.println("--- SLH-DSA-SHAKE-128f ---");
        SlhParams params = SlhParams.SHAKE_128F;
        int iters = 3;

        bench("KeyGen", () -> SLHDSA.keyGen(params), iters);

        SLHDSA.KeyPair kp = SLHDSA.keyGen(params);
        bench("Sign", () -> SLHDSA.sign(MSG, kp.secretKey(), params), iters);

        byte[] sig = SLHDSA.sign(MSG, kp.secretKey(), params);
        bench("Verify", () -> SLHDSA.verify(MSG, sig, kp.publicKey(), params), iters);

        System.out.println();
    }
}
