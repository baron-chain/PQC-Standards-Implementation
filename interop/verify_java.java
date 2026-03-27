/*
 * verify_java.java -- Verify ML-DSA-65 interop test vectors using the Java implementation.
 *
 * This file is meant to be compiled and run with the project's classpath.
 *
 * Usage (from the repository root):
 *
 *     # Option 1: compile with Maven, then run directly
 *     cd java && mvn compile -q && cd ..
 *     javac -cp java/target/classes \
 *           -d interop/out \
 *           interop/verify_java.java
 *     java  -cp java/target/classes:interop/out \
 *           interop.VerifyJava
 *
 *     # Option 2: via the interop shell script
 *     bash interop/run_interop.sh
 */

package interop;

import com.pqc.mldsa.DsaParams;
import com.pqc.mldsa.MLDSA;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class VerifyJava {

    public static void main(String[] args) throws IOException {
        System.out.println("=== ML-DSA-65 verification (Java) ===");

        // Locate vectors file -- try several relative paths
        Path vectorsPath = null;
        String[] candidates = {
            "interop/mldsa65_vectors.json",
            "../interop/mldsa65_vectors.json",
            "mldsa65_vectors.json",
        };
        for (String c : candidates) {
            Path p = Paths.get(c);
            if (Files.exists(p)) {
                vectorsPath = p;
                break;
            }
        }
        if (vectorsPath == null) {
            System.err.println("ERROR: cannot find mldsa65_vectors.json");
            System.exit(1);
        }

        String content = Files.readString(vectorsPath);

        // Minimal JSON parsing (no external dependency required).
        String pk  = extractJsonString(content, "pk");
        String msg = extractJsonString(content, "msg");
        String sig = extractJsonString(content, "sig");
        String alg = extractJsonString(content, "algorithm");

        byte[] pkBytes  = hexToBytes(pk);
        byte[] msgBytes = hexToBytes(msg);
        byte[] sigBytes = hexToBytes(sig);

        System.out.println("  algorithm : " + alg);
        System.out.println("  pk size   : " + pkBytes.length + " bytes");
        System.out.println("  msg size  : " + msgBytes.length + " bytes");
        System.out.println("  sig size  : " + sigBytes.length + " bytes");

        boolean ok = MLDSA.verify(pkBytes, msgBytes, sigBytes, DsaParams.ML_DSA_65);

        if (ok) {
            System.out.println("  result    : PASS");
        } else {
            System.out.println("  result    : FAIL");
            System.exit(1);
        }
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /**
     * Extract a JSON string value by key (simple, no external dependencies).
     */
    private static String extractJsonString(String json, String key) {
        String search = "\"" + key + "\"";
        int idx = json.indexOf(search);
        if (idx < 0) {
            throw new IllegalArgumentException("Key not found: " + key);
        }
        // Find the colon, then the opening quote of the value
        int colon = json.indexOf(':', idx + search.length());
        int open  = json.indexOf('"', colon + 1);
        int close = json.indexOf('"', open + 1);
        return json.substring(open + 1, close);
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                + Character.digit(hex.charAt(i + 1), 16));
        }
        return out;
    }
}
