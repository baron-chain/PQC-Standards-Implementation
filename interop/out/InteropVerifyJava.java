/*
 * interop_verify_java.java — Comprehensive Java cross-language PQC verifier.
 *
 * Reads all JSON vector files from VECTORS_DIR and verifies:
 *   ML-KEM:  MLKEM.decaps(dk, ct, params) == ss
 *   ML-DSA:  MLDSA.verify(pk, msg, sig, params) == true
 *   SLH-DSA: SLHDSA.verify(msg, sig, pk, params) == true
 *
 * Output lines (parseable by orchestrator):
 *   RESULT:ML-KEM-512:PASS
 *   RESULT:ML-DSA-44:FAIL:verification returned false
 *
 * Compile and run (from repo root):
 *   cd java && mvn compile -q && cd ..
 *   mkdir -p interop/out
 *   javac -cp java/target/classes -d interop/out interop/interop_verify_java.java
 *   java  -cp java/target/classes:interop/out interop.InteropVerifyJava [VECTORS_DIR]
 *
 * VECTORS_DIR defaults to interop/vectors (relative to working directory).
 */

package interop;

import com.pqc.mlkem.MLKEM;
import com.pqc.mlkem.Params;
import com.pqc.mldsa.MLDSA;
import com.pqc.mldsa.DsaParams;
import com.pqc.slhdsa.SLHDSA;
import com.pqc.slhdsa.SlhParams;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

public class InteropVerifyJava {

    public static void main(String[] args) throws IOException {
        String vectorsDirStr = args.length > 0 ? args[0] : "interop/vectors";
        Path vectorsDir = Paths.get(vectorsDirStr);

        if (!Files.isDirectory(vectorsDir)) {
            System.err.println("ERROR: vectors directory not found: " + vectorsDirStr);
            System.exit(1);
        }

        int failed = 0;
        File[] files = vectorsDir.toFile().listFiles(f -> f.getName().endsWith(".json"));
        if (files == null || files.length == 0) {
            System.err.println("ERROR: no JSON files found in " + vectorsDirStr);
            System.exit(1);
        }

        Arrays.sort(files);

        for (File file : files) {
            String content;
            try {
                content = Files.readString(file.toPath());
            } catch (IOException e) {
                System.err.println("ERROR: cannot read " + file.getName() + ": " + e.getMessage());
                failed++;
                continue;
            }

            String alg = extractString(content, "algorithm");
            boolean pass;
            String errMsg = "";

            try {
                if (alg.startsWith("ML-KEM")) {
                    pass = verifyMLKEM(alg, content);
                } else if (alg.startsWith("ML-DSA")) {
                    pass = verifyMLDSA(alg, content);
                } else if (alg.startsWith("SLH-DSA")) {
                    pass = verifySLHDSA(alg, content);
                } else {
                    pass = false;
                    errMsg = "unknown algorithm family: " + alg;
                }
            } catch (Exception e) {
                pass = false;
                errMsg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            }

            if (pass) {
                System.out.println("RESULT:" + alg + ":PASS");
            } else {
                if (errMsg.isEmpty()) errMsg = "verification failed";
                System.out.println("RESULT:" + alg + ":FAIL:" + errMsg);
                failed++;
            }
        }

        System.exit(failed > 0 ? 1 : 0);
    }

    // -------------------------------------------------------------------------
    // ML-KEM verification
    // -------------------------------------------------------------------------

    private static boolean verifyMLKEM(String alg, String json) {
        byte[] dk         = hexToBytes(extractString(json, "dk"));
        byte[] ct         = hexToBytes(extractString(json, "ct"));
        byte[] ssExpected = hexToBytes(extractString(json, "ss"));

        Params params;
        switch (alg) {
            case "ML-KEM-512":  params = Params.ML_KEM_512;  break;
            case "ML-KEM-768":  params = Params.ML_KEM_768;  break;
            case "ML-KEM-1024": params = Params.ML_KEM_1024; break;
            default: throw new IllegalArgumentException("unknown ML-KEM param set: " + alg);
        }

        byte[] ssGot = MLKEM.decaps(dk, ct, params);
        if (!Arrays.equals(ssGot, ssExpected)) {
            throw new RuntimeException("decapsulated shared secret does not match expected");
        }
        return true;
    }

    // -------------------------------------------------------------------------
    // ML-DSA verification
    // -------------------------------------------------------------------------

    private static boolean verifyMLDSA(String alg, String json) {
        byte[] pk  = hexToBytes(extractString(json, "pk"));
        byte[] msg = hexToBytes(extractString(json, "msg"));
        byte[] sig = hexToBytes(extractString(json, "sig"));

        DsaParams params;
        switch (alg) {
            case "ML-DSA-44": params = DsaParams.ML_DSA_44; break;
            case "ML-DSA-65": params = DsaParams.ML_DSA_65; break;
            case "ML-DSA-87": params = DsaParams.ML_DSA_87; break;
            default: throw new IllegalArgumentException("unknown ML-DSA param set: " + alg);
        }

        boolean ok = MLDSA.verify(pk, msg, sig, params);
        if (!ok) throw new RuntimeException("signature verification returned false");
        return true;
    }

    // -------------------------------------------------------------------------
    // SLH-DSA verification
    // -------------------------------------------------------------------------

    private static boolean verifySLHDSA(String alg, String json) {
        byte[] pk  = hexToBytes(extractString(json, "pk"));
        byte[] msg = hexToBytes(extractString(json, "msg"));
        byte[] sig = hexToBytes(extractString(json, "sig"));

        SlhParams params;
        switch (alg) {
            case "SLH-DSA-SHAKE-128f": params = SlhParams.SHAKE_128F; break;
            case "SLH-DSA-SHAKE-128s": params = SlhParams.SHAKE_128S; break;
            case "SLH-DSA-SHAKE-192f": params = SlhParams.SHAKE_192F; break;
            case "SLH-DSA-SHAKE-192s": params = SlhParams.SHAKE_192S; break;
            case "SLH-DSA-SHAKE-256f": params = SlhParams.SHAKE_256F; break;
            case "SLH-DSA-SHAKE-256s": params = SlhParams.SHAKE_256S; break;
            default: throw new IllegalArgumentException("unknown SLH-DSA param set: " + alg);
        }

        // SLHDSA.verify(msg, sig, pk, params) — argument order per FIPS 205
        boolean ok = SLHDSA.verify(msg, sig, pk, params);
        if (!ok) throw new RuntimeException("signature verification returned false");
        return true;
    }

    // -------------------------------------------------------------------------
    // Minimal JSON string extractor (no external dependencies)
    // -------------------------------------------------------------------------

    private static String extractString(String json, String key) {
        String search = "\"" + key + "\"";
        int idx = json.indexOf(search);
        if (idx < 0) throw new IllegalArgumentException("key not found: " + key);
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
