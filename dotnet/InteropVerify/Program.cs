/**
 * interop-verify — .NET cross-language PQC verifier.
 *
 * Reads all JSON vector files from VECTORS_DIR and verifies:
 *   ML-KEM:  Decaps(dk, ct) == ss
 *   ML-DSA:  Verify(pk, msg, sig) == true
 *   SLH-DSA: Verify(pk, msg, sig) == true
 *
 * Output lines (parseable by orchestrator):
 *   RESULT:ML-KEM-512:PASS
 *   RESULT:ML-DSA-44:FAIL:verification returned false
 *
 * Usage:
 *   dotnet run -- [VECTORS_DIR]
 */

using System.Text.Json;
using PqcStandards.MlKem;
using PqcStandards.MlDsa;
using PqcStandards.SlhDsa;

// ---------------------------------------------------------------------------
// Vectors directory
// ---------------------------------------------------------------------------
string vectorsDir = args.Length > 0
    ? args[0]
    : Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "interop", "vectors");

if (!Directory.Exists(vectorsDir))
{
    Console.Error.WriteLine($"ERROR: Vectors directory not found: {vectorsDir}");
    Environment.Exit(1);
}

// ---------------------------------------------------------------------------
// Parameter dispatch
// ---------------------------------------------------------------------------
var mlKemParams = new Dictionary<string, MlKemParams>
{
    ["ML-KEM-512"]  = MlKemParams.MlKem512,
    ["ML-KEM-768"]  = MlKemParams.MlKem768,
    ["ML-KEM-1024"] = MlKemParams.MlKem1024,
};

var mlDsaParams = new Dictionary<string, MlDsaParams>
{
    ["ML-DSA-44"] = MlDsaParams.MlDsa44,
    ["ML-DSA-65"] = MlDsaParams.MlDsa65,
    ["ML-DSA-87"] = MlDsaParams.MlDsa87,
};

var slhDsaParams = new Dictionary<string, SlhParams>
{
    ["SLH-DSA-SHAKE-128f"] = SlhParams.Shake128f,
    ["SLH-DSA-SHAKE-128s"] = SlhParams.Shake128s,
    ["SLH-DSA-SHAKE-192f"] = SlhParams.Shake192f,
    ["SLH-DSA-SHAKE-192s"] = SlhParams.Shake192s,
    ["SLH-DSA-SHAKE-256f"] = SlhParams.Shake256f,
    ["SLH-DSA-SHAKE-256s"] = SlhParams.Shake256s,
};

// ---------------------------------------------------------------------------
// Process all vector files
// ---------------------------------------------------------------------------
var jsonFiles = Directory.GetFiles(vectorsDir, "*.json");
Array.Sort(jsonFiles);

foreach (var jsonFile in jsonFiles)
{
    JsonDocument doc;
    try
    {
        using var stream = File.OpenRead(jsonFile);
        doc = JsonDocument.Parse(stream);
    }
    catch { continue; }

    var root = doc.RootElement;
    if (!root.TryGetProperty("algorithm", out var algProp)) continue;
    string alg = algProp.GetString() ?? "";

    try
    {
        // -----------------------------------------------------------------
        // ML-KEM: verify Decaps(dk, ct) == ss
        // -----------------------------------------------------------------
        if (mlKemParams.TryGetValue(alg, out var kemParams))
        {
            byte[] dk = Convert.FromHexString(root.GetProperty("dk").GetString()!);
            byte[] ct = Convert.FromHexString(root.GetProperty("ct").GetString()!);
            byte[] expectedSs = Convert.FromHexString(root.GetProperty("ss").GetString()!);

            byte[] ss = MlKemAlgorithm.Decaps(kemParams, dk, ct);

            if (!ss.SequenceEqual(expectedSs))
                Console.WriteLine($"RESULT:{alg}:FAIL:shared secret mismatch");
            else
                Console.WriteLine($"RESULT:{alg}:PASS");
        }

        // -----------------------------------------------------------------
        // ML-DSA: verify(pk, msg, sig) == true
        // -----------------------------------------------------------------
        else if (mlDsaParams.TryGetValue(alg, out var dsaParams))
        {
            byte[] pk  = Convert.FromHexString(root.GetProperty("pk").GetString()!);
            byte[] msg = Convert.FromHexString(root.GetProperty("msg").GetString()!);
            byte[] sig = Convert.FromHexString(root.GetProperty("sig").GetString()!);

            bool ok = MlDsaAlgorithm.Verify(dsaParams, pk, msg, sig);

            if (!ok)
                Console.WriteLine($"RESULT:{alg}:FAIL:verification returned false");
            else
                Console.WriteLine($"RESULT:{alg}:PASS");
        }

        // -----------------------------------------------------------------
        // SLH-DSA: verify(pk, msg, sig) == true
        // -----------------------------------------------------------------
        else if (slhDsaParams.TryGetValue(alg, out var slhParams))
        {
            byte[] pk  = Convert.FromHexString(root.GetProperty("pk").GetString()!);
            byte[] msg = Convert.FromHexString(root.GetProperty("msg").GetString()!);
            byte[] sig = Convert.FromHexString(root.GetProperty("sig").GetString()!);

            bool ok = SlhDsaAlgorithm.Verify(slhParams, pk, msg, sig);

            if (!ok)
                Console.WriteLine($"RESULT:{alg}:FAIL:verification returned false");
            else
                Console.WriteLine($"RESULT:{alg}:PASS");
        }
        // Unknown algorithm — skip silently
    }
    catch (Exception ex)
    {
        string errMsg = ex.Message.Replace('\n', ' ').Replace(':', ';');
        Console.WriteLine($"RESULT:{alg}:FAIL:{errMsg}");
    }
    finally
    {
        doc.Dispose();
    }
}
