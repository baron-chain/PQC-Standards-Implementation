namespace PqcStandards.SlhDsa;

/// <summary>SLH-DSA parameter sets per FIPS 205.</summary>
public sealed record SlhParams(
    string Name,
    int N,          // Security parameter (hash output bytes)
    int H,          // Total tree height
    int D,          // Number of layers (hypertree layers)
    int HPrime,     // Height of each tree = H/D
    int A,          // FORS trees count
    int K,          // FORS leaves per tree (log)
    int W,          // Winternitz parameter
    int Len,        // WOTS+ chain count
    string HashFamily,  // "SHAKE" or "SHA2"
    int SigSize)
{
    // SHAKE-based
    public static readonly SlhParams Shake128s = new("SLH-DSA-SHAKE-128s", 16, 63, 7, 9, 12, 14, 16, 35, "SHAKE", 7856);
    public static readonly SlhParams Shake128f = new("SLH-DSA-SHAKE-128f", 16, 66, 22, 3, 6, 33, 16, 35, "SHAKE", 17088);
    public static readonly SlhParams Shake192s = new("SLH-DSA-SHAKE-192s", 24, 63, 7, 9, 14, 17, 16, 51, "SHAKE", 16224);
    public static readonly SlhParams Shake192f = new("SLH-DSA-SHAKE-192f", 24, 66, 22, 3, 8, 33, 16, 51, "SHAKE", 35664);
    public static readonly SlhParams Shake256s = new("SLH-DSA-SHAKE-256s", 32, 64, 8, 8, 14, 22, 16, 67, "SHAKE", 29792);
    public static readonly SlhParams Shake256f = new("SLH-DSA-SHAKE-256f", 32, 68, 17, 4, 9, 35, 16, 67, "SHAKE", 49856);

    // SHA2-based
    public static readonly SlhParams Sha2_128s = new("SLH-DSA-SHA2-128s", 16, 63, 7, 9, 12, 14, 16, 35, "SHA2", 7856);
    public static readonly SlhParams Sha2_128f = new("SLH-DSA-SHA2-128f", 16, 66, 22, 3, 6, 33, 16, 35, "SHA2", 17088);
    public static readonly SlhParams Sha2_192s = new("SLH-DSA-SHA2-192s", 24, 63, 7, 9, 14, 17, 16, 51, "SHA2", 16224);
    public static readonly SlhParams Sha2_192f = new("SLH-DSA-SHA2-192f", 24, 66, 22, 3, 8, 33, 16, 51, "SHA2", 35664);
    public static readonly SlhParams Sha2_256s = new("SLH-DSA-SHA2-256s", 32, 64, 8, 8, 14, 22, 16, 67, "SHA2", 29792);
    public static readonly SlhParams Sha2_256f = new("SLH-DSA-SHA2-256f", 32, 68, 17, 4, 9, 35, 16, 67, "SHA2", 49856);

    /// <summary>All parameter sets.</summary>
    public static readonly SlhParams[] All = [
        Shake128s, Shake128f, Shake192s, Shake192f, Shake256s, Shake256f,
        Sha2_128s, Sha2_128f, Sha2_192s, Sha2_192f, Sha2_256s, Sha2_256f
    ];
}
