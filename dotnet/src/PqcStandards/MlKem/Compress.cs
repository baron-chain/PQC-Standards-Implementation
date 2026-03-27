namespace PqcStandards.MlKem;

/// <summary>Compress and Decompress per FIPS 203.</summary>
public static class Compress
{
    /// <summary>Compress: round(2^d / Q * x) mod 2^d.</summary>
    public static int CompressValue(int x, int d)
    {
        // (2^d * x + Q/2) / Q mod 2^d
        long num = ((long)x << d) + Field.Q / 2;
        return (int)(num / Field.Q) & ((1 << d) - 1);
    }

    /// <summary>Decompress: round(Q / 2^d * y).</summary>
    public static int DecompressValue(int y, int d)
    {
        return (int)(((long)Field.Q * y + (1 << (d - 1))) >> d);
    }

    public static int[] CompressPoly(int[] f, int d)
    {
        int[] r = new int[256];
        for (int i = 0; i < 256; i++)
            r[i] = CompressValue(f[i], d);
        return r;
    }

    public static int[] DecompressPoly(int[] f, int d)
    {
        int[] r = new int[256];
        for (int i = 0; i < 256; i++)
            r[i] = DecompressValue(f[i], d);
        return r;
    }
}
