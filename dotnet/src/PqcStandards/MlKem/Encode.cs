namespace PqcStandards.MlKem;

/// <summary>ByteEncode and ByteDecode per FIPS 203.</summary>
public static class Encode
{
    /// <summary>Encode an array of 256 integers (each in [0, 2^d)) into 32*d bytes.</summary>
    public static byte[] ByteEncode(int[] f, int d)
    {
        byte[] b = new byte[32 * d];
        for (int i = 0; i < 256; i++)
        {
            int a = f[i];
            for (int j = 0; j < d; j++)
            {
                int bitIndex = i * d + j;
                b[bitIndex / 8] |= (byte)(((a >> j) & 1) << (bitIndex % 8));
            }
        }
        return b;
    }

    /// <summary>Decode 32*d bytes into an array of 256 integers.</summary>
    public static int[] ByteDecode(byte[] b, int d)
    {
        int[] f = new int[256];
        int mod = d < 12 ? (1 << d) : Field.Q;
        for (int i = 0; i < 256; i++)
        {
            int a = 0;
            for (int j = 0; j < d; j++)
            {
                int bitIndex = i * d + j;
                a |= ((b[bitIndex / 8] >> (bitIndex % 8)) & 1) << j;
            }
            f[i] = a % mod;
        }
        return f;
    }
}
