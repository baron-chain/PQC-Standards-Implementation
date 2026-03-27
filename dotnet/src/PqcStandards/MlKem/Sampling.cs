namespace PqcStandards.MlKem;

/// <summary>Sampling functions for ML-KEM (FIPS 203).</summary>
public static class Sampling
{
    /// <summary>SampleNTT: rejection sampling from XOF(rho || i || j).</summary>
    public static int[] SampleNtt(byte[] rho, byte i, byte j)
    {
        byte[] input = new byte[rho.Length + 2];
        Buffer.BlockCopy(rho, 0, input, 0, rho.Length);
        input[rho.Length] = i;
        input[rho.Length + 1] = j;

        // Generate enough XOF output
        byte[] buf = HashFuncs.Xof(input, 3 * 256 * 2);

        int[] a = new int[256];
        int ctr = 0;
        int pos = 0;
        while (ctr < 256)
        {
            int d1 = ((buf[pos] | (buf[pos + 1] << 8)) & 0xFFF);
            int d2 = (((buf[pos + 1] >> 4) | (buf[pos + 2] << 4)) & 0xFFF);
            pos += 3;

            if (d1 < Field.Q) a[ctr++] = d1;
            if (ctr < 256 && d2 < Field.Q) a[ctr++] = d2;
        }
        return a;
    }

    /// <summary>SamplePolyCBD: sample polynomial from centered binomial distribution.</summary>
    public static int[] SamplePolyCbd(byte[] sigma, byte nonce, int eta)
    {
        byte[] buf = HashFuncs.Prf(sigma, nonce, 64 * eta);
        int[] f = new int[256];

        for (int i = 0; i < 256; i++)
        {
            int a = 0, b = 0;
            for (int j = 0; j < eta; j++)
            {
                int bitIdx = 2 * i * eta + j;
                a += (buf[bitIdx / 8] >> (bitIdx % 8)) & 1;
            }
            for (int j = 0; j < eta; j++)
            {
                int bitIdx = 2 * i * eta + eta + j;
                b += (buf[bitIdx / 8] >> (bitIdx % 8)) & 1;
            }
            f[i] = Field.ModQ(a - b);
        }
        return f;
    }
}
