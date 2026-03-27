namespace PqcStandards.MlDsa;

/// <summary>NTT for ML-DSA with Q=8380417, using root of unity zeta=1753.</summary>
public static class DsaNtt
{
    public static readonly int[] Zetas = ComputeZetas();

    private static int[] ComputeZetas()
    {
        int[] z = new int[256];
        for (int i = 0; i < 256; i++)
            z[i] = DsaField.Pow(1753, BitRev8(i));
        return z;
    }

    private static int BitRev8(int x)
    {
        int r = 0;
        for (int i = 0; i < 8; i++)
        {
            r = (r << 1) | (x & 1);
            x >>= 1;
        }
        return r;
    }

    /// <summary>Forward NTT (8 layers).</summary>
    public static int[] NttForward(int[] a)
    {
        int[] f = (int[])a.Clone();
        int k = 0;
        for (int len = 128; len >= 1; len >>= 1)
        {
            for (int start = 0; start < 256; start += 2 * len)
            {
                k++;
                int zeta = Zetas[k];
                for (int j = start; j < start + len; j++)
                {
                    int t = DsaField.Mul(zeta, f[j + len]);
                    f[j + len] = DsaField.Sub(f[j], t);
                    f[j] = DsaField.Add(f[j], t);
                }
            }
        }
        return f;
    }

    /// <summary>Inverse NTT.</summary>
    public static int[] NttInverse(int[] a)
    {
        int[] f = (int[])a.Clone();
        int k = 256;
        for (int len = 1; len <= 128; len <<= 1)
        {
            for (int start = 0; start < 256; start += 2 * len)
            {
                k--;
                int zeta = DsaField.Sub(0, Zetas[k]);
                for (int j = start; j < start + len; j++)
                {
                    int t = f[j];
                    f[j] = DsaField.Add(t, f[j + len]);
                    f[j + len] = DsaField.Mul(zeta, DsaField.Sub(t, f[j + len]));
                }
            }
        }
        // Multiply by N^{-1} mod Q: 256^{-1} mod 8380417 = 8347681
        int nInv = DsaField.Pow(256, DsaField.Q - 2);
        for (int i = 0; i < 256; i++)
            f[i] = DsaField.Mul(f[i], nInv);
        return f;
    }

    /// <summary>Pointwise multiplication.</summary>
    public static int[] PointwiseMul(int[] a, int[] b)
    {
        int[] c = new int[256];
        for (int i = 0; i < 256; i++)
            c[i] = DsaField.Mul(a[i], b[i]);
        return c;
    }
}
